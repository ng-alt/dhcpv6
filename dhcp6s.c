/*	$Id: dhcp6s.c,v 1.3 2003/01/23 18:44:33 shirleyma Exp $	*/
/*	ported from KAME: dhcp6s.c,v 1.91 2002/09/24 14:20:50 itojun Exp */

/*
 * Copyright (C) 1998 and 1999 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/uio.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <errno.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <netinet/in.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>
#include <limits.h>

#include <timer.h>
#include <queue.h>
#include <server6_addr.h>

typedef enum { DHCP6_CONFINFO_PREFIX, DHCP6_CONFINFO_ADDRS } dhcp6_conftype_t;

struct dhcp6_binding {
	TAILQ_ENTRY(dhcp6_binding) link;

	dhcp6_conftype_t type;
	struct duid clientid;
	void *val;

	u_int32_t duration;
	struct dhcp6_timer *timer;
};
static TAILQ_HEAD(, dhcp6_binding) dhcp6_binding_head;

static int debug = 0;

const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_SERVER;
char *device = NULL;
int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */

static const struct sockaddr_in6 *sa6_any_downstream;
static struct msghdr rmh;
static char rdatabuf[BUFSIZ];
static int rmsgctllen;
static char *rmsgctlbuf;
static struct duid server_duid;
static struct dhcp6_list arg_dnslist;
struct link_decl *subnet;
struct rootgroup *globalgroup = NULL;

#define DUID_FILE "/var/db/dhcp6s_duid"
#define DHCP6S_CONF "/etc/dhcp6s.conf"
#define DHCP6S_ADDR_CONF "/etc/server6_addr.conf"

#define DH6_VALID_MESSAGE(a) \
	(a == DH6_SOLICIT || a == DH6_REQUEST || a == DH6_RENEW || \
	 a == DH6_REBIND || a == DH6_CONFIRM || a == DH6_RELEASE || \
	 a == DH6_DECLINE || a == DH6_INFORM_REQ)

static void usage __P((void));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static int server6_recv __P((int));
static int server6_react_message __P((struct dhcp6_if *,
				      struct in6_pktinfo *, struct dhcp6 *,
				      struct dhcp6_optinfo *,
				      struct sockaddr *, int));
static int server6_send __P((int, struct dhcp6_if *, struct dhcp6 *,
			     struct dhcp6_optinfo *,
			     struct sockaddr *, int,
			     struct dhcp6_optinfo *));
static int create_conflist __P((dhcp6_conftype_t, struct duid *,
				struct dhcp6_list *, struct dhcp6_list *,
				struct dhcp6_list *, int));
static struct dhcp6_binding *add_binding __P((struct duid *,
					      dhcp6_conftype_t, void *));
static struct dhcp6_binding *find_binding __P((struct duid *,
					       dhcp6_conftype_t, void *));
static void update_binding __P((struct dhcp6_binding *));
static void remove_binding __P((struct dhcp6_binding *));
static struct dhcp6_timer *binding_timo __P((void *));
static char *bindingstr __P((struct dhcp6_binding *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	struct in6_addr a;
	struct dhcp6_listval *dlv;
	char *progname, *conffile = DHCP6S_CONF;
	char *addr_conffile = DHCP6S_ADDR_CONF;
	
	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	TAILQ_INIT(&arg_dnslist);

	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "c:dDfn:")) != -1) {
		switch (ch) {
		case 'c':
			conffile = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'D':
			debug = 2;
			break;
		case 'f':
			foreground++;
			break;
		case 'n':
			warnx("-n dnsserv option was obsoleted.  "
			    "use configuration file.");
			if (inet_pton(AF_INET6, optarg, &a) != 1) {
				errx(1, "invalid DNS server %s", optarg);
				/* NOTREACHED */
			}
			if ((dlv = malloc(sizeof *dlv)) == NULL) {
				errx(1, "malloc failed for a DNS server");
				/* NOTREACHED */
			}
			dlv->val_addr6 = a;
			TAILQ_INSERT_TAIL(&arg_dnslist, dlv, link);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		/* NOTREACHED */
	}
	device = argv[0];

	if (foreground == 0) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
	}
	setloglevel(debug);

	ifinit(device);
	globalgroup = (struct rootgroup *)malloc(sizeof(struct rootgroup));
	if (globalgroup == NULL) {
		dprintf(LOG_ERR, "failed to allocate memory", strerror(errno));
		exit(1);
	}
	memset(globalgroup, 0, sizeof(*globalgroup));
	if ((sfparse(addr_conffile)) != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse addr configuration file",
			FNAME);
		exit(1);
	}
	
	if ((cfparse(conffile)) != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse configuration file",
			FNAME);
		exit(1);
	}
	if (init_leases() != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse lease file",
			FNAME);
		exit(1);
	}
	
	/* prohibit a mixture of old and new style of DNS server config */
	if (!TAILQ_EMPTY(&arg_dnslist)) {
		if (!TAILQ_EMPTY(&dnslist)) {
			dprintf(LOG_INFO, "%s" "do not specify DNS servers "
			    "both by command line and by configuration file.",
			    FNAME);
			exit(1);
		}
		dnslist = arg_dnslist;
		TAILQ_INIT(&arg_dnslist);
	}

	server6_init();

	server6_mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr,
		"usage: dhcp6s [-c configfile] [-dDf] intface\n");
	exit(0);
}

/*------------------------------------------------------------*/

void
server6_init()
{
	struct addrinfo hints;
	struct addrinfo *res, *res2;
	int error;
	int ifidx;
	int on = 1;
	struct ipv6_mreq mreq6;
	static struct iovec iov;
	static struct sockaddr_in6 sa6_any_downstream_storage;

	TAILQ_INIT(&dhcp6_binding_head);

	ifidx = if_nametoindex(device);
	if (ifidx == 0) {
		dprintf(LOG_ERR, "%s" "invalid interface %s", FNAME, device);
		exit(1);
	}

	/* get our DUID */
	if (get_duid(DUID_FILE, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to get a DUID", FNAME);
		exit(1);
	}

	/* initialize send/receive buffer */
	iov.iov_base = (caddr_t)rdatabuf;
	iov.iov_len = sizeof(rdatabuf);
	rmh.msg_iov = &iov;
	rmh.msg_iovlen = 1;
	rmsgctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	if ((rmsgctlbuf = (char *)malloc(rmsgctllen)) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed", FNAME);
		exit(1);
	}

	/* initialize socket */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		dprintf(LOG_ERR, "%s" "socket(insock): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEADDR, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s" "setsockopt(insock, SO_REUSEADDR): %s",
			FNAME, strerror(errno));
		exit(1);
	}
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(inbound, IPV6_RECVPKTINFO): %s",
			FNAME, strerror(errno));
		exit(1);
	}
#else
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_PKTINFO, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(inbound, IPV6_PKTINFO): %s",
			FNAME, strerror(errno));
		exit(1);
	}
#endif
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		dprintf(LOG_ERR, "%s" "bind(insock): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
	    &((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
	    sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    &mreq6, sizeof(mreq6))) {
		dprintf(LOG_ERR, "%s" "setsockopt(insock, IPV6_JOIN_GROUP)",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLSERVER, DH6PORT_UPSTREAM,
			    &hints, &res2);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
	    &((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
	    sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    &mreq6, sizeof(mreq6))) {
		dprintf(LOG_ERR,
			"%s" "setsockopt(insock, IPV6_JOIN_GROUP): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		dprintf(LOG_ERR, "%s" "socket(outsock): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	/* set outgoing interface of multicast packets for DHCP reconfig */
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	    &ifidx, sizeof(ifidx)) < 0) {
		dprintf(LOG_ERR,
			"%s" "setsockopt(outsock, IPV6_MULTICAST_IF): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	/* make the socket write-only */
	freeaddrinfo(res);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memcpy(&sa6_any_downstream_storage, res->ai_addr, res->ai_addrlen);
	sa6_any_downstream =
		(const struct sockaddr_in6*)&sa6_any_downstream_storage;
	freeaddrinfo(res);
}

static void
server6_mainloop()
{
	struct timeval *w;
	int ret;
	fd_set r;

	while (1) {
		w = dhcp6_check_timer();

		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, w);
		switch (ret) {
		case -1:
			dprintf(LOG_ERR, "%s" "select: %s",
				FNAME, strerror(errno));
			exit(1);
			/* NOTREACHED */
		case 0:		/* timeout */
			break;
		default:
			break;
		}
		if (FD_ISSET(insock, &r))
			server6_recv(insock);
	}
}

static int
server6_recv(s)
	int s;
{
	ssize_t len;
	struct sockaddr_storage from;
	int fromlen;
	struct msghdr mhdr;
	struct iovec iov;
	char cmsgbuf[BUFSIZ];
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo optinfo;
	memset(&iov, 0, sizeof(iov));
	memset(&mhdr, 0, sizeof(mhdr));

	iov.iov_base = rdatabuf;
	iov.iov_len = sizeof(rdatabuf);
	mhdr.msg_name = &from;
	mhdr.msg_namelen = sizeof(from);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (caddr_t)cmsgbuf;
	mhdr.msg_controllen = sizeof(cmsgbuf);

	if ((len = recvmsg(insock, &mhdr, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "recvmsg: %s", FNAME, strerror(errno));
		return -1;
	}
	fromlen = mhdr.msg_namelen;

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&mhdr, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
		}
	}
	if (pi == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to get packet info", FNAME);
		return -1;
	}
	if ((ifp = find_ifconfbyid((unsigned int)pi->ipi6_ifindex)) == NULL) {
		dprintf(LOG_INFO, "%s" "unexpected interface (%d)", FNAME,
		    (unsigned int)pi->ipi6_ifindex);
		return -1;
	}
	if (len < sizeof(*dh6)) {
		dprintf(LOG_INFO, "%s" "short packet", FNAME);
		return -1;
	}
	
	dh6 = (struct dhcp6 *)rdatabuf;

	dprintf(LOG_DEBUG, "%s" "received %s from %s", FNAME,
	    dhcp6msgstr(dh6->dh6_msgtype),
	    addr2str((struct sockaddr *)&from));

	/*
	 * parse and validate options in the request
	 */
	dhcp6_init_options(&optinfo);
	if (dhcp6_get_options((struct dhcp6opt *)(dh6 + 1),
	    (struct dhcp6opt *)(rdatabuf + len), &optinfo) < 0) {
		dprintf(LOG_INFO, "%s" "failed to parse options", FNAME);
		return -1;
	}

	/* ToDo: allocate subnet after relay agent done
	 * now assume client is on the same link as server
	 * if the subnet couldn't be found return status code NotOnLink to client
	 */
	subnet = server6_allocate_link(globalgroup, NULL);
	if (!(DH6_VALID_MESSAGE(dh6->dh6_msgtype)))
		dprintf(LOG_INFO, "%s" "unknown or unsupported msgtype %s",
		    FNAME, dhcp6msgstr(dh6->dh6_msgtype));
	else
		server6_react_message(ifp, pi, dh6, &optinfo,
			(struct sockaddr *)&from, fromlen);
	dhcp6_clear_options(&optinfo);
	return 0;
}

static int
server6_react_message(ifp, pi, dh6, optinfo, from, fromlen)
	struct dhcp6_if *ifp;
	struct in6_pktinfo *pi;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6_optinfo roptinfo;
	struct host_conf *client_conf;
	struct dhcp6_listval *lv;
	
	struct host_decl *hostlist;
	struct host_decl *host;
	int addr_flag;
	int do_binding = 0;
	int addr_request = 0;
	int resptype = DH6_REPLY;
	int num = DH6OPT_STCODE_SUCCESS;
	hostlist = globalgroup->iflist->hostlist;

	/* message validation according to Section 18.2 of dhcpv6-28 */

	/* the message must include a Client Identifier option */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	} else {
		dprintf(LOG_DEBUG, "%s" "client ID %s", FNAME,
			duidstr(&optinfo->clientID));
	}
	/* the message must include a Server Identifier option in below messages*/
	switch (dh6->dh6_msgtype) {
	case DH6_REQUEST:
	case DH6_RENEW:
        case DH6_DECLINE:
		if (optinfo->serverID.duid_len == 0) {
			dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
			return -1;
		}
		/* the contents of the Server Identifier option must match ours */
		if (duidcmp(&optinfo->serverID, &server_duid)) {
			dprintf(LOG_INFO, "%s" "server ID mismatch", FNAME);
			return -1;
		}
		break;
	default:
		break;
	}
	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);
	/* server information option */
	if (duidcpy(&roptinfo.serverID, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto fail;
	}
	/* copy client information back */
	if (duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto fail;
	}
	/* if the client is not on the link */
	if (subnet == NULL) {
		num = DH6OPT_STCODE_NOTONLINK; 
		/* Draft-28 18.2.2, drop the message if NotOnLink */
		if (dh6->dh6_msgtype == DH6_CONFIRM)
			goto fail;
		else
			goto send;
	}
	/*
	 * When the server receives a Request message via unicast from a
	 * client to which the server has not sent a unicast option, the server
	 * discards the Request message and responds with a Reply message
	 * containing a Status Code option with value UseMulticast, a Server
	 * Identifier option containing the server's DUID, the Client
	 * Identifier option from the client message and no other options.
	 * [dhcpv6-26 18.2.1]
	 * (Our current implementation never sends a unicast option.)
	 */

	switch (dh6->dh6_msgtype) {
	case DH6_REQUEST:
	case DH6_RENEW:
	case DH6_DECLINE:
		if (!IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
			int stcode = DH6OPT_STCODE_USEMULTICAST;
			goto send;
		}
	default:
		break;
	}

	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT: 
		/* get per-host configuration for the client, if any. */
		if ((client_conf = find_hostconf(&optinfo->clientID))) {
			dprintf(LOG_DEBUG, "%s" "found a host configuration for %s",
				FNAME, client_conf->name);
		}

		/* preference (if configured) */
		if (ifp->server_pref != DH6OPT_PREF_UNDEF)
			roptinfo.pref = ifp->server_pref;

		/* ToDo: will merger the two configuration file later */
		if ((optinfo->flags & DHCIFF_RAPID_COMMIT) && 
				(ifp->allow_flags & DHCIFF_RAPID_COMMIT)) {
		/*
		 * If the client has included a Rapid Commit option and the
		 * server has been configured to respond with committed address
		 * assignments and other resources, responds to the Solicit
		 * with a Reply message.
		 * [dhcpv6-26 Section 17.2.1]
		 */
			roptinfo.flags |= DHCIFF_RAPID_COMMIT;
			do_binding = 1;
			resptype = DH6_REPLY;
		} else
			resptype = DH6_ADVERTISE;

		if ((optinfo->flags & DHCIFF_RAPID_COMMIT) && 
				(subnet->linkscope.allow_flags & DHCIFF_RAPID_COMMIT)) {
			if (!(optinfo->flags & DHCIFF_INFO_ONLY) || optinfo->iaidinfo.iaid != 0) {
				addr_request = 1;
			}
			roptinfo.flags |= DHCIFF_RAPID_COMMIT;
			resptype = DH6_REPLY;
		} else
			resptype = DH6_ADVERTISE;
		break;
	case DH6_INFORM_REQ:
		/* DNS server */
		if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
			dprintf(LOG_ERR, "%s" "failed to copy DNS servers", FNAME);
			goto fail;
		}
		break;
	case DH6_REQUEST:
		/* get iaid for that request client for that interface */
		if (!(optinfo->flags & DHCIFF_INFO_ONLY) || optinfo->iaidinfo.iaid != 0) {
			addr_request = 1;
		} else
			addr_request = 0;
		/* DNS server */
		if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
			dprintf(LOG_ERR, "%s" "failed to copy DNS servers", FNAME);
			goto fail;
		}
		break;
	/*
	 * Locates the client's binding and verifies that the information
	 * from the client matches the information stored for that client.
	 */
	case DH6_RENEW:
	case DH6_REBIND:
	case DH6_DECLINE:
	case DH6_RELEASE:
		if (dh6->dh6_msgtype == DH6_RENEW || dh6->dh6_msgtype == DH6_REBIND)
			addr_flag = ADDR_UPDATE;
		else 
			addr_flag = ADDR_REMOVE;
		for (lv = TAILQ_FIRST(&optinfo->prefix_list); lv;
	     			lv = TAILQ_NEXT(lv, link)) {
			struct dhcp6_binding *binding;
			binding = find_binding(&optinfo->clientID,
					       DHCP6_CONFINFO_PREFIX,
					       &lv->val_prefix6);
			if (binding == NULL) {
				num = DH6OPT_STCODE_NOBINDING;
				dprintf(LOG_INFO, "%s" "can't find a binding of prefix"
					" %s/%d for %s", FNAME,
					in6addr2str(&lv->val_prefix6.addr, 0),
					lv->val_prefix6.plen,
					duidstr(&optinfo->clientID));
				continue; /* XXX: is this okay? */
			}

			/* we always extend the requested binding. */
			update_binding(binding);

			/* include a Status Code option with value Success. */
			num = DH6OPT_STCODE_SUCCESS;

			if (dhcp6_add_listval(&roptinfo.stcode_list,
		    		&num, DHCP6_LISTVAL_NUM) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add a "
			    		"status code", FNAME);
			}
			/* add the prefix */
			if (dhcp6_add_listval(&roptinfo.prefix_list, binding->val,
		    		DHCP6_LISTVAL_PREFIX6) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add a renewed prefix",
			   		 FNAME);
				goto fail;
			}
		}
		if (!TAILQ_EMPTY(&optinfo->addr_list)) {
			memcpy(&roptinfo.iaidinfo, &optinfo->iaidinfo, 
					sizeof(roptinfo.iaidinfo));
			roptinfo.flags = optinfo->flags;
			dhcp6_copy_list(&roptinfo.addr_list, &optinfo->addr_list);
			if (server6_find_iaidaddr(&roptinfo) == NULL) {
				num = DH6OPT_STCODE_NOBINDING;
				dprintf(LOG_INFO, "%s" "Nobinding for client %s iaid %d",
					FNAME, duidstr(&optinfo->clientID), optinfo->iaidinfo.iaid);
			} else 
#ifdef TEST 
				if (server6_validate_binding(&roptinfo.flags) != 0) { 
				num = DH6OPT_STCODE_NOTONLINK;
				dprintf(LOG_INFO, "%s" "Bindings are not on link for client %s iaid %d",
					FNAME, duidstr(&optinfo->clientID), optinfo->iaidinfo.iaid);
				if (TAILQ_EMPTY(&roptinfo->addr_list))
					num = DH6OPT_STCODE_NOADDRAVAIL;
			} else
				
#endif		
				if (server6_update_iaidaddr(&roptinfo, addr_flag) != 0) {
				num = DH6OPT_STCODE_UNSPECFAIL;
				dprintf(LOG_INFO, "%s" "Bindings failed for client %s iaid %d",
					FNAME, duidstr(&optinfo->clientID), optinfo->iaidinfo.iaid);
				/* status code */	
			} 
			
		} else 
			num = DH6OPT_STCODE_NOADDRAVAIL;
		break;
	case DH6_CONFIRM:
		if (!TAILQ_EMPTY(&optinfo->addr_list)) {
			memcpy(&roptinfo.iaidinfo, &optinfo->iaidinfo, 
					sizeof(roptinfo.iaidinfo)); 
			roptinfo.flags = optinfo->flags;
			dhcp6_copy_list(&roptinfo.addr_list, &optinfo->addr_list);
			if (server6_find_iaidaddr(&roptinfo) == NULL) {
				num = DH6OPT_STCODE_NOBINDING;
				dprintf(LOG_INFO, "%s" "Nobinding for client %s iaid %d",
					FNAME, duidstr(&optinfo->clientID), optinfo->iaidinfo.iaid);
			} else if (server6_validate_iaidaddr(&roptinfo) != 0)  {
					num = DH6OPT_STCODE_NOTONLINK;
				dprintf(LOG_INFO, "%s" "Bindings are not on link for client %s iaid %d",
					FNAME, duidstr(&optinfo->clientID), optinfo->iaidinfo.iaid);
			} 
		}
		break;
	default:
		break;
	}
	/*
 	 * see if we have information for requested options, and if so,
 	 * configure corresponding options.
 	 */
	/*
	 * If the Request message contained an Option Request option, the
	 * server MUST include options in the Reply message for any options in
	 * the Option Request option the server is configured to return to the
	 * client.
	 * [dhcpv6-26 18.2.1]
	 * Note: our current implementation always includes all information
	 * that we can provide.  So we do not have to check the option request
	 * options.
	 */
	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT:
	case DH6_RENEW:
	case DH6_REBIND:
		for (lv = TAILQ_FIRST(&optinfo->reqopt_list); lv;
     				lv = TAILQ_NEXT(lv, link)) {
			switch(lv->val_num) {
			case DH6OPT_PREFIX_DELEGATION:
				create_conflist(DHCP6_CONFINFO_PREFIX,
		    			&optinfo->clientID, &roptinfo.prefix_list,
		    			client_conf ? &client_conf->prefix_list : NULL,
		    			TAILQ_EMPTY(&optinfo->prefix_list) ?
		    			NULL : &optinfo->prefix_list,
		    			do_binding);
			break;
			}
		}
		break;
	default:
		break;
	}
	if (addr_request == 1) {
		/* get per-host configuration for the client, if any. */
		if ((client_conf = find_hostconf(&optinfo->clientID))) {
			dprintf(LOG_DEBUG, "%s" "found a host configuration named %s",
				FNAME, client_conf->name);
		}
		roptinfo.iaidinfo.iaid = optinfo->iaidinfo.iaid;
		if ((host = find_hostdecl(&optinfo->clientID, 
						optinfo->iaidinfo.iaid, hostlist))) {
			dprintf(LOG_DEBUG, "%s" "found a host configuration %d",
				FNAME, host->iaid);
		} else {
			if ((server6_find_iaidaddr(&roptinfo)) == NULL) {
				if (optinfo->flags & DHCIFF_TEMP_ADDRS 
					|| subnet->linkscope.send_flags & DHCIFF_TEMP_ADDRS) 
					server6_create_addrlist(1, subnet, optinfo, &roptinfo); 
				else
					server6_create_addrlist(0, subnet, optinfo, &roptinfo);
				if (!TAILQ_EMPTY(&roptinfo.addr_list)) {
					if (server6_add_iaidaddr(&roptinfo)) {
						dprintf(LOG_ERR, 
						"assigned ipv6address for client iaid %d failed",
							roptinfo.iaidinfo.iaid);
						num = DH6OPT_STCODE_UNSPECFAIL;
					} 
				} else 
					num = DH6OPT_STCODE_NOADDRAVAIL;

			} else 
#ifdef TEST 
				if (server6_validate_binding(&roptinfo) != 0 ){
				}
#endif		
				addr_flag = ADDR_UPDATE;
				if (server6_update_iaidaddr(&roptinfo, addr_flag)) {
					dprintf(LOG_ERR,
						"assigned ipv6address for client iaid %d failed",
						roptinfo.iaidinfo.iaid);
					num = DH6OPT_STCODE_UNSPECFAIL;
			} 
		}
		/*
	 	 * See if we have to make a binding of some configuration information
	 	 * for the client.
	 	 */
		create_conflist(DHCP6_CONFINFO_PREFIX,
	    		&optinfo->clientID, &roptinfo.prefix_list,
	    		client_conf ? &client_conf->prefix_list : NULL,
	    		&optinfo->prefix_list, 1);
	}
	/* add address status code */
  send:
	dprintf(LOG_DEBUG, " status code: %s", dhcp6_stcodestr(num));
	if (dhcp6_add_listval(&roptinfo.stcode_list,
	   	&num, DHCP6_LISTVAL_NUM) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to copy "
	    		"status code", FNAME);
		goto fail;
	}
	/* send a reply message. */
	(void)server6_send(resptype, ifp, dh6, optinfo, from, fromlen,
			   &roptinfo);

  end:
	dhcp6_clear_options(&roptinfo);
	return 0;

  fail:
	dhcp6_clear_options(&roptinfo);
	return -1;
}

static int
server6_send(type, ifp, origmsg, optinfo, from, fromlen, roptinfo)
	int type;
	struct dhcp6_if *ifp;
	struct dhcp6 *origmsg;
	struct dhcp6_optinfo *optinfo, *roptinfo;
	struct sockaddr *from;
	int fromlen;
{
	char replybuf[BUFSIZ];
	struct sockaddr_in6 dst;
	int len, optlen;
	struct dhcp6 *dh6;

	if (sizeof(struct dhcp6) > sizeof(replybuf)) {
		dprintf(LOG_ERR, "%s" "buffer size assumption failed", FNAME);
		return (-1);
	}

	dh6 = (struct dhcp6 *)replybuf;
	len = sizeof(*dh6);
	memset(dh6, 0, sizeof(*dh6));
	dh6->dh6_msgtypexid = origmsg->dh6_msgtypexid;
	dh6->dh6_msgtype = (u_int8_t)type;

	/* set options in the reply message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(replybuf +
							    sizeof(replybuf)),
					roptinfo)) < 0) {
		dprintf(LOG_INFO, "%s" "failed to construct reply options",
			FNAME);
		return (-1);
	}
	len += optlen;

	/* specify the destination and send the reply */
	dst = *sa6_any_downstream;
	dst.sin6_addr = ((struct sockaddr_in6 *)from)->sin6_addr;
	dst.sin6_scope_id = ((struct sockaddr_in6 *)from)->sin6_scope_id;
	if (transmit_sa(outsock, &dst, replybuf, len) != 0) {
		dprintf(LOG_ERR, "%s" "transmit %s to %s failed", FNAME,
			dhcp6msgstr(type), addr2str((struct sockaddr *)&dst));
		return (-1);
	}

	dprintf(LOG_DEBUG, "%s" "transmit %s to %s", FNAME,
		dhcp6msgstr(type), addr2str((struct sockaddr *)&dst));

	return 0;
}

static int
create_conflist(type, clientid, ret_list, conf_list, req_list, do_binding)
	dhcp6_conftype_t type;
	struct duid *clientid;
	struct dhcp6_list *ret_list, *conf_list, *req_list;
	int do_binding;
{
	struct dhcp6_listval *clv;
	struct dhcp6_binding *binding;
	void *val;

	if (conf_list == NULL)
		return 0;

	/* sanity check about type */
	switch(type) {
	case DHCP6_CONFINFO_PREFIX:
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected configuration type(%d)",
			FNAME, type);
		exit(1);
	}

	for (clv = TAILQ_FIRST(conf_list); clv; clv = TAILQ_NEXT(clv, link)) {
		struct dhcp6_listval *dl;

		/* 
		 * If the client explicitly specified a list of option values,
		 * we only return those specified values (if authorized). 
		 */
		if (req_list) {
			switch(type) {
			case DHCP6_CONFINFO_PREFIX:
				if (dhcp6_find_listval(req_list,
				    &clv->val_prefix6,
				    DHCP6_LISTVAL_PREFIX6) == NULL) {
					continue;
				}
				break;
			}
		}

		/*
		 * TODO: check if the requesting router is authorized.
		 */
		;

		/*
		 * If we already have a binding for the prefix, the request
		 * is probably being retransmitted or the information is being
		 * renewed.  Then just update the timer of the binding.
		 * Otherwise, create a binding for the prefix.
		 */
		if (do_binding) {
			if ((binding = find_binding(clientid, type, &clv->uv)))
				update_binding(binding);
			else if ((binding = add_binding(clientid, type,
							&clv->uv)) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to create a "
					"binding");
				continue;
			}
			val = binding->val;
		} else
			val = (void *)&clv->uv;

		/* add the entry to the returned list */
		if ((dl = malloc(sizeof(*dl))) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to allocate "
				"memory for prefix", FNAME);
			continue; /* XXX: remove binding? */
		}
		switch(type) {
		case DHCP6_CONFINFO_PREFIX:
			dl->val_prefix6 = *(struct dhcp6_prefix *)val;
			break;
		}

		TAILQ_INSERT_TAIL(ret_list, dl, link);
	}

	return 0;
}

static struct dhcp6_binding *
add_binding(clientid, type, val0)
	struct duid *clientid;
	dhcp6_conftype_t type;
	void *val0;
{
	struct dhcp6_binding *binding = NULL;
	u_int32_t duration = DHCP6_DURATITION_INFINITE;
	char *val = NULL;

	if ((binding = malloc(sizeof(*binding))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory", FNAME);
		return (NULL);
	}
	memset(binding, 0, sizeof(*binding));
	binding->type = type;
	if (duidcpy(&binding->clientid, clientid)) {
		dprintf(LOG_ERR, "%s" "failed to copy DUID");
		goto fail;
	}

	switch(type) {
	case DHCP6_CONFINFO_PREFIX:
		duration = ((struct dhcp6_prefix *)val0)->duration;
		if ((val = malloc(sizeof(struct dhcp6_prefix))) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to allocate memory for "
				"prefix");
			goto fail;
		}
		memcpy(val, val0, sizeof(struct dhcp6_prefix));
		binding->val = val;
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected binding type(%d)", FNAME,
			type);
		exit(1);
	}

	binding->duration = duration;
	if (duration != DHCP6_DURATITION_INFINITE) {
		struct timeval timo;

		binding->timer = dhcp6_add_timer(binding_timo, binding);
		if (binding->timer == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add timer", FNAME);
			goto fail;
		}
		timo.tv_sec = (long)duration;
		timo.tv_usec = 0;
		dhcp6_set_timer(&timo, binding->timer);
	}

	TAILQ_INSERT_TAIL(&dhcp6_binding_head, binding, link);

	dprintf(LOG_DEBUG, "%s" "add a new binding %s for %s", FNAME,
		bindingstr(binding), duidstr(clientid));

	return (binding);

  fail:
	if (binding) {
		duidfree(&binding->clientid);
		free(binding);
	}
	if (val)
		free(val);
	return (NULL);
}

static struct dhcp6_binding *
find_binding(clientid, type, val0)
	struct duid *clientid;
	dhcp6_conftype_t type;
	void *val0;
{
	struct dhcp6_binding *bp;
	struct dhcp6_prefix *pfx0, *pfx;

	for (bp = TAILQ_FIRST(&dhcp6_binding_head); bp;
	     bp = TAILQ_NEXT(bp, link)) {
		if (bp->type != type ||
		    duidcmp(&bp->clientid, clientid)) {
			continue;
		}

		switch(type) {
		case DHCP6_CONFINFO_PREFIX:
			pfx0 = (struct dhcp6_prefix *)val0;
			pfx = (struct dhcp6_prefix *)bp->val;
			if (pfx0->plen == pfx->plen &&
			    IN6_ARE_ADDR_EQUAL(&pfx0->addr, &pfx->addr)) {
				return (bp);
			}
			break;
		default:
			dprintf(LOG_ERR,
				"%s" "unexpected binding type(%d)", FNAME,
				type);
			exit(1);
		}
	}

	return (NULL);
}

static void
update_binding(binding)
	struct dhcp6_binding *binding;
{
	struct timeval timo;

	/* if the lease duration is infinite, there's nothing to do. */
	if (binding->duration == DHCP6_DURATITION_INFINITE)
		return;

	/* reset the timer with the duration */
	timo.tv_sec = (long)binding->duration;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, binding->timer);

	dprintf(LOG_DEBUG, "%s" "update a binding %s for %s", FNAME,
		bindingstr(binding), duidstr(&binding->clientid));
}

static void
remove_binding(binding)
	struct dhcp6_binding *binding;
{
	void *val = binding->val;

	dprintf(LOG_DEBUG, "%s" "removing a binding %s for %s", FNAME,
		bindingstr(binding), duidstr(&binding->clientid));

	if (binding->timer)
		dhcp6_remove_timer(&binding->timer);

	TAILQ_REMOVE(&dhcp6_binding_head, binding, link);

	switch(binding->type) {
	case DHCP6_CONFINFO_PREFIX:
		dprintf(LOG_INFO, "%s" "remove prefix binding %s/%d for %s",
			FNAME,
			in6addr2str(&((struct dhcp6_prefix *)val)->addr, 0),
			((struct dhcp6_prefix *)val)->plen,
			duidstr(&binding->clientid));
		free(binding->val);
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected binding type(%d)", FNAME,
			binding->type);
		exit(1);
	}

	duidfree(&binding->clientid);
	free(binding);
}

static struct dhcp6_timer *
binding_timo(arg)
	void *arg;
{
	struct dhcp6_binding *binding = (struct dhcp6_binding *)arg;

	remove_binding(binding);

	return NULL;
}

static char *
bindingstr(binding)
	struct dhcp6_binding *binding;
{
	struct dhcp6_prefix *pfx;
	static char strbuf[LINE_MAX];	/* XXX: thread unsafe */

	switch(binding->type) {
	case DHCP6_CONFINFO_PREFIX:
		pfx = (struct dhcp6_prefix *)binding->val;
		snprintf(strbuf, sizeof(strbuf),
			 "[prefix: %s/%d, duration=%ld]",
			 in6addr2str(&pfx->addr, 0), pfx->plen,
			 (unsigned long)binding->duration);
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected binding type(%d)", FNAME,
			binding->type);
		exit(1);
	}

	return (strbuf);
}
