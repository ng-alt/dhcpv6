/*	$Id: dhcp6s.c,v 1.7 2003/02/27 19:43:08 shemminger Exp $	*/
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

#include "queue.h"
#include "timer.h"
#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "server6_conf.h"
#include "lease.h"

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
extern FILE *server6_lease_file;
char server6_lease_temp[256] = "/var/db/dhcpv6/server6.leasesXXXXXX";

static const struct sockaddr_in6 *sa6_any_downstream;
static struct msghdr rmh;
static char rdatabuf[BUFSIZ];
static int rmsgctllen;
static char *rmsgctlbuf;
static struct duid server_duid;
static struct dhcp6_list arg_dnslist;
struct link_decl *subnet = NULL;
struct rootgroup *globalgroup = NULL;

#define DUID_FILE "/var/db/dhcpv6/dhcp6s_duid"
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
extern struct link_decl *dhcp6_allocate_link __P((struct rootgroup *, struct in6_addr *));

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
		dprintf(LOG_ERR, "failed to allocate memory %s", strerror(errno));
		exit(1);
	}
	memset(globalgroup, 0, sizeof(*globalgroup));
	if ((sfparse(addr_conffile)) != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse addr configuration file",
			FNAME);
		exit(1);
	}
	
	server6_init();
	if ((server6_lease_file = init_leases(PATH_SERVER6_LEASE)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to parse lease file",
			FNAME);
		exit(1);
	}
	server6_lease_file = 
		sync_leases(server6_lease_file, PATH_SERVER6_LEASE, server6_lease_temp);	
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
		dprintf(LOG_ERR, "%s" "setsockopt(insock, IPV6_JOIN_GROUP) %s",
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
	subnet = dhcp6_allocate_link(globalgroup, NULL);
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
	int addr_flag;
	int addr_request = 0;
	int resptype = DH6_REPLY;
	int num = DH6OPT_STCODE_SUCCESS;

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
		 * [dhcpv6-28 Section 17.2.1]
		 */
			roptinfo.flags |= DHCIFF_RAPID_COMMIT;
			resptype = DH6_REPLY;
		} else
			resptype = DH6_ADVERTISE;

		/* [dhcpv6-28 Section 17.2.2] */
		if (optinfo->iaidinfo.iaid != 0) {
			memcpy(&roptinfo.iaidinfo, &optinfo->iaidinfo, 
					sizeof(roptinfo.iaidinfo));
			roptinfo.type = optinfo->type;
			dprintf(LOG_DEBUG, "option type is %d", roptinfo.type);
			addr_request = 1;
			resptype = DH6_ADVERTISE;
						
		}
		if ((optinfo->flags & DHCIFF_RAPID_COMMIT) && 
				(subnet->linkscope.allow_flags & DHCIFF_RAPID_COMMIT)) {
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
		if (optinfo->iaidinfo.iaid != 0) {
			memcpy(&roptinfo.iaidinfo, &optinfo->iaidinfo, 
					sizeof(roptinfo.iaidinfo));
			roptinfo.type = optinfo->type;
			addr_request = 1;
		} 
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
	case DH6_CONFIRM:
		if (dh6->dh6_msgtype == DH6_RENEW || dh6->dh6_msgtype == DH6_REBIND)
			addr_flag = ADDR_UPDATE;
		if (dh6->dh6_msgtype == DH6_RELEASE)
			addr_flag = ADDR_REMOVE;
		if (dh6->dh6_msgtype == DH6_CONFIRM)
			addr_flag = ADDR_VALIDATE;
		if (dh6->dh6_msgtype == DH6_DECLINE)
			addr_flag = ADDR_ABANDON;
	if (optinfo->iaidinfo.iaid != 0) {
		if (!TAILQ_EMPTY(&optinfo->addr_list)) {
			struct dhcp6_iaidaddr *iaidaddr;
			memcpy(&roptinfo.iaidinfo, &optinfo->iaidinfo, 
					sizeof(roptinfo.iaidinfo));
			roptinfo.type = optinfo->type;
			/* find bindings */
			if ((iaidaddr = dhcp6_find_iaidaddr(&roptinfo)) == NULL) {
				num = DH6OPT_STCODE_NOBINDING;
				dprintf(LOG_INFO, "%s" "Nobinding for client %s iaid %d",
					FNAME, duidstr(&optinfo->clientID), 
						optinfo->iaidinfo.iaid);
				break;
			}
			if (addr_flag != ADDR_UPDATE) {
				dhcp6_copy_list(&roptinfo.addr_list, &optinfo->addr_list);
			} else {
				if (optinfo->type == IAPD)
					dhcp6_create_prefixlist(&roptinfo, optinfo, 
							iaidaddr, subnet);
				else
					dhcp6_create_addrlist(&roptinfo, optinfo, 
							iaidaddr, subnet);
				/* in case there is not bindings available */
				if (TAILQ_EMPTY(&roptinfo.addr_list)) {
					num = DH6OPT_STCODE_NOTONLINK;
					dprintf(LOG_INFO, "%s" 
					    "Bindings are not on link for client %s iaid %d",
						FNAME, duidstr(&optinfo->clientID), 
						roptinfo.iaidinfo.iaid);
					break;
				}
			}
			if (addr_flag == ADDR_VALIDATE) {
				if (dhcp6_validate_bindings(&roptinfo, iaidaddr))
					num = DH6OPT_STCODE_NOTONLINK;
				break;
			} else {
				/* do update if this is not a confirm */
				if (dhcp6_update_iaidaddr(&roptinfo, addr_flag) 
						!= 0) {
					dprintf(LOG_INFO, "%s" 
						"bindings failed for client %s iaid %d",
						FNAME, duidstr(&optinfo->clientID), 
							roptinfo.iaidinfo.iaid);
					num = DH6OPT_STCODE_UNSPECFAIL;
					break;
				}
			}
			num = DH6OPT_STCODE_SUCCESS;
		} else 
			num = DH6OPT_STCODE_NOADDRAVAIL;
	} else 
		dprintf(LOG_ERR, "invalid message type");
		break;
	default:
		break;
	}
	/*
 	 * XXX: see if we have information for requested options, and if so,
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
	if (addr_request == 1) {
		int found_binding = 0;
		struct dhcp6_iaidaddr *iaidaddr;
		/* get per-host configuration for the client, if any. */
		if ((client_conf = find_hostconf(&optinfo->clientID))) {
			dprintf(LOG_DEBUG, "%s" "found a host configuration named %s",
				FNAME, client_conf->name);
		}
		/* find bindings */
		if ((iaidaddr = dhcp6_find_iaidaddr(&roptinfo)) != NULL) {
			found_binding = 1;
			addr_flag = ADDR_UPDATE;
		}
		/* valid and create addresses list */
		if (optinfo->type == IAPD)
			dhcp6_create_prefixlist(&roptinfo, optinfo, iaidaddr, subnet);
		else
			dhcp6_create_addrlist(&roptinfo, optinfo, iaidaddr, subnet);
		if (TAILQ_EMPTY(&roptinfo.addr_list)) {
			num = DH6OPT_STCODE_NOADDRAVAIL;
		} else {
		/* valid client request address list */
			if (found_binding) {
			       if (dhcp6_update_iaidaddr(&roptinfo, addr_flag) != 0) {
					dprintf(LOG_ERR,
					"assigned ipv6address for client iaid %d failed",
						roptinfo.iaidinfo.iaid);
					num = DH6OPT_STCODE_UNSPECFAIL;
			       } else
					num = DH6OPT_STCODE_SUCCESS;
			} else {
			       	if (dhcp6_add_iaidaddr(&roptinfo) != 0) {
					dprintf(LOG_ERR, 
					"assigned ipv6address for client iaid %d failed",
						roptinfo.iaidinfo.iaid);
					num = DH6OPT_STCODE_UNSPECFAIL;
				} else
					num = DH6OPT_STCODE_SUCCESS;
			}
		}
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

