/*	$Id: dhcp6c.c,v 1.13 2003/04/03 19:08:37 shirleyma Exp $	*/
/*	ported from KAME: dhcp6c.c,v 1.97 2002/09/24 14:20:49 itojun Exp */

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
#include <sys/uio.h>

#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <sys/timeb.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>

#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <ifaddrs.h>

#include "queue.h"
#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "lease.h"

static int debug = 0;
static u_long sig_flags = 0;
#define SIGF_TERM 0x1
#define SIGF_HUP 0x2
#define DHCP6S_VALID_REPLY(a) \
	(a == DHCP6S_REQUEST || a == DHCP6S_RENEW || \
	 a == DHCP6S_REBIND || a == DHCP6S_DECLINE || \
	 a == DHCP6S_RELEASE || a == DHCP6S_CONFIRM || \
	 a == DHCP6S_INFOREQ)

const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_CLIENT;

char *device = NULL;
static struct iaid_table iaidtab[50];
static u_int8_t client6_request_flag = 0;

#define CLIENT6_RELEASE_ADDR	0x1
#define CLIENT6_CONFIRM_ADDR	0x2
#define CLIENT6_REQUEST_ADDR	0x4
#define CLIENT6_INFO_REQ	0x8

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
int rtsock;	/* routing socket */


extern FILE *client6_lease_file;
extern struct dhcp6_iaidaddr client6_iaidaddr;

static const struct sockaddr_in6 *sa6_allagent;
static struct duid client_duid;

static void usage __P((void));
static void client6_init __P((char *));
static void client6_ifinit __P((void));
void free_servers __P((struct dhcp6_if *));
static void free_resources __P((void));
static void client6_mainloop __P((void));
static void process_signals __P((void));
static struct dhcp6_serverinfo *find_server __P((struct dhcp6_if *,
						 struct duid *));
static struct dhcp6_serverinfo *allocate_newserver __P((struct dhcp6_if *, struct dhcp6_optinfo *));
static struct dhcp6_serverinfo *select_server __P((struct dhcp6_if *));
void client6_send __P((struct dhcp6_event *));
int client6_send_newstate __P((struct dhcp6_if *, int));
static void client6_recv __P((void));
static int client6_recvadvert __P((struct dhcp6_if *, struct dhcp6 *,
				   ssize_t, struct dhcp6_optinfo *));
static int client6_recvreply __P((struct dhcp6_if *, struct dhcp6 *,
				  ssize_t, struct dhcp6_optinfo *));
static void client6_signal __P((int));
static struct dhcp6_event *find_event_withid __P((struct dhcp6_if *,
						  u_int32_t));
struct dhcp6_timer *client6_timo __P((void *));
extern int client6_ifaddrconf __P((ifaddrconf_cmd_t, struct dhcp6_addr *));

#define DHCP6C_CONF "/etc/dhcp6c.conf"
#define DHCP6C_PIDFILE "/var/run/dhcpv6/dhcp6c.pid"
#define DUID_FILE "/var/db/dhcpv6/dhcp6c_duid"
char client6_lease_temp[256];
struct dhcp6_list request_list;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch, pid;
	char *progname, *conffile = DHCP6C_CONF;
	FILE *pidfp;
	char *addr;

	srandom(time(NULL) & getpid());

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	TAILQ_INIT(&request_list);
	while ((ch = getopt(argc, argv, "c:r:R:P:dDfI")) != -1) {
		switch (ch) {
		case 'c':
			conffile = optarg;
			break;
		case 'P':
			client6_request_flag |= CLIENT6_REQUEST_ADDR;
			for (addr = strtok(optarg, " "); addr; 
					addr = strtok(NULL, " ")) {
				struct dhcp6_listval *lv;
				if ((lv = 
					(struct dhcp6_listval *)malloc(sizeof(*lv)))
						== NULL) {
					dprintf(LOG_ERR, "failed to allocate memory");
					exit(1);
				}
				memset(lv, 0, sizeof(*lv));
				if (inet_pton(AF_INET6, strtok(addr, "/"), 
						&lv->val_dhcp6addr.addr) < 1) {
					dprintf(LOG_ERR, 
						"invalid ipv6address for release");
					usage();
					exit(1);
				}
				lv->val_dhcp6addr.type = IAPD;
				lv->val_dhcp6addr.plen = atoi(strtok(NULL, "/"));
				lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
				TAILQ_INSERT_TAIL(&request_list, lv, link);
			} 
			break;

		case 'R':
			client6_request_flag |= CLIENT6_REQUEST_ADDR;
			for (addr = strtok(optarg, " "); addr; 
					addr = strtok(NULL, " ")) {
				struct dhcp6_listval *lv;
				if ((lv = 
					(struct dhcp6_listval *)malloc(sizeof(*lv)))
						== NULL) {
					dprintf(LOG_ERR, "failed to allocate memory");
					exit(1);
				}
				memset(lv, 0, sizeof(*lv));
				if (inet_pton(AF_INET6, addr, 
						&lv->val_dhcp6addr.addr) < 1) {
					dprintf(LOG_ERR, 
						"invalid ipv6address for release");
					usage();
					exit(1);
				}
				lv->val_dhcp6addr.type = IANA;
				lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
				TAILQ_INSERT_TAIL(&request_list, lv, link);
			} 
			break;
		case 'r':
			client6_request_flag |= CLIENT6_RELEASE_ADDR;
			if (strcmp(optarg, "all")) {
				for (addr = strtok(optarg, " "); addr; 
						addr = strtok(NULL, " ")) {
					struct dhcp6_listval *lv;
					if ((lv = 
						(struct dhcp6_listval *)malloc(sizeof(*lv)))
							== NULL) {
						dprintf(LOG_ERR, "failed to allocate memory");
						exit(1);
					}
					memset(lv, 0, sizeof(*lv));
					if (inet_pton(AF_INET6, addr, 
							&lv->val_dhcp6addr.addr) < 1) {
						dprintf(LOG_ERR, 
							"invalid ipv6address for release");
						usage();
						exit(1);
					}
					lv->val_dhcp6addr.type = IANA;
					TAILQ_INSERT_TAIL(&request_list, lv, link);
				}
			} 
			break;
		case 'I':
			client6_request_flag |= CLIENT6_INFO_REQ;
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
		default:
			usage();
			exit(0);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		exit(0);
	}
	device = argv[0];

	if (foreground == 0) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
	}
	setloglevel(debug);

	/* dump current PID */
	pid = getpid();
	if ((pidfp = fopen(DHCP6C_PIDFILE, "w")) != NULL) {
		fprintf(pidfp, "%d\n", pid);
		fclose(pidfp);
	}

	ifinit(device);

	if ((cfparse(conffile)) != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse configuration file",
			FNAME);
		exit(1);
	}
	client6_init(device);
	client6_ifinit();
	client6_mainloop();
	exit(0);
}

static void
usage()
{

	fprintf(stderr, 
	"usage: dhcpc [-c configfile] [-r all or (ipv6address ipv6address...)]"
	"[-R (ipv6 address ipv6address...) [-dDIf] interface\n");
}

/*------------------------------------------------------------*/

void
client6_init(device)
	char *device;
{
	struct addrinfo hints, *res;
	static struct sockaddr_in6 sa6_allagent_storage;
	int error, on = 1;
	struct dhcp6_if *ifp;
	int ifidx;

	ifidx = if_nametoindex(device);
	if (ifidx == 0) {
		dprintf(LOG_ERR, "if_nametoindex(%s)", device);
		exit(1);
	}

	/* get our DUID */
	if (get_duid(DUID_FILE, &client_duid)) {
		dprintf(LOG_ERR, "%s" "failed to get a DUID", FNAME);
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		dprintf(LOG_ERR, "%s" "socket(inbound)", FNAME);
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
		dprintf(LOG_ERR, "%s" "bind(inbonud): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		dprintf(LOG_ERR, "%s" "socket(outbound): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(outbound, IPV6_MULTICAST_IF): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(outsock, IPV6_MULTICAST_LOOP): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	/* make the socket write-only */
	freeaddrinfo(res);

	/* open a routing socket to watch the routing table */
	if ((rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "open a routing socket: %s",
			FNAME, strerror(errno));
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memcpy(&sa6_allagent_storage, res->ai_addr, res->ai_addrlen);
	sa6_allagent = (const struct sockaddr_in6 *)&sa6_allagent_storage;
	freeaddrinfo(res);

	/* client interface configuration */
	if ((ifp = find_ifconfbyname(device)) == NULL) {
		dprintf(LOG_ERR, "%s" "interface %s not configured",
			FNAME, device);
		exit(1);
	}
	ifp->outsock = outsock;

	if (signal(SIGHUP, client6_signal) == SIG_ERR) {
		dprintf(LOG_WARNING, "%s" "failed to set signal: %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (signal(SIGTERM, client6_signal) == SIG_ERR) {
		dprintf(LOG_WARNING, "%s" "failed to set signal: %s",
			FNAME, strerror(errno));
		exit(1);
	}
}

static void
client6_ifinit()
{
	struct dhcp6_if *ifp;
	struct dhcp6_event *ev;
	char iaidstr[20];
	char leasename[50];

	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		dhcp6_init_iaidaddr();
		/* get iaid for each interface */
		if ((ifp->iaidinfo.iaid = get_iaid(ifp->ifname, iaidtab)) == 0) {
			create_iaid(iaidtab);
			ifp->iaidinfo.iaid = get_iaid(ifp->ifname, iaidtab);
			dprintf(LOG_DEBUG, "%s" "interface %s iaid is %d", 
				FNAME, ifp->ifname, ifp->iaidinfo.iaid);
		}
		client6_iaidaddr.ifp = ifp;
		memcpy(&client6_iaidaddr.client6_info.iaidinfo, &ifp->iaidinfo, 
				sizeof(client6_iaidaddr.client6_info.iaidinfo));
		duidcpy(&client6_iaidaddr.client6_info.clientid, &client_duid);
		/* parse the lease file */
		strcpy(leasename, PATH_CLIENT6_LEASE);
		sprintf(iaidstr, "%d", ifp->iaidinfo.iaid);
		strcat(leasename, iaidstr);
		if ((client6_lease_file = 
			init_leases(leasename)) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to parse lease file", FNAME);
			exit(1);
		}
		strcpy(client6_lease_temp, leasename);
		strcat(client6_lease_temp, "XXXXXX");
		client6_lease_file = 
			sync_leases(client6_lease_file, leasename, client6_lease_temp);

		if (!TAILQ_EMPTY(&client6_iaidaddr.lease_list)) {
			struct dhcp6_lease *cl;
			struct dhcp6_listval *lv;
			if (!(client6_request_flag & CLIENT6_REQUEST_ADDR) && 
					!(client6_request_flag & CLIENT6_RELEASE_ADDR))
				client6_request_flag |= CLIENT6_CONFIRM_ADDR;
			if (TAILQ_EMPTY(&request_list)) {
				/* create an address list for release all/confirm */
				for (cl = TAILQ_FIRST(&client6_iaidaddr.lease_list); cl; 
					cl = TAILQ_NEXT(cl, link)) {
					/* IANA, IAPD */
					if ((lv = malloc(sizeof(*lv))) == NULL) {
						dprintf(LOG_ERR, "%s" 
					"failed to allocate memory for an ipv6 addr", FNAME);
			 			exit(1);
					}
					memcpy(&lv->val_dhcp6addr, &cl->lease_addr, 
						sizeof(lv->val_dhcp6addr));
					lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
					TAILQ_INSERT_TAIL(&request_list, lv, link);
					/* config the interface for reboot */
					if (cl->lease_addr.type == IAPD) {
						dprintf(LOG_INFO, "get prefix %s/%d",
							in6addr2str(&cl->lease_addr.addr, 0),
							cl->lease_addr.plen);
						/* XXX:	what to do for PD */
						continue;
					} else if ((client6_request_flag & CLIENT6_CONFIRM_ADDR) 
						    && client6_ifaddrconf(IFADDRCONF_ADD,
						    &cl->lease_addr) != 0) {
						dprintf(LOG_INFO, "config address failed: %s",
							in6addr2str(&cl->lease_addr.addr, 0));
						exit(1);
					}
					
				}
			} else if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
				for (lv = TAILQ_FIRST(&request_list); lv; 
						lv = TAILQ_NEXT(lv, link)) {
					if (dhcp6_find_lease(&client6_iaidaddr, 
							&lv->val_dhcp6addr) == NULL) {
						dprintf(LOG_INFO, "this address %s is not"
							" leased by this client", 
						    in6addr2str(&lv->val_dhcp6addr.addr,0));
						exit(0);
					}
				}
			}	
		} else if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
			dprintf(LOG_INFO, "no ipv6 addresses are leased by client");
			exit(0);
		}
		
		/* create an event for the initial delay */
		if ((ev = dhcp6_create_event(ifp, DHCP6S_INIT)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to create an event",
				FNAME);
			exit(1);
		}
		ifp->servers = NULL;
		ev->ifp->current_server = NULL;
		TAILQ_INSERT_TAIL(&ifp->event_list, ev, link);
		if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a timer for %s",
				FNAME, ifp->ifname);
			exit(1);
		}
		dhcp6_reset_timer(ev);
	}
}

static void
free_resources()
{
	struct dhcp6_if *ifp;
	
	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		struct dhcp6_event *ev, *ev_next;
		dprintf(LOG_DEBUG, "%s" " remove all events on interface", FNAME);
		/* cancel all outstanding events for each interface */
		for (ev = TAILQ_FIRST(&ifp->event_list); ev; ev = ev_next) {
			ev_next = TAILQ_NEXT(ev, link);
			dhcp6_remove_event(ev);
		}
		free_servers(ifp);
	}
}

static void
process_signals()
{
	if ((sig_flags & SIGF_TERM)) {
		dprintf(LOG_INFO, FNAME "exiting");
		free_resources();
		unlink(DHCP6C_PIDFILE);
		exit(0);
	}
	if ((sig_flags & SIGF_HUP)) {
		dprintf(LOG_INFO, FNAME "restarting");
		free_resources();
		client6_ifinit();
	}

	sig_flags = 0;
}

static void
client6_mainloop()
{
	struct timeval *w;
	int ret;
	fd_set r;

	while(1) {
		if (sig_flags)
			process_signals();
		dprintf(LOG_DEBUG, "%s" " called", FNAME);
		w = dhcp6_check_timer();

		FD_ZERO(&r);
		FD_SET(insock, &r);

		ret = select(insock + 1, &r, NULL, NULL, w);
		switch (ret) {
		case -1:
			if (errno != EINTR) {
				dprintf(LOG_ERR, "%s" "select: %s",
				    FNAME, strerror(errno));
				exit(1);
			}
			break;
		case 0:	/* timeout */
			break;	/* dhcp6_check_timer() will treat the case */
		default: /* received a packet */
			client6_recv();
		}
	}
}

struct dhcp6_timer *
client6_timo(arg)
	void *arg;
{
	struct dhcp6_event *ev = (struct dhcp6_event *)arg;
	struct dhcp6_if *ifp;
	struct timeval now;
	struct ra_info *rainfo;
#ifdef TEST
	int mbitset = 0;
#else
	int mbitset = 1;
#endif
	ifp = ev->ifp;
	ev->timeouts++;
	gettimeofday(&now, NULL);
	if ((ev->max_retrans_cnt && ev->timeouts >= ev->max_retrans_cnt) ||
	    (ev->max_retrans_dur && (now.tv_sec - ev->start_time.tv_sec) 
	     >= ev->max_retrans_dur)) {
		/* XXX: check up the duration time for renew & rebind */
		dprintf(LOG_INFO, "%s" "no responses were received", FNAME);
		dhcp6_remove_event(ev);	/* XXX: should free event data? */
		return (NULL);
	}

	switch(ev->state) {
	case DHCP6S_INIT:
		/* From INIT state client could
		 * go to CONFIRM state if the client reboots;
		 * go to RELEASE state if the client issues a release;
		 * go to INFOREQ state if the client requests info-only;
		 * go to SOLICIT state if the client requests addresses;
		 */
		ev->timeouts = 0; /* indicate to generate a new XID. */
		/* check RA flags M bits */
		for (rainfo = ifp->ralist; rainfo; rainfo = rainfo->next) {
			if (rainfo->flags & RA_MBIT_SET) {
				mbitset = 1;
				break;
			}
		}
		if ((ifp->send_flags & DHCIFF_INFO_ONLY) || 
		    (client6_request_flag & CLIENT6_INFO_REQ) || mbitset == 0)
			ev->state = DHCP6S_INFOREQ;
		else if (client6_request_flag & CLIENT6_RELEASE_ADDR) 
			/* do release */
			ev->state = DHCP6S_RELEASE;
		else if (client6_request_flag & CLIENT6_CONFIRM_ADDR) {
			struct dhcp6_listval *lv;
			/* do confirm for reboot for IANA, IATA*/
			if (client6_iaidaddr.client6_info.type == IAPD)
				ev->state = DHCP6S_REBIND;
			else
				ev->state = DHCP6S_CONFIRM;
			for (lv = TAILQ_FIRST(&request_list); lv; 
					lv = TAILQ_NEXT(lv, link)) {
				lv->val_dhcp6addr.preferlifetime = 0;
				lv->val_dhcp6addr.validlifetime = 0;
			}
		} else
			ev->state = DHCP6S_SOLICIT;
		dhcp6_set_timeoparam(ev);
	case DHCP6S_SOLICIT:
		if (ifp->servers) {
			ifp->current_server = select_server(ifp);
			if (ifp->current_server == NULL) {
				/* this should not happen! */
				dprintf(LOG_ERR, "%s" "can't find a server",
					FNAME);
				exit(1); /* XXX */
			}
			/* if get the address assginment break */
			if (!TAILQ_EMPTY(&client6_iaidaddr.lease_list)) {
				dhcp6_remove_event(ev);
				return (NULL);
			}
			ev->timeouts = 0;
			ev->state = DHCP6S_REQUEST;
			dhcp6_set_timeoparam(ev);
		}
	case DHCP6S_INFOREQ:
	case DHCP6S_REQUEST:
		client6_send(ev);
		break;
	case DHCP6S_RELEASE:
	case DHCP6S_DECLINE:
	case DHCP6S_CONFIRM:
	case DHCP6S_RENEW:
	case DHCP6S_REBIND:
		if (!TAILQ_EMPTY(&request_list))
			client6_send(ev);
		else {
			dprintf(LOG_INFO, "%s"
		    		"all information to be updated were canceled",
		    		FNAME);
			dhcp6_remove_event(ev);
			return (NULL);
		}
		break;
	default:
		break;
	}
	dhcp6_reset_timer(ev);
	return (ev->timer);
}

static struct dhcp6_serverinfo *
select_server(ifp)
	struct dhcp6_if *ifp;
{
	struct dhcp6_serverinfo *s;

	/*
	 * pick the best server according to dhcpv6-26 Section 17.1.3
	 * XXX: we currently just choose the one that is active and has the
	 * highest preference.
	 */
	for (s = ifp->servers; s; s = s->next) {
		if (s->active) {
			dprintf(LOG_DEBUG, "%s" "picked a server (ID: %s)",
				FNAME, duidstr(&s->optinfo.serverID));
			return (s);
		}
	}

	return (NULL);
}

static void
client6_signal(sig)
	int sig;
{

	dprintf(LOG_INFO, FNAME "received a signal (%d)", sig);

	switch (sig) {
	case SIGTERM:
		sig_flags |= SIGF_TERM;
		break;
	case SIGHUP:
		sig_flags |= SIGF_HUP;
		break;
	}
}

void
client6_send(ev)
	struct dhcp6_event *ev;
{
	struct dhcp6_if *ifp;
	char buf[BUFSIZ];
	struct sockaddr_in6 dst;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo optinfo;
	ssize_t optlen, len;
	struct timeval duration, now;

	ifp = ev->ifp;

	dh6 = (struct dhcp6 *)buf;
	memset(dh6, 0, sizeof(*dh6));

	switch(ev->state) {
	case DHCP6S_SOLICIT:
		dh6->dh6_msgtype = DH6_SOLICIT;
		break;
	case DHCP6S_REQUEST:
		if (ifp->current_server == NULL) {
			dprintf(LOG_ERR, "%s" "assumption failure", FNAME);
			exit(1); /* XXX */
		}
		dh6->dh6_msgtype = DH6_REQUEST;
		break;
	case DHCP6S_RENEW:
		if (ifp->current_server == NULL) {
			dprintf(LOG_ERR, "%s" "assumption failure", FNAME);
			exit(1); /* XXX */
		}
		dh6->dh6_msgtype = DH6_RENEW;
		break;
	case DHCP6S_DECLINE:
		if (ifp->current_server == NULL) {
			dprintf(LOG_ERR, "%s" "assumption failure", FNAME);
			exit(1); /* XXX */
		}
		dh6->dh6_msgtype = DH6_DECLINE;
		break;
	case DHCP6S_INFOREQ:	
		dh6->dh6_msgtype = DH6_INFORM_REQ;
		break;
	case DHCP6S_REBIND:
		dh6->dh6_msgtype = DH6_REBIND;
		break;
	case DHCP6S_CONFIRM:
		dh6->dh6_msgtype = DH6_CONFIRM;
		break;
	case DHCP6S_RELEASE:
		dh6->dh6_msgtype = DH6_RELEASE;
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected state %d", FNAME, ev->state);
		exit(1);	/* XXX */
	}
	/*
	 * construct options
	 */
	dhcp6_init_options(&optinfo);
	if (ev->timeouts == 0) {
		gettimeofday(&ev->start_time, NULL);
		optinfo.elapsed_time = 0;
		/*
		 * A client SHOULD generate a random number that cannot easily
		 * be guessed or predicted to use as the transaction ID for
		 * each new message it sends.
		 *
		 * A client MUST leave the transaction-ID unchanged in
		 * retransmissions of a message. [dhcpv6-26 15.1]
		 */
		ev->xid = random() & DH6_XIDMASK;
		dprintf(LOG_DEBUG, "%s" "ifp %p event %p a new XID (%x) is generated",
			FNAME, ifp, ev, ev->xid);
	} else {
		gettimeofday(&now, NULL);
		timeval_sub(&now, &(ev->start_time), &duration);
		optinfo.elapsed_time = (duration.tv_sec) * 1000 + (duration.tv_usec) / 1000000;
	}
	dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
	dh6->dh6_xid |= htonl(ev->xid);
	len = sizeof(*dh6);


	/* server ID */
	switch(ev->state) {
	case DHCP6S_REQUEST:
	case DHCP6S_RENEW:
	case DHCP6S_DECLINE:
		if (&ifp->current_server->optinfo == NULL)
			exit(1);
		dprintf(LOG_DEBUG, "current server ID %s",
			duidstr(&ifp->current_server->optinfo.serverID));
		if (duidcpy(&optinfo.serverID,
		    &ifp->current_server->optinfo.serverID)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID",
			    FNAME);
			goto end;
		}
		break;
	case DHCP6S_RELEASE:
		if (duidcpy(&optinfo.serverID, &client6_iaidaddr.client6_info.serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
			goto end;
		}
		break;
	}
	/* client ID */
	if (duidcpy(&optinfo.clientID, &client_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto end;
	}

	/* option request options */
	if (dhcp6_copy_list(&optinfo.reqopt_list, &ifp->reqopt_list)) {
		dprintf(LOG_ERR, "%s" "failed to copy requested options",
		    FNAME);
		goto end;
	}
	
	switch(ev->state) {
	case DHCP6S_SOLICIT:
		/* rapid commit */
		if (ifp->send_flags & DHCIFF_RAPID_COMMIT) 
			optinfo.flags |= DHCIFF_RAPID_COMMIT;
		if (!(ifp->send_flags & DHCIFF_INFO_ONLY) ||
		    (client6_request_flag & CLIENT6_REQUEST_ADDR)) {
			memcpy(&optinfo.iaidinfo, &client6_iaidaddr.client6_info.iaidinfo,
					sizeof(optinfo.iaidinfo));
			if (ifp->send_flags & DHCIFF_PREFIX_DELEGATION)
				optinfo.type = IAPD;
			else if (ifp->send_flags & DHCIFF_TEMP_ADDRS)
				optinfo.type = IATA;
			else
				optinfo.type = IANA;
		}
		/* support for client preferred ipv6 address */
		if (client6_request_flag & CLIENT6_REQUEST_ADDR) {
			if (dhcp6_copy_list(&optinfo.addr_list, &request_list))
				goto end;
		}
		break;
	case DHCP6S_REQUEST:
		if (!(ifp->send_flags & DHCIFF_INFO_ONLY)) {
			memcpy(&optinfo.iaidinfo, &client6_iaidaddr.client6_info.iaidinfo,
					sizeof(optinfo.iaidinfo));
			dprintf(LOG_DEBUG, "%s IAID is %d", FNAME, optinfo.iaidinfo.iaid);
			if (ifp->send_flags & DHCIFF_TEMP_ADDRS) 
				optinfo.type = IATA;
			else if (ifp->send_flags & DHCIFF_PREFIX_DELEGATION)
				optinfo.type = IAPD;
			else
				optinfo.type = IANA;
		}
		break;
	case DHCP6S_RENEW:
	case DHCP6S_REBIND:
	case DHCP6S_RELEASE:
	case DHCP6S_CONFIRM:
	case DHCP6S_DECLINE:
		/*
		if (ifp->send_flags & DHCIFF_PREFIX_DELEGATION)
			optinfo.type = IAPD;
		else if (ifp->send_flags & DHCIFF_TEMP_ADDRS)
			optinfo.type = IATA;
		else
			optinfo.type = IANA;
		*/
		if (!TAILQ_EMPTY(&request_list)) {
			memcpy(&optinfo.iaidinfo, &client6_iaidaddr.client6_info.iaidinfo,
				sizeof(optinfo.iaidinfo));
			optinfo.type = client6_iaidaddr.client6_info.type;
			/* XXX: ToDo: seperate to prefix list and address list */
			if (dhcp6_copy_list(&optinfo.addr_list, &request_list))
				goto end;
			if (ev->state == DHCP6S_CONFIRM) {
				optinfo.iaidinfo.renewtime = 0;
				optinfo.iaidinfo.rebindtime = 0;
			}
		} else {
			if (ev->state == DHCP6S_RELEASE) {
				dprintf(LOG_INFO, "release empty address list");
				exit(1);
			}
			/* XXX: allow the other emtpy list ?? */
		}
		if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
			if (dhcp6_update_iaidaddr(&optinfo, ADDR_REMOVE)) {
				dprintf(LOG_INFO, "client release failed");
				exit(1);
			}
		}
		break;
	default:
		break;
	}
	/* set options in the message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(buf + sizeof(buf)),
					&optinfo)) < 0) {
		dprintf(LOG_INFO, "%s" "failed to construct options", FNAME);
		goto end;
	}
	len += optlen;

	/*
	 * Unless otherwise specified, a client sends DHCP messages to the
	 * All_DHCP_Relay_Agents_and_Servers or the DHCP_Anycast address.
	 * [dhcpv6-26 Section 13.]
	 * Our current implementation always follows the case.
	 */
	dst = *sa6_allagent;
	dst.sin6_scope_id = ifp->linkid;

	if (sendto(ifp->outsock, buf, len, 0, (struct sockaddr *)&dst,
	    sizeof(dst)) == -1) {
		dprintf(LOG_ERR, FNAME "transmit failed: %s", strerror(errno));
		goto end;
	}

	dprintf(LOG_DEBUG, "%s" "send %s to %s", FNAME,
		dhcp6msgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&dst));

  end:
	dhcp6_clear_options(&optinfo);
	return;
}
	
static void
client6_recv()
{
	char rbuf[BUFSIZ], cmsgbuf[BUFSIZ];
	struct msghdr mhdr;
	struct iovec iov;
	struct sockaddr_storage from;
	struct dhcp6_if *ifp;
	struct dhcp6opt *p, *ep;
	struct dhcp6_optinfo optinfo;
	ssize_t len;
	struct dhcp6 *dh6;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;

	memset(&iov, 0, sizeof(iov));
	memset(&mhdr, 0, sizeof(mhdr));

	iov.iov_base = (caddr_t)rbuf;
	iov.iov_len = sizeof(rbuf);
	mhdr.msg_name = (caddr_t)&from;
	mhdr.msg_namelen = sizeof(from);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (caddr_t)cmsgbuf;
	mhdr.msg_controllen = sizeof(cmsgbuf);
	if ((len = recvmsg(insock, &mhdr, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "recvmsg: %s", FNAME, strerror(errno));
		return;
	}

	/* detect receiving interface */
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
		return;
	}
	if ((ifp = find_ifconfbyname(device)) == NULL) {
		dprintf(LOG_INFO, "%s" "unexpected interface (%d)", FNAME,
			(unsigned int)pi->ipi6_ifindex);
		return;
	}
	dh6 = (struct dhcp6 *)rbuf;

	dprintf(LOG_DEBUG, "%s" "receive %s from %s on %s", FNAME,
		dhcp6msgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&from), ifp->ifname);

	/* get options */
	dhcp6_init_options(&optinfo);
	p = (struct dhcp6opt *)(dh6 + 1);
	ep = (struct dhcp6opt *)((char *)dh6 + len);
	if (dhcp6_get_options(p, ep, &optinfo) < 0) {
		dprintf(LOG_INFO, "%s" "failed to parse options", FNAME);
#ifdef TEST
		return;
#endif
	}

	switch(dh6->dh6_msgtype) {
	case DH6_ADVERTISE:
		(void)client6_recvadvert(ifp, dh6, len, &optinfo);
		break;
	case DH6_REPLY:
		(void)client6_recvreply(ifp, dh6, len, &optinfo);
		break;
	default:
		dprintf(LOG_INFO, "%s" "received an unexpected message (%s) "
			"from %s", FNAME, dhcp6msgstr(dh6->dh6_msgtype),
			addr2str((struct sockaddr *)&from));
		break;
	}

	dhcp6_clear_options(&optinfo);
	return;
}

static int
client6_recvadvert(ifp, dh6, len, optinfo0)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	ssize_t len;
	struct dhcp6_optinfo *optinfo0;
{
	struct dhcp6_serverinfo *newserver;
	struct dhcp6_event *ev;
	struct dhcp6_listval *lv;

	/* find the corresponding event based on the received xid */
	ev = find_event_withid(ifp, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
	if (ev == NULL) {
		dprintf(LOG_INFO, "%s" "XID mismatch", FNAME);
		return -1;
	}
	/* if server policy doesn't allow rapid commit
	if (ev->state != DHCP6S_SOLICIT ||
	    (ifp->send_flags & DHCIFF_RAPID_COMMIT)) {
	*/
	if (ev->state != DHCP6S_SOLICIT) { 
		dprintf(LOG_INFO, "%s" "unexpected advertise", FNAME);
		return -1;
	}
	
	/* packet validation based on Section 15.3 of dhcpv6-26. */
	if (optinfo0->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	} else {
		dprintf(LOG_DEBUG, "%s" "server ID: %s, pref=%2x", FNAME,
			duidstr(&optinfo0->serverID),
			optinfo0->pref);
	}
	if (optinfo0->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no client ID option", FNAME);
		return -1;
	}
	if (duidcmp(&optinfo0->clientID, &client_duid)) {
		dprintf(LOG_INFO, "%s" "client DUID mismatch", FNAME);
		return -1;
	}

	/*
	 * The client MUST ignore any Advertise message that includes a Status
	 * Code option containing any error.
	 */
	for (lv = TAILQ_FIRST(&optinfo0->stcode_list); lv;
	     lv = TAILQ_NEXT(lv, link)) {
		dprintf(LOG_INFO, "%s" "status code: %s",
		    FNAME, dhcp6_stcodestr(lv->val_num));
		if (lv->val_num != DH6OPT_STCODE_SUCCESS) {
			return (-1);
		}
	}

	/* ignore the server if it is known */
	if (find_server(ifp, &optinfo0->serverID)) {
		dprintf(LOG_INFO, "%s" "duplicated server (ID: %s)",
			FNAME, duidstr(&optinfo0->serverID));
		return -1;
	}

	newserver = allocate_newserver(ifp, optinfo0);
	if (newserver == NULL)
		return (-1);
		
	/* if the server has an extremely high preference, just use it. */
	if (newserver->pref == DH6OPT_PREF_MAX) {
		ev->timeouts = 0;
		ev->state = DHCP6S_REQUEST;
		ifp->current_server = newserver;
		dhcp6_set_timeoparam(ev);
		dhcp6_reset_timer(ev);
		client6_send(ev);

	} else if (ifp->servers->next == NULL) {
		struct timeval *rest, elapsed, tv_rt, tv_irt, timo;

		/*
		 * If this is the first advertise, adjust the timer so that
		 * the client can collect other servers until IRT elapses.
		 * XXX: we did not want to do such "low level" timer
		 *      calculation here.
		 */
		rest = dhcp6_timer_rest(ev->timer);
		tv_rt.tv_sec = (ev->retrans * 1000) / 1000000;
		tv_rt.tv_usec = (ev->retrans * 1000) % 1000000;
		tv_irt.tv_sec = (ev->init_retrans * 1000) / 1000000;
		tv_irt.tv_usec = (ev->init_retrans * 1000) % 1000000;
		timeval_sub(&tv_rt, rest, &elapsed);
		if (TIMEVAL_LEQ(elapsed, tv_irt))
			timeval_sub(&tv_irt, &elapsed, &timo);
		else
			timo.tv_sec = timo.tv_usec = 0;

		dprintf(LOG_DEBUG, "%s" "reset timer for %s to %d.%06d",
			FNAME, ifp->ifname,
			(int)timo.tv_sec, (int)timo.tv_usec);

		dhcp6_set_timer(&timo, ev->timer);
	}
	/* if the client send preferred addresses reqeust in SOLICIT */
	/* XXX: client might have some local policy to select the addresses */
	if (!TAILQ_EMPTY(&optinfo0->addr_list))
		dhcp6_copy_list(&request_list, &optinfo0->addr_list);
	return 0;
}

static struct dhcp6_serverinfo *
find_server(ifp, duid)
	struct dhcp6_if *ifp;
	struct duid *duid;
{
	struct dhcp6_serverinfo *s;

	for (s = ifp->servers; s; s = s->next) {
		if (duidcmp(&s->optinfo.serverID, duid) == 0)
			return (s);
	}

	return (NULL);
}

static struct dhcp6_serverinfo *
allocate_newserver(ifp, optinfo)
	struct dhcp6_if *ifp;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_serverinfo *newserver, **sp;

	/* keep the server */
	if ((newserver = malloc(sizeof(*newserver))) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed for server",
			FNAME);
		return (NULL);
	}
	memset(newserver, 0, sizeof(*newserver));
	dhcp6_init_options(&newserver->optinfo);
	if (dhcp6_copy_options(&newserver->optinfo, optinfo)) {
		dprintf(LOG_ERR, "%s" "failed to copy options", FNAME);
		free(newserver);
		return (NULL);
	}
	dprintf(LOG_DEBUG, "%s" "new server DUID %s, len %d ", 
		FNAME, duidstr(&newserver->optinfo.serverID), 
		newserver->optinfo.serverID.duid_len);
	if (optinfo->pref != DH6OPT_PREF_UNDEF)
		newserver->pref = optinfo->pref;
	newserver->active = 1;
	for (sp = &ifp->servers; *sp; sp = &(*sp)->next) {
		if ((*sp)->pref != DH6OPT_PREF_MAX &&
		    (*sp)->pref < newserver->pref) {
			break;
		}
	}
	newserver->next = *sp;
	*sp = newserver;
	return newserver;
}

void
free_servers(ifp)
	struct dhcp6_if *ifp;
{
	struct dhcp6_serverinfo *sp, *sp_next;
	/* free all servers we've seen so far */
	for (sp = ifp->servers; sp; sp = sp_next) {
		sp_next = sp->next;
		dprintf(LOG_DEBUG, "%s" "removing server (ID: %s)",
		    FNAME, duidstr(&sp->optinfo.serverID));
		dhcp6_clear_options(&sp->optinfo);
		free(sp);
	}
	ifp->servers = NULL;
	ifp->current_server = NULL;
}

static int
client6_recvreply(ifp, dh6, len, optinfo)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	ssize_t len;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_listval *lv;
	struct dhcp6_event *ev;
	int addr_status_code = DH6OPT_STCODE_UNSPECFAIL;
	struct dhcp6_serverinfo *newserver;
	int newstate = 0;
	/* find the corresponding event based on the received xid */
	dprintf(LOG_DEBUG, "%s" "reply message XID is (%x)",
		FNAME, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
	ev = find_event_withid(ifp, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
	if (ev == NULL) {
		dprintf(LOG_INFO, "%s" "XID mismatch", FNAME);
		return -1;
	}

	if (!(DHCP6S_VALID_REPLY(ev->state)) &&
	    (ev->state != DHCP6S_SOLICIT ||
	     !(ifp->send_flags & DHCIFF_RAPID_COMMIT))) {
		dprintf(LOG_INFO, "%s" "unexpected reply", FNAME);
		return -1;
	}

	dhcp6_clear_list(&request_list);

	/* A Reply message must contain a Server ID option */
	if (optinfo->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	}
	dprintf(LOG_DEBUG, "%s" "serverID is %s len is %d", FNAME,
		duidstr(&optinfo->serverID), optinfo->serverID.duid_len); 
	/* get current server */
	switch (ev->state) {
	case DHCP6S_SOLICIT:
	case DHCP6S_CONFIRM:
	case DHCP6S_REBIND:
		newserver = allocate_newserver(ifp, optinfo);
		if (newserver == NULL)
			return (-1);
		ifp->current_server = newserver;
		duidcpy(&client6_iaidaddr.client6_info.serverid, 
			&ifp->current_server->optinfo.serverID);
		break;
	default:
		break;
	}
	/*
	 * DUID in the Client ID option (which must be contained for our
	 * client implementation) must match ours.
	 */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no client ID option", FNAME);
		return -1;
	}
	if (duidcmp(&optinfo->clientID, &client_duid)) {
		dprintf(LOG_INFO, "%s" "client DUID mismatch", FNAME);
		return -1;
	}

	if (!TAILQ_EMPTY(&optinfo->dns_list)) {
		struct dhcp6_listval *d;
		int i = 0;

		for (d = TAILQ_FIRST(&optinfo->dns_list); d;
		     d = TAILQ_NEXT(d, link), i++) {
			dprintf(LOG_DEBUG, "%s" "nameserver[%d] %s",
				FNAME, i, in6addr2str(&d->val_addr6, 0));
		}
	}
	/*
	 * The client MAY choose to report any status code or message from the
	 * status code option in the Reply message.
	 * [dhcpv6-26 Section 18.1.8]
	 */
	addr_status_code = 0;
	for (lv = TAILQ_FIRST(&optinfo->stcode_list); lv;
	     lv = TAILQ_NEXT(lv, link)) {
		dprintf(LOG_INFO, "%s" "status code: %s",
		    FNAME, dhcp6_stcodestr(lv->val_num));
		switch (lv->val_num) {
		case DH6OPT_STCODE_SUCCESS:
		case DH6OPT_STCODE_UNSPECFAIL:
		case DH6OPT_STCODE_NOADDRAVAIL:
		case DH6OPT_STCODE_NOPREFIXAVAIL:
		case DH6OPT_STCODE_NOBINDING:
		case DH6OPT_STCODE_NOTONLINK:
		case DH6OPT_STCODE_USEMULTICAST:
			addr_status_code = lv->val_num;
		default:
			break;
		}
	}
	switch (addr_status_code) {
	case DH6OPT_STCODE_UNSPECFAIL:
	case DH6OPT_STCODE_USEMULTICAST:
		dprintf(LOG_INFO, "%s" "status code: %s", FNAME, 
			dhcp6_stcodestr(addr_status_code));
		/* retransmit the message with multicast address */
		/* how many time allow the retransmission with error status code? */
		return -1;
	}
	
	/*
	 * Update configuration information to be renewed or rebound
	 * declined, confirmed, released.
	 * Note that the returned list may be empty, in which case
	 * the waiting information should be removed.
	 */
	switch (ev->state) {
	case DHCP6S_SOLICIT:
		if (optinfo->iaidinfo.iaid == 0)
			break;
		else if (!optinfo->flags & DHCIFF_RAPID_COMMIT) {
			newstate = DHCP6S_REQUEST;
			break;
		}
	case DHCP6S_REQUEST:
		/* NotOnLink: 1. SOLICIT 
		 * NoAddrAvail: Information Request */
		switch(addr_status_code) {
		case DH6OPT_STCODE_NOTONLINK:
			dprintf(LOG_DEBUG, "%s" 
			    "got a NotOnLink reply for request/rapid commit,"
			    " sending solicit.", FNAME);
			newstate = DHCP6S_SOLICIT;
			break;
		case DH6OPT_STCODE_NOADDRAVAIL:
		case DH6OPT_STCODE_NOPREFIXAVAIL:
			dprintf(LOG_DEBUG, "%s" 
			    "got a NoAddrAvail reply for request/rapid commit,"
			    " sending inforeq.", FNAME);
			optinfo->iaidinfo.iaid = 0;
			newstate = DHCP6S_INFOREQ;
			break;
#ifdef TEST
		case DH6OPT_STCODE_SUCCESS:
		case DH6OPT_STCODE_UNDEFINE:
#endif
		default:
			if (!TAILQ_EMPTY(&optinfo->addr_list)) {
				dhcp6_add_iaidaddr(optinfo);
			}
			break;
		}
		break;
	case DHCP6S_RENEW:
	case DHCP6S_REBIND:
		/* NoBinding for RENEW, REBIND, send REQUEST */
		switch(addr_status_code) {
		case DH6OPT_STCODE_NOBINDING:
			newstate = DHCP6S_REQUEST;
			dprintf(LOG_DEBUG, "%s" 
			    	  "got a NoBinding reply, sending request.", FNAME);
			dhcp6_remove_iaidaddr(&client6_iaidaddr);
			break;
		case DH6OPT_STCODE_NOADDRAVAIL:
		case DH6OPT_STCODE_NOPREFIXAVAIL:
		case DH6OPT_STCODE_UNSPECFAIL:
			break;
		case DH6OPT_STCODE_SUCCESS:
		case DH6OPT_STCODE_UNDEFINE:
		default:
			dhcp6_update_iaidaddr(optinfo, ADDR_UPDATE);
			break;
		}
		break;
	case DHCP6S_CONFIRM:
		/* NOtOnLink for a Confirm, send SOLICIT message */
		switch(addr_status_code) {
		case DH6OPT_STCODE_NOTONLINK:
			dprintf(LOG_DEBUG, "%s" 
				"got a NotOnLink reply for confirm, sending solicit.", FNAME);
			/* remove event data list */
			free_servers(ifp);
			newstate = DHCP6S_SOLICIT;
			break;
		case DH6OPT_STCODE_SUCCESS:
		{
			struct timeb now;
			struct timeval timo;
			time_t offset;
			/* XXX: set up renew/rebind timer */
			dprintf(LOG_DEBUG, "%s" "got an expected reply for confirm", FNAME);
			ftime(&now);
			client6_iaidaddr.state = ACTIVE;
			if ((client6_iaidaddr.timer = dhcp6_add_timer(dhcp6_iaidaddr_timo, 
						&client6_iaidaddr)) == NULL) {
		 		dprintf(LOG_ERR, "%s" "failed to add a timer for iaid %d",
					FNAME, client6_iaidaddr.client6_info.iaidinfo.iaid);
		 		return (-1);
			}
			if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
				client6_iaidaddr.client6_info.iaidinfo.renewtime 
					= get_min_preferlifetime(&client6_iaidaddr)/2;
			}
			if (client6_iaidaddr.client6_info.iaidinfo.rebindtime == 0) {
				client6_iaidaddr.client6_info.iaidinfo.rebindtime 
					= (get_min_preferlifetime(&client6_iaidaddr)*4)/5;
			}
			offset = now.time - client6_iaidaddr.start_date;
			if ( offset > client6_iaidaddr.client6_info.iaidinfo.renewtime) 
				timo.tv_sec = 0;
			else
				timo.tv_sec = client6_iaidaddr.client6_info.iaidinfo.renewtime 						- offset; 
			timo.tv_usec = 0;
			dhcp6_set_timer(&timo, client6_iaidaddr.timer);
			break;
		}
		default:
			break;
		}
		break;
	case DHCP6S_DECLINE:
		/* send REQUEST message to server with none decline address */
		dprintf(LOG_DEBUG, "%s" 
		    "got an expected reply for decline, sending request.", FNAME);
		/* remove event data list */
		newstate = DHCP6S_REQUEST;
		break;
	case DHCP6S_RELEASE:
		dprintf(LOG_INFO, "%s" "got an expected release, exit.", FNAME);
		dhcp6_remove_event(ev);
		exit(0);
		break;
	default:
		break;
	}
	dhcp6_remove_event(ev);
	if (newstate) {
		client6_send_newstate(ifp, newstate);
	} else 
		dprintf(LOG_DEBUG, "%s" "got an expected reply, sleeping.", FNAME);
	TAILQ_INIT(&request_list);
	return 0;
}

int 
client6_send_newstate(ifp, state)
	struct dhcp6_if *ifp;
	int state;
{
	struct dhcp6_event *ev;
	if ((ev = dhcp6_create_event(ifp, state)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create an event",
			FNAME);
		return (-1);
	}
	if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to add a timer for %s",
			FNAME, ifp->ifname);
		free(ev);
		return(-1);
	}
	TAILQ_INSERT_TAIL(&ifp->event_list, ev, link);
	ev->timeouts = 0;
	dhcp6_set_timeoparam(ev);
	dhcp6_reset_timer(ev);
	client6_send(ev);
	return 0;
}

static struct dhcp6_event *
find_event_withid(ifp, xid)
	struct dhcp6_if *ifp;
	u_int32_t xid;
{
	struct dhcp6_event *ev;

	for (ev = TAILQ_FIRST(&ifp->event_list); ev;
	     ev = TAILQ_NEXT(ev, link)) {
		dprintf(LOG_DEBUG, "%s" "ifp %p event %p id is %x", 
			FNAME, ifp, ev, ev->xid);
		if (ev->xid == xid)
			return (ev);
	}

	return (NULL);
}
