/*	$Id: client6_addr.c,v 1.7 2003/02/25 00:31:52 shirleyma Exp $	*/

/*
 * Copyright (C) International Business Machines  Corp., 2003
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

/* Author: Shirley Ma, xma@us.ibm.com */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ioctl.h>

#include <linux/ipv6.h>

#include <net/if.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if_arp.h>

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "lease.h"
#include "queue.h"


static int dhcp6_update_lease __P((struct dhcp6_addr *, struct dhcp6_lease *));
static int dhcp6_add_lease __P((struct dhcp6_addr *));
struct dhcp6_lease *dhcp6_find_lease __P((struct dhcp6_iaidaddr *, 
			struct dhcp6_addr *));
int client6_ifaddrconf __P((ifaddrconf_cmd_t, struct dhcp6_addr *));
u_int32_t get_min_preferlifetime __P((struct dhcp6_iaidaddr *));
u_int32_t get_max_validlifetime __P((struct dhcp6_iaidaddr *));
struct dhcp6_timer *dhcp6_iaidaddr_timo __P((void *));
struct dhcp6_timer *dhcp6_lease_timo __P((void *));

extern struct dhcp6_iaidaddr client6_iaidaddr;
extern struct dhcp6_timer *client6_timo __P((void *));
extern void client6_send __P((struct dhcp6_event *));
extern void free_servers __P((struct dhcp6_if *));
extern ssize_t gethwid __P((char *, int, const char *, u_int16_t *));

#define DEFAULT_PREFIX_LEN 64
extern FILE *client6_lease_file;
extern struct dhcp6_iaidaddr client6_iaidaddr;
extern struct dhcp6_list request_list;

void
dhcp6_init_iaidaddr()
{
	memset(&client6_iaidaddr, 0, sizeof(client6_iaidaddr));
	TAILQ_INIT(&client6_iaidaddr.lease_list);
}

int
dhcp6_add_iaidaddr(optinfo)
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_listval *lv, *lv_next = NULL;
	struct timeval timo;
	struct dhcp6_lease *cl_lease;
	double d;
	
	memcpy(&client6_iaidaddr.client6_info.iaidinfo, &optinfo->iaidinfo, 
			sizeof(client6_iaidaddr.client6_info.iaidinfo));
	client6_iaidaddr.client6_info.type = optinfo->type;
	duidcpy(&client6_iaidaddr.client6_info.clientid, &optinfo->clientID);
	if (duidcpy(&client6_iaidaddr.client6_info.serverid, &optinfo->serverID)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID %s", 
			FNAME, &optinfo->serverID);
		return (-1);
	}
	if ((client6_iaidaddr.timer = 
		    dhcp6_add_timer(dhcp6_iaidaddr_timo, &client6_iaidaddr)) == NULL) {
		 dprintf(LOG_ERR, "%s" "failed to add a timer for iaid %d",
			FNAME, client6_iaidaddr.client6_info.iaidinfo.iaid);
		 return (-1);
	}
	/* add new address */
	for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = lv_next) {
		lv_next = TAILQ_NEXT(lv, link);
		if ((cl_lease = dhcp6_find_lease(&client6_iaidaddr, 
						&lv->val_dhcp6addr)) != NULL) {
			dhcp6_update_lease(&lv->val_dhcp6addr, cl_lease);
			continue;
		}
		if (dhcp6_add_lease(&lv->val_dhcp6addr)) {
			dprintf(LOG_ERR, "%s" "failed to add a new addr lease %s", 
				FNAME, in6addr2str(&lv->val_dhcp6addr.addr, 0));
			continue;
		}
	}
	/* set up renew T1, rebind T2 timer renew/rebind based on iaid */
	/* Should we process IA_TA, IA_NA differently */
	if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
		client6_iaidaddr.client6_info.iaidinfo.renewtime 
			= get_min_preferlifetime(&client6_iaidaddr) / 2;
	}
	if (client6_iaidaddr.client6_info.iaidinfo.rebindtime == 0) {
		client6_iaidaddr.client6_info.iaidinfo.rebindtime 
			= (get_min_preferlifetime(&client6_iaidaddr) * 4) / 5;
	}
	if (TAILQ_EMPTY(&client6_iaidaddr.lease_list) || 
	    client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
		dhcp6_remove_timer(client6_iaidaddr.timer);
		return 0;
	}
	/* set up start date, and renew timer */
	time(&client6_iaidaddr.start_date);
	client6_iaidaddr.state = ACTIVE;
	d = client6_iaidaddr.client6_info.iaidinfo.renewtime;
	timo.tv_sec = (long)d;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, client6_iaidaddr.timer);
	return (0);
}

int
dhcp6_add_lease(addr)
	struct dhcp6_addr *addr;
{
	struct dhcp6_lease *sp;
	struct timeval timo;
	double d;

	dprintf(LOG_DEBUG, "%s" "try to add address %s", FNAME,
		in6addr2str(&addr->addr, 0));
	
	/* ignore meaningless address */
	if (addr->status_code != DH6OPT_STCODE_SUCCESS &&
			addr->status_code != DH6OPT_STCODE_UNDEFINE) {
		dprintf(LOG_ERR, "%s" "not successful status code for %s is %s", FNAME,
			in6addr2str(&addr->addr, 0), dhcp6_stcodestr(addr->status_code));
		return (0);
	}
	if (addr->validlifetime == 0 || addr->preferlifetime == 0) {
		dprintf(LOG_ERR, "%s" "zero address life time for %s",
			FNAME, in6addr2str(&addr->addr, 0));
		return (0);
	}
	if ((sp = dhcp6_find_lease(&client6_iaidaddr, addr)) != NULL) {
		dprintf(LOG_ERR, "%s" "duplicated address: %s",
		    FNAME, in6addr2str(&addr->addr, 0));
		return (-1);
	}
	if ((sp = (struct dhcp6_lease *)malloc(sizeof(*sp))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory"
			" for a addr", FNAME);
		return (-1);
	}
	memset(sp, 0, sizeof(*sp));
	memcpy(&sp->lease_addr, addr, sizeof(sp->lease_addr));
	/* set up expired timer for lease*/
	if ((sp->timer = dhcp6_add_timer(dhcp6_lease_timo, sp)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to add a timer for lease %s",
			FNAME, in6addr2str(&addr->addr, 0));
		free(sp);
		return (-1);
	}
	sp->iaidaddr = &client6_iaidaddr;
	time(&sp->start_date);
	sp->state = ACTIVE;
	sp->addr_type = sp->iaidaddr->client6_info.type;
	d = sp->lease_addr.preferlifetime;
	timo.tv_sec = (long)d;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, sp->timer);
	if (write_lease(sp, client6_lease_file) != 0) {
		dprintf(LOG_ERR, "%s" "failed to write a new lease address %s to lease file", 
			FNAME, in6addr2str(&sp->lease_addr.addr, 0));
		if (sp->timer)
			dhcp6_remove_timer(sp->timer);
		free(sp);
		return (-1);
	}
	/* XXX: ToDo: prefix delegation for client */
	if (sp->addr_type == IAPD) {
		dprintf(LOG_INFO, "request prefix is %s/%d", 
			in6addr2str(&sp->lease_addr.addr, 0), sp->lease_addr.plen);
	} else if (client6_ifaddrconf(IFADDRCONF_ADD, addr) != 0) {
		dprintf(LOG_ERR, "%s" "adding address failed: %s",
		    FNAME, in6addr2str(&addr->addr, 0));
		if (sp->timer)
			dhcp6_remove_timer(sp->timer);
		free(sp);
		return (-1);
	}
	TAILQ_INSERT_TAIL(&client6_iaidaddr.lease_list, sp, link);
	return 0;
}

int
dhcp6_remove_iaidaddr(iaidaddr)
	struct dhcp6_iaidaddr *iaidaddr;
{
	struct dhcp6_lease *lv, *lv_next;
	for (lv = TAILQ_FIRST(&iaidaddr->lease_list); lv; lv = lv_next) { 
		lv_next = TAILQ_NEXT(lv, link);
		(void)dhcp6_remove_lease(lv);
	}
	/*
	if (iaidaddr->client6_info.serverid.duid_id != NULL)
		duidfree(&iaidaddr->client6_info.serverid);
	 */
	if (iaidaddr->timer)
		dhcp6_remove_timer(iaidaddr->timer);
	TAILQ_INIT(&iaidaddr->lease_list);
	return 0;
}

int
dhcp6_remove_lease(sp)
	struct dhcp6_lease *sp;
{
	dprintf(LOG_DEBUG, "%s" "removing address %s", FNAME,
		in6addr2str(&sp->lease_addr.addr, 0));
	sp->state = INVALID;
	if (write_lease(sp, client6_lease_file) != 0) {
		dprintf(LOG_INFO, "%s" 
			"failed to write removed lease address %s to lease file", 
			FNAME, in6addr2str(&sp->lease_addr.addr, 0));
		return (-1);
	}
	/* XXX: ToDo: prefix delegation for client */
	if (sp->addr_type == IAPD) {
		dprintf(LOG_INFO, "request prefix is %s/%d", 
			in6addr2str(&sp->lease_addr.addr, 0), sp->lease_addr.plen);
	} else if (client6_ifaddrconf(IFADDRCONF_REMOVE, &sp->lease_addr) != 0) {
			dprintf(LOG_INFO, "%s" "removing address %s failed",
		    		FNAME, in6addr2str(&sp->lease_addr.addr, 0));
	}
	/* remove expired timer for this lease. */
	if (sp->timer)
		dhcp6_remove_timer(sp->timer);
	TAILQ_REMOVE(&client6_iaidaddr.lease_list, sp, link);
	free(sp);
	/* can't remove expired iaidaddr even there is no lease in this iaidaddr
	 * since the rebind->solicit timer uses this iaidaddr
	 * if(TAILQ_EMPTY(&client6_iaidaddr.lease_list))
	 *	dhcp6_remove_iaidaddr();
	 */
	return 0;
}

int
dhcp6_update_iaidaddr(optinfo, flag)
	struct dhcp6_optinfo *optinfo;
	int flag;
{
	struct dhcp6_listval *lv, *lv_next = NULL;
	struct dhcp6_lease *cl, *cl_next;
	struct timeval timo;
	double d;
	dprintf(LOG_DEBUG, "%s" " called", FNAME);
	if (flag == ADDR_REMOVE) {
		for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = lv_next) {
			lv_next = TAILQ_NEXT(lv, link);
			if (cl = dhcp6_find_lease(&client6_iaidaddr, &lv->val_dhcp6addr)) {
				/* remove leases */
				dhcp6_remove_lease(cl);
			}
		}
		return 0;
	}
	/* flag == ADDR_UPDATE */
	for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = lv_next) {
		lv_next = TAILQ_NEXT(lv, link);
		if ((cl = dhcp6_find_lease(&client6_iaidaddr, &lv->val_dhcp6addr)) != NULL) {
		/* update leases */
			dhcp6_update_lease(&lv->val_dhcp6addr, cl);
			continue;
		}
		/* need to add the new leases */	
		if (dhcp6_add_lease(&lv->val_dhcp6addr)) {
			dprintf(LOG_INFO, "%s" "failed to add a new addr lease %s",
				FNAME, in6addr2str(&lv->val_dhcp6addr.addr, 0));
			continue;
		}
		continue;
	}
	/* remove leases that not on the updated list */
	for (cl = TAILQ_FIRST(&client6_iaidaddr.lease_list); cl; cl = cl_next) { 
			cl_next = TAILQ_NEXT(cl, link);
		lv = dhcp6_find_listval(&optinfo->addr_list, &cl->lease_addr, 
			DHCP6_LISTVAL_DHCP6ADDR);
		/* remove leases that not on the updated list */
		if (lv == NULL)
			dhcp6_remove_lease(cl);
	}	
	/* update server id */
	if (client6_iaidaddr.state == REBIND) {
		if (duidcpy(&client6_iaidaddr.client6_info.serverid, &optinfo->serverID)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
			return (-1);
		}
	}
	if (client6_iaidaddr.timer == NULL) {
		if ((client6_iaidaddr.timer = 
		     dhcp6_add_timer(dhcp6_iaidaddr_timo, &client6_iaidaddr)) == NULL) {
	 		dprintf(LOG_ERR, "%s" "failed to add a timer for iaid %d",
				FNAME, client6_iaidaddr.client6_info.iaidinfo.iaid);
	 		return (-1);
	    	}
	}
	if (TAILQ_EMPTY(&client6_iaidaddr.lease_list) || 
	    client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
		dhcp6_remove_timer(client6_iaidaddr.timer);
		return 0;
	}
	/* update the start date and timer */
	time(&client6_iaidaddr.start_date);
	client6_iaidaddr.state = ACTIVE;
	d = client6_iaidaddr.client6_info.iaidinfo.renewtime;
	timo.tv_sec = (long)d;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, client6_iaidaddr.timer);
	return 0;
}

static int
dhcp6_update_lease(addr, sp)
	struct dhcp6_addr *addr;
	struct dhcp6_lease *sp;
{
	struct timeval timo;
	double d;
	if (addr->preferlifetime == DHCP6_DURATITION_INFINITE) {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with infinite preferlifetime", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen,
		    addr->preferlifetime);
	} else {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with preferlifetime %d", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen,
		    addr->preferlifetime);
	}
	if (addr->validlifetime == DHCP6_DURATITION_INFINITE) {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with infinite validlifetime", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen,
		    addr->validlifetime);
	} else {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with validlifetime %d", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen,
		    addr->validlifetime);
	}
	if (addr->status_code != DH6OPT_STCODE_SUCCESS &&
		 	addr->status_code != DH6OPT_STCODE_UNDEFINE) {
		dprintf(LOG_ERR, "%s" "not successful status code for %s is %s", FNAME,
			in6addr2str(&addr->addr, 0), dhcp6_stcodestr(addr->status_code));
		dhcp6_remove_lease(sp);
	}
	/* remove leases with validlifetime == 0, and preferlifetime == 0 */
	if (addr->validlifetime == 0 || addr->preferlifetime == 0) {
		dprintf(LOG_ERR, "%s" "zero address life time for %s",
			FNAME, in6addr2str(&addr->addr, 0));
		dhcp6_remove_lease(sp);
	}
	memcpy(&sp->lease_addr, addr, sizeof(sp->lease_addr));
	sp->state = ACTIVE;
	time(&sp->start_date);
	if (write_lease(sp, client6_lease_file) != 0) {
		dprintf(LOG_ERR, "%s" 
			"failed to write an updated lease address %s to lease file", 
			FNAME, in6addr2str(&sp->lease_addr.addr, 0));
		return (-1);
	}
	if (sp->timer == NULL) {
		if ((sp->timer = dhcp6_add_timer(dhcp6_lease_timo, sp)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a timer for lease %s",
				FNAME, in6addr2str(&addr->addr, 0));
			return (-1);
		}
	}
	d = sp->lease_addr.preferlifetime;
	timo.tv_sec = (long)d;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, sp->timer);
	return (0);
}

struct dhcp6_lease *
dhcp6_find_lease(iaidaddr, ifaddr)
	struct dhcp6_iaidaddr *iaidaddr;
	struct dhcp6_addr *ifaddr;
{
	struct dhcp6_lease *sp;
	for (sp = TAILQ_FIRST(&iaidaddr->lease_list); sp;
	     sp = TAILQ_NEXT(sp, link)) {
		/* sp->lease_addr.plen == ifaddr->plen */
		dprintf(LOG_DEBUG, "%s" "get address is %s/%d ", FNAME,
			in6addr2str(&ifaddr->addr, 0), ifaddr->plen);
		dprintf(LOG_DEBUG, "%s" "lease address is %s/%d ", FNAME,
			in6addr2str(&sp->lease_addr.addr, 0), ifaddr->plen);
		if (IN6_ARE_ADDR_EQUAL(&sp->lease_addr.addr, &ifaddr->addr) &&
		    sp->lease_addr.plen == ifaddr->plen) {
			return (sp);
		}
	}
	return (NULL);
}

struct dhcp6_timer *
dhcp6_iaidaddr_timo(arg)
	void *arg;
{
	struct dhcp6_iaidaddr *sp = (struct dhcp6_iaidaddr *)arg;
	struct dhcp6_event *ev;
	struct dhcp6_eventdata *evd;
	struct timeval timeo;
	int dhcpstate;
	double d;

	dprintf(LOG_DEBUG, "%s" "client6_iaidaddr timeout for %d, state=%d", FNAME,
		client6_iaidaddr.client6_info.iaidinfo.iaid, sp->state);

	dhcp6_clear_list(&request_list);
	/* ToDo: what kind of opiton Request value, client would like to pass? */
	switch(sp->state) {
	case ACTIVE:
		sp->state = RENEW;
		dhcpstate = DHCP6S_RENEW;
		d = sp->client6_info.iaidinfo.rebindtime - sp->client6_info.iaidinfo.renewtime;
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		break;
	case RENEW:
		sp->state = REBIND;
		dhcpstate = DHCP6S_REBIND;
		d = get_max_validlifetime(&client6_iaidaddr) -
				sp->client6_info.iaidinfo.rebindtime; 
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		if (sp->client6_info.serverid.duid_id != NULL)
			duidfree(&sp->client6_info.serverid);
		break;
	case REBIND:
		dprintf(LOG_INFO, "%s" "failed to rebind a client6_iaidaddr %d"
		    " go to solicit and request new ipv6 addresses",
		    FNAME, client6_iaidaddr.client6_info.iaidinfo.iaid);
		sp->state = INVALID;
		dhcpstate = DHCP6S_SOLICIT;
		free_servers(sp->ifp);
		break;
	default:
		return (NULL);
	}
	if ((ev = dhcp6_create_event(sp->ifp, dhcpstate)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event"
		    FNAME);
		return (NULL); /* XXX: should try to recover reserve memory?? */
	}
	switch(sp->state) {
	case RENEW:
		if (duidcpy(&ev->serverid, &sp->client6_info.serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
			return (NULL);
		}
	case REBIND:
		ev->max_retrans_dur = d; 
		break;
	}
	if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event "
	    	"timer", FNAME);
		free(ev);
		return (NULL); /* XXX */
	}
	TAILQ_INSERT_TAIL(&sp->ifp->event_list, ev, link);
	if (sp->state != INVALID) {
		struct dhcp6_lease *cl;
		/* create an address list for renew and rebind */
		for (cl = TAILQ_FIRST(&client6_iaidaddr.lease_list); cl; 
			cl = TAILQ_NEXT(cl, link)) {
			struct dhcp6_listval *lv;
			/* IA_NA address */
			if ((lv = malloc(sizeof(*lv))) == NULL) {
				dprintf(LOG_ERR, "%s" 
				"failed to allocate memory for an ipv6 addr", FNAME);
		 		return (NULL);
			}
			memcpy(&lv->val_dhcp6addr, &cl->lease_addr, 
					sizeof(lv->val_dhcp6addr));
			lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
			TAILQ_INSERT_TAIL(&request_list, lv, link);
		}
		dhcp6_set_timer(&timeo, sp->timer);
	} else {
		dhcp6_remove_iaidaddr(&client6_iaidaddr);
		/* remove event data for that event */
		sp->timer = NULL;
	}
	ev->timeouts = 0;
	dhcp6_set_timeoparam(ev);
	dhcp6_reset_timer(ev);
	client6_send(ev);
	return (sp->timer);
}


struct dhcp6_timer *
dhcp6_lease_timo(arg)
	void *arg;
{
	struct dhcp6_lease *sp = (struct dhcp6_lease *)arg;
	struct timeval timeo;
	double d;

	dprintf(LOG_DEBUG, "%s" "lease timeout for %s, state=%d", FNAME,
		in6addr2str(&sp->lease_addr.addr, 0), sp->state);
	/* cancel the current event for this lease */
	if (sp->state == INVALID) {
		dprintf(LOG_INFO, "%s" "failed to remove an addr %s",
		    FNAME, in6addr2str(&sp->lease_addr.addr, 0));
		dhcp6_remove_lease(sp);
		return (NULL);
	}
	switch(sp->state) {
	case ACTIVE:
		sp->state = EXPIRED;
		d = sp->lease_addr.validlifetime - sp->lease_addr.preferlifetime;
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		dhcp6_set_timer(&timeo, sp->timer);
		break;
	case EXPIRED:
		sp->state = INVALID;
		dhcp6_remove_lease(sp);
	default:
		return (NULL);
	}
	return (sp->timer);
}

int
client6_ifaddrconf(cmd, ifaddr)
	ifaddrconf_cmd_t cmd;
	struct dhcp6_addr *ifaddr;
{
	struct in6_ifreq req;
	struct dhcp6_if *ifp = client6_iaidaddr.ifp;
	unsigned long ioctl_cmd;
	char *cmdstr;
	int s;

	switch(cmd) {
	case IFADDRCONF_ADD:
		cmdstr = "add";
		ioctl_cmd = SIOCSIFADDR;
		break;
	case IFADDRCONF_REMOVE:
		cmdstr = "remove";
		ioctl_cmd = SIOCDIFADDR;
		break;
	default:
		return (-1);
	}

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "can't open a temporary socket: %s",
			FNAME, strerror(errno));
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.ifr6_ifindex = if_nametoindex(ifp->ifname);
	memcpy(&req.ifr6_addr, &ifaddr->addr, sizeof(req.ifr6_addr));
	/*ToDo: an draft issue here, how to get the right prefix for 
	 * client, so far len = 64; 
	req.ifr6_prefixlen = ifaddr->plen;
	 */
	req.ifr6_prefixlen = DEFAULT_PREFIX_LEN;

	if (ioctl(s, ioctl_cmd, &req)) {
		dprintf(LOG_NOTICE, "%s" "failed to %s an address on %s: %s",
		    FNAME, cmdstr, ifp->ifname, strerror(errno));
		close(s);
		return (-1);
	}

	dprintf(LOG_DEBUG, "%s" "%s an address %s on %s", FNAME, cmdstr,
	    in6addr2str(&ifaddr->addr, 0), ifp->ifname);
	/* ToDo: netlink to DAD */
	close(s); 
	return (0);
}

u_int32_t
get_min_preferlifetime(sp)
	struct dhcp6_iaidaddr *sp;
{
	struct dhcp6_lease *lv, *first;
	u_int32_t min;
	if (TAILQ_EMPTY(&sp->lease_list))
		return 0;
	first = TAILQ_FIRST(&sp->lease_list);
	min = first->lease_addr.preferlifetime;
	for (lv = TAILQ_FIRST(&sp->lease_list); lv; lv = TAILQ_NEXT(lv, link)) {
		min = MIN(min, lv->lease_addr.preferlifetime);
	}
	return min;
}

u_int32_t
get_max_validlifetime(sp)
	struct dhcp6_iaidaddr *sp;
{
	struct dhcp6_lease *lv, *first;
	u_int32_t max;
	if (TAILQ_EMPTY(&sp->lease_list))
		return 0;
	first = TAILQ_FIRST(&sp->lease_list);
	max = first->lease_addr.validlifetime;
	for (lv = TAILQ_FIRST(&sp->lease_list); lv; lv = TAILQ_NEXT(lv, link)) {
		max = MAX(max, lv->lease_addr.validlifetime);
	}
	return max;
}

int
get_iaid(char *ifname, struct iaid_table *iaidtab)
{
	struct iaid_table *temp;
	struct hardware hdaddr;
	hdaddr.len = gethwid(hdaddr.data, 17, ifname, &hdaddr.type);
	for (temp = iaidtab; temp; temp++) {
		if (strncmp(temp->hwaddr.data, hdaddr.data, hdaddr.len)) continue;
		else
			return temp->iaid;
	}
	return 0;
}

int 
create_iaid(struct iaid_table *iaidtab)
{
	char buff[1024];
	struct ifconf ifc;
	struct ifreq *ifr, if_hwaddr;
	int sock, i;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0 )) < 0) 
		return -1;
	
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
		dprintf(LOG_ERR, "%s" "ioctl SIOCGIFCONF", FNAME);
		return -1;
	}

	ifr = ifc.ifc_req;
	for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
		if (!strcmp(ifr->ifr_name, "lo")) continue;
		strcpy(if_hwaddr.ifr_name, ifr->ifr_name);
		if (ioctl(sock, SIOCGIFHWADDR, &if_hwaddr) < 0) {
			dprintf(LOG_ERR, "%s" "ioctl SIOCGIFHWADDR", FNAME);
			return -1;
		}
		/* so far we only support ethernet hw */
		if (if_hwaddr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
			unsigned char *hwaddr = (unsigned char *)if_hwaddr.ifr_hwaddr.sa_data;
			bcopy(hwaddr, iaidtab->hwaddr.data, sizeof(hwaddr));
			iaidtab->hwaddr.len = 6;
			memcpy(&iaidtab->iaid, (unsigned char *)&hwaddr[3], 
					sizeof(iaidtab->iaid));
			iaidtab->hwaddr.type = if_hwaddr.ifr_hwaddr.sa_family;	
		}
		dprintf(LOG_DEBUG, "%s"" interface is %s, iaid is %d", 
				FNAME, ifr->ifr_name, iaidtab->iaid);
		iaidtab += 1;
	}
	return 0;
}
