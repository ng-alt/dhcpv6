/*	$Id: client6_addr.c,v 1.2 2003/01/20 20:25:22 shirleyma Exp $	*/

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

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "client6_addr.h"

#include "queue.h"

typedef enum { IFADDRCONF_ADD, IFADDRCONF_REMOVE } ifaddrconf_cmd_t;

static void client6_remove_lease __P((struct client6_lease *));
static int client6_update_lease __P((struct dhcp6_addr *, struct client6_lease *));
static int client6_add_lease __P((struct dhcp6_addr *));
static struct client6_lease *client6_find_lease __P((struct dhcp6_addr *));
static int client6_ifaddrconf __P((ifaddrconf_cmd_t, struct dhcp6_addr *));
static struct dhcp6_timer *client6_iaidaddr_timo __P((void *));
static struct dhcp6_timer *client6_lease_timo __P((void *));
static u_int32_t get_min_preferlifetime __P((struct client6_iaidaddr *));
static u_int32_t get_max_validlifetime __P((struct client6_iaidaddr *));
extern struct dhcp6_timer *client6_timo __P((void *));
extern void client6_send __P((struct dhcp6_event *));
extern void client6_send_rebind __P((struct dhcp6_event *));

static struct client6_iaidaddr iaidaddr;

void
client6_init_iaidaddr()
{
	memset(&iaidaddr, 0, sizeof(iaidaddr));
	TAILQ_INIT(&iaidaddr.ifaddr_list);
}

int
client6_add_iaidaddr(ifp, optinfo, serverid)
	struct dhcp6_if *ifp;
	struct dhcp6_optinfo *optinfo;
	struct duid *serverid;
{
	struct dhcp6_listval *lv;
	struct timeval timo;
	struct client6_lease *cl_lease;
	iaidaddr.ifp = ifp;
	memcpy(&iaidaddr.iaidinfo, &optinfo->iaidinfo, sizeof(iaidaddr.iaidinfo));
	if (duidcpy(&iaidaddr.serverid, serverid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID %s", 
			FNAME, serverid);
		return (-1);
	}
	if ((iaidaddr.timer = 
		    dhcp6_add_timer(client6_iaidaddr_timo, &iaidaddr)) == NULL) {
		 dprintf(LOG_ERR, "%s" "failed to add a timer for iaid %d",
			FNAME, iaidaddr.iaidinfo.iaid);
		 return (-1);
	}
	/* add new address */
	for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		if ((cl_lease = client6_find_lease(&lv->val_dhcp6addr)) != NULL) {
			client6_update_lease(&lv->val_dhcp6addr, cl_lease);
			continue;
		}
		if (client6_add_lease(&lv->val_dhcp6addr)) {
			dprintf(LOG_ERR, "%s" "failed to add a new addr lease %s", 
				FNAME, in6addr2str(&lv->val_dhcp6addr.addr, 0));
			continue;
		}
	}
	/* set up renew T1, rebind T2 timer renew/rebind based on iaid */
	/* Should we process IA_TA, IA_NA differently */
	if (iaidaddr.iaidinfo.renewtime == 0) {
		iaidaddr.iaidinfo.renewtime = 0.5 * get_min_preferlifetime(&iaidaddr);
	}
	if (iaidaddr.iaidinfo.rebindtime == 0) {
		iaidaddr.iaidinfo.rebindtime = 0.3 * get_min_preferlifetime(&iaidaddr);
	}
	/* set up start date, and renew timer */
	time(&iaidaddr.start_date);
	iaidaddr.state = IAID6S_ACTIVE;
	timo.tv_sec = iaidaddr.iaidinfo.renewtime;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, iaidaddr.timer);
	return (0);
}

int
client6_add_lease(addr)
	struct dhcp6_addr *addr;
{
	struct client6_lease *sp;
	struct timeval timo;
	dprintf(LOG_DEBUG, "%s" "try to add address %s", FNAME,
		in6addr2str(&addr->addr, 0));

	/* ignore meaningless address */
	if (addr->validlifetime == 0 || addr->preferlifetime == 0) {
		dprintf(LOG_ERR, "%s" "zero address life time for %s",
			in6addr2str(&addr->addr, 0), FNAME);
		return (0);
	}
	if ((sp = client6_find_lease(addr)) != NULL) {
		dprintf(LOG_ERR, "%s" "duplicated address: %s",
		    FNAME, in6addr2str(&addr->addr, 0));
		return (-1);
	}
	if ((sp = (struct client6_lease *)malloc(sizeof(*sp))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory"
			" for a addr", FNAME);
		return (-1);
	}
	memset(sp, 0, sizeof(*sp));
	memcpy(&sp->dhcp6addr, addr, sizeof(sp->dhcp6addr));
	/* set up expired timer for lease*/
	if ((sp->timer = dhcp6_add_timer(client6_lease_timo, sp)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to add a timer for lease %s",
			FNAME, in6addr2str(&addr->addr, 0));
		free(sp);
		return (-1);
	}
	sp->iaidaddr = &iaidaddr;
	time(&sp->start_date);
	sp->state = ADDR6S_ACTIVE;
	if (client6_ifaddrconf(IFADDRCONF_ADD, addr) != 0) {
		dprintf(LOG_ERR, "%s" "adding address failed: %s",
		    FNAME, in6addr2str(&addr->addr, 0));
		if (sp->timer)
			dhcp6_remove_timer(&sp->timer);
		free(sp);
		return (-1);
	}
	timo.tv_sec = sp->dhcp6addr.preferlifetime;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, sp->timer);
	sp->state = ADDR6S_ACTIVE;
	TAILQ_INSERT_TAIL(&iaidaddr.ifaddr_list, sp, link);
	return 0;
}

void
client6_remove_iaidaddr()
{
	struct client6_lease *lv;
	for (lv = TAILQ_FIRST(&iaidaddr.ifaddr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		TAILQ_REMOVE(&iaidaddr.ifaddr_list, lv, link);
		(void)client6_remove_lease(lv);
	}
	if (iaidaddr.serverid.duid_id != NULL)
		duidfree(&iaidaddr.serverid);
	memset(&iaidaddr.iaidinfo, 0, sizeof(iaidaddr.iaidinfo));	
	if (iaidaddr.timer)
		dhcp6_remove_timer(&iaidaddr.timer);

	if (iaidaddr.evdata) {
		TAILQ_REMOVE(&iaidaddr.evdata->event->data_list, iaidaddr.evdata, link);
		free(iaidaddr.evdata);
		iaidaddr.evdata = NULL;
	}
	client6_init_iaidaddr();
	return;
}

void
client6_remove_lease(sp)
	struct client6_lease *sp;
{
	dprintf(LOG_DEBUG, "%s" "removing address %s", FNAME,
		in6addr2str(&sp->dhcp6addr.addr, 0));
	if (client6_ifaddrconf(IFADDRCONF_REMOVE, &sp->dhcp6addr) != 0) {
		dprintf(LOG_INFO, "%s" "removing address %s failed",
		    FNAME, in6addr2str(&sp->dhcp6addr.addr, 0));
	}
	/* remove expired timer for this lease. */
	if (sp->timer)
		dhcp6_remove_timer(&sp->timer);
	TAILQ_REMOVE(&iaidaddr.ifaddr_list, sp, link);
	free(sp);
	return;
}

int
client6_update_iaidaddr(ev, optinfo, serverid)
	struct dhcp6_event *ev;
	struct dhcp6_optinfo *optinfo;
	struct duid *serverid;
{
	struct dhcp6_listval *lv;
	struct client6_lease *cl;
	struct dhcp6_eventdata *evd, *evd_next;
	struct timeval timo;
	dprintf(LOG_DEBUG, "%s" " called", FNAME);
	for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		if ((cl = client6_find_lease(&lv->val_dhcp6addr)) != NULL) {
		/* update leases */
			client6_update_lease(&lv->val_dhcp6addr, cl);
			continue;
		}
		/* need to add the new leases */	
		if (client6_add_lease(&lv->val_dhcp6addr)) {
			dprintf(LOG_INFO, "%s" "failed to add a new addr lease %s",
				FNAME, in6addr2str(&lv->val_dhcp6addr.addr, 0));
			continue;
		}
	}
	/* remove leases that not on the updated list */
	for (evd = TAILQ_FIRST(&ev->data_list); evd; evd = evd_next) {
		struct client6_iaidaddr *iaidaddr;
		iaidaddr = (struct client6_iaidaddr *)evd->data;
		evd_next = TAILQ_NEXT(evd, link);
		if (evd->type != DHCP6_DATA_ADDR)
			continue;
		if (TAILQ_EMPTY(&iaidaddr->ifaddr_list))
			dprintf(LOG_DEBUG, "%s" "evdata is empty ", FNAME);
		for (cl = TAILQ_FIRST(&iaidaddr->ifaddr_list); cl; 
				cl = TAILQ_NEXT(cl, link)) {		
			lv = dhcp6_find_listval(&optinfo->addr_list, &cl->dhcp6addr, 
				DHCP6_LISTVAL_DHCP6ADDR);
			/* remove leases that not on the updated list */
			if (lv == NULL)
				client6_remove_lease(cl);
			/* need to be update leases */
		}
		TAILQ_REMOVE(&ev->data_list, evd, link);
#ifdef mshirley
		/* some field in evd was freed twice, duidfree()? */
		free(evd);
		evd = NULL;
#endif
	}
	/* update server id */
	if (iaidaddr.state == IAID6S_REBIND) {
		if (duidcpy(&iaidaddr.serverid, serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
			return -1;
		}
	}
	if (iaidaddr.evdata) {
		TAILQ_REMOVE(&iaidaddr.evdata->event->data_list, 
				iaidaddr.evdata, link);
		free(iaidaddr.evdata);
		iaidaddr.evdata = NULL;
	}
	if (iaidaddr.timer == NULL) {
		    if ((iaidaddr.timer = dhcp6_add_timer(client6_iaidaddr_timo, &iaidaddr)) 
				    == NULL) {
		 	dprintf(LOG_ERR, "%s" "failed to add a timer for iaid %d",
				FNAME, iaidaddr.iaidinfo.iaid);
		 	return (-1);
		    }
	}
	/* update the start date and timer */
	time(&iaidaddr.start_date);
	iaidaddr.state = IAID6S_ACTIVE;
	timo.tv_sec = iaidaddr.iaidinfo.renewtime;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, iaidaddr.timer);
	return 0;
}

static int
client6_update_lease(addr, sp)
	struct dhcp6_addr *addr;
	struct client6_lease *sp;
{
	struct timeval timo;
	dprintf(LOG_DEBUG, "%s" " called", FNAME);	
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
	/* remove leases with validlifetime == 0, and preferlifetime == 0 */
	if (addr->validlifetime == 0 || addr->preferlifetime == 0) {
		dprintf(LOG_ERR, "%s" "zero address life time for %s",
			in6addr2str(&addr->addr, 0), FNAME);
		client6_remove_lease(sp);
	}
	memcpy(&sp->dhcp6addr, addr, sizeof(sp->dhcp6addr));
	if (sp->timer == NULL) {
		if ((sp->timer = dhcp6_add_timer(client6_lease_timo, sp)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a timer for lease %s",
				FNAME, in6addr2str(&addr->addr, 0));
			return (-1);
		}
	}
	timo.tv_sec = sp->dhcp6addr.preferlifetime;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, sp->timer);
	sp->state = ADDR6S_ACTIVE;
	return (0);
}

static struct client6_lease *
client6_find_lease(ifaddr)
	struct dhcp6_addr *ifaddr;
{
	struct client6_lease *sp;
	dprintf(LOG_DEBUG, "%s" " called", FNAME);	
	for (sp = TAILQ_FIRST(&iaidaddr.ifaddr_list); sp;
	     sp = TAILQ_NEXT(sp, link)) {
		/* sp->dhcp6addr.plen == ifaddr->plen */
		dprintf(LOG_DEBUG, "%s" "get address is %s ", FNAME,
			in6addr2str(&ifaddr->addr, 0));
		dprintf(LOG_DEBUG, "%s" "lease address is %s ", FNAME,
			in6addr2str(&sp->dhcp6addr.addr, 0));
		if (IN6_ARE_ADDR_EQUAL(&sp->dhcp6addr.addr, &ifaddr->addr)) {
			return (sp);
		}
	}
	return (NULL);
}

static struct dhcp6_timer *
client6_iaidaddr_timo(arg)
	void *arg;
{
	struct client6_iaidaddr *sp = (struct client6_iaidaddr *)arg;
	struct dhcp6_event *ev;
	struct dhcp6_eventdata *evd;
	struct timeval timeo;
	int dhcpstate;
	double d;

	dprintf(LOG_DEBUG, "%s" "iaidaddr timeout for %d, state=%d", FNAME,
		iaidaddr.iaidinfo.iaid, sp->state);

	/* cancel the current event for this iaidaddr. */
	if (sp->evdata) {
		TAILQ_REMOVE(&sp->evdata->event->data_list, sp->evdata, link);
		free(sp->evdata);
		sp->evdata = NULL;
	}
	
	if (sp->state == IAID6S_REBIND) {
		dprintf(LOG_INFO, "%s" "failed to rebind an iaidaddr %d",
		    FNAME, iaidaddr.iaidinfo.iaid);
		/* try another rebind or return NULL*/
		return (NULL);
	}
	/* ToDo: what kind of opiton Request value, client would like to pass? */
	switch(sp->state) {
	case IAID6S_ACTIVE:
		sp->state = IAID6S_RENEW;
		dhcpstate = DHCP6S_RENEW;
		d = sp->iaidinfo.rebindtime;
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		break;
	case IAID6S_RENEW:
		sp->state = IAID6S_REBIND;
		dhcpstate = DHCP6S_REBIND;
		/* ToDo: how long the rebind should wait ?
		 * if too long*/
		d = get_max_validlifetime(&iaidaddr); 
		/* ToDo: set a SOLICT event */
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		if (&sp->serverid)
			duidfree(&sp->serverid);
		break;
	default:
		return (NULL);
	}
	dhcp6_set_timer(&timeo, sp->timer);
	if ((ev = dhcp6_create_event(sp->ifp, dhcpstate)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event"
		    FNAME);
		return (NULL); /* XXX: should try to recover */
	}
	if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event "
		    "timer", FNAME);
		free(ev);
		return (NULL); /* XXX */
	}
	if ((evd = malloc(sizeof(*evd))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event "
		    "data", FNAME);
		free(ev->timer);
		free(ev);
		return (NULL); /* XXX */
	}
	if (sp->state == IAID6S_RENEW) {
		if (duidcpy(&ev->serverid, &sp->serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID",
			    FNAME);
			free(ev->timer);
			free(ev);
			return (NULL); /* XXX */
		}
	}
	memset(evd, 0, sizeof(*evd));
	evd->type = DHCP6_DATA_ADDR;
	evd->data = sp;
	evd->event = ev;
	TAILQ_INSERT_TAIL(&ev->data_list, evd, link);

	TAILQ_INSERT_TAIL(&sp->ifp->event_list, ev, link);

	ev->timeouts = 0;
	dhcp6_set_timeoparam(ev);
	dhcp6_reset_timer(ev);

	sp->evdata = evd;

	switch(sp->state) {
	case IAID6S_RENEW:
		ev->max_retrans_dur = sp->iaidinfo.rebindtime;
		break;
	case IAID6S_REBIND:
		ev->max_retrans_dur = get_max_validlifetime(&iaidaddr);
		break;
	}
	client6_send(ev);
	return (sp->timer);
}


static struct dhcp6_timer *
client6_lease_timo(arg)
	void *arg;
{
	struct client6_lease *sp = (struct client6_lease *)arg;
	struct timeval timeo;
	double d;

	dprintf(LOG_DEBUG, "%s" "lease timeout for %s, state=%d", FNAME,
		in6addr2str(&sp->dhcp6addr.addr, 0), sp->state);
	/* cancel the current event for this lease */
	if (sp->state == ADDR6S_INVALID) {
		dprintf(LOG_INFO, "%s" "failed to remove an addr %s",
		    FNAME, in6addr2str(&sp->dhcp6addr.addr, 0));
		client6_remove_lease(sp);
		return (NULL);
	}
	switch(sp->state) {
	case ADDR6S_ACTIVE:
		sp->state = ADDR6S_EXPIRED;
		d = sp->dhcp6addr.validlifetime - sp->dhcp6addr.preferlifetime;
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		dhcp6_set_timer(&timeo, sp->timer);
		break;
	case ADDR6S_EXPIRED:
		sp->state = ADDR6S_INVALID;
	default:
		client6_remove_lease(sp);
		return (NULL);
	}
	return (sp->timer);
}

static int
client6_ifaddrconf(cmd, ifaddr)
	ifaddrconf_cmd_t cmd;
	struct dhcp6_addr *ifaddr;
{
	struct in6_ifreq req;
	struct dhcp6_if *ifp = iaidaddr.ifp;
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
	req.ifr6_prefixlen = 64;

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

int
client6_do_release(addr_list)
	struct dhcp6_list *addr_list;
{
	/* create an event for a relese */
}

static u_int32_t
get_min_preferlifetime(sp)
	struct client6_iaidaddr *sp;
{
	struct client6_lease *lv, *first;
	u_int32_t min;
	if (TAILQ_EMPTY(&sp->ifaddr_list))
		return 0;
	first = TAILQ_FIRST(&sp->ifaddr_list);
	min = first->dhcp6addr.preferlifetime;
	for (lv = TAILQ_FIRST(&sp->ifaddr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		min = MIN(min, lv->dhcp6addr.preferlifetime);
	}
	return min;
}

static u_int32_t
get_max_validlifetime(sp)
	struct client6_iaidaddr *sp;
{
	struct client6_lease *lv, *first;
	u_int32_t max;
	if (TAILQ_EMPTY(&sp->ifaddr_list))
		return 0;
	first = TAILQ_FIRST(&sp->ifaddr_list);
	max = first->dhcp6addr.validlifetime;
	for (lv = TAILQ_FIRST(&sp->ifaddr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		max = MAX(max, lv->dhcp6addr.validlifetime);
	}
	return max;
}

