/*	$Id: client6_addr.c,v 1.1 2003/01/16 15:41:11 root Exp $	*/

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
static int client6_ifaddrconf __P((ifaddrconf_cmd_t, struct client6_lease *));

extern struct dhcp6_timer *client6_timo __P((void *));
extern void client6_send_renew __P((struct dhcp6_event *));
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
	iaidaddr.ifp = ifp;
	iaidaddr.renewtime = optinfo->renewtime;
	iaidaddr.rebindtime = optinfo->rebindtime;
	iaidaddr.iaid = optinfo->iaid;
	if (duidcpy(&iaidaddr.serverid, serverid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID %s", FNAME, serverid);
		return (-1);
	}
	TAILQ_INIT(&iaidaddr.ifaddr_list);
	/* add new address */
	for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		/* it shouldn't have duplicated leases here, if so ignore it */
		if (client6_find_lease(&lv->val_dhcp6addr) != NULL)
			continue;

		if (client6_add_lease(&lv->val_dhcp6addr)) {
			dprintf(LOG_ERR, "%s" "failed to add a new addr", FNAME);
			/* continue updating */
		}
	}
	return (0);
}

int
client6_add_lease(addr)
	struct dhcp6_addr *addr;
{
	struct client6_lease *sp;
	dprintf(LOG_DEBUG, "%s" "try to add address %s", FNAME,
		in6addr2str(&addr->addr, 0));

	/* ignore meaningless address, this never happens */
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
	sp->validlifetime = addr->validlifetime;
	sp->preferlifetime = addr->preferlifetime;
	memcpy(&sp->addr, &addr->addr, sizeof(addr->addr));
	sp->plen = addr->plen;
	sp->state = ADDR6S_ACTIVE;

	if (client6_ifaddrconf(IFADDRCONF_ADD, sp) != 0) {
		dprintf(LOG_ERR, "%s" "adding address failed: %s",
		    FNAME, in6addr2str(&addr->addr, 0));
		free(sp);
		return (-1);
	}
	/* ToDo: preferlifetime EXPIRED; validlifetime DELETED; renew T1; rebind T2 timer
	 * renew/rebind based on iaid, preferlifetime, validlifetime based on per addr
	 */
	/* if a finite lease perferlifetime is specified, set up a timer. */
	TAILQ_INSERT_TAIL(&iaidaddr.ifaddr_list, sp, link);
	return 0;
}

void
client6_remove_iaidaddr()
{
	struct client6_lease *ifa;

	while ((ifa = TAILQ_FIRST(&iaidaddr.ifaddr_list)) != NULL) {
		TAILQ_REMOVE(&iaidaddr.ifaddr_list, ifa, link);
		dprintf(LOG_DEBUG, "%s" "removing address %s", FNAME,
	    		in6addr2str(&ifa->addr, 0));
		if (ifa->timer)
			dhcp6_remove_timer(&ifa->timer);
		if (ifa->evdata) {
			TAILQ_REMOVE(&ifa->evdata->event->data_list, ifa->evdata, link);
			free(ifa->evdata);
		}
		client6_ifaddrconf(IFADDRCONF_REMOVE, ifa);
		free(ifa);
	}

	duidfree(&iaidaddr.serverid);
	/* ToDo: send release message to server */
	iaidaddr.iaid = 0;
	iaidaddr.renewtime = 0;
	iaidaddr.rebindtime = 0;
	
	if (iaidaddr.timer)
		dhcp6_remove_timer(&iaidaddr.timer);

	if (iaidaddr.evdata) {
		TAILQ_REMOVE(&iaidaddr.evdata->event->data_list, iaidaddr.evdata, link);
		free(iaidaddr.evdata);
		iaidaddr.evdata = NULL;
	}
	return;
}

int
client6_update_iaidaddr(ev, optinfo, serverid)
	struct dhcp6_event *ev;
	struct dhcp6_optinfo *optinfo;
	struct duid *serverid;
{
	struct dhcp6_listval *lv;
	struct dhcp6_eventdata *evd, *evd_next;
	
	/* add new address */
	for (lv = TAILQ_FIRST(&optinfo->addr_list); lv; lv = TAILQ_NEXT(lv, link)) {
		struct client6_lease *cl_lease;
		/* need to be update the corresponding parameters */
		if ((cl_lease = client6_find_lease(&lv->val_dhcp6addr)) != NULL) {
			client6_update_lease(&lv->val_dhcp6addr, cl_lease);
			continue;
		}
		/* need to add the new addrs */	
		if (client6_add_lease(&lv->val_dhcp6addr)) {
			dprintf(LOG_INFO, "%s" "failed to add a new addr");
			continue;
		}
		/* and also remove the lease which are not on the current addr list */
	}
	/* ToDo: 
	 * update existing address
	 * remove addresses that were not updated 
	 * if we're rebinding the addr, copy the new server ID.
	 */
	if (iaidaddr.state == ADDR6S_REBIND) {
		if (duidcpy(&iaidaddr.serverid, serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
			return -1;
		}
	}

	return 0;
}

static int
client6_update_lease(addr, sp)
	struct dhcp6_addr *addr;
	struct client6_lease *sp;
{
	if (addr->preferlifetime == DHCP6_DURATITION_INFINITE) {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with infinite preferlifetime", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen);
	} else {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with preferlifetime %d", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen);
	}
	if (addr->validlifetime == DHCP6_DURATITION_INFINITE) {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with infinite validlifetime", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen);
	} else {
		dprintf(LOG_DEBUG, "%s" "update an address %s/%d "
		    "with validlifetime %d", FNAME,
		    in6addr2str(&addr->addr, 0), addr->plen);
	}
 
	sp->validlifetime = addr->validlifetime;
	sp->preferlifetime = addr->preferlifetime;

	/* ToDo: update the renew/rebind, expire/release timer*/
	
	sp->state = ADDR6S_ACTIVE;
	return (0);
}

static struct client6_lease *
client6_find_lease(ifaddr)
	struct dhcp6_addr *ifaddr;
{
	struct client6_lease *sp;

	for (sp = TAILQ_FIRST(&iaidaddr.ifaddr_list); sp;
	     sp = TAILQ_NEXT(sp, link)) {
		if (sp->plen == ifaddr->plen &&
		    IN6_ARE_ADDR_EQUAL(&sp->addr, &ifaddr->addr)) {
			return (sp);
		}
	}
	return (NULL);
}

static int
client6_ifaddrconf(cmd, ifaddr)
	ifaddrconf_cmd_t cmd;
	struct client6_lease *ifaddr;
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
	memcpy(&req.ifr6_addr, &ifaddr->addr, sizeof(ifaddr->addr));
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

