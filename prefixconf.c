/*	$Id: prefixconf.c,v 1.4 2003/02/10 23:47:09 shirleyma Exp $	*/
/*	ported from KAME: prefixconf.c,v 1.9 2002/12/12 09:47:26 suz Exp */

/*
 * Copyright (C) 2002 WIDE Project.
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
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ioctl.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <linux/ipv6.h>

#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <queue.h>

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "prefixconf.h"

/* should be moved to a header file later */
struct dhcp6_ifprefix {
	TAILQ_ENTRY(dhcp6_ifprefix) plink;

	/* interface configuration */
	struct prefix_ifconf *ifconf;

	/* interface prefix parameters */
	struct sockaddr_in6 paddr;
	int plen;

	/* address assigned on the interface based on the prefix */
	struct sockaddr_in6 ifaddr;
};
static TAILQ_HEAD(, dhcp6_siteprefix) siteprefix_listhead;

typedef enum { IFADDRCONF_ADD, IFADDRCONF_REMOVE } ifaddrconf_cmd_t;

static int ifaddrconf __P((ifaddrconf_cmd_t, struct dhcp6_ifprefix *));
static struct dhcp6_siteprefix *find_siteprefix6 __P((struct dhcp6_prefix *));
static struct dhcp6_timer *prefix6_timo __P((void *));
static int add_ifprefix __P((struct dhcp6_siteprefix *,
    struct dhcp6_prefix *, struct prefix_ifconf *));
static void prefix6_remove __P((struct dhcp6_siteprefix *));
static int update __P((struct dhcp6_siteprefix *, struct dhcp6_prefix *,
			  struct duid *));

extern struct dhcp6_timer *client6_timo __P((void *));
extern void client6_send __P((struct dhcp6_event *));

void
prefix6_init()
{
	TAILQ_INIT(&siteprefix_listhead);
}

void
prefix6_remove_all()
{
	struct dhcp6_siteprefix *sp, *sp_next;

	for (sp = TAILQ_FIRST(&siteprefix_listhead); sp; sp = sp_next) {
		sp_next = TAILQ_NEXT(sp, link);

		prefix6_remove(sp);
	}
}

int
prefix6_add(ifp, prefix, serverid)
	struct dhcp6_if *ifp;
	struct dhcp6_prefix *prefix;
	struct duid *serverid;
{
	struct prefix_ifconf *pif;
	struct dhcp6_siteprefix *sp;

	dprintf(LOG_DEBUG, "%s" "try to add prefix %s/%d", FNAME,
		in6addr2str(&prefix->addr, 0), prefix->plen);

	/* ignore meaningless prefix */
	if (prefix->duration == 0) {
		dprintf(LOG_INFO, "%s" "zero duration for %s/%d",
			in6addr2str(&prefix->addr, 0), prefix->plen);
		return 0;
	}

	if ((sp = find_siteprefix6(prefix)) != NULL) {
		dprintf(LOG_INFO, "%s" "duplicated delegated prefix: %s/%d",
		    FNAME, in6addr2str(&prefix->addr, 0), prefix->plen);
		return -1;
	}

	if ((sp = malloc(sizeof(*sp))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory"
			" for a prefix", FNAME);
		return -1;
	}
	memset(sp, 0, sizeof(*sp));
	TAILQ_INIT(&sp->ifprefix_list);
	sp->prefix = *prefix;
	sp->ifp = ifp;
	sp->state = PREFIX6S_ACTIVE;
	if (duidcpy(&sp->serverid, serverid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID");
		goto fail;
	}

	/* if a finite lease duration is specified, set up a timer. */
	if (sp->prefix.duration != DHCP6_DURATITION_INFINITE) {
		struct timeval timo;

		if ((sp->timer = dhcp6_add_timer(prefix6_timo, sp)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a timer for "
				"prefix %s/%d",
				in6addr2str(&prefix->addr, 0), prefix->plen);
			goto fail;
		}
		
		timo.tv_sec = sp->prefix.duration >> 1;
		timo.tv_usec = 0;

		dhcp6_set_timer(&timo, sp->timer);
	}

	for (pif = prefix_ifconflist; pif; pif = pif->next) {
		/*
		 * the requesting router MUST NOT assign any delegated
		 * prefixes or subnets from the delegated prefix(es) to the
		 * link through which it received the DHCP message from the
		 * delegating router.
		 * [dhcpv6-opt-prefix-delegation-01, Section 11.1]
		 */
		if (strcmp(pif->ifname, ifp->ifname) == 0)
			continue;

		add_ifprefix(sp, prefix, pif);
	}

	TAILQ_INSERT_TAIL(&siteprefix_listhead, sp, link);

	return 0;

  fail:
	if (sp) {
		duidfree(&sp->serverid);
		free(sp);
	}
	return -1;
}

static void
prefix6_remove(sp)
	struct dhcp6_siteprefix *sp;
{
	struct dhcp6_ifprefix *ipf;

	dprintf(LOG_DEBUG, "%s" "removing prefix %s/%d", FNAME,
	    in6addr2str(&sp->prefix.addr, 0), sp->prefix.plen);

	while ((ipf = TAILQ_FIRST(&sp->ifprefix_list)) != NULL) {
		TAILQ_REMOVE(&sp->ifprefix_list, ipf, plink);
		ifaddrconf(IFADDRCONF_REMOVE, ipf);
		free(ipf);
	}

	duidfree(&sp->serverid);

	if (sp->timer)
		dhcp6_remove_timer(sp->timer);

	if (sp->evdata) {
		TAILQ_REMOVE(&sp->evdata->event->data_list, sp->evdata, link);
		free(sp->evdata);
		sp->evdata = NULL;
	}

	TAILQ_REMOVE(&siteprefix_listhead, sp, link);

	free(sp);
}

int
prefix6_update(ev, prefix_list, serverid)
	struct dhcp6_event *ev;
	struct dhcp6_list *prefix_list;
	struct duid *serverid;
{
	struct dhcp6_listval *lv;
	struct dhcp6_eventdata *evd, *evd_next;

	/* add new prefixes */
	for (lv = TAILQ_FIRST(prefix_list); lv; lv = TAILQ_NEXT(lv, link)) {
		if (find_siteprefix6(&lv->val_prefix6) != NULL)
			continue;

		if (prefix6_add(ev->ifp, &lv->val_prefix6, serverid)) {
			dprintf(LOG_INFO, "%s" "failed to add a new prefix");
			/* continue updating */
		}
	}

	/* update existing prefixes */
	for (evd = TAILQ_FIRST(&ev->data_list); evd; evd = evd_next) {
		evd_next = TAILQ_NEXT(evd, link);

		if (evd->type != DHCP6_DATA_PREFIX)
			continue;

		lv = dhcp6_find_listval(prefix_list,
		    &((struct dhcp6_siteprefix *)evd->data)->prefix,
		    DHCP6_LISTVAL_PREFIX6);
		if (lv == NULL)
			continue;

		TAILQ_REMOVE(&ev->data_list, evd, link);
		((struct dhcp6_siteprefix *)evd->data)->evdata = NULL;

		update((struct dhcp6_siteprefix *)evd->data,
		    &lv->val_prefix6, serverid);

		free(evd);		    
	}

	/* remove prefixes that were not updated */
	for (evd = TAILQ_FIRST(&ev->data_list); evd; evd = evd_next) {
		evd_next = TAILQ_NEXT(evd, link);

		if (evd->type != DHCP6_DATA_PREFIX)
			continue;

		TAILQ_REMOVE(&ev->data_list, evd, link);
		((struct dhcp6_siteprefix *)evd->data)->evdata = NULL;

		prefix6_remove((struct dhcp6_siteprefix *)evd->data);

		free(evd);
	}

	return 0;
}

static int
update(sp, prefix, serverid)
	struct dhcp6_siteprefix *sp;
	struct dhcp6_prefix *prefix;
	struct duid *serverid;
{
	struct timeval timo;

	if (prefix->duration == DHCP6_DURATITION_INFINITE) {
		dprintf(LOG_DEBUG, "%s" "update a prefix %s/%d "
		    "with infinite duration", FNAME,
		    in6addr2str(&prefix->addr, 0), prefix->plen,
		    prefix->duration);
	} else {
		dprintf(LOG_DEBUG, "%s" "update a prefix %s/%d "
		    "with duration %d", FNAME,
		    in6addr2str(&prefix->addr, 0), prefix->plen,
		    prefix->duration);
	}
 
	sp->prefix.duration = prefix->duration;

	switch(sp->prefix.duration) {
	case 0:
		prefix6_remove(sp);
		return 0;
	case DHCP6_DURATITION_INFINITE:
		if (sp->timer)
			dhcp6_remove_timer(sp->timer);
		break;
	default:
		if (sp->timer == NULL) {
			sp->timer = dhcp6_add_timer(prefix6_timo, sp);
			if (sp->timer == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add prefix "
				    "timer", FNAME);
				prefix6_remove(sp); /* XXX */
				return -1;
			}
		}
		/* update the timer */
		timo.tv_sec = sp->prefix.duration >> 1;
		timo.tv_usec = 0;

		dhcp6_set_timer(&timo, sp->timer);
		break;
	}

	/* if we're rebinding the prefix, copy the new server ID. */
	if (sp->state == PREFIX6S_REBIND) {
		if (duidcpy(&sp->serverid, serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID");
			prefix6_remove(sp); /* XXX */
			return -1;
		}
	}

	sp->state = PREFIX6S_ACTIVE;

	return 0;
}

static struct dhcp6_siteprefix *
find_siteprefix6(prefix)
	struct dhcp6_prefix *prefix;
{
	struct dhcp6_siteprefix *sp;

	for (sp = TAILQ_FIRST(&siteprefix_listhead); sp;
	     sp = TAILQ_NEXT(sp, link)) {
		if (sp->prefix.plen == prefix->plen &&
		    IN6_ARE_ADDR_EQUAL(&sp->prefix.addr, &prefix->addr)) {
			return (sp);
		}
	}

	return (NULL);
}

static struct dhcp6_timer *
prefix6_timo(arg)
	void *arg;
{
	struct dhcp6_siteprefix *sp = (struct dhcp6_siteprefix *)arg;
	struct dhcp6_event *ev;
	struct dhcp6_eventdata *evd;
	struct timeval timeo;
	int dhcpstate;
	double d;

	dprintf(LOG_DEBUG, "%s" "prefix timeout for %s/%d, state=%d", FNAME,
		in6addr2str(&sp->prefix.addr, 0), sp->prefix.plen, sp->state);

	/* cancel the current event for the prefix. */
	if (sp->evdata) {
		TAILQ_REMOVE(&sp->evdata->event->data_list, sp->evdata, link);
		free(sp->evdata);
		sp->evdata = NULL;
	}

	if (sp->state == PREFIX6S_REBIND) {
		dprintf(LOG_INFO, "%s" "failed to rebind a prefix %s/%d",
		    FNAME, in6addr2str(&sp->prefix.addr, 0), sp->prefix.plen);
		prefix6_remove(sp);
		return (NULL);
	}

	switch(sp->state) {
	case PREFIX6S_ACTIVE:
		sp->state = PREFIX6S_RENEW;
		dhcpstate = DHCP6S_RENEW;
		d = sp->prefix.duration / 3; /* (0.8 - 0.5) * duration */
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		break;
	case PREFIX6S_RENEW:
		sp->state = PREFIX6S_REBIND;
		dhcpstate = DHCP6S_REBIND;
		d = sp->prefix.duration / 5; /* (1.0 - 0.8) * duration */
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		duidfree(&sp->serverid);
		break;
	default:
		return (NULL);
	}
	dhcp6_set_timer(&timeo, sp->timer);

	if ((ev = dhcp6_create_event(sp->ifp, dhcpstate)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event"
		    FNAME);
		exit(1); /* XXX: should try to recover */
	}
	if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event "
		    "timer", FNAME);
		free(ev);
		exit(1); /* XXX */
	}
	if ((evd = malloc(sizeof(*evd))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to create a new event "
		    "data", FNAME);
		free(ev->timer);
		free(ev);
		exit(1); /* XXX */
	}
	if (sp->state == PREFIX6S_RENEW) {
		if (duidcpy(&ev->serverid, &sp->serverid)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID",
			    FNAME);
			free(ev->timer);
			free(ev);
			exit(1); /* XXX */
		}
	}
	memset(evd, 0, sizeof(*evd));
	evd->type = DHCP6_DATA_PREFIX;
	evd->data = sp;
	evd->event = ev;
	TAILQ_INSERT_TAIL(&ev->data_list, evd, link);

	TAILQ_INSERT_TAIL(&sp->ifp->event_list, ev, link);

	ev->timeouts = 0;
	dhcp6_set_timeoparam(ev);
	dhcp6_reset_timer(ev);

	sp->evdata = evd;

	switch(sp->state) {
	case PREFIX6S_RENEW:
	case PREFIX6S_REBIND:
		client6_send(ev);
		break;
	case PREFIX6S_ACTIVE:
		/* what to do? */
		break;
	}

	return (sp->timer);
}

static int
add_ifprefix(siteprefix, prefix, pconf)
	struct dhcp6_siteprefix *siteprefix;
	struct dhcp6_prefix *prefix;
	struct prefix_ifconf *pconf;
{
	struct dhcp6_ifprefix *ifpfx = NULL;
	struct in6_addr *a;
	u_long sla_id;
	char *sp;
	int b, i;

	if ((ifpfx = malloc(sizeof(*ifpfx))) == NULL) {
		dprintf(LOG_ERR, FNAME
		    "failed to allocate memory for ifprefix");
		return -1;
	}
	memset(ifpfx, 0, sizeof(*ifpfx));

	ifpfx->ifconf = pconf;

	ifpfx->paddr.sin6_family = AF_INET6;
	ifpfx->paddr.sin6_addr = prefix->addr;
	ifpfx->plen = prefix->plen + pconf->sla_len;
	/*
	 * XXX: our current implementation assumes ifid len is a multiple of 8
	 */
	if ((pconf->ifid_len % 8) != 0) {
		dprintf(LOG_NOTICE, FNAME
		    "assumption failure on the length of interface ID");
		goto bad;
	}
	if (ifpfx->plen + pconf->ifid_len < 0 ||
	    ifpfx->plen + pconf->ifid_len > 128) {
		dprintf(LOG_INFO, FNAME
			"invalid prefix length %d + %d + %d",
			prefix->plen, pconf->sla_len, pconf->ifid_len);
		goto bad;
	}

	/* copy prefix and SLA ID */
	a = &ifpfx->paddr.sin6_addr;
	b = prefix->plen;
	for (i = 0, b = prefix->plen; b > 0; b -= 8, i++)
		a->s6_addr[i] = prefix->addr.s6_addr[i];
	sla_id = htonl(pconf->sla_id);
	sp = ((char *)&sla_id + 3);
	i = (128 - pconf->ifid_len) / 8;
	for (b = pconf->sla_len; b > 7; b -= 8, sp--)
		a->s6_addr[--i] = *sp;
	if (b)
		a->s6_addr[--i] |= *sp;

	/* configure the corresponding address */
	ifpfx->ifaddr = ifpfx->paddr;
	for (i = 15; i >= pconf->ifid_len / 8; i--)
		ifpfx->ifaddr.sin6_addr.s6_addr[i] = pconf->ifid[i];
	if (ifaddrconf(IFADDRCONF_ADD, ifpfx))
		goto bad;

	/* TODO: send a control message for other processes */

	TAILQ_INSERT_TAIL(&siteprefix->ifprefix_list, ifpfx, plink);

	return 0;

  bad:
	if (ifpfx)
		free(ifpfx);
	return -1;
}

static int
ifaddrconf(cmd, ifpfx)
	ifaddrconf_cmd_t cmd;
	struct dhcp6_ifprefix *ifpfx;
{
	struct prefix_ifconf *pconf = ifpfx->ifconf;
	struct in6_ifreq req;
	unsigned long ioctl_cmd;
	char *cmdstr;
	int s;			/* XXX overhead */

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

	if ((s = socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "can't open a temporary socket: %s",
			FNAME, strerror(errno));
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.ifr6_ifindex = if_nametoindex(pconf->ifname);
	memcpy(&req.ifr6_addr, &ifpfx->ifaddr, sizeof(req.ifr6_addr));
	req.ifr6_prefixlen = ifpfx->plen;

	if (ioctl(s, ioctl_cmd, &req)) {
		dprintf(LOG_NOTICE, "%s" "failed to %s an address on %s: %s",
		    FNAME, cmdstr, pconf->ifname, strerror(errno));
		close(s);
		return (-1);
	}

	dprintf(LOG_DEBUG, "%s" "%s an address %s on %s", FNAME, cmdstr,
	    addr2str((struct sockaddr *)&ifpfx->ifaddr), pconf->ifname);

	close(s);
	return (0);
}
