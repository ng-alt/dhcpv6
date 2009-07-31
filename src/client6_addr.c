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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
# include <linux/sockios.h>
#endif

#ifndef HAVE_STRUCT_IN6_IFREQ_IFR6_ADDR
#ifdef HAVE_LINUX_IPV6_H
# include <linux/ipv6.h>
#endif
#endif

#ifdef HAVE_NET_IF_VAR_H
# include <net/if_var.h>
#endif

#ifdef HAVE_NETINET6_IN6_VAR_H
# include <netinet6/in6_var.h>
#endif

#include <glib.h>

#include "duid.h"
#include "dhcp6.h"
#include "confdata.h"
#include "common.h"
#include "timer.h"
#include "server6_conf.h"
#include "lease.h"
#include "str.h"
#include "gfunc.h"
#include "client6_addr.h"

extern void run_script(struct dhcp6_if *, gint, gint, guint32);

gint dhcp6_add_lease(dhcp6_addr_t *);

extern dhcp6_iaidaddr_t client6_iaidaddr;
extern dhcp6_timer_t *client6_timo(void *);
extern void client6_send(dhcp6_event_t *);
extern void free_servers(struct dhcp6_if *);

extern gint nlsock;
extern FILE *client6_lease_file;
extern dhcp6_iaidaddr_t client6_iaidaddr;
extern GSList *request_list;

/* BEGIN STATIC FUNCTIONS */

static gint _dhcp6_update_lease(dhcp6_addr_t *addr, dhcp6_lease_t *sp) {
    struct timeval timo;
    gdouble d;

    if (addr->status_code != DH6OPT_STCODE_SUCCESS &&
        addr->status_code != DH6OPT_STCODE_UNDEFINE) {
        g_error("%s: not successful status code for %s is %s", __func__,
                in6addr2str(&addr->addr, 0),
                dhcp6_stcodestr(addr->status_code));
        dhcp6c_remove_lease(sp);
        return 0;
    }

    /* remove leases with validlifetime == 0, and preferlifetime == 0 */
    if (addr->validlifetime == 0 || addr->preferlifetime == 0 ||
        addr->preferlifetime > addr->validlifetime) {
        g_error("%s: invalid address life time for %s",
                __func__, in6addr2str(&addr->addr, 0));
        dhcp6c_remove_lease(sp);
        return 0;
    }

    memcpy(&sp->lease_addr, addr, sizeof(sp->lease_addr));
    sp->state = ACTIVE;
    time(&sp->start_date);

    if (write_lease(sp, client6_lease_file) != 0) {
        g_error("%s: failed to write an updated lease address %s to lease file",
                __func__, in6addr2str(&sp->lease_addr.addr, 0));
        return -1;
    }

    if (sp->lease_addr.validlifetime == DHCP6_DURATITION_INFINITE ||
        sp->lease_addr.preferlifetime == DHCP6_DURATITION_INFINITE) {
        g_message("%s: infinity address life time for %s",
                  __func__, in6addr2str(&addr->addr, 0));

        if (sp->timer) {
            dhcp6_remove_timer(sp->timer);
        }

        return 0;
    }

    if (sp->timer == NULL) {
        if ((sp->timer = dhcp6_add_timer(dhcp6_lease_timo, sp)) == NULL) {
            g_error("%s: failed to add a timer for lease %s",
                    __func__, in6addr2str(&addr->addr, 0));
            return -1;
        }
    }

    d = sp->lease_addr.preferlifetime;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, sp->timer);

    return 0;
}

static dhcp6_event_t *_dhcp6_iaidaddr_find_event(dhcp6_iaidaddr_t *sp,
                                                 gint state) {
    dhcp6_event_t *event;
    GSList *iterator = sp->ifp->event_list;

    while (iterator) {
        event = (dhcp6_event_t *) iterator->data;

        if (event->state == state) {
            return event;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

/* END STATIC FUNCTIONS */

void dhcp6_init_iaidaddr(void) {
    memset(&client6_iaidaddr, 0, sizeof(client6_iaidaddr));
    client6_iaidaddr.lease_list = NULL;
}

gint dhcp6_add_iaidaddr(dhcp6_optinfo_t *optinfo, ia_t *ia) {
    dhcp6_value_t *lv = NULL;
    struct timeval timo;
    dhcp6_lease_t *cl_lease = NULL;
    gdouble d;
    GSList *iterator = ia->addr_list;

    /* ignore IA with T1 > T2 */
    if (ia->iaidinfo.renewtime > ia->iaidinfo.rebindtime) {
        g_message(" renew time is greater than rebind time");
        return 0;
    }

    memcpy(&client6_iaidaddr.client6_info.iaidinfo, &ia->iaidinfo,
           sizeof(client6_iaidaddr.client6_info.iaidinfo));
    client6_iaidaddr.client6_info.type = ia->type;
    duidcpy(&client6_iaidaddr.client6_info.clientid, &optinfo->clientID);

    if (duidcpy(&client6_iaidaddr.client6_info.serverid, &optinfo->serverID)) {
        g_error("%s: failed to copy server ID %s",
                __func__, duidstr(&optinfo->serverID));
        return -1;
    }

    /* add new address */
    while (iterator) {
        lv = (dhcp6_value_t *) iterator->data;

        if (lv->val_dhcp6addr.type != IAPD) {
            lv->val_dhcp6addr.plen =
                dhcp6_get_prefixlen(&lv->val_dhcp6addr.addr, dhcp6_if);

            if (lv->val_dhcp6addr.plen == PREFIX_LEN_NOTINRA) {
                g_warning("assigned address %s prefix len is not in any RAs"
                          " prefix length using 64 bit instead",
                          in6addr2str(&lv->val_dhcp6addr.addr, 0));
            }
        }

        if ((cl_lease = dhcp6_find_lease(&client6_iaidaddr,
                                         &lv->val_dhcp6addr)) != NULL) {
            _dhcp6_update_lease(&lv->val_dhcp6addr, cl_lease);
            continue;
        }

        if (dhcp6_add_lease(&lv->val_dhcp6addr)) {
            g_error("%s: failed to add a new addr lease %s",
                    __func__, in6addr2str(&lv->val_dhcp6addr.addr, 0));
            continue;
        }

        iterator = g_slist_next(iterator);
    }

    if (!g_slist_length(client6_iaidaddr.lease_list)) {
        return 0;
    }

    /* set up renew T1, rebind T2 timer renew/rebind based on iaid */
    /* Should we process IA_TA, IA_NA differently */
    if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0 ||
        client6_iaidaddr.client6_info.iaidinfo.renewtime >
        client6_iaidaddr.client6_info.iaidinfo.rebindtime) {
        guint32 min_plifetime;

        min_plifetime = get_min_preferlifetime(&client6_iaidaddr);

        if (min_plifetime == DHCP6_DURATITION_INFINITE) {
            client6_iaidaddr.client6_info.iaidinfo.renewtime = min_plifetime;
        } else {
            client6_iaidaddr.client6_info.iaidinfo.renewtime =
                min_plifetime / 2;
        }
    }

    if (client6_iaidaddr.client6_info.iaidinfo.rebindtime == 0 ||
        client6_iaidaddr.client6_info.iaidinfo.renewtime >
        client6_iaidaddr.client6_info.iaidinfo.rebindtime) {
        client6_iaidaddr.client6_info.iaidinfo.rebindtime =
            get_min_preferlifetime(&client6_iaidaddr) * 4 / 5;
    }

    g_message("renew time %d, rebind time %d",
              client6_iaidaddr.client6_info.iaidinfo.renewtime,
              client6_iaidaddr.client6_info.iaidinfo.rebindtime);

    if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
        return 0;
    }

    if (client6_iaidaddr.client6_info.iaidinfo.renewtime ==
        DHCP6_DURATITION_INFINITE) {
        client6_iaidaddr.client6_info.iaidinfo.rebindtime =
            DHCP6_DURATITION_INFINITE;
        return 0;
    }

    /* set up start date, and renew timer */
    if ((client6_iaidaddr.timer =
         dhcp6_add_timer(dhcp6_iaidaddr_timo, &client6_iaidaddr)) == NULL) {
        g_error("%s: failed to add a timer for iaid %u",
                __func__, client6_iaidaddr.client6_info.iaidinfo.iaid);
        return -1;
    }

    time(&client6_iaidaddr.start_date);
    client6_iaidaddr.state = ACTIVE;
    d = client6_iaidaddr.client6_info.iaidinfo.renewtime;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, client6_iaidaddr.timer);

    return 0;
}

gint dhcp6_add_lease(dhcp6_addr_t *addr) {
    dhcp6_lease_t *sp;
    struct timeval timo;
    gdouble d;

    g_debug("%s: try to add address %s",
            __func__, in6addr2str(&addr->addr, 0));

    /* ignore meaningless address */
    if (addr->status_code != DH6OPT_STCODE_SUCCESS &&
        addr->status_code != DH6OPT_STCODE_UNDEFINE) {
        g_error("%s: not successful status code for %s is %s", __func__,
                in6addr2str(&addr->addr, 0),
                dhcp6_stcodestr(addr->status_code));
        return 0;
    }

    if (addr->validlifetime == 0 || addr->preferlifetime == 0 ||
        addr->preferlifetime > addr->validlifetime) {
        g_error("%s: invalid address life time for %s",
                __func__, in6addr2str(&addr->addr, 0));
        return 0;
    }

    if ((sp = dhcp6_find_lease(&client6_iaidaddr, addr)) != NULL) {
        g_error("%s: duplicated address: %s",
                __func__, in6addr2str(&addr->addr, 0));
        return -1;
    }

    if ((sp = (dhcp6_lease_t *) g_malloc0(sizeof(*sp))) == NULL) {
        g_error("%s: failed to allocate memory for a addr", __func__);
        return -1;
    }

    memcpy(&sp->lease_addr, addr, sizeof(sp->lease_addr));
    sp->iaidaddr = &client6_iaidaddr;
    time(&sp->start_date);
    sp->state = ACTIVE;

    if (client6_lease_file && (write_lease(sp, client6_lease_file) != 0)) {
        g_error("%s: failed to write a new lease address %s to lease file",
                __func__, in6addr2str(&sp->lease_addr.addr, 0));

        if (sp->timer) {
            dhcp6_remove_timer(sp->timer);
        }

        g_free(sp);
        sp = NULL;
        return -1;
    }

    if (sp->lease_addr.type == IAPD) {
        g_message("request prefix is %s/%d",
                  in6addr2str(&sp->lease_addr.addr, 0), sp->lease_addr.plen);
    } else if (client6_ifaddrconf(IFADDRCONF_ADD, addr) != 0) {
        g_error("%s: adding address failed: %s",
                __func__, in6addr2str(&addr->addr, 0));

        if (sp->timer) {
            dhcp6_remove_timer(sp->timer);
        }

        g_free(sp);
        sp = NULL;
        return -1;
    }

    client6_iaidaddr.lease_list = g_slist_append(client6_iaidaddr.lease_list,
                                                 sp);

    /* for infinite lifetime don't do any timer */
    if (sp->lease_addr.validlifetime == DHCP6_DURATITION_INFINITE ||
        sp->lease_addr.preferlifetime == DHCP6_DURATITION_INFINITE) {
        g_message("%s: infinity address life time for %s",
                  __func__, in6addr2str(&addr->addr, 0));
        return 0;
    }

    /* set up expired timer for lease */
    if ((sp->timer = dhcp6_add_timer(dhcp6_lease_timo, sp)) == NULL) {
        g_error("%s: failed to add a timer for lease %s",
                __func__, in6addr2str(&addr->addr, 0));
        g_free(sp);
        sp = NULL;
        return -1;
    }

    d = sp->lease_addr.preferlifetime;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, sp->timer);
    return 0;
}

gint dhcp6_remove_iaidaddr(dhcp6_iaidaddr_t *iaidaddr) {
    dhcp6_lease_t *lv = NULL;
    GSList *iterator = iaidaddr->lease_list;

    while (iterator) {
        lv = (dhcp6_lease_t *) iterator->data;
        dhcp6c_remove_lease(lv);
        iterator = g_slist_next(iterator);
    }

    /*
     * if (iaidaddr->client6_info.serverid.duid_id != NULL)
     * duidfree(&iaidaddr->client6_info.serverid);
     */
    if (iaidaddr->timer) {
        dhcp6_remove_timer(iaidaddr->timer);
    }

    g_slist_free(iaidaddr->lease_list);
    iaidaddr->lease_list = NULL;
    return 0;
}

gint dhcp6c_remove_lease(dhcp6_lease_t *sp) {
    g_debug("%s: removing address %s", __func__,
            in6addr2str(&sp->lease_addr.addr, 0));
    sp->state = INVALID;

    if (write_lease(sp, client6_lease_file) != 0) {
        g_message("%s: failed to write removed lease address %s to lease file",
                  __func__, in6addr2str(&sp->lease_addr.addr, 0));
        return -1;
    }

    /* XXX: ToDo: prefix delegation for client */
    if (sp->lease_addr.type == IAPD) {
        g_message("request prefix is %s/%d",
                  in6addr2str(&sp->lease_addr.addr, 0), sp->lease_addr.plen);
        /* XXX: remove from the update prefix list */
    } else if (client6_ifaddrconf(IFADDRCONF_REMOVE, &sp->lease_addr) != 0) {
        g_message("%s: removing address %s failed",
                  __func__, in6addr2str(&sp->lease_addr.addr, 0));
    }

    /* remove expired timer for this lease. */
    if (sp->timer) {
        dhcp6_remove_timer(sp->timer);
    }

    client6_iaidaddr.lease_list = g_slist_remove(client6_iaidaddr.lease_list,
                                                 sp);
    g_free(sp);
    sp = NULL;

    /* can't remove expired iaidaddr even there is no lease in this iaidaddr
     * since the rebind->solicit timer uses this iaidaddr
     *
     * if (!g_slist_length(client6_iaidaddr.lease_list)) {
     *     dhcp6_remove_iaidaddr();
     * }
     */

    return 0;
}

gint dhcp6_update_iaidaddr(dhcp6_optinfo_t *optinfo, ia_t *ia, gint flag) {
    dhcp6_value_t *lv = NULL;
    dhcp6_lease_t *cl = NULL;
    struct timeval timo;
    gdouble d;
    GSList *iterator = NULL;

    if (client6_iaidaddr.client6_info.iaidinfo.renewtime >
        client6_iaidaddr.client6_info.iaidinfo.rebindtime) {
        g_message(" renew time is greater than rebind time");
        return 0;
    }

    if (flag == ADDR_REMOVE) {
        iterator = ia->addr_list;

        while (iterator) {
            lv = (dhcp6_value_t *) iterator->data;
            cl = dhcp6_find_lease(&client6_iaidaddr, &lv->val_dhcp6addr);

            if (cl) {
                /* remove leases */
                dhcp6c_remove_lease(cl);
            }

            iterator = g_slist_next(iterator);
        }

        return 0;
    }

    /* flag == ADDR_UPDATE */
    iterator = ia->addr_list;
    while (iterator) {
        lv = (dhcp6_value_t *) iterator->data;

        if (lv->val_dhcp6addr.type != IAPD) {
            lv->val_dhcp6addr.plen =
                dhcp6_get_prefixlen(&lv->val_dhcp6addr.addr, dhcp6_if);

            if (lv->val_dhcp6addr.plen == PREFIX_LEN_NOTINRA) {
                g_warning("assigned address %s is not in any RAs"
                          " prefix length using 64 bit instead",
                          in6addr2str(&lv->val_dhcp6addr.addr, 0));
            }
        }

        if ((cl = dhcp6_find_lease(&client6_iaidaddr,
                                   &lv->val_dhcp6addr)) != NULL) {
            /* update leases */
            _dhcp6_update_lease(&lv->val_dhcp6addr, cl);
            continue;
        }

        /* need to add the new leases */
        if (dhcp6_add_lease(&lv->val_dhcp6addr)) {
            g_message("%s: failed to add a new addr lease %s",
                      __func__, in6addr2str(&lv->val_dhcp6addr.addr, 0));
            continue;
        }

        iterator = g_slist_next(iterator);
    }

    /* update server id */
    if (client6_iaidaddr.state == REBIND) {
        if (duidcpy
            (&client6_iaidaddr.client6_info.serverid, &optinfo->serverID)) {
            g_error("%s: failed to copy server ID", __func__);
            return -1;
        }
    }

    if (!g_slist_length(client6_iaidaddr.lease_list)) {
        return 0;
    }

    /* set up renew T1, rebind T2 timer renew/rebind based on iaid */
    /* Should we process IA_TA, IA_NA differently */
    if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
        guint32 min_plifetime;

        min_plifetime = get_min_preferlifetime(&client6_iaidaddr);

        if (min_plifetime == DHCP6_DURATITION_INFINITE) {
            client6_iaidaddr.client6_info.iaidinfo.renewtime = min_plifetime;
        } else {
            client6_iaidaddr.client6_info.iaidinfo.renewtime =
                min_plifetime / 2;
        }
    }

    if (client6_iaidaddr.client6_info.iaidinfo.rebindtime == 0) {
        client6_iaidaddr.client6_info.iaidinfo.rebindtime =
            get_min_preferlifetime(&client6_iaidaddr) * 4 / 5;
    }

    g_message("renew time %d, rebind time %d",
              client6_iaidaddr.client6_info.iaidinfo.renewtime,
              client6_iaidaddr.client6_info.iaidinfo.rebindtime);

    if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
        return 0;
    }

    if (client6_iaidaddr.client6_info.iaidinfo.renewtime ==
        DHCP6_DURATITION_INFINITE) {
        client6_iaidaddr.client6_info.iaidinfo.rebindtime =
            DHCP6_DURATITION_INFINITE;

        if (client6_iaidaddr.timer) {
            dhcp6_remove_timer(client6_iaidaddr.timer);
        }

        return 0;
    }

    /* update the start date and timer */
    if (client6_iaidaddr.timer == NULL) {
        if ((client6_iaidaddr.timer =
             dhcp6_add_timer(dhcp6_iaidaddr_timo,
                             &client6_iaidaddr)) == NULL) {
            g_error("%s: failed to add a timer for iaid %u",
                    __func__, client6_iaidaddr.client6_info.iaidinfo.iaid);
            return -1;
        }
    }

    time(&client6_iaidaddr.start_date);
    client6_iaidaddr.state = ACTIVE;
    d = client6_iaidaddr.client6_info.iaidinfo.renewtime;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, client6_iaidaddr.timer);

    return 0;
}

dhcp6_timer_t *dhcp6_iaidaddr_timo(void *arg) {
    dhcp6_iaidaddr_t *sp = (dhcp6_iaidaddr_t *) arg;
    dhcp6_event_t *ev, *prev_ev = NULL;
    struct timeval timeo;
    gint dhcpstate, prev_state;
    gdouble d = 0;
    dhcp6_lease_t *cl = NULL;
    GSList *iterator = client6_iaidaddr.lease_list;

    g_debug("client6_iaidaddr timeout for %d, state=%d",
            client6_iaidaddr.client6_info.iaidinfo.iaid, sp->state);

    g_slist_free(request_list);
    request_list = NULL;

    /* ToDo: what kind of opiton Request value, client would like to pass? */
    switch (sp->state) {
        case ACTIVE:
            sp->state = RENEW;
            dhcpstate = DHCP6S_RENEW;
            d = sp->client6_info.iaidinfo.rebindtime -
                sp->client6_info.iaidinfo.renewtime;
            timeo.tv_sec = (long) d;
            timeo.tv_usec = 0;
            break;
        case RENEW:
            sp->state = REBIND;
            dhcpstate = DHCP6S_REBIND;
            prev_ev = _dhcp6_iaidaddr_find_event(sp, DHCP6S_RENEW);
            d = get_max_validlifetime(&client6_iaidaddr) -
                sp->client6_info.iaidinfo.rebindtime;
            timeo.tv_sec = (long) d;
            timeo.tv_usec = 0;

            if (sp->client6_info.serverid.duid_id != NULL) {
                duidfree(&sp->client6_info.serverid);
            }

            break;
        case REBIND:
            g_message("%s: failed to rebind a client6_iaidaddr %d"
                      " go to solicit and request new ipv6 addresses",
                      __func__, client6_iaidaddr.client6_info.iaidinfo.iaid);
            sp->state = INVALID;
            dhcpstate = DHCP6S_SOLICIT;
            prev_ev = _dhcp6_iaidaddr_find_event(sp, DHCP6S_REBIND);
            free_servers(sp->ifp);
            break;
        default:
            return NULL;
    }

    prev_state = prev_ev ? prev_ev->state : dhcpstate;

    /* Remove the event for the previous state */
    if (prev_ev) {
        g_debug("%s: remove previous event for state=%d",
                __func__, prev_ev->state);
        dhcp6_remove_event(prev_ev, NULL);
    }

    /* Create a new event for the new state */
    if ((ev = dhcp6_create_event(sp->ifp, dhcpstate)) == NULL) {
        g_error("%s: failed to create a new event", __func__);
        return NULL;            /* XXX: should try to recover reserve
                                 * memory?? */
    }

    run_script(sp->ifp, prev_state, ev->state, ev->uuid);

    switch (sp->state) {
        case RENEW:
            if (duidcpy(&ev->serverid, &sp->client6_info.serverid)) {
                g_error("%s: failed to copy server ID", __func__);
                g_free(ev);
                ev = NULL;
                return NULL;
            }
        case REBIND:
            /* BUG: d not set! */
            ev->max_retrans_dur = d;
            break;
        default:
            break;
    }

    if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
        g_error("%s: failed to create a new event timer", __func__);

        if (sp->state == RENEW) {
            duidfree(&ev->serverid);
        }

        g_free(ev);
        ev = NULL;
        return NULL;            /* XXX */
    }

    sp->ifp->event_list = g_slist_append(sp->ifp->event_list, ev);

    if (sp->state != INVALID && g_slist_length(iterator)) {
        /* create an address list for renew and rebind */
        while (iterator) {
            dhcp6_value_t *lv;
            cl = (dhcp6_lease_t *) iterator->data;

            /* IA_NA address */
            if ((lv = g_malloc0(sizeof(*lv))) == NULL) {
                g_error("%s: failed to allocate memory for an ipv6 addr",
                        __func__);

                if (sp->state == RENEW) {
                    duidfree(&ev->serverid);
                }

                g_free(ev->timer);
                g_free(ev);
                return NULL;
            }

            memcpy(&lv->val_dhcp6addr, &cl->lease_addr,
                   sizeof(lv->val_dhcp6addr));
            lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
            request_list = g_slist_append(request_list, lv);

            iterator = g_slist_next(iterator);
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

    return sp->timer;
}

dhcp6_timer_t *dhcp6_lease_timo(void *arg) {
    dhcp6_lease_t *sp = (dhcp6_lease_t *) arg;
    struct timeval timeo;
    gdouble d;

    g_debug("%s: lease timeout for %s, state=%d", __func__,
            in6addr2str(&sp->lease_addr.addr, 0), sp->state);

    /* cancel the current event for this lease */
    if (sp->state == INVALID) {
        g_message("%s: failed to remove an addr %s",
                  __func__, in6addr2str(&sp->lease_addr.addr, 0));
        dhcp6c_remove_lease(sp);
        return NULL;
    }

    switch (sp->state) {
        case ACTIVE:
            sp->state = EXPIRED;
            d = sp->lease_addr.validlifetime - sp->lease_addr.preferlifetime;
            timeo.tv_sec = (long) d;
            timeo.tv_usec = 0;
            dhcp6_set_timer(&timeo, sp->timer);
            break;
        case EXPIRED:
            sp->state = INVALID;
            dhcp6c_remove_lease(sp);
        default:
            return NULL;
    }

    return sp->timer;
}

gint client6_ifaddrconf(ifaddrconf_cmd_t cmd, dhcp6_addr_t *ifaddr) {
    struct in6_ifreq req;
    struct dhcp6_if *ifp = client6_iaidaddr.ifp;
    gulong ioctl_cmd;
    gchar *cmdstr;
    gint s, errno;

    switch (cmd) {
        case IFADDRCONF_ADD:
            cmdstr = "add";
            ioctl_cmd = SIOCSIFADDR;
            break;
        case IFADDRCONF_REMOVE:
            cmdstr = "remove";
            ioctl_cmd = SIOCDIFADDR;
            break;
        default:
            return -1;
    }

    if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        g_error("%s: can't open a temporary socket: %s",
                __func__, strerror(errno));
        return -1;
    }

    memset(&req, 0, sizeof(req));

#if defined(__linux__)
    req.ifr6_ifindex = if_nametoindex(ifp->ifname);
    memcpy(&req.ifr6_addr, &ifaddr->addr, sizeof(req.ifr6_addr));
    req.ifr6_prefixlen = ifaddr->plen;
#endif

    if (ioctl(s, ioctl_cmd, &req) && errno != EEXIST) {
        g_message("%s: failed to %s an address on %s: %s",
                  __func__, cmdstr, ifp->ifname, strerror(errno));
        close(s);
        return -1;
    }

    g_debug("%s: %s an address %s on %s", __func__, cmdstr,
            in6addr2str(&ifaddr->addr, 0), ifp->ifname);
    close(s);

    return 0;
}

gint get_iaid(const gchar *ifname, const iaid_table_t *iaidtab,
              gint num_device) {
    hardware_t hdaddr;
    iaid_table_t *temp = (iaid_table_t *) iaidtab;
    gint i;

    hdaddr.len = gethwid(hdaddr.data, 6, ifname, &hdaddr.type);

    for (i = 0; i < num_device; i++, temp++) {
        if (!memcmp(temp->hwaddr.data, hdaddr.data, temp->hwaddr.len)
            && hdaddr.len == temp->hwaddr.len
            && hdaddr.type == temp->hwaddr.type) {
            g_debug("%s: found interface %s iaid %u",
                    __func__, ifname, temp->iaid);
            return temp->iaid;
        } else {
            continue;
        }
    }

    return 0;
}

gint create_iaid(iaid_table_t *iaidtab, gint num_device) {
    iaid_table_t *temp = iaidtab;
    struct ifaddrs *ifa = NULL, *ifap = NULL;
    gint i;
    guint8 len;
    guint32 *p = NULL;
    guint32 tempkey;

    if (getifaddrs(&ifap) != 0) {
        g_error("%s: getifaddrs", __func__);
        return -1;
    }

    for (i = 0, ifa = ifap;
         (ifa != NULL) && (i < MAX_DEVICE); i++, ifa = ifa->ifa_next) {
        if (!g_strcmp0(ifa->ifa_name, "lo")) {
            continue;
        }

        temp->hwaddr.len = gethwid(temp->hwaddr.data,
                                   sizeof(temp->hwaddr.data),
                                   ifa->ifa_name, &temp->hwaddr.type);

        switch (temp->hwaddr.type) {
            case ARPHRD_ETHER:
            case ARPHRD_IEEE802:
                memcpy(&temp->iaid, (temp->hwaddr.data) + 2,
                       sizeof(temp->iaid));
                break;
#if defined(__linux__)
            case ARPHRD_PPP:
                temp->iaid = 0;
                len = sizeof(ifa->ifa_name);

                for (i = 0; i < len; i++) {
                    p = (guint32 *) ifa->ifa_name;
                    memcpy(&tempkey, p, sizeof(tempkey));
                    temp->iaid ^= tempkey;
                }

                memcpy(&tempkey, p, len % sizeof(tempkey));
                temp->iaid ^= tempkey;
                temp->iaid += if_nametoindex(ifa->ifa_name);
                break;
#endif
            default:
                g_message("doesn't support %s address family %d",
                          ifa->ifa_name, temp->hwaddr.type);
                continue;
        }

        g_debug("%s: create iaid %u for interface %s",
                __func__, temp->iaid, ifa->ifa_name);
        num_device++;
        temp++;
    }

    freeifaddrs(ifap);
    return num_device;
}
