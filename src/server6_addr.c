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
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#include <glib.h>

#include "queue.h"
#include "duid.h"
#include "dhcp6.h"
#include "confdata.h"
#include "lease.h"
#include "server6_conf.h"
#include "common.h"
#include "timer.h"
#include "str.h"

extern FILE *server6_lease_file;
extern GHashTable *host_addr_hash_table;
extern GHashTable *lease_hash_table;
extern GHashTable *server6_hash_table;

struct dhcp6_lease *dhcp6_find_lease(struct dhcp6_iaidaddr *,
                                     struct dhcp6_addr *);
struct link_decl *dhcp6_allocate_link(struct dhcp6_if *, struct rootgroup *,
                                      struct in6_addr *);
struct host_decl *dhcp6_allocate_host(struct dhcp6_if *, struct rootgroup *,
                                      struct dhcp6_optinfo *);
gint dhcp6_get_hostconf(struct ia_listval *, struct ia_listval *,
                        struct dhcp6_iaidaddr *, struct host_decl *);
gint dhcp6_add_lease(struct dhcp6_iaidaddr *, struct dhcp6_addr *);
gint dhcp6_update_lease(struct dhcp6_addr *, struct dhcp6_lease *);

/* BEGIN STATIC FUNCTIONS */

static void _get_random_bytes(guint8 seed[], gint num) {
    gint i;

    for (i = 0; i < num; i++) {
        seed[i] = random();
    }

    return;
}

static void _create_tempaddr(struct in6_addr *prefix, gint plen,
                             struct in6_addr *tempaddr) {
    gint i, num_bytes;
    guint8 seed[16];

    _get_random_bytes(seed, 16);
    /* address mask */
    memset(tempaddr, 0, sizeof(*tempaddr));
    num_bytes = plen / 8;

    for (i = 0; i < num_bytes; i++) {
        tempaddr->s6_addr[i] = prefix->s6_addr[i];
    }

    tempaddr->s6_addr[num_bytes] =
        (prefix->s6_addr[num_bytes] | (0xFF >> plen % 8))
        & (seed[num_bytes] | ((0xFF << 8) - plen % 8));

    for (i = num_bytes + 1; i < 16; i++) {
        tempaddr->s6_addr[i] = seed[i];
    }

    return;
}

static gint _addr_on_segment(struct v6addrseg *seg, struct dhcp6_addr *addr) {
    gint onseg = 0;
    struct v6addr *prefix;

    g_debug("%s: checking address %s on segment", __func__,
            in6addr2str(&addr->addr, 0));

    switch (addr->type) {
        case IATA:
            prefix = getprefix(&addr->addr, seg->prefix.plen);

            if (prefix && !memcmp(&seg->prefix, prefix, sizeof(seg->prefix))) {
                g_debug("%s: address is on link", __func__);
                onseg = 1;
            } else
                onseg = 0;

            free(prefix);
            prefix = NULL;
            break;
        case IANA:
            if (ipv6addrcmp(&addr->addr, &seg->min) >= 0 &&
                ipv6addrcmp(&seg->max, &addr->addr) >= 0) {
                g_debug("%s: address is on link", __func__);
                onseg = 1;
            } else {
                onseg = 0;
            }

            break;
        default:
            break;
    }

    return onseg;
}

static void _server6_get_addrpara(struct dhcp6_addr *v6addr,
                                  struct v6addrseg *seg) {
    v6addr->plen = seg->prefix.plen;

    if (seg->parainfo.prefer_life_time == 0 &&
        seg->parainfo.valid_life_time == 0) {
        seg->parainfo.valid_life_time = DEFAULT_VALID_LIFE_TIME;
        seg->parainfo.prefer_life_time = DEFAULT_PREFERRED_LIFE_TIME;
    } else if (seg->parainfo.prefer_life_time == 0) {
        seg->parainfo.prefer_life_time = seg->parainfo.valid_life_time / 2;
    } else if (seg->parainfo.valid_life_time == 0) {
        seg->parainfo.valid_life_time = 2 * seg->parainfo.prefer_life_time;
    }

    g_debug(" preferlifetime %u, validlifetime %u",
            seg->parainfo.prefer_life_time,
            seg->parainfo.valid_life_time);

    g_debug(" renewtime %u, rebindtime %u",
            seg->parainfo.renew_time, seg->parainfo.rebind_time);

    v6addr->preferlifetime = seg->parainfo.prefer_life_time;
    v6addr->validlifetime = seg->parainfo.valid_life_time;
    v6addr->status_code = DH6OPT_STCODE_SUCCESS;
    v6addr->status_msg = NULL;
    return;
}

static void _server6_get_newaddr(iatype_t type, struct dhcp6_addr *v6addr,
                                 struct v6addrseg *seg) {
    struct in6_addr current;
    gint round = 0;

    memcpy(&current, &seg->free, sizeof(current));

    do {
        v6addr->type = type;

        switch (type) {
            case IATA:
                /* assume the temp addr never being run out */
                _create_tempaddr(&seg->prefix.addr, seg->prefix.plen,
                                 &v6addr->addr);
                break;
            case IANA:
                memcpy(&v6addr->addr, &seg->free, sizeof(v6addr->addr));

                if (round && IN6_ARE_ADDR_EQUAL(&current, &v6addr->addr)) {
                    memset(&v6addr->addr, 0, sizeof(v6addr->addr));
                    break;
                }

                inc_ipv6addr(&seg->free);

                if (ipv6addrcmp(&seg->free, &seg->max) == 1) {
                    round = 1;
                    memcpy(&seg->free, &seg->min, sizeof(seg->free));
                }

                break;
            default:
                break;
        }
    } while ((g_hash_table_lookup(lease_hash_table,
                                  (gconstpointer) v6addr) != NULL) ||
             (g_hash_table_lookup(host_addr_hash_table,
                                  (gconstpointer) &v6addr->addr) != NULL) ||
             (is_anycast(&v6addr->addr, seg->prefix.plen)));

    if (IN6_IS_ADDR_UNSPECIFIED(&v6addr->addr)) {
        return;
    }

    g_debug("new address %s is got", in6addr2str(&v6addr->addr, 0));
    _server6_get_addrpara(v6addr, seg);
    return;
}

static void _server6_get_prefixpara(struct dhcp6_addr *v6addr,
                                    struct v6prefix *seg) {
    v6addr->plen = seg->prefix.plen;

    if (seg->parainfo.prefer_life_time == 0 &&
        seg->parainfo.valid_life_time == 0) {
        seg->parainfo.valid_life_time = DEFAULT_VALID_LIFE_TIME;
        seg->parainfo.prefer_life_time = DEFAULT_PREFERRED_LIFE_TIME;
    } else if (seg->parainfo.prefer_life_time == 0) {
        seg->parainfo.prefer_life_time = seg->parainfo.valid_life_time / 2;
    } else if (seg->parainfo.valid_life_time == 0) {
        seg->parainfo.valid_life_time = 2 * seg->parainfo.prefer_life_time;
    }

    g_debug(" preferlifetime %u, validlifetime %u",
            seg->parainfo.prefer_life_time, seg->parainfo.valid_life_time);

    g_debug(" renewtime %u, rebindtime %u",
            seg->parainfo.renew_time, seg->parainfo.rebind_time);

    v6addr->preferlifetime = seg->parainfo.prefer_life_time;
    v6addr->validlifetime = seg->parainfo.valid_life_time;
    v6addr->status_code = DH6OPT_STCODE_SUCCESS;
    v6addr->status_msg = NULL;
    return;
}

/* END STATIC FUNCTIONS */

struct host_decl *find_hostdecl(struct duid *duid, guint32 iaid,
                                struct host_decl *hostlist) {
    struct host_decl *host;

    for (host = hostlist; host; host = host->next) {
        if (!duidcmp(duid, &host->cid) && host->iaidinfo.iaid == iaid) {
            return host;
        }

        continue;
    }

    return NULL;
}

/* for request/solicit rapid commit */
gint dhcp6_add_iaidaddr(struct dhcp6_optinfo *optinfo, struct ia_listval *ia) {
    struct dhcp6_iaidaddr *iaidaddr;
    struct dhcp6_listval *lv, *lv_next = NULL;
    struct timeval timo;
    gdouble d;

    iaidaddr = (struct dhcp6_iaidaddr *) malloc(sizeof(*iaidaddr));

    if (iaidaddr == NULL) {
        g_error("%s: failed to allocate memory", __func__);
        return -1;
    }

    memset(iaidaddr, 0, sizeof(*iaidaddr));
    duidcpy(&iaidaddr->client6_info.clientid, &optinfo->clientID);
    iaidaddr->client6_info.iaidinfo.iaid = ia->iaidinfo.iaid;
    iaidaddr->client6_info.type = ia->type;
    TAILQ_INIT(&iaidaddr->lease_list);

    /* add new leases */
    for (lv = TAILQ_FIRST(&ia->addr_list); lv; lv = lv_next) {
        lv_next = TAILQ_NEXT(lv, link);

        if ((g_hash_table_lookup(lease_hash_table,
                 (gconstpointer) &lv->val_dhcp6addr)) != NULL) {
            g_message("%s: address for %s has been used",
                      __func__, in6addr2str(&lv->val_dhcp6addr.addr, 0));
            TAILQ_REMOVE(&ia->addr_list, lv, link);
            continue;
        }

        if (dhcp6_add_lease(iaidaddr, &lv->val_dhcp6addr) != 0) {
            TAILQ_REMOVE(&ia->addr_list, lv, link);
        }
    }

    /* it's meaningless to have an iaid without any leases */
    if (TAILQ_EMPTY(&iaidaddr->lease_list)) {
        g_message("%s: no leases are added for duid %s iaid %u", __func__,
                  duidstr(&iaidaddr->client6_info.clientid),
                  iaidaddr->client6_info.iaidinfo.iaid);
        return 0;
    }

    g_hash_table_insert(server6_hash_table, &iaidaddr->client6_info, iaidaddr);
    g_debug("%s: g_hash_table_add an iaidaddr %u for client duid %s",
            __func__, iaidaddr->client6_info.iaidinfo.iaid,
            duidstr(&iaidaddr->client6_info.clientid));

    /* set up timer for iaidaddr */
    iaidaddr->timer = dhcp6_add_timer(dhcp6_iaidaddr_timo, iaidaddr);
    if (iaidaddr->timer == NULL) {
        g_error("%s: failed to add a timer for iaid %u",
                __func__, iaidaddr->client6_info.iaidinfo.iaid);
        dhcp6_remove_iaidaddr(iaidaddr);
        return -1;
    }

    time(&iaidaddr->start_date);
    iaidaddr->state = ACTIVE;
    d = get_max_validlifetime(iaidaddr);
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, iaidaddr->timer);
    return 0;
}

gint dhcp6_remove_iaidaddr(struct dhcp6_iaidaddr *iaidaddr) {
    struct dhcp6_lease *lv, *lv_next;
    struct dhcp6_lease *lease;

    /* remove all the leases in this iaid */
    for (lv = TAILQ_FIRST(&iaidaddr->lease_list); lv; lv = lv_next) {
        lv_next = TAILQ_NEXT(lv, link);

        if ((lease = g_hash_table_lookup(lease_hash_table,
                         (gconstpointer) &lv->lease_addr)) != NULL) {
            if (dhcp6_remove_lease(lv)) {
                g_error("%s: failed to remove an iaid %u",
                        __func__, iaidaddr->client6_info.iaidinfo.iaid);
                return -1;
            }
        }
    }

    if (!g_hash_table_remove(server6_hash_table, &iaidaddr->client6_info)) {
        g_error("%s: failed to remove an iaid %u from hash",
                __func__, iaidaddr->client6_info.iaidinfo.iaid);
        return -1;
    }

    if (iaidaddr->timer) {
        dhcp6_remove_timer(iaidaddr->timer);
    }

    g_debug("%s: removed iaidaddr %u", __func__,
            iaidaddr->client6_info.iaidinfo.iaid);
    free(iaidaddr);
    return 0;
}

struct dhcp6_iaidaddr *dhcp6_find_iaidaddr(struct duid *clientID,
                                           guint32 iaid, iatype_t type) {
    struct dhcp6_iaidaddr *iaidaddr;
    struct client6_if client6_info;

    duidcpy(&client6_info.clientid, clientID);
    client6_info.iaidinfo.iaid = iaid;
    client6_info.type = type;

    iaidaddr = g_hash_table_lookup(server6_hash_table,
                                   (gconstpointer) &client6_info);
    if (iaidaddr == NULL) {
        g_debug("%s: iaid %u iaidaddr for client duid %s doesn't exists",
                __func__, client6_info.iaidinfo.iaid,
                duidstr(&client6_info.clientid));
    }

    duidfree(&client6_info.clientid);
    return iaidaddr;
}

gint dhcp6_remove_lease(struct dhcp6_lease *lease) {
    lease->state = INVALID;

    if (write_lease(lease, server6_lease_file) != 0) {
        g_error("%s: failed to write an invalid lease %s to lease file",
                __func__, in6addr2str(&lease->lease_addr.addr, 0));
        return -1;
    }

    if (!g_hash_table_remove(lease_hash_table, &lease->lease_addr)) {
        g_error("%s: failed to remove an address %s from hash", __func__,
                in6addr2str(&lease->lease_addr.addr, 0));
        return -1;
    }

    if (lease->timer) {
        dhcp6_remove_timer(lease->timer);
    }

    TAILQ_REMOVE(&lease->iaidaddr->lease_list, lease, link);
    g_debug("%s: removed lease %s", __func__,
            in6addr2str(&lease->lease_addr.addr, 0));
    free(lease);
    return 0;
}

/* for renew/rebind/release/decline */
gint dhcp6_update_iaidaddr(struct dhcp6_optinfo *optinfo, struct ia_listval *ia,
                           gint flag) {
    struct dhcp6_iaidaddr *iaidaddr;
    struct dhcp6_lease *lease, *lease_next = NULL;
    struct dhcp6_listval *lv, *lv_next = NULL;
    struct timeval timo;
    gdouble d;

    if ((iaidaddr = dhcp6_find_iaidaddr(&optinfo->clientID,
                                        ia->iaidinfo.iaid,
                                        ia->type)) == NULL) {
        return -1;
    }

    if (flag == ADDR_UPDATE) {
        /* add or update new lease */
        for (lv = TAILQ_FIRST(&ia->addr_list); lv; lv = lv_next) {
            lv_next = TAILQ_NEXT(lv, link);
            g_debug("%s: address is %s ", __func__,
                    in6addr2str(&lv->val_dhcp6addr.addr, 0));

            if ((lease = dhcp6_find_lease(iaidaddr, &lv->val_dhcp6addr))
                != NULL) {
                dhcp6_update_lease(&lv->val_dhcp6addr, lease);
            } else {
                dhcp6_add_lease(iaidaddr, &lv->val_dhcp6addr);
            }
        }

        /* remove leases that not on the reply list */
        for (lease = TAILQ_FIRST(&iaidaddr->lease_list); lease;
             lease = lease_next) {
            lease_next = TAILQ_NEXT(lease, link);

            if (!addr_on_addrlist(&ia->addr_list, &lease->lease_addr)) {
                g_debug("%s: lease %s is not on the link",
                        __func__, in6addr2str(&lease->lease_addr.addr,
                                                  0));
                dhcp6_remove_lease(lease);
            }
        }

        g_debug("%s: update iaidaddr for iaid %u", __func__,
                iaidaddr->client6_info.iaidinfo.iaid);
    } else {
        /* remove leases */
        for (lv = TAILQ_FIRST(&ia->addr_list); lv; lv = lv_next) {
            lv_next = TAILQ_NEXT(lv, link);
            lease = dhcp6_find_lease(iaidaddr, &lv->val_dhcp6addr);

            if (lease) {
                if (flag == ADDR_ABANDON) {
                    /* XXX: preallocate a abandoned duid for maintain
                     * abandoned list with preferlifetime xxx, validlifetime
                     * xxx */
                }

                dhcp6_remove_lease(lease);
            } else {
                g_message("%s: address is not on the iaid", __func__);
            }
        }
    }

    /* it's meaningless to have an iaid without any leases */
    if (TAILQ_EMPTY(&iaidaddr->lease_list)) {
        g_message("%s: no leases are added for duid %s iaid %u", __func__,
                  duidstr(&iaidaddr->client6_info.clientid),
                  iaidaddr->client6_info.iaidinfo.iaid);
        dhcp6_remove_iaidaddr(iaidaddr);
        return 0;
    }

    /* update the start date and timer */
    if (iaidaddr->timer == NULL) {
        if ((iaidaddr->timer =
             dhcp6_add_timer(dhcp6_iaidaddr_timo, iaidaddr)) == NULL) {
            g_error("%s: failed to add a timer for iaid %u",
                    __func__, iaidaddr->client6_info.iaidinfo.iaid);
            return -1;
        }
    }

    time(&iaidaddr->start_date);
    iaidaddr->state = ACTIVE;
    d = get_max_validlifetime(iaidaddr);
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, iaidaddr->timer);
    return 0;
}

gint dhcp6_validate_bindings(struct dhcp6_list *addrlist,
                             struct dhcp6_iaidaddr *iaidaddr, gint update) {
    struct dhcp6_listval *lv;

    /* XXX: confirm needs to update bindings ?? */
    for (lv = TAILQ_FIRST(addrlist); lv; lv = TAILQ_NEXT(lv, link)) {
        if (dhcp6_find_lease(iaidaddr, &lv->val_dhcp6addr) == NULL) {
            if (update) {
                /* returns with lifetimes of 0 [RFC3315, Section 18.2.3] */
                lv->val_dhcp6addr.validlifetime = 0;
                lv->val_dhcp6addr.preferlifetime = 0;
            }

            return -1;
        }
    }

    return 0;
}

gint dhcp6_add_lease(struct dhcp6_iaidaddr *iaidaddr, struct dhcp6_addr *addr) {
    struct dhcp6_lease *sp;
    struct timeval timo;
    gdouble d;

    if (addr->status_code != DH6OPT_STCODE_SUCCESS &&
        addr->status_code != DH6OPT_STCODE_UNDEFINE) {
        g_error("%s: not successful status code for %s is %s", __func__,
                in6addr2str(&addr->addr, 0),
                dhcp6_stcodestr(addr->status_code));
        return 0;
    }

    /* ignore meaningless address, this never happens */
    if (addr->validlifetime == 0 || addr->preferlifetime == 0) {
        g_message("%s: zero address life time for %s",
                  __func__, in6addr2str(&addr->addr, 0));
        return 0;
    }

    if (((sp = g_hash_table_lookup(lease_hash_table,
                                   (gconstpointer) addr))) != NULL) {
        g_message("%s: duplicated address: %s",
                  __func__, in6addr2str(&addr->addr, 0));
        return -1;
    }

    if ((sp = (struct dhcp6_lease *) malloc(sizeof(*sp))) == NULL) {
        g_error("%s: failed to allocate memory for an address", __func__);
        return -1;
    }

    memset(sp, 0, sizeof(*sp));
    memcpy(&sp->lease_addr, addr, sizeof(sp->lease_addr));
    sp->iaidaddr = iaidaddr;
    /* ToDo: preferlifetime EXPIRED; validlifetime DELETED; */
    /* if a finite lease perferlifetime is specified, set up a timer. */
    time(&sp->start_date);
    g_debug("%s: start date is %ld", __func__, sp->start_date);
    sp->state = ACTIVE;

    if (write_lease(sp, server6_lease_file) != 0) {
        g_error("%s: failed to write a new lease address %s to lease file",
                __func__, in6addr2str(&sp->lease_addr.addr, 0));
        free(sp->timer);
        free(sp);
        return -1;
    }

    g_debug("%s: write lease %s/%d to lease file", __func__,
            in6addr2str(&sp->lease_addr.addr, 0), sp->lease_addr.plen);
    g_hash_table_insert(lease_hash_table, &sp->lease_addr, sp);
    TAILQ_INSERT_TAIL(&iaidaddr->lease_list, sp, link);

    if (sp->lease_addr.validlifetime == DHCP6_DURATITION_INFINITE ||
        sp->lease_addr.preferlifetime == DHCP6_DURATITION_INFINITE) {
        g_message("%s: infinity address life time for %s",
                  __func__, in6addr2str(&addr->addr, 0));
        return 0;
    }

    if ((sp->timer = dhcp6_add_timer(dhcp6_lease_timo, sp)) == NULL) {
        g_error("%s: failed to create a new event timer", __func__);
        free(sp);
        return -1;
    }

    d = sp->lease_addr.preferlifetime;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, sp->timer);
    g_debug("%s: add lease for %s/%d iaid %u with preferlifetime %u"
            " with validlifetime %u", __func__,
            in6addr2str(&sp->lease_addr.addr, 0), sp->lease_addr.plen,
            sp->iaidaddr->client6_info.iaidinfo.iaid,
            sp->lease_addr.preferlifetime, sp->lease_addr.validlifetime);
    return 0;
}

/* assume we've found the updated lease already */
gint dhcp6_update_lease(struct dhcp6_addr *addr, struct dhcp6_lease *sp) {
    struct timeval timo;
    gdouble d;

    if (addr->status_code != DH6OPT_STCODE_SUCCESS &&
        addr->status_code != DH6OPT_STCODE_UNDEFINE) {
        g_error("%s: not successful status code for %s is %s", __func__,
                in6addr2str(&addr->addr, 0),
                dhcp6_stcodestr(addr->status_code));
        dhcp6_remove_lease(sp);
        return 0;
    }

    /* remove lease with perferlifetime or validlifetime 0 */
    if (addr->validlifetime == 0 || addr->preferlifetime == 0) {
        g_message("%s: zero address life time for %s",
                  __func__, in6addr2str(&addr->addr, 0));
        dhcp6_remove_lease(sp);
        return 0;
    }

    memcpy(&sp->lease_addr, addr, sizeof(sp->lease_addr));
    time(&sp->start_date);
    sp->state = ACTIVE;

    if (write_lease(sp, server6_lease_file) != 0) {
        g_error("%s: failed to write an updated lease %s to lease file",
                __func__, in6addr2str(&sp->lease_addr.addr, 0));
        return -1;
    }

    if (sp->lease_addr.validlifetime == DHCP6_DURATITION_INFINITE ||
        sp->lease_addr.preferlifetime == DHCP6_DURATITION_INFINITE) {
        g_message("%s: infinity address life time for %s",
                  __func__, in6addr2str(&addr->addr, 0));
        return 0;
    }

    if (sp->timer == NULL) {
        if ((sp->timer = dhcp6_add_timer(dhcp6_lease_timo, sp)) == NULL) {
            g_error("%s: failed to create a new event timer", __func__);
            return -1;
        }
    }

    d = sp->lease_addr.preferlifetime;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, sp->timer);
    return 0;
}

struct dhcp6_lease *dhcp6_find_lease(struct dhcp6_iaidaddr *iaidaddr,
                                     struct dhcp6_addr *ifaddr) {
    struct dhcp6_lease *sp;

    for (sp = TAILQ_FIRST(&iaidaddr->lease_list); sp;
         sp = TAILQ_NEXT(sp, link)) {
        /* check for prefix length sp->lease_addr.plen == ifaddr->plen && */
        g_debug("%s: request address is %s/%d ", __func__,
                in6addr2str(&ifaddr->addr, 0), ifaddr->plen);
        g_debug("%s: lease address is %s/%d ", __func__,
                in6addr2str(&sp->lease_addr.addr, 0), ifaddr->plen);

        if (IN6_ARE_ADDR_EQUAL(&sp->lease_addr.addr, &ifaddr->addr)) {
            if (ifaddr->type == IAPD) {
                if (sp->lease_addr.plen == ifaddr->plen) {
                    return sp;
                }
            } else if (ifaddr->type == IANA || ifaddr->type == IATA) {
                return sp;
            }
        }
    }

    return NULL;
}

struct dhcp6_timer *dhcp6_iaidaddr_timo(void *arg) {
    struct dhcp6_iaidaddr *sp = (struct dhcp6_iaidaddr *) arg;

    g_debug("server6_iaidaddr timeout for %u, state=%d",
            sp->client6_info.iaidinfo.iaid, sp->state);

    switch (sp->state) {
        case ACTIVE:
        case EXPIRED:
            sp->state = EXPIRED;
            dhcp6_remove_iaidaddr(sp);
        default:
            break;
    }

    return NULL;
}

struct dhcp6_timer *dhcp6_lease_timo(void *arg) {
    struct dhcp6_lease *sp = (struct dhcp6_lease *) arg;
    struct timeval timeo;
    gdouble d;

    g_debug("%s: lease timeout for %s, state=%d", __func__,
            in6addr2str(&sp->lease_addr.addr, 0), sp->state);

    switch (sp->state) {
        case ACTIVE:
            sp->state = EXPIRED;
            d = sp->lease_addr.validlifetime - sp->lease_addr.preferlifetime;
            timeo.tv_sec = (long) d;
            timeo.tv_usec = 0;
            dhcp6_set_timer(&timeo, sp->timer);
            break;
        case EXPIRED:
        case INVALID:
            sp->state = INVALID;
            dhcp6_remove_lease(sp);
            return NULL;
        default:
            return NULL;
    }

    return sp->timer;
}

gint dhcp6_get_hostconf(struct ia_listval *ria, struct ia_listval *ia,
                        struct dhcp6_iaidaddr *iaidaddr,
                        struct host_decl *host) {
    struct dhcp6_list *reply_list = &ia->addr_list;

    if (!(host->hostscope.allow_flags & DHCIFF_TEMP_ADDRS)) {
        ria->iaidinfo.renewtime = host->hostscope.renew_time;
        ria->iaidinfo.rebindtime = host->hostscope.rebind_time;
        ria->type = ia->type;

        switch (ia->type) {
            case IANA:
                dhcp6_copy_list(reply_list, &host->addrlist);
                break;
            case IATA:
                break;
            case IAPD:
                dhcp6_copy_list(reply_list, &host->prefixlist);
                break;
        }
    }

    return 0;
}

gint dhcp6_create_addrlist(struct ia_listval *ria, struct ia_listval *ia,
                           const struct dhcp6_iaidaddr *iaidaddr,
                           const struct link_decl *subnet,
                           guint16 *ia_status_code) {
    struct dhcp6_listval *v6addr;
    struct v6addrseg *seg;
    struct dhcp6_list *reply_list = &ria->addr_list;
    struct dhcp6_list *req_list = &ia->addr_list;
    gint numaddr;
    struct dhcp6_listval *lv, *lv_next = NULL;

    ria->iaidinfo.renewtime = subnet->linkscope.renew_time;
    ria->iaidinfo.rebindtime = subnet->linkscope.rebind_time;
    ria->type = ia->type;

    /* check the duplication */
    for (lv = TAILQ_FIRST(req_list); lv; lv = lv_next) {
        lv_next = TAILQ_NEXT(lv, link);
        if (addr_on_addrlist(reply_list, &lv->val_dhcp6addr)) {
            TAILQ_REMOVE(req_list, lv, link);
        }
    }

    dhcp6_copy_list(reply_list, req_list);

    for (lv = TAILQ_FIRST(reply_list); lv; lv = lv_next) {
        lv_next = TAILQ_NEXT(lv, link);
        lv->val_dhcp6addr.type = ia->type;
        lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
        lv->val_dhcp6addr.status_msg = NULL;
    }

    for (seg = subnet->seglist; seg; seg = seg->next) {
        numaddr = 0;

        for (lv = TAILQ_FIRST(reply_list); lv; lv = lv_next) {
            lv_next = TAILQ_NEXT(lv, link);
            /* skip checked segment */

            if (lv->val_dhcp6addr.status_code == DH6OPT_STCODE_SUCCESS) {
                continue;
            }

            if (IN6_IS_ADDR_RESERVED(&lv->val_dhcp6addr.addr) ||
                is_anycast(&lv->val_dhcp6addr.addr, seg->prefix.plen)) {
                numaddr += 1;
                lv->val_dhcp6addr.status_code = DH6OPT_STCODE_NOTONLINK;
                g_debug("%s: %s address not on link",
                        __func__, in6addr2str(&lv->val_dhcp6addr.addr,
                                                  0));
                *ia_status_code = DH6OPT_STCODE_NOTONLINK;
                continue;
            }

            lv->val_dhcp6addr.type = ia->type;

            if (_addr_on_segment(seg, &lv->val_dhcp6addr)) {
                if (numaddr == 0) {
                    lv->val_dhcp6addr.type = ia->type;
                    _server6_get_addrpara(&lv->val_dhcp6addr, seg);
                    numaddr += 1;
                } else {
                    /* check the addr count per seg, we only allow one
                     * address per segment, set the status code */
                    lv->val_dhcp6addr.status_code = DH6OPT_STCODE_NOADDRAVAIL;
                }
            } else {
                numaddr += 1;
                lv->val_dhcp6addr.status_code = DH6OPT_STCODE_NOTONLINK;
                g_debug("%s: %s address not on link",
                        __func__, in6addr2str(&lv->val_dhcp6addr.addr,
                                                  0));
                *ia_status_code = DH6OPT_STCODE_NOTONLINK;
            }
        }

        if (iaidaddr != NULL) {
            struct dhcp6_lease *cl;

            for (cl = TAILQ_FIRST(&iaidaddr->lease_list); cl;
                 cl = TAILQ_NEXT(cl, link)) {
                if (_addr_on_segment(seg, &cl->lease_addr)) {
                    if (addr_on_addrlist(reply_list, &cl->lease_addr)) {
                        continue;
                    } else if (numaddr == 0) {
                        v6addr =
                            (struct dhcp6_listval *) malloc(sizeof(*v6addr));
                        if (v6addr == NULL) {
                            g_error("%s: fail to allocate memory %s",
                                    __func__, strerror(errno));
                            return -1;
                        }

                        memset(v6addr, 0, sizeof(*v6addr));
                        memcpy(&v6addr->val_dhcp6addr, &cl->lease_addr,
                               sizeof(v6addr->val_dhcp6addr));
                        v6addr->val_dhcp6addr.type = ia->type;
                        _server6_get_addrpara(&v6addr->val_dhcp6addr, seg);
                        numaddr += 1;
                        TAILQ_INSERT_TAIL(reply_list, v6addr, link);
                        continue;
                    }
                }

            }
        }

        if (numaddr == 0) {
            v6addr = (struct dhcp6_listval *) malloc(sizeof(*v6addr));
            if (v6addr == NULL) {
                g_error("%s: fail to allocate memory %s",
                        __func__, strerror(errno));
                return -1;
            }

            memset(v6addr, 0, sizeof(*v6addr));
            v6addr->val_dhcp6addr.type = ia->type;
            _server6_get_newaddr(ia->type, &v6addr->val_dhcp6addr, seg);

            if (IN6_IS_ADDR_UNSPECIFIED(&v6addr->val_dhcp6addr.addr)) {
                free(v6addr);
                continue;
            }

            TAILQ_INSERT_TAIL(reply_list, v6addr, link);
        }
    }

    return 0;
}

gint dhcp6_create_prefixlist(struct ia_listval *ria, struct ia_listval *ia,
                             const struct dhcp6_iaidaddr *iaidaddr,
                             const struct link_decl *subnet,
                             guint16 *ia_status_code) {
    struct dhcp6_listval *v6addr;
    struct v6prefix *prefix6;
    struct dhcp6_list *reply_list = &ria->addr_list;
    const struct dhcp6_list *req_list = &ia->addr_list;
    struct dhcp6_listval *lv, *lv_next = NULL;

    /* XXX: ToDo check hostdecl first */
    ria->iaidinfo.renewtime = subnet->linkscope.renew_time;
    ria->iaidinfo.rebindtime = subnet->linkscope.rebind_time;
    ria->type = ia->type;

    for (prefix6 = subnet->prefixlist; prefix6; prefix6 = prefix6->next) {
        v6addr = (struct dhcp6_listval *) malloc(sizeof(*v6addr));

        if (v6addr == NULL) {
            g_error("%s: fail to allocate memory", __func__);
            return -1;
        }

        memset(v6addr, 0, sizeof(*v6addr));
        /* XXX: ToDo: get new paras */
        memcpy(&v6addr->val_dhcp6addr.addr, &prefix6->prefix.addr,
               sizeof(v6addr->val_dhcp6addr.addr));
        v6addr->val_dhcp6addr.plen = prefix6->prefix.plen;
        v6addr->val_dhcp6addr.type = IAPD;
        _server6_get_prefixpara(&v6addr->val_dhcp6addr, prefix6);
        g_debug(" get prefix %s/%d, preferlifetime %u, validlifetime %u",
                in6addr2str(&v6addr->val_dhcp6addr.addr, 0),
                v6addr->val_dhcp6addr.plen,
                v6addr->val_dhcp6addr.preferlifetime,
                v6addr->val_dhcp6addr.validlifetime);
        TAILQ_INSERT_TAIL(reply_list, v6addr, link);
    }

    for (prefix6 = subnet->prefixlist; prefix6; prefix6 = prefix6->next) {
        for (lv = TAILQ_FIRST(req_list); lv; lv = lv_next) {
            lv_next = TAILQ_NEXT(lv, link);

            if (IN6_IS_ADDR_RESERVED(&lv->val_dhcp6addr.addr) ||
                is_anycast(&lv->val_dhcp6addr.addr, prefix6->prefix.plen) ||
                !addr_on_addrlist(reply_list, &lv->val_dhcp6addr)) {
                lv->val_dhcp6addr.status_code = DH6OPT_STCODE_NOTONLINK;
                *ia_status_code = DH6OPT_STCODE_NOTONLINK;
                g_debug(" %s prefix not on link",
                        in6addr2str(&lv->val_dhcp6addr.addr, 0));
                lv->val_dhcp6addr.type = IAPD;
                TAILQ_INSERT_TAIL(reply_list, lv, link);
            }
        }
    }

    return 0;
}

struct host_decl *dhcp6_allocate_host(struct dhcp6_if *ifp,
                                      struct rootgroup *rootgroup,
                                      struct dhcp6_optinfo *optinfo) {
    struct host_decl *host = NULL;
    struct interface *ifnetwork;
    struct duid *duid = &optinfo->clientID;
    struct ia_listval *lv;

    for (ifnetwork = rootgroup->iflist; ifnetwork;
         ifnetwork = ifnetwork->next) {
        if (strcmp(ifnetwork->name, ifp->ifname) != 0) {
            continue;
        } else {
            if (TAILQ_EMPTY(&optinfo->ia_list)) {
                host = find_hostdecl(duid, 0, ifnetwork->hostlist);
                return host;
            } else {
                for (lv = TAILQ_FIRST(&optinfo->ia_list);
                     lv; lv = TAILQ_NEXT(lv, link)) {
                    host = find_hostdecl(duid, lv->iaidinfo.iaid,
                                         ifnetwork->hostlist);
                    if (host != NULL) {
                        return host;
                    }
                }
            }
        }
    }

    return NULL;
}

struct link_decl *dhcp6_allocate_link(struct dhcp6_if *ifp,
                                      struct rootgroup *rootgroup,
                                      struct in6_addr *relay) {
    struct link_decl *link;
    struct interface *ifnetwork;

    ifnetwork = rootgroup->iflist;

    for (ifnetwork = rootgroup->iflist; ifnetwork;
         ifnetwork = ifnetwork->next) {
        if (strcmp(ifnetwork->name, ifp->ifname) != 0) {
            continue;
        } else {
            for (link = ifnetwork->linklist; link; link = link->next) {
                /* if relay is NULL, assume client and server are on the same 
                 * link (which cannot have a relay configuration option) */
                struct v6addrlist *temp;

                if (relay == NULL) {
                    if (link->relaylist != NULL) {
                        continue;
                    } else {
                        return link;
                    }
                } else {
                    for (temp = link->relaylist; temp; temp = temp->next) {
                        /* only compare the prefix configured to the relay
                         * link address */
                        if (!prefixcmp(relay, &temp->v6addr.addr,
                                       temp->v6addr.plen)) {
                            return link;
                        } else {
                            continue;
                        }
                    }
                }
            }
        }
    }

    return NULL;
}
