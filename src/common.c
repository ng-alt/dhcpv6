/* ported from KAME: common.c,v 1.65 2002/12/06 01:41:29 suz Exp */

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <unistd.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#include <glib.h>

#include "common.h"

extern gchar *script;

gint debug_thresh;
dhcp6_if_t *dhcp6_if;
dns_info_t dnsinfo;

static host_conf_t *_host_conflist;

/* BEGIN STATIC FUNCTIONS */

static gint _in6_matchflags(struct sockaddr *addr, size_t addrlen,
                            gchar *ifnam, gint flags) {
    gint s;
    struct ifreq ifr;

    if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        warn("in6_matchflags: socket(DGRAM6)");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifnam, sizeof(ifr.ifr_name));
    ifr.ifr_addr = *(struct sockaddr *) addr;

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        warn("in6_matchflags: ioctl(SIOCGIFFLAGS, %s)",
             addr2str(addr, addrlen));
        close(s);
        return -1;
    }

    close(s);
    return (ifr.ifr_ifru.ifru_flags & flags);
}

static gint _ia_add_address(ia_t *ia, dhcp6_addr_t *addr6) {
    /* set up address type */
    addr6->type = ia->type;

    if (dhcp6_find_listval(ia->addr_list, addr6, DHCP6_LISTVAL_DHCP6ADDR)) {
        g_message("duplicated address (%s/%d)",
                  in6addr2str(&addr6->addr, 0), addr6->plen);
        /* XXX: decline message */
        return 0;
    }

    if (dhcp6_add_listval(ia->addr_list, addr6,
                          DHCP6_LISTVAL_DHCP6ADDR) == NULL) {
        g_error("%s: failed to copy an address", __func__);
        return -1;
    }

    return 0;
}

static gint _get_assigned_ipv6addrs(guchar *p, guchar *ep, ia_t *ia) {
    guchar *np, *cp;
    dhcp6opt_t opth;
    dhcp6_addr_info_t ai;
    dhcp6_prefix_info_t pi;
    dhcp6_addr_t addr6;
    gint optlen, opt;
    guint16 val16;
    gint num;

    for (; p + sizeof(dhcp6opt_t) <= ep; p = np) {
        memcpy(&opth, p, sizeof(opth));
        optlen = ntohs(opth.dh6opt_len);
        opt = ntohs(opth.dh6opt_type);
        cp = p + sizeof(opth);
        np = cp + optlen;
        g_debug("  IA address option: %s, len %d", dhcp6optstr(opt), optlen);

        if (np > ep) {
            g_message("%s: malformed DHCP options", __func__);
            return -1;
        }

        switch (opt) {
            case DH6OPT_STATUS_CODE:
                if (optlen < sizeof(val16)) {
                    goto malformed;
                }

                memcpy(&val16, cp, sizeof(val16));
                num = ntohs(val16);
                print_status_code("IA", num, p, optlen);
                ia->status_code = num;
                break;
            case DH6OPT_IADDR:
                if (optlen < sizeof(ai) - sizeof(guint32)) {
                    goto malformed;
                }

                memcpy(&ai, p, sizeof(ai));
                /* copy the information into internal format */
                memset(&addr6, 0, sizeof(addr6));
                memcpy(&addr6.addr, (struct in6_addr *) cp,
                       sizeof(struct in6_addr));
                addr6.preferlifetime = ntohl(ai.preferlifetime);
                addr6.validlifetime = ntohl(ai.validlifetime);
                g_debug("  get IAADR address information: "
                        "%s preferlifetime %d validlifetime %d",
                        in6addr2str(&addr6.addr, 0),
                        addr6.preferlifetime, addr6.validlifetime);

                /* It shouldn't happen, since Server will do the check before 
                 * sending the data to clients */
                if (addr6.preferlifetime > addr6.validlifetime) {
                    g_message("preferred life time (%d) is greater than "
                              "valid life time (%d)", addr6.preferlifetime,
                              addr6.validlifetime);
                    goto malformed;
                }

                if (optlen == sizeof(ai) - sizeof(guint32)) {
                    addr6.status_code = DH6OPT_STCODE_UNDEFINE;
                } else {
                    /* address status code might be added after IADDA option */
                    memcpy(&opth, p + sizeof(ai), sizeof(opth));
                    optlen = ntohs(opth.dh6opt_len);
                    opt = ntohs(opth.dh6opt_type);

                    switch (opt) {
                        case DH6OPT_STATUS_CODE:
                            if (optlen < sizeof(val16)) {
                                goto malformed;
                            }

                            memcpy(&val16, p + sizeof(ai) + sizeof(opth),
                                   sizeof(val16));
                            num = ntohs(val16);
                            print_status_code("address", num, p, optlen);
                            addr6.status_code = num;
                            break;
                        default:
                            goto malformed;
                    }
                }

                if (_ia_add_address(ia, &addr6)) {
                    goto fail;
                }

                break;
            case DH6OPT_IAPREFIX:
                if (optlen < sizeof(pi) - sizeof(guint32)) {
                    goto malformed;
                }

                memcpy(&pi, p, sizeof(pi));
                /* copy the information into internal format */
                memset(&addr6, 0, sizeof(addr6));
                addr6.preferlifetime = ntohl(pi.preferlifetime);
                addr6.validlifetime = ntohl(pi.validlifetime);
                addr6.plen = pi.plen;
                memcpy(&addr6.addr, &pi.prefix, sizeof(struct in6_addr));
                g_debug("  get IAPREFIX prefix information: "
                        "%s/%d preferlifetime %d validlifetime %d",
                        in6addr2str(&addr6.addr, 0), addr6.plen,
                        addr6.preferlifetime, addr6.validlifetime);

                /* It shouldn't happen, since Server will do the check before 
                 * sending the data to clients */
                if (addr6.preferlifetime > addr6.validlifetime) {
                    g_message("preferred life time (%d) is greater than "
                              "valid life time (%d)", addr6.preferlifetime,
                              addr6.validlifetime);
                    goto malformed;
                }

                if (optlen == sizeof(pi) - sizeof(guint32)) {
                    addr6.status_code = DH6OPT_STCODE_UNDEFINE;
                } else {
                    /* address status code might be added after IADDA option */
                    memcpy(&opth, p + sizeof(pi), sizeof(opth));
                    optlen = ntohs(opth.dh6opt_len);
                    opt = ntohs(opth.dh6opt_type);

                    switch (opt) {
                        case DH6OPT_STATUS_CODE:
                            if (optlen < sizeof(val16)) {
                                goto malformed;
                            }

                            memcpy(&val16, p + sizeof(pi) + sizeof(opth),
                                   sizeof(val16));
                            num = ntohs(val16);
                            print_status_code("prefix", num, p, optlen);
                            addr6.status_code = num;
                            break;
                        default:
                            goto malformed;
                    }
                }

                if (_ia_add_address(ia, &addr6)) {
                    goto fail;
                }

                break;
            default:
                goto malformed;
        }
    }

    return 0;

malformed:
    g_message("  malformed IA option: type %d, len %d", opt, optlen);

fail:
    g_slist_free(ia->addr_list);
    ia->addr_list = NULL;

    return -1;
}

static gint _dhcp6_set_ia_options(guchar **tmpbuf, gint *optlen, ia_t *ia) {
    gint buflen = 0;
    guchar *tp = NULL;
    guint32 iaid = 0;
    dhcp6_iaid_info_t opt_iana;
    dhcp6_iaid_info_t opt_iapd;
    dhcp6_prefix_info_t pi;
    dhcp6_addr_info_t ai;
    dhcp6_status_info_t status;
    dhcp6_value_t *dp = NULL;
    gint iaddr_len = 0;
    gint num = 0;

    memset(&opt_iana, 0, sizeof(opt_iana));
    memset(&opt_iapd, 0, sizeof(opt_iapd));
    memset(&pi, 0, sizeof(pi));
    memset(&ai, 0, sizeof(ai));
    memset(&status, 0, sizeof(status));

    switch (ia->type) {
        case IATA:
        case IANA:
            if (ia->iaidinfo.iaid == 0) {
                break;
            }

            if (ia->type == IATA) {
                *optlen = sizeof(iaid);
                g_debug("%s: set IA_TA iaid information: %d", __func__,
                        ia->iaidinfo.iaid);
                iaid = htonl(ia->iaidinfo.iaid);
            } else {
                *optlen = sizeof(opt_iana);
                g_debug("%s: set IA_NA iaidinfo: "
                        "iaid %u renewtime %u rebindtime %u",
                        __func__, ia->iaidinfo.iaid,
                        ia->iaidinfo.renewtime,
                        ia->iaidinfo.rebindtime);
                opt_iana.iaid = htonl(ia->iaidinfo.iaid);
                opt_iana.renewtime = htonl(ia->iaidinfo.renewtime);
                opt_iana.rebindtime = htonl(ia->iaidinfo.rebindtime);
            }

            buflen = sizeof(opt_iana) + g_slist_length(ia->addr_list) *
                (sizeof(ai) + sizeof(status)) + sizeof(status);

            if ((*tmpbuf = g_malloc0(buflen)) == NULL) {
                g_error("%s: memory allocation failed for options", __func__);
                return -1;
            }

            if (ia->type == IATA) {
                memcpy(*tmpbuf, &iaid, sizeof(iaid));
            } else {
                memcpy(*tmpbuf, &opt_iana, sizeof(opt_iana));
            }

            tp = *tmpbuf + *optlen;

            if (g_slist_length(ia->addr_list)) {
                GSList *iterator = ia->addr_list;

                while (iterator) {
                    dp = (dhcp6_value_t *) iterator->data;
                    iaddr_len = sizeof(ai) - sizeof(guint32);

                    if (dp->val_dhcp6addr.status_code !=
                        DH6OPT_STCODE_UNDEFINE) {
                        iaddr_len += sizeof(status);
                    }

                    memset(&ai, 0, sizeof(ai));
                    ai.dh6_ai_type = htons(DH6OPT_IADDR);
                    ai.dh6_ai_len = htons(iaddr_len);
                    ai.preferlifetime =
                        htonl(dp->val_dhcp6addr.preferlifetime);
                    ai.validlifetime = htonl(dp->val_dhcp6addr.validlifetime);
                    memcpy(&ai.addr, &dp->val_dhcp6addr.addr,
                           sizeof(ai.addr));
                    memcpy(tp, &ai, sizeof(ai));
                    *optlen += sizeof(ai);
                    tp += sizeof(ai);
                    g_debug("set IADDR address option len %d: "
                            "%s preferlifetime %d validlifetime %d",
                            iaddr_len, in6addr2str(&ai.addr, 0),
                            ntohl(ai.preferlifetime),
                            ntohl(ai.validlifetime));

                    /* set up address status code if any */
                    if (dp->val_dhcp6addr.status_code !=
                        DH6OPT_STCODE_UNDEFINE) {
                        status.dh6_status_type = htons(DH6OPT_STATUS_CODE);
                        status.dh6_status_len =
                            htons(sizeof(status.dh6_status_code));
                        status.dh6_status_code =
                            htons(dp->val_dhcp6addr.status_code);
                        memcpy(tp, &status, sizeof(status));
                        print_status_code("address",
                                          dp->val_dhcp6addr.status_code,
                                          NULL, 0);
                        *optlen += sizeof(status);
                        tp += sizeof(status);
                        g_debug("set IADDR status len %d optlen: %d",
                                (gint) sizeof(status), *optlen);
                        /* XXX: copy status message if any */
                    }

                    iterator = g_slist_next(iterator);
                }

                num = ia->status_code;
            } else if (dhcp6_mode == DHCP6_MODE_SERVER) {
                /* set up IA status code in error case */
                num = (ia->status_code != DH6OPT_STCODE_UNDEFINE &&
                       ia->status_code != DH6OPT_STCODE_SUCCESS)
                    ? ia->status_code : DH6OPT_STCODE_NOADDRAVAIL;
            }

            if (num != DH6OPT_STCODE_UNDEFINE) {
                status.dh6_status_type = htons(DH6OPT_STATUS_CODE);
                status.dh6_status_len = htons(sizeof(status.dh6_status_code));
                status.dh6_status_code = htons(num);
                memcpy(tp, &status, sizeof(status));
                print_status_code("IA", num, NULL, 0);
                *optlen += sizeof(status);
                tp += sizeof(status);
                g_debug("set IA status len %d optlen: %d",
                        (gint) sizeof(status), *optlen);
                /* XXX: copy status message if any */
            }

            break;
        case IAPD:
            if (ia->iaidinfo.iaid == 0) {
                break;
            }

            *optlen = sizeof(opt_iapd);
            g_debug("%s: set IA_PD iaidinfo: "
                    "iaid %u renewtime %u rebindtime %u",
                    __func__, ia->iaidinfo.iaid, ia->iaidinfo.renewtime,
                    ia->iaidinfo.rebindtime);
            opt_iapd.iaid = htonl(ia->iaidinfo.iaid);
            opt_iapd.renewtime = htonl(ia->iaidinfo.renewtime);
            opt_iapd.rebindtime = htonl(ia->iaidinfo.rebindtime);
            buflen = sizeof(opt_iapd) + g_slist_length(ia->addr_list) *
                (sizeof(pi) + sizeof(status)) + sizeof(status);

            if ((*tmpbuf = g_malloc0(buflen)) == NULL) {
                g_error("%s: memory allocation failed for options", __func__);
                return -1;
            }

            memcpy(*tmpbuf, &opt_iapd, sizeof(opt_iapd));
            tp = *tmpbuf + *optlen;

            if (g_slist_length(ia->addr_list)) {
                GSList *iterator = ia->addr_list;

                while (iterator) {
                    dp = (dhcp6_value_t *) iterator->data;
                    iaddr_len = sizeof(pi) - sizeof(guint32);

                    if (dp->val_dhcp6addr.status_code !=
                        DH6OPT_STCODE_UNDEFINE) {
                        iaddr_len += sizeof(status);
                    }

                    memset(&pi, 0, sizeof(pi));
                    pi.dh6_pi_type = htons(DH6OPT_IAPREFIX);
                    pi.dh6_pi_len = htons(iaddr_len);
                    pi.preferlifetime =
                        htonl(dp->val_dhcp6addr.preferlifetime);
                    pi.validlifetime = htonl(dp->val_dhcp6addr.validlifetime);
                    pi.plen = dp->val_dhcp6addr.plen;
                    memcpy(&pi.prefix, &dp->val_dhcp6addr.addr,
                           sizeof(pi.prefix));
                    memcpy(tp, &pi, sizeof(pi));
                    *optlen += sizeof(pi);
                    tp += sizeof(pi);
                    g_debug("set IAPREFIX option len %d: "
                            "%s/%d preferlifetime %d validlifetime %d",
                            iaddr_len, in6addr2str(&pi.prefix, 0),
                            pi.plen, ntohl(pi.preferlifetime),
                            ntohl(pi.validlifetime));

                    /* set up address status code if any */
                    if (dp->val_dhcp6addr.status_code !=
                        DH6OPT_STCODE_UNDEFINE) {
                        status.dh6_status_type = htons(DH6OPT_STATUS_CODE);
                        status.dh6_status_len =
                            htons(sizeof(status.dh6_status_code));
                        status.dh6_status_code =
                            htons(dp->val_dhcp6addr.status_code);
                        memcpy(tp, &status, sizeof(status));
                        print_status_code("prefix",
                                          dp->val_dhcp6addr.status_code,
                                          NULL, 0);
                        *optlen += sizeof(status);
                        tp += sizeof(status);
                        g_debug("set IAPREFIX status len %d optlen: %d",
                                (gint) sizeof(status), *optlen);
                        /* XXX: copy status message if any */
                    }

                    iterator = g_slist_next(iterator);
                }

                num = ia->status_code;
            } else if (dhcp6_mode == DHCP6_MODE_SERVER) {
                /* set up IA status code in error case */
                num = (ia->status_code != DH6OPT_STCODE_UNDEFINE &&
                       ia->status_code != DH6OPT_STCODE_SUCCESS)
                    ? ia->status_code : DH6OPT_STCODE_NOPREFIXAVAIL;
            }

            if (num != DH6OPT_STCODE_UNDEFINE) {
                status.dh6_status_type = htons(DH6OPT_STATUS_CODE);
                status.dh6_status_len = htons(sizeof(status.dh6_status_code));
                status.dh6_status_code = htons(num);
                memcpy(tp, &status, sizeof(status));
                print_status_code("IA", num, NULL, 0);
                *optlen += sizeof(status);
                tp += sizeof(status);
                g_debug("set IA status len %d optlen: %d",
                        (gint) sizeof(status), *optlen);
                /* XXX: copy status message if any */
            }

            break;
        default:
            break;
    }

    return 0;
}

/* END STATIC FUNCTIONS */

dhcp6_if_t *find_ifconfbyname(const gchar *ifname) {
    dhcp6_if_t *ifp;

    for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
        if (g_strcmp0(ifp->ifname, ifname) == 0) {
            return ifp;
        }
    }

    return NULL;
}

dhcp6_if_t *find_ifconfbyid(guint id) {
    dhcp6_if_t *ifp;

    for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
        if (ifp->ifid == id) {
            return ifp;
        }
    }

    return NULL;
}

host_conf_t *find_hostconf(const duid_t *duid) {
    host_conf_t *host;

    for (host = _host_conflist; host; host = host->next) {
        if (host->duid.duid_len == duid->duid_len &&
            memcmp(host->duid.duid_id, duid->duid_id,
                   host->duid.duid_len) == 0) {
            return host;
        }
    }

    return NULL;
}

void ifinit(const gchar *ifname) {
    dhcp6_if_t *ifp;

    if ((ifp = find_ifconfbyname(ifname)) != NULL) {
        g_message("%s: duplicated interface: %s", __func__, ifname);
        return;
    }

    if ((ifp = g_malloc0(sizeof(*ifp))) == NULL) {
        g_error("%s: memory allocation failure", __func__);
        goto die;
    }

    ifp->event_list = NULL;

    if ((ifp->ifname = strdup((gchar *) ifname)) == NULL) {
        g_error("%s: failed to copy ifname", __func__);
        goto die;
    }

    if ((ifp->ifid = if_nametoindex(ifname)) == 0) {
        g_error("%s: invalid interface(%s): %s", __func__,
                ifname, strerror(errno));
        goto die;
    }
#ifdef HAVE_SCOPELIB
    if (inet_zoneid(AF_INET6, 2, ifname, &ifp->linkid)) {
        g_error("%s: failed to get link ID for %s", __func__, ifname);
        goto die;
    }
#else
    ifp->linkid = ifp->ifid;    /* XXX */
#endif

    if (get_linklocal(ifname, &ifp->linklocal) < 0) {
        goto die;
    }

    ifp->next = dhcp6_if;
    dhcp6_if = ifp;
    return;

die:
    exit(1);
}

gint dhcp6_copy_list(GSList *dst, GSList *src) {
    dhcp6_value_t *ent = NULL, *dent = NULL;
    GSList *iterator = src;

    if (g_slist_length(dst)) {
        goto fail;
    }

    while (iterator) {
        ent = (dhcp6_value_t *) iterator->data;

        if ((dent = g_malloc0(sizeof(*dent))) == NULL) {
            goto fail;
        }

        memcpy(&dent->uv, &ent->uv, sizeof(ent->uv));
        dst = g_slist_append(dst, dent);

        iterator = g_slist_next(iterator);
    }

    return 0;

fail:
    g_slist_free(dst);
    dst = NULL;

    return -1;
}

dhcp6_value_t *dhcp6_find_listval(GSList *head, void *val,
                                  dhcp6_listval_type_t type) {
    dhcp6_value_t *lv = NULL;
    GSList *iterator = head;

    if (!g_slist_length(iterator)) {
        return NULL;
    }

    while (iterator) {
        lv = (dhcp6_value_t *) iterator->data;

        switch (type) {
            case DHCP6_LISTVAL_NUM:
                if (lv->val_num == *(gint *) val) {
                    return lv;
                }

                break;
            case DHCP6_LISTVAL_ADDR6:
                if (IN6_ARE_ADDR_EQUAL(&lv->val_addr6,
                                       (struct in6_addr *) val)) {
                    return lv;
                }

                break;
            case DHCP6_LISTVAL_DHCP6ADDR:
                if (IN6_ARE_ADDR_EQUAL(&lv->val_dhcp6addr.addr,
                                       &((dhcp6_addr_t *) val)->addr) &&
                    (lv->val_dhcp6addr.plen ==
                     ((dhcp6_addr_t *) val)->plen)) {
                    return lv;
                }

                break;
            case DHCP6_LISTVAL_DHCP6LEASE:
                /* FIXME */
                break;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

dhcp6_value_t *dhcp6_add_listval(GSList *head, void *val,
                                 dhcp6_listval_type_t type) {
    dhcp6_value_t *lv;

    if ((lv = g_malloc0(sizeof(*lv))) == NULL) {
        g_error("%s: failed to allocate memory for list entry", __func__);
        return NULL;
    }

    switch (type) {
        case DHCP6_LISTVAL_NUM:
            lv->val_num = *(gint *) val;
            break;
        case DHCP6_LISTVAL_ADDR6:
            lv->val_addr6 = *(struct in6_addr *) val;
            break;
        case DHCP6_LISTVAL_DHCP6ADDR:
            lv->val_dhcp6addr = *(dhcp6_addr_t *) val;
            break;
        default:
            g_error("%s: unexpected list value type (%d)", __func__, type);
            return NULL;
    }

    head = g_slist_append(head, lv);
    return lv;
}

ia_t *ia_create_listval(void) {
    ia_t *ia;

    if ((ia = g_malloc0(sizeof(*ia))) == NULL) {
        g_error("%s: failed to allocate memory for ia list", __func__);
        return NULL;
    }

    ia->addr_list = NULL;
    ia->status_code = DH6OPT_STCODE_UNDEFINE;

    return ia;
}

void ia_clear_list(GSList *head) {
    ia_t *ia;
    GSList *iterator = head;

    while (iterator) {
        ia = (ia_t *) iterator->data;

        g_slist_free(ia->addr_list);
        ia->addr_list = NULL;

        iterator = g_slist_next(iterator);
    }

    g_slist_free(head);
    head = NULL;

    return;
}

gint ia_copy_list(GSList *dst, GSList *src) {
    ia_t *dent;
    const ia_t *ent;
    GSList *iterator = src;

    if (!g_slist_length(iterator)) {
        goto fail;
    }

    while (iterator) {
        ent = (ia_t *) iterator->data;

        if ((dent = ia_create_listval()) == NULL) {
            goto fail;
        }

        dent->type = ent->type;
        dent->flags = ent->flags;
        dent->iaidinfo = ent->iaidinfo;

        if (dhcp6_copy_list(dent->addr_list, ent->addr_list)) {
            g_free(dent);
            goto fail;
        }

        dent->status_code = ent->status_code;
        dst = g_slist_append(dst, dent);

        iterator = g_slist_next(iterator);
    }

    return 0;

fail:
    ia_clear_list(dst);
    return -1;
}

ia_t *ia_find_listval(GSList *head, iatype_t type, guint32 iaid) {
    ia_t *ia = NULL;
    GSList *iterator = head;

    while (iterator) {
        ia = (ia_t *) iterator->data;

        if (ia->type == type && ia->iaidinfo.iaid == iaid) {
            return ia;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

dhcp6_event_t *dhcp6_create_event(dhcp6_if_t *ifp, gint state) {
    dhcp6_event_t *ev;

    static guint32 counter = 0;

    if ((ev = g_malloc0(sizeof(*ev))) == NULL) {
        g_error("%s: failed to allocate memory for an event", __func__);
        return NULL;
    }

    /* for safety */
    ev->serverid.duid_id = NULL;
    ev->ifp = ifp;
    ev->state = state;
    ev->uuid = counter++;
    ev->data_list = NULL;
    g_debug("%s: create an event %p uuid %u for state %d",
            __func__, ev, ev->uuid, ev->state);

    return ev;
}

void dhcp6_remove_event(gpointer data, gpointer user_data) {
    dhcp6_event_t *ev = (dhcp6_event_t *) data;

    g_debug("%s: removing an event %p on %s, state=%d, xid=%x", __func__,
            ev, ev->ifp->ifname, ev->state, ev->xid);

    if (g_slist_length(ev->data_list)) {
        g_error("%s: assumption failure: event data list is not empty",
                __func__);
        exit(1);
    }

    if (ev->serverid.duid_id != NULL) {
        duidfree(&ev->serverid);
    }

    if (ev->timer) {
        dhcp6_remove_timer(ev->timer);
    }

    ev->ifp->event_list = g_slist_remove_all(ev->ifp->event_list, ev);
    g_free(ev);
    ev = NULL;
    return;
}

gint getifaddr(struct in6_addr *addr, gchar *ifnam, struct in6_addr *prefix,
               gint plen, gint strong, gint ignoreflags) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in6 sin6;

    gint error = -1;

    if (getifaddrs(&ifap) != 0) {
        err(1, "getifaddr: getifaddrs");
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        int s1, s2;

        if (strong && g_strcmp0(ifnam, ifa->ifa_name) != 0) {
            continue;
        }

        /* in any case, ignore interfaces in different scope zones. */
        if ((s1 = in6_addrscopebyif(prefix, ifnam)) < 0 ||
            (s2 = in6_addrscopebyif(prefix, ifa->ifa_name)) < 0 || s1 != s2) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET6) {
            continue;
        }

        if (sizeof(*(ifa->ifa_addr)) > sizeof(sin6)) {
            continue;
        }

        if (_in6_matchflags(ifa->ifa_addr, sizeof(sin6), ifa->ifa_name,
                            ignoreflags)) {
            continue;
        }

        memcpy(&sin6, ifa->ifa_addr, sizeof(sin6));


        if (plen % 8 == 0) {
            if (memcmp(&sin6.sin6_addr, prefix, plen / 8) != 0) {
                continue;
            }
        } else {
            struct in6_addr a, m;

            int i;

            memcpy(&a, &sin6.sin6_addr, sizeof(a));
            memset(&m, 0, sizeof(m));
            memset(&m, 0xff, plen / 8);
            m.s6_addr[plen / 8] = (0xff00 >> (plen % 8)) & 0xff;

            for (i = 0; i < sizeof(a); i++) {
                a.s6_addr[i] &= m.s6_addr[i];
            }

            if (memcmp(&a, prefix, plen / 8) != 0 ||
                a.s6_addr[plen / 8] !=
                (prefix->s6_addr[plen / 8] & m.s6_addr[plen / 8])) {
                continue;
            }
        }

        memcpy(addr, &sin6.sin6_addr, sizeof(*addr));
        error = 0;
        break;
    }

    freeifaddrs(ifap);
    return error;
}

gint in6_addrscopebyif(struct in6_addr *addr, gchar *ifnam) {
    guint ifindex;

    if ((ifindex = if_nametoindex(ifnam)) == 0) {
        return -1;
    }

    if (IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MC_LINKLOCAL(addr)) {
        return ifindex;
    }

    if (IN6_IS_ADDR_SITELOCAL(addr) || IN6_IS_ADDR_MC_SITELOCAL(addr)) {
        return 1;             /* XXX */
    }

    if (IN6_IS_ADDR_MC_ORGLOCAL(addr)) {
        return 1;             /* XXX */
    }

    return 1;                 /* treat it as global */
}

/* XXX: this code assumes getifaddrs(3) */
const gchar *getdev(struct sockaddr_in6 *addr) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in6 *a6;
    static gchar ret_ifname[IFNAMSIZ + 1];

    if (getifaddrs(&ifap) != 0) {
        err(1, "getdev: getifaddrs");
        /* NOTREACHED */
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family != AF_INET6) {
            continue;
        }

        a6 = (struct sockaddr_in6 *) ifa->ifa_addr;

        if (!IN6_ARE_ADDR_EQUAL(&a6->sin6_addr, &addr->sin6_addr) ||
            a6->sin6_scope_id != addr->sin6_scope_id) {
            continue;
        }

        break;
    }

    if (ifa) {
        strncpy(ret_ifname, ifa->ifa_name, IFNAMSIZ);
    }

    freeifaddrs(ifap);

    return (ifa ? ret_ifname : NULL);
}

gint transmit_sa(gint s, struct sockaddr_in6 *sa, gchar *buf, size_t len) {
    gint error;

    error = sendto(s, buf, len, MSG_DONTROUTE, (struct sockaddr *) sa,
                   sizeof(*sa));

    return (error != len) ? -1 : 0;
}

glong random_between(glong x, glong y) {
    glong ratio;

    ratio = 1 << 16;

    while ((y - x) * ratio < (y - x)) {
        ratio = ratio / 2;
    }

    return x + ((y - x) * (ratio - 1) / random() & (ratio - 1));
}

gint prefix6_mask(struct in6_addr *in6, gint plen) {
    struct sockaddr_in6 mask6;
    gint i;

    if (sa6_plen2mask(&mask6, plen)) {
        return -1;
    }

    for (i = 0; i < 16; i++) {
        in6->s6_addr[i] &= mask6.sin6_addr.s6_addr[i];
    }

    return 0;
}

gint sa6_plen2mask(struct sockaddr_in6 *sa6, gint plen) {
    guchar *cp;

    if (plen < 0 || plen > 128) {
        return -1;
    }

    memset(sa6, 0, sizeof(*sa6));
    sa6->sin6_family = AF_INET6;

    for (cp = (guchar *) & sa6->sin6_addr; plen > 7; plen -= 8) {
        *cp++ = 0xff;
    }

    *cp = 0xff << (8 - plen);
    return 0;
}

/* return IPv6 address scope type. caller assumes that smaller is narrower. */
gint in6_scope(struct in6_addr *addr) {
    gint scope;

    if (addr->s6_addr[0] == 0xfe) {
        scope = addr->s6_addr[1] & 0xc0;

        switch (scope) {
            case 0x80:
                return 2;       /* link-local */
                break;
            case 0xc0:
                return 5;       /* site-local */
                break;
            default:
                return 14;      /* global: just in case */
                break;
        }
    }

    /* multicast scope. just return the scope field */
    if (addr->s6_addr[0] == 0xff) {
        return (addr->s6_addr[1] & 0x0f);
    }

    if (memcmp(&in6addr_loopback, addr, sizeof(addr) - 1) == 0) {
        if (addr->s6_addr[15] == 1) {   /* loopback */
            return 1;
        }

        if (addr->s6_addr[15] == 0) {   /* unspecified */
            return 0;           /* XXX: good value? */
        }
    }

    return 14;                  /* global */
}

void dhcp6_init_options(dhcp6_optinfo_t *optinfo) {
    memset(optinfo, 0, sizeof(*optinfo));
    /* for safety */
    optinfo->clientID.duid_id = NULL;
    optinfo->serverID.duid_id = NULL;
    optinfo->pref = DH6OPT_PREF_UNDEF;
    optinfo->ia_list = NULL;
    optinfo->reqopt_list = NULL;
    optinfo->dnsinfo.servers = NULL;
    optinfo->relay_list = NULL;
    optinfo->dnsinfo.domains = NULL;
    optinfo->status_code = DH6OPT_STCODE_UNDEFINE;
    optinfo->status_msg = NULL;
    return;
}

void dhcp6_clear_options(dhcp6_optinfo_t *optinfo) {
    duidfree(&optinfo->clientID);
    duidfree(&optinfo->serverID);

    ia_clear_list(optinfo->ia_list);
    g_slist_free(optinfo->reqopt_list);
    optinfo->reqopt_list = NULL;

    g_slist_free(optinfo->dnsinfo.servers);
    optinfo->dnsinfo.servers = NULL;

    g_slist_free(optinfo->relay_list);
    optinfo->relay_list = NULL;

    if (dhcp6_mode == DHCP6_MODE_CLIENT) {
        g_slist_free(optinfo->dnsinfo.domains);
    }

    optinfo->dnsinfo.domains = NULL;
    dhcp6_init_options(optinfo);
    return;
}

gint dhcp6_copy_options(dhcp6_optinfo_t *dst, dhcp6_optinfo_t *src) {
    if (duidcpy(&dst->clientID, &src->clientID)) {
        goto fail;
    }

    if (duidcpy(&dst->serverID, &src->serverID)) {
        goto fail;
    }

    dst->flags = src->flags;

    if (ia_copy_list(dst->ia_list, src->ia_list)) {
        goto fail;
    }

    if (dhcp6_copy_list(dst->reqopt_list, src->reqopt_list)) {
        goto fail;
    }

    dst->dnsinfo.servers = g_slist_copy(src->dnsinfo.servers);
    if (dst == NULL) {
        goto fail;
    }

    memcpy(&dst->server_addr, &src->server_addr, sizeof(dst->server_addr));
    dst->pref = src->pref;

    return 0;

fail:
    /* cleanup temporary resources */
    dhcp6_clear_options(dst);
    return -1;
}

gint dhcp6_get_options(dhcp6opt_t *p, dhcp6opt_t *ep,
                       dhcp6_optinfo_t *optinfo) {
    dhcp6opt_t *np, opth;
    ia_t *ia;
    gint i, opt, optlen, reqopts, num;
    guchar *cp, *val, *iacp;
    guint16 val16;
    guint32 val32;

    for (; p + 1 <= ep; p = np) {
        duid_t duid0;

        /* 
         * get the option header.  XXX: since there is no guarantee
         * about the header alignment, we need to make a local copy.
         */
        memcpy(&opth, p, sizeof(opth));
        optlen = ntohs(opth.dh6opt_len);
        opt = ntohs(opth.dh6opt_type);

        cp = (guchar *) (p + 1);
        np = (dhcp6opt_t *) (cp + optlen);

        g_debug("%s: get DHCP option %s, len %d",
                __func__, dhcp6optstr(opt), optlen);

        /* option length field overrun */
        if (np > ep) {
            g_message("%s: malformed DHCP options", __func__);
            return -1;
        }

        switch (opt) {
            case DH6OPT_CLIENTID:
                if (optlen == 0) {
                    goto malformed;
                }

                duid0.duid_len = optlen;
                duid0.duid_id = cp;
                g_debug("  client DUID: %s", duidstr(&duid0));

                if (duidcpy(&optinfo->clientID, &duid0)) {
                    g_error("%s: failed to copy DUID", __func__);
                    goto fail;
                }

                break;
            case DH6OPT_SERVERID:
                if (optlen == 0) {
                    goto malformed;
                }

                duid0.duid_len = optlen;
                duid0.duid_id = cp;
                g_debug("  server DUID: %s", duidstr(&duid0));

                if (duidcpy(&optinfo->serverID, &duid0)) {
                    g_error("%s: failed to copy DUID", __func__);
                    goto fail;
                }

                break;
            case DH6OPT_ELAPSED_TIME:
                if (optlen != sizeof(guint16)) {
                    goto malformed;
                }

                memcpy(&val16, cp, sizeof(val16));
                num = ntohs(val16);
                g_debug(" this message elapsed time is: %d", num);
                break;
            case DH6OPT_STATUS_CODE:
                if (optlen < sizeof(guint16)) {
                    goto malformed;
                }

                memcpy(&val16, cp, sizeof(val16));
                num = ntohs(val16);
                print_status_code("message", num, p, optlen);
                optinfo->status_code = num;
                break;
            case DH6OPT_ORO:
                if ((optlen % 2) != 0 || optlen == 0) {
                    goto malformed;
                }

                reqopts = optlen / 2;

                for (i = 0, val = cp; i < reqopts;
                     i++, val += sizeof(guint16)) {
                    guint16 opttype;

                    memcpy(&opttype, val, sizeof(guint16));
                    num = ntohs(opttype);

                    g_debug("  requested option: %s", dhcp6optstr(num));

                    if (dhcp6_find_listval(optinfo->reqopt_list,
                                           &num, DHCP6_LISTVAL_NUM)) {
                        g_message("%s: duplicated option type (%s)", __func__,
                                  dhcp6optstr(opttype));
                        goto nextoption;
                    }

                    if (dhcp6_add_listval(optinfo->reqopt_list,
                                          &num, DHCP6_LISTVAL_NUM) == NULL) {
                        g_error("%s: failed to copy requested option",
                                __func__);
                        goto fail;
                    }
                  nextoption:;
                }

                break;
            case DH6OPT_PREFERENCE:
                if (optlen != 1) {
                    goto malformed;
                }

                optinfo->pref = (guint8) * (guchar *) cp;
                g_debug("%s: get option preference is %2x",
                        __func__, optinfo->pref);
                break;
            case DH6OPT_RAPID_COMMIT:
                if (optlen != 0) {
                    goto malformed;
                }

                optinfo->flags |= DHCIFF_RAPID_COMMIT;
                g_debug("%s: get option rapid-commit", __func__);
                break;
            case DH6OPT_UNICAST:
                if (optlen != sizeof(struct in6_addr)
                    && dhcp6_mode != DHCP6_MODE_CLIENT) {
                    goto malformed;
                }

                optinfo->flags |= DHCIFF_UNICAST;
                memcpy(&optinfo->server_addr,
                       (struct in6_addr *) cp, sizeof(struct in6_addr));
                break;
            case DH6OPT_IA_TA:
            case DH6OPT_IA_NA:
            case DH6OPT_IA_PD:
                iacp = cp;

                if ((ia = ia_create_listval()) == NULL) {
                    g_error("%s: failed to allocate memory for ia list",
                            __func__);
                    goto fail;
                }

                ia->iaidinfo.iaid = ntohl(*(guint32 *) iacp);
                iacp += sizeof(guint32);

                switch (opt) {
                    case DH6OPT_IA_TA:
                        if (optlen < sizeof(guint32)) {
                            g_free(ia);
                            ia = NULL;
                            goto malformed;
                        }

                        ia->type = IATA;
                        ia->flags |= DHCIFF_TEMP_ADDRS;
                        g_debug("%s: get option iaid is %u", __func__,
                                ia->iaidinfo.iaid);
                        break;
                    case DH6OPT_IA_NA:
                    case DH6OPT_IA_PD:
                        if (optlen < sizeof(dhcp6_iaid_info_t)) {
                            g_free(ia);
                            ia = NULL;
                            goto malformed;
                        }

                        ia->type = (opt == DH6OPT_IA_NA) ? IANA : IAPD;
                        ia->iaidinfo.renewtime = ntohl(*(guint32 *) iacp);
                        iacp += sizeof(guint32);
                        ia->iaidinfo.rebindtime = ntohl(*(guint32 *) iacp);
                        iacp += sizeof(guint32);

                        g_debug("%s: get option iaid is %u, "
                                "renewtime %u, rebindtime %u", __func__,
                                ia->iaidinfo.iaid,
                                ia->iaidinfo.renewtime,
                                ia->iaidinfo.rebindtime);
                        break;
                }

                if (ia_find_listval(optinfo->ia_list, ia->type,
                                    ia->iaidinfo.iaid)) {
                    g_message("%s: duplicated iaid", __func__);
                    g_free(ia);
                    ia = NULL;
                    goto fail;
                }

                if (_get_assigned_ipv6addrs(iacp, cp + optlen, ia)) {
                    g_free(ia);
                    ia = NULL;
                    goto fail;
                }

                optinfo->ia_list = g_slist_append(optinfo->ia_list, ia);

                break;
            case DH6OPT_DNS_SERVERS:
                if (optlen % sizeof(struct in6_addr) || optlen == 0) {
                    goto malformed;
                }

                for (val = cp; val < cp + optlen;
                     val += sizeof(struct in6_addr)) {
                    if (g_slist_find_custom(optinfo->dnsinfo.servers,
                                            (gconstpointer) val,
                                            _find_in6_addr) != NULL) {
                        g_message("%s: duplicated DNS address (%s)", __func__,
                                  in6addr2str((struct in6_addr *) val, 0));
                        break;
                    }

                    optinfo->dnsinfo.servers =
                       g_slist_append(optinfo->dnsinfo.servers, val);

                    g_message("%s: get DNS address (%s)", __func__,
                              in6addr2str((struct in6_addr *) val, 0));
                }

                break;
            case DH6OPT_DOMAIN_LIST:
                if (optlen == 0) {
                    goto malformed;
                }

                /* dependency on lib resolv */
                for (val = cp; val < cp + optlen;) {
                    int n;
                    gchar *dname = NULL;

                    if ((dname = g_malloc0(MAXDNAME)) == NULL) {
                        g_error("%s: failed to allocate memory", __func__);
                        goto fail;
                    }

                    n = dn_expand(cp, cp + optlen, val, dname, MAXDNAME);

                    if (n < 0) {
                        goto malformed;
                    } else {
                        val += n;
                        g_debug("expand domain name %s, size %d", dname,
                                (gint) strlen(dname));
                    }

                    if (g_slist_find_custom(optinfo->dnsinfo.domains,
                                            (gconstpointer) dname,
                                            _find_string) == NULL) {
                        optinfo->dnsinfo.domains =
                            g_slist_append(optinfo->dnsinfo.domains, dname);
                    }
                }

                break;
            case DH6OPT_INFO_REFRESH_TIME:
                if (optlen != sizeof(guint32)) {
                    goto malformed;
                }

                memcpy(&val32, cp, sizeof(val32));
                optinfo->irt = ntohl(val32);
                g_debug("information refresh time is %u", optinfo->irt);
                break;
            default:
                /* no option specific behavior */
                g_message("%s: unknown or unexpected DHCP6 option %s, len %d",
                          __func__, dhcp6optstr(opt), optlen);
                break;
        }
    }

    return 0;

malformed:
    g_message("%s: malformed DHCP option: type %d, len %d",
              __func__, opt, optlen);
fail:
    dhcp6_clear_options(optinfo);
    return -1;
}

gint dhcp6_set_options(dhcp6opt_t *bp, dhcp6opt_t *ep,
                       dhcp6_optinfo_t *optinfo) {
    dhcp6opt_t *p = bp, opth;
    gint len = 0, optlen = 0;
    guchar *tmpbuf = NULL;
    ia_t *ia;

    if (optinfo->clientID.duid_len) {
        if (!copy_option(DH6OPT_CLIENTID, optinfo->clientID.duid_len,
                         optinfo->clientID.duid_id, p, ep, &opth)) {
            goto fail;
        }
    }

    if (optinfo->serverID.duid_len) {
        if (!copy_option(DH6OPT_SERVERID, optinfo->serverID.duid_len,
                         optinfo->serverID.duid_id, p, ep, &opth)) {
            goto fail;
        }
    }

    if (dhcp6_mode == DHCP6_MODE_CLIENT) {
        if (!copy_option(DH6OPT_ELAPSED_TIME, 2, &optinfo->elapsed_time, p,
                         ep, &opth)) {
            goto fail;
        }
    }

    if (optinfo->flags & DHCIFF_RAPID_COMMIT) {
        if (!copy_option(DH6OPT_RAPID_COMMIT, 0, "", p, ep, &opth)) {
            goto fail;
        }
    }

    if ((dhcp6_mode == DHCP6_MODE_SERVER) &&
        (optinfo->flags & DHCIFF_UNICAST)) {
        if (!IN6_IS_ADDR_UNSPECIFIED(&optinfo->server_addr)) {
            if (!copy_option(DH6OPT_UNICAST, sizeof(optinfo->server_addr),
                             &optinfo->server_addr, p, ep, &opth)) {
                goto fail;
            }
        }
    }

    if (g_slist_length(optinfo->ia_list)) {
        GSList *iterator = optinfo->ia_list;

        while (iterator) {
            ia = (ia_t *) iterator->data;
            tmpbuf = NULL;

            if (_dhcp6_set_ia_options(&tmpbuf, &optlen, ia)) {
                goto fail;
            }

            if (tmpbuf != NULL) {
                switch (ia->type) {
                    case IANA:
                        if (!copy_option(DH6OPT_IA_NA, optlen, tmpbuf, p,
                                         ep, &opth)) {
                            goto fail;
                        }

                        break;
                    case IATA:
                        if (!copy_option(DH6OPT_IA_TA, optlen, tmpbuf, p,
                                         ep, &opth)) {
                            goto fail;
                        }

                        break;
                    case IAPD:
                        if (!copy_option(DH6OPT_IA_PD, optlen, tmpbuf, p,
                                         ep, &opth)) {
                            goto fail;
                        }

                        break;
                }

                g_free(tmpbuf);
            }

            iterator = g_slist_next(iterator);
        }
    }

    if (dhcp6_mode == DHCP6_MODE_SERVER && optinfo->pref != DH6OPT_PREF_UNDEF) {
        guint8 p8 = (guint8) optinfo->pref;
        g_debug("server preference %2x", optinfo->pref);

        if (!copy_option(DH6OPT_PREFERENCE, sizeof(p8), &p8, p, ep, &opth)) {
            goto fail;
        }
    }

    if (optinfo->status_code != DH6OPT_STCODE_UNDEFINE) {
        guint16 code = htons(optinfo->status_code);

        if (!copy_option(DH6OPT_STATUS_CODE, sizeof(code), &code,
                         p, ep, &opth)) {
            goto fail;
        }
    }

    if (g_slist_length(optinfo->reqopt_list)) {
        dhcp6_value_t *opt;
        guint16 *valp;
        GSList *iterator = optinfo->reqopt_list;

        tmpbuf = NULL;
        optlen = g_slist_length(optinfo->reqopt_list) * sizeof(guint16);

        if ((tmpbuf = g_malloc0(optlen)) == NULL) {
            g_error("%s: memory allocation failed for options", __func__);
            goto fail;
        }

        valp = (guint16 *) tmpbuf;

        while (iterator) {
            opt = (dhcp6_value_t *) iterator->data;

            *valp = htons((guint16) opt->val_num);
            iterator = g_slist_next(iterator);
        }

        if (!copy_option(DH6OPT_ORO, optlen, tmpbuf, p, ep, &opth)) {
            goto fail;
        }

        g_free(tmpbuf);
    }

    if (g_slist_length(optinfo->dnsinfo.servers)) {
        struct in6_addr *in6buf, *in6tmp;
        GSList *iterator = NULL;

        tmpbuf = NULL;
        optlen = g_slist_length(optinfo->dnsinfo.servers) *
                 sizeof(struct in6_addr);

        if ((tmpbuf = g_malloc0(optlen)) == NULL) {
            g_error("%s: memory allocation failed for DNS options", __func__);
            goto fail;
        }

        in6buf = (struct in6_addr *) tmpbuf;
        iterator = optinfo->dnsinfo.servers;

        while (iterator) {
            in6tmp = (struct in6_addr *) iterator->data;
            memcpy(in6buf, in6tmp, sizeof(struct in6_addr));
            in6buf++;
            iterator = g_slist_next(iterator);
        }

        if (!copy_option(DH6OPT_DNS_SERVERS, optlen, tmpbuf, p, ep, &opth)) {
            goto fail;
        }

        g_free(tmpbuf);
    }

    if (g_slist_length(optinfo->dnsinfo.domains)) {
        gchar *name;
        guchar *dst;
        GSList *iterator = optinfo->dnsinfo.domains;

        optlen = 0;
        tmpbuf = NULL;

        if ((tmpbuf = g_malloc0(MAXDNAME * MAXDN)) == NULL) {
            g_error("%s: memory allocation failed for DNS options", __func__);
            goto fail;
        }

        memset(&tmpbuf, '\0', sizeof(tmpbuf));
        dst = tmpbuf;

        while (iterator) {
            gint n;
            name = (gchar *) iterator->data;

            n = dn_comp(name, dst, MAXDNAME, NULL, NULL);

            if (n < 0) {
                g_error("%s: compress domain name %s failed", __func__, name);
                goto fail;
            } else {
                g_debug("%s: compress domain name %s", __func__, name);
            }

            optlen += n;
            dst += n;

            iterator = g_slist_next(iterator);
        }

        if (!copy_option(DH6OPT_DOMAIN_LIST, optlen, tmpbuf, p, ep, &opth)) {
            goto fail;
        }

        g_free(tmpbuf);
    }

    if (dhcp6_mode == DHCP6_MODE_SERVER && optinfo->irt) {
        guint32 irt = htonl(optinfo->irt);

        if (!copy_option(DH6OPT_INFO_REFRESH_TIME, sizeof(irt), &irt, p,
                         ep, &opth)) {
            goto fail;
        }
    }

    return len;

fail:
    if (tmpbuf) {
        g_free(tmpbuf);
        tmpbuf = NULL;
    }

    return -1;
}

void dhcp6_set_timeoparam(dhcp6_event_t *ev) {
    ev->retrans = 0;
    ev->init_retrans = 0;
    ev->max_retrans_cnt = 0;
    ev->max_retrans_dur = 0;
    ev->max_retrans_time = 0;

    switch (ev->state) {
        case DHCP6S_SOLICIT:
            ev->init_retrans = SOL_TIMEOUT;
            ev->max_retrans_time = SOL_MAX_RT;
            break;
        case DHCP6S_INFOREQ:
            ev->init_retrans = INF_TIMEOUT;
            ev->max_retrans_time = INF_MAX_RT;
            break;
        case DHCP6S_REQUEST:
            ev->init_retrans = REQ_TIMEOUT;
            ev->max_retrans_time = REQ_MAX_RT;
            ev->max_retrans_cnt = REQ_MAX_RC;
            break;
        case DHCP6S_RENEW:
            ev->init_retrans = REN_TIMEOUT;
            ev->max_retrans_time = REN_MAX_RT;
            break;
        case DHCP6S_REBIND:
            ev->init_retrans = REB_TIMEOUT;
            ev->max_retrans_time = REB_MAX_RT;
            break;
        case DHCP6S_DECLINE:
            ev->init_retrans = DEC_TIMEOUT;
            ev->max_retrans_cnt = DEC_MAX_RC;
            break;
        case DHCP6S_RELEASE:
            ev->init_retrans = REL_TIMEOUT;
            ev->max_retrans_cnt = REL_MAX_RC;
            break;
        case DHCP6S_CONFIRM:
            ev->init_retrans = CNF_TIMEOUT;
            ev->max_retrans_dur = CNF_MAX_RD;
            ev->max_retrans_time = CNF_MAX_RT;
            break;
        default:
            g_message("%s: unexpected event state %d on %s",
                      __func__, ev->state, ev->ifp->ifname);
            exit(1);
    }
}

dhcp6_event_t *dhcp6_reset_timer(dhcp6_event_t *ev) {
    gdouble n, r;
    struct timeval interval;

    switch (ev->state) {
        case DHCP6S_INIT:
            /*
             * The first Solicit message from the client on the interface
             * MUST be delayed by a random amount of time between
             * MIN_SOL_DELAY and MAX_SOL_DELAY.
             * [dhcpv6-28 14.]
             */
            ev->retrans = (random() % (MAX_SOL_DELAY - MIN_SOL_DELAY)) +
                MIN_SOL_DELAY;
            break;
        default:
            if (ev->timeouts == 0) {
                /*
                 * The first RT MUST be selected to be strictly
                 * greater than IRT by choosing RAND to be strictly
                 * greater than 0.
                 * [dhcpv6-28 14.]
                 */
                r = (gdouble) ((random() % 1000) + 1) / 10000;
                n = ev->init_retrans + r * ev->init_retrans;
            } else {
                r = (gdouble) ((random() % 2000) - 1000) / 10000;

                if (ev->timeouts == 0) {
                    n = ev->init_retrans + r * ev->init_retrans;
                } else {
                    n = 2 * ev->retrans + r * ev->retrans;
                }
            }

            if (ev->max_retrans_time && n > ev->max_retrans_time) {
                n = ev->max_retrans_time + r * ev->max_retrans_time;
            }

            ev->retrans = (long) n;
            break;
    }

    interval.tv_sec = (ev->retrans * 1000) / 1000000;
    interval.tv_usec = (ev->retrans * 1000) % 1000000;
    dhcp6_set_timer(&interval, ev->timer);

    g_debug("%s: reset a timer on %s, state=%s, timeo=%d, retrans=%ld",
            __func__, ev->ifp->ifname, dhcp6msgstr(ev->state), ev->timeouts,
            (glong) ev->retrans);

    return ev;
}

gboolean copy_option(gint option, guint8 len, void *data, dhcp6opt_t *p,
                     dhcp6opt_t *ep, dhcp6opt_t *opth) {
    if (((void *) ep - (void *) p) < (len + sizeof(dhcp6opt_t))) {
        g_message("%s: option buffer short for %s", __func__,
                  dhcp6optstr(option));
        return FALSE;
    }

    opth->dh6opt_type = htons(option);
    opth->dh6opt_len = htons(len);
    memcpy(p, opth, sizeof(*opth));

    if (len) {
        memcpy(p + 1, data, len);
    }

    p = (dhcp6opt_t *) ((gchar *) (p + 1) + len);
    len += sizeof(dhcp6opt_t) + len;
    g_debug("%s: set %s", __func__, dhcp6optstr(option));

    return TRUE;
}

gboolean is_in6_addr_reserved(struct in6_addr *addr) {
    return (IN6_IS_ADDR_MULTICAST(addr) ||
            IN6_IS_ADDR_LOOPBACK(addr) ||
            IN6_IS_ADDR_UNSPECIFIED(addr));
}

void random_init(void) {
    gint f, n;
    guint seed = time(NULL) & getpid();
    gchar rand_state[256];

    f = open("/dev/urandom", O_RDONLY);

    if (f > 0) {
        n = read(f, rand_state, sizeof(rand_state));
        close(f);

        if (n > 32) {
            initstate(seed, rand_state, n);
            return;
        }
    }

    srandom(seed);
    return;
}
