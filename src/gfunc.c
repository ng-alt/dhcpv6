/*
 * gfunc.c
 * glib helper functions (GFunc, GCompareFunc, etc) used in dhcpv6.
 *
 * Copyright (C) 2009  Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author(s): David Cantrell <dcantrell@redhat.com>
 */

#include <netinet/in.h>

#include <glib.h>

#include "queue.h"
#include "duid.h"
#include "dhcp6.h"
#include "confdata.h"
#include "gfunc.h"
#include "str.h"

/* FIXME: convert to IN6_ARE_ADDR_EQUAL */
gint _find_in6_addr(gconstpointer a, gconstpointer b) {
    struct in6_addr *addr1 = (struct in6_addr *) a;
    struct in6_addr *addr2 = (struct in6_addr *) b;

    return ((*addr1).s6_addr - (*addr2).s6_addr);
}

gint _find_string(gconstpointer a, gconstpointer b) {
    gchar *name1 = (gchar *) a;
    gchar *name2 = (gchar *) b;

    return g_strcmp0(name1, name2);
}

gint _find_event_by_xid(gconstpointer a, gconstpointer b) {
    dhcp6_event_t *event = (dhcp6_event_t *) a;
    guint32 *xid = (guint32 *) b;

    return ((event->xid) - (*xid));
}

gint _find_event_by_state(gconstpointer a, gconstpointer b) {
    dhcp6_event_t *event = (dhcp6_event_t *) a;
    gint *state = (gint *) b;

    return ((event->state) - (*state));
}

/* FIXME: convert to IN6_ARE_ADDR_EQUAL and better return values */
gint _find_lease_by_addr(gconstpointer a, gconstpointer b) {
    dhcp6_lease_t *lease = (dhcp6_lease_t *) a;
    struct dhcp6_addr *ifaddr = (struct dhcp6_addr *) b;

    /* check for prefix length sp->lease_addr.plen == ifaddr->plen && */
    g_debug("%s: request address is %s/%d ", __func__,
            in6addr2str(&ifaddr->addr, 0), ifaddr->plen);
    g_debug("%s: lease address is %s/%d ", __func__,
            in6addr2str(&lease->lease_addr.addr, 0), ifaddr->plen);

    if (IN6_ARE_ADDR_EQUAL(&lease->lease_addr.addr, &ifaddr->addr)) {
        if (ifaddr->type == IAPD && lease->lease_addr.plen == ifaddr->plen) {
            return 0;
        } else if (ifaddr->type == IANA || ifaddr->type == IATA) {
            return 0;
        }
    }

    return 1;
}

void _print_in6_addr(gpointer data, gpointer user_data) {
    struct in6_addr *ns = (struct in6_addr *) data;
    gchar *msg = (gchar *) user_data;

    g_debug("%s %s", msg, in6addr2str(ns, 0));
    return;
}

void _print_string(gpointer data, gpointer user_data) {
    gchar *str = (gchar *) data;
    gchar *msg = (gchar *) user_data;

    g_debug("%s %s", msg, str);
    return;
}

/* FIXME: will go away when optlist becomes a GSList */
gint dhcp6_has_option(struct dhcp6_list *optlist, gint option) {
    struct dhcp6_listval *lv = NULL;

    if (TAILQ_EMPTY(optlist)) {
        return 0;
    }

    for (lv = TAILQ_FIRST(optlist); lv; lv = TAILQ_NEXT(lv, link)) {
        if (lv->val_num == option) {
            return 1;
        }
    }

    return 0;
}
