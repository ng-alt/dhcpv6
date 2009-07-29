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
gint dhcp6_has_option(GSList *optlist, gint option) {
    dhcp6_value_t *lv = NULL;
    GSList *iterator = optlist;

    if (!g_slist_length(iterator)) {
        return 0;
    }

    do {
        lv = (dhcp6_value_t *) iterator->data;

        if (lv->val_num == option) {
            return 1;
        }
    } while ((iterator = g_slist_next(iterator)) != NULL);

    return 0;
}
