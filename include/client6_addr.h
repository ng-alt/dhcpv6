/*
 * client6_addr.h
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

#ifndef __CLIENT6_ADDR_H_DEFINED
#define __CLIENT6_ADDR_H_DEFINED

#include "constants.h"
#include "types.h"
#include "duid.h"
#include "common.h"
#include "dhcp6c.h"

/* XXX: global from common.c */
extern dhcp6_if_t *dhcp6_if;

void dhcp6_init_iaidaddr(void);
gboolean dhcp6_add_iaidaddr(dhcp6_optinfo_t *, ia_t *);
gboolean dhcp6_add_lease(dhcp6_addr_t *);
gboolean dhcp6_remove_iaidaddr(dhcp6_iaidaddr_t *);
gboolean dhcp6c_remove_lease(dhcp6_lease_t *);
gboolean dhcp6_update_iaidaddr(dhcp6_optinfo_t *, ia_t *, gint);
dhcp6_timer_t *dhcp6_iaidaddr_timo(void *);
dhcp6_timer_t *dhcp6_lease_timo(void *);
gboolean client6_ifaddrconf(ifaddrconf_cmd_t, dhcp6_addr_t *);
gint get_iaid(const gchar *, const iaid_table_t *, gint);
gint create_iaid(iaid_table_t *, gint);

#endif /* __CLIENT6_ADDR_H_DEFINED */
