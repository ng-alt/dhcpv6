/*
 * server6_addr.h
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

#ifndef __SERVER6_ADDR_H_DEFINED
#define __SERVER6_ADDR_H_DEFINED

#include "types.h"
#include "str.h"
#include "lease.h"
#include "server6_conf.h"
#include "duid.h"
#include "timer.h"
#include "common.h"

host_decl_t *find_hostdecl(duid_t *, guint32, GSList *);
gint dhcp6_add_iaidaddr(dhcp6_optinfo_t *, ia_t *);
gint dhcp6_remove_iaidaddr(dhcp6_iaidaddr_t *);
dhcp6_iaidaddr_t *dhcp6_find_iaidaddr(duid_t *, guint32, iatype_t);
gint dhcp6s_remove_lease(dhcp6_lease_t *);
gint dhcp6_update_iaidaddr(dhcp6_optinfo_t *, ia_t *, gint);
gint dhcp6_validate_bindings(GSList *, dhcp6_iaidaddr_t *, gint);
gint dhcp6_add_lease(dhcp6_iaidaddr_t *, dhcp6_addr_t *);
gint dhcp6_update_lease(dhcp6_addr_t *, dhcp6_lease_t *);
dhcp6_timer_t *dhcp6_iaidaddr_timo(void *);
dhcp6_timer_t *dhcp6_lease_timo(void *);
gint dhcp6_get_hostconf(ia_t *, ia_t *, dhcp6_iaidaddr_t *, host_decl_t *);
gint dhcp6_create_addrlist(ia_t *, ia_t *, const dhcp6_iaidaddr_t *,
                           const link_decl_t *, guint16 *);
gint dhcp6_create_prefixlist(ia_t *, ia_t *, const dhcp6_iaidaddr_t *,
                             const link_decl_t *, guint16 *);
host_decl_t *dhcp6_allocate_host(dhcp6_if_t *, rootgroup_t *,
                                 dhcp6_optinfo_t *);
link_decl_t *dhcp6_allocate_link(dhcp6_if_t *, rootgroup_t *,
                                 struct in6_addr *);

#endif /* __SERVER6_ADDR_H_DEFINED */
