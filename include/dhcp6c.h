/*
 * dhcp6c.h
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

#ifndef __DHCP6C_H_DEFINED
#define __DHCP6C_H_DEFINED

#include "constants.h"
#include "types.h"

gint client6_init(gchar *);
gint get_if_rainfo(dhcp6_if_t *);
void client6_send(dhcp6_event_t *);
void free_servers(dhcp6_if_t *);
gint client6_send_newstate(dhcp6_if_t *, gint);
void run_script(dhcp6_if_t *, gint, gint, guint32);
dhcp6_timer_t *client6_timo(void *);

#endif /* __DHCP6C_H_DEFINED */
