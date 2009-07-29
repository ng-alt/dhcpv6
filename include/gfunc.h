/*
 * gfunc.h
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

#ifndef __GFUNC_H_DEFINED
#define __GFUNC_H_DEFINED

gint _find_in6_addr(gconstpointer, gconstpointer);
gint _find_string(gconstpointer, gconstpointer);
void _print_in6_addr(gpointer, gpointer);
void _print_string(gpointer, gpointer);
gint dhcp6_has_option(GSList *, gint);

#endif /* __GFUNC_H_DEFINED */
