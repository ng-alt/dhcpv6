/* dhcp6client.h
 *
 * Interface to the DHCPv6 client libdhcp6client library.
 *
 * Copyright (C) 2006, 2007, 2008  Red Hat, Inc.
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
 * Author(s): Jason Vas Dias
 *            David Cantrell <dcantrell@redhat.com>
 */

/* include libdhcp.h for this */
extern struct libdhcp_control_s;

/* the DHCPv6 client main() function */
extern int dhcpv6_client(struct libdhcp_control_s *dhc_ctl,
                         int argc, char **argv, char **envp);
