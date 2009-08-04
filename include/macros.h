/*
 * macros.h
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

#ifndef __MACROS_H_DEFINED
#define __MACROS_H_DEFINED

/* Some systems define thes in in.h */
#ifndef IN6_IS_ADDR_UNSPECIFIED
#define IN6_IS_ADDR_UNSPECIFIED(a)           \
    (((__const guint32 *) (a))[0] == 0     \
     && ((__const guint32 *) (a))[1] == 0  \
     && ((__const guint32 *) (a))[2] == 0  \
     && ((__const guint32 *) (a))[3] == 0)
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
#define IN6_IS_ADDR_LOOPBACK(a)                      \
    (((__const guint32 *) (a))[0] == 0             \
     && ((__const guint32 *) (a))[1] == 0          \
     && ((__const guint32 *) (a))[2] == 0          \
     && ((__const guint32 *) (a))[3] == htonl (1))
#endif

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const guint8 *) (a))[0] == 0xff)
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a) \
    ((((__const guint32 *) (a))[0] & htonl(0xffc00000)) == htonl(0xfe800000))
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a) \
    ((((__const guint32 *) (a))[0] & htonl(0xffc00000)) == htonl(0xfec00000))
#endif

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b)                                             \
    ((((__const guint32 *) (a))[0] == ((__const guint32 *) (b))[0])     \
     && (((__const guint32 *) (a))[1] == ((__const guint32 *) (b))[1])  \
     && (((__const guint32 *) (a))[2] == ((__const guint32 *) (b))[2])  \
     && (((__const guint32 *) (a))[3] == ((__const guint32 *) (b))[3]))
#endif

#ifndef IN6_IS_ADDR_RESERVED
#define IN6_IS_ADDR_RESERVED(a)                            \
    IN6_IS_ADDR_MULTICAST(a) || IN6_IS_ADDR_LOOPBACK(a) || \
    IN6_IS_ADDR_UNSPECIFIED(a)
#endif

#define DHCP6S_VALID_REPLY(a)                      \
    (a == DHCP6S_REQUEST || a == DHCP6S_RENEW ||   \
     a == DHCP6S_REBIND || a == DHCP6S_DECLINE ||  \
     a == DHCP6S_RELEASE || a == DHCP6S_CONFIRM || \
     a == DHCP6S_INFOREQ)

/* a < b */
#define TIMEVAL_LT(a, b)           \
    (((a).tv_sec < (b).tv_sec) ||  \
    (((a).tv_sec == (b).tv_sec) && \
    ((a).tv_usec < (b).tv_usec)))

/* a <= b */
#define TIMEVAL_LEQ(a, b)          \
    (((a).tv_sec < (b).tv_sec) ||  \
    (((a).tv_sec == (b).tv_sec) && \
    ((a).tv_usec <= (b).tv_usec)))

#endif /* __MACROS_H_DEFINED */
