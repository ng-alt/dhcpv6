dnl configure.ac for dhcpv6
dnl
dnl Copyright (C) 2007  Red Hat, Inc.  All rights reserved.
dnl
dnl This copyrighted material is made available to anyone wishing to use,
dnl modify, copy, or redistribute it subject to the terms and conditions of
dnl the GNU General Public License v.2, or (at your option) any later version.
dnl This program is distributed in the hope that it will be useful, but WITHOUT
dnl ANY WARRANTY expressed or implied, including the implied warranties of
dnl MERCHANTABILITY or FITNESS FOR A * PARTICULAR PURPOSE.  See the GNU General
dnl Public License for more details.  You should have received a copy of the
dnl GNU General Public License along with this program; if not, write to the
dnl Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
dnl 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
dnl source code or documentation are not subject to the GNU General Public
dnl License and may only be used or replicated with the express permission of
dnl Red Hat, Inc.
dnl
dnl Red Hat Author: David Cantrell <dcantrell@redhat.com>

AC_PREREQ(2.61)
AC_INIT([dhcpv6], [1.0.3], [dcantrell@redhat.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/dhcp6s.c])
AC_CONFIG_HEADER([config.h])

dnl Versioning
dnl (from glib's configure.in ...)
dnl Making releases:
dnl     DHCPV6_MICRO_VERSION += 1;
dnl     DHCPV6_INTERFACE_AGE += 1;
dnl     DHCPV6_BINARY_AGE += 1;
dnl if any functions have been added, set DHCPV6_INTERFACE_AGE to 0.
dnl if backwards compatibility has been broken (e.g., functions removed,
dnl function signatures changed),
dnl set DHCPV6_BINARY_AGE and DHCPV6_INTERFACE_AGE to 0.
DHCPV6_MAJOR_VERSION=1
DHCPV6_MINOR_VERSION=0
DHCPV6_MICRO_VERSION=3
DHCPV6_INTERFACE_AGE=0
DHCPV6_BINARY_AGE=0
DHCPV6_VERSION_SUFFIX=
DHCPV6_VERSION=$DHCPV6_MAJOR_VERSION.$DHCPV6_MINOR_VERSION.$DHCPV6_MICRO_VERSION$DHCPV6_VERSION_SUFFIX

LT_RELEASE=$DHCPV6_MAJOR_VERSION.$DHCPV6_MINOR_VERSION
LT_CURRENT=`expr $DHCPV6_MICRO_VERSION - $DHCPV6_INTERFACE_AGE`
LT_REVISION=$DHCPV6_INTERFACE_AGE
AC_SUBST(DHCPV6_VERSION)
AC_SUBST(LT_RELEASE)
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

# Ensure that the DHCPV6_*-specified version is the same as the literal
# in the AC_INIT line, above.
test $PACKAGE_VERSION = $DHCPV6_VERSION ||
  AC_MSG_ERROR(configure.ac: version mismatch: $PACKAGE_VERSION != $DHCPV6_VERSION)

AC_DEFINE_UNQUOTED([BUILD_DATE], ["`date +%m%d%Y`"], [Date of dhcpv6 build])

AC_PROG_CPP
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_LIBTOOL

# check for required headers
AC_HEADER_RESOLV
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

# Check for headers we must have on the system
AC_CHECK_HEADERS([arpa/inet.h err.h errno.h getopt.h fcntl.h ifaddrs.h \
                  linux/ipv6.h linux/sockios.h net/if.h net/if_arp.h \
                  netdb.h netinet/in.h signal.h stdint.h stdlib.h \
                  string.h sys/ioctl.h sys/socket.h sys/time.h \
                  sys/timeb.h syslog.h unistd.h \
                  linux/netlink.h linux/rtnetlink.h],
                 [],
                 [AC_MSG_FAILURE([*** Header file $ac_header not found.])],
                 [[#ifdef HAVE_SYS_SOCKET_H
                   # include <sys/socket.h>
                   #endif
                 ]])

# Check for headers that are nice, but we don't absolutely have to have
AC_CHECK_HEADERS([sys/queue.h isc-dhcp/libdhcp_control.h])

AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# check for required library functions
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([bzero ftime gettimeofday memset select socket strchr strdup \
                strerror strrchr strstr strtol strtoul],
               [],
               [AC_MSG_FAILURE([*** Required function $ac_func not found.])])

# find dn_comp() and dn_expand()
AM_CHECK_RESOLVER

AC_CONFIG_FILES([Makefile include/Makefile src/Makefile man/Makefile \
                 etc/Makefile etc/sysconfig/Makefile etc/init.d/Makefile])
AC_OUTPUT
