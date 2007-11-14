dnl resolver.m4 - autoconf checks for dn_expand() and dn_comp()
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
dnl Red Hat Author(s): David Cantrell <dcantrell@redhat.com>

AC_DEFUN([AM_CHECK_RESOLVER],[
AC_SUBST(LIBS)

saved_LIBS="$LIBS"
LIBS="-lresolv"

AC_CHECK_DECL(
    [dn_comp],
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include <resolv.h>],
            [int i = dn_comp(NULL, NULL, 0, NULL, NULL);]
        )],
        [],
        [AC_MSG_FAILURE([*** Unable to find dn_comp() in libresolv])]
    ),
    [AC_MSG_FAILURE([*** Symbol dn_comp is not declared])],
    [#include <resolv.h>]
)

AC_CHECK_DECL(
    [dn_expand],
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include <resolv.h>],
            [int i = dn_expand(NULL, NULL, 0, NULL, NULL);]
        )],
        [],
        [AC_MSG_FAILURE([*** Unable to find dn_expand() in libresolv])]
    ),
    [AC_MSG_FAILURE([*** Symbol dn_expand is not declared])],
    [#include <resolv.h>]
)

LIBS="$saved_LIBS -lresolv"
])
