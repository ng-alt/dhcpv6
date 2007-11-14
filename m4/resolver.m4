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
AC_SUBST(RESOLVER_LIBS)

AC_CHECK_LIB([resolv], [dh_comp], [:],
             [AC_MSG_FAILURE([*** Unable to find dn_comp() in libresolv])])

AC_CHECK_LIB([resolv], [dh_expand], [:]
             [AC_MSG_FAILURE([*** Unable to find dn_expand() in libresolv])])

AC_CHECK_HEADERS([resolv.h], [],
                 [AC_MSG_FAILURE([*** Header file $ac_header not found.])])

dnl libresolv is a system library, so the headers should already be available,
dnl we just need to set the library flags
RESOLVER_LIBS = -lresolv
])
