dnl resolver.m4 - autoconf checks for dn_expand() and dn_comp()
dnl
dnl Copyright (C) 2007, 2008  Red Hat, Inc.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU Lesser General Public License as published
dnl by the Free Software Foundation; either version 2.1 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl
dnl Author(s): David Cantrell <dcantrell@redhat.com>

AC_DEFUN([AM_CHECK_RESOLVER],[
    saved_LIBS="$LIBS"
    LIBS="-lresolv"

    AC_MSG_CHECKING([for dn_comp])

    AC_LANG_CONFTEST(
        [AC_LANG_PROGRAM(
            [[#include <resolv.h>]],
            [[if (dn_comp(NULL, NULL, 0, NULL, NULL) == -1)]],
            [[    return 1;]]
         )]
    )

    AC_MSG_RESULT([yes])

    AC_MSG_CHECKING([for dn_expand])

    AC_LANG_CONFTEST(
        [AC_LANG_PROGRAM(
            [[#include <resolv.h>]],
            [[if (dn_expand(NULL, NULL, NULL, NULL, 0) == -1)]],
            [[    return 1;]]
         )]
    )

    AC_MSG_RESULT([yes])

    LIBS="$saved_LIBS"
    RESOLV_LIBS="-lresolv"

    AC_SUBST(LIBS)
    AC_SUBST(RESOLV_LIBS)
])
