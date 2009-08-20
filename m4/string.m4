dnl string.m4 - autoconf checks for memset()
dnl
dnl Copyright (C) 2009  Red Hat, Inc.
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

AC_DEFUN([AM_CHECK_STRING_H],[
    memset=no
    AC_MSG_CHECKING([for memset])
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM(
            [[#include <string.h>]],
            [[char tmp[3];]],
            [[memset(tmp, 0, 3);]]
        )],
        [memset=yes],
        [AC_MSG_FAILURE([memset() not found])]
    )
    AC_MSG_RESULT([$memset])
])
