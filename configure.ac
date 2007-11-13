dnl configure.ac for dhcpv6
dnl Author: David Cantrell <dcantrell@redhat.com>

AC_PREREQ(2.59)
AC_INIT([dhcpv6], [0.99.1], [dcantrell@redhat.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/dhcp6s.c])
AC_CONFIG_HEADER([config.h])

AC_DEFINE_UNQUOTED([BUILD_DATE], ["`date +%m%d%Y`"], [Date of dhcpv6 build])

AC_PROG_CPP
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h arpa/nameser.h err.h errno.h fcntl.h getopt.h \
                  ifaddrs.h inttypes.h linux/if.h linux/ipv6.h linux/netlink.h \
                  linux/rtnetlink.h linux/sockios.h net/if.h net/if_arp.h \
                  netdb.h netinet/in.h resolv.h signal.h stdarg.h stdint.h \
                  stdio.h stdlib.h string.h sys/ioctl.h sys/queue.h \
                  sys/socket.h sys/stat.h sys/types.h syslog.h time.h \
                  unistd.h],
                 [],
                 [AC_MSG_FAILURE([*** Header file $ac_header not found.])])

AC_PROG_LIBTOOL

AC_CONFIG_FILES([Makefile include/Makefile src/Makefile man/Makefile etc/Makefile etc/sysconfig/Makefile etc/init.d/Makefile])
AC_OUTPUT
