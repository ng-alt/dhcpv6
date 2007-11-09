#
# Makefile.am for dhcpv6 src subdirectory
# Author: David Cantrell <dcantrell@redhat.com>
#

INCLUDES = -I$(top_srcdir)/include

COMMONSRCS = common.c timer.c hash.c lease.c lease_token.l

AM_YFLAGS = -d
AM_CFLAGS = -fPIC

sbin_PROGRAMS = dhcp6s dhcp6r dhcp6c

dhcp6s_SOURCES = dhcp6s.c server6_conf.c server6_addr.c server6_parse.y \
                 server6_token.l $(COMMONSRCS)
dhcp6r_SOURCES = dhcp6r.c relay6_database.c relay6_parser.c relay6_socket.c
dhcp6c_SOURCES = dhcp6c.c cfg.c netlink.c client6_addr.c client6_parse.y \
                 client6_token.l dad_token.l ra_token.l resolv_token.l \
                 radvd_token.l $(COMMONSRCS)

MAINTAINERCLEANFILES = Makefile.in
