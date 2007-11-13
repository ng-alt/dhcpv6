#
# Makefile.am for dhcpv6 etc/sysconfig subdirectory
# Author: David Cantrell <dcantrell@redhat.com>
#

MAINTAINERCLEANFILES = Makefile.in

install-data-local:
	$(MKDIR_P) $(sysconfdir)/sysconfig
	$(install_sh_DATA) dhcp6s.sysconfig $(sysconfdir)/sysconfig/dhcp6s
	$(install_sh_DATA) dhcp6r.sysconfig $(sysconfdir)/sysconfig/dhcp6r
