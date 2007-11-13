#
# Makefile.am for dhcpv6 etc/init.d subdirectory
# Author: David Cantrell <dcantrell@redhat.com>
#

MAINTAINERCLEANFILES = Makefile.in

install-data-local:
	$(MKDIR_P) $(sysconfdir)/init.d
	$(install_sh_SCRIPT) -m 0755 dhcp6s.sh $(sysconfdir)/init.d/dhcp6s
	$(install_sh_SCRIPT) -m 0755 dhcp6r.sh $(sysconfdir)/init.d/dhcp6r
