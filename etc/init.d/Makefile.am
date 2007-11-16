#
# Makefile.am for dhcpv6 etc/init.d subdirectory
# Author: David Cantrell <dcantrell@redhat.com>
#

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = dhcp6r.sh dhcp6s.sh

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/init.d
	$(install_sh_SCRIPT) -m 0755 dhcp6s.sh $(DESTDIR)$(sysconfdir)/init.d/dhcp6s
	$(install_sh_SCRIPT) -m 0755 dhcp6r.sh $(DESTDIR)$(sysconfdir)/init.d/dhcp6r
