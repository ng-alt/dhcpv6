# Makefile.am for dhcpv6 man subdirectory
# Author: David Cantrell <dcantrell@redhat.com>

man5_MANS = dhcp6c.conf.man dhcp6s.conf.man
man8_MANS = dhcp6c.man dhcp6r.man dhcp6s.man

EXTRA_DIST = *.man.in

CLEANFILES = *.man

MAINTAINERCLEANFILES = Makefile.in

sed_verbose = $(sed_verbose_$(V))
sed_verbose_ = $(sed_verbose_$(AM_DEFAULT_VERBOSITY))
sed_verbose_0 = @echo "  SED    "$@;

%.man: %.man.in
	$(sed_verbose)sed \
		-e 's|%DHCP6C_LEASE_PATH%|$(DHCP6C_LEASE_PATH)|g' \
		-e 's|%DHCP6C_DUID_PATH%|$(DHCP6C_DUID_PATH)|g' \
		-e 's|%DHCP6C_CONF_PATH%|$(DHCP6C_CONF_PATH)|g' \
		-e 's|%DHCP6C_PID_PATH%|$(DHCP6C_PID_PATH)|g' \
		-e 's|%DHCP6S_PID_PATH%|$(DHCP6S_PID_PATH)|g' \
		-e 's|%DHCP6R_PID_PATH%|$(DHCP6R_PID_PATH)|g' \
		-e 's|%DHCP6S_CONF_PATH%|$(DHCP6S_CONF_PATH)|g' \
		-e 's|%DHCP6S_DUID_PATH%|$(DHCP6S_DUID_PATH)|g' \
		-e 's|%DHCP6S_LEASE_PATH%|$(DHCP6S_LEASE_PATH)|g' < $< > $@
