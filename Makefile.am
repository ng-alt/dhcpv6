#
# Makefile.am for dhcpv6
# Author: David Cantrell <dcantrell@redhat.com>
#

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src man etc

EXTRA_DIST = AUTHORS LICENSE README TODO docs ChangeLog

MAINTAINERCLEANFILES = Makefile.in config.guess config.h.in config.sub \
                       depcomp install-sh ltmain.sh missing ABOUT-NLS \
                       INSTALL aclocal.m4 configure ylwrap $(DIST_ARCHIVES)

CLEANFILES = *~ ChangeLog

MOSTLYCLEANDIRS = m4

CVSTAG = $(shell echo "$(PACKAGE)-$(VERSION)" | sed -e 's|\.|_|g')
FTPURL = ftp://upload.sourceforge.net/incoming/

ChangeLog:
	rm -f ChangeLog ChangeLog.bak
	cvs2cl

tag:
	cvs tag -R $(CVSTAG)

release: dist-gzip
	rm -rf $(PACKAGE)-$(VERSION)
	gzip -dc $(PACKAGE)-$(VERSION).tar.gz | tar -xvf -
	( cd $(PACKAGE)-$(VERSION) && ./configure && make ) || exit 1
	$(MAKE) tag
	curl --upload-file $(PACKAGE)-$(VERSION).tar.gz $(FTPURL)
