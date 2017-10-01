# Makefile.am for libgpg-error documentation
# Copyright (C) 2014 g10 Code GmbH
#
# This file is part of libgpg-error.
#
# libgpg-error is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# libgpg-error is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <https://www.gnu.org/licenses/>.


EXTRA_DIST = HACKING errorref.txt \
	     yat2m.c

DISTCLEANFILES = gpgrt.cps yat2m-stamp.tmp yat2m-stamp $(myman_pages)
CLEANFILES = yat2m errorref.txt.x

info_TEXINFOS = gpgrt.texi
gpgrt_TEXINFOS = lgpl.texi gpl.texi

YAT2M_OPTIONS = -I $(srcdir) \
	--release "Libgpg-error @PACKAGE_VERSION@" --source "GnuPG"

myman_sources = gpgrt.texi
myman_pages   = gpg-error-config.1

man_MANS = $(myman_pages)

yat2m: yat2m.c
	$(CC_FOR_BUILD) -DPACKAGE_VERSION="\"$(PACKAGE_VERSION)\"" \
                -o $@ $(srcdir)/yat2m.c


yat2m-stamp: $(myman_sources)
	@rm -f yat2m-stamp.tmp
	@touch yat2m-stamp.tmp
	for file in $(myman_sources) ; do \
              ./yat2m $(YAT2M_OPTIONS) --store \
	          `test -f '$$file' || echo '$(srcdir)/'`$$file ; done
	@mv -f yat2m-stamp.tmp $@

yat2m-stamp: yat2m

$(myman_pages) : yat2m-stamp
	@if test -f $@; then :; else \
            trap 'rm -rf yat2m-stamp yat2m-lock' 1 2 13 15; \
               if mkdir yat2m-lock 2>/dev/null; then \
                 rm -f yat2m-stamp; \
                 $(MAKE) $(AM_MAKEFLAGS) yat2m-stamp; \
                 rmdir yat2m-lock; \
               else \
                 while test -d yat2m-lock; do sleep 1; done; \
                 test -f yat2m-stamp; exit $$?; \
               fi; \
             fi

# Make sure that gpgrt.texi is touched if any other texi file has
# been modified.  This is required so that the version.texi magic
# updates the release date.
gpgrt.texi : $(gpgrt_TEXINFOS)
	touch $(srcdir)/gpgrt.texi

errorref.txt.x : errorref.txt
	sed '/^##/ d' $< >$@
	echo "# Installed by $(PACKAGE_NAME) $(PACKAGE_VERSION)" >>$@

install-exec-hook:
if CROSS_COMPILING
	@echo "not install yat2m while cross-compiling"
else
	@echo "installing yat2m on the build system"; \
         $(MKDIR_P) "$(DESTDIR)$(bindir)"; \
	 $(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) \
	         yat2m "$(DESTDIR)$(bindir)/yat2m"
endif

install-data-local: errorref.txt.x
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) errorref.txt.x $(DESTDIR)$(pkgdatadir)/errorref.txt

uninstall-local:
	-@rm $(DESTDIR)$(pkgdatadir)/errorref.txt
if !CROSS_COMPILING
	-@rm $(DESTDIR)$(bindir)/yat2m
endif
