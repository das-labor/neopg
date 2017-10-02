# Makefile.am - w32 Makefile for nPth.
# Copyright (C) 2011 g10 Code GmbH
#
# This file is part of nPth.
#
# nPth is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# nPth is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

# Note: This directory is only used for W32

EXTRA_DIST = npth.def
nodist_include_HEADERS = npth.h

lib_LTLIBRARIES = libnpth.la

libnpth_la_SOURCES = npth.h npth.c

# AM_CPPFLAGS =
# AM_CFLAGS =

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

npth_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/npth.def
extra_ltoptions = -XCClinker -static-libgcc

install-def-file:
	$(INSTALL) $(srcdir)/npth.def $(DESTDIR)$(libdir)/npth.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/npth.def

gpgme_deps = $(gpgme_res) npth.def


libnpth_la_LDFLAGS = $(no_undefined) $(export_symbols) $(extra_ltoptions) \
	-version-info \
	@LIBNPTH_LT_CURRENT@:@LIBNPTH_LT_REVISION@:@LIBNPTH_LT_AGE@
libnpth_la_DEPENDENCIES = $(npth_deps)
libnpth_la_LIBADD = @NETLIBS@

install-data-local: install-def-file

uninstall-local: uninstall-def-file
