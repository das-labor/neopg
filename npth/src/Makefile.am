# Makefile.am - src/ Makefile for npth.
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

EXTRA_DIST = libnpth.vers
#	     versioninfo.rc.in
nodist_include_HEADERS = npth.h

lib_LTLIBRARIES = libnpth.la

if HAVE_LD_VERSION_SCRIPT
libnpth_version_script_cmd = -Wl,--version-script=$(srcdir)/libnpth.vers
else
libnpth_version_script_cmd =
endif

libnpth_la_SOURCES = npth.h npth.c npth-sigev.c

# AM_CPPFLAGS =
# AM_CFLAGS =

if HAVE_W32_SYSTEM
RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

npth_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/npth.def

install-def-file:
	$(INSTALL) $(srcdir)/npth.def $(DESTDIR)$(libdir)/npth.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/npth.def

gpgme_deps = $(gpgme_res) npth.def

else
npth_res =
no_undefined =
export_symbols =
install-def-file:
uninstall-def-file:

npth_deps =
endif

libnpth_la_LDFLAGS = $(no_undefined) $(export_symbols) \
	$(libnpth_version_script_cmd) -version-info \
	@LIBNPTH_LT_CURRENT@:@LIBNPTH_LT_REVISION@:@LIBNPTH_LT_AGE@

libnpth_la_DEPENDENCIES = $(srcdir)/libnpth.vers $(npth_deps)

install-data-local: install-def-file

uninstall-local: uninstall-def-file

