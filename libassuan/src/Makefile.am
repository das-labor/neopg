# Assuan Makefile
# Copyright (C) 2001, 2002, 2003, 2009, 2010 Free Software Foundation, Inc.
#
# This file is part of Assuan.
#
# Assuan is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Assuan is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.
## Process this file with automake to produce Makefile.in

EXTRA_DIST = libassuan.m4 libassuan.vers \
             versioninfo.rc.in libassuan.def
AM_CPPFLAGS = -I..

m4datadir = $(datadir)/aclocal
m4data_DATA = libassuan.m4
lib_LTLIBRARIES = libassuan.la
include_HEADERS = assuan.h

if HAVE_LD_VERSION_SCRIPT
libassuan_version_script_cmd = -Wl,--version-script=$(srcdir)/libassuan.vers
else
libassuan_version_script_cmd =
endif


common_sources = \
	assuan.h \
	assuan-defs.h \
	assuan.c context.c system.c \
	debug.c debug.h conversion.c sysutils.c \
	client.c server.c \
	assuan-error.c \
	assuan-buffer.c \
	assuan-handler.c \
	assuan-inquire.c \
	assuan-listen.c \
	assuan-pipe-server.c \
	assuan-socket-server.c \
	assuan-pipe-connect.c \
	assuan-socket-connect.c \
	assuan-uds.c \
	assuan-logging.c \
	assuan-socket.c

if HAVE_W32_SYSTEM
common_sources += system-w32.c
else
common_sources += system-posix.c
endif


if HAVE_W32_SYSTEM

LTRCCOMPILE = $(LIBTOOL) --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) | \
     sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

SUFFIXES: .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i $< -o $@

libassuan_res = versioninfo.lo
libassuan_res_ldflag = -Wl,.libs/versioninfo.o

no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/libassuan.def
extra_ltoptions = -XCClinker -static-libgcc

install-def-file:
	$(INSTALL) $(srcdir)/libassuan.def $(DESTDIR)$(libdir)/libassuan.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/libassuan.def

libassuan_deps = $(libassuan_res) libassuan.def

else
libassuan_res =
libassuan_res_ldflag =
no_undefined =
export_symbols =
extra_ltoptions =

install-def-file:
uninstall-def-file:

libassuan_deps =
endif


libassuan_la_SOURCES = $(common_sources) assuan-io.c
nodist_libassuan_la_SOURCES = assuan.h
libassuan_la_CPPFLAGS = $(AM_CPPFLAGS) @GPG_ERROR_CFLAGS@
libassuan_la_LDFLAGS = $(libassuan_res_ldflag) $(no_undefined) \
        $(extra_ltoptions) \
	$(export_symbols) $(libassuan_version_script_cmd) -version-info \
	@LIBASSUAN_LT_CURRENT@:@LIBASSUAN_LT_REVISION@:@LIBASSUAN_LT_AGE@
libassuan_la_DEPENDENCIES = @LTLIBOBJS@ \
	$(srcdir)/libassuan.vers $(libassuan_deps)
libassuan_la_LIBADD = @LTLIBOBJS@ @NETLIBS@ @GPG_ERROR_LIBS@

