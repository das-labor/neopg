# Makefile.am for libgpg-error.
# Copyright (C) 2003, 2004, 2014 g10 Code GmbH
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

gpg_extra_headers =
extra_cppflags =

localedir = $(datadir)/locale

lib_LTLIBRARIES = libgpg-error.la
include_HEADERS = gpg-error.h gpgrt.h

EXTRA_DIST = mkstrtable.awk err-codes.h.in \
	w32-add.h gpg-error.vers gpg-error.def.in \
        versioninfo.rc.in gpg-error.w32-manifest.in

BUILT_SOURCES = gpg-error.def

tmp_files = _gpg-error.def.h

CLEANFILES = gpg-error.def $(tmp_files)


#
# {{{ Begin Windows part
#
if HAVE_W32_SYSTEM
arch_sources = w32-gettext.c w32-lock.c w32-thread.c \
	       w32-iconv.c w32-estream.c
RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
            -DLOCALEDIR=\"$(localedir)\" $(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

gpg_error_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols gpg-error.def
# i686-w64-mingw32.gcc version 4.9.1 takes the long long helper
# functions from libgcc_s_sjlj-1.dll and not from a static libgcc.  As
# a plain C program we do not use exception handler and thus there is
# no need to use this DLL.  Thus we force gcc to link that statically.
extra_ltoptions = -XCClinker -static-libgcc

versioninfo.lo : gpg-error.w32-manifest

install-def-file: gpg-error.def
	-$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) gpg-error.def $(DESTDIR)$(libdir)/gpg-error.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/gpg-error.def

libgpg_error_la_DEPENDENCIES = $(gpg_error_res) gpg-error.def
intllibs =

#
# }}} End Windows part
#
else
#
# {{{ Begin Unix part
#
arch_sources = posix-lock.c posix-thread.c
gpg_error_res =
no_undefined =
export_symbols =
extra_ltoptions =

install-def-file:
uninstall-def-file:

intllibs = @LTLIBINTL@

endif
#
# }}} End Unix part
#

if HAVE_LD_VERSION_SCRIPT
  libgpg_error_vers_opt = -Wl,--version-script=$(srcdir)/gpg-error.vers
else
  libgpg_error_vers_opt =
endif

libgpg_error_la_LDFLAGS = \
  $(no_undefined) $(export_symbols) $(libgpg_error_vers_opt) \
  $(extra_ltoptions) -version-info \
  @LIBGPG_ERROR_LT_CURRENT@:@LIBGPG_ERROR_LT_REVISION@:@LIBGPG_ERROR_LT_AGE@

libgpg_error_la_SOURCES = gettext.h $(arch_sources) \
	gpgrt-int.h init.c init.h version.c lock.h thread.h \
	estream.c estream-printf.c estream-printf.h \
	strsource.c strerror.c code-to-errno.c code-from-errno.c \
	visibility.c visibility.h b64dec.c gpg-error.h

# libgpg_error_la_DEPENDENCIES = \
#        $(srcdir)/gpg-error.vers

# Note that RCCOMPILE needs the same defines as ..._la_CPPFLAGS but
# without the extra_cppflags because they may include am -idirafter
# which is not supported by the RC compiler.
libgpg_error_la_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" $(extra_cppflags)
libgpg_error_la_LIBADD = $(gpg_error_res) $(intllibs) $(LTLIBMULTITHREAD)

# We use CC proper for preprocessing thus we have to convince it that
# the data is really to be preprocessed.
gpg-error.def: Makefile gpg-error.def.in
	cat $(srcdir)/gpg-error.def.in >_$@.h
	$(CPP) $(DEFAULT_INCLUDES) $(INCLUDES) $(extra_cppflags) _$@.h | \
	  grep -v '^#' >$@
	-rm _$@.h

