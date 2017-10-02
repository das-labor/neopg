# Makefile.am - for gcrypt/src
# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
#               2006, 2007  Free Software Foundation, Inc.
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.


## Process this file with automake to produce Makefile.in

EXTRA_DIST = libgcrypt.vers gcrypt.h.in libgcrypt.def

nodist_include_HEADERS = gcrypt.h

lib_LTLIBRARIES = libgcrypt.la
bin_PROGRAMS = dumpsexp hmac256 mpicalc

AM_CFLAGS = $(GPG_ERROR_CFLAGS)
AM_CCASFLAGS = $(NOEXECSTACK_FLAGS)

if HAVE_LD_VERSION_SCRIPT
  libgcrypt_version_script_cmd = -Wl,--version-script=$(srcdir)/libgcrypt.vers
else
  libgcrypt_version_script_cmd =
endif

libgcrypt_la_CFLAGS = $(GPG_ERROR_CFLAGS)
libgcrypt_la_SOURCES = \
        gcrypt-int.h g10lib.h visibility.c visibility.h types.h \
	gcrypt-testapi.h cipher.h cipher-proto.h \
	misc.c global.c sexp.c hwfeatures.c hwf-common.h \
	stdmem.c stdmem.h secmem.c secmem.h \
	mpi.h fips.c \
	hmac256.c hmac256.h context.c context.h \
	ec-context.h

EXTRA_libgcrypt_la_SOURCES = hwf-x86.c hwf-arm.c
gcrypt_hwf_modules = @GCRYPT_HWF_MODULES@


if HAVE_W32_SYSTEM

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(libgcrypt_la_CPPFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

gcrypt_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/libgcrypt.def
extra_ltoptions = -XCClinker -static-libgcc

install-def-file:
	-$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) $(srcdir)/libgcrypt.def $(DESTDIR)$(libdir)/libgcrypt.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/libgcrypt.def

gcrypt_deps = $(gcrypt_res) libgcrypt.def

else !HAVE_W32_SYSTEM

gcrypt_res =
gcrypt_res_ldflag =
no_undefined =
export_symbols =
extra_ltoptions =
install-def-file:
uninstall-def-file:

gcrypt_deps =

endif !HAVE_W32_SYSTEM


libgcrypt_la_LDFLAGS = $(no_undefined) $(export_symbols) $(extra_ltoptions) \
	$(libgcrypt_version_script_cmd) -version-info \
	@LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@
libgcrypt_la_DEPENDENCIES = \
         $(gcrypt_hwf_modules) \
	../cipher/libcipher.la \
	../random/librandom.la \
	../mpi/libmpi.la \
	$(srcdir)/libgcrypt.vers $(gcrypt_deps)
libgcrypt_la_LIBADD = $(gcrypt_res) \
        $(gcrypt_hwf_modules) \
	../cipher/libcipher.la \
	../random/librandom.la \
	../mpi/libmpi.la $(GPG_ERROR_LIBS)


dumpsexp_SOURCES = dumpsexp.c

mpicalc_SOURCES = mpicalc.c
mpicalc_CFLAGS = $(GPG_ERROR_CFLAGS)
mpicalc_LDADD = libgcrypt.la $(DL_LIBS) $(GPG_ERROR_LIBS)

hmac256_SOURCES = hmac256.c
hmac256_CFLAGS = -DSTANDALONE


install-data-local: install-def-file

uninstall-local: uninstall-def-file
