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

# We distribute the generated sources err-sources.h and err-codes.h,
# because they are needed to build the po directory, and they don't
# depend on the configuration anyway.


if HAVE_W32CE_SYSTEM
gpg_extra_headers = gpg-extra/errno.h
extra_cppflags = -idirafter gpg-extra
else
gpg_extra_headers =
extra_cppflags =
endif

localedir = $(datadir)/locale

bin_PROGRAMS = gpg-error

if HAVE_W32_SYSTEM
noinst_PROGRAMS = gen-w32-lock-obj
else
noinst_PROGRAMS = gen-posix-lock-obj
endif

# Distributed lock object definitions for cross compilation.
lock_obj_pub = \
        syscfg/lock-obj-pub.aarch64-unknown-linux-gnu.h     \
	syscfg/lock-obj-pub.aarch64-apple-darwin.h          \
        syscfg/lock-obj-pub.alpha-unknown-linux-gnu.h       \
        syscfg/lock-obj-pub.arm-unknown-linux-androideabi.h \
        syscfg/lock-obj-pub.arm-unknown-linux-gnueabi.h     \
	syscfg/lock-obj-pub.arm-apple-darwin.h              \
        syscfg/lock-obj-pub.hppa-unknown-linux-gnu.h        \
	syscfg/lock-obj-pub.i386-apple-darwin.h             \
        syscfg/lock-obj-pub.i686-pc-gnu.h                   \
        syscfg/lock-obj-pub.i686-pc-kfreebsd-gnu.h          \
        syscfg/lock-obj-pub.i686-pc-linux-gnu.h             \
        syscfg/lock-obj-pub.m68k-unknown-linux-gnu.h        \
        syscfg/lock-obj-pub.mips-unknown-linux-gnu.h        \
        syscfg/lock-obj-pub.mips64el-unknown-linux-gnuabi64.h \
        syscfg/lock-obj-pub.mipsel-unknown-linux-gnu.h      \
	syscfg/lock-obj-pub.nios2-unknown-linux-gnu.h       \
        syscfg/lock-obj-pub.or1k-unknown-linux-gnu.h        \
        syscfg/lock-obj-pub.powerpc-unknown-linux-gnu.h     \
        syscfg/lock-obj-pub.powerpc64-unknown-linux-gnu.h   \
	syscfg/lock-obj-pub.powerpc64le-unknown-linux-gnu.h \
	syscfg/lock-obj-pub.powerpc-unknown-linux-gnuspe.h  \
        syscfg/lock-obj-pub.s390x-ibm-linux-gnu.h           \
        syscfg/lock-obj-pub.sh3-unknown-linux-gnu.h         \
        syscfg/lock-obj-pub.sh4-unknown-linux-gnu.h         \
        syscfg/lock-obj-pub.sparc-unknown-linux-gnu.h       \
        syscfg/lock-obj-pub.sparc64-unknown-linux-gnu.h     \
	syscfg/lock-obj-pub.x86_64-apple-darwin.h           \
        syscfg/lock-obj-pub.x86_64-pc-kfreebsd-gnu.h        \
        syscfg/lock-obj-pub.x86_64-pc-linux-gnu.h           \
        syscfg/lock-obj-pub.x86_64-pc-linux-gnux32.h        \
        syscfg/lock-obj-pub.x86_64-pc-linux-musl.h          \
	syscfg/lock-obj-pub.tilegx-unknown-linux-gnu.h      \
	syscfg/lock-obj-pub.ia64-unknown-linux-gnu.h        \
	syscfg/lock-obj-pub.mingw32.h


lib_LTLIBRARIES = libgpg-error.la
nodist_include_HEADERS = gpg-error.h gpgrt.h
bin_SCRIPTS = gpg-error-config
m4datadir = $(datadir)/aclocal
m4data_DATA = gpg-error.m4

EXTRA_DIST = mkstrtable.awk err-sources.h.in err-codes.h.in \
	mkerrnos.awk errnos.in README \
	mkerrcodes.awk mkerrcodes1.awk mkerrcodes2.awk mkerrcodes.c \
	mkheader.c gpg-error.h.in mkw32errmap.c w32-add.h w32ce-add.h \
	err-sources.h err-codes.h gpg-error-config.in gpg-error.m4 \
	gpg-error.vers gpg-error.def.in \
        versioninfo.rc.in gpg-error.w32-manifest.in \
	$(lock_obj_pub)

BUILT_SOURCES = err-sources.h err-codes.h code-to-errno.h code-from-errno.h \
	err-sources-sym.h err-codes-sym.h errnos-sym.h gpg-error.h gpgrt.h \
	gpg-error.def mkw32errmap.map.c

tmp_files = _mkerrcodes.h _gpg-error.def.h mkw32errmap.tab.h mkw32errmap.map.c

CLEANFILES = err-sources.h err-codes.h code-to-errno.h code-from-errno.h \
	gpg-error.h gpgrt.h \
        mkerrcodes mkerrcodes.h gpg-error.def mkw32errmap.tab.h \
	mkw32errmap.map.c err-sources-sym.h err-codes-sym.h errnos-sym.h \
	gpg-extra/errno.h mkheader $(tmp_files) lock-obj-pub.native.h


#
# {{{ Begin Windows part
#
if HAVE_W32_SYSTEM
arch_sources = w32-gettext.c w32-lock.c w32-lock-obj.h w32-thread.c \
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
arch_sources = posix-lock.c posix-lock-obj.h posix-thread.c
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
	visibility.c visibility.h b64dec.c
nodist_libgpg_error_la_SOURCES = gpg-error.h

# libgpg_error_la_DEPENDENCIES = \
#        $(srcdir)/gpg-error.vers

# Note that RCCOMPILE needs the same defines as ..._la_CPPFLAGS but
# without the extra_cppflags because they may include am -idirafter
# which is not supported by the RC compiler.
libgpg_error_la_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" $(extra_cppflags)
libgpg_error_la_LIBADD = $(gpg_error_res) $(intllibs) $(LTLIBMULTITHREAD)

gpg_error_SOURCES = strsource-sym.c strerror-sym.c gpg-error.c
gpg_error_CPPFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
                     -DLOCALEDIR=\"$(localedir)\" $(extra_cppflags)
gpg_error_LDADD = ./libgpg-error.la $(LTLIBINTL)

# We build err-sources.h and err-codes.h in the source directory.
# This is needed because gettext does only look into the source
# directory to find the files listed in po/POTFILE.in.  To make these
# rules work we also need to depend on Makefile.am and not on the
# generated files Makefile.in or Makefile.
$(srcdir)/err-sources.h: Makefile.am mkstrtable.awk err-sources.h.in
	$(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=3 \
		$(srcdir)/err-sources.h.in >$@

err-sources-sym.h: Makefile mkstrtable.awk err-sources.h.in
	$(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=2 -v nogettext=1 \
		$(srcdir)/err-sources.h.in >$@

$(srcdir)/err-codes.h: Makefile.am mkstrtable.awk err-codes.h.in
	$(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=3 \
		$(srcdir)/err-codes.h.in >$@

err-codes-sym.h: Makefile mkstrtable.awk err-codes.h.in
	$(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=2 -v nogettext=1 \
		$(srcdir)/err-codes.h.in >$@

code-to-errno.h: Makefile mkerrnos.awk errnos.in
	$(AWK) -f $(srcdir)/mkerrnos.awk $(srcdir)/errnos.in >$@

# It is correct to use $(CPP).  We want the host's idea of the error codes.
mkerrcodes.h: Makefile mkerrcodes.awk $(gpg_extra_headers)
	$(AWK) -f $(srcdir)/mkerrcodes1.awk $(srcdir)/errnos.in >_$@
	$(CPP) $(CPPFLAGS) $(extra_cppflags) -P _$@ | grep GPG_ERR_ | \
               $(AWK) -f $(srcdir)/mkerrcodes.awk >$@
	-rm _$@

if HAVE_W32CE_SYSTEM
# It is correct to use $(CPP).  We want the host's idea of the error codes.
mkw32errmap.tab.h: Makefile mkw32errmap.c
	$(CPP) -DRESOLVE_MACROS $(srcdir)/mkw32errmap.c | \
	      grep '{&mkw32errmap_marker' >$@
mkw32errmap.map.c: mkw32errmap
	./mkw32errmap --map > $@
gpg-extra/errno.h: mkw32errmap
	-$(MKDIR_P) gpg-extra
	./mkw32errmap > $@
else
mkw32errmap.map.c:
	echo "/*dummy*/" > $@
endif

# We use CC proper for preprocessing thus we have to convince it that
# the data is really to be preprocessed.
gpg-error.def: Makefile gpg-error.def.in
	cat $(srcdir)/gpg-error.def.in >_$@.h
	$(CPP) $(DEFAULT_INCLUDES) $(INCLUDES) $(extra_cppflags) _$@.h | \
	  grep -v '^#' >$@
	-rm _$@.h

# It is correct to use $(CC_FOR_BUILD) here.  We want to run the
# program at build time.
mkerrcodes: mkerrcodes.c mkerrcodes.h Makefile
	$(CC_FOR_BUILD) -I. -I$(srcdir) -o $@ $(srcdir)/mkerrcodes.c

if HAVE_W32CE_SYSTEM
# It is correct to use $(CC_FOR_BUILD) here.  We want to run the
# program at build time.
mkw32errmap: mkw32errmap.c mkw32errmap.tab.h Makefile
	$(CC_FOR_BUILD) -I. -I$(srcdir) -o $@ $(srcdir)/mkw32errmap.c
endif

code-from-errno.h: mkerrcodes Makefile
	./mkerrcodes | $(AWK) -f $(srcdir)/mkerrcodes2.awk >$@

errnos-sym.h: Makefile mkstrtable.awk errnos.in
	$(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=2 -v nogettext=1 \
		-v prefix=GPG_ERR_ -v namespace=errnos_ \
		$(srcdir)/errnos.in >$@


mkheader: mkheader.c Makefile
	$(CC_FOR_BUILD) -g -O0 -I. -I$(srcdir) -o $@ $(srcdir)/mkheader.c

parts_of_gpg_error_h = 	 	\
	gpg-error.h.in  	\
	err-sources.h.in 	\
	err-codes.h.in 	 	\
	errnos.in 	 	\
	w32-add.h	 	\
	w32ce-add.h      	\
	$(lock_obj_pub)

# If we are cross-compiling or building on Windows we better make sure
# that no stale native lock include file will be found by mkheader.
if FORCE_USE_SYSCFG
pre_mkheader_cmds = if test -f lock-obj-pub.native.h; \
                    then rm lock-obj-pub.native.h; fi
else
pre_mkheader_cmds = :
parts_of_gpg_error_h += ./lock-obj-pub.native.h

./lock-obj-pub.native.h: Makefile gen-posix-lock-obj$(EXEEXT) posix-lock-obj.h
	./gen-posix-lock-obj >$@
endif

# We also depend on versioninfo.rc because that is build by
# config.status and thus has up-to-date version numbers.
gpg-error.h: Makefile mkheader $(parts_of_gpg_error_h) \
             versioninfo.rc ../config.h
	$(pre_mkheader_cmds)
	./mkheader $(host_os) $(host_triplet)  $(srcdir)/gpg-error.h.in \
                   ../config.h $(PACKAGE_VERSION) $(VERSION_NUMBER) >$@

gpgrt.h: gpg-error.h
	cp gpg-error.h gpgrt.h

install-data-local:
if HAVE_W32CE_SYSTEM
	-$(MKDIR_P) "$(DESTDIR)$(includedir)/gpg-extra"
	$(INSTALL_DATA) gpg-extra/errno.h \
                         "$(DESTDIR)$(includedir)/gpg-extra/errno.h"
else
        :
endif
