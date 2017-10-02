# configure.ac - for libassuan
# Copyright (C) 2001, 2002, 2003, 2006, 2007, 2009,
#               2011, 2012, 2013 Free Software Foundation, Inc.
# Copyright (C) 2013, 2014, 2015  g10 Code GmbH
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

# Process this file with autoconf to produce a configure script.


AC_PREREQ(2.61)
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# (git tag -s libassuan-n.m.k) and run "./autogen.sh --force".  Please
# bump the version number immediately after the release and do another
# commit and push so that the git magic is able to work.  See below
# for the LT versions.
m4_define([mym4_package],[libassuan])
m4_define([mym4_major], [2])
m4_define([mym4_minor], [4])
m4_define([mym4_micro], [4])

# To start a new development series, i.e a new major or minor number
# you need to mark an arbitrary commit before the first beta release
# with an annotated tag.  For example a 2.1 branch starts off with
# the tag "foo-2.1-base".  This is used as the base for counting
# beta numbers before the first release of a series.

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isbeta).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_verslist], m4_split(m4_esyscmd([./autogen.sh --find-version] \
                           mym4_package mym4_major mym4_minor mym4_micro),[:]))
m4_define([mym4_isbeta],       m4_argn(2, mym4_verslist))
m4_define([mym4_version],      m4_argn(4, mym4_verslist))
m4_define([mym4_revision],     m4_argn(7, mym4_verslist))
m4_define([mym4_revision_dec], m4_argn(8, mym4_verslist))

AC_INIT([mym4_package],[mym4_version], [http://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBASSUAN_LT_CURRENT=7
LIBASSUAN_LT_AGE=7
LIBASSUAN_LT_REVISION=3

# If the API is changed in an incompatible way: increment the next counter.
LIBASSUAN_CONFIG_API_VERSION=2
##############################################

AC_SUBST(LIBASSUAN_LT_CURRENT)
AC_SUBST(LIBASSUAN_LT_AGE)
AC_SUBST(LIBASSUAN_LT_REVISION)

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR(src/assuan.h.in)
AC_CONFIG_MACRO_DIR(m4)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_HOST
AM_SILENT_RULES
AB_INIT

AC_GNU_SOURCE


AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",[Bug report address])
VERSION_NUMBER=m4_esyscmd(printf "0x%02x%02x%02x" mym4_major \
                          mym4_minor mym4_micro)
AC_SUBST(VERSION_NUMBER)


# Don't default to build static libs.
LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])

# For now we hardcode the use of version scripts.  It would be better
# to write a test for this or even implement this within libtool.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
    *-apple-darwin*)
        AC_DEFINE(_XOPEN_SOURCE, 500, Activate POSIX interface on MacOS X)
        AC_DEFINE(_DARWIN_C_SOURCE, 900000L,
                  Expose all libc features (__DARWIN_C_FULL))
        ;;
esac

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

AH_TOP([
#ifndef _ASSUAN_CONFIG_H_INCLUDED
#define _ASSUAN_CONFIG_H_INCLUDED

/* Enable gpg-error's strerror macro under W32CE.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1

/* Provide the es_ macro for estream.  */
#define GPGRT_ENABLE_ES_MACROS 1

])

AH_BOTTOM([

#endif /*_ASSUAN_CONFIG_H_INCLUDED*/
])


# Checks for programs.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
#AC_ARG_PROGRAM

# We need to compile and run a program on the build machine.  A
# comment in libgpg-error says that the AC_PROG_CC_FOR_BUILD macro in
# the AC archive is broken for autoconf 2.57.  Given that there is no
# newer version of that macro, we assume that it is also broken for
# autoconf 2.61 and thus we use a simple but usually sufficient
# approach.
AC_MSG_CHECKING(for cc for build)
if test "$cross_compiling" = "yes"; then
  CC_FOR_BUILD="${CC_FOR_BUILD-cc}"
else
  CC_FOR_BUILD="${CC_FOR_BUILD-$CC}"
fi
AC_MSG_RESULT($CC_FOR_BUILD)
AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])


if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],_gcc_wopt=yes,_gcc_wopt=no)
    AC_MSG_RESULT($_gcc_wopt)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_wopt" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi
fi


#
# Options depending on the host OS.
#
have_dosish_system=no
have_w32_system=no
have_w64_system=no
have_w32ce_system=no
case "${host}" in
    *-linux*)
        if test "$GCC" = yes; then
          CFLAGS="$CFLAGS -fPIC -DPIC"
        fi
        ;;
    x86_64-*mingw32*)
        have_dosish_system=yes
        have_w32_system=yes
        have_w64_system=yes
        ;;
    *-mingw32ce*)
        have_dosish_system=yes
        have_w32_system=yes
        have_w32ce_system=yes
        ;;
    *-mingw32*)
        have_dosish_system=yes
        have_w32_system=yes
        ;;
    *-solaris*)
	AC_DEFINE(_XOPEN_SOURCE, 500, Activate extensions on Solaris)
	AC_DEFINE(_XOPEN_SOURCE_EXTENDED, 1, Activate extensions on Solaris)
	AC_DEFINE(__EXTENSIONS__, 1, Activate extensions on Solaris)
	;;
esac

if test "$have_dosish_system" = yes; then
   AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
             [Defined if we run on some of the PCDOS like systems
              (DOS, Windoze. OS/2) with special properties like
              no file modes])
fi

if test "$have_w32_system" = yes; then
    AC_DEFINE(HAVE_W32_SYSTEM,1,[Defined if we run on a W32 API based system])
    if test "$have_w64_system" = yes; then
      AC_DEFINE(HAVE_W64_SYSTEM,1,
                [Defined if we run on a 64 bit W32 API based system])
    fi
    if test "$have_w32ce_system" = yes; then
       AC_DEFINE(HAVE_W32CE_SYSTEM,1,[Defined if we run on WindowsCE])
    fi
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)
AM_CONDITIONAL(HAVE_W32CE_SYSTEM, test "$have_w32ce_system" = yes)
AM_CONDITIONAL(HAVE_W64_SYSTEM, test "$have_w64_system" = yes)


#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
AC_SUBST(BUILD_REVISION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION",
                   [GIT commit id revision used to build this package])

changequote(,)dnl
BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
changequote([,])dnl
BUILD_FILEVERSION="${BUILD_FILEVERSION}mym4_revision_dec"
AC_SUBST(BUILD_FILEVERSION)

AC_ARG_ENABLE([build-timestamp],
  AC_HELP_STRING([--enable-build-timestamp],
                 [set an explicit build timestamp for reproducibility.
                  (default is the current time in ISO-8601 format)]),
     [if test "$enableval" = "yes"; then
        BUILD_TIMESTAMP=`date -u +%Y-%m-%dT%H:%M+0000 2>/dev/null || date`
      else
        BUILD_TIMESTAMP="$enableval"
      fi],
     [BUILD_TIMESTAMP="<none>"])
AC_SUBST(BUILD_TIMESTAMP)
AC_DEFINE_UNQUOTED(BUILD_TIMESTAMP, "$BUILD_TIMESTAMP",
                   [The time this package was configured for a build])



#
# Check for network libraries.  They are needed for tests.
#
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))
AC_SUBST(NETLIBS)

if test "$have_w32_system" = yes; then
   if test "$have_w32ce_system" = yes; then
     NETLIBS="-lws2 $NETLIBS"
   else
     # FIXME: Check why we need to use ws2_32 and document that.
     NETLIBS="-lws2_32 $NETLIBS"
   fi
fi

#
# Provide info for src/libassuan-config.in
#
LIBASSUAN_CONFIG_LIB="-lassuan"
LIBASSUAN_CONFIG_CFLAGS=""
LIBASSUAN_CONFIG_HOST="$host"
LIBASSUAN_CONFIG_EXTRA_LIBS=
if test x"$NETLIBS" != x; then
  LIBASSUAN_CONFIG_EXTRA_LIBS="$LIBASSUAN_CONFIG_EXTRA_LIBS $NETLIBS"
fi
AC_SUBST(LIBASSUAN_CONFIG_LIB)
AC_SUBST(LIBASSUAN_CONFIG_CFLAGS)
AC_SUBST(LIBASSUAN_CONFIG_HOST)
AC_SUBST(LIBASSUAN_CONFIG_API_VERSION)
AC_SUBST(LIBASSUAN_CONFIG_EXTRA_LIBS)

#
# Checks for header files.
#
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h locale.h sys/uio.h stdint.h inttypes.h \
                  sys/types.h sys/stat.h unistd.h sys/time.h fcntl.h \
                  sys/select.h ])
AC_TYPE_UINTPTR_T
AC_TYPE_UINT16_T

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

gl_HEADER_SYS_SOCKET
gl_TYPE_SOCKLEN_T

AC_CHECK_MEMBER(struct cmsghdr.cmsg_len,
                [use_descriptor_passing=yes],
                [use_descriptor_passing=no
                 AC_MSG_WARN([
***
*** Data structure for sending ancillary data missing.
*** Descriptor passing won't work.
***])],[
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <unistd.h>
       ])
if test "$use_descriptor_passing" = "yes"; then
 AC_DEFINE(USE_DESCRIPTOR_PASSING, 1,
            [Defined if descriptor passing is supported])
fi
AM_CONDITIONAL(USE_DESCRIPTOR_PASSING, test "$use_descriptor_passing" = "yes")


# Checking for libgpg-error.
AM_PATH_GPG_ERROR(1.17,, AC_MSG_ERROR([libgpg-error was not found]))

#
# Checks for library functions.
#
AC_CHECK_FUNCS([flockfile funlockfile inet_pton stat getaddrinfo \
                getrlimit ])

# If we didn't find inet_pton, it might be in -lsocket (which might
# require -lnsl)
if test X"$ac_cv_func_inet_pton" != X"yes" ; then
    AC_SEARCH_LIBS([inet_pton],[socket],[],[],[-lnsl])
    if test X"$ac_cv_search_inet_pton" != X"no" ; then
        AC_DEFINE([HAVE_INET_PTON],1,[Define to 1 if you have `inet_pton'.])
    fi
fi


# On some systems (e.g. Solaris) nanosleep requires linking to librl.
# Given that we use nanosleep only as an optimization over a select
# based wait function we want it only if it is available in libc.
_save_libs="$LIBS"
AC_SEARCH_LIBS([nanosleep], [],
               [AC_DEFINE(HAVE_NANOSLEEP,1,
                [Define to 1 if you have the `nanosleep' function in libc.])])
LIBS="$_save_libs"


# Check for funopen
AC_CHECK_FUNCS(funopen)
if test $ac_cv_func_funopen != yes; then
    # No funopen but we can implement that in terms of fopencookie.
    AC_CHECK_FUNCS(fopencookie)
    if test $ac_cv_func_fopencookie = yes; then
        AC_LIBOBJ([funopen])
    else
        AC_MSG_WARN([
***
*** No implementation of fopencookie or funopen available.
*** The assuan_get_data_fp function won't work; see the
*** manual for details.  GnuPG does not require this feature.
***])
    fi
fi


AC_REPLACE_FUNCS(isascii)
AC_REPLACE_FUNCS(putc_unlocked)
AC_REPLACE_FUNCS(memrchr)
AC_REPLACE_FUNCS(stpcpy)
AC_CHECK_HEADERS(unistd.h)
AC_REPLACE_FUNCS(setenv)


#
# Check for the getsockopt SO_PEERCRED
#
AC_MSG_CHECKING(for SO_PEERCRED)
AC_CACHE_VAL(assuan_cv_sys_so_peercred,
      [AC_TRY_COMPILE([#include <sys/socket.h>],
         [struct ucred cr;
          int cl = sizeof cr;
          getsockopt (1, SOL_SOCKET, SO_PEERCRED, &cr, &cl);],
          assuan_cv_sys_so_peercred=yes,
          assuan_cv_sys_so_peercred=no)
       ])
AC_MSG_RESULT($assuan_cv_sys_so_peercred)

if test $assuan_cv_sys_so_peercred = yes; then
  AC_DEFINE(HAVE_SO_PEERCRED, 1,
            [Defined if SO_PEERCRED is supported (Linux specific)])
else
  # Check for the getsockopt LOCAL_PEEREID (NetBSD)
  AC_MSG_CHECKING(for LOCAL_PEEREID)
  AC_CACHE_VAL(assuan_cv_sys_so_local_peereid,
      [AC_TRY_COMPILE([#include <sys/socket.>
         #include <sys/un.h>],
         [struct unpcbid unp;
          int unpl = sizeof unp;
          getsockopt (1, SOL_SOCKET, LOCAL_PEEREID, &unp, &unpl);],
          assuan_cv_sys_so_local_peereid=yes,
          assuan_cv_sys_so_local_peereid=no)
       ])
  AC_MSG_RESULT($assuan_cv_sys_so_local_peereid)

  if test $assuan_cv_sys_so_local_peereid = yes; then
    AC_DEFINE(HAVE_LOCAL_PEEREID, 1,
              [Defined if LOCAL_PEEREID is supported (NetBSD specific)])
  else
    # (Open)Solaris
    AC_CHECK_FUNCS([getpeerucred], AC_CHECK_HEADERS([ucred.h]))
    if test $ac_cv_func_getpeerucred != yes; then
        # FreeBSD
        AC_CHECK_FUNCS([getpeereid])
    fi
  fi
fi


#
# Extra features
#
build_doc=yes
AC_ARG_ENABLE([doc], AC_HELP_STRING([--disable-doc],
                                    [do not build the documentation]),
                     build_doc=$enableval, build_doc=yes)
AM_CONDITIONAL([BUILD_DOC], [test "x$build_doc" != xno])


#
# Create the config files.
#
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([m4/Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_CONFIG_FILES([tests/Makefile])
AC_CONFIG_FILES([src/libassuan-config], [chmod +x src/libassuan-config])
AC_CONFIG_FILES([src/versioninfo.rc])

AC_OUTPUT

echo "
        Libassuan v${VERSION} has been configured as follows:

        Revision: mym4_revision  (mym4_revision_dec)
        Platform: $host
"
