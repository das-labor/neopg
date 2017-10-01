# configure.ac for libgpg-error
# Copyright (C) 2003, 2004, 2006, 2010, 2013-2017 g10 Code GmbH
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# (Process this file with autoconf to produce a configure script.)
AC_PREREQ(2.59)
min_automake_version="1.14"

m4_define([mym4_package],[libgpg-error])
m4_define([mym4_major], [1])
m4_define([mym4_minor], [28])

m4_define([mym4_version], 1.28-beta)
m4_define([mym4_revision], 0)
m4_define([mym4_revision_dec], 0)
AC_INIT([mym4_package],[mym4_version], [https://bugs.gnupg.org])
# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed:		AGE=0)
# Note that added error codes don't constitute an interface change.
LIBGPG_ERROR_LT_CURRENT=22
LIBGPG_ERROR_LT_AGE=22
LIBGPG_ERROR_LT_REVISION=0
################################################

AC_SUBST(LIBGPG_ERROR_LT_CURRENT)
AC_SUBST(LIBGPG_ERROR_LT_AGE)
AC_SUBST(LIBGPG_ERROR_LT_REVISION)

VERSION_NUMBER=m4_esyscmd(printf "0x%02x%02x00" mym4_major mym4_minor)
AC_SUBST(VERSION_NUMBER)

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 foreign])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/err-sources.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES

# We need to know about the host architecture to avoid spurious
# warnings.
AC_CANONICAL_HOST
AB_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_AWK
AC_CHECK_TOOL(AR, ar, :)
AC_GNU_SOURCE

# Set some variables depending on the platform for later use.
have_w32_system=no
have_w64_system=no
case "${host}" in
    x86_64-*mingw32*)
        have_w32_system=yes
        have_w64_system=yes
        ;;
    *-mingw32*)
        have_w32_system=yes
        ;;
    *-apple-darwin*)
        # This is the equivalent of the _GNU_SOURCE feature-test-macro
        # on GNU libc systems.
        AC_DEFINE(_DARWIN_C_SOURCE, 900000L,
                  Expose all libc features (__DARWIN_C_FULL).)
        ;;
    *)
       ;;
esac


if test "$have_w32_system" != yes; then
  gl_THREADLIB_EARLY
fi

# We build libgpg-error with large file support so that we have a 64
# bit off_t.  Our external interface uses the gpgrt_off_t which is
# anyway specified as 64 bit.  Thus the same libgpg-error can be used
# by software which is not build with large file support.
AC_SYS_LARGEFILE


LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])


# We need to compile and run a program on the build machine.
dnl The AC_PROG_CC_FOR_BUILD macro in the AC archive is broken for
dnl autoconf 2.57.
dnl AC_PROG_CC_FOR_BUILD
AC_MSG_CHECKING(for cc for build)
if test "$cross_compiling" = "yes"; then
  CC_FOR_BUILD="${CC_FOR_BUILD-cc}"
else
  CC_FOR_BUILD="${CC_FOR_BUILD-$CC}"
fi
AC_MSG_RESULT($CC_FOR_BUILD)
AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])


AH_BOTTOM([
/* Force using of NLS for W32 even if no libintl has been found.  This is
   okay because we have our own gettext implementation for W32.  */
#if defined(HAVE_W32_SYSTEM) && !defined(ENABLE_NLS)
#define ENABLE_NLS 1
#endif

/* Connect the generic estream-printf.c to our framework.  */
#define _ESTREAM_PRINTF_REALLOC _gpgrt_realloc
#define _ESTREAM_PRINTF_EXTRA_INCLUDE "gpgrt-int.h"

/* For building we need to define these macro.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS 1
#define GPG_ERR_ENABLE_ERRNO_MACROS 1
#define GPGRT_ENABLE_ES_MACROS 1
])


AM_GNU_GETTEXT_VERSION([0.19.3])
AM_GNU_GETTEXT([external])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h locale.h stdint.h sys/select.h sys/time.h])
AC_FUNC_STRERROR_R
case "${host_os}" in
     solaris*)
     # All versions of Solaris from 2.4 have a thread-safe strerror().
     # Since Solaris 10, in addition strerror_r() exists.
     ;;
     *)
     AC_CHECK_FUNC([strerror_r], [],
AC_MSG_WARN([[Without strerror_r, gpg_strerror_r might not be thread-safe]]))
     ;;
esac

AC_CHECK_FUNCS([flockfile vasprintf])


#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_C_CONST

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_HEADER_TIME
AC_CHECK_SIZEOF(time_t,,[[
#include <stdio.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
]])

# Find a 64 bit integer type to be used instead of off_t.  We prefer
# the standard integer types over int64_t and finally try long long.
if test "$ac_cv_sizeof_int" = "8"; then
   replacement_for_off_t="int"
elif test "$ac_cv_sizeof_long" = "8"; then
   replacement_for_off_t="long"
elif test "$ac_cv_header_stdint_h" = yes; then
   replacement_for_off_t="int64_t"
elif test "$ac_cv_sizeof_long_long" = "8"; then
   replacement_for_off_t="long long"
else
   AC_MSG_ERROR([[
***
*** No 64 bit signed integer type found.  Can't build this library.
***]])
fi
AC_DEFINE_UNQUOTED(REPLACEMENT_FOR_OFF_T, "$replacement_for_off_t",
                   [Used by mkheader to insert the replacement type.])



#
# Setup gcc specific options
#
AC_MSG_NOTICE([checking for cc features])
if test "$GCC" = yes; then
    # Check whether gcc does not emit a diagnostic for unknown -Wno-*
    # options.  This is the case for gcc >= 4.6
    AC_MSG_CHECKING([if gcc ignores unknown -Wno-* options])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6 )
#kickerror
#endif]],[])],[_gcc_silent_wno=yes],[_gcc_silent_wno=no])
    AC_MSG_RESULT($_gcc_silent_wno)

    # Note that it is okay to use CFLAGS here because these are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        M_CFLAGS="-O3 -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        M_CFLAGS="$M_CFLAGS -Wformat -Wno-format-y2k -Wformat-security"
        if test x"$_gcc_silent_wno" = xyes ; then
          _gcc_wopt=yes
        else
          AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
          _gcc_cflags_save=$CFLAGS
          CFLAGS="-Wno-missing-field-initializers"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                            [_gcc_wopt=yes],[_gcc_wopt=no])
          AC_MSG_RESULT($_gcc_wopt)
          CFLAGS=$_gcc_cflags_save;
        fi
        if test x"$_gcc_wopt" = xyes ; then
          M_CFLAGS="$M_CFLAGS -W -Wno-sign-compare -Wno-missing-field-initializers"
        fi

        AC_MSG_CHECKING([if gcc supports -Wdeclaration-after-statement])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wdeclaration-after-statement"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          M_CFLAGS="$M_CFLAGS -Wdeclaration-after-statement"
        fi

	# Prepend the maintainer-cflags so that the user can override
	# them, e.g. to override the optimization flags for debugging.
	CFLAGS="$M_CFLAGS $CFLAGS"
    else
        CFLAGS="$CFLAGS -Wall"
    fi

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi

    # The undocumented option -Wno-psabi suppresses the annoying
    #   "the ABI of passing union with long double has changed in GCC 4.4"
    # which is emitted in estream-printf.c but entirely irrelvant
    # because that union is local to the file.
    if test x"$_gcc_silent_wno" = xyes ; then
       CFLAGS="$CFLAGS -Wno-psabi"
    fi
fi

#
# Check whether the compiler supports the GCC style aligned attribute
#
AC_CACHE_CHECK([whether the GCC style aligned attribute is supported],
       [gcry_cv_gcc_attribute_aligned],
       [gcry_cv_gcc_attribute_aligned=no
        AC_COMPILE_IFELSE([AC_LANG_SOURCE(
          [[struct { int a; } foo __attribute__ ((aligned (16)));]])],
          [gcry_cv_gcc_attribute_aligned=yes])])
if test "$gcry_cv_gcc_attribute_aligned" = "yes" ; then
   AC_DEFINE(HAVE_GCC_ATTRIBUTE_ALIGNED,1,
     [Defined if a GCC style "__attribute__ ((aligned (n))" is supported])
fi

#
# Check for ELF visibility support.
#
AC_CACHE_CHECK(whether the visibility attribute is supported,
       gcry_cv_visibility_attribute,
       [gcry_cv_visibility_attribute=no
        AC_LANG_CONFTEST([AC_LANG_SOURCE(
          [[int foo __attribute__ ((visibility ("hidden"))) = 1;
            int bar __attribute__ ((visibility ("protected"))) = 1;
          ]])])

        if ${CC-cc} -Werror -S conftest.c -o conftest.s \
                  1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD ; then
            if grep '\.hidden.*foo' conftest.s >/dev/null 2>&1 ; then
                if grep '\.protected.*bar' conftest.s >/dev/null 2>&1; then
                    gcry_cv_visibility_attribute=yes
                fi
            fi
        fi
       ])
if test "$gcry_cv_visibility_attribute" = "yes"; then
    AC_CACHE_CHECK(for broken visibility attribute,
       gcry_cv_broken_visibility_attribute,
       [gcry_cv_broken_visibility_attribute=yes
        AC_LANG_CONFTEST([AC_LANG_SOURCE(
          [[int foo (int x);
            int bar (int x) __asm__ ("foo")
                            __attribute__ ((visibility ("hidden")));
            int bar (int x) { return x; }
          ]])])

        if ${CC-cc} -Werror -S conftest.c -o conftest.s \
                  1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD ; then
           if grep '\.hidden@<:@ 	_@:>@foo' conftest.s >/dev/null 2>&1;
            then
               gcry_cv_broken_visibility_attribute=no
           fi
        fi
       ])
fi
if test "$gcry_cv_visibility_attribute" = "yes"; then
    AC_CACHE_CHECK(for broken alias attribute,
       gcry_cv_broken_alias_attribute,
       [gcry_cv_broken_alias_attribute=yes
        AC_LANG_CONFTEST([AC_LANG_SOURCE(
          [[extern int foo (int x) __asm ("xyzzy");
            int bar (int x) { return x; }
            extern __typeof (bar) foo __attribute ((weak, alias ("bar")));
            extern int dfoo;
            extern __typeof (dfoo) dfoo __asm ("abccb");
            int dfoo = 1;
          ]])])

        if ${CC-cc} -Werror -S conftest.c -o conftest.s \
                  1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD ; then
           if grep 'xyzzy' conftest.s >/dev/null 2>&1 && \
              grep 'abccb' conftest.s >/dev/null 2>&1; then
              gcry_cv_broken_alias_attribute=no
           fi
        fi
        ])
fi
if test "$gcry_cv_visibility_attribute" = "yes"; then
    AC_CACHE_CHECK(if gcc supports -fvisibility=hidden,
       gcry_cv_gcc_has_f_visibility,
       [gcry_cv_gcc_has_f_visibility=no
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-fvisibility=hidden"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                          gcry_cv_gcc_has_f_visibility=yes)
        CFLAGS=$_gcc_cflags_save;
       ])
fi
if test "$gcry_cv_visibility_attribute" = "yes" \
   && test "$gcry_cv_broken_visibility_attribute" != "yes" \
   && test "$gcry_cv_broken_alias_attribute" != "yes" \
   && test "$gcry_cv_gcc_has_f_visibility" = "yes"
 then
   AC_DEFINE(GPGRT_USE_VISIBILITY, 1,
             [Define to use the GNU C visibility attribute.])
   CFLAGS="$CFLAGS -fvisibility=hidden"
fi

#
# Check whether ld supports a version script.
# (Actually not a check but a list of systems which are known to support it.)
#
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
esac
AC_ARG_ENABLE([ld-version-script],
              AC_HELP_STRING([--enable-ld-version-script],
                             [enable/disable use of linker version script.
                              (default is system dependent)]),
              [have_ld_version_script=$enableval],
              [ : ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")


#
# Check for thread library.
#
# Windows has always thread support; thus we don't bother to test for
# it as it may lead to false results when cross building.
if test "$have_w32_system" = yes; then
  AC_DEFINE([USE_WINDOWS_THREADS], [1])
  LIBTHREAD=
  LTLIBTHREAD=
  LIBMULTITHREAD=
  LTLIBMULTITHREAD=
  THREADLIB_CPPFLAGS=""
  AC_SUBST([LIBTHREAD])
  AC_SUBST([LTLIBTHREAD])
  AC_SUBST([LIBMULTITHREAD])
  AC_SUBST([LTLIBMULTITHREAD])
else
  gl_LOCK
  if test "$gl_threads_api" = posix; then
    AC_CHECK_SIZEOF(pthread_mutex_t,,[AC_INCLUDES_DEFAULT
                                      #include <pthread.h>])
  fi
fi

# Default value for GPG_ERROR_CONFIG_LIBS
config_libs="-lgpg-error"

#
# Check for other libraries (now only for -lrt).
#
LIB_SCHED_YIELD=
AC_SUBST([LIB_SCHED_YIELD])
AC_SEARCH_LIBS([sched_yield], [rt posix4],
               [if test "$ac_cv_search_sched_yield" != "none required"; then
                  LIB_SCHED_YIELD=$ac_cv_search_sched_yield
                  config_libs="$config_libs $LIB_SCHED_YIELD"
                fi])

#
# Prepare building of estream
#
estream_INIT


#
# Special defines for certain platforms
#
if test "$have_w32_system" = yes; then
    AC_DEFINE(HAVE_W32_SYSTEM,1,[Defined if we run on a W32 API based system])
    if test "$have_w64_system" = yes; then
      AC_DEFINE(HAVE_W64_SYSTEM,1,[Defined if we run on 64 bit W32 API system])
    fi
fi

AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)
AM_CONDITIONAL(HAVE_W64_SYSTEM, test "$have_w64_system" = yes)
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

AC_DEFINE_UNQUOTED(HOST_TRIPLET_STRING, "$host", [The host triplet])


#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
AC_SUBST(BUILD_REVISION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION",
                   [GIT commit id revision used to build this package])

changequote(,)dnl
BUILD_VERSION=`echo "$PACKAGE_VERSION"|sed 's/\([0-9.]*\).*/\1./'`
changequote([,])dnl
BUILD_VERSION="${BUILD_VERSION}0.mym4_revision_dec"
BUILD_FILEVERSION=`echo "${BUILD_VERSION}" | tr . ,`
AC_SUBST(BUILD_VERSION)
AC_SUBST(BUILD_FILEVERSION)


build_tests=yes
AC_ARG_ENABLE([tests], AC_HELP_STRING([--disable-tests],
                                    [do not build the tests]),
                     build_tests=$enableval, build_tests=yes)
AM_CONDITIONAL([BUILD_TESTS], [test "x$build_tests" != xno])

#
# Substitution
#
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([po/Makefile.in m4/Makefile])
AC_CONFIG_FILES([src/Makefile tests/Makefile])
AC_CONFIG_FILES([src/versioninfo.rc src/gpg-error.w32-manifest])

AC_OUTPUT

tmp=
if test "$have_w32_system" != yes; then
   if test x"$gl_use_threads" = xno; then
     tmp=" NO-THREADS"
   fi
fi
if test "$gcry_cv_gcc_attribute_aligned" != "yes" ; then
cat <<G10EOF
***
***  Please note that your compiler does not support the GCC style
***  aligned attribute.  Using this software may evoke bus errors.
***
G10EOF
fi
