# configure.ac                                          -*- Autoconf -*-
# Copyright (C) 2011, 2012 g10 Code GmbH
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

# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# (git tag -s npth-n.m) and run "./autogen.sh --force".  Please bump
# the version number immediately after the release and do another
# commit and push so that the git magic is able to work.
# See below for the LT versions.
m4_define(my_version, [1.6])

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (my_isgit). The latter works
# by requiring the final tag in the repository.
m4_define([git_revision],
          m4_esyscmd([git rev-parse --short HEAD | tr -d '\n\r']))
m4_define([git_revision_dec],
          m4_esyscmd_s([echo $((0x$(echo ]git_revision[|head -c 4)))]))
m4_define([git_betastring],
          m4_esyscmd_s([git describe --match 'npth-[0-9].*[0-9]' --long|\
                        awk -F- '$3!=0{print"-beta"$3}']))
m4_define([my_isgit],m4_if(git_betastring,[],[no],[yes]))
m4_define([my_full_version],[my_version[]git_betastring])

AC_INIT([npth],[my_full_version],[gnupg-devel@gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBNPTH_LT_CURRENT=1
LIBNPTH_LT_AGE=1
LIBNPTH_LT_REVISION=1

# If the API is changed in an incompatible way: increment the next counter.
NPTH_CONFIG_API_VERSION=1
##############################################

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/npth.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE
AC_CANONICAL_HOST
AM_SILENT_RULES

# Enable GNU extensions on systems that have them.
AC_GNU_SOURCE

AH_VERBATIM([_REENTRANT],
[#ifndef _REENTRANT
# define _REENTRANT 1
#endif])

# Checks for programs.
AC_PROG_CC

AC_SUBST(LIBNPTH_LT_CURRENT)
AC_SUBST(LIBNPTH_LT_AGE)
AC_SUBST(LIBNPTH_LT_REVISION)

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])

run_tests="yes"
AC_ARG_ENABLE(tests,
  AC_HELP_STRING([--disable-tests], [disable tests]),
         run_tests=$enableval)
AM_CONDITIONAL(RUN_TESTS, test "$run_tests" = "yes")


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
        AC_SEARCH_LIBS([dispatch_semaphore_create],[dispatch],
        [AC_DEFINE([HAVE_LIB_DISPATCH],1,[Defined if we have libdispatch])])
        ;;
    *-*-aix*)
        have_fork_unsafe_semaphore=yes
        ;;
    *-*-dragonfly*|*-*-freebsd*|*-*-netbsd*)
        LIBS="-lpthread $LIBS"
        AC_SEARCH_LIBS([sem_init],[rt])
        ;;
esac

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")
if test "$have_fork_unsafe_semaphore" = yes; then
   AC_DEFINE(HAVE_FORK_UNSAFE_SEMAPHORE, 1, [Defined if we have fork-unsafe semaphore])
fi

# Set some default values
config_libs="-lnpth $LIBS"
have_w32_system=no
have_w32ce_system=no
have_w64_system=no

# Define OS macros
case "${host}" in
    x86_64-*mingw32*)
        have_w64_system=yes
        ;;
    *-mingw32ce*)
        have_w32ce_system=yes
        ;;
esac
case "${host}" in
    *-mingw32ce*|*-mingw32*)
        have_w32_system=yes
        ;;
    *)
        ;;
esac

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1,
             [Defined if we run on any kind of W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)

if test "$have_w64_system" = yes; then
   AC_DEFINE(HAVE_W64_SYSTEM,1,
             [Defined if we run on a 64 bit W32 API based system])
fi
AM_CONDITIONAL(HAVE_W64_SYSTEM, test "$have_w64_system" = yes)

#
# Generate values for the DLL version info
#
if test "$have_w32_system" = yes; then
    BUILD_ISODATE=`date --iso-8601`
    changequote(,)dnl
    BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
    changequote([,])dnl
    BUILD_FILEVERSION="${BUILD_FILEVERSION}git_revision_dec"
fi
AC_SUBST(BUILD_ISODATE)
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
# Checks for header files.
#
# fixme: For what do we need the sys/socket test?
AC_CHECK_HEADERS([sys/socket.h sys/select.h unistd.h sys/time.h time.h \
                  signal.h])
INSERT_SYS_SELECT_H=
if test x"$ac_cv_header_sys_select_h" = xyes; then
  INSERT_SYS_SELECT_H="include <sys/select.h>"
fi
AC_SUBST(INSERT_SYS_SELECT_H)

if test x"$ac_cv_header_sys_time_h" = xyes; then
  INSERT_SYS_TIME_H="include <sys/time.h>"
fi
AC_SUBST(INSERT_SYS_TIME_H)

if test x"$ac_cv_header_time_h" = xyes; then
  INSERT_TIME_H="include <time.h>"
fi
AC_SUBST(INSERT_TIME_H)

if test x"$ac_cv_header_signal_h" = xyes; then
  INSERT_SIGNAL_H="include <signal.h>"
fi
AC_SUBST(INSERT_SIGNAL_H)


# Some systems lack socklen_t - provide a replacement.
gl_TYPE_SOCKLEN_T
case "${host}" in
  *-*-mingw32*)
    # socklen_t may or may not be defined depending on what headers
    # are included.  To be safe we use int as this is the actual type.
    INSERT_SOCKLEN_T="define _npth_socklen_t int"
    ;;
  *)
    if test ".$gl_cv_socklen_t_equiv" = "."; then
      INSERT_SOCKLEN_T="define _npth_socklen_t socklen_t"
    else
      INSERT_SOCKLEN_T="define _npth_socklen_t ${gl_cv_socklen_t_equiv}"
    fi
esac
AC_SUBST(INSERT_SOCKLEN_T)


#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T


#
# Checks for libraries and functions.
#
#   We test for pthread_detach because glibc 2.22 includes
#   pthread_create but not pthread_detach.
if test "$have_w32_system" = no; then
  AC_SEARCH_LIBS([pthread_detach],[pthread])
  case "x$ac_cv_search_pthread_detach" in
    xno)
      have_pthread=no
      ;;
    xnone\ required)
      have_pthread=yes
      ;;
    *)
      have_pthread=yes
      config_libs="$config_libs $ac_cv_search_pthread_detach"
      ;;
  esac
  if test "$have_pthread" != no; then
    AC_DEFINE(HAVE_PTHREAD,1,[Define if we have pthread.])
    AC_CHECK_FUNCS([pthread_tryjoin_np pthread_setname_np pthread_getname_np])
    AC_CHECK_FUNCS([pthread_mutex_timedlock])
    AC_CHECK_FUNCS([pthread_rwlock_rdlock pthread_rwlock_wrlock])
    AC_CHECK_FUNCS([pthread_rwlock_timedrdlock pthread_rwlock_timedwrlock])
    AC_CHECK_FUNCS([pthread_rwlock_tryrdlock pthread_rwlock_trywrlock])
    AC_CHECK_FUNCS([pthread_atfork])
  fi
fi

AC_CHECK_FUNCS([select pselect gettimeofday])

npth_LIBSOCKET
config_libs="$config_libs $LIBSOCKET"

# Save and restore LIBS so e.g., -lrt, isn't added to it.  Otherwise, *all*
# programs in the package would end up linked with that potentially-shared
# library, inducing unnecessary run-time overhead.
LIB_CLOCK_GETTIME=
AC_SUBST([LIB_CLOCK_GETTIME])
gl_saved_libs=$LIBS
AC_SEARCH_LIBS([clock_gettime], [rt posix4],
               [if test "$ac_cv_search_clock_gettime" != "none required"; then
                  LIB_CLOCK_GETTIME=$ac_cv_search_clock_gettime
                  config_libs="$config_libs $LIB_CLOCK_GETTIME"
                fi
                AC_DEFINE([HAVE_CLOCK_GETTIME],1,
                  [Define to 1 if you have the `clock_gettime' function.])
                ])
LIBS=$gl_saved_libs


#
# Set NETLIBS
#
if test "$have_w32ce_system" = yes; then
   NETLIBS="-lws2 $NETLIBS"
elif test "$have_w32_system" = yes; then
   NETLIBS="-lws2_32 $NETLIBS"
fi
AC_SUBST(NETLIBS)


#
# Substitutions to set generated files in a Emacs buffer to read-only.
#
AC_SUBST(emacs_local_vars_begin, [['Local][ ][Variables:']])
AC_SUBST(emacs_local_vars_read_only, ['buffer-read-only: t'])
AC_SUBST(emacs_local_vars_end, ['End:'])


#
# Substitution used for npth-config
#
NPTH_CONFIG_LIBS="$config_libs"
NPTH_CONFIG_CFLAGS=""
NPTH_CONFIG_HOST="$host"
AC_SUBST(NPTH_CONFIG_API_VERSION)
AC_SUBST(NPTH_CONFIG_LIBS)
AC_SUBST(NPTH_CONFIG_CFLAGS)
AC_SUBST(NPTH_CONFIG_HOST)

#
# Last check.
#
die=no
if test "$have_w32_system" = no; then
  if test "$have_pthread" = "no"; then
     die=yes
     AC_MSG_NOTICE([[
***
*** You need Pthread to build this program.
*** Normally, this library comes with your system.  On Windows, you can use:
***   http://sourceware.org/pthreads-win32/
***]])
  fi
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi

#
# Write output
#
AC_CONFIG_FILES([Makefile
src/npth.h
src/Makefile
w32/Makefile
tests/Makefile])
AC_CONFIG_FILES(npth-config, chmod +x npth-config)
AC_OUTPUT

echo "
        $PACKAGE_NAME-$PACKAGE_VERSION prepared for make

        Revision: git_revision  (git_revision_dec)
        Platform: $host
"
