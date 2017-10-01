#undef ENABLE_NLS

# FIXME: Mac support:
#/* Define to 1 if you have the MacOS X function CFLocaleCopyCurrent in the
#   CoreFoundation framework. */
#undef HAVE_CFLOCALECOPYCURRENT

# FIXME: Mac support:
#/* Define to 1 if you have the MacOS X function CFPreferencesCopyAppValue in
#   the CoreFoundation framework. */
#undef HAVE_CFPREFERENCESCOPYAPPVALUE

include(CheckFunctionExists)
include(CheckIncludeFile)

check_function_exists("dcgettext" HAVE_DCGETTEXT)
check_function_exists("strerror_r" HAVE_DECL_STRERROR_R)
check_function_exists("gettext" HAVE_GETTEXT)
check_function_exists("iconv" HAVE_ICONV)
check_function_exists("strerror_r" HAVE_STRERROR_R)


check_include_file("dlfcn.h" HAVE_DLFCN_H)
check_include_file("inttypes.h" HAVE_INTTYPES_H)
check_include_file("locale.h" HAVE_LOCALE_H)
check_include_file("memory.h" HAVE_MEMORY_H)
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("strings.h" HAVE_STRINGS_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("unistd.h" HAVE_UNISTD_H)

if(WINCE)
set(HAVE_W32CE_SYSTEM 1)
endif(WINCE)

if(WIN32)
set(HAVE_W32_SYSTEM 1)
endif(WIN32)

set(LT_OBJDIR "")
set(NO_MINUS_C_MINUS_O 0)
set(PACKAGE "\"libgpg-error\"")
set(PACKAGE_BUGREPORT "\"kde-windows@kde.org\"")
set(PACKAGE_VERSION "\"1.12\"")
set(BUILD_REVISION "\"\"")
set(BUILD_TIMESTAMP "\"\"") # don't use a timestamp for now
set(PACKAGE_NAME "\"libgpg-error\"")
set(PACKAGE_STRING "\"${PACKAGE_NAME}-${PACKAGE_VERSION}\"")
set(PACKAGE_TARNAME "\"${PACKAGE_STRING}.tar.bz2\"")
set(PACKAGE_URL "\"http://windows.kde.org\"")

#/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS

#/* Define to 1 if strerror_r returns char *. */
#undef STRERROR_R_CHAR_P

#/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# undef _ALL_SOURCE
#endif
#/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# undef _GNU_SOURCE
#endif
#/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# undef _POSIX_PTHREAD_SEMANTICS
#endif
#/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# undef _TANDEM_SOURCE
#endif
#/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# undef __EXTENSIONS__
#endif
#/* Define to 1 if on MINIX. */
#undef _MINIX
#/* Define to 2 if the system does not provide POSIX.1 features except with
#   this defined. */
#undef _POSIX_1_SOURCE
#/* Define to 1 if you need to in order for `stat' and other things to work. */
#undef _POSIX_SOURCE
#/* Define to empty if `const' does not conform to ANSI C. */
#undef const

set(VERSION ${PACKAGE_VERSION})
set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
set (PKGDATADIR "${DATADIR}/project")

#/* For building we need to define this macro.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS

add_definitions(-DHAVE_CONFIG_H)

configure_file(config.h.cmake config.h)
