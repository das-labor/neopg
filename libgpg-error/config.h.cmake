/* config.h.in.  Generated from configure.ac by autoheader.  */

/* GIT commit id revision used to build this package */
#cmakedefine BUILD_REVISION

/* The time this package was configured for a build */
#cmakedefine BUILD_TIMESTAMP

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#cmakedefine ENABLE_NLS 1

/* Define to 1 if you have the MacOS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
#cmakedefine HAVE_CFLOCALECOPYCURRENT 1

/* Define to 1 if you have the MacOS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
#cmakedefine HAVE_CFPREFERENCESCOPYAPPVALUE 1

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#cmakedefine HAVE_DCGETTEXT 1

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
#cmakedefine HAVE_DECL_STRERROR_R 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine HAVE_DLFCN_H 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#cmakedefine HAVE_GETTEXT 1

/* Define if you have the iconv() function. */
#cmakedefine HAVE_ICONV 1

/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine HAVE_INTTYPES_H 1

/* Define to 1 if you have the <locale.h> header file. */
#cmakedefine HAVE_LOCALE_H 1

/* Define to 1 if you have the <memory.h> header file. */
#cmakedefine HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror_r' function. */
#cmakedefine HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#cmakedefine HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H 1

/* Defined if we run on WindowsCE */
#cmakedefine HAVE_W32CE_SYSTEM @HAVE_W32CE_SYSTEM@

/* Defined if we run on a W32 API based system */
#cmakedefine HAVE_W32_SYSTEM @HAVE_W32_SYSTEM@

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#cmakedefine LT_OBJDIR @LT_OBJDIR@

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
#cmakedefine NO_MINUS_C_MINUS_O 1

/* Name of package */
#cmakedefine PACKAGE @PACKAGE@

/* Define to the address where bug reports for this package should be sent. */
#cmakedefine PACKAGE_BUGREPORT @PACKAGE_BUGREPORT@

/* Define to the full name of this package. */
#cmakedefine PACKAGE_NAME @PACKAGE_NAME@

/* Define to the full name and version of this package. */
#cmakedefine PACKAGE_STRING @PACKAGE_STRING@

/* Define to the one symbol short name of this package. */
#cmakedefine PACKAGE_TARNAME @PACKAGE_TARNAME@

/* Define to the home page for this package. */
#cmakedefine PACKAGE_URL @PACKAGE_URL@

/* Define to the version of this package. */
#cmakedefine PACKAGE_VERSION @PACKAGE_VERSION@

/* Define to 1 if you have the ANSI C header files. */
#cmakedefine STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
#cmakedefine STRERROR_R_CHAR_P 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
#cmakedefine _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#cmakedefine _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
#cmakedefine _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
#cmakedefine _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
#cmakedefine __EXTENSIONS__ 1
#endif


/* Version number of package */
#cmakedefine VERSION @VERSION@

/* Define to 1 if on MINIX. */
#cmakedefine _MINIX 1

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
#cmakedefine _POSIX_1_SOURCE 2

/* Define to 1 if you need to in order for `stat' and other things to work. */
#cmakedefine _POSIX_SOURCE 1

/* Define to empty if `const' does not conform to ANSI C. */
#cmakedefine const


/* Force using of NLS for W32 even if no libintl has been found.  This is 
   okay because we have our own gettext implementation for W32.  */
#if defined(HAVE_W32_SYSTEM) && !defined(ENABLE_NLS)
#define ENABLE_NLS 1
#endif
/* For building we need to define these macro.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS 1
#define GPG_ERR_ENABLE_ERRNO_MACROS 1

#if defined(HAVE_W32_SYSTEM) && !defined(HAVE_STDINT_H)
#define uint32_t unsigned __int32
#define uint16_t unsigned __int16
#endif
