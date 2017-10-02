/* config.h for building with Visual-C for WindowsCE. 
 * Copyright 2010 g10 Code GmbH
 * 
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 * 
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* This file was originally created by running 
 *   ./autogen.sh --build-w32ce
 * on svn revision 389 (libassuan 2.0.2-svn389) and then adjusted to work
 * with Visual-C.
 */

#ifndef _ASSUAN_CONFIG_H_INCLUDED
#define _ASSUAN_CONFIG_H_INCLUDED

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.0.2-svn389-msc1"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libassuan " PACKAGE_VERSION

/* Name of this package */
#define PACKAGE "libassuan"

/* Bug report address */
#define PACKAGE_BUGREPORT "bug-libassuan@gnupg.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libassuan"


/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libassuan"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Version of this package */
#define VERSION PACKAGE_VERSION


/* Enable gpg-error's strerror macro under W32CE.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1


/* Define to 1 if you have the declaration of `sys_siglist', and to 0 if you
   don't. */
#define HAVE_DECL_SYS_SIGLIST 0

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
   with special properties like no file modes */
#define HAVE_DOSISH_SYSTEM 1

/* Define to 1 if you have the `flockfile' function. */
/* #undef HAVE_FLOCKFILE */

/* Define to 1 if you have the `fopencookie' function. */
/* #undef HAVE_FOPENCOOKIE */

/* Define to 1 if you have the `funlockfile' function. */
/* #undef HAVE_FUNLOCKFILE */

/* Define to 1 if you have the `funopen' function. */
/* #undef HAVE_FUNOPEN */

/* Define to 1 if you have the `inet_pton' function. */
/* #undef HAVE_INET_PTON */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #undef HAVE_INTTYPES_H */

/* Define to 1 if you have the `isascii' function. */
#define HAVE_ISASCII 1

/* Define to 1 if you have the <locale.h> header file. */
/* #undef HAVE_LOCALE_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memrchr' function. */
/* #undef HAVE_MEMRCHR */

/* Define to 1 if you have the `nanosleep' function in libc. */
/* #undef HAVE_NANOSLEEP */

/* Define to 1 if you have the `putc_unlocked' function. */
/* #undef HAVE_PUTC_UNLOCKED */

/* Define to 1 if you have the `setenv' function. */
/* #undef HAVE_SETENV */

/* Defined if SO_PEERCRED is supported (Linux specific) */
/* #undef HAVE_SO_PEERCRED */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpcpy' function. */
/* #undef HAVE_STPCPY */

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
/* #undef HAVE_SYS_STAT_H */

/* Define to 1 if you have the <sys/types.h> header file. */
/* #undef HAVE_SYS_TYPES_H */

/* Define to 1 if you have the <sys/uio.h> header file. */
/* #undef HAVE_SYS_UIO_H */

/* Define to 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Define to 1 if you have the `vasprintf' function. */
/* #undef HAVE_VASPRINTF */

/* Defined if we run on WindowsCE */
#define HAVE_W32CE_SYSTEM 1

/* Defined if we run on a W32 API based system */
#define HAVE_W32_SYSTEM 1

/* Define to 1 if you have the <winsock2.h> header file. */
#define HAVE_WINSOCK2_H 1

/* Define to 1 if you have the <ws2tcpip.h> header file. */
#define HAVE_WS2TCPIP_H 1

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
/* #undef NO_MINUS_C_MINUS_O */

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Defined if descriptor passing is supported */
/* #undef USE_DESCRIPTOR_PASSING */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif


/* snprintf is not part of oldnames.lib thus we redefine it here. */
#define snprintf _snprintf

/* We also need to define these functions.  */
#define strdup _strdup
#define strcasecmp _stricmp


#endif /*_ASSUAN_CONFIG_H_INCLUDED*/

