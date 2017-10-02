# libsocket.m4 serial 1 - based on gnulib socketlib.m4
dnl Copyright (C) 2008-2012 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl npth_SOCKETLIB
dnl Determines the library to use for socket functions.
dnl Sets and AC_SUBSTs LIBSOCKET.
AC_DEFUN([npth_LIBSOCKET],
[
  LIBSOCKET=
  dnl Unix API.
  dnl Solaris has most socket functions in libsocket.
  dnl Haiku has most socket functions in libnetwork.
  dnl BeOS has most socket functions in libnet.
  AC_CACHE_CHECK([for library containing setsockopt], [npth_cv_lib_socket], [
      npth_cv_lib_socket=
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();]], [[setsockopt();]])],
        [],
        [npth_save_LIBS="$LIBS"
         LIBS="$npth_save_LIBS -lsocket"
         AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();]], [[setsockopt();]])],
           [npth_cv_lib_socket="-lsocket"])
         if test -z "$npth_cv_lib_socket"; then
           LIBS="$npth_save_LIBS -lnetwork"
           AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();]], [[setsockopt();]])],
             [npth_cv_lib_socket="-lnetwork"])
           if test -z "$npth_cv_lib_socket"; then
             LIBS="$npth_save_LIBS -lnet"
             AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();]], [[setsockopt();]])],
               [npth_cv_lib_socket="-lnet"])
           fi
         fi
         LIBS="$npth_save_LIBS"
        ])
      if test -z "$npth_cv_lib_socket"; then
        npth_cv_lib_socket="none needed"
      fi
  ])
  if test "$npth_cv_lib_socket" != "none needed"; then
    LIBSOCKET="$npth_cv_lib_socket"
  fi
  AC_SUBST([LIBSOCKET])
])
