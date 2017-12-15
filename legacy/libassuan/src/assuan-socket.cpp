/* assuan-socket.c - Socket wrapper
   Copyright (C) 2004, 2005, 2009 Free Software Foundation, Inc.
   Copyright (C) 2001-2015 g10 Code GmbH

   This file is part of Assuan.

   Assuan is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   Assuan is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_W32_SYSTEM
#define WIN32_LEAN_AND_MEAN
#include <io.h>
#include <wincrypt.h>
#include <windows.h>
#endif
#include <errno.h>

#include "assuan-defs.h"

#ifdef HAVE_W32_SYSTEM
#ifndef ECONNREFUSED
#define ECONNREFUSED 107
#endif

int _assuan_sock_wsa2errno(int err) {
  switch (err) {
    case WSAENOTSOCK:
      return EINVAL;
    case WSAEWOULDBLOCK:
      return EAGAIN;
    case ERROR_BROKEN_PIPE:
      return EPIPE;
    case WSANOTINITIALISED:
      return ENOSYS;
    case WSAECONNREFUSED:
      return ECONNREFUSED;
    default:
      return EIO;
  }
}
#endif

/* Public API.  */

gpg_error_t assuan_sock_init() {
  gpg_error_t err;
#ifdef HAVE_W32_SYSTEM
  WSADATA wsadat;
#endif

#ifdef HAVE_W32_SYSTEM
  if (!err) WSAStartup(0x202, &wsadat);
#endif

  return err;
}
