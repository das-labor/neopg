/* assuan-io.c - Wraps the read and write functions.
   Copyright (C) 2002, 2004, 2006-2009 Free Software Foundation, Inc.

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif 
# include <windows.h>
#else
# include <sys/wait.h>
#endif

#include "assuan-defs.h"


ssize_t
_assuan_simple_read (assuan_context_t ctx, void *buffer, size_t size)
{
  return _assuan_read (ctx, ctx->inbound.fd, buffer, size);
}


ssize_t
_assuan_simple_write (assuan_context_t ctx, const void *buffer, size_t size)
{
  return _assuan_write (ctx, ctx->outbound.fd, buffer, size);
}
