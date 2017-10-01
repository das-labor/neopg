/* w32-thread.c - GPGRT thread functions for Windows
   Copyright (C) 2014 g10 Code GmbH

   This file is part of libgpg-error.

   libgpg-error is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   libgpg-error is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_W32_SYSTEM
# error This module may only be build for Windows.
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <gpg-error.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "thread.h"

/*
 * Functions called before and after blocking syscalls.
 * gpgrt_set_syscall_clamp is used to set them.
 */
static void (*pre_syscall_func)(void);
static void (*post_syscall_func)(void);


/* Helper to set the clamp functions.  This is called as a helper from
 * _gpgrt_set_syscall_clamp to keep the function pointers local. */
void
_gpgrt_thread_set_syscall_clamp (void (*pre)(void), void (*post)(void))
{
  pre_syscall_func = pre;
  post_syscall_func = post;
}



gpg_err_code_t
_gpgrt_yield (void)
{
  if (pre_syscall_func)
    pre_syscall_func ();
  Sleep (0);
  if (post_syscall_func)
    post_syscall_func ();
  return 0;
}
