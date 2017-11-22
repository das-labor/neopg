/* posix-thread.c - GPGRT thread functions for POSIX systems
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

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* Get posix option macros.  */

#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

#include "gpg-error.h"

#include "gpgrt-int.h"

/*
 * Functions called before and after blocking syscalls.
 * gpgrt_set_syscall_clamp is used to set them.
 */
static void (*pre_syscall_func)(void);
static void (*post_syscall_func)(void);

/* Helper to set the clamp functions.  This is called as a helper from
 * _gpgrt_set_syscall_clamp to keep the function pointers local. */
void _gpgrt_thread_set_syscall_clamp(void (*pre)(void), void (*post)(void)) {
  pre_syscall_func = pre;
  post_syscall_func = post;
}

gpg_error_t _gpgrt_yield(void) {
#ifdef _POSIX_PRIORITY_SCHEDULING
  if (pre_syscall_func) pre_syscall_func();
  sched_yield();
  if (post_syscall_func) post_syscall_func();
#else
  return GPG_ERR_NOT_SUPPORTED;
#endif

  return 0;
}
