/* posix-lock.c - GPGRT lock functions for POSIX systems
   Copyright (C) 2005-2009 Free Software Foundation, Inc.
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

   Parts of the code, in particular use_pthreads_p, are based on code
   from gettext, written by Bruno Haible <bruno@clisp.org>, 2005.
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "gpg-error.h"
#include "gpgrt-int.h"
//#include "posix-lock-obj.h"

#define gpgrt_lock_t pthread_mutex_t
#define GPGRT_LOCK_INITIALIZER PTHREAD_MUTEX_INITIALIZER

/*
 * Functions called before and after blocking syscalls.
 * gpgrt_set_syscall_clamp is used to set them.
 */
static void (*pre_lock_func)(void);
static void (*post_lock_func)(void);

/* Helper to set the clamp functions.  This is called as a helper from
 * _gpgrt_set_syscall_clamp to keep the function pointers local. */
void _gpgrt_lock_set_lock_clamp(void (*pre)(void), void (*post)(void)) {
  pre_lock_func = pre;
  post_lock_func = post;
}

gpg_error_t _gpgrt_lock_init(gpgrt_lock_t *lockhd) {
  int rc = pthread_mutex_init(lockhd, NULL);
  if (rc) rc = gpg_error_from_errno(rc);
  return rc;
}

gpg_error_t _gpgrt_lock_lock(gpgrt_lock_t *lockhd) {
  int rc;
  if (pre_lock_func) pre_lock_func();
  rc = pthread_mutex_lock(lockhd);
  if (rc) rc = gpg_error_from_errno(rc);
  if (post_lock_func) post_lock_func();

  return rc;
}

gpg_error_t _gpgrt_lock_trylock(gpgrt_lock_t *lockhd) {
  int rc;
  rc = pthread_mutex_trylock(lockhd);
  if (rc) rc = gpg_error_from_errno(rc);
  return rc;
}

gpg_error_t _gpgrt_lock_unlock(gpgrt_lock_t *lockhd) {
  int rc;

  rc = pthread_mutex_unlock(lockhd);
  if (rc) rc = gpg_error_from_errno(rc);

  return rc;
}

/* Note: Use this function only if no other thread holds or waits for
   this lock.  */
gpg_error_t _gpgrt_lock_destroy(gpgrt_lock_t *lockhd) {
  int rc;
  rc = pthread_mutex_destroy(lockhd);
  if (rc)
    rc = gpg_error_from_errno(rc);
  else {
    /* Re-init the mutex so that it can be re-used.  */
    /* XXX UB ? */
    gpgrt_lock_t tmp = GPGRT_LOCK_INITIALIZER;
    memcpy(lockhd, &tmp, sizeof tmp);
  }
  return rc;
}
