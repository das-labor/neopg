/* init.c - Initialize the GnuPG error library.
   Copyright (C) 2005, 2010 g10 Code GmbH

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

#include "gpgrt-int.h"

/* The realloc function as set by gpgrt_set_alloc_func.  */
static void *(*custom_realloc)(void *a, size_t n);

/* Initialize the library.  This function should be run early.  */
gpg_error_t gpg_err_init(void) {
  _gpgrt_estream_init();
  return 0;
}

/* Register F as allocation function.  This function is used for all
   APIs which return an allocated buffer.  F needs to have standard
   realloc semantics.  It should be called as early as possible and
   not changed later. */
void _gpgrt_set_alloc_func(void *(*f)(void *a, size_t n)) {
  custom_realloc = f;
}

/* The realloc to be used for data returned by the public API.  */
void *_gpgrt_realloc(void *a, size_t n) {
  if (custom_realloc) return custom_realloc(a, n);

  if (!n) {
    free(a);
    return NULL;
  }

  if (!a) return malloc(n);

  return realloc(a, n);
}

/* The malloc to be used for data returned by the public API.  */
void *_gpgrt_malloc(size_t n) {
  if (!n) n++;
  return _gpgrt_realloc(NULL, n);
}

/* The free to be used for data returned by the public API.  */
void _gpgrt_free(void *a) { _gpgrt_realloc(a, 0); }

void _gpg_err_set_errno(int err) { errno = err; }
