/* util.c
 * Copyright (C) 2001, 2009, 2012 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * KSBA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <botan/hash.h>

#include "util.h"

static void *(*alloc_func)(size_t n) = malloc;
static void *(*realloc_func)(void *p, size_t n) = realloc;
static void (*free_func)(void *) = free;

/* Note, that we expect that the free fucntion does not change
   ERRNO. */
void ksba_set_malloc_hooks(void *(*new_alloc_func)(size_t n),
                           void *(*new_realloc_func)(void *p, size_t n),
                           void (*new_free_func)(void *)) {
  alloc_func = new_alloc_func;
  realloc_func = new_realloc_func;
  free_func = new_free_func;
}

/* Hash BUFFER of LENGTH bytes using the algorithjm denoted by OID,
   where OID may be NULL to demand the use od SHA-1.  The resulting
   digest will be placed in the provided buffer RESULT which must have
   been allocated by the caller with at LEAST RESULTSIZE bytes; the
   actual length of the result is put into RESULTLEN.

   The function shall return 0 on success or any other appropriate
   gpg-error.
*/
gpg_error_t _ksba_hash_buffer(const char *oid, const void *buffer,
                              size_t length, size_t resultsize,
                              unsigned char *result, size_t *resultlen) {
  if (oid && strcmp(oid, "1.3.14.3.2.26")) return GPG_ERR_NOT_SUPPORTED;
  if (resultsize < 20) return GPG_ERR_BUFFER_TOO_SHORT;
  std::unique_ptr<Botan::HashFunction> sha1 =
      Botan::HashFunction::create_or_throw("SHA-1");
  Botan::secure_vector<uint8_t> hash = sha1->process((uint8_t *)buffer, length);
  memcpy(result, hash.data(), hash.size());
  *resultlen = 20;
  return 0;
}

/* Wrapper for the common memory allocation functions.  These are here
   so that we can add hooks.  The corresponding macros should be used.
   These macros are not named xfoo() because this name is commonly
   used for function which die on errror.  We use macronames like
   xtryfoo() instead. */

void *ksba_malloc(size_t n) { return alloc_func(n); }

void *ksba_calloc(size_t n, size_t m) {
  size_t nbytes;
  void *p;

  nbytes = n * m;
  if (m && nbytes / m != n) {
    gpg_err_set_errno(ENOMEM);
    p = NULL;
  } else
    p = ksba_malloc(nbytes);
  if (p) memset(p, 0, nbytes);
  return p;
}

void *ksba_realloc(void *mem, size_t n) { return realloc_func(mem, n); }

char *ksba_strdup(const char *str) {
  char *p = (char *)ksba_malloc(strlen(str) + 1);
  if (p) strcpy(p, str);
  return p;
}

void ksba_free(void *a) {
  if (a) free_func(a);
}

static void out_of_core(void) {
  fputs("\nfatal: out of memory\n", stderr);
  exit(2);
}

/* Implementations of the common xfoo() memory allocation functions */
void *_ksba_xmalloc(size_t n) {
  void *p = ksba_malloc(n);
  if (!p) out_of_core();
  return p;
}

void *_ksba_xcalloc(size_t n, size_t m) {
  void *p = ksba_calloc(n, m);
  if (!p) out_of_core();
  return p;
}

void *_ksba_xrealloc(void *mem, size_t n) {
  void *p = ksba_realloc(mem, n);
  if (!p) out_of_core();
  return p;
}

char *_ksba_xstrdup(const char *str) {
  char *p = ksba_strdup(str);
  if (!p) out_of_core();
  return p;
}

static inline int ascii_toupper(int c) {
  if (c >= 'a' && c <= 'z') c &= ~0x20;
  return c;
}

int _ksba_ascii_memcasecmp(const void *a_arg, const void *b_arg, size_t n) {
  const char *a = (const char *)a_arg;
  const char *b = (const char *)b_arg;

  if (a == b) return 0;
  for (; n; n--, a++, b++) {
    if (*a != *b && ascii_toupper(*a) != ascii_toupper(*b))
      return *a == *b ? 0 : (ascii_toupper(*a) - ascii_toupper(*b));
  }
  return 0;
}
