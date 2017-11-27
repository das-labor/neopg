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

/* Internal tracing functions.  Except for TRACE_FP we use flockfile
 * and funlockfile to protect their use. */
static FILE *trace_fp;
static int trace_save_errno;
static int trace_with_errno;
static const char *trace_arg_module;
static const char *trace_arg_file;
static int trace_arg_line;
static int trace_missing_lf;
static int trace_prefix_done;

void _gpgrt_internal_trace_begin(const char *module, const char *file, int line,
                                 int with_errno) {
  int save_errno = errno;

  if (!trace_fp) {
    FILE *fp;
    const char *s = getenv("GPGRT_TRACE_FILE");

    if (!s || !(fp = fopen(s, "wb"))) fp = stderr;
    trace_fp = fp;
  }

  flockfile(trace_fp);
  trace_save_errno = save_errno;
  trace_with_errno = with_errno;
  trace_arg_module = module;
  trace_arg_file = file;
  trace_arg_line = line;
  trace_missing_lf = 0;
  trace_prefix_done = 0;
}

static void print_internal_trace_prefix(void) {
  if (!trace_prefix_done) {
    trace_prefix_done = 1;
    fprintf(trace_fp,
            "%s:%s:%d: ", trace_arg_module, /* npth_is_protected ()?"":"^",*/
            trace_arg_file, trace_arg_line);
  }
}

static void do_internal_trace(const char *format, va_list arg_ptr) {
  print_internal_trace_prefix();
  vfprintf(trace_fp, format, arg_ptr);
  if (trace_with_errno)
    fprintf(trace_fp, " errno=%s", strerror(trace_save_errno));
  if (*format && format[strlen(format) - 1] != '\n') fputc('\n', trace_fp);
}

void _gpgrt_internal_trace_printf(const char *format, ...) {
  va_list arg_ptr;

  print_internal_trace_prefix();
  va_start(arg_ptr, format);
  vfprintf(trace_fp, format, arg_ptr);
  va_end(arg_ptr);
  trace_missing_lf = (*format && format[strlen(format) - 1] != '\n');
}

void _gpgrt_internal_trace(const char *format, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, format);
  do_internal_trace(format, arg_ptr);
  va_end(arg_ptr);
}

void _gpgrt_internal_trace_end(void) {
  int save_errno = trace_save_errno;

  if (trace_missing_lf) fputc('\n', trace_fp);
  funlockfile(trace_fp);
  errno = save_errno;
}
