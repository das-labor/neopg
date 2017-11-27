/* logging.c - Useful logging functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006,
 *               2009, 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#ifdef HAVE_W32_SYSTEM
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif /*!HAVE_W32_SYSTEM*/
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
/* #include <execinfo.h> */

#define GNUPG_COMMON_NEED_AFLOCAL 1
#include "common-defs.h"
#include "logging.h"
#include "sysutils.h"
#include "util.h"

#ifdef HAVE_W32_SYSTEM
#ifndef S_IRWXG
#define S_IRGRP S_IRUSR
#define S_IWGRP S_IWUSR
#endif
#ifndef S_IRWXO
#define S_IROTH S_IRUSR
#define S_IWOTH S_IWUSR
#endif
#endif

#undef WITH_IPV6
#if defined(AF_INET6) && defined(PF_INET) && defined(INET6_ADDRSTRLEN) && \
    defined(HAVE_INET_PTON)
#define WITH_IPV6 1
#endif

#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT EINVAL
#endif
#ifndef INADDR_NONE /* Slowaris is missing that.  */
#define INADDR_NONE ((unsigned long)(-1))
#endif /*INADDR_NONE*/

#ifdef HAVE_W32_SYSTEM
#define sock_close(a) closesocket(a)
#else
#define sock_close(a) close(a)
#endif

static estream_t logstream;
static int log_socket = -1;
static char prefix_buffer[80];
static int with_time;
static int with_prefix;
static int with_pid;
#ifdef HAVE_W32_SYSTEM
static int no_registry;
#endif
static int (*get_pid_suffix_cb)(unsigned long *r_value);
static const char *(*socket_dir_cb)(void);
static int running_detached;
static int force_prefixes;

static int missing_lf;
static int errorcount;

int log_get_errorcount(int clear) {
  int n = errorcount;
  if (clear) errorcount = 0;
  return n;
}

void log_inc_errorcount(void) { errorcount++; }

/* The following 3 functions are used by es_fopencookie to write logs
   to a socket.  */
struct fun_cookie_s {
  int fd;
  int quiet;
  char name[1];
};

/* Write NBYTES of BUFFER to file descriptor FD. */
static int writen(int fd, const void *buffer, size_t nbytes) {
  const char *buf = (const char *)buffer;
  size_t nleft = nbytes;
  int nwritten;

  while (nleft > 0) {
    nwritten = write(fd, buf, nleft);
    if (nwritten < 0 && errno == EINTR) continue;
    if (nwritten < 0) return -1;
    nleft -= nwritten;
    buf = buf + nwritten;
  }

  return 0;
}

/* Returns true if STR represents a valid port number in decimal
   notation and no garbage is following.  */
static int parse_portno(const char *str, unsigned short *r_port) {
  unsigned int value;

  for (value = 0; *str && (*str >= '0' && *str <= '9'); str++) {
    value = value * 10 + (*str - '0');
    if (value > 65535) return 0;
  }
  if (*str || !value) return 0;

  *r_port = value;
  return 1;
}

static gpgrt_ssize_t fun_writer(void *cookie_arg, const void *buffer,
                                size_t size) {
  struct fun_cookie_s *cookie = (fun_cookie_s *)cookie_arg;

  log_socket = cookie->fd;
  if (cookie->fd != -1) {
    if (!writen(cookie->fd, buffer, size))
      return (gpgrt_ssize_t)size; /* Okay. */
  }

  if (!running_detached && cookie->fd != -1 && isatty(es_fileno(es_stderr))) {
    if (*cookie->name)
      es_fprintf(es_stderr, "error writing to '%s': %s\n", cookie->name,
                 strerror(errno));
    else
      es_fprintf(es_stderr, "error writing to file descriptor %d: %s\n",
                 cookie->fd, strerror(errno));
  }
  return (gpgrt_ssize_t)size;
}

static int fun_closer(void *cookie_arg) {
  struct fun_cookie_s *cookie = (fun_cookie_s *)cookie_arg;

  if (cookie->fd != -1 && cookie->fd != 2) sock_close(cookie->fd);
  xfree(cookie);
  log_socket = -1;
  return 0;
}

/* Common function to either set the logging to a file or a file
   descriptor. */
static void set_file_fd(const char *name, int fd) {
  estream_t fp;
  struct fun_cookie_s *cookie;

  /* Close an open log stream.  */
  if (logstream) {
    es_fclose(logstream);
    logstream = NULL;
  }

  /* Figure out what kind of logging we want.  */
  if (name && !strcmp(name, "-")) {
    name = NULL;
    fd = es_fileno(es_stderr);
  }

  /* Setup a new stream.  */

  /* The xmalloc below is justified because we can expect that this
     function is called only during initialization and there is no
     easy way out of this error condition.  */
  cookie = (fun_cookie_s *)xmalloc(sizeof *cookie + (name ? strlen(name) : 0));
  strcpy(cookie->name, name ? name : "");
  cookie->quiet = 0;
  if (!name)
    cookie->fd = fd;
  else {
    do
      cookie->fd =
          open(name, O_WRONLY | O_APPEND | O_CREAT,
               (S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH));
    while (cookie->fd == -1 && errno == EINTR);
  }
  log_socket = cookie->fd;

  {
    es_cookie_io_functions_t io = {NULL};
    io.func_write = fun_writer;
    io.func_close = fun_closer;

    fp = es_fopencookie(cookie, "w", io);
  }

  /* On error default to a stderr based estream.  */
  if (!fp) fp = es_stderr;

  es_setvbuf(fp, NULL, _IOLBF, 0);

  logstream = fp;

  missing_lf = 0;
}

/* Set the file to write log to.  The special names NULL and "-" may
   be used to select stderr and names formatted like
   "socket:///home/foo/mylogs" may be used to write the logging to the
   socket "/home/foo/mylogs".  If the connection to the socket fails
   or a write error is detected, the function writes to stderr and
   tries the next time again to connect the socket.
  */
void log_set_file(const char *name) { set_file_fd(name ? name : "-", -1); }

void log_set_fd(int fd) {
  if (!gnupg_fd_valid(fd))
    log_fatal("logger-fd is invalid: %s\n", strerror(errno));

  set_file_fd(NULL, fd);
}

/* Set a function to retrieve the directory name of a socket if
 * only "socket://" has been given to log_set_file.  */
void log_set_socket_dir_cb(const char *(*fnc)(void)) { socket_dir_cb = fnc; }

void log_set_pid_suffix_cb(int (*cb)(unsigned long *r_value)) {
  get_pid_suffix_cb = cb;
}

void log_set_prefix(const char *text, unsigned int flags) {
  if (text) {
    strncpy(prefix_buffer, text, sizeof(prefix_buffer) - 1);
    prefix_buffer[sizeof(prefix_buffer) - 1] = 0;
  }

  with_prefix = (flags & GPGRT_LOG_WITH_PREFIX);
  with_time = (flags & GPGRT_LOG_WITH_TIME);
  with_pid = (flags & GPGRT_LOG_WITH_PID);
  running_detached = (flags & GPGRT_LOG_RUN_DETACHED);
#ifdef HAVE_W32_SYSTEM
  no_registry = (flags & GPGRT_LOG_NO_REGISTRY);
#endif
}

const char *log_get_prefix(unsigned int *flags) {
  if (flags) {
    *flags = 0;
    if (with_prefix) *flags |= GPGRT_LOG_WITH_PREFIX;
    if (with_time) *flags |= GPGRT_LOG_WITH_TIME;
    if (with_pid) *flags |= GPGRT_LOG_WITH_PID;
    if (running_detached) *flags |= GPGRT_LOG_RUN_DETACHED;
#ifdef HAVE_W32_SYSTEM
    if (no_registry) *flags |= GPGRT_LOG_NO_REGISTRY;
#endif
  }
  return prefix_buffer;
}

/* This function returns true if the file descriptor FD is in use for
   logging.  This is preferable over a test using log_get_fd in that
   it allows the logging code to use more then one file descriptor.  */
int log_test_fd(int fd) {
  if (logstream) {
    int tmp = es_fileno(logstream);
    if (tmp != -1 && tmp == fd) return 1;
  }
  if (log_socket != -1 && log_socket == fd) return 1;
  return 0;
}

int log_get_fd() { return logstream ? es_fileno(logstream) : -1; }

estream_t log_get_stream() {
  if (!logstream) {
    log_set_file(NULL); /* Make sure a log stream has been set.  */
    assert(logstream);
  }
  return logstream;
}

static void print_prefix(int level, int leading_backspace) {
  if (level != GPGRT_LOG_CONT) { /* Note this does not work for multiple line
                                  * logging as we would
                                  * need to print to a buffer first */
    if (with_time && !force_prefixes) {
      struct tm *tp;
      time_t atime = time(NULL);

      tp = localtime(&atime);
      es_fprintf_unlocked(logstream, "%04d-%02d-%02d %02d:%02d:%02d ",
                          1900 + tp->tm_year, tp->tm_mon + 1, tp->tm_mday,
                          tp->tm_hour, tp->tm_min, tp->tm_sec);
    }
    if (with_prefix || force_prefixes)
      es_fputs_unlocked(prefix_buffer, logstream);
    if (with_pid || force_prefixes) {
      unsigned long pidsuf;
      int pidfmt;

      if (get_pid_suffix_cb && (pidfmt = get_pid_suffix_cb(&pidsuf)))
        es_fprintf_unlocked(logstream, pidfmt == 1 ? "[%u.%lu]" : "[%u.%lx]",
                            (unsigned int)getpid(), pidsuf);
      else
        es_fprintf_unlocked(logstream, "[%u]", (unsigned int)getpid());
    }
    if ((!with_time && (with_prefix || with_pid)) || force_prefixes)
      es_putc_unlocked(':', logstream);
    /* A leading backspace suppresses the extra space so that we can
       correctly output, programname, filename and linenumber. */
    if (!leading_backspace &&
        (with_time || with_prefix || with_pid || force_prefixes))
      es_putc_unlocked(' ', logstream);
  }

  switch (level) {
    case GPGRT_LOG_BEGIN:
      break;
    case GPGRT_LOG_CONT:
      break;
    case GPGRT_LOG_INFO:
      break;
    case GPGRT_LOG_WARN:
      break;
    case GPGRT_LOG_ERROR:
      break;
    case GPGRT_LOG_FATAL:
      es_fputs_unlocked("Fatal: ", logstream);
      break;
    case GPGRT_LOG_BUG:
      es_fputs_unlocked("Ohhhh jeeee: ", logstream);
      break;
    case GPGRT_LOG_DEBUG:
      es_fputs_unlocked("DBG: ", logstream);
      break;
    default:
      es_fprintf_unlocked(logstream, "[Unknown log level %d]: ", level);
      break;
  }
}

static void do_logv(int level, int ignore_arg_ptr, const char *extrastring,
                    const char *prefmt, const char *fmt, va_list arg_ptr) {
  int leading_backspace = (fmt && *fmt == '\b');

  if (!logstream) {
#ifdef HAVE_W32_SYSTEM
    char *tmp;

    tmp =
        (no_registry ? NULL : read_w32_registry_string(NULL, GNUPG_REGISTRY_DIR,
                                                       "DefaultLogFile"));
    log_set_file(tmp && *tmp ? tmp : NULL);
    xfree(tmp);
#else
    log_set_file(NULL); /* Make sure a log stream has been set.  */
#endif
    assert(logstream);
  }

  es_flockfile(logstream);
  if (missing_lf && level != GPGRT_LOG_CONT) es_putc_unlocked('\n', logstream);
  missing_lf = 0;

  print_prefix(level, leading_backspace);
  if (leading_backspace) fmt++;

  if (fmt) {
    if (prefmt) es_fputs_unlocked(prefmt, logstream);

    if (ignore_arg_ptr) { /* This is used by log_string and comes with the extra
                           * feature that after a LF the next line is indent at
                           * the
                           * length of the prefix.  Note that we do not yet
                           * include
                           * the length of the timestamp and pid in the indent
                           * computation.  */
      const char *p, *pend;

      for (p = fmt; (pend = strchr(p, '\n')); p = pend + 1)
        es_fprintf_unlocked(logstream, "%*s%.*s",
                            (int)((p != fmt && (with_prefix || force_prefixes))
                                      ? strlen(prefix_buffer) + 2
                                      : 0),
                            "", (int)(pend - p) + 1, p);
      es_fputs_unlocked(p, logstream);
    } else
      es_vfprintf_unlocked(logstream, fmt, arg_ptr);
    if (*fmt && fmt[strlen(fmt) - 1] != '\n') missing_lf = 1;
  }

  /* If we have an EXTRASTRING print it now while we still hold the
   * lock on the logstream.  */
  if (extrastring) {
    int c;

    if (missing_lf) {
      es_putc_unlocked('\n', logstream);
      missing_lf = 0;
    }
    print_prefix(level, leading_backspace);
    es_fputs_unlocked(">> ", logstream);
    missing_lf = 1;
    while ((c = *extrastring++)) {
      missing_lf = 1;
      if (c == '\\')
        es_fputs_unlocked("\\\\", logstream);
      else if (c == '\r')
        es_fputs_unlocked("\\r", logstream);
      else if (c == '\n') {
        es_fputs_unlocked("\\n\n", logstream);
        if (*extrastring) {
          print_prefix(level, leading_backspace);
          es_fputs_unlocked(">> ", logstream);
        } else
          missing_lf = 0;
      } else
        es_putc_unlocked(c, logstream);
    }
    if (missing_lf) {
      es_putc_unlocked('\n', logstream);
      missing_lf = 0;
    }
  }

  if (level == GPGRT_LOG_FATAL) {
    if (missing_lf) es_putc_unlocked('\n', logstream);
    es_funlockfile(logstream);
    exit(2);
  } else if (level == GPGRT_LOG_BUG) {
    if (missing_lf) es_putc_unlocked('\n', logstream);
    es_funlockfile(logstream);
    /* Using backtrace requires a configure test and to pass
     * -rdynamic to gcc.  Thus we do not enable it now.  */
    /* { */
    /*   void *btbuf[20]; */
    /*   int btidx, btlen; */
    /*   char **btstr; */

    /*   btlen = backtrace (btbuf, DIM (btbuf)); */
    /*   btstr = backtrace_symbols (btbuf, btlen); */
    /*   if (btstr) */
    /*     for (btidx=0; btidx < btlen; btidx++) */
    /*       log_debug ("[%d] %s\n", btidx, btstr[btidx]); */
    /* } */
    abort();
  } else
    es_funlockfile(logstream);
}

void log_log(int level, const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(level, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
}

void log_logv(int level, const char *fmt, va_list arg_ptr) {
  do_logv(level, 0, NULL, NULL, fmt, arg_ptr);
}

/* Same as log_logv but PREFIX is printed immediately before FMT.
 * Note that PREFIX is an additional string and independent of the
 * prefix set by log_set_prefix.  */
void log_logv_with_prefix(int level, const char *prefix, const char *fmt,
                          va_list arg_ptr) {
  do_logv(level, 0, NULL, prefix, fmt, arg_ptr);
}

static void do_log_ignore_arg(int level, const char *str, ...) {
  va_list arg_ptr;
  va_start(arg_ptr, str);
  do_logv(level, 1, NULL, NULL, str, arg_ptr);
  va_end(arg_ptr);
}

/* Log STRING at LEVEL but indent from the second line on by the
 * length of the prefix.  */
void log_string(int level, const char *string) {
  /* We need a dummy arg_ptr, but there is no portable way to create
   * one.  So we call the do_logv function through a variadic wrapper. */
  do_log_ignore_arg(level, string);
}

void log_info(const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(GPGRT_LOG_INFO, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
}

void log_error(const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(GPGRT_LOG_ERROR, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
  /* Protect against counter overflow.  */
  if (errorcount < 30000) errorcount++;
}

void log_fatal(const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(GPGRT_LOG_FATAL, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
  abort(); /* Never called; just to make the compiler happy.  */
}

void log_bug(const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(GPGRT_LOG_BUG, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
  abort(); /* Never called; just to make the compiler happy.  */
}

void log_debug(const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(GPGRT_LOG_DEBUG, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
}

/* The same as log_debug but at the end of the output STRING is
 * printed with LFs expanded to include the prefix and a final --end--
 * marker.  */
void log_debug_with_string(const char *string, const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(GPGRT_LOG_DEBUG, 0, string, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
}

void log_printf(const char *fmt, ...) {
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  do_logv(fmt ? GPGRT_LOG_CONT : GPGRT_LOG_BEGIN, 0, NULL, NULL, fmt, arg_ptr);
  va_end(arg_ptr);
}

/* Flush the log - this is useful to make sure that the trailing
   linefeed has been printed.  */
void log_flush(void) { do_log_ignore_arg(GPGRT_LOG_CONT, NULL); }

/* Print a hexdump of BUFFER.  With TEXT of NULL print just the raw
   dump, with TEXT just an empty string, print a trailing linefeed,
   otherwise print an entire debug line. */
void log_printhex(const char *text, const void *buffer, size_t length) {
  if (text && *text) log_debug("%s ", text);
  if (length) {
    const unsigned char *p = (const unsigned char *)buffer;
    log_printf("%02X", *p);
    for (length--, p++; length--; p++) log_printf(" %02X", *p);
  }
  if (text) log_printf("\n");
}

/*
void
log_printcanon () {}
is found in sexputils.c
*/

/*
void
log_printsexp () {}
is found in sexputils.c
*/

void log_clock(const char *string) {
#if 0
  static unsigned long long initial;
  struct timespec tv;
  unsigned long long now;

  if (clock_gettime (CLOCK_REALTIME, &tv))
    {
      log_debug ("error getting the realtime clock value\n");
      return;
    }
  now = tv.tv_sec * 1000000000ull;
  now += tv.tv_nsec;

  if (!initial)
    initial = now;

  log_debug ("[%6llu] %s", (now - initial)/1000, string);
#else
  /* You need to link with -ltr to enable the above code.  */
  log_debug("[not enabled in the source] %s", string);
#endif
}

#ifdef GPGRT_HAVE_MACRO_FUNCTION
void bug_at(const char *file, int line, const char *func) {
  log_log(GPGRT_LOG_BUG, "... this is a bug (%s:%d:%s)\n", file, line, func);
  abort(); /* Never called; just to make the compiler happy.  */
}
#else  /*!GPGRT_HAVE_MACRO_FUNCTION*/
void bug_at(const char *file, int line) {
  log_log(GPGRT_LOG_BUG, "you found a bug ... (%s:%d)\n", file, line);
  abort(); /* Never called; just to make the compiler happy.  */
}
#endif /*!GPGRT_HAVE_MACRO_FUNCTION*/

#ifdef GPGRT_HAVE_MACRO_FUNCTION
void _log_assert(const char *expr, const char *file, int line,
                 const char *func) {
  log_log(GPGRT_LOG_BUG, "Assertion \"%s\" in %s failed (%s:%d)\n", expr, func,
          file, line);
  abort(); /* Never called; just to make the compiler happy.  */
}
#else  /*!GPGRT_HAVE_MACRO_FUNCTION*/
void _log_assert(const char *expr, const char *file, int line) {
  log_log(GPGRT_LOG_BUG, "Assertion \"%s\" failed (%s:%d)\n", expr, file, line);
  abort(); /* Never called; just to make the compiler happy.  */
}
#endif /*!GPGRT_HAVE_MACRO_FUNCTION*/
