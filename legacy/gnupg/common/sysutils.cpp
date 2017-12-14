/* sysutils.c -  system helpers
 * Copyright (C) 1991-2001, 2003-2004,
 *               2006-2008  Free Software Foundation, Inc.
 * Copyright (C) 2013-2016 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
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
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#include <asm/sysinfo.h>
#include <asm/unistd.h>
#endif
#include <time.h>
#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
#include <sys/time.h>
#endif
#ifdef HAVE_W32_SYSTEM
#if WINVER < 0x0500
#define WINVER 0x0500 /* Required for AllowSetForegroundWindow.  */
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <fcntl.h>

#include <assuan.h>

#include "util.h"

#include "sysutils.h"

int disable_core_dumps(void) {
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
#ifdef HAVE_SETRLIMIT
  struct rlimit limit;

  /* We only set the current limit unless we were not able to
     retrieve the old value. */
  if (getrlimit(RLIMIT_CORE, &limit)) limit.rlim_max = 0;
  limit.rlim_cur = 0;
  if (!setrlimit(RLIMIT_CORE, &limit)) return 0;
  if (errno != EINVAL && errno != ENOSYS)
    log_fatal(_("can't disable core dumps: %s\n"), strerror(errno));
#endif
  return 1;
#endif
}

int enable_core_dumps(void) {
#ifdef HAVE_DOSISH_SYSTEM
  return 0;
#else
#ifdef HAVE_SETRLIMIT
  struct rlimit limit;

  if (getrlimit(RLIMIT_CORE, &limit)) return 1;
  limit.rlim_cur = limit.rlim_max;
  setrlimit(RLIMIT_CORE, &limit);
  return 1; /* We always return true because this function is
               merely a debugging aid. */
#endif
  return 1;
#endif
}

/* Return a string which is used as a kind of process ID.  */
const byte *get_session_marker(size_t *rlen) {
  static byte marker[SIZEOF_UNSIGNED_LONG * 2];
  static int initialized;

  if (!initialized) {
    gcry_create_nonce(marker, sizeof marker);
    initialized = 1;
  }
  *rlen = sizeof(marker);
  return marker;
}

/* Wrapper around the usual sleep function.  This one won't wake up
   before the sleep time has really elapsed.  When build with Pth it
   merely calls pth_sleep and thus suspends only the current
   thread. */
void gnupg_sleep(unsigned int seconds) {
/* Fixme:  make sure that a sleep won't wake up to early.  */
#ifdef HAVE_W32_SYSTEM
  Sleep(seconds * 1000);
#else
  sleep(seconds);
#endif
}

/* This function is a NOP for POSIX systems but required under Windows
   as the file handles as returned by OS calls (like CreateFile) are
   different from the libc file descriptors (like open). This function
   translates system file handles to libc file handles.  FOR_WRITE
   gives the direction of the handle.  */
int translate_sys2libc_fd(gnupg_fd_t fd, int for_write) {
#if defined(HAVE_W32_SYSTEM)
  int x;

  if (fd == GNUPG_INVALID_FD) return -1;

  /* Note that _open_osfhandle is currently defined to take and return
     a long.  */
  x = _open_osfhandle((long)fd, for_write ? 1 : 0);
  if (x == -1) log_error("failed to translate osfhandle %p\n", (void *)fd);
  return x;
#else /*!HAVE_W32_SYSTEM */
  (void)for_write;
  return fd;
#endif
}

/* This is the same as translate_sys2libc_fd but takes an integer
   which is assumed to be such an system handle.  On WindowsCE the
   passed FD is a rendezvous ID and the function finishes the pipe
   creation. */
int translate_sys2libc_fd_int(int fd, int for_write) {
#if HAVE_W32_SYSTEM
  if (fd <= 2) return fd; /* Do not do this for error, stdin, stdout, stderr. */

  return translate_sys2libc_fd((void *)fd, for_write);
#else
  (void)for_write;
  return fd;
#endif
}

/* Make sure that the standard file descriptors are opened. Obviously
   some folks close them before an exec and the next file we open will
   get one of them assigned and thus any output (i.e. diagnostics) end
   up in that file (e.g. the trustdb).  Not actually a gpg problem as
   this will happen with almost all utilities when called in a wrong
   way.  However we try to minimize the damage here and raise
   awareness of the problem.

   Must be called before we open any files! */
void gnupg_reopen_std(const char *pgmname) {
#if defined(HAVE_STAT) && !defined(HAVE_W32_SYSTEM)
  struct stat statbuf;
  int did_stdin = 0;
  int did_stdout = 0;
  int did_stderr = 0;
  FILE *complain;

  if (fstat(STDIN_FILENO, &statbuf) == -1 && errno == EBADF) {
    if (open("/dev/null", O_RDONLY) == STDIN_FILENO)
      did_stdin = 1;
    else
      did_stdin = 2;
  }

  if (fstat(STDOUT_FILENO, &statbuf) == -1 && errno == EBADF) {
    if (open("/dev/null", O_WRONLY) == STDOUT_FILENO)
      did_stdout = 1;
    else
      did_stdout = 2;
  }

  if (fstat(STDERR_FILENO, &statbuf) == -1 && errno == EBADF) {
    if (open("/dev/null", O_WRONLY) == STDERR_FILENO)
      did_stderr = 1;
    else
      did_stderr = 2;
  }

  /* It's hard to log this sort of thing since the filehandle we would
     complain to may be closed... */
  if (!did_stderr)
    complain = stderr;
  else if (!did_stdout)
    complain = stdout;
  else
    complain = NULL;

  if (complain) {
    if (did_stdin == 1)
      fprintf(complain, "%s: WARNING: standard input reopened\n", pgmname);
    if (did_stdout == 1)
      fprintf(complain, "%s: WARNING: standard output reopened\n", pgmname);
    if (did_stderr == 1)
      fprintf(complain, "%s: WARNING: standard error reopened\n", pgmname);

    if (did_stdin == 2 || did_stdout == 2 || did_stderr == 2)
      fprintf(complain,
              "%s: fatal: unable to reopen standard input,"
              " output, or error\n",
              pgmname);
  }

  if (did_stdin == 2 || did_stdout == 2 || did_stderr == 2) exit(3);
#else /* !(HAVE_STAT && !HAVE_W32_SYSTEM) */
  (void)pgmname;
#endif
}

/* Hack required for Windows.  */
void gnupg_allow_set_foregound_window(pid_t pid) {
  if (!pid)
    log_info("%s called with invalid pid %lu\n",
             "gnupg_allow_set_foregound_window", (unsigned long)pid);
#if defined(HAVE_W32_SYSTEM)
  else if (!AllowSetForegroundWindow((pid_t)pid == (pid_t)(-1) ? ASFW_ANY
                                                               : pid))
    log_info("AllowSetForegroundWindow(%lu) failed: %s\n", (unsigned long)pid,
             w32_strerror(-1));
#endif
}

int gnupg_remove(const char *fname) { return remove(fname); }

/* Wrapper for rename(2) to handle Windows peculiarities.  */
gpg_error_t gnupg_rename_file(const char *oldname, const char *newname) {
  gpg_error_t err = 0;

#ifdef HAVE_DOSISH_SYSTEM
  {
    int wtime = 0;

    gnupg_remove(newname);
  again:
    if (rename(oldname, newname)) {
      if (GetLastError() == ERROR_SHARING_VIOLATION) {
        /* Another process has the file open.  We do not use a
         * lock for read but instead we wait until the other
         * process has closed the file.  This may take long but
         * that would also be the case with a dotlock approach for
         * read and write.  Note that we don't need this on Unix
         * due to the inode concept.
         *
         * So let's wait until the rename has worked.  The retry
         * intervals are 50, 100, 200, 400, 800, 50ms, ...  */
        if (!wtime || wtime >= 800)
          wtime = 50;
        else
          wtime *= 2;

        if (wtime >= 800)
          log_info(_("waiting for file '%s' to become accessible ...\n"),
                   oldname);

        Sleep(wtime);
        goto again;
      }
      err = gpg_error_from_syserror();
    }
  }
#else  /* Unix */
  {
    if (rename(oldname, newname)) err = gpg_error_from_syserror();
  }
#endif /* Unix */

  if (err)
    log_error(_("renaming '%s' to '%s' failed: %s\n"), oldname, newname,
              gpg_strerror(err));
  return err;
}

#ifndef HAVE_W32_SYSTEM
static mode_t modestr_to_mode(const char *modestr) {
  mode_t mode = 0;

  if (modestr && *modestr) {
    modestr++;
    if (*modestr && *modestr++ == 'r') mode |= S_IRUSR;
    if (*modestr && *modestr++ == 'w') mode |= S_IWUSR;
    if (*modestr && *modestr++ == 'x') mode |= S_IXUSR;
    if (*modestr && *modestr++ == 'r') mode |= S_IRGRP;
    if (*modestr && *modestr++ == 'w') mode |= S_IWGRP;
    if (*modestr && *modestr++ == 'x') mode |= S_IXGRP;
    if (*modestr && *modestr++ == 'r') mode |= S_IROTH;
    if (*modestr && *modestr++ == 'w') mode |= S_IWOTH;
    if (*modestr && *modestr++ == 'x') mode |= S_IXOTH;
  }

  return mode;
}
#endif

/* A wrapper around mkdir which takes a string for the mode argument.
   This makes it easier to handle the mode argument which is not
   defined on all systems.  The format of the modestring is

      "-rwxrwxrwx"

   '-' is a don't care or not set.  'r', 'w', 'x' are read allowed,
   write allowed, execution allowed with the first group for the user,
   the second for the group and the third for all others.  If the
   string is shorter than above the missing mode characters are meant
   to be not set.  */
int gnupg_mkdir(const char *name, const char *modestr) {
#if MKDIR_TAKES_ONE_ARG
  (void)modestr;
  /* Note: In the case of W32 we better use CreateDirectory and try to
     set appropriate permissions.  However using mkdir is easier
     because this sets ERRNO.  */
  return mkdir(name);
#else
  return mkdir(name, modestr_to_mode(modestr));
#endif
}

/* A wrapper around chmod which takes a string for the mode argument.
   This makes it easier to handle the mode argument which is not
   defined on all systems.  The format of the modestring is the same
   as for gnupg_mkdir.  */
int gnupg_chmod(const char *name, const char *modestr) {
#ifdef HAVE_W32_SYSTEM
  (void)name;
  (void)modestr;
  return 0;
#else
  return chmod(name, modestr_to_mode(modestr));
#endif
}

int gnupg_setenv(const char *name, const char *value, int overwrite) {
#ifdef HAVE_W32_SYSTEM
  /*  Windows maintains (at least) two sets of environment variables.
      One set can be accessed by GetEnvironmentVariable and
      SetEnvironmentVariable.  This set is inherited by the children.
      The other set is maintained in the C runtime, and is accessed
      using getenv and putenv.  We try to keep them in sync by
      modifying both sets.  */
  {
    int exists;
    char tmpbuf[10];
    exists = GetEnvironmentVariable(name, tmpbuf, sizeof tmpbuf);

    if ((!exists || overwrite) && !SetEnvironmentVariable(name, value)) {
      gpg_err_set_errno(EINVAL); /* (Might also be ENOMEM.) */
      return -1;
    }
  }
#endif /*W32*/

  return setenv(name, value, overwrite);
}

/* Return the current working directory as a malloced string.  Return
   NULL and sets ERRNo on error.  */
char *gnupg_getcwd(void) {
  char *buffer;
  size_t size = 100;

  for (;;) {
    buffer = (char *)xtrymalloc(size + 1);
    if (!buffer) return NULL;
    if (getcwd(buffer, size) == buffer) return buffer;
    xfree(buffer);
    if (errno != ERANGE) return NULL;
    size *= 2;
  }
}

/* Check whether FD is valid.  */
int gnupg_fd_valid(int fd) {
  int d = dup(fd);
  if (d < 0) return 0;
  close(d);
  return 1;
}
