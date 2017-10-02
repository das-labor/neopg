/* system-posix.c - System support functions.
   Copyright (C) 2009, 2010 Free Software Foundation, Inc.

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

#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
/* Solaris 8 needs sys/types.h before time.h.  */
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#ifdef HAVE_GETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif /*HAVE_GETRLIMIT*/
#if __linux__
# include <dirent.h>
#endif /*__linux__ */


#include "assuan-defs.h"
#include "debug.h"




assuan_fd_t
assuan_fdopen (int fd)
{
  return dup (fd);
}



/* Sleep for the given number of microseconds.  Default
   implementation.  */
void
__assuan_usleep (assuan_context_t ctx, unsigned int usec)
{
  if (! usec)
    return;

#ifdef HAVE_NANOSLEEP
  {
    struct timespec req;
    struct timespec rem;

    req.tv_sec = 0;
    req.tv_nsec = usec * 1000;

    while (nanosleep (&req, &rem) < 0 && errno == EINTR)
      req = rem;
  }
#else
  {
    struct timeval tv;

    tv.tv_sec  = usec / 1000000;
    tv.tv_usec = usec % 1000000;
    select (0, NULL, NULL, NULL, &tv);
  }
#endif
}



/* Create a pipe with one inheritable end.  Easy for Posix.  */
int
__assuan_pipe (assuan_context_t ctx, assuan_fd_t fd[2], int inherit_idx)
{
  return pipe (fd);
}



/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  Easy for Posix.  */
int
__assuan_close (assuan_context_t ctx, assuan_fd_t fd)
{
  return close (fd);
}



ssize_t
__assuan_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
  return read (fd, buffer, size);
}



ssize_t
__assuan_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer,
		size_t size)
{
  return write (fd, buffer, size);
}



int
__assuan_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
  int ret;

  do
    ret = recvmsg (fd, msg, flags);
  while (ret == -1 && errno == EINTR);

  return ret;
}



int
__assuan_sendmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
		  int flags)
{
  int ret;

  do
    ret = sendmsg (fd, msg, flags);
  while (ret == -1 && errno == EINTR);

  return ret;
}



static int
writen (int fd, const char *buffer, size_t length)
{
  while (length)
    {
      int nwritten = write (fd, buffer, length);

      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          return -1; /* write error */
        }
      length -= nwritten;
      buffer += nwritten;
    }
  return 0;  /* okay */
}


/* Return the maximum number of currently allowed open file
 * descriptors.  */
static int
get_max_fds (void)
{
  int max_fds = -1;

#ifdef HAVE_GETRLIMIT
  struct rlimit rl;

  /* Under Linux we can figure out the highest used file descriptor by
   * reading /proc/PID/fd.  This is in the common cases much faster
   * than for example doing 4096 close calls where almost all of them
   * will fail.  We use the same code in GnuPG and measured this: On a
   * system with a limit of 4096 files and only 8 files open with the
   * highest number being 10, we speedup close_all_fds from 125ms to
   * 0.4ms including the readdir.
   *
   * Another option would be to close the file descriptors as returned
   * from reading that directory - however then we need to snapshot
   * that list before starting to close them.  */
#ifdef __linux__
  {
    DIR *dir = NULL;
    struct dirent *dir_entry;
    const char *s;
    int x;

    dir = opendir ("/proc/self/fd");
    if (dir)
      {
        while ((dir_entry = readdir (dir)))
          {
            s = dir_entry->d_name;
            if ( *s < '0' || *s > '9')
              continue;
            x = atoi (s);
            if (x > max_fds)
              max_fds = x;
          }
        closedir (dir);
      }
    if (max_fds != -1)
      return max_fds + 1;
    }
#endif /* __linux__ */

# ifdef RLIMIT_NOFILE
  if (!getrlimit (RLIMIT_NOFILE, &rl))
    max_fds = rl.rlim_max;
# endif

# ifdef RLIMIT_OFILE
  if (max_fds == -1 && !getrlimit (RLIMIT_OFILE, &rl))
    max_fds = rl.rlim_max;

# endif
#endif /*HAVE_GETRLIMIT*/

#ifdef _SC_OPEN_MAX
  if (max_fds == -1)
    {
      long int scres = sysconf (_SC_OPEN_MAX);
      if (scres >= 0)
        max_fds = scres;
    }
#endif

#ifdef _POSIX_OPEN_MAX
  if (max_fds == -1)
    max_fds = _POSIX_OPEN_MAX;
#endif

#ifdef OPEN_MAX
  if (max_fds == -1)
    max_fds = OPEN_MAX;
#endif

  if (max_fds == -1)
    max_fds = 256;  /* Arbitrary limit.  */

  /* AIX returns INT32_MAX instead of a proper value.  We assume that
     this is always an error and use a more reasonable limit.  */
#ifdef INT32_MAX
  if (max_fds == INT32_MAX)
    max_fds = 256;
#endif

  return max_fds;
}


int
__assuan_spawn (assuan_context_t ctx, pid_t *r_pid, const char *name,
		const char **argv,
		assuan_fd_t fd_in, assuan_fd_t fd_out,
		assuan_fd_t *fd_child_list,
		void (*atfork) (void *opaque, int reserved),
		void *atforkvalue, unsigned int flags)
{
  int pid;

  pid = fork ();
  if (pid < 0)
    return -1;

  if (pid == 0)
    {
      /* Child process (server side).  */
      int i;
      int n;
      char errbuf[512];
      int *fdp;
      int fdnul;

      if (atfork)
	atfork (atforkvalue, 0);

      fdnul = open ("/dev/null", O_WRONLY);
      if (fdnul == -1)
	{
	  TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		  "can't open `/dev/null': %s", strerror (errno));
	  _exit (4);
	}

      /* Dup handles to stdin/stdout. */
      if (fd_out != STDOUT_FILENO)
	{
	  if (dup2 (fd_out == ASSUAN_INVALID_FD ? fdnul : fd_out,
		    STDOUT_FILENO) == -1)
	    {
	      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		      "dup2 failed in child: %s", strerror (errno));
	      _exit (4);
	    }
	}

      if (fd_in != STDIN_FILENO)
	{
	  if (dup2 (fd_in == ASSUAN_INVALID_FD ? fdnul : fd_in,
		    STDIN_FILENO) == -1)
	    {
	      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "__assuan_spawn", ctx,
		      "dup2 failed in child: %s", strerror (errno));
	      _exit (4);
	    }
	}

      /* Dup stderr to /dev/null unless it is in the list of FDs to be
	 passed to the child. */
      fdp = fd_child_list;
      if (fdp)
	{
	  for (; *fdp != -1 && *fdp != STDERR_FILENO; fdp++)
	    ;
	}
      if (!fdp || *fdp == -1)
	{
	  if (dup2 (fdnul, STDERR_FILENO) == -1)
	    {
	      TRACE1 (ctx, ASSUAN_LOG_SYSIO, "pipe_connect_unix", ctx,
		      "dup2(dev/null, 2) failed: %s", strerror (errno));
	      _exit (4);
	    }
	}
      close (fdnul);

      /* Close all files which will not be duped and are not in the
	 fd_child_list. */
      n = get_max_fds ();
      for (i = 0; i < n; i++)
	{
	  if (i == STDIN_FILENO || i == STDOUT_FILENO || i == STDERR_FILENO)
	    continue;
	  fdp = fd_child_list;
	  if (fdp)
	    {
	      while (*fdp != -1 && *fdp != i)
		fdp++;
	    }

	  if (!(fdp && *fdp != -1))
	    close (i);
	}
      gpg_err_set_errno (0);

      if (! name)
	{
	  /* No name and no args given, thus we don't do an exec
	     but continue the forked process.  */
	  *argv = "server";

	  /* FIXME: Cleanup.  */
	  return 0;
	}

      execv (name, (char *const *) argv);

      /* oops - use the pipe to tell the parent about it */
      snprintf (errbuf, sizeof(errbuf)-1,
		"ERR %d can't exec `%s': %.50s\n",
		_assuan_error (ctx, GPG_ERR_ASS_SERVER_START),
		name, strerror (errno));
      errbuf[sizeof(errbuf)-1] = 0;
      writen (1, errbuf, strlen (errbuf));
      _exit (4);
    }

  if (! name)
    *argv = "client";

  *r_pid = pid;

  return 0;
}



/* FIXME: Add some sort of waitpid function that covers GPGME and
   gpg-agent's use of assuan.  */
pid_t
__assuan_waitpid (assuan_context_t ctx, pid_t pid, int nowait,
		  int *status, int options)
{
  /* We can't just release the PID, a waitpid is mandatory.  But
     NOWAIT in POSIX systems just means the caller already did the
     waitpid for this child.  */
  if (! nowait)
    return waitpid (pid, NULL, 0);
  return 0;
}



int
__assuan_socketpair (assuan_context_t ctx, int namespace, int style,
		     int protocol, assuan_fd_t filedes[2])
{
  return socketpair (namespace, style, protocol, filedes);
}


int
__assuan_socket (assuan_context_t ctx, int namespace, int style, int protocol)
{
  return socket (namespace, style, protocol);
}


int
__assuan_connect (assuan_context_t ctx, int sock, struct sockaddr *addr,
		  socklen_t length)
{
  return connect (sock, addr, length);
}



/* The default system hooks for assuan contexts.  */
struct assuan_system_hooks _assuan_system_hooks =
  {
    ASSUAN_SYSTEM_HOOKS_VERSION,
    __assuan_usleep,
    __assuan_pipe,
    __assuan_close,
    __assuan_read,
    __assuan_write,
    __assuan_recvmsg,
    __assuan_sendmsg,
    __assuan_spawn,
    __assuan_waitpid,
    __assuan_socketpair,
    __assuan_socket,
    __assuan_connect
  };
