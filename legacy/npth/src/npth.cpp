/* npth.c - a lightweight implementation of pth over pthread.
 * Copyright (C) 2011 g10 Code GmbH
 *
 * This file is part of nPth.
 *
 * nPth is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * nPth is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>

static int
my_usleep(unsigned int usec)
{
  struct timespec req = { 0, ((long) usec) * 1000 };
  return nanosleep(&req, NULL);
}

#include <unistd.h>
#ifndef HAVE_PSELECT
# include <signal.h>
#endif

#include "npth.h"

/* The global lock that excludes all threads but one.  */
pthread_mutex_t scepter = PTHREAD_MUTEX_INITIALIZER;

/* Systems that don't have pthread_mutex_timedlock get a busy wait
   implementation that probes the lock every BUSY_WAIT_INTERVAL
   milliseconds.  */
#define BUSY_WAIT_INTERVAL 200

typedef int (*trylock_func_t) (void *);

static int
busy_wait_for (trylock_func_t trylock, void *lock,
	       const struct timespec *abstime)
{
  int err;

  /* This is not great, but better than nothing.  Only works for locks
     which are mostly uncontested.  Provides absolutely no fairness at
     all.  Creates many wake-ups.  */
  while (1)
    {
      struct timespec ts;
      err = npth_clock_gettime (&ts);
      if (err < 0)
	{
	  /* Just for safety make sure we return some error.  */
	  err = errno ? errno : EINVAL;
	  break;
	}

      if (npth_timercmp (abstime, &ts, <))
	{
	  err = ETIMEDOUT;
	  break;
	}

      err = (*trylock) (lock);
      if (err != EBUSY)
	break;

      /* Try again after waiting a bit.  We could calculate the
	 maximum wait time from ts and abstime, but we don't
	 bother, as our granularity is pretty fine.  */
      my_usleep (BUSY_WAIT_INTERVAL * 1000);
    }

  return err;
}


static void
enter_npth (void)
{
  int res;

  res = pthread_mutex_unlock (&scepter);
  assert (res == 0);
}


static void
leave_npth (void)
{
  int res;
  int save_errno = errno;

  do {
    res = pthread_mutex_lock(&scepter);
  } while (res < 0 && errno == EINTR);

  assert (!res);
  errno = save_errno;
}

#define ENTER() enter_npth ()
#define LEAVE() leave_npth ()


int
npth_init (void)
{
  int res;

  res = pthread_mutex_init(&scepter, NULL);
  if (res < 0)
    return errno;

  LEAVE();
  return 0;
}


int
npth_getname_np (npth_t target_thread, char *buf, size_t buflen)
{
#ifdef HAVE_PTHREAD_GETNAME_NP
  return pthread_getname_np (target_thread, buf, buflen);
#else
  (void)target_thread;
  (void)buf;
  (void)buflen;
  return ENOSYS;
#endif
}


int
npth_setname_np (npth_t target_thread, const char *name)
{
#ifdef HAVE_PTHREAD_SETNAME_NP
#ifdef __NetBSD__
  return pthread_setname_np (target_thread, "%s", (void*) name);
#else
#ifdef __APPLE__
  if (target_thread == npth_self ())
    return pthread_setname_np (name);
  else
    return ENOTSUP;
#else
  return pthread_setname_np (target_thread, name);
#endif
#endif
#else
  (void)target_thread;
  (void)name;
  return ENOSYS;
#endif
}



struct startup_s
{
  void *(*start_routine) (void *);
  void *arg;
};


static void *
thread_start (void *startup_arg)
{
  struct startup_s *startup = (startup_s*) startup_arg;
  void *(*start_routine) (void *);
  void *arg;
  void *result;

  start_routine = startup->start_routine;
  arg = startup->arg;
  free (startup);

  LEAVE();
  result = (*start_routine) (arg);
  /* Note: instead of returning here, we might end up in
     npth_exit() instead.  */
  ENTER();

  return result;
}


int
npth_create (npth_t *thread, const npth_attr_t *attr,
	     void *(*start_routine) (void *), void *arg)
{
  int err;
  struct startup_s *startup;

  startup = (startup_s*) malloc (sizeof (*startup));
  if (!startup)
    return errno;

  startup->start_routine = start_routine;
  startup->arg = arg;
  err = pthread_create (thread, attr, thread_start, startup);
  if (err)
    {
      free (startup);
      return err;
    }

  /* Memory is released in thread_start.  */
  return 0;
}


int
npth_join (npth_t thread, void **retval)
{
  int err;

#ifdef HAVE_PTHREAD_TRYJOIN_NP
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  pthread_tryjoin_np is a GNU extension.  */
  err = pthread_tryjoin_np (thread, retval);
  if (err != EBUSY)
    return err;
#endif /*HAVE_PTHREAD_TRYJOIN_NP*/

  ENTER();
  err = pthread_join (thread, retval);
  LEAVE();
  return err;
}


void
npth_exit (void *retval)
{
  ENTER();
  pthread_exit (retval);
  /* Never reached.  But just in case pthread_exit does return... */
  LEAVE();
}


int
npth_mutex_lock (npth_mutex_t *mutex)
{
  int err;

  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_mutex_trylock (mutex);
  if (err != EBUSY)
    return err;

  ENTER();
  err = pthread_mutex_lock (mutex);
  LEAVE();
  return err;
}


int
npth_mutex_timedlock (npth_mutex_t *mutex, const struct timespec *abstime)
{
  int err;

  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_mutex_trylock (mutex);
  if (err != EBUSY)
    return err;

  ENTER();
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
  err = pthread_mutex_timedlock (mutex, abstime);
#else
  err = busy_wait_for ((trylock_func_t) pthread_mutex_trylock, mutex, abstime);
#endif
  LEAVE();
  return err;
}


#ifndef _NPTH_NO_RWLOCK
int
npth_rwlock_rdlock (npth_rwlock_t *rwlock)
{
  int err;

#ifdef HAVE_PTHREAD_RWLOCK_TRYRDLOCK
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_rwlock_tryrdlock (rwlock);
  if (err != EBUSY)
    return err;
#endif

  ENTER();
  err = pthread_rwlock_rdlock (rwlock);
  LEAVE();
  return err;
}


int
npth_rwlock_timedrdlock (npth_rwlock_t *rwlock, const struct timespec *abstime)
{
  int err;

#ifdef HAVE_PTHREAD_RWLOCK_TRYRDLOCK
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_rwlock_tryrdlock (rwlock);
  if (err != EBUSY)
    return err;
#endif

  ENTER();
#if HAVE_PTHREAD_RWLOCK_TIMEDRDLOCK
  err = pthread_rwlock_timedrdlock (rwlock, abstime);
#else
  err = busy_wait_for ((trylock_func_t) pthread_rwlock_tryrdlock, rwlock,
		       abstime);
#endif
  LEAVE();
  return err;
}


int
npth_rwlock_wrlock (npth_rwlock_t *rwlock)
{
  int err;

#ifdef HAVE_PTHREAD_RWLOCK_TRYWRLOCK
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_rwlock_trywrlock (rwlock);
  if (err != EBUSY)
    return err;
#endif

  ENTER();
  err = pthread_rwlock_wrlock (rwlock);
  LEAVE();
  return err;
}


int
npth_rwlock_timedwrlock (npth_rwlock_t *rwlock, const struct timespec *abstime)
{
  int err;

#ifdef HAVE_PTHREAD_RWLOCK_TRYWRLOCK
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_rwlock_trywrlock (rwlock);
  if (err != EBUSY)
    return err;
#endif

  ENTER();
#if HAVE_PTHREAD_RWLOCK_TIMEDWRLOCK
  err = pthread_rwlock_timedwrlock (rwlock, abstime);
#elif HAVE_PTHREAD_RWLOCK_TRYRDLOCK
  err = busy_wait_for ((trylock_func_t) pthread_rwlock_trywrlock, rwlock,
		       abstime);
#else
  err = ENOSYS;
#endif
  LEAVE();
  return err;
}
#endif


int
npth_cond_wait (npth_cond_t *cond, npth_mutex_t *mutex)
{
  int err;

  ENTER();
  err = pthread_cond_wait (cond, mutex);
  LEAVE();
  return err;
}


int
npth_cond_timedwait (npth_cond_t *cond, npth_mutex_t *mutex,
		     const struct timespec *abstime)
{
  int err;

  ENTER();
  err = pthread_cond_timedwait (cond, mutex, abstime);
  LEAVE();
  return err;
}


/* Standard POSIX Replacement API */

int
npth_usleep(unsigned int usec)
{
  int res;

  ENTER();
  res = my_usleep(usec);
  LEAVE();
  return res;
}


unsigned int
npth_sleep(unsigned int sec)
{
  unsigned res;

  ENTER();
  res = sleep(sec);
  LEAVE();
  return res;
}


int
npth_system(const char *cmd)
{
  int res;

  ENTER();
  res = system(cmd);
  LEAVE();
  return res;
}


pid_t
npth_waitpid(pid_t pid, int *status, int options)
{
  pid_t res;

  ENTER();
  res = waitpid(pid,status, options);
  LEAVE();
  return res;
}


int
npth_connect(int s, const struct sockaddr *addr, socklen_t addrlen)
{
  int res;

  ENTER();
  res = connect(s, addr, addrlen);
  LEAVE();
  return res;
}


int
npth_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
  int res;

  ENTER();
  res = accept(s, addr, addrlen);
  LEAVE();
  return res;
}


int
npth_select(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
	    struct timeval *timeout)
{
  int res;

  ENTER();
  res = select(nfd, rfds, wfds, efds, timeout);
  LEAVE();
  return res;
}


int
npth_pselect(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
	     const struct timespec *timeout, const sigset_t *sigmask)
{
  int res;

  ENTER();
#ifdef HAVE_PSELECT
  res = pselect (nfd, rfds, wfds, efds, timeout, sigmask);
#else /*!HAVE_PSELECT*/
  {
    /* A better emulation of pselect would be to create a pipe, wait
       in the select for one end and have a signal handler write to
       the other end.  However, this is non-trivial to implement and
       thus we only print a compile time warning.  */
#   ifdef __GNUC__
#     warning Using a non race free pselect emulation.
#   endif

    struct timeval t, *tp;

    tp = NULL;
    if (!timeout)
      ;
    else if (timeout->tv_nsec >= 0 && timeout->tv_nsec < 1000000000)
      {
        t.tv_sec = timeout->tv_sec;
        t.tv_usec = (timeout->tv_nsec + 999) / 1000;
        tp = &t;
      }
    else
      {
        errno = EINVAL;
        res = -1;
        goto leave;
      }

    if (sigmask)
      {
        int save_errno;
        sigset_t savemask;

        pthread_sigmask (SIG_SETMASK, sigmask, &savemask);
        res = select (nfd, rfds, wfds, efds, tp);
        save_errno = errno;
        pthread_sigmask (SIG_SETMASK, &savemask, NULL);
        errno = save_errno;
      }
    else
      res = select (nfd, rfds, wfds, efds, tp);

  leave:
    ;
  }
#endif /*!HAVE_PSELECT*/
  LEAVE();
  return res;
}


ssize_t
npth_read(int fd, void *buf, size_t nbytes)
{
  ssize_t res;

  ENTER();
  res = read(fd, buf, nbytes);
  LEAVE();
  return res;
}


ssize_t
npth_write(int fd, const void *buf, size_t nbytes)
{
  ssize_t res;

  ENTER();
  res = write(fd, buf, nbytes);
  LEAVE();
  return res;
}


int
npth_recvmsg (int fd, struct msghdr *msg, int flags)
{
  int res;

  ENTER();
  res = recvmsg (fd, msg, flags);
  LEAVE();
  return res;
}


int
npth_sendmsg (int fd, const struct msghdr *msg, int flags)
{
  int res;

  ENTER();
  res = sendmsg (fd, msg, flags);
  LEAVE();
  return res;
}


void
npth_protect (void)
{
  LEAVE();
}

void
npth_unprotect (void)
{
  ENTER();
}


int
npth_clock_gettime (struct timespec *ts)
{
#if defined(CLOCK_REALTIME) && HAVE_CLOCK_GETTIME
  return clock_gettime (CLOCK_REALTIME, ts);
#elif HAVE_GETTIMEOFDAY
  {
    struct timeval tv;

    if (gettimeofday (&tv, NULL))
      return -1;
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;
    return 0;
  }
#else
  /* FIXME: fall back on time() with seconds resolution.  */
# error clock_gettime not available - please provide a fallback.
#endif
}
