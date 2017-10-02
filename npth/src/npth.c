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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_LIB_DISPATCH
# include <dispatch/dispatch.h>
typedef dispatch_semaphore_t sem_t;

/* This glue code is for macOS which does not have full implementation
   of POSIX semaphore.  On macOS, using semaphore in Grand Central
   Dispatch library is better than using the partial implementation of
   POSIX semaphore where sem_init doesn't work well.
 */

static int
sem_init (sem_t *sem, int is_shared, unsigned int value)
{
  (void)is_shared;
  if ((*sem = dispatch_semaphore_create (value)) == NULL)
    return -1;
  else
    return 0;
}

static int
sem_post (sem_t *sem)
{
  dispatch_semaphore_signal (*sem);
  return 0;
}

static int
sem_wait (sem_t *sem)
{
  dispatch_semaphore_wait (*sem, DISPATCH_TIME_FOREVER);
  return 0;
}
#else
# include <semaphore.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifndef HAVE_PSELECT
# include <signal.h>
#endif

#include "npth.h"


/* The global lock that excludes all threads but one.  This is a
   semaphore, because these can be safely used in a library even if
   the application or other libraries call fork(), including from a
   signal handler.  sem_post is async-signal-safe.  (The reason a
   semaphore is safe and a mutex is not safe is that a mutex has an
   owner, while a semaphore does not.)  We init sceptre to a static
   buffer for use by sem_init; in case sem_open is used instead
   SCEPTRE will changed to the value returned by sem_open.
   GOT_SCEPTRE is a flag used for debugging to tell wether we hold
   SCEPTRE.  */
static sem_t sceptre_buffer;
static sem_t *sceptre = &sceptre_buffer;
static int got_sceptre;

/* Configure defines HAVE_FORK_UNSAFE_SEMAPHORE if child process can't
   access non-shared unnamed semaphore which is created by its parent.

   We use unnamed semaphore (if available) for the global lock.  The
   specific semaphore is only valid for those threads in a process,
   and it is no use by other processes.  Thus, PSHARED argument for
   sem_init is naturally 0.

   However, there are daemon-like applications which use fork after
   npth's initialization by npth_init.  In this case, a child process
   uses the semaphore which was created by its parent process, while
   parent does nothing with the semaphore.  In some system (e.g. AIX),
   access by child process to non-shared unnamed semaphore is
   prohibited.  For such a system, HAVE_FORK_UNSAFE_SEMAPHORE should
   be defined, so that unnamed semaphore will be created with the
   option PSHARED=1.  The purpose of the setting of PSHARED=1 is only
   for allowing the access of the lock by child process.  For NPTH, it
   does not mean any other interactions between processes.

 */
#ifdef HAVE_FORK_UNSAFE_SEMAPHORE
#define NPTH_SEMAPHORE_PSHARED 1
#else
#define NPTH_SEMAPHORE_PSHARED 0
#endif

/* The main thread is the active thread at the time pth_init was
   called.  As of now it is only useful for debugging.  The volatile
   make sure the compiler does not eliminate this set but not used
   variable.  */
static volatile pthread_t main_thread;

/* This flag is set as soon as npth_init has been called or if any
 * thread has been created.  It will never be cleared again.  The only
 * purpose is to make npth_protect and npth_unprotect more robust in
 * that they can be shortcut when npth_init has not yet been called.
 * This is important for libraries which want to support nPth by using
 * those two functions but may have be initialized before pPth. */
static int initialized_or_any_threads;

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
      usleep (BUSY_WAIT_INTERVAL * 1000);
    }

  return err;
}


static void
enter_npth (void)
{
  int res;

  got_sceptre = 0;
  res = sem_post (sceptre);
  assert (res == 0);
}


static void
leave_npth (void)
{
  int res;
  int save_errno = errno;

  do {
    res = sem_wait (sceptre);
  } while (res < 0 && errno == EINTR);

  assert (!res);
  got_sceptre = 1;
  errno = save_errno;
}

#define ENTER() enter_npth ()
#define LEAVE() leave_npth ()


int
npth_init (void)
{
  int res;

  main_thread = pthread_self();

  /* Track that we have been initialized.  */
  initialized_or_any_threads |= 1;

  /* Better reset ERRNO so that we know that it has been set by
     sem_init.  */
  errno = 0;

  /* The semaphore is binary.  */
  res = sem_init (sceptre, NPTH_SEMAPHORE_PSHARED, 1);
  /* There are some versions of operating systems which have sem_init
     symbol defined but the call actually returns ENOSYS at runtime.
     We know this problem for older versions of AIX (<= 4.3.3) and
     macOS.  For macOS, we use semaphore in Grand Central Dispatch
     library, so ENOSYS doesn't happen.  We only support AIX >= 5.2,
     where sem_init is supported.
   */
  if (res < 0)
    {
      /* POSIX.1-2001 defines the semaphore interface but does not
         specify the return value for success.  Thus we better
         bail out on error only on a POSIX.1-2008 system.  */
#if _POSIX_C_SOURCE >= 200809L
      return errno;
#endif
    }

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
  struct startup_s *startup = startup_arg;
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

  startup = malloc (sizeof (*startup));
  if (!startup)
    return errno;

  initialized_or_any_threads |= 2;

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
  res = usleep(usec);
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
npth_unprotect (void)
{
  /* If we are not initialized we may not access the semaphore and
   * thus we shortcut it. Note that in this case the unprotect/protect
   * is not needed.  For failsafe reasons if an nPth thread has ever
   * been created but nPth has accidentally not initialized we do not
   * shortcut so that a stack backtrace (due to the access of the
   * uninitialized semaphore) is more expressive.  */
  if (initialized_or_any_threads)
    ENTER();
}


void
npth_protect (void)
{
  /* See npth_unprotect for commentary.  */
  if (initialized_or_any_threads)
    LEAVE();
}


int
npth_is_protected (void)
{
  return got_sceptre;
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
