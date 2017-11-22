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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int my_usleep(unsigned int usec) {
  struct timespec req = {0, ((long)usec) * 1000};
  return nanosleep(&req, NULL);
}

#include <unistd.h>
#ifndef HAVE_PSELECT
#include <signal.h>
#endif

#include "npth.h"

/* The global lock that excludes all threads but one.  */
pthread_mutex_t scepter = PTHREAD_MUTEX_INITIALIZER;

static void enter_npth(void) {
  int res;

  res = pthread_mutex_unlock(&scepter);
  assert(res == 0);
}

static void leave_npth(void) {
  int res;
  int save_errno = errno;

  do {
    res = pthread_mutex_lock(&scepter);
  } while (res < 0 && errno == EINTR);

  assert(!res);
  errno = save_errno;
}

#define ENTER() enter_npth()
#define LEAVE() leave_npth()

int npth_init(void) {
  int res;

  res = pthread_mutex_init(&scepter, NULL);
  if (res < 0) return errno;

  LEAVE();
  return 0;
}

struct startup_s {
  void *(*start_routine)(void *);
  void *arg;
};

static void *thread_start(void *startup_arg) {
  struct startup_s *startup = (startup_s *)startup_arg;
  void *(*start_routine)(void *);
  void *arg;
  void *result;

  start_routine = startup->start_routine;
  arg = startup->arg;
  free(startup);

  LEAVE();
  result = (*start_routine)(arg);
  /* Note: instead of returning here, we might end up in
     npth_exit() instead.  */
  ENTER();

  return result;
}

int npth_create(npth_t *thread, const npth_attr_t *attr,
                void *(*start_routine)(void *), void *arg) {
  int err;
  struct startup_s *startup;

  startup = (startup_s *)malloc(sizeof(*startup));
  if (!startup) return errno;

  startup->start_routine = start_routine;
  startup->arg = arg;
  err = pthread_create(thread, attr, thread_start, startup);
  if (err) {
    free(startup);
    return err;
  }

  /* Memory is released in thread_start.  */
  return 0;
}

int npth_join(npth_t thread, void **retval) {
  int err;

#ifdef HAVE_PTHREAD_TRYJOIN_NP
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  pthread_tryjoin_np is a GNU extension.  */
  err = pthread_tryjoin_np(thread, retval);
  if (err != EBUSY) return err;
#endif /*HAVE_PTHREAD_TRYJOIN_NP*/

  ENTER();
  err = pthread_join(thread, retval);
  LEAVE();
  return err;
}

void npth_exit(void *retval) {
  ENTER();
  pthread_exit(retval);
  /* Never reached.  But just in case pthread_exit does return... */
  LEAVE();
}

int npth_mutex_lock(npth_mutex_t *mutex) {
  int err;

  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_mutex_trylock(mutex);
  if (err != EBUSY) return err;

  ENTER();
  err = pthread_mutex_lock(mutex);
  LEAVE();
  return err;
}

#ifndef _NPTH_NO_RWLOCK
int npth_rwlock_rdlock(npth_rwlock_t *rwlock) {
  int err;

#ifdef HAVE_PTHREAD_RWLOCK_TRYRDLOCK
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_rwlock_tryrdlock(rwlock);
  if (err != EBUSY) return err;
#endif

  ENTER();
  err = pthread_rwlock_rdlock(rwlock);
  LEAVE();
  return err;
}

int npth_rwlock_wrlock(npth_rwlock_t *rwlock) {
  int err;

#ifdef HAVE_PTHREAD_RWLOCK_TRYWRLOCK
  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = pthread_rwlock_trywrlock(rwlock);
  if (err != EBUSY) return err;
#endif

  ENTER();
  err = pthread_rwlock_wrlock(rwlock);
  LEAVE();
  return err;
}

#endif

/* Standard POSIX Replacement API */

int npth_usleep(unsigned int usec) {
  int res;

  ENTER();
  res = my_usleep(usec);
  LEAVE();
  return res;
}

unsigned int npth_sleep(unsigned int sec) {
  unsigned res;

  ENTER();
  res = sleep(sec);
  LEAVE();
  return res;
}

int npth_system(const char *cmd) {
  int res;

  ENTER();
  res = system(cmd);
  LEAVE();
  return res;
}

pid_t npth_waitpid(pid_t pid, int *status, int options) {
  pid_t res;

  ENTER();
  res = waitpid(pid, status, options);
  LEAVE();
  return res;
}

int npth_connect(int s, const struct sockaddr *addr, socklen_t addrlen) {
  int res;

  ENTER();
  res = connect(s, addr, addrlen);
  LEAVE();
  return res;
}

int npth_accept(int s, struct sockaddr *addr, socklen_t *addrlen) {
  int res;

  ENTER();
  res = accept(s, addr, addrlen);
  LEAVE();
  return res;
}

int npth_select(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
                struct timeval *timeout) {
  int res;

  ENTER();
  res = select(nfd, rfds, wfds, efds, timeout);
  LEAVE();
  return res;
}

int npth_pselect(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
                 const struct timespec *timeout, const sigset_t *sigmask) {
  int res;

  ENTER();
#ifdef HAVE_PSELECT
  res = pselect(nfd, rfds, wfds, efds, timeout, sigmask);
#else /*!HAVE_PSELECT*/
  {
/* A better emulation of pselect would be to create a pipe, wait
   in the select for one end and have a signal handler write to
   the other end.  However, this is non-trivial to implement and
   thus we only print a compile time warning.  */
#ifdef __GNUC__
#warning Using a non race free pselect emulation.
#endif

    struct timeval t, *tp;

    tp = NULL;
    if (!timeout)
      ;
    else if (timeout->tv_nsec >= 0 && timeout->tv_nsec < 1000000000) {
      t.tv_sec = timeout->tv_sec;
      t.tv_usec = (timeout->tv_nsec + 999) / 1000;
      tp = &t;
    } else {
      errno = EINVAL;
      res = -1;
      goto leave;
    }

    if (sigmask) {
      int save_errno;
      sigset_t savemask;

      pthread_sigmask(SIG_SETMASK, sigmask, &savemask);
      res = select(nfd, rfds, wfds, efds, tp);
      save_errno = errno;
      pthread_sigmask(SIG_SETMASK, &savemask, NULL);
      errno = save_errno;
    } else
      res = select(nfd, rfds, wfds, efds, tp);

  leave:;
  }
#endif /*!HAVE_PSELECT*/
  LEAVE();
  return res;
}

ssize_t npth_read(int fd, void *buf, size_t nbytes) {
  ssize_t res;

  ENTER();
  res = read(fd, buf, nbytes);
  LEAVE();
  return res;
}

ssize_t npth_write(int fd, const void *buf, size_t nbytes) {
  ssize_t res;

  ENTER();
  res = write(fd, buf, nbytes);
  LEAVE();
  return res;
}

int npth_recvmsg(int fd, struct msghdr *msg, int flags) {
  int res;

  ENTER();
  res = recvmsg(fd, msg, flags);
  LEAVE();
  return res;
}

int npth_sendmsg(int fd, const struct msghdr *msg, int flags) {
  int res;

  ENTER();
  res = sendmsg(fd, msg, flags);
  LEAVE();
  return res;
}

void npth_protect(void) { LEAVE(); }

void npth_unprotect(void) { ENTER(); }
