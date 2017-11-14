/* npth.h - a lightweight implementation of pth over pthread.
 * Copyright (C) 2011, 2012, 2015, 2017 g10 Code GmbH
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

/* Changes to GNU Pth:
 *
 * Return value and arguments follow strictly the pthread format:
 *
 * - Return the error number instead of setting errno,
 *
 * - No _new functions.  Use _init functions instead.
 *
 * - Attributes are set by specific instead of generic getter/setter
 *   functions.
 *
 * - Offers replacement functions for sendmsg and recvmsg.
 */

#ifndef _NPTH_H
#define _NPTH_H

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <signal.h>
#define _npth_socklen_t socklen_t
#include <pthread.h>

#ifdef __ANDROID__
#include <android/api-level.h>
#if __ANDROID_API__ < 9
/* Android 8 and earlier are missing rwlocks.  We punt to mutexes in
   that case.  */
#define _NPTH_NO_RWLOCK 1
#endif
#endif

#ifdef __cplusplus
extern "C" {
#if 0 /* (Keep Emacsens' auto-indent happy.) */
}
#endif
#endif



/* Global Library Management */

#define npth_t pthread_t

/* Initialize the library and convert current thread to main thread.
   Must be first npth function called in a process.  Returns error
   number on error and 0 on success.  */

int npth_init(void);


/* Thread Attribute Handling */

#define npth_attr_t pthread_attr_t
#define npth_attr_init pthread_attr_init
#define npth_attr_destroy pthread_attr_destroy
#define NPTH_CREATE_JOINABLE PTHREAD_CREATE_JOINABLE
#define NPTH_CREATE_DETACHED PTHREAD_CREATE_DETACHED
#define npth_attr_getdetachstate pthread_attr_getdetachstate
#define npth_attr_setdetachstate pthread_attr_setdetachstate


/* Thread Control */
int npth_create(npth_t *thread, const npth_attr_t *attr,
		void *(*start_routine) (void *), void *arg);

#define npth_self pthread_self

int npth_join(npth_t thread, void **retval);
#define npth_detach pthread_detach

void npth_exit(void *retval);


/* Key-Based Storage */

#define npth_key_t pthread_key_t
#define npth_key_create pthread_key_create
#define npth_key_delete pthread_key_delete
#define npth_setspecific pthread_setspecific
#define npth_getspecific pthread_getspecific


/* Process Forking */

/* POSIX only supports a global atfork handler.  So, to implement
   per-thread handlers like in Pth, we would need to keep the data in
   thread local storage.  But, neither pthread_self nor
   pthread_getspecific are standardized as async-signal-safe (what a
   joke!), and __thread is an ELF extension.  Still, using
   pthread_self and pthread_getspecific is probably portable
   enough to implement the atfork handlers, if required.

   pth_fork is only required because fork() is not pth aware.  fork()
   is pthread aware though, and already only creates a single thread
   in the child process.  */
/* pth_atfork_push, pth_atfork_pop, pth_fork */


/* Synchronization */

#define npth_mutexattr_t pthread_mutexattr_t
#define npth_mutexattr_init pthread_mutexattr_init
#define npth_mutexattr_destroy pthread_mutexattr_destroy
#define npth_mutexattr_settype pthread_mutexattr_settype
#define npth_mutexattr_gettype pthread_mutexattr_gettype
#define NPTH_MUTEX_NORMAL PTHREAD_MUTEX_NORMAL
#define NPTH_MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE
#define NPTH_MUTEX_ERRORCHECK PTHREAD_MUTEX_ERRORCHECK
#define NPTH_MUTEX_DEFAULT PTHREAD_MUTEX_DEFAULT

#define npth_mutex_t pthread_mutex_t
#define NPTH_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define NPTH_RECURSIVE_MUTEX_INITIALIZER_NP \
  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#define NPTH_ERRORCHECK_MUTEX_INITIALIZER_NP \
  PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define npth_mutex_init pthread_mutex_init
#define npth_mutex_destroy pthread_mutex_destroy
#define npth_mutex_trylock pthread_mutex_trylock

int npth_mutex_lock(npth_mutex_t *mutex);

#define npth_mutex_unlock pthread_mutex_unlock

#ifdef _NPTH_NO_RWLOCK

typedef int npth_rwlockattr_t;
#define npth_rwlockattr_init(attr)
#define npth_rwlockattr_destroy(attr)
#define npth_rwlockattr_gettype_np(attr,kind)
#define npth_rwlockattr_settype_np(attr,kind)
#define NPTH_RWLOCK_PREFER_READER_NP 0
#define NPTH_RWLOCK_PREFER_WRITER_NP 0
#define NPTH_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP 0
#define NPTH_RWLOCK_DEFAULT_NP 0
#define NPTH_RWLOCK_INITIALIZER NPTH_MUTEX_INITIALIZER
#define NPTH_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP NPTH_MUTEX_INITIALIZER
typedef npth_mutex_t npth_rwlock_t;
#define npth_rwlock_init(rwlock,attr) npth_mutex_init(rwlock,0)
#define npth_rwlock_destroy npth_mutex_destroy
#define npth_rwlock_rdlock npth_mutex_lock
#define npth_rwlock_wrlock npth_mutex_lock
#define npth_rwlock_rdlock npth_mutex_lock
#define npth_rwlock_unlock npth_mutex_unlock

#else /* _NPTH_NO_RWLOCK */

#define npth_rwlockattr_t pthread_rwlockattr_t
#define npth_rwlockattr_init pthread_rwlockattr_init
#define npth_rwlockattr_destroy pthread_rwlockattr_destroy
#define npth_rwlockattr_gettype_np pthread_rwlockattr_gettype_np
#define npth_rwlockattr_settype_np pthread_rwlockattr_settype_np
#define NPTH_RWLOCK_PREFER_READER_NP PTHREAD_RWLOCK_PREFER_READER_NP
/* Note: The prefer-writer setting is ineffective and the same as
   prefer-reader.  This is because reader locks are specified to be
   recursive, but for efficiency reasons we do not keep track of which
   threads already hold a reader lock.  For this reason, we can not
   prefer some reader locks over others, and thus a recursive reader
   lock could be stalled by a pending writer, leading to a dead
   lock.  */
#define NPTH_RWLOCK_PREFER_WRITER_NP PTHREAD_RWLOCK_PREFER_WRITER_NP
/* The non-recursive choise is a promise by the application that it
   does not lock the rwlock for reading recursively.  In this setting,
   writers are preferred, but note that recursive reader locking is
   prone to deadlocks in that case.  */
#define NPTH_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP \
  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
#define NPTH_RWLOCK_DEFAULT_NP PTHREAD_RWLOCK_DEFAULT_NP
#define NPTH_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER
#define NPTH_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP \
  PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP

typedef pthread_rwlock_t npth_rwlock_t;
#define npth_rwlock_init pthread_rwlock_init
#define npth_rwlock_destroy pthread_rwlock_destroy

int npth_rwlock_rdlock (npth_rwlock_t *rwlock);
int npth_rwlock_wrlock (npth_rwlock_t *rwlock);
#define npth_rwlock_unlock  pthread_rwlock_unlock

#endif /* !_NPTH_NO_RWLOCK */


/* Standard POSIX Replacement API */

int npth_usleep(unsigned int usec);
unsigned int npth_sleep(unsigned int sec);

pid_t npth_waitpid(pid_t pid, int *status, int options);
int npth_system(const char *cmd);
#define npth_sigmask pthread_sigmask
int npth_sigwait(const sigset_t *set, int *sig);

int npth_connect(int s, const struct sockaddr *addr, _npth_socklen_t addrlen);
int npth_accept(int s, struct sockaddr *addr, _npth_socklen_t *addrlen);
int npth_select(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
		struct timeval *timeout);
int npth_pselect(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
		 const struct timespec *timeout, const sigset_t *sigmask);
ssize_t npth_read(int fd, void *buf, size_t nbytes);
ssize_t npth_write(int fd, const void *buf, size_t nbytes);
int npth_recvmsg (int fd, struct msghdr *msg, int flags);
int npth_sendmsg (int fd, const struct msghdr *msg, int flags);

/* For anything not covered here, you can enter/leave manually at your
   own risk.  */
void npth_unprotect (void);
void npth_protect (void);

/* If you run into problems with the above calls, this function can be
 * used to examine in which state nPth is.  */
int npth_is_protected (void);

#if 0 /* (Keep Emacsens' auto-indent happy.) */
{
#endif
#ifdef __cplusplus
}
#endif
#endif /*_NPTH_H*/
