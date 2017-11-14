/* npth.h - a lightweight implementation of pth over native threads
 * Copyright (C) 2011, 2015 g10 Code GmbH
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

#ifndef _NPTH_H
#define _NPTH_H

#include <sys/types.h>
#include <time.h>
#include <errno.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* (Keep Emacsens' auto-indent happy.) */
}
#endif
#endif

struct msghdr;

/* The mingw-w64 headers define timespec.  For older compilers we keep
   our replacement.  */
#ifndef __MINGW64_VERSION_MAJOR
struct timespec {
  long tv_sec;                 /* seconds */
  long tv_nsec;                /* nanoseconds */
};
#endif /*__MINGW64_VERSION_MAJOR */


#ifndef ETIMEDOUT
#define ETIMEDOUT 10060  /* This is WSAETIMEDOUT.  */
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 10045 /* This is WSAEOPNOTSUPP.  */
#endif


int npth_init (void);

typedef struct npth_attr_s *npth_attr_t;
typedef unsigned long int npth_t;
typedef struct npth_mutexattr_s *npth_mutexattr_t;
typedef struct npth_mutex_s *npth_mutex_t;
typedef struct npth_rwlockattr_s *npth_rwlockattr_t;
typedef struct npth_rwlock_s *npth_rwlock_t;

int npth_attr_init (npth_attr_t *attr);
int npth_attr_destroy (npth_attr_t *attr);
#define NPTH_CREATE_JOINABLE 0
#define NPTH_CREATE_DETACHED 1
int npth_attr_getdetachstate(npth_attr_t *attr, int *detachstate);
int npth_attr_setdetachstate(npth_attr_t *attr, int detachstate);

int npth_create (npth_t *newthread, const npth_attr_t *attr,
		 void *(*start_routine) (void *), void *arg);

npth_t npth_self (void);

int npth_join (npth_t th, void **thread_return);
int npth_detach (npth_t th);
void npth_exit (void *retval);

typedef DWORD npth_key_t;
int npth_key_create (npth_key_t *key,
		     void (*destr_function) (void *));
int npth_key_delete (npth_key_t key);
void *npth_getspecific (npth_key_t key);
int npth_setspecific (npth_key_t key, const void *pointer);

int npth_mutexattr_init (npth_mutexattr_t *attr);
int npth_mutexattr_destroy (npth_mutexattr_t *attr);
int npth_mutexattr_gettype (const npth_mutexattr_t *attr,
			    int *kind);
int npth_mutexattr_settype (npth_mutexattr_t *attr, int kind);
#define NPTH_MUTEX_NORMAL 0
#define NPTH_MUTEX_RECURSIVE 1
#define NPTH_MUTEX_ERRORCHECK 2
#define NPTH_MUTEX_DEFAULT NPTH_MUTEX_NORMAL

#define NPTH_MUTEX_INITIALIZER ((npth_mutex_t) -1)
#define NPTH_RECURSIVE_MUTEX_INITIALIZER_NP ((npth_mutex_t) -2)
#define NPTH_ERRORCHECK_MUTEX_INITIALIZER_NP ((npth_mutex_t) -3)
int npth_mutex_init (npth_mutex_t *mutex, const npth_mutexattr_t *mutexattr);
int npth_mutex_destroy (npth_mutex_t *mutex);
int npth_mutex_trylock(npth_mutex_t *mutex);
int npth_mutex_lock(npth_mutex_t *mutex);
int npth_mutex_unlock(npth_mutex_t *mutex);

int npth_rwlockattr_init (npth_rwlockattr_t *attr);
int npth_rwlockattr_destroy (npth_rwlockattr_t *attr);
int npth_rwlockattr_gettype_np (const npth_rwlockattr_t *attr,
				int *kind);
int npth_rwlockattr_settype_np (npth_rwlockattr_t *attr, int kind);
#define NPTH_RWLOCK_PREFER_READER_NP 0
#define NPTH_RWLOCK_PREFER_WRITER_NP 1
#define NPTH_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP 2
#define NPTH_RWLOCK_DEFAULT_NP NPTH_RWLOCK_PREFER_READER_NP
#define NPTH_RWLOCK_INITIALIZER ((npth_rwlock_t) -1)
#define NPTH_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP ((npth_rwlock_t) -2)

/* For now, we don't support any rwlock attributes.  */
int npth_rwlock_init (npth_rwlock_t *rwlock,
		      const npth_rwlockattr_t *attr);
int npth_rwlock_destroy (npth_rwlock_t *rwlock);
int npth_rwlock_rdlock (npth_rwlock_t *rwlock);

int npth_rwlock_wrlock (npth_rwlock_t *rwlock);
int npth_rwlock_unlock (npth_rwlock_t *rwlock);

int npth_usleep(unsigned int usec);
unsigned int npth_sleep(unsigned int sec);

pid_t npth_waitpid(pid_t pid, int *status, int options);
int npth_system(const char *cmd);

int npth_connect(int s, const struct sockaddr *addr, socklen_t addrlen);
int npth_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
/* Only good for sockets!  */
int npth_select(int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
		struct timeval *timeout);

ssize_t npth_read(int fd, void *buf, size_t nbytes);
ssize_t npth_write(int fd, const void *buf, size_t nbytes);
int npth_recvmsg (int fd, struct msghdr *msg, int flags);
int npth_sendmsg (int fd, const struct msghdr *msg, int flags);

void npth_unprotect (void);
void npth_protect (void);

/* Return true when we hold the sceptre.  This is used to debug
 * problems with npth_unprotect and npth_protect.  */
int npth_is_protected (void);

#if 0 /* (Keep Emacsens' auto-indent happy.) */
{
#endif
#ifdef __cplusplus
}
#endif
#endif /*_NPTH_H*/
