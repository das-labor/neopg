/* npth.c - a lightweight implementation of pth over native threads
 * Copyright (C) 2011, 2014 g10 Code GmbH
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

/* We implement the join mechanism ourself.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <io.h>

#include "npth.h"

#include <stdio.h>
#define DEBUG_CALLS 1
#define _npth_debug(x, ...) fprintf(stderr, __VA_ARGS__)

#ifndef TEST
#undef  DEBUG_CALLS
#define DEBUG_CALLS 0
#undef _npth_debug
#define _npth_debug(x, ...)
#endif

/* This seems to be a common standard.  */
#define THREAD_NAME_MAX 15

/* The global lock that excludes all threads but one.  Note that this
   implements the single-user-thread policy, but also protects all our
   global data such as the thread_table.  GOT_SCEPTRE is a flag used
   for debugging to tell wether we hold SCEPTRE.  */
static CRITICAL_SECTION sceptre;
static int got_sceptre;


/* This flag is set as soon as npth_init has been called or if any
 * thread has been created.  It will never be cleared again.  The only
 * purpose is to make npth_protect and npth_unprotect more robust in
 * that they can be shortcut when npth_init has not yet been called.
 * This is important for libraries which want to support nPth by using
 * those two functions but may have been initialized before nPth. */
static int initialized_or_any_threads;


typedef struct npth_impl_s *npth_impl_t;
#define MAX_THREADS 1024
#define INVALID_THREAD_ID 0
/* Thread ID to thread context table.  We never allocate ID 0.  */
static npth_impl_t thread_table[MAX_THREADS];

/* The TLS index to store thread ID of the current thread.  Used to
   make faster lookups of the thread data.  */
DWORD tls_index;



/* Map a windows error value (GetLastError) to a POSIX error value.  */
static int
map_error (int winerr)
{
  /* FIXME */
  return EIO;
}


static int
wait_for_single_object (HANDLE obj, DWORD msecs)
{
  DWORD res;

  res = WaitForSingleObject(obj, msecs);

  if (res == WAIT_ABANDONED)
    return EDEADLK;
  else if (res == WAIT_TIMEOUT)
    return ETIMEDOUT;
  else if (res == WAIT_FAILED)
    return map_error (GetLastError());
  else if (res != WAIT_OBJECT_0)
    return EINTR;
  else
    return 0;
}


static void
enter_npth (const char *function)
{
  int res;

  if (DEBUG_CALLS)
    _npth_debug (DEBUG_CALLS, "tid %lu: enter_npth (%s)\n",
		 npth_self (), function ? function : "unknown");
  got_sceptre = 0;
  LeaveCriticalSection (&sceptre);
}


static void
leave_npth (const char *function)
{
  EnterCriticalSection (&sceptre);
  got_sceptre = 1;

  if (DEBUG_CALLS)
    _npth_debug (DEBUG_CALLS, "tid %lu: leave_npth (%s)\n",
		 npth_self (), function ? function : "");
}

#define ENTER() enter_npth(__FUNCTION__)
#define LEAVE() leave_npth(__FUNCTION__)


struct npth_impl_s
{
  /* Usually there is one ref owned by the thread as long as it is
     running, and one ref for everybody else as long as the thread is
     joinable.  */
  int refs;

  HANDLE handle;

  /* True if thread is detached.  */
  int detached;

  /* The start routine and arg.  */
  void *(*start_routine) (void *);
  void *start_arg;

  char name[THREAD_NAME_MAX + 1];

  /* Doubly-linked list for the waiter queue in condition
     variables.  */
  npth_impl_t next;
  npth_impl_t *prev_ptr;

  /* The event on which this thread waits when it is queued.  */
  HANDLE event;

  void *result;
};


static void
dequeue_thread (npth_impl_t thread)
{
  /* Unlink the thread from any condition waiter queue.  */
  if (thread->next)
    {
      thread->next->prev_ptr = thread->prev_ptr;
      thread->next = NULL;
    }
  if (thread->prev_ptr)
    {
      *(thread->prev_ptr) = thread->next;
      thread->prev_ptr = NULL;
    }
}


/* Enqueue THREAD to come after the thread whose next pointer is
   prev_ptr.  */
static void
enqueue_thread (npth_impl_t thread, npth_impl_t *prev_ptr)
{
  if (*prev_ptr)
    (*prev_ptr)->prev_ptr = &thread->next;
  thread->prev_ptr = prev_ptr;
  thread->next = *prev_ptr;
  *prev_ptr = thread;
}


static int
find_thread (npth_t thread_id, npth_impl_t *thread)
{
  if (thread_id < 1 || thread_id >= MAX_THREADS)
    return ESRCH;

  if (! thread_table[thread_id])
    return ESRCH;

  *thread = thread_table[thread_id];
  return 0;
}


static int
new_thread (npth_t *thread_id)
{
  npth_impl_t thread;
  int id;

  /* ID 0 is never allocated.  */
  for (id = 1; id < MAX_THREADS; id++)
    if (! thread_table[id])
      break;
  if (id == MAX_THREADS)
    return EAGAIN;

  thread = malloc (sizeof (*thread));
  if (! thread)
    return errno;

  thread->refs = 1;
  thread->handle = INVALID_HANDLE_VALUE;
  thread->detached = 0;
  thread->start_routine = NULL;
  thread->start_arg = NULL;
  thread->next = NULL;
  thread->prev_ptr = NULL;
  /* We create the event when it is first needed (not all threads wait
     on conditions).  */
  thread->event = INVALID_HANDLE_VALUE;
  memset (thread->name, '\0', sizeof (thread->name));

  thread_table[id] = thread;

  *thread_id = id;
  return 0;
}


static void
free_thread (npth_t thread_id)
{
  npth_impl_t thread = thread_table[thread_id];

  if (thread->handle)
    CloseHandle (thread->handle);

  /* Unlink the thread from any condition waiter queue.  */
  dequeue_thread (thread);

  free (thread);

  thread_table[thread_id] = NULL;
}


static void
deref_thread (npth_t thread_id)
{
  npth_impl_t thread = thread_table[thread_id];

  thread->refs -= 1;
  if (thread->refs == 0)
    free_thread (thread_id);
}



int
npth_init (void)
{
  int err;
  npth_t thread_id;
  BOOL res;
  HANDLE handle;
  npth_impl_t thread;

  InitializeCriticalSection (&sceptre);

  /* Track that we have been initialized.  */
  initialized_or_any_threads = 1;

  /* Fake a thread table item for the main thread.  */
  tls_index = TlsAlloc();
  if (tls_index == TLS_OUT_OF_INDEXES)
    return map_error (GetLastError());

  err = new_thread(&thread_id);
  if (err)
    return err;

  /* GetCurrentThread() is not usable by other threads, so it needs to
     be duplicated.  */
  res = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
			GetCurrentProcess(), &handle,
			0, FALSE, DUPLICATE_SAME_ACCESS);
  if (!res)
    {
      free_thread (thread_id);
      return map_error(GetLastError());
    }

  thread = thread_table[thread_id];
  thread->handle = handle;

  if (! TlsSetValue(tls_index, (LPVOID) thread_id))
    return map_error (GetLastError());

  LEAVE();
  return 0;
}


struct npth_attr_s
{
  int detachstate;
};


int
npth_attr_init (npth_attr_t *attr_r)
{
  npth_attr_t attr;

  attr = malloc (sizeof *attr);
  if (!attr)
    return errno;

  attr->detachstate = NPTH_CREATE_JOINABLE;
  *attr_r = attr;
  return 0;
}


int
npth_attr_destroy (npth_attr_t *attr)
{
  free (*attr);
  return 0;
}


int
npth_attr_getdetachstate (npth_attr_t *attr,
			  int *detachstate)
{
  *detachstate = (*attr)->detachstate;
  return 0;
}


int
npth_attr_setdetachstate (npth_attr_t *attr, int detachstate)
{
  if (detachstate != NPTH_CREATE_JOINABLE
      && detachstate != NPTH_CREATE_DETACHED)
    return EINVAL;

  (*attr)->detachstate = detachstate;
  return 0;
}


static DWORD
thread_start (void *arg)
{
  npth_t thread_id = (npth_t) arg;
  npth_impl_t thread;
  void *result;

  if (! TlsSetValue(tls_index, (LPVOID) thread_id))
    /* FIXME: There is not much we can do here.  */
    ;

  LEAVE();
  /* We must be protected here, because we access the global
     thread_table.  */

  thread = thread_table[thread_id];
  result = thread->start_routine (thread->start_arg);
  /* We might not return here if the thread calls npth_exit().  */

  thread->result = result;

  /* Any joiner will be signaled once we terminate.  */
  deref_thread (thread_id);

  ENTER();

  /* We can not return result, as that is a void*, not a DWORD.  */
  return 0;
}


int
npth_create (npth_t *newthread, const npth_attr_t *user_attr,
	     void *(*start_routine) (void *), void *start_arg)
{
  int err = 0;
  npth_t thread_id = INVALID_THREAD_ID;
  npth_attr_t attr;
  int attr_allocated;
  npth_impl_t thread;
  HANDLE handle;

  /* We must stay protected here, because we access the global
     thread_table.  Also, creating a new thread is not a blocking
     operation.  */
  if (user_attr)
    {
      attr = *user_attr;
      attr_allocated = 0;
    }
  else
    {
      err = npth_attr_init (&attr);
      if (err)
	return err;
      attr_allocated = 1;
    }

  err = new_thread (&thread_id);
  if (err)
    goto err_out;

  thread = thread_table[thread_id];
  if (attr->detachstate == NPTH_CREATE_DETACHED)
    thread->detached = 1;
  else
    thread->refs += 1;

  thread->start_routine = start_routine;
  thread->start_arg = start_arg;

  handle = CreateThread (NULL, 0,
			 (LPTHREAD_START_ROUTINE)thread_start,
			 (void *) thread_id, CREATE_SUSPENDED,
			 NULL);
  if (handle == NULL)
    {
      err = map_error (GetLastError());
      goto err_out;
    }

  thread->handle = handle;
  *newthread = thread_id;

  ResumeThread (thread->handle);

  return 0;

 err_out:
  if (thread_id)
    free_thread (thread_id);
  if (attr_allocated)
    npth_attr_destroy (&attr);

  return err;
}


npth_t
npth_self (void)
{
  LPVOID thread_id;

  thread_id = TlsGetValue (tls_index);
  if (thread_id == 0 && GetLastError() != ERROR_SUCCESS)
    /* FIXME: Log the error.  */
    ;
  return (npth_t) thread_id;
}


/* Not part of the public interface at the moment, thus static.  */
static int
npth_tryjoin_np (npth_t thread_id, void **thread_return)
{
  int err;
  npth_impl_t thread;
  int res;

  err = find_thread (thread_id, &thread);
  if (err)
    return err;

  if (thread->detached)
    return EINVAL;

  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = wait_for_single_object (thread->handle, 0);
  if (err == ETIMEDOUT)
    err = EBUSY;

  if (err)
    return err;

  if (thread_return)
    *thread_return = thread->result;
  deref_thread (thread_id);

  return 0;
}


int
npth_join (npth_t thread_id, void **thread_return)
{
  int err;
  npth_impl_t thread;
  int res;

  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = npth_tryjoin_np (thread_id, thread_return);
  if (err != EBUSY)
    return err;

  err = find_thread (thread_id, &thread);
  if (err)
    return err;

  if (thread->detached)
    return EINVAL;

  ENTER();
  err = wait_for_single_object (thread->handle, INFINITE);
  LEAVE();

  if (err)
    return err;

  if (thread_return)
    *thread_return = thread->result;
  deref_thread (thread_id);

  return 0;
}


int
npth_detach (npth_t thread_id)
{
  int err;
  npth_impl_t thread;

  err = find_thread (thread_id, &thread);
  if (err)
    return err;

  if (thread->detached)
    return EINVAL;

  /* The detached flag indicates to other thread that the outside
     reference in the global thread table has been consumed.  */
  thread->detached = 1;
  deref_thread (thread_id);

  return 0;
}


void
npth_exit (void *retval)
{
  int err;
  npth_t thread_id;
  npth_impl_t thread;

  thread_id = npth_self();
  err = find_thread (thread_id, &thread);
  if (err)
    /* FIXME: log this?  */
    return;

  thread->result = retval;
  /* Any joiner will be signaled once we terminate.  */
  deref_thread (thread_id);

  ENTER();

  /* We can not use retval here, as that is a void*, not a DWORD.  */
  ExitThread(0);

  /* Never reached.  But just in case ExitThread does return... */
  LEAVE();
}



int
npth_key_create (npth_key_t *key,
		 void (*destr_function) (void *))
{
  DWORD idx;

  if (destr_function)
    return EOPNOTSUPP;

  idx = TlsAlloc ();
  if (idx == TLS_OUT_OF_INDEXES)
    return map_error (GetLastError());

  *key = idx;
  return 0;
}


int
npth_key_delete (npth_key_t key)
{
  BOOL res;

  res = TlsFree (key);
  if (res == 0)
    return map_error (GetLastError());
  return 0;
}


void *
npth_getspecific (npth_key_t key)
{
  /* Pthread doesn't support error reporting beyond returning NULL for
     an invalid key, which is also what TlsGetValue returns in that
     case.  */
  return TlsGetValue (key);
}


int
npth_setspecific (npth_key_t key, const void *pointer)
{
  BOOL res;

  res = TlsSetValue (key, (void *) pointer);
  if (res == 0)
    return map_error (GetLastError());

  return 0;
}


struct npth_mutexattr_s
{
  int kind;
};


int
npth_mutexattr_init (npth_mutexattr_t *attr_r)
{
  npth_mutexattr_t attr;

  attr = malloc (sizeof *attr);
  if (!attr)
    return errno;

  attr->kind = NPTH_MUTEX_DEFAULT;
  *attr_r = attr;
  return 0;
}


int
npth_mutexattr_destroy (npth_mutexattr_t *attr)
{
  free (*attr);
  *attr = NULL;
  return 0;
}


int
npth_mutexattr_gettype (const npth_mutexattr_t *attr,
			int *kind)
{
  *kind = (*attr)->kind;
  return 0;
}


int
npth_mutexattr_settype (npth_mutexattr_t *attr, int kind)
{
  if (kind != NPTH_MUTEX_NORMAL && kind != NPTH_MUTEX_RECURSIVE
      && kind != NPTH_MUTEX_ERRORCHECK)
    return EINVAL;

  (*attr)->kind = kind;
  return 0;
}


struct npth_mutex_s
{
  /* We have to use a mutex, not a CRITICAL_SECTION, because the
     latter can not be used with timed waits.  */
  HANDLE mutex;
};


int
npth_mutex_init (npth_mutex_t *mutex_r, const npth_mutexattr_t *mutex_attr)
{
  npth_mutex_t mutex;

  /* We can not check *mutex_r here, as it may contain random data.  */
  mutex = malloc (sizeof (*mutex));
  if (!mutex)
    return errno;

  /* We ignore MUTEX_ATTR.  */
  mutex->mutex = CreateMutex (NULL, FALSE, NULL);
  if (!mutex->mutex)
    {
      int err = map_error (GetLastError());
      free (mutex);
      return err;
    }

  *mutex_r = mutex;
  return 0;
}


int
npth_mutex_destroy (npth_mutex_t *mutex)
{
  BOOL res;

  if (*mutex == 0 || *mutex == NPTH_MUTEX_INITIALIZER
      || *mutex == NPTH_RECURSIVE_MUTEX_INITIALIZER_NP)
    return EINVAL;

  res = CloseHandle ((*mutex)->mutex);
  if (res == 0)
    return map_error (GetLastError());

  free (*mutex);
  *mutex = NULL;

  return 0;
}


/* Must be called with global lock held.  */
static int
mutex_init_check (npth_mutex_t *mutex)
{
  int err;
  npth_mutexattr_t attr;
  int kind;

  if (*mutex == 0)
    return EINVAL;

  if ((*mutex) == NPTH_MUTEX_INITIALIZER)
    kind = NPTH_MUTEX_NORMAL;
  else if ((*mutex) == NPTH_RECURSIVE_MUTEX_INITIALIZER_NP)
    kind = NPTH_MUTEX_RECURSIVE;
  else if ((*mutex) == NPTH_ERRORCHECK_MUTEX_INITIALIZER_NP)
    kind = NPTH_MUTEX_ERRORCHECK;
  else
    /* Already initialized.  */
    return 0;

  /* Make sure we don't try again in case of error.  */
  *mutex = 0;

  err = npth_mutexattr_init (&attr);
  if (err)
    return err;

  err = npth_mutexattr_settype (&attr, kind);
  if (err)
    {
      npth_mutexattr_destroy (&attr);
      return err;
    }

  err = npth_mutex_init (mutex, &attr);
  npth_mutexattr_destroy (&attr);

  return err;
}


int
npth_mutex_lock (npth_mutex_t *mutex)
{
  int err;

  /* While we are protected, let's check for a static initializer.  */
  err = mutex_init_check (mutex);
  if (err)
    return err;

  /* No need to allow competing threads to enter when we can get the
     lock immediately.  */
  err = npth_mutex_trylock (mutex);
  if (err != EBUSY)
    return err;

  ENTER();
  err = wait_for_single_object ((*mutex)->mutex, INFINITE);
  LEAVE();

  if (err)
    return err;

  return 0;
}


int
npth_mutex_trylock (npth_mutex_t *mutex)
{
  int err;
  DWORD res;

  /* While we are protected, let's check for a static initializer.  */
  err = mutex_init_check (mutex);
  if (err)
    return err;

  /* We do not leave the global lock for a quick try.  */
  err = wait_for_single_object ((*mutex)->mutex, 0);
  if (err == ETIMEDOUT)
    err = EBUSY;

  if (err)
    return err;

  return 0;
}


int
npth_mutex_unlock (npth_mutex_t *mutex)
{
  BOOL res;

  if (*mutex == 0 || *mutex == NPTH_MUTEX_INITIALIZER
      || *mutex == NPTH_RECURSIVE_MUTEX_INITIALIZER_NP)
    return EINVAL;

  res = ReleaseMutex ((*mutex)->mutex);
  if (res == 0)
    return map_error (GetLastError());

  return 0;
}


struct npth_rwlockattr_s
{
  int kind;
};


int
npth_rwlockattr_init (npth_rwlockattr_t *attr_r)
{
  npth_rwlockattr_t attr;

  attr = malloc (sizeof *attr);
  if (!attr)
    return errno;

  attr->kind = NPTH_RWLOCK_DEFAULT_NP;
  *attr_r = attr;
  return 0;
}


int
npth_rwlockattr_destroy (npth_rwlockattr_t *attr)
{
  free (*attr);
  *attr = NULL;
  return 0;
}


int
npth_rwlockattr_gettype_np (const npth_rwlockattr_t *attr,
			    int *kind)
{
  *kind = (*attr)->kind;
  return 0;
}


int
npth_rwlockattr_settype_np (npth_rwlockattr_t *attr, int kind)
{
  if (kind != NPTH_RWLOCK_PREFER_READER_NP
      && kind != NPTH_RWLOCK_PREFER_WRITER_NP
      && kind != NPTH_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
    return EINVAL;

  (*attr)->kind = kind;
  return 0;
}


struct npth_rwlock_s
{
  /* Objects are protected by the global lock, so no lock here
     necessary.  This is even true for the condition (by specifying
     NULL as the mutex in npth_cond_wait and npth_cond_timedwait).  */

  /* True if we prefer writers over readers.  */
  int prefer_writer;

  /* Readers who want the lock wait on this condition, which is
     broadcast when the last writer goes away.  */
  npth_cond_t reader_wait;

  /* The number of readers waiting on the condition.  */
  int nr_readers_queued;

  /* The number of current readers.  */
  int nr_readers;

  /* Writers who want the lock wait on this condition, which is
     signaled when the current writer or last reader goes away.  */
  npth_cond_t writer_wait;

  /* The number of queued writers.  */
  int nr_writers_queued;

  /* The number of current writers.  This is either 1 (then nr_readers
     is 0) or it is 0.  At unlock time this value tells us if the
     current lock holder is a writer or a reader.  */
  int nr_writers;
};


int
npth_rwlock_init (npth_rwlock_t *rwlock_r,
		  const npth_rwlockattr_t *user_attr)
{
  int err;
  npth_rwlock_t rwlock;
  npth_rwlockattr_t attr;
  int attr_allocated;

  if (user_attr != NULL)
    {
      attr = *user_attr;
      attr_allocated = 0;
    }
  else
    {
      err = npth_rwlockattr_init (&attr);
      if (err)
	return err;
    }

  /* We can not check *rwlock_r here, as it may contain random data.  */
  rwlock = malloc (sizeof (*rwlock));
  if (!rwlock)
    {
      err = errno;
      goto err_out;
    }

  rwlock->prefer_writer = (attr->kind == NPTH_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

  err = npth_cond_init (&rwlock->reader_wait, NULL);
  if (err)
    {
      free (rwlock);
      goto err_out;
    }

  err = npth_cond_init (&rwlock->writer_wait, NULL);
  if (err)
    {
      npth_cond_destroy (&rwlock->reader_wait);
      free (rwlock);
      goto err_out;
    }

  rwlock->nr_readers = 0;
  rwlock->nr_readers_queued = 0;
  rwlock->nr_writers = 0;
  rwlock->nr_writers_queued = 0;

  *rwlock_r = rwlock;

 err_out:
  if (attr_allocated)
    npth_rwlockattr_destroy (&attr);
  return err;
}


/* Must be called with global lock held.  */
static int
rwlock_init_check (npth_rwlock_t *rwlock)
{
  int err;
  npth_rwlockattr_t attr;
  int kind;

  if (*rwlock == 0)
    return EINVAL;

  if ((*rwlock) == NPTH_RWLOCK_INITIALIZER)
    kind = NPTH_RWLOCK_PREFER_READER_NP;
  if ((*rwlock) == NPTH_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP)
    kind = NPTH_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP;
  else
    /* Already initialized.  */
    return 0;

  /* Make sure we don't try again in case of error.  */
  *rwlock = 0;

  err = npth_rwlockattr_init (&attr);
  if (err)
    return err;

  err = npth_rwlockattr_settype_np (&attr, kind);
  if (err)
    {
      npth_rwlockattr_destroy (&attr);
      return err;
    }

  err = npth_rwlock_init (rwlock, &attr);
  npth_rwlockattr_destroy (&attr);

  return err;
}


int
npth_rwlock_destroy (npth_rwlock_t *rwlock)
{
  int err;

  if (*rwlock == 0 || *rwlock == NPTH_RWLOCK_INITIALIZER)
    return EINVAL;

  if ((*rwlock)->nr_writers || (*rwlock)->nr_readers || (*rwlock)->nr_writers_queued
      || (*rwlock)->nr_readers_queued)
    return EBUSY;

  err = npth_cond_destroy (&(*rwlock)->reader_wait);
  if (err)
    /* FIXME: Log this.  */
    ;

  err = npth_cond_destroy (&(*rwlock)->writer_wait);
  if (err)
    /* FIXME: Log this.  */
    ;

  free (rwlock);

  *rwlock = NULL;
  return 0;
}


int
npth_rwlock_rdlock (npth_rwlock_t *rwlock)
{
  int err;

  while (1)
    {
      /* Quick check.  */
      err = npth_rwlock_tryrdlock (rwlock);
      if (err != EBUSY)
	return err;

      (*rwlock)->nr_readers_queued++;
      err = npth_cond_wait (&(*rwlock)->reader_wait, NULL);
      (*rwlock)->nr_readers_queued--;
      if (err)
	return err;
    }
}


int
npth_rwlock_wrlock (npth_rwlock_t *rwlock)
{
  int err;

  while (1)
    {
      /* Quick check.  */
      err = npth_rwlock_trywrlock (rwlock);
      if (err != EBUSY)
	return err;

      (*rwlock)->nr_writers_queued++;
      err = npth_cond_wait (&(*rwlock)->writer_wait, NULL);
      (*rwlock)->nr_writers_queued--;
      if (err)
	return err;
    }
}


int
npth_rwlock_unlock (npth_rwlock_t *rwlock)
{
  int err;

  if ((*rwlock)->nr_writers)
    /* We are the writer.  */
    (*rwlock)->nr_writers = 0;
  else
    /* We are the reader.  */
    (*rwlock)->nr_readers--;

  if ((*rwlock)->nr_readers == 0)
    {
      if ((*rwlock)->nr_writers_queued)
	{
	  err = npth_cond_signal (&(*rwlock)->writer_wait);
	  if (err)
	    return err;
	}
      else if ((*rwlock)->nr_readers_queued)
	{
	  err = npth_cond_broadcast (&(*rwlock)->reader_wait);
	  return err;
	}
    }
  return 0;
}


/* Standard POSIX Replacement API */

int
npth_usleep(unsigned int usec)
{
  ENTER();
  Sleep((usec + 999) / 1000);
  LEAVE();
  return 0;
}


unsigned int
npth_sleep(unsigned int sec)
{
  ENTER();
  Sleep (sec * 1000);
  LEAVE();
  return 0;
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
  return EOPNOTSUPP;
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
  return EOPNOTSUPP;
}


int
npth_sendmsg (int fd, const struct msghdr *msg, int flags)
{
  return EOPNOTSUPP;
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
