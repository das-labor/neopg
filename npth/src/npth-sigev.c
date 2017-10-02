/* npth-sigev.c - signal handling interface
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

/* This is a support interface to make it easier to handle signals.
 *
 * The interfaces here support one (and only one) thread (here called
 * "main thread") in the application to monitor several signals while
 * selecting on filedescriptors.
 *
 * First, the main thread should call npth_sigev_init.  This
 * initializes some global data structures used to record interesting
 * and pending signals.
 *
 * Then, the main thread should call npth_sigev_add for every signal
 * it is interested in observing, and finally npth_sigev_fini.  This
 * will block the signal in the main threads sigmask.  Note that these
 * signals should also be blocked in all other threads.  Since they
 * are blocked in the main thread after calling npth_sigev_add, it is
 * recommended to call npth_sigev_add in the main thread before
 * creating any threads.
 *
 * The function npth_sigev_sigmask is a convenient function that
 * returns the sigmask of the thread at time of npth_sigev_init, but
 * with all registered signals unblocked.  It is recommended to do all
 * other changes to the main thread's sigmask before calling
 * npth_sigev_init, so that the return value of npth_sigev_sigmask can
 * be used in the npth_pselect invocation.
 *
 * In any case, the main thread should invoke npth_pselect with a
 * sigmask that has all signals that should be monitored unblocked.
 *
 * After npth_pselect returns, npth_sigev_get_pending can be called in
 * a loop until it returns 0 to iterate over the list of pending
 * signals.  Each time a signal is returned by that function, its
 * status is reset to non-pending.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <assert.h>

#include "npth.h"

/* Record events that have been noticed.  */
static sigset_t sigev_pending;

/* The signal mask during normal operation.  */
static sigset_t sigev_block;

/* The signal mask during pselect.  */
static sigset_t sigev_unblock;

/* Registered signal numbers.  Needed to iterate over sigset_t.
   Bah.  */
#define SIGEV_MAX 32
static int sigev_signum[SIGEV_MAX];
static int sigev_signum_cnt;

/* The internal handler which just sets a global flag.  */
static void
_sigev_handler (int signum)
{
  sigaddset (&sigev_pending, signum);
}


/* Start setting up signal event handling.  */
void
npth_sigev_init (void)
{
  sigemptyset (&sigev_pending);
  pthread_sigmask (SIG_SETMASK, NULL, &sigev_block);
  pthread_sigmask (SIG_SETMASK, NULL, &sigev_unblock);
}


/* Add signal SIGNUM to the list of watched signals.  */
void
npth_sigev_add (int signum)
{
  struct sigaction sa;
  sigset_t ss;

  sigemptyset(&ss);

  assert (sigev_signum_cnt < SIGEV_MAX);
  sigev_signum[sigev_signum_cnt++] = signum;

  /* Make sure we can receive it.  */
  sigdelset (&sigev_unblock, signum);
  sigaddset (&sigev_block, signum);

  sa.sa_handler = _sigev_handler;
  sa.sa_mask = ss;
  sa.sa_flags = 0; /* NOT setting SA_RESTART! */

  sigaction (signum, &sa, NULL);
}


#ifdef HAVE_PTHREAD_ATFORK
/* There is non-POSIX operating system where fork is not available to
   applications.  There, we have no pthread_atfork either.  In such a
   case, we don't call pthread_atfork.  */
static void
restore_sigmask_for_child_process (void)
{
  pthread_sigmask (SIG_SETMASK, &sigev_unblock, NULL);
}
#endif

/* Finish the list of watched signals.  This starts to block them,
   too.  */
void
npth_sigev_fini (void)
{
  /* Block the interesting signals.  */
  pthread_sigmask (SIG_SETMASK, &sigev_block, NULL);
#ifdef HAVE_PTHREAD_ATFORK
  pthread_atfork (NULL, NULL, restore_sigmask_for_child_process);
#endif
}


/* Get the sigmask as needed for pselect.  */
sigset_t *
npth_sigev_sigmask (void)
{
  return &sigev_unblock;
}


/* Return the next signal event that occured.  Returns if none are
   left, 1 on success.  */
int
npth_sigev_get_pending (int *r_signum)
{
  int i;
  for (i = 0; i < sigev_signum_cnt; i++)
    {
      int signum = sigev_signum[i];
      if (sigismember (&sigev_pending, signum))
	{
	  sigdelset (&sigev_pending, signum);
	  *r_signum = signum;
	  return 1;
	}
    }
  return 0;
}

