/* t-thread.c
 * Copyright 2012 g10 Code GmbH
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "t-support.h"


static int counter;
static npth_mutex_t counter_mutex;
static int thread_twoone_ready;

static void *
thread_one (void *arg)
{
  int rc, i;

  info_msg ("thread-one started");
  npth_usleep (10);  /* Give the other thread some time to start.  */
  for (i=0; i < 10; i++)
    {
      /* We would not need the mutex here, but we use it to allow the
         system to switch to another thread.  */
      rc = npth_mutex_lock (&counter_mutex);
      fail_if_err (rc);

      counter++;

      rc = npth_mutex_unlock (&counter_mutex);
      fail_if_err (rc);
    }
  info_msg ("thread-one terminated");

  return (void*)4711;
}


static void *
thread_twoone (void *arg)
{
  int rc, i;

  npth_setname_np (npth_self (), "thread-twoone");
  info_msg ("thread-twoone started");

  rc = npth_detach (npth_self ());
  fail_if_err (rc);

  while (counter < 100)
    {
      npth_usleep (1000);
      counter++;
    }
  info_msg ("thread-twoone terminated");
  thread_twoone_ready = 1;

  return NULL;
}


static void *
thread_two (void *arg)
{
  int rc, i;

  info_msg ("thread-two started");

  for (i=0; i < 10; i++)
    {
      rc = npth_mutex_lock (&counter_mutex);
      fail_if_err (rc);

      counter--;

      if (i == 5)
        {
          npth_t tid;

          info_msg ("creating thread-twoone");
          rc = npth_create (&tid, NULL, thread_twoone, NULL);
          fail_if_err (rc);
          npth_usleep (10);  /* Give new thread some time to start.  */
        }

      rc = npth_mutex_unlock (&counter_mutex);
      fail_if_err (rc);
    }

  info_msg ("busy waiting for thread twoone");
  while (!thread_twoone_ready)
    npth_sleep (0);

  info_msg ("thread-two terminated");

  return (void*)4722;
}





int
main (int argc, char *argv[])
{
  int rc;
  npth_attr_t tattr;
  int state;
  npth_t tid1, tid2;
  void *retval;

  if (argc >= 2 && !strcmp (argv[1], "--verbose"))
    opt_verbose = 1;

  rc = npth_init ();
  fail_if_err (rc);

  rc = npth_mutex_init (&counter_mutex, NULL);
  fail_if_err (rc);

  rc = npth_attr_init (&tattr);
  fail_if_err (rc);
  rc = npth_attr_getdetachstate (&tattr, &state);
  fail_if_err (rc);
  if ( state != NPTH_CREATE_JOINABLE )
    fail_msg ("new tattr is not joinable");

  info_msg ("creating thread-one");
  rc = npth_create (&tid1, &tattr, thread_one, NULL);
  fail_if_err (rc);
  npth_setname_np (tid1, "thread-one");

  info_msg ("creating thread-two");
  rc = npth_create (&tid2, &tattr, thread_two, NULL);
  fail_if_err (rc);
  npth_setname_np (tid2, "thread-two");

  rc = npth_attr_destroy (&tattr);
  fail_if_err (rc);

  info_msg ("waiting for thread-one to terminate");
  rc = npth_join (tid1, &retval);
  fail_if_err (rc);
  if (retval != (void*)4711)
    fail_msg ("thread-one returned an unexpected value");

  info_msg ("waiting for thread-two to terminate");
  rc = npth_join (tid2, &retval);
  fail_if_err (rc);
  if (retval != (void*)4722)
    fail_msg ("thread-two returned an unexpected value");

  if (counter != 100)
    fail_msg ("counter value not as expected");

  return 0;
}
