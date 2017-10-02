/* t-mutex.c
 * Copyright 2011, 2012 g10 Code GmbH
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


int
main (int argc, char *argv[])
{
  int rc;
  npth_mutex_t mutex;

  rc = npth_init ();
  fail_if_err (rc);

  rc = npth_mutex_init (&mutex, NULL);
  fail_if_err (rc);
  rc = npth_mutex_lock (&mutex);
  fail_if_err (rc);
  rc = npth_mutex_unlock (&mutex);
  fail_if_err (rc);

  return 0;
}
