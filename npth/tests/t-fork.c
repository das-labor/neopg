/* t-fork.c
 * Copyright 2016 g10 Code GmbH
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "t-support.h"

/* This is a test if nPth can allow daemon-like applications
   initializing earlier.

   For daemon-like applications, ideally, it is expected to call
   npth_init after fork.  This condition is not satisfied sometimes.

   Failure of this test means nPth implementation doesn't allow
   npth_init after fork.  In such a case, application should be
   modified.
 */

int
main (int argc, const char *argv[])
{
  int rc;
  pid_t pid;

  if (argc >= 2 && !strcmp (argv[1], "--verbose"))
    opt_verbose = 1;

  rc = npth_init ();
  fail_if_err (rc);

  pid = fork ();
  if (pid == (pid_t)-1)
    fail_msg ("fork failed");
  else if (pid)
   {
     int status;

     info_msg ("forked");
     wait (&status);
     fail_if_err (status);
   }
  else
    {
      info_msg ("child exit");
      npth_usleep (1000);     /* Let NPTH enter, sleep, and leave.  */
    }

  return 0;
}
