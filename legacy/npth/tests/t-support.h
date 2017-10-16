/* t-support.h - Helper routines for regression tests.
 * Copyright (C) 2011 g10 Code GmbH
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "npth.h"

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

static int opt_verbose;


#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s\n",			\
                   __FILE__, __LINE__, strerror(err));		\
          exit (1);						\
        }							\
    }								\
  while (0)

#define fail_msg(text)                                          \
  do								\
    {								\
      fprintf (stderr, "%s:%d: %s\n",                           \
               __FILE__, __LINE__, text);                       \
      exit (1);                                                 \
    }								\
  while (0)

#define info_msg(text)                          \
  do                                            \
    {                                           \
      if (opt_verbose)                          \
        fprintf (stderr, "%s\n", text);         \
    }                                           \
  while (0)
