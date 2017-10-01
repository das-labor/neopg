/* t-b64dec.c - b64dec test.
   Copyright (C) 2017 g10 Code GmbH

   This file is part of libgpg-error.

   libgpg-error is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   libgpg-error is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with libgpgme-error; if not, write to the Free
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <gpg-error.h>

static const char *test_b64_string = "bGliZ3BnLWVycm9yIGlzIGZyZWUgc29"
  "mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnkgaXQgd"
  "W5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljIEx"
  "pY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb"
  "247IGVpdGhlciB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXI"
  "gb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi4=";

static const char *test_string = "libgpg-error is free software; "
  "you can redistribute it and/or modify it under the terms of "
  "the GNU Lesser General Public License as published by the Free "
  "Software Foundation; either version 2.1 of the License, or "
  "(at your option) any later version.";

#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     errcount++;                                 \
                   } while(0)

static int errcount;

static gpg_error_t
test_b64dec_string (const char *string, const char *expected)
{
  gpg_error_t err;
  gpgrt_b64state_t state;
  char *buffer;
  size_t len;

  len = strlen (string);
  buffer = malloc (strlen (string) + 1);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      return err;
    }

  state = gpgrt_b64dec_start ("");
  if (!state)
    {
      err = gpg_error_from_syserror ();
      free (buffer);
      return err;
    }

  err = gpgrt_b64dec_proc (state, buffer, len, &len);
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_EOF)
        {
          free (buffer);
          free (state);
          return err;
        }
    }

  err = gpgrt_b64dec_finish (state);
  if (err)
    {
      free (buffer);
      return err;
    }

  if (strncmp (buffer, expected, len) == 0)
    err = 0;
  else
    err = GPG_ERR_INTERNAL;

  free (buffer);
  return err;
}



int
main (int argc, char **argv)
{
  gpg_error_t err;

  (void)argc;
  (void)argv;

  err = test_b64dec_string (test_b64_string, test_string);

  if (err)
    {
      fail (1);
      return 1;
    }
  else
    return 0;
}
