/* t-oid.c - Test utility for the OID functions
 *      Copyright (C) 2009 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * KSBA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"

#define PGM "t-oid"
#define BADOID "1.3.6.1.4.1.11591.2.12242973"


static void *
read_into_buffer (FILE *fp, size_t *r_length)
{
  char *buffer;
  size_t buflen;
  size_t nread, bufsize = 0;

  *r_length = 0;
#define NCHUNK 8192
#ifdef HAVE_W32_SYSTEM
  setmode (fileno(fp), O_BINARY);
#endif
  buffer = NULL;
  buflen = 0;
  do
    {
      bufsize += NCHUNK;
      buffer = realloc (buffer, bufsize);
      if (!buffer)
        {
          perror ("realloc failed");
          exit (1);
        }

      nread = fread (buffer + buflen, 1, NCHUNK, fp);
      if (nread < NCHUNK && ferror (fp))
        {
          perror ("fread failed");
          exit (1);
        }
      buflen += nread;
    }
  while (nread == NCHUNK);
#undef NCHUNK

  *r_length = buflen;
  return buffer;
}


static void
test_oid_to_str (void)
{
  struct {
    unsigned int binlen;
    unsigned char *bin;
    char *str;
  } tests[] = {

    {  7, "\x02\x82\x06\x01\x0A\x0C\x00",
       "0.2.262.1.10.12.0"
    },
    {  7, "\x02\x82\x06\x01\x0A\x0C\x01",
       "0.2.262.1.10.12.1"
    },
    {  7, "\x2A\x86\x48\xCE\x38\x04\x01",
       "1.2.840.10040.4.1"
    },
    {  7, "\x2A\x86\x48\xCE\x38\x04\x03",
       "1.2.840.10040.4.3"
    },
    { 10, "\x2B\x06\x01\x04\x01\xDA\x47\x02\x01\x01",
      "1.3.6.1.4.1.11591.2.1.1"
    },
    {  3, "\x55\x1D\x0E",
       "2.5.29.14"
    },
    {  9, "\x80\x02\x70\x50\x25\x46\xfd\x0c\xc0",
       BADOID
    },
    {  1, "\x80",
       BADOID
    },
    {  2, "\x81\x00",
       "2.48"
    },
    {  2, "\x81\x01",
       "2.49"
    },
    {  2, "\x81\x7f",
       "2.175"
    },
    {  2, "\x81\x80",  /* legal encoding? */
       "2.48"
    },
    {  2, "\x81\x81\x01",  /* legal encoding? */
       "2.49"
    },
    {  0, "",
       ""
    },

    { 0, NULL, NULL }
  };
  int tidx;
  char *str;

  for (tidx=0; tests[tidx].bin; tidx++)
    {
      str = ksba_oid_to_str (tests[tidx].bin, tests[tidx].binlen);
      if (!str)
        {
          perror ("ksba_oid_to_str failed");
          exit (1);
        }
      if (strcmp (tests[tidx].str, str))
        {
          fprintf (stderr, "ksba_oid_to_str test %d failed\n", tidx);
          fprintf (stderr, "  got=%s\n", str);
          fprintf (stderr, " want=%s\n", tests[tidx].str);
          exit (1);
        }
      ksba_free (str);
    }
}


int
main (int argc, char **argv)
{
  gpg_error_t err;

  if (argc)
    {
      argc--;
      argv++;
    }


  if (!argc)
    {
      test_oid_to_str ();
    }
  else if (!strcmp (*argv, "--from-str"))
    {
      unsigned char *buffer;
      size_t n, buflen;

      for (argv++,argc-- ; argc; argc--, argv++)
        {
          err = ksba_oid_from_str (*argv, &buffer, &buflen);
          if (err)
            {
              fprintf (stderr, "can't convert `%s': %s\n",
                       *argv, gpg_strerror (err));
              return 1;
            }
          printf ("%s ->", *argv);
          for (n=0; n < buflen; n++)
            printf (" %02X", buffer[n]);
          putchar ('\n');
          free (buffer);
        }
    }
  else if (!strcmp (*argv, "--to-str"))
    {
      char *buffer;
      size_t buflen;
      char *result;

      argv++;argc--;

      buffer = read_into_buffer (stdin, &buflen);
      result = ksba_oid_to_str (buffer, buflen);
      free (buffer);
      printf ("%s\n", result? result:"[malloc failed]");
      free (result);
    }
  else
    {
      fputs ("usage: "PGM" [--from-str|--to-str]\n", stderr);
      return 1;
    }

  return 0;
}
