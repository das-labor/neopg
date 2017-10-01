/* t-printf.c - Check the estream printf fucntions.
 * Copyright (C) 2013 g10 Code GmbH
 *
 * This file is part of libgpg-error.
 *
 * libgpg-error is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * libgpg-error is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* Note that these tests check against glibc behaviour.  On non glibc
   systems expect non matching return codes in some border cases.  */


#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <locale.h>

#define PGM "t-printf"

#include "t-common.h"


static char *one_test_buf1;
static int   one_test_rc1;

static void
one_test_x0 (const char *format, ...)
{
  va_list arg_ptr;

  show ("format: ->%s<-\n", format);

  errno = ENOENT; /* For the "%m" test.  */
  va_start (arg_ptr, format);
#ifdef HAVE_VASPRINTF
  one_test_rc1 = vasprintf (&one_test_buf1, format, arg_ptr);
#else
  one_test_rc1 = -1;
#endif
  va_end (arg_ptr);
  if (one_test_rc1 == -1)
    {
      fail ("   sys: errno=%d (%s)\n", errno, strerror (errno));
      one_test_buf1 = NULL;
    }
  else
    show ("   sys: ->%s<-\n", one_test_buf1);
}

static void
one_test_x1 (const char *format, ...)
{
  int rc2;
  va_list arg_ptr;
  char *buf2;

  errno = ENOENT;
  va_start (arg_ptr, format);
  rc2 = gpgrt_vasprintf (&buf2, format, arg_ptr);
  va_end (arg_ptr);
  if (rc2 == -1)
    {
      fail ("   our: errno=%d (%s)\n", errno, strerror (errno));
    }
  else
    show ("   our: ->%s<-\n", buf2);

  if (one_test_rc1 != -1 && rc2 != -1 && strcmp (one_test_buf1, buf2))
    {
      fail ("error: output does not match\n"
            "format: ->%s<-\n   sys: ->%s<-\n   our: ->%s<-\n",
            format, one_test_buf1, buf2);
    }
  else if ( one_test_rc1 != rc2 )
    {
      fail ("error: return codes are different: sys_rc=%d our_rc=%d\n",
            one_test_rc1, rc2);
    }

  free (buf2);
}

static void
one_test_x2 (const char *format, ...)
{
  va_list arg_ptr;
  char *buf2;

  /* Test once more using the bsprintf variant.  */
  errno = ENOENT;
  va_start (arg_ptr, format);
  buf2 = gpgrt_vbsprintf (format, arg_ptr);
  va_end (arg_ptr);
  if (!buf2)
    {
      fail ("   our(2): errno=%d (%s)\n", errno, strerror (errno));
    }
  else if (verbose)
    show ("   our: ->%s<-\n", buf2);

  if (one_test_rc1 != -1 && buf2 && strcmp (one_test_buf1, buf2))
    {
      fail ("error: output does not match\n"
            "format(2): ->%s<-\n   sys: ->%s<-\n   our: ->%s<-\n",
            format, one_test_buf1, buf2);
    }
  es_free (buf2);

  free (one_test_buf1);
  one_test_buf1 = NULL;
}


#define one_test_0(a)                              \
  one_test_x0 (a);                                 \
  one_test_x1 (a);                                 \
  one_test_x2 (a)
#define one_test_1(a, b)                           \
  one_test_x0 (a, b);                              \
  one_test_x1 (a, b);                              \
  one_test_x2 (a, b)
#define one_test_2(a, b, c)                        \
  one_test_x0 (a, b, c);                           \
  one_test_x1 (a, b, c);                           \
  one_test_x2 (a, b, c)
#define one_test_3(a, b, c, d)                     \
  one_test_x0 (a, b, c, d);                        \
  one_test_x1 (a, b, c, d);                        \
  one_test_x2 (a, b, c, d)

static void
run_tests (void)
{
#ifndef HAVE_VASPRINTF
  /* We do not have a system vasprintf.  */
  show ("run-tests: disabled due to missing vasprintf.\n");
#else /*HAVE_VASPRINTF */

  /*one_test ("%d %% %'d", 17, 19681977);*/

  one_test_2 ("%d %% %d", 17, 768114563);
  one_test_2 ("%d %% %d", 17, -768114563);

  one_test_1 ("%d", 17);
  one_test_1 ("%4d", 17);
  one_test_1 ("%40d", 17);
  one_test_1 ("%-d", 17);
  one_test_1 ("%-4d", 17);
  one_test_1 ("%-140d", 17);
  one_test_1 ("%d", -17);
  one_test_1 ("%4d", -17);
  one_test_1 ("%40d", -17);
  one_test_1 ("%-d", -17);
  one_test_1 ("%-4d", -17);
  one_test_1 ("%-40d", -17);

  one_test_1 ("%+4d", 17);
  one_test_1 ("%+4d", -17);
  one_test_1 ("%-+4d", 17);
  one_test_1 ("%-+4d", -17);
  one_test_1 ("% 4d", 17);
  one_test_1 ("% 4d", -17);
  one_test_1 ("%- +4d", 17);
  one_test_1 ("%- +4d", -17);

  one_test_1 ("%.4d", 17);
  one_test_1 ("%.0d", 17);
  one_test_1 ("%.0d", 0);
  one_test_1 ("%.4d", -17);
  one_test_1 ("%.0d", -17);
  one_test_1 ("%6.4d", 17);
  one_test_1 ("%6.4d", -17);
  one_test_1 ("%6.0d", 0);
  one_test_1 ("%4.6d", 17);
  one_test_1 ("%4.6d", -17);

  one_test_1 ("% 4.6d", 17);
  one_test_1 ("% 6.0d", 0);

  one_test_1 ("%.4d", 17);
  one_test_1 ("%04d", 17);
  one_test_1 ("%.4d", -17);
  one_test_1 ("%04d", -17);
  one_test_1 ("%0.d", 0);

  one_test_2 ("%*d", 7, 42);
  one_test_2 ("%*d", -7, 42);
  one_test_2 ("%.*d", 7, 42);
  one_test_2 ("%.*d", -7, 42);
  one_test_3 ("%*.*d", 10, 7, 42);
  one_test_3 ("%*.*d", 10, -7, 42);
  one_test_3 ("%*.*d", -10, 7, 42);
  one_test_3 ("%*.*d", -10, -7, 42);

  one_test_2 ("%*x", 7, 42);
  one_test_2 ("%*x", -7, 42);
  one_test_2 ("%.*x", 7, 42);
  one_test_2 ("%.*x", -7, 42);
  one_test_3 ("%*.*x", 10, 7, 42);
  one_test_3 ("%*.*x", 10, -7, 42);
  one_test_3 ("%*.*x", -10, 7, 42);
  one_test_3 ("%*.*x", -10, -7, 42);
  one_test_2 ("%#*x", 7, 42);
  one_test_2 ("%#*x", -7, 42);
  one_test_2 ("%#.*x", 7, 42);
  one_test_2 ("%#.*x", -7, 42);
  one_test_3 ("%#*.*x", 10, 7, 42);
  one_test_3 ("%#*.*x", 10, -7, 42);
  one_test_3 ("%#*.*x", -10, 7, 42);
  one_test_3 ("%#*.*x", -10, -7, 42);

  one_test_2 ("%*X", 7, 42);
  one_test_2 ("%*X", -7, 42);
  one_test_2 ("%.*X", 7, 42);
  one_test_2 ("%.*X", -7, 42);
  one_test_3 ("%*.*X", 10, 7, 42);
  one_test_3 ("%*.*X", 10, -7, 42);
  one_test_3 ("%*.*X", -10, 7, 42);
  one_test_3 ("%*.*X", -10, -7, 42);
  one_test_2 ("%#*X", 7, 42);
  one_test_2 ("%#*X", -7, 42);
  one_test_2 ("%#.*X", 7, 42);
  one_test_2 ("%#.*X", -7, 42);
  one_test_3 ("%#*.*X", 10, 7, 42);
  one_test_3 ("%#*.*X", 10, -7, 42);
  one_test_3 ("%#*.*X", -10, 7, 42);
  one_test_3 ("%#*.*X", -10, -7, 42);

  one_test_2 ("%*o", 7, 42);
  one_test_2 ("%*o", -7, 42);
  one_test_2 ("%.*o", 7, 42);
  one_test_2 ("%.*o", -7, 42);
  one_test_3 ("%*.*o", 10, 7, 42);
  one_test_3 ("%*.*o", 10, -7, 42);
  one_test_3 ("%*.*o", -10, 7, 42);
  one_test_3 ("%*.*o", -10, -7, 42);
  one_test_2 ("%#*o", 7, 42);
  one_test_2 ("%#*o", -7, 42);
  one_test_2 ("%#.*o", 7, 42);
  one_test_2 ("%#.*o", -7, 42);
  one_test_3 ("%#*.*o", 10, 7, 42);
  one_test_3 ("%#*.*o", 10, -7, 42);
  one_test_3 ("%#*.*o", -10, 7, 42);
  one_test_3 ("%#*.*o", -10, -7, 42);

  one_test_1 ("%s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%.0s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%.10s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%.48s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%.49s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%.50s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%.51s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%48s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%49s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%50s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%51s", "the quick brown fox jumps over the lazy dogs back");
  one_test_1 ("%-51s", "the quick brown fox jumps over the lazy dogs back");

  one_test_1 ("/%s=", "CN");

  one_test_1 ("%f", 3.1415926535);
  one_test_1 ("%f", -3.1415926535);
  one_test_1 ("%.10f", 3.1415926535);
  one_test_1 ("%.2f", 3.1415926535);
  one_test_1 ("%.1f", 3.1415926535);
  one_test_1 ("%.0f", 3.1415926535);
  one_test_1 ("%.20f", 3.1415926535);
  one_test_1 ("%10.10f", 3.1415926535);
  one_test_1 ("%10.2f", 3.1415926535);
  one_test_1 ("%10.1f", 3.1415926535);
  one_test_1 ("%10.0f", 3.1415926535);
  one_test_1 ("%30.20f", 3.1415926535);
  one_test_1 ("%10.10f", -3.1415926535);
  one_test_1 ("%10.2f", -3.1415926535);
  one_test_1 ("%10.1f", -3.1415926535);
  one_test_1 ("%10.0f", -3.1415926535);
  one_test_1 ("%30.20f", -3.1415926535);

  one_test_1 ("%-10f", 3.1415926535);
  one_test_1 ("%-10.10f", 3.1415926535);
  one_test_1 ("%-10.2f", 3.1415926535);
  one_test_1 ("%-10.1f", 3.1415926535);
  one_test_1 ("%-10.0f", 3.1415926535);
  one_test_1 ("%-30.20f", 3.1415926535);
  one_test_1 ("%-10f", -3.1415926535);
  one_test_1 ("%-10.10f", -3.1415926535);
  one_test_1 ("%-10.2f", -3.1415926535);
  one_test_1 ("%-10.1f", -3.1415926535);
  one_test_1 ("%-10.0f", -3.1415926535);
  one_test_1 ("%-30.20f", -3.1415926535);

  one_test_1 ("%#.0f",  3.1415926535);
  one_test_1 ("%#10.0f",  3.1415926535);
  one_test_1 ("%#10.0f", -3.1415926535);
  one_test_1 ("%-#10.0f",  3.1415926535);
  one_test_1 ("%-#10.0f", -3.1415926535);

  one_test_1 ("%e", 3.1415926535);
  one_test_1 ("%g", 3.1415926535);

  one_test_1 ("%a", 1.0);
  one_test_1 ("%a", -1.0);
  one_test_1 ("%a", 3.1415926535);

#ifdef HAVE_LONG_DOUBLE
  one_test_1 ("%La", (long double)1.0);
  one_test_1 ("%La", (long double)-1.0);
  one_test_1 ("%La", (long double)3.1415926535);
#endif

#ifdef __GLIBC__
  /* "%m" is a glibc extension so this _test_ will only work on such a
     system.  */
  one_test_0 ("%m");
  one_test_1 ("%d=%m", 17);
  one_test_2 ("%2$d:%m:%1$d", 42, 17);
#endif /*__GLIBC__*/

#endif /*HAVE_VASPRINTF */
}

static void
check_snprintf (void)
{
  char buffer[20];
  int rc, rc2;
  size_t tmplen, blen, blen2;

  rc = gpgrt_snprintf (buffer, 0, "%*s", 18, "");
  if (rc != 18)
    printf ("rc=%d\n", rc );
  rc = gpgrt_snprintf (buffer, sizeof buffer, "%*s", 18, "");
  if (rc != 18)
    printf ("rc=%d, strlen(buffer)=%d\n", rc, (int)strlen (buffer));
  rc = gpgrt_snprintf (buffer, sizeof buffer, "%*s", 19, "");
  if (rc != 19)
    printf ("rc=%d, strlen(buffer)=%d\n", rc, (int)strlen (buffer));
  rc = gpgrt_snprintf (buffer, sizeof buffer, "%*s", 20, "");
  if (rc != 20)
    printf ("rc=%d, strlen(buffer)=%d\n", rc, (int)strlen (buffer));
  rc = gpgrt_snprintf (buffer, sizeof buffer, "%*s", 21, "");
  if (rc != 21)
    printf ("rc=%d, strlen(buffer)=%d\n", rc, (int)strlen (buffer));

  for (tmplen = 0; tmplen <= sizeof buffer; tmplen++)
    {
      rc = gpgrt_snprintf (buffer, tmplen, "%04d%02d%02dT%02d%02d%02d",
                             1998, 9, 7, 16, 56, 05);
      blen = strlen (buffer);
      rc2 = snprintf (buffer, tmplen, "%04d%02d%02dT%02d%02d%02d",
                     1998, 9, 7, 16, 56, 05);
      blen2 = strlen (buffer);
      if (rc != rc2 || blen != blen2)
        printf ("snprintf test with len %u gives %d instead of %d (%u,%u)\n",
                (unsigned int)tmplen, rc, rc2,
                (unsigned int)blen, (unsigned int)blen2);
    }
}



int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts (
"usage: ./" PGM " [options]\n"
"\n"
"Options:\n"
"  --verbose      Show what is going on\n"
"  --debug        Flyswatter\n"
);
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
    }

  setlocale (LC_NUMERIC, "");
  if (!gpg_error_check_version (GPG_ERROR_VERSION))
    {
      die ("gpg_error_check_version returned an error");
      errorcount++;
    }

  run_tests ();
  check_snprintf ();

#ifdef __GLIBC__
  return !!errorcount;
#else
  return 0;
#endif
}
