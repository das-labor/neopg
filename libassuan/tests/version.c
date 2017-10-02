/* version.c - Check the version info fucntions
   Copyright (C) 2013 g10 Code GmbH

   This file is part of Assuan.

   Assuan is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   Assuan is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/assuan.h"
#include "common.h"


/*

     M A I N

*/
int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    {
      log_set_prefix (*argv);
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts (
"usage: ./version [options]\n"
"\n"
"Options:\n"
"  --verbose      Show what is going on\n"
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

  assuan_set_assuan_log_prefix (log_prefix);

  if (!assuan_check_version (ASSUAN_VERSION))
    log_error ("assuan_check_version returned an error\n");
  if (!assuan_check_version ("2.0.99"))
    log_error ("assuan_check_version returned an error for an old version\n");
  if (assuan_check_version ("15"))
    log_error ("assuan_check_version did not returned an error"
               " for a newer version\n");
  if (verbose || errorcount)
    {
      log_info ("Version from header: %s (0x%06x)\n",
                ASSUAN_VERSION, ASSUAN_VERSION_NUMBER);
      log_info ("Version from binary: %s \n", assuan_check_version (NULL));
    }

  return errorcount ? 1 : 0;
}
