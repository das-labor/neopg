/* init.c - Various initializations
 *	Copyright (C) 2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif

#include <gcrypt.h>
#include "util.h"
#include "i18n.h"

/* This object is used to register memory cleanup functions.
   Technically they are not needed but they can avoid frequent
   questions about un-released memory.  Note that we use the system
   malloc and not any wrappers.  */
struct mem_cleanup_item_s;
typedef struct mem_cleanup_item_s *mem_cleanup_item_t;

struct mem_cleanup_item_s
{
  mem_cleanup_item_t next;
  void (*func) (void);
};

static mem_cleanup_item_t mem_cleanup_list;


/* The default error source of the application.  This is different
   from GPG_ERR_SOURCE_DEFAULT in that it does not depend on the
   source file and thus is usable in code shared by applications.
   Note that we need to initialize it because otherwise some linkers
   (OS X at least) won't find the symbol when linking the t-*.c
   files.  */
gpg_err_source_t default_errsource = 0;


#ifdef HAVE_W32CE_SYSTEM
static void parse_std_file_handles (int *argcp, char ***argvp);
static void
sleep_on_exit (void)
{
  /* The sshd on CE swallows some of the command output.  Sleeping a
     while usually helps.  */
  Sleep (400);
}
#endif /*HAVE_W32CE_SYSTEM*/


static void
run_mem_cleanup (void)
{
  mem_cleanup_item_t next;

  while (mem_cleanup_list)
    {
      next = mem_cleanup_list->next;
      mem_cleanup_list->func ();
      free (mem_cleanup_list);
      mem_cleanup_list = next;
    }
}


void
register_mem_cleanup_func (void (*func)(void))
{
  mem_cleanup_item_t item;

  for (item = mem_cleanup_list; item; item = item->next)
    if (item->func == func)
      return; /* Function has already been registered.  */

  item = malloc (sizeof *item);
  if (item)
    {
      item->func = func;
      item->next = mem_cleanup_list;
      mem_cleanup_list = item;
    }
}


/* If STRING is not NULL write string to es_stdout or es_stderr.  MODE
   must be 1 or 2.  If STRING is NULL flush the respective stream.  */
static int
writestring_via_estream (int mode, const char *string)
{
  if (mode == 1 || mode == 2)
    {
      if (string)
        return es_fputs (string, mode == 1? es_stdout : es_stderr);
      else
        return es_fflush (mode == 1? es_stdout : es_stderr);
    }
  else
    return -1;
}


/* This function should be the first called after main.  */
void
early_system_init (void)
{
}


/* This function is to be used early at program startup to make sure
   that some subsystems are initialized.  This is in particular
   important for W32 to initialize the sockets so that our socket
   emulation code used directly as well as in libassuan may be used.
   It should best be called before any I/O is done so that setup
   required for logging is ready.  ARGCP and ARGVP are the addresses
   of the parameters given to main.  This function may modify them.

   This function should be called only via the macro
   init_common_subsystems.

   CAUTION: This might be called while running suid(root).  */
void
_init_common_subsystems (gpg_err_source_t errsource, int *argcp, char ***argvp)
{
  /* Store the error source in a global variable. */
  default_errsource = errsource;

  atexit (run_mem_cleanup);

  /* Try to auto set the character set.  */
  set_native_charset (NULL);

#ifdef HAVE_W32_SYSTEM
  /* For W32 we need to initialize the socket layer.  This is because
     we use recv and send in libassuan as well as at some other
     places.  */
  {
    WSADATA wsadat;

    WSAStartup (0x202, &wsadat);
  }
#endif

  /* Initialize the Estream library. */
  gpgrt_init ();
  gpgrt_set_alloc_func (gcry_realloc);

  /* Access the standard estreams as early as possible.  If we don't
     do this the original stdio streams may have been closed when
     _es_get_std_stream is first use and in turn it would connect to
     the bit bucket.  */
  {
    int i;
    for (i=0; i < 3; i++)
      (void)_gpgrt_get_std_stream (i);
  }

  /* --version et al shall use estream as well.  */
  argparse_register_outfnc (writestring_via_estream);

  /* Logging shall use the standard socket directory as fallback.  */
  log_set_socket_dir_cb (gnupg_socketdir);
}
