/* init.c - Initialize the GnuPG error library.
   Copyright (C) 2005, 2010 g10 Code GmbH

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
   License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "gpgrt-int.h"
#include "gettext.h"
#include "init.h"


/* Locale directory support.  */

#if _WIN32

#include <windows.h>

static int tls_index = TLS_OUT_OF_INDEXES;  /* Index for the TLS functions.  */

static char *get_locale_dir (void);
static void drop_locale_dir (char *locale_dir);

#else /*!HAVE_W32_SYSTEM*/

#define get_locale_dir() LOCALEDIR
#define drop_locale_dir(dir)

#endif /*!HAVE_W32_SYSTEM*/


/* The realloc function as set by gpgrt_set_alloc_func.  */
static void *(*custom_realloc)(void *a, size_t n);



static void
real_init (void)
{
#ifdef ENABLE_NLS
  const char *locale_dir;

  /* We only have to bind our locale directory to our text domain.  */
  locale_dir = get_locale_dir ();
  if (locale_dir)
    {
      bindtextdomain (PACKAGE, locale_dir);
      drop_locale_dir (locale_dir);
    }
#endif
  _gpgrt_estream_init ();
}

/* Initialize the library.  This function should be run early.  */
gpg_error_t
gpg_err_init (void)
{
#ifdef _WIN32
# ifdef DLL_EXPORT
  /* We always have a constructor and thus this function is called
     automatically.  Due to the way the C init code of mingw works,
     the constructors are called before our DllMain function is
     called.  The problem with that is that the TLS has not been setup
     and w32-gettext.c requires TLS.  To solve this we do nothing here
     but call the actual init code from our DllMain.  */
# else /*!DLL_EXPORT*/
  /* Note that if the TLS is actually used, we can't release the TLS
     as there is no way to know when a thread terminates (i.e. no
     thread-specific-atexit).  You are really better off to use the
     DLL! */
  if (tls_index == TLS_OUT_OF_INDEXES)
    {
      tls_index = TlsAlloc ();
      if (tls_index == TLS_OUT_OF_INDEXES)
        {
          /* No way to continue - commit suicide.  */
          abort ();
        }
      _gpg_w32__init_gettext_module ();
      real_init ();
    }
# endif /*!DLL_EXPORT*/
#else
  real_init ();
#endif
  return 0;
}


/* Deinitialize libgpg-error.  This function is only used in special
   circumstances.  No gpg-error function should be used after this
   function has been called.  A value of 0 passed for MODE
   deinitializes the entire libgpg-error, a value of 1 releases
   resources allocated for the current thread and only that thread may
   not anymore access libgpg-error after such a call.  Under Windows
   this function may be called from the DllMain function of a DLL
   which statically links to libgpg-error.  */
void
gpg_err_deinit (int mode)
{
#if defined (HAVE_W32_SYSTEM) && !defined(DLL_EXPORT)
  struct tls_space_s *tls;

  tls = TlsGetValue (tls_index);
  if (tls)
    {
      TlsSetValue (tls_index, NULL);
      LocalFree (tls);
    }

  if (mode == 0)
    {
      TlsFree (tls_index);
      tls_index = TLS_OUT_OF_INDEXES;
    }
#else
  (void)mode;
#endif
}




/* Register F as allocation function.  This function is used for all
   APIs which return an allocated buffer.  F needs to have standard
   realloc semantics.  It should be called as early as possible and
   not changed later. */
void
_gpgrt_set_alloc_func (void *(*f)(void *a, size_t n))
{
  custom_realloc = f;
}


/* The realloc to be used for data returned by the public API.  */
void *
_gpgrt_realloc (void *a, size_t n)
{
  if (custom_realloc)
    return custom_realloc (a, n);

  if (!n)
    {
      free (a);
      return NULL;
    }

  if (!a)
    return malloc (n);

  return realloc (a, n);
}


/* The malloc to be used for data returned by the public API.  */
void *
_gpgrt_malloc (size_t n)
{
  if (!n)
    n++;
  return _gpgrt_realloc (NULL, n);
}


/* The free to be used for data returned by the public API.  */
void
_gpgrt_free (void *a)
{
  _gpgrt_realloc (a, 0);
}


void
_gpg_err_set_errno (int err)
{
  errno = err;
}



/* Internal tracing functions.  Except for TRACE_FP we use flockfile
 * and funlockfile to protect their use. */
static FILE *trace_fp;
static int trace_save_errno;
static int trace_with_errno;
static const char *trace_arg_module;
static const char *trace_arg_file;
static int trace_arg_line;
static int trace_missing_lf;
static int trace_prefix_done;

void
_gpgrt_internal_trace_begin (const char *module, const char *file, int line,
                             int with_errno)
{
  int save_errno = errno;

  if (!trace_fp)
    {
      FILE *fp;
      const char *s = getenv ("GPGRT_TRACE_FILE");

      if (!s || !(fp = fopen (s, "wb")))
        fp = stderr;
      trace_fp = fp;
    }

  flockfile (trace_fp);
  trace_save_errno = save_errno;
  trace_with_errno = with_errno;
  trace_arg_module = module;
  trace_arg_file = file;
  trace_arg_line = line;
  trace_missing_lf = 0;
  trace_prefix_done = 0;
}

static void
print_internal_trace_prefix (void)
{
  if (!trace_prefix_done)
    {
      trace_prefix_done = 1;
      fprintf (trace_fp, "%s:%s:%d: ",
               trace_arg_module,/* npth_is_protected ()?"":"^",*/
               trace_arg_file, trace_arg_line);
    }
}

static void
do_internal_trace (const char *format, va_list arg_ptr)
{
  print_internal_trace_prefix ();
  vfprintf (trace_fp, format, arg_ptr);
  if (trace_with_errno)
    fprintf (trace_fp, " errno=%s", strerror (trace_save_errno));
  if (*format && format[strlen(format)-1] != '\n')
    fputc ('\n', trace_fp);
}

void
_gpgrt_internal_trace_printf (const char *format, ...)
{
  va_list arg_ptr;

  print_internal_trace_prefix ();
  va_start (arg_ptr, format) ;
  vfprintf (trace_fp, format, arg_ptr);
  va_end (arg_ptr);
  trace_missing_lf = (*format && format[strlen(format)-1] != '\n');
}


void
_gpgrt_internal_trace (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format) ;
  do_internal_trace (format, arg_ptr);
  va_end (arg_ptr);
}


void
_gpgrt_internal_trace_end (void)
{
  int save_errno = trace_save_errno;

  if (trace_missing_lf)
    fputc ('\n', trace_fp);
  funlockfile (trace_fp);
  errno = save_errno;
}



#ifdef HAVE_W32_SYSTEM
/*****************************************
 ******** Below is only Windows code. ****
 *****************************************/

static char *
get_locale_dir (void)
{
  static wchar_t moddir[MAX_PATH+5];
  char *result, *p;
  int nbytes;

  if (!GetModuleFileNameW (NULL, moddir, MAX_PATH))
    *moddir = 0;

#define SLDIR "\\share\\locale"
  if (*moddir)
    {
      nbytes = WideCharToMultiByte (CP_UTF8, 0, moddir, -1, NULL, 0, NULL, NULL);
      if (nbytes < 0)
        return NULL;

      result = malloc (nbytes + strlen (SLDIR) + 1);
      if (result)
        {
          nbytes = WideCharToMultiByte (CP_UTF8, 0, moddir, -1,
                                        result, nbytes, NULL, NULL);
          if (nbytes < 0)
            {
              free (result);
              result = NULL;
            }
          else
            {
              p = strrchr (result, '\\');
              if (p)
                *p = 0;
              /* If we are installed below "bin" strip that part and
                 use the top directory instead.

                 Background: Under Windows we don't install GnuPG
                 below bin/ but in the top directory with only share/,
                 lib/, and etc/ below it.  One of the reasons is to
                 keep the the length of the filenames at bay so not to
                 increase the limited length of the PATH envvar.
                 Another and more important reason, however, is that
                 the very first GPG versions on W32 were installed
                 into a flat directory structure and for best
                 compatibility with these versions we didn't changed
                 that later.  For WindowsCE we can right away install
                 it under bin, though.  The hack with detection of the
                 bin directory part allows us to eventually migrate to
                 such a directory layout under plain Windows without
                 the need to change libgpg-error.  */
              p = strrchr (result, '\\');
              if (p && !strcmp (p+1, "bin"))
                *p = 0;
              /* Append the static part.  */
              strcat (result, SLDIR);
            }
        }
    }
  else /* Use the old default value.  */
    {
      result = malloc (10 + strlen (SLDIR) + 1);
      if (result)
        {
          strcpy (result, "c:\\gnupg");
          strcat (result, SLDIR);
        }
    }
#undef SLDIR
  return result;
}


static void
drop_locale_dir (char *locale_dir)
{
  free (locale_dir);
}


/* Return the tls object.  This function is guaranteed to return a
   valid non-NULL object.  */
struct tls_space_s *
get_tls (void)
{
  struct tls_space_s *tls;

  tls = TlsGetValue (tls_index);
  if (!tls)
    {
      /* Called by a thread which existed before this DLL was loaded.
         Allocate the space.  */
      tls = LocalAlloc (LPTR, sizeof *tls);
      if (!tls)
        {
          /* No way to continue - commit suicide.  */
          abort ();
        }
      tls->gt_use_utf8 = 0;
      TlsSetValue (tls_index, tls);
    }

  return tls;
}


/* Entry point called by the DLL loader.  */
#ifdef DLL_EXPORT
int WINAPI
DllMain (HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
  struct tls_space_s *tls;
  (void)reserved;
  (void)hinst;

  switch (reason)
    {
    case DLL_PROCESS_ATTACH:
      tls_index = TlsAlloc ();
      if (tls_index == TLS_OUT_OF_INDEXES)
        return FALSE;
#ifndef _GPG_ERR_HAVE_CONSTRUCTOR
      /* If we have not constructors (e.g. MSC) we call it here.  */
      _gpg_w32__init_gettext_module ();
#endif
      /* falltru.  */
    case DLL_THREAD_ATTACH:
      tls = LocalAlloc (LPTR, sizeof *tls);
      if (!tls)
        return FALSE;
      tls->gt_use_utf8 = 0;
      TlsSetValue (tls_index, tls);
      if (reason == DLL_PROCESS_ATTACH)
        {
          real_init ();
        }
      break;

    case DLL_THREAD_DETACH:
      tls = TlsGetValue (tls_index);
      if (tls)
        LocalFree (tls);
      break;

    case DLL_PROCESS_DETACH:
      tls = TlsGetValue (tls_index);
      if (tls)
        LocalFree (tls);
      TlsFree (tls_index);
      break;

    default:
      break;
    }

  return TRUE;
}
#endif /*DLL_EXPORT*/

#endif /*HAVE_W32_SYSTEM*/
