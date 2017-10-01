/* gpg-error.c - Determining gpg-error error codes.
   Copyright (C) 2004, 2016 g10 Code GmbH

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
   License along with libgpg-error; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef ENABLE_NLS
#ifdef HAVE_W32_SYSTEM
# include "gettext.h"
#else
# include <libintl.h>
#endif
# define _(a) gettext (a)
# ifdef gettext_noop
#  define N_(a) gettext_noop (a)
# else
#  define N_(a) (a)
# endif
#else
# define _(a) (a)
# define N_(a) (a)
#endif

#include <gpg-error.h>


#if HAVE_W32_SYSTEM
/* The implementation follows below.  */
static char *get_locale_dir (void);
static void drop_locale_dir (char *locale_dir);
#else
#define get_locale_dir() LOCALEDIR
#define drop_locale_dir(dir)
#endif

static void
i18n_init (void)
{
#ifdef ENABLE_NLS
  char *locale_dir;

#ifdef HAVE_LC_MESSAGES
  setlocale (LC_TIME, "");
  setlocale (LC_MESSAGES, "");
#else
# ifndef HAVE_W32_SYSTEM
  setlocale (LC_ALL, "" );
# endif
#endif

  /* Note that for this program we would only need the textdomain call
     because libgpg-error already initializes itself to its locale dir
     (via gpg_err_init or a constructor).  However this is only done
     for the static standard locale and thus if the above setlocale
     calls select a different locale the bindtext below will do
     something else.  */

  locale_dir = get_locale_dir ();
  if (locale_dir)
    {
      bindtextdomain (PACKAGE, locale_dir);
      drop_locale_dir (locale_dir);
    }
  textdomain (PACKAGE);
#endif
}


#ifdef HAVE_W32_SYSTEM

#include <windows.h>


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
                 use the top directory instead.  */
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

#endif	/* HAVE_W32_SYSTEM */


const char *gpg_strerror_sym (gpg_error_t err);
const char *gpg_strsource_sym (gpg_error_t err);


static int
get_err_from_number (char *str, gpg_error_t *err)
{
  unsigned long nr;
  char *tail;

  gpg_err_set_errno (0);
  nr = strtoul (str, &tail, 0);
  if (errno)
    return 0;

  if (nr > UINT_MAX)
    return 0;

  if (*tail)
    {
      unsigned long cnr = strtoul (tail + 1, &tail, 0);
      if (errno || *tail)
	return 0;

      if (nr >= GPG_ERR_SOURCE_DIM || cnr >= GPG_ERR_CODE_DIM)
	return 0;

      nr = gpg_err_make (nr, cnr);
    }

  *err = (unsigned int) nr;
  return 1;
}


static int
get_err_from_symbol_one (char *str, gpg_error_t *err,
			 int *have_source, int *have_code)
{
  static const char src_prefix[] = "GPG_ERR_SOURCE_";
  static const char code_prefix[] = "GPG_ERR_";

  if (!strncasecmp (src_prefix, str, sizeof (src_prefix) - 1))
    {
      gpg_err_source_t src;

      if (*have_source)
	return 0;
      *have_source = 1;
      str += sizeof (src_prefix) - 1;

      for (src = 0; src < GPG_ERR_SOURCE_DIM; src++)
	{
	  const char *src_sym;

	  src_sym = gpg_strsource_sym (src << GPG_ERR_SOURCE_SHIFT);
	  if (src_sym && !strcasecmp (str, src_sym + sizeof (src_prefix) - 1))
	    {
	      *err |= src << GPG_ERR_SOURCE_SHIFT;
	      return 1;
	    }
	}
    }
  else if (!strncasecmp (code_prefix, str, sizeof (code_prefix) - 1))
    {
      gpg_err_code_t code;

      if (*have_code)
	return 0;
      *have_code = 1;
      str += sizeof (code_prefix) - 1;

      for (code = 0; code < GPG_ERR_CODE_DIM; code++)
	{
	  const char *code_sym = gpg_strerror_sym (code);
	  if (code_sym
	      && !strcasecmp (str, code_sym + sizeof (code_prefix) - 1))
	    {
	      *err |= code;
	      return 1;
	    }
	}
    }
  return 0;
}


static int
get_err_from_symbol (char *str, gpg_error_t *err)
{
  char *str2 = str;
  int have_source = 0;
  int have_code = 0;
  int ret;
  char *saved_pos = NULL;
  char saved_char;

  *err = 0;
  while (*str2 && ((*str2 >= 'A' && *str2 <= 'Z')
		   || (*str2 >= '0' && *str2 <= '9')
		   || *str2 == '_'))
    str2++;
  if (*str2)
    {
      saved_pos = str2;
      saved_char = *str2;
      *str2 = '\0';
      str2++;
    }
  else
    str2 = NULL;

  ret = get_err_from_symbol_one (str, err, &have_source, &have_code);
  if (ret && str2)
    ret = get_err_from_symbol_one (str2, err, &have_source, &have_code);

  if (saved_pos)
    *saved_pos = saved_char;
  return ret;
}


static int
get_err_from_str_one (char *str, gpg_error_t *err,
		      int *have_source, int *have_code)
{
  gpg_err_source_t src;
  gpg_err_code_t code;

  for (src = 0; src < GPG_ERR_SOURCE_DIM; src++)
    {
      const char *src_str = gpg_strsource (src << GPG_ERR_SOURCE_SHIFT);
      if (src_str && !strcasecmp (str, src_str))
	{
	  if (*have_source)
	    return 0;

	  *have_source = 1;
	  *err |= src << GPG_ERR_SOURCE_SHIFT;
	  return 1;
	}
    }

  for (code = 0; code < GPG_ERR_CODE_DIM; code++)
    {
      const char *code_str = gpg_strerror (code);
      if (code_str && !strcasecmp (str, code_str))
	{
	  if (*have_code)
	    return 0;

	  *have_code = 1;
	  *err |= code;
	  return 1;
	}
    }

  return 0;
}


static int
get_err_from_str (char *str, gpg_error_t *err)
{
  char *str2 = str;
  int have_source = 0;
  int have_code = 0;
  int ret;
  char *saved_pos = NULL;
  char saved_char = 0; /* (avoid warning) */

  *err = 0;
  ret = get_err_from_str_one (str, err, &have_source, &have_code);
  if (ret)
    return ret;

  while (*str2 && ((*str2 >= 'A' && *str2 <= 'Z')
		   || (*str2 >= 'a' && *str2 <= 'z')
		   || (*str2 >= '0' && *str2 <= '9')
		   || *str2 == '_'))
    str2++;
  if (*str2)
    {
      saved_pos = str2;
      saved_char = *str2;
      *((char *) str2) = '\0';
      str2++;
      while (*str2 && !((*str2 >= 'A' && *str2 <= 'Z')
			|| (*str2 >= 'a' && *str2 <= 'z')
			|| (*str2 >= '0' && *str2 <= '9')
			|| *str2 == '_'))
	str2++;
    }
  else
    str2 = NULL;

  ret = get_err_from_str_one (str, err, &have_source, &have_code);
  if (ret && str2)
    ret = get_err_from_str_one (str2, err, &have_source, &have_code);

  if (saved_pos)
    *saved_pos = saved_char;
  return ret;
}


static void
print_desc (const char *symbol)
{
  static int initialized;
  static FILE *fp;
  char line[512];
  char *p;
  int indesc = 0;
  int blanklines = 0;
  int last_was_keyword = 0;

  if (!symbol)
    return;

  if (!initialized)
    {
      initialized = 1;
      fp = fopen (PKGDATADIR "/errorref.txt", "r");
    }
  if (!fp)
    return;
  rewind (fp);
  while (fgets (line, sizeof line, fp))
    {
      if (*line == '#')
        continue;
      if (*line && line[strlen(line)-1] == '\n')
        line[strlen(line)-1] = 0;

      if (!strncmp (line, "GPG_ERR_", 8))
        {
          if (indesc == 1 && last_was_keyword)
            continue; /* Skip keywords immediately following a matched
                       * keyword.  */
          last_was_keyword = 1;

          indesc = 0;
          p = strchr (line, ' ');
          if (!p)
            continue;
          *p = 0;
          if (!strcmp (line, symbol))
            {
              indesc = 1;
              continue; /* Skip this line.  */
            }
        }
      else
        last_was_keyword = 0;
      if (!indesc)
        continue;
      if (indesc == 1 && !*line)
        continue; /* Skip leading empty lines in a description.  */
      if (indesc == 1)
        putchar ('\n'); /* One leading empty line.  */
      indesc = 2;
      if (!*line)
        {
          blanklines++;
          continue;
        }
      for (; blanklines; blanklines--)
        putchar ('\n');
      printf ("%s\n", line);
    }
  putchar ('\n'); /* One trailing blank line.  */
}





static int
show_usage (const char *name)
{
  if (name)
    {
      fprintf (stderr, _("Usage: %s GPG-ERROR [...]\n"),
               strrchr (name,'/')? (strrchr (name, '/')+1): name);
      exit (1);
    }

  fputs ("gpg-error (" PACKAGE_NAME ") " PACKAGE_VERSION "\n", stdout);
  fputs ("Options:\n"
         "  --version      Print version\n"
         "  --lib-version  Print library version\n"
         "  --help         Print this help\n"
         "  --list         Print all error codes\n"
         "  --defines      Print all error codes as #define lines\n"
         "  --desc         Print with error description\n"
         , stdout);
  exit (0);
}



int
main (int argc, char *argv[])
{
  const char *pgmname = argv[0];
  int last_argc = -1;
  int i;
  int listmode = 0;
  int desc = 0;
  const char *source_sym;
  const char *error_sym;
  gpg_error_t err;

  gpgrt_init ();
  i18n_init ();


  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--version"))
        {
          fputs ("gpg-error (" PACKAGE_NAME ") " PACKAGE_VERSION "\n", stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--help"))
        {
          show_usage (NULL);
        }
      else if (!strcmp (*argv, "--lib-version"))
        {
          argc--; argv++;
          printf ("Version from header: %s (0x%06x)\n",
                  GPG_ERROR_VERSION, GPG_ERROR_VERSION_NUMBER);
          printf ("Version from binary: %s\n", gpg_error_check_version (NULL));
          printf ("Copyright blurb ...:%s\n",
                  gpg_error_check_version ("\x01\x01"));
          exit (0);
        }
      else if (!strcmp (*argv, "--list"))
        {
          listmode = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--defines"))
        {
          listmode = 2;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--desc"))
        {
          desc = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (pgmname);
    }

  if ((argc && listmode) || (!argc && !listmode))
    show_usage (pgmname);


  if (listmode == 1)
    {
      for (i=0; i <  GPG_ERR_SOURCE_DIM; i++)
        {
          /* We use error code 1 because gpg_err_make requires a
             non-zero error code. */
          err = gpg_err_make (i, 1);
          err -= 1;
	  source_sym = gpg_strsource_sym (err);
          if (source_sym)
            {
              printf ("%u = (%u, -) = (%s, -) = (%s, -)\n",
                      err, gpg_err_source (err),
                      source_sym, gpg_strsource (err));
              if (desc)
                print_desc (source_sym);
            }
        }
      for (i=0; i <  GPG_ERR_CODE_DIM; i++)
        {
          err = gpg_err_make (GPG_ERR_SOURCE_UNKNOWN, i);
	  error_sym = gpg_strerror_sym (err);
          if (error_sym)
            {
              printf ("%u = (-, %u) = (-, %s) = (-, %s)\n",
                      err, gpg_err_code (err),
                      error_sym, gpg_strerror (err));
              if (desc)
                print_desc (error_sym);
            }
        }
    }
  else if (listmode == 2)
    {
      int n, nmax;

      for (i=0, nmax=0; i <  GPG_ERR_SOURCE_DIM; i++)
        {
          err = gpg_err_make (i, 1);
	  source_sym = gpg_strsource_sym (err);
          if (source_sym)
            {
              n = strlen (source_sym);
              if (n > nmax)
                nmax = n;
            }
        }
      for (i=0; i <  GPG_ERR_SOURCE_DIM; i++)
        {
          err = gpg_err_make (i, 1);
	  source_sym = gpg_strsource_sym (err);
          if (source_sym)
            printf ("#define %-*s %3u\n", nmax,source_sym,gpg_err_source (err));
        }


      for (i=0, nmax = 0; i <  GPG_ERR_CODE_DIM; i++)
        {
          err = gpg_err_make (GPG_ERR_SOURCE_UNKNOWN, i);
	  error_sym = gpg_strerror_sym (err);
          if (error_sym)
            {
              n = strlen (error_sym);
              if (n > nmax)
                nmax = n;
            }
        }
      for (i=0; i <  GPG_ERR_CODE_DIM; i++)
        {
          err = gpg_err_make (GPG_ERR_SOURCE_UNKNOWN, i);
	  error_sym = gpg_strerror_sym (err);
          if (error_sym)
            printf ("#define %-*s %5u\n", nmax, error_sym, gpg_err_code (err));
        }
    }
  else /* Standard mode.  */
    {
      for (i=0; i < argc; i++)
        {
          if (get_err_from_number (argv[i], &err)
              || get_err_from_symbol (argv[i], &err)
              || get_err_from_str (argv[i], &err))
            {
              source_sym = gpg_strsource_sym (err);
              error_sym = gpg_strerror_sym (err);

              printf ("%u = (%u, %u) = (%s, %s) = (%s, %s)\n",
                      err, gpg_err_source (err), gpg_err_code (err),
                      source_sym ? source_sym : "-", error_sym ? error_sym:"-",
                      gpg_strsource (err), gpg_strerror (err));
              if (desc)
                print_desc (error_sym);
            }
          else
            fprintf (stderr, _("%s: warning: could not recognize %s\n"),
                     argv[0], argv[i]);
        }
    }

  exit (0);
}
