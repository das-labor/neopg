/* homedir.c - Setup the home directory.
 * Copyright (C) 2004, 2006, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2013, 2016 Werner Koch
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
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_W32_SYSTEM
#include <winsock2.h> /* Due to the stupid mingw64 requirement to
                           include this header before windows.h which
                           is often implicitly included.  */
#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_COMMON_APPDATA
#define CSIDL_COMMON_APPDATA 0x0023
#endif
#ifndef CSIDL_FLAG_CREATE
#define CSIDL_FLAG_CREATE 0x8000
#endif
#endif /*HAVE_W32_SYSTEM*/

#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif

#include "sysutils.h"
#include "util.h"

/* The GnuPG homedir.  This is only accessed by the functions
 * gnupg_homedir and gnupg_set_homedir.  Malloced.  */
static char *the_gnupg_homedir;

/* Flag indicating that home directory is not the default one.  */
static byte non_default_homedir;

#ifdef HAVE_W32_SYSTEM
/* This flag is true if this process' binary has been installed under
   bin and not in the root directory as often used before GnuPG 2.1. */
static byte w32_bin_is_bin;
#endif /*HAVE_W32_SYSTEM*/

#ifdef HAVE_W32_SYSTEM
static const char *w32_rootdir(void);
#endif

#ifdef HAVE_W32_SYSTEM
static void w32_try_mkdir(const char *dir) { CreateDirectory(dir, NULL); }
#endif

/* This is a helper function to load a Windows function from either of
   one DLLs. */
#ifdef HAVE_W32_SYSTEM
static HRESULT w32_shgetfolderpath(HWND a, int b, HANDLE c, DWORD d, LPSTR e) {
  static int initialized;
  static HRESULT(WINAPI * func)(HWND, int, HANDLE, DWORD, LPSTR);

  if (!initialized) {
    static char *dllnames[] = {"shell32.dll", "shfolder.dll", NULL};
    void *handle;
    int i;

    initialized = 1;

    for (i = 0, handle = NULL; !handle && dllnames[i]; i++) {
      handle = dlopen(dllnames[i], RTLD_LAZY);
      if (handle) {
        func = dlsym(handle, "SHGetFolderPathA");
        if (!func) {
          dlclose(handle);
          handle = NULL;
        }
      }
    }
  }

  if (func)
    return func(a, b, c, d, e);
  else
    return -1;
}
#endif /*HAVE_W32_SYSTEM*/

/* Check whether DIR is the default homedir.  */
static int is_gnupg_default_homedir(const char *dir) {
  int result;
  char *a = make_absfilename(dir, NULL);
  char *b = make_absfilename(GNUPG_DEFAULT_HOMEDIR, NULL);
  result = !compare_filenames(a, b);
  xfree(b);
  xfree(a);
  return result;
}

/* Get the standard home directory.  In general this function should
   not be used as it does not consider a registry value (under W32) or
   the GNUPGHOME environment variable.  It is better to use
   default_homedir(). */
const char *standard_homedir(void) {
#ifdef HAVE_W32_SYSTEM
  static const char *dir;

  if (!dir) {
    const char *rdir;

    rdir = w32_rootdir();
    if (w32_portable_app) {
      dir = xstrconcat(rdir, DIRSEP_S "home", NULL);
    } else {
      char path[MAX_PATH];

      /* It might be better to use LOCAL_APPDATA because this is
         defined as "non roaming" and thus more likely to be kept
         locally.  For private keys this is desired.  However,
         given that many users copy private keys anyway forth and
         back, using a system roaming services might be better
         than to let them do it manually.  A security conscious
         user will anyway use the registry entry to have better
         control.  */
      if (w32_shgetfolderpath(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0,
                              path) >= 0) {
        char *tmp = xmalloc(strlen(path) + 6 + 1);
        strcpy(stpcpy(tmp, path), "\\gnupg");
        dir = tmp;

        /* Try to create the directory if it does not yet exists.  */
        if (access(dir, F_OK)) w32_try_mkdir(dir);
      } else
        dir = GNUPG_DEFAULT_HOMEDIR;
    }
  }
  return dir;
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_DEFAULT_HOMEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

/* Set up the default home directory.  The usual --homedir option
   should be parsed later. */
const char *default_homedir(void) {
  const char *dir;

#ifdef HAVE_W32_SYSTEM
  /* For a portable application we only use the standard homedir.  */
  w32_rootdir();
  if (w32_portable_app) return standard_homedir();
#endif /*HAVE_W32_SYSTEM*/

  dir = getenv("GNUPGHOME");
#ifdef HAVE_W32_SYSTEM
  if (!dir || !*dir) {
    static const char *saved_dir;

    if (!saved_dir) {
      if (!dir || !*dir) {
        char *tmp;

        tmp = read_w32_registry_string(NULL, GNUPG_REGISTRY_DIR, "HomeDir");
        if (tmp && !*tmp) {
          xfree(tmp);
          tmp = NULL;
        }
        if (tmp) saved_dir = tmp;
      }

      if (!saved_dir) saved_dir = standard_homedir();
    }
    dir = saved_dir;
  }
#endif /*HAVE_W32_SYSTEM*/
  if (!dir || !*dir)
    dir = GNUPG_DEFAULT_HOMEDIR;
  else if (!is_gnupg_default_homedir(dir))
    non_default_homedir = 1;

  return dir;
}

#ifdef HAVE_W32_SYSTEM
/* Determine the root directory of the gnupg installation on Windows.  */
static const char *w32_rootdir(void) {
  static int got_dir;
  static char dir[MAX_PATH + 5];

  if (!got_dir) {
    char *p;
    int rc;
    wchar_t wdir[MAX_PATH + 5];

    rc = GetModuleFileNameW(NULL, wdir, MAX_PATH);
    if (rc &&
        WideCharToMultiByte(CP_UTF8, 0, wdir, -1, dir, MAX_PATH - 4, NULL,
                            NULL) < 0)
      rc = 0;
    if (!rc) {
      log_debug("GetModuleFileName failed: %s\n", w32_strerror(-1));
      *dir = 0;
    }
    got_dir = 1;
    p = strrchr(dir, DIRSEP_C);
    if (p) {
      *p = 0;

      /* If we are installed below "bin" we strip that and use
         the top directory instead.  */
      p = strrchr(dir, DIRSEP_C);
      if (p && !strcmp(p + 1, "bin")) {
        *p = 0;
        w32_bin_is_bin = 1;
      }
    }
    if (!p) {
      log_debug("bad filename '%s' returned for this process\n", dir);
      *dir = 0;
    }
  }

  if (*dir) return dir;
  /* Fallback to the hardwired value. */
  return GNUPG_LIBEXECDIR;
}

static const char *w32_commondir(void) {
  static char *dir;

  if (!dir) {
    const char *rdir;
    char path[MAX_PATH];

    /* Make sure that w32_rootdir has been called so that we are
       able to check the portable application flag.  The common dir
       is the identical to the rootdir.  In that case there is also
       no need to strdup its value.  */
    rdir = w32_rootdir();
    if (w32_portable_app) return rdir;

    if (w32_shgetfolderpath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path) >= 0) {
      char *tmp = xmalloc(strlen(path) + 4 + 1);
      strcpy(stpcpy(tmp, path), "\\GNU");
      dir = tmp;
      /* No auto create of the directory.  Either the installer or
         the admin has to create these directories.  */
    } else {
      /* Ooops: Not defined - probably an old Windows version.
         Use the installation directory instead.  */
      dir = xstrdup(rdir);
    }
  }

  return dir;
}
#endif /*HAVE_W32_SYSTEM*/

/* Change the homedir.  Some care must be taken to set this early
 * enough because previous calls to gnupg_homedir may else return a
 * different string.  */
void gnupg_set_homedir(const char *newdir) {
  if (!newdir || !*newdir)
    newdir = default_homedir();
  else if (!is_gnupg_default_homedir(newdir))
    non_default_homedir = 1;
  xfree(the_gnupg_homedir);
  the_gnupg_homedir = make_absfilename(newdir, NULL);
  ;
}

/* Return the homedir.  The returned string is valid until another
 * gnupg-set-homedir call.  This is always an absolute directory name.
 * The function replaces the former global var opt.homedir.  */
const char *gnupg_homedir(void) {
  /* If a homedir has not been set, set it to the default.  */
  if (!the_gnupg_homedir)
    the_gnupg_homedir = make_absfilename(default_homedir(), NULL);
  return the_gnupg_homedir;
}

/* Return whether the home dir is the default one.  */
int gnupg_default_homedir_p(void) { return !non_default_homedir; }

/* Return the name of the sysconfdir.  This is a static string.  This
   function is required because under Windows we can't simply compile
   it in.  */
const char *gnupg_sysconfdir(void) {
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name) {
    const char *s1, *s2;
    s1 = w32_commondir();
    s2 = DIRSEP_S "etc" DIRSEP_S "gnupg";
    name = xmalloc(strlen(s1) + strlen(s2) + 1);
    strcpy(stpcpy(name, s1), s2);
  }
  return name;
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_SYSCONFDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *gnupg_bindir(void) {
#if defined(HAVE_W32_SYSTEM)
  const char *rdir;

  rdir = w32_rootdir();
  if (w32_bin_is_bin) {
    static char *name;

    if (!name) name = xstrconcat(rdir, DIRSEP_S "bin", NULL);
    return name;
  } else
    return rdir;
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_BINDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

/* Return the name of the libexec directory.  The name is allocated in
   a static area on the first use.  This function won't fail. */
const char *gnupg_libexecdir(void) {
#ifdef HAVE_W32_SYSTEM
  return gnupg_bindir();
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_LIBEXECDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *gnupg_libdir(void) {
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    name = xstrconcat(w32_rootdir(), DIRSEP_S "lib" DIRSEP_S "gnupg", NULL);
  return name;
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_LIBDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *gnupg_datadir(void) {
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    name = xstrconcat(w32_rootdir(), DIRSEP_S "share" DIRSEP_S "gnupg", NULL);
  return name;
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_DATADIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *gnupg_localedir(void) {
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    name = xstrconcat(w32_rootdir(), DIRSEP_S "share" DIRSEP_S "locale", NULL);
  return name;
#else  /*!HAVE_W32_SYSTEM*/
  return LOCALEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

/* Return the name of the cache directory.  The name is allocated in a
   static area on the first use.  Windows only: If the directory does
   not exist it is created.  */
const char *gnupg_cachedir(void) {
#ifdef HAVE_W32_SYSTEM
  static const char *dir;

  if (!dir) {
    const char *rdir;

    rdir = w32_rootdir();
    if (w32_portable_app) {
      dir = xstrconcat(rdir, DIRSEP_S, "var", DIRSEP_S, "cache", DIRSEP_S,
                       "gnupg", NULL);
    } else {
      char path[MAX_PATH];
      const char *s1[] = {"GNU", "cache", "gnupg", NULL};
      int s1_len;
      const char **comp;

      s1_len = 0;
      for (comp = s1; *comp; comp++) s1_len += 1 + strlen(*comp);

      if (w32_shgetfolderpath(NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
                              NULL, 0, path) >= 0) {
        char *tmp = xmalloc(strlen(path) + s1_len + 1);
        char *p;

        p = stpcpy(tmp, path);
        for (comp = s1; *comp; comp++) {
          p = stpcpy(p, "\\");
          p = stpcpy(p, *comp);

          if (access(tmp, F_OK)) w32_try_mkdir(tmp);
        }

        dir = tmp;
      } else {
        dir = "c:\\temp\\cache\\gnupg";
      }
    }
  }
  return dir;
#else  /*!HAVE_W32_SYSTEM*/
  return GNUPG_LOCALSTATEDIR "/cache/" PACKAGE_NAME;
#endif /*!HAVE_W32_SYSTEM*/
}

/* For sanity checks.  */
static int gnupg_module_name_called;

/* Return the file name of a helper tool.  WHICH is one of the
   GNUPG_MODULE_NAME_foo constants.  */
const char *gnupg_module_name(int which) {
  gnupg_module_name_called = 1;

#define X(a, b, c)                                                        \
  do {                                                                    \
    static char *name;                                                    \
    if (!name) name = xstrconcat(gnupg_##a(), DIRSEP_S c EXEEXT_S, NULL); \
    return name;                                                          \
  } while (0)

  switch (which) {
    case GNUPG_MODULE_NAME_AGENT:
#ifdef GNUPG_DEFAULT_AGENT
      return GNUPG_DEFAULT_AGENT;
#else
      X(bindir, "agent", "gpg-agent");
#endif

    case GNUPG_MODULE_NAME_SCDAEMON:
#ifdef GNUPG_DEFAULT_SCDAEMON
      return GNUPG_DEFAULT_SCDAEMON;
#else
      X(libexecdir, "scd", "scdaemon");
#endif

    case GNUPG_MODULE_NAME_DIRMNGR:
#ifdef GNUPG_DEFAULT_DIRMNGR
      return GNUPG_DEFAULT_DIRMNGR;
#else
      X(bindir, "dirmngr", DIRMNGR_NAME);
#endif

    case GNUPG_MODULE_NAME_PROTECT_TOOL:
#ifdef GNUPG_DEFAULT_PROTECT_TOOL
      return GNUPG_DEFAULT_PROTECT_TOOL;
#else
      X(libexecdir, "agent", "gpg-protect-tool");
#endif

    case GNUPG_MODULE_NAME_DIRMNGR_LDAP:
#ifdef GNUPG_DEFAULT_DIRMNGR_LDAP
      return GNUPG_DEFAULT_DIRMNGR_LDAP;
#else
      X(libexecdir, "dirmngr", "dirmngr_ldap");
#endif

    case GNUPG_MODULE_NAME_CHECK_PATTERN:
      X(libexecdir, "tools", "gpg-check-pattern");

    case GNUPG_MODULE_NAME_GPGSM:
      X(bindir, "sm", "gpgsm");

    case GNUPG_MODULE_NAME_GPG:
      X(bindir, "g10", GPG_NAME "2");

    case GNUPG_MODULE_NAME_GPGV:
      X(bindir, "g10", GPG_NAME "v2");

    case GNUPG_MODULE_NAME_CONNECT_AGENT:
      X(bindir, "tools", "gpg-connect-agent");

    default:
      BUG();
  }
#undef X
}
