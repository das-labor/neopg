/* utf8conf.c -  UTF8 character set conversion
 * Copyright (C) 1994, 1998, 1999, 2000, 2001, 2003, 2006,
 *               2008, 2010  Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif
#include <errno.h>

#include <boost/format.hpp>
#include <boost/locale.hpp>

#include "common-defs.h"
#include "i18n.h"
#include "stringhelp.h"
#include "utf8conv.h"
#include "util.h"

#ifndef MB_LEN_MAX
#define MB_LEN_MAX 16
#endif

static const char *active_charset_name = "iso-8859-1";
static int no_translation; /* Set to true if we let simply pass through. */
static int use_conv;       /* use conversion */

/* Error handler for iconv failures. This is needed to not clutter the
   output with repeated diagnostics about a missing conversion. */
static void handle_conv_error(const char *to, const char *from,
                              int use_fallback) {
  if (errno == EINVAL) {
    static int shown1, shown2;
    int x;

    if (to && !strcmp(to, "utf-8")) {
      x = shown1;
      shown1 = 1;
    } else {
      x = shown2;
      shown2 = 1;
    }

    if (!x)
      log_info(_("conversion from '%s' to '%s' not available\n"), from, to);
  } else {
    static int shown;

    if (!shown) log_info(_("conversion failed: %s\n"), strerror(errno));
    shown = 1;
  }

  if (use_fallback) {
    /* To avoid further error messages we fallback to UTF-8 for the
       native encoding.  Nowadays this seems to be the best bet in
       case of errors from iconv or nl_langinfo.  */
    active_charset_name = "utf-8";
    no_translation = 0;
    use_conv = 0;
  }
}

int set_native_charset(const char *newset) {
  const char *full_newset;

  if (!newset) {
#ifdef HAVE_ANDROID_SYSTEM
    newset = "utf-8";
#elif defined HAVE_W32_SYSTEM
    static char codepage[30];
    unsigned int cpno;
    const char *aliases;

    /* We are a console program thus we need to use the
       GetConsoleOutputCP function and not the GetACP which
       would give the codepage for a GUI program.  Note this is not
       a bulletproof detection because GetConsoleCP might return a
       different one for console input.  Not sure how to cope with
       that.  If the console Code page is not known we fall back to
       the system code page.  */
    cpno = GetConsoleOutputCP();
    if (!cpno) cpno = GetACP();
    sprintf(codepage, "CP%u", cpno);
    /* Resolve alias.  We use a long string string and not the usual
       array to optimize if the code is taken to a DSO.  Taken from
       libiconv 1.9.2. */
    newset = codepage;
    for (aliases = ("CP936"
                    "\0"
                    "GBK"
                    "\0"
                    "CP1361"
                    "\0"
                    "JOHAB"
                    "\0"
                    "CP20127"
                    "\0"
                    "ASCII"
                    "\0"
                    "CP20866"
                    "\0"
                    "KOI8-R"
                    "\0"
                    "CP21866"
                    "\0"
                    "KOI8-RU"
                    "\0"
                    "CP28591"
                    "\0"
                    "ISO-8859-1"
                    "\0"
                    "CP28592"
                    "\0"
                    "ISO-8859-2"
                    "\0"
                    "CP28593"
                    "\0"
                    "ISO-8859-3"
                    "\0"
                    "CP28594"
                    "\0"
                    "ISO-8859-4"
                    "\0"
                    "CP28595"
                    "\0"
                    "ISO-8859-5"
                    "\0"
                    "CP28596"
                    "\0"
                    "ISO-8859-6"
                    "\0"
                    "CP28597"
                    "\0"
                    "ISO-8859-7"
                    "\0"
                    "CP28598"
                    "\0"
                    "ISO-8859-8"
                    "\0"
                    "CP28599"
                    "\0"
                    "ISO-8859-9"
                    "\0"
                    "CP28605"
                    "\0"
                    "ISO-8859-15"
                    "\0"
                    "CP65001"
                    "\0"
                    "UTF-8"
                    "\0");
         *aliases;
         aliases += strlen(aliases) + 1, aliases += strlen(aliases) + 1) {
      if (!strcmp(codepage, aliases) || (*aliases == '*' && !aliases[1])) {
        newset = aliases + strlen(aliases) + 1;
        break;
      }
    }

#else /*!HAVE_W32_SYSTEM && !HAVE_ANDROID_SYSTEM*/

#ifdef HAVE_LANGINFO_CODESET
    newset = nl_langinfo(CODESET);
#else  /*!HAVE_LANGINFO_CODESET*/
    /* Try to get the used charset from environment variables.  */
    static char codepage[30];
    const char *lc, *dot, *mod;

    strcpy(codepage, "iso-8859-1");
    lc = getenv("LC_ALL");
    if (!lc || !*lc) {
      lc = getenv("LC_CTYPE");
      if (!lc || !*lc) lc = getenv("LANG");
    }
    if (lc && *lc) {
      dot = strchr(lc, '.');
      if (dot) {
        mod = strchr(++dot, '@');
        if (!mod) mod = dot + strlen(dot);
        if (mod - dot < sizeof codepage && dot != mod) {
          memcpy(codepage, dot, mod - dot);
          codepage[mod - dot] = 0;
        }
      }
    }
    newset = codepage;
#endif /*!HAVE_LANGINFO_CODESET*/
#endif /*!HAVE_W32_SYSTEM && !HAVE_ANDROID_SYSTEM*/
  }

  full_newset = newset;
  if (strlen(newset) > 3 && !ascii_memcasecmp(newset, "iso", 3)) {
    newset += 3;
    if (*newset == '-' || *newset == '_') newset++;
  }

  /* Note that we silently assume that plain ASCII is actually meant
     as Latin-1.  This makes sense because many Unix system don't have
     their locale set up properly and thus would get annoying error
     messages and we have to handle all the "bug" reports. Latin-1 has
     traditionally been the character set used for 8 bit characters on
     Unix systems. */
  if (!*newset || !ascii_strcasecmp(newset, "8859-1") ||
      !ascii_strcasecmp(newset, "646") || !ascii_strcasecmp(newset, "ASCII") ||
      !ascii_strcasecmp(newset, "ANSI_X3.4-1968")) {
    active_charset_name = "iso-8859-1";
    no_translation = 0;
    use_conv = 0;
  } else if (!ascii_strcasecmp(newset, "utf8") ||
             !ascii_strcasecmp(newset, "utf-8")) {
    active_charset_name = "utf-8";
    no_translation = 1;
    use_conv = 0;
  } else {
    const std::string test = "test";
    try {
      std::string test_native =
          boost::locale::conv::from_utf<char>(test, full_newset);
      std::string test_utf8 =
          boost::locale::conv::to_utf<char>(test_native, full_newset);
      if (test != test_utf8) throw std::runtime_error("conversion failed");
    } catch (std::runtime_error &e) {
      return -1;
    }

    active_charset_name = full_newset;
    no_translation = 0;
    use_conv = 1;
  }
  return 0;
}

const char *get_native_charset() { return active_charset_name; }

/* Return true if the native charset is utf-8.  */
int is_native_utf8(void) { return no_translation; }

/* Convert string, which is in native encoding to UTF8 and return a
   new allocated UTF-8 string.  This function terminates the process
   on memory shortage.  */
std::string native_to_utf8(const std::string &orig_string) {
  return boost::locale::conv::to_utf<char>(orig_string, active_charset_name);
}

static std::string do_utf8_to_native(const char *string, size_t length,
                                     int delim, int with_conv) {
  int nleft;
  int i;
  unsigned char encbuf[8];
  int encidx;
  const unsigned char *s;
  size_t n;
  char *p = NULL;
  unsigned long val = 0;
  size_t slen;
  int resync = 0;
  std::stringstream buffer;

  for (slen = length, nleft = encidx = 0, s = (const unsigned char *)string;
       slen; s++, slen--) {
    if (resync) {
      if (!(*s < 128 || (*s >= 0xc0 && *s <= 0xfd))) {
        /* Still invalid. */
        buffer << boost::format("\\x%02x") % *s;
        continue;
      }
      resync = 0;
    }
    if (!nleft) {
      if (!(*s & 0x80)) {
        /* Plain ascii. */
        if (delim != -1 &&
            (*s < 0x20 || *s == 0x7f || *s == delim || (delim && *s == '\\'))) {
          buffer << '\\';
          switch (*s) {
            case '\n':
              buffer << 'n';
              break;
            case '\r':
              buffer << 'r';
              break;
            case '\f':
              buffer << 'f';
              break;
            case '\v':
              buffer << 'v';
              break;
            case '\b':
              buffer << 'b';
              break;
            case 0:
              buffer << '0';
              break;
            default:
              buffer << boost::format("x%02x") % *s;
              break;
          }
        } else
          buffer << (char)*s;
      } else if ((*s & 0xe0) == 0xc0) /* 110x xxxx */
      {
        val = *s & 0x1f;
        nleft = 1;
        encidx = 0;
        encbuf[encidx++] = *s;
      } else if ((*s & 0xf0) == 0xe0) /* 1110 xxxx */
      {
        val = *s & 0x0f;
        nleft = 2;
        encidx = 0;
        encbuf[encidx++] = *s;
      } else if ((*s & 0xf8) == 0xf0) /* 1111 0xxx */
      {
        val = *s & 0x07;
        nleft = 3;
        encidx = 0;
        encbuf[encidx++] = *s;
      } else if ((*s & 0xfc) == 0xf8) /* 1111 10xx */
      {
        val = *s & 0x03;
        nleft = 4;
        encidx = 0;
        encbuf[encidx++] = *s;
      } else if ((*s & 0xfe) == 0xfc) /* 1111 110x */
      {
        val = *s & 0x01;
        nleft = 5;
        encidx = 0;
        encbuf[encidx++] = *s;
      } else /* Invalid encoding: print as \xNN. */
      {
        buffer << boost::format("\\x%02x") % *s;
        resync = 1;
      }
    } else if (*s < 0x80 || *s >= 0xc0) /* Invalid utf-8 */
    {
      for (i = 0; i < encidx; i++) {
        buffer << boost::format("\\x%02x") % encbuf[i];
        buffer << boost::format("\\x%02x") % *s;
      }
      nleft = 0;
      encidx = 0;
      resync = 1;
    } else {
      encbuf[encidx++] = *s;
      val <<= 6;
      val |= *s & 0x3f;
      if (!--nleft) /* Ready. */
      {
        if (no_translation) {
          for (i = 0; i < encidx; i++) buffer << (char)encbuf[i];
          encidx = 0;
        } else if (with_conv) {
          /* Our strategy for using iconv is a bit strange but it
             better keeps compatibility with previous versions in
             regard to how invalid encodings are displayed.  What we
             do is to keep the utf-8 as is and have the real
             translation step then at the end.  Yes, I know that
             this is ugly.  However we are short of the 1.4 release
             and for this branch we should not mess too much around
             with iconv things.  One reason for this is that we
             don't know enough about non-GNU iconv implementation
             and want to minimize the risk of breaking the code on
             too many platforms.  */
          for (i = 0; i < encidx; i++) buffer << (char)encbuf[i];
          n += encidx;
          encidx = 0;
        } else /* Latin-1 case. */
        {
          if (val >= 0x80 && val < 256) {
            /* We can simply print this character */
            buffer << (char)val;
          } else {
            /* We do not have a translation: print utf8. */
            for (i = 0; i < encidx; i++) {
              buffer << boost::format("\\x%02x") % encbuf[i];
            }
            encidx = 0;
          }
        }
      }
    }
  }
  std::string output = buffer.str();
  if (with_conv) {
    /* Note: See above for comments.  */
    try {
      std::string result =
          boost::locale::conv::from_utf<char>(output, active_charset_name);
      return result;
    } catch (boost::locale::conv::invalid_charset_error &e) {
      handle_conv_error(active_charset_name, "utf-8", 1);
      return utf8_to_native(string, length, delim);
    } catch (boost::locale::conv::conversion_error &e) {
      static int shown;

      if (!shown)
        log_info(_("conversion from '%s' to '%s' failed\n"), "utf-8",
                 active_charset_name);
      shown = 1;
      return do_utf8_to_native(string, length, delim, 0);
    }
  } else {
    return output;
  }
}

/* Convert string, which is in UTF-8 to native encoding.  Replace
   illegal encodings by some "\xnn" and quote all control
   characters. A character with value DELIM will always be quoted, it
   must be a vanilla ASCII character.  A DELIM value of -1 is special:
   it disables all quoting of control characters.  This function
   terminates the process on memory shortage.  */
std::string utf8_to_native(const char *string, size_t length, int delim) {
  return do_utf8_to_native(string, length, delim, use_conv);
}

#ifdef HAVE_W32_SYSTEM
/* Return a malloced string encoded for CODEPAGE from the wide char input
   string STRING.  Caller must free this value.  Returns NULL and sets
   ERRNO on failure.  Calling this function with STRING set to NULL is
   not defined.  */
static char *wchar_to_cp(const wchar_t *string, unsigned int codepage) {
  int n;
  char *result;

  n = WideCharToMultiByte(codepage, 0, string, -1, NULL, 0, NULL, NULL);
  if (n < 0) {
    gpg_err_set_errno(EINVAL);
    return NULL;
  }

  result = xtrymalloc(n + 1);
  if (!result) return NULL;

  n = WideCharToMultiByte(codepage, 0, string, -1, result, n, NULL, NULL);
  if (n < 0) {
    xfree(result);
    gpg_err_set_errno(EINVAL);
    result = NULL;
  }
  return result;
}

/* Return a malloced wide char string from a CODEPAGE encoded input
   string STRING.  Caller must free this value.  Returns NULL and sets
   ERRNO on failure.  Calling this function with STRING set to NULL is
   not defined.  */
static wchar_t *cp_to_wchar(const char *string, unsigned int codepage) {
  int n;
  size_t nbytes;
  wchar_t *result;

  n = MultiByteToWideChar(codepage, 0, string, -1, NULL, 0);
  if (n < 0) {
    gpg_err_set_errno(EINVAL);
    return NULL;
  }

  nbytes = (size_t)(n + 1) * sizeof(*result);
  if (nbytes / sizeof(*result) != (n + 1)) {
    gpg_err_set_errno(ENOMEM);
    return NULL;
  }
  result = xtrymalloc(nbytes);
  if (!result) return NULL;

  n = MultiByteToWideChar(codepage, 0, string, -1, result, n);
  if (n < 0) {
    xfree(result);
    gpg_err_set_errno(EINVAL);
    result = NULL;
  }
  return result;
}

/* Return a malloced string encoded in the active code page from the
 * wide char input string STRING.  Caller must free this value.
 * Returns NULL and sets ERRNO on failure.  Calling this function with
 * STRING set to NULL is not defined.  */
char *wchar_to_native(const wchar_t *string) {
  return wchar_to_cp(string, CP_ACP);
}

/* Return a malloced wide char string from an UTF-8 encoded input
 * string STRING.  Caller must free this value.  Returns NULL and sets
 * ERRNO on failure.  Calling this function with STRING set to NULL is
 * not defined.  */
wchar_t *native_to_wchar(const char *string) {
  return cp_to_wchar(string, CP_ACP);
}

/* Return a malloced string encoded in UTF-8 from the wide char input
 * string STRING.  Caller must free this value.  Returns NULL and sets
 * ERRNO on failure.  Calling this function with STRING set to NULL is
 * not defined.  */
char *wchar_to_utf8(const wchar_t *string) {
  return wchar_to_cp(string, CP_UTF8);
}

/* Return a malloced wide char string from an UTF-8 encoded input
 * string STRING.  Caller must free this value.  Returns NULL and sets
 * ERRNO on failure.  Calling this function with STRING set to NULL is
 * not defined.  */
wchar_t *utf8_to_wchar(const char *string) {
  return cp_to_wchar(string, CP_UTF8);
}

#endif /*HAVE_W32_SYSTEM*/
