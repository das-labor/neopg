/* strsource.c - Describing an error source.
   Copyright (C) 2003 g10 Code GmbH

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

#include <gpg-error.h>

#include "gettext.h"

static const char *
err_source (gpg_err_source_t source)
{
  switch (source)
    {
    case GPG_ERR_SOURCE_UNKNOWN:
      return gettext_noop("Unspecified source");
    case GPG_ERR_SOURCE_GCRYPT:
      return gettext_noop("gcrypt");
    case GPG_ERR_SOURCE_GPG:
      return gettext_noop("GnuPG");
    case GPG_ERR_SOURCE_GPGSM:
      return gettext_noop("GpgSM");
    case GPG_ERR_SOURCE_GPGAGENT:
      return gettext_noop("GPG Agent");
    case GPG_ERR_SOURCE_PINENTRY:
      return gettext_noop("Pinentry");
    case GPG_ERR_SOURCE_SCD:
      return gettext_noop("SCD");
    case GPG_ERR_SOURCE_GPGME:
      return gettext_noop("GPGME");
    case GPG_ERR_SOURCE_KEYBOX:
      return gettext_noop("Keybox");
    case GPG_ERR_SOURCE_KSBA:
      return gettext_noop("KSBA");
    case GPG_ERR_SOURCE_DIRMNGR:
      return gettext_noop("Dirmngr");
    case GPG_ERR_SOURCE_GSTI:
      return gettext_noop("GSTI");
    case GPG_ERR_SOURCE_GPA:
      return gettext_noop("GPA");
    case GPG_ERR_SOURCE_KLEO:
      return gettext_noop("Kleopatra");
    case GPG_ERR_SOURCE_G13:
      return gettext_noop("G13");
    case GPG_ERR_SOURCE_ASSUAN:
      return gettext_noop("Assuan");

    case GPG_ERR_SOURCE_TLS:
      return gettext_noop("TLS");

    case GPG_ERR_SOURCE_ANY:
      return gettext_noop("Any source");
    case GPG_ERR_SOURCE_USER_1:
      return gettext_noop("User defined source 1");
    case GPG_ERR_SOURCE_USER_2:
      return gettext_noop("User defined source 2");
    case GPG_ERR_SOURCE_USER_3:
      return gettext_noop("User defined source 3");
    case GPG_ERR_SOURCE_USER_4:
      return gettext_noop("User defined source 4");
    case GPG_ERR_SOURCE_DIM:
    default:
      break;
    }
  return gettext_noop("Unknown source");
};

/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *
_gpg_strsource (gpg_error_t err)
{
  gpg_err_source_t source = gpg_err_source (err);
  return dgettext (PACKAGE, err_source(source));
}
