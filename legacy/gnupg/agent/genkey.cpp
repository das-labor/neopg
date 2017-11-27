/* genkey.c - Generate a keypair
 * Copyright (C) 2002, 2003, 2004, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

#include "../common/exechelp.h"
#include "../common/sysutils.h"

static int store_key(gcry_sexp_t privater, const char *passphrase, int force,
                     unsigned long s2k_count) {
  int rc;
  unsigned char *buf;
  size_t len;
  unsigned char grip[20];

  if (!gcry_pk_get_keygrip(privater, grip)) {
    log_error("can't calculate keygrip\n");
    return GPG_ERR_GENERAL;
  }

  len = gcry_sexp_sprint(privater, GCRYSEXP_FMT_CANON, NULL, 0);
  assert(len);
  buf = (unsigned char *)gcry_malloc_secure(len);
  if (!buf) return gpg_error_from_syserror();
  len = gcry_sexp_sprint(privater, GCRYSEXP_FMT_CANON, buf, len);
  assert(len);

  if (passphrase) {
    unsigned char *p;

    rc = agent_protect(buf, passphrase, &p, &len, s2k_count, -1);
    if (rc) {
      xfree(buf);
      return rc;
    }
    xfree(buf);
    buf = p;
  }

  rc = agent_write_private_key(grip, buf, len, force);
  xfree(buf);
  return rc;
}

/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static gpg_error_t reenter_compare_cb(struct pin_entry_info_s *pi) {
  const char *pin1 = (const char *)pi->check_cb_arg;

  if (!strcmp(pin1, pi->pin)) return 0; /* okay */
  return GPG_ERR_BAD_PASSPHRASE;
}

/* Ask the user for a new passphrase using PROMPT.  On success the
   function returns 0 and store the passphrase at R_PASSPHRASE; if the
   user opted not to use a passphrase NULL will be stored there.  The
   user needs to free the returned string.  In case of an error and
   error code is returned and NULL stored at R_PASSPHRASE.  */
gpg_error_t agent_ask_new_passphrase(ctrl_t ctrl, const char *prompt,
                                     char **r_passphrase) {
  gpg_error_t err;
  const char *text1 = prompt;
  const char *text2 = L_("Please re-enter this passphrase");
  char *initial_errtext = NULL;
  struct pin_entry_info_s *pi, *pi2;

  *r_passphrase = NULL;

  {
    size_t size;
    unsigned char *buffer;

    err = pinentry_loopback(ctrl, "NEW_PASSPHRASE", &buffer, &size,
                            MAX_PASSPHRASE_LEN);
    if (!err) {
      if (size) {
        buffer[size] = 0;
        *r_passphrase = (char *)buffer;
      } else
        *r_passphrase = NULL;
    }
    return err;
  }

  pi = (pin_entry_info_s *)gcry_calloc_secure(
      1, sizeof(*pi) + MAX_PASSPHRASE_LEN + 1);
  if (!pi) return gpg_error_from_syserror();
  pi2 = (pin_entry_info_s *)gcry_calloc_secure(
      1, sizeof(*pi2) + MAX_PASSPHRASE_LEN + 1);
  if (!pi2) {
    err = gpg_error_from_syserror();
    xfree(pi2);
    return err;
  }
  pi->max_length = MAX_PASSPHRASE_LEN + 1;
  pi->max_tries = 3;
  pi->with_qualitybar = 1;
  pi->with_repeat = 1;
  pi2->max_length = MAX_PASSPHRASE_LEN + 1;
  pi2->max_tries = 3;
  pi2->check_cb = reenter_compare_cb;
  pi2->check_cb_arg = pi->pin;

next_try:
  err = agent_askpin(ctrl, text1, NULL, initial_errtext, pi, NULL,
                     (cache_mode_t)(0));
  xfree(initial_errtext);
  initial_errtext = NULL;
  if (!err) {
    /* Unless the passphrase is empty or the pinentry told us that
       it already did the repetition check, ask to confirm it.  */
    if (*pi->pin && !pi->repeat_okay) {
      err = agent_askpin(ctrl, text2, NULL, NULL, pi2, NULL, (cache_mode_t)(0));
      if (err == GPG_ERR_BAD_PASSPHRASE) { /* The re-entered one did not match
                                              and the user did not
                                              hit cancel. */
        initial_errtext = xtrystrdup(L_("does not match - try again"));
        if (initial_errtext) goto next_try;
        err = gpg_error_from_syserror();
      }
    }
  }

  if (!err && *pi->pin) {
    /* User wants a passphrase. */
    *r_passphrase = xtrystrdup(pi->pin);
    if (!*r_passphrase) err = gpg_error_from_syserror();
  }

  xfree(initial_errtext);
  xfree(pi2);
  xfree(pi);
  return err;
}

/* Generate a new keypair according to the parameters given in
   KEYPARAM.  If CACHE_NONCE is given first try to lookup a passphrase
   using the cache nonce.  If NO_PROTECTION is true the key will not
   be protected by a passphrase.  If OVERRIDE_PASSPHRASE is true that
   passphrase will be used for the new key.  */
int agent_genkey(ctrl_t ctrl, const char *cache_nonce, const char *keyparam,
                 size_t keyparamlen, int no_protection,
                 const char *override_passphrase, membuf_t *outbuf) {
  gcry_sexp_t s_keyparam, s_key, s_private, s_public;
  char *passphrase_buffer = NULL;
  const char *passphrase;
  int rc;
  size_t len;
  char *buf;

  rc = gcry_sexp_sscan(&s_keyparam, NULL, keyparam, keyparamlen);
  if (rc) {
    log_error("failed to convert keyparam: %s\n", gpg_strerror(rc));
    return GPG_ERR_INV_DATA;
  }

  /* Get the passphrase now, cause key generation may take a while. */
  if (override_passphrase)
    passphrase = override_passphrase;
  else if (no_protection || !cache_nonce)
    passphrase = NULL;
  else {
    passphrase_buffer = agent_get_cache(cache_nonce, CACHE_MODE_NONCE);
    passphrase = passphrase_buffer;
  }

  if (passphrase || no_protection)
    ;
  else {
    rc = agent_ask_new_passphrase(ctrl, L_("Please enter the passphrase to%0A"
                                           "protect your new key"),
                                  &passphrase_buffer);
    if (rc) return rc;
    passphrase = passphrase_buffer;
  }

  rc = gcry_pk_genkey(&s_key, s_keyparam);
  gcry_sexp_release(s_keyparam);
  if (rc) {
    log_error("key generation failed: %s\n", gpg_strerror(rc));
    xfree(passphrase_buffer);
    return rc;
  }

  /* break out the parts */
  s_private = gcry_sexp_find_token(s_key, "private-key", 0);
  if (!s_private) {
    log_error("key generation failed: invalid return value\n");
    gcry_sexp_release(s_key);
    xfree(passphrase_buffer);
    return GPG_ERR_INV_DATA;
  }
  s_public = gcry_sexp_find_token(s_key, "public-key", 0);
  if (!s_public) {
    log_error("key generation failed: invalid return value\n");
    gcry_sexp_release(s_private);
    gcry_sexp_release(s_key);
    xfree(passphrase_buffer);
    return GPG_ERR_INV_DATA;
  }
  gcry_sexp_release(s_key);
  s_key = NULL;

  /* store the secret key */
  if (DBG_CRYPTO) log_debug("storing private key\n");
  rc = store_key(s_private, passphrase, 0, ctrl->s2k_count);
  if (!rc) {
    if (!cache_nonce) {
      char tmpbuf[12];
      gcry_create_nonce(tmpbuf, 12);
      cache_nonce = bin2hex(tmpbuf, 12, NULL);
    }
    if (cache_nonce && !no_protection &&
        !agent_put_cache(cache_nonce, CACHE_MODE_NONCE, passphrase,
                         CACHE_TTL_NONCE))
      agent_write_status(ctrl, "CACHE_NONCE", cache_nonce, NULL);
  }
  xfree(passphrase_buffer);
  passphrase_buffer = NULL;
  passphrase = NULL;
  gcry_sexp_release(s_private);
  if (rc) {
    gcry_sexp_release(s_public);
    return rc;
  }

  /* return the public key */
  if (DBG_CRYPTO) log_debug("returning public key\n");
  len = gcry_sexp_sprint(s_public, GCRYSEXP_FMT_CANON, NULL, 0);
  assert(len);
  buf = (char *)xtrymalloc(len);
  if (!buf) {
    gpg_error_t tmperr = gpg_error_from_syserror();
    gcry_sexp_release(s_private);
    gcry_sexp_release(s_public);
    return tmperr;
  }
  len = gcry_sexp_sprint(s_public, GCRYSEXP_FMT_CANON, buf, len);
  assert(len);
  put_membuf(outbuf, buf, len);
  gcry_sexp_release(s_public);
  xfree(buf);

  return 0;
}

/* Apply a new passphrase to the key S_SKEY and store it.  If
   PASSPHRASE_ADDR and *PASSPHRASE_ADDR are not NULL, use that
   passphrase.  If PASSPHRASE_ADDR is not NULL store a newly entered
   passphrase at that address. */
gpg_error_t agent_protect_and_store(ctrl_t ctrl, gcry_sexp_t s_skey,
                                    char **passphrase_addr) {
  gpg_error_t err;

  if (passphrase_addr && *passphrase_addr) {
    /* Take an empty string as request not to protect the key.  */
    err = store_key(s_skey, **passphrase_addr ? *passphrase_addr : NULL, 1,
                    ctrl->s2k_count);
  } else {
    char *pass = NULL;

    if (passphrase_addr) {
      xfree(*passphrase_addr);
      *passphrase_addr = NULL;
    }
    err = agent_ask_new_passphrase(ctrl, L_("Please enter the new passphrase"),
                                   &pass);
    if (!err) err = store_key(s_skey, pass, 1, ctrl->s2k_count);
    if (!err && passphrase_addr)
      *passphrase_addr = pass;
    else
      xfree(pass);
  }

  return err;
}
