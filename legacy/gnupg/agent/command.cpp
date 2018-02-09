/* command.c - gpg-agent command handler
 * Copyright (C) 2001-2011 Free Software Foundation, Inc.
 * Copyright (C) 2001-2013 Werner Koch
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

/* FIXME: we should not use the default assuan buffering but setup
   some buffering in secure mempory to protect session keys etc. */

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <botan/secmem.h>

#include <assuan.h>
#include "../common/asshelp.h"
#include "../common/server-help.h"
#include "agent.h"
#include "cvt-openpgp.h"

/* Maximum allowed size of the inquired ciphertext.  */
#define MAXLEN_CIPHERTEXT 4096
/* Maximum allowed size of the key parameters.  */
#define MAXLEN_KEYPARAM 1024
/* Maximum allowed size of key data as used in inquiries (bytes). */
#define MAXLEN_KEYDATA 8192

/* A shortcut to call assuan_set_error using an gpg_error_t and a
   text string.  */
#define set_error(e, t) assuan_set_error(ctx, e, (t))

/* Check that the maximum digest length we support has at least the
   length of the keygrip.  */
#if MAX_DIGEST_LEN < 20
#error MAX_DIGEST_LEN shorter than keygrip
#endif

/* Data used to associate an Assuan context with local server data.
   This is this modules local part of the server_control_s struct.  */
struct server_local_s {
  /* Our Assuan context.  */
  assuan_context_t assuan_ctx;

  /* If this flag is true, the passphrase cache is used for signing
     operations.  It defaults to true but may be set on a per
     connection base.  The global option opt.ignore_cache_for_signing
     takes precedence over this flag.  */
  unsigned int use_cache_for_signing : 1;

  /* An allocated description for the next key operation.  This is
     used if a pinnetry needs to be popped up.  */
  char *keydesc;

  /* Last CACHE_NONCE sent as status (malloced).  */
  char *last_cache_nonce;

  /* Last PASSWD_NONCE sent as status (malloced). */
  char *last_passwd_nonce;
};

/*  Local prototypes.  */
static int command_has_option(const char *cmd, const char *cmdopt);

/* Release the memory buffer MB but first wipe out the used memory. */
static void clear_outbuf(membuf_t *mb) {
  void *p;
  size_t n;

  p = get_membuf(mb, &n);
  if (p) {
    wipememory(p, n);
    xfree(p);
  }
}

/* Write the content of memory buffer MB as assuan data to CTX and
   wipe the buffer out afterwards. */
static gpg_error_t write_and_clear_outbuf(assuan_context_t ctx, membuf_t *mb) {
  gpg_error_t ae;
  void *p;
  size_t n;

  p = get_membuf(mb, &n);
  if (!p) return gpg_error_from_syserror();
  ae = assuan_send_data(ctx, p, n);
  memset(p, 0, n);
  xfree(p);
  return ae;
}

/* Clear the nonces used to enable the passphrase cache for certain
   multi-command command sequences.  */
static void clear_nonce_cache(ctrl_t ctrl) {
  if (ctrl->server_local->last_cache_nonce) {
    agent_put_cache(ctrl->server_local->last_cache_nonce, CACHE_MODE_NONCE,
                    NULL, 0);
    xfree(ctrl->server_local->last_cache_nonce);
    ctrl->server_local->last_cache_nonce = NULL;
  }
  if (ctrl->server_local->last_passwd_nonce) {
    agent_put_cache(ctrl->server_local->last_passwd_nonce, CACHE_MODE_NONCE,
                    NULL, 0);
    xfree(ctrl->server_local->last_passwd_nonce);
    ctrl->server_local->last_passwd_nonce = NULL;
  }
}

/* This function is called by Libassuan whenever the client sends a
   reset.  It has been registered similar to the other Assuan
   commands.  */
static gpg_error_t reset_notify(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);

  (void)line;

  memset(ctrl->keygrip, 0, 20);
  ctrl->have_keygrip = 0;
  ctrl->digest.valuelen = 0;

  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

  clear_nonce_cache(ctrl);

  return 0;
}

/* Replace all '+' by a blank in the string S. */
static void plus_to_blank(char *s) {
  for (; *s; s++) {
    if (*s == '+') *s = ' ';
  }
}

/* Parse a hex string.  Return an Assuan error code or 0 on success and the
   length of the parsed string in LEN. */
static int parse_hexstring(assuan_context_t ctx, const char *string,
                           size_t *len) {
  const char *p;
  size_t n;

  /* parse the hash value */
  for (p = string, n = 0; hexdigitp(p); p++, n++)
    ;
  if (*p != ' ' && *p != '\t' && *p)
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid hexstring");
  if ((n & 1)) return set_error(GPG_ERR_ASS_PARAMETER, "odd number of digits");
  *len = n;
  return 0;
}

/* Parse the keygrip in STRING into the provided buffer BUF.  BUF must
   provide space for 20 bytes.  BUF is not changed if the function
   returns an error. */
static int parse_keygrip(assuan_context_t ctx, const char *string,
                         unsigned char *buf) {
  int rc;
  size_t n = 0;

  rc = parse_hexstring(ctx, string, &n);
  if (rc) return rc;
  n /= 2;
  if (n != 20)
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid length of keygrip");

  if (hex2bin(string, buf, 20) < 0) return set_error(GPG_ERR_BUG, "hex2bin");

  return 0;
}

/* Write an Assuan status line.  KEYWORD is the first item on the
   status line.  The following arguments are all separated by a space
   in the output.  The last argument must be a NULL.  Linefeeds and
   carriage returns characters (which are not allowed in an Assuan
   status line) are silently quoted in C-style.  */
gpg_error_t agent_write_status(ctrl_t ctrl, const char *keyword, ...) {
  gpg_error_t err = 0;
  va_list arg_ptr;
  const char *text;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;
  char buf[950], *p;
  size_t n;

  va_start(arg_ptr, keyword);

  p = buf;
  n = 0;
  while ((text = va_arg(arg_ptr, const char *))) {
    if (n) {
      *p++ = ' ';
      n++;
    }
    for (; *text && n < DIM(buf) - 3; n++, text++) {
      if (*text == '\n') {
        *p++ = '\\';
        *p++ = 'n';
      } else if (*text == '\r') {
        *p++ = '\\';
        *p++ = 'r';
      } else
        *p++ = *text;
    }
  }
  *p = 0;
  err = assuan_write_status(ctx, keyword, buf);

  va_end(arg_ptr);
  return err;
}

/* This function is similar to print_assuan_status but takes a CTRL
   arg instead of an assuan context as first argument.  */
gpg_error_t agent_print_status(ctrl_t ctrl, const char *keyword,
                               const char *format, ...) {
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  va_start(arg_ptr, format);
  err = vprint_assuan_status(ctx, keyword, format, arg_ptr);
  va_end(arg_ptr);
  return err;
}

/* An agent progress callback for Libgcrypt.  This has been registered
 * to be called via the progress dispatcher mechanism from
 * gpg-agent.c  */
static void progress_cb(ctrl_t ctrl, const char *what, int printchar,
                        int current, int total) {
  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    ;
  else if (printchar == '\n' && what && !strcmp(what, "primegen"))
    agent_print_status(ctrl, "PROGRESS", "%.20s X 100 100", what);
  else
    agent_print_status(ctrl, "PROGRESS", "%.20s %c %d %d", what,
                       printchar == '\n' ? 'X' : printchar, current, total);
}

/* Helper to print a message while leaving a command.  Note that this
 * function does not call assuan_set_error; the caller may do this
 * prior to calling us.  */
static gpg_error_t leave_cmd(assuan_context_t ctx, gpg_error_t err) {
  if (err) {
    const char *name = assuan_get_command_name(ctx);
    if (!name) name = "?";

    log_error("command '%s' failed: %s\n", name, gpg_strerror(err));
  }
  return err;
}

static const char hlp_istrusted[] =
    "ISTRUSTED <hexstring_with_fingerprint>\n"
    "\n"
    "Return OK when we have an entry with this fingerprint in our\n"
    "trustlist";
static gpg_error_t cmd_istrusted(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc, n, i;
  char *p;
  char fpr[41];

  /* Parse the fingerprint value. */
  for (p = line, n = 0; hexdigitp(p); p++, n++)
    ;
  if (*p || !(n == 40 || n == 32))
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid fingerprint");
  i = 0;
  if (n == 32) {
    strcpy(fpr, "00000000");
    i += 8;
  }
  for (p = line; i < 40; p++, i++) fpr[i] = *p >= 'a' ? (*p & 0xdf) : *p;
  fpr[i] = 0;
  rc = agent_istrusted(ctrl, fpr, NULL);
  if (!rc || rc == GPG_ERR_NOT_TRUSTED)
    return rc;
  else if (rc == -1 || rc == GPG_ERR_EOF)
    return GPG_ERR_NOT_TRUSTED;
  else
    return leave_cmd(ctx, rc);
}

static const char hlp_listtrusted[] =
    "LISTTRUSTED\n"
    "\n"
    "List all entries from the trustlist.";
static gpg_error_t cmd_listtrusted(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc;

  (void)line;

  rc = agent_listtrusted(ctx);
  return leave_cmd(ctx, rc);
}

static const char hlp_martrusted[] =
    "MARKTRUSTED <hexstring_with_fingerprint> <flag> <display_name>\n"
    "\n"
    "Store a new key in into the trustlist.";
static gpg_error_t cmd_marktrusted(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc, n, i;
  char *p;
  char fpr[41];
  int flag;

  /* parse the fingerprint value */
  for (p = line, n = 0; hexdigitp(p); p++, n++)
    ;
  if (!spacep(p) || !(n == 40 || n == 32))
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid fingerprint");
  i = 0;
  if (n == 32) {
    strcpy(fpr, "00000000");
    i += 8;
  }
  for (p = line; i < 40; p++, i++) fpr[i] = *p >= 'a' ? (*p & 0xdf) : *p;
  fpr[i] = 0;

  while (spacep(p)) p++;
  flag = *p++;
  if ((flag != 'S' && flag != 'P') || !spacep(p))
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid flag - must be P or S");
  while (spacep(p)) p++;

  rc = agent_marktrusted(ctrl, p, fpr, flag);
  return leave_cmd(ctx, rc);
}

static const char hlp_havekey[] =
    "HAVEKEY <hexstrings_with_keygrips>\n"
    "\n"
    "Return success if at least one of the secret keys with the given\n"
    "keygrips is available.";
static gpg_error_t cmd_havekey(assuan_context_t ctx, char *line) {
  gpg_error_t err;
  unsigned char buf[20];

  do {
    err = parse_keygrip(ctx, line, buf);
    if (err) return err;

    if (!agent_key_available(buf)) return 0; /* Found.  */

    while (*line && *line != ' ' && *line != '\t') line++;
    while (*line == ' ' || *line == '\t') line++;
  } while (*line);

  /* No leave_cmd() here because errors are expected and would clutter
     the log.  */
  return GPG_ERR_NO_SECKEY;
}

static const char hlp_sigkey[] =
    "SIGKEY <hexstring_with_keygrip>\n"
    "SETKEY <hexstring_with_keygrip>\n"
    "\n"
    "Set the  key used for a sign or decrypt operation.";
static gpg_error_t cmd_sigkey(assuan_context_t ctx, char *line) {
  int rc;
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);

  rc = parse_keygrip(ctx, line, ctrl->keygrip);
  if (rc) return rc;
  ctrl->have_keygrip = 1;
  return 0;
}

static const char hlp_setkeydesc[] =
    "SETKEYDESC plus_percent_escaped_string\n"
    "\n"
    "Set a description to be used for the next PKSIGN, PKDECRYPT, IMPORT_KEY\n"
    "or EXPORT_KEY operation if this operation requires a passphrase.  If\n"
    "this command is not used a default text will be used.  Note, that\n"
    "this description implictly selects the label used for the entry\n"
    "box; if the string contains the string PIN (which in general will\n"
    "not be translated), \"PIN\" is used, otherwise the translation of\n"
    "\"passphrase\" is used.  The description string should not contain\n"
    "blanks unless they are percent or '+' escaped.\n"
    "\n"
    "The description is only valid for the next PKSIGN, PKDECRYPT,\n"
    "IMPORT_KEY, EXPORT_KEY, or DELETE_KEY operation.";
static gpg_error_t cmd_setkeydesc(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  char *desc, *p;

  for (p = line; *p == ' '; p++)
    ;
  desc = p;
  p = strchr(desc, ' ');
  if (p)
    *p = 0; /* We ignore any garbage; we might late use it for other args. */

  if (!*desc) return set_error(GPG_ERR_ASS_PARAMETER, "no description given");

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  plus_to_blank(desc);

  xfree(ctrl->server_local->keydesc);

  ctrl->server_local->keydesc = xtrystrdup(desc);
  if (!ctrl->server_local->keydesc) return gpg_error_from_syserror();
  return 0;
}

static const char hlp_sethash[] =
    "SETHASH (--hash=<name>)|(<algonumber>) <hexstring>\n"
    "\n"
    "The client can use this command to tell the server about the data\n"
    "(which usually is a hash) to be signed.";
static gpg_error_t cmd_sethash(assuan_context_t ctx, char *line) {
  int rc;
  size_t n;
  char *p;
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  unsigned char *buf;
  char *endp;
  int algo;

  /* Parse the alternative hash options which may be used instead of
     the algo number.  */
  if (has_option_name(line, "--hash")) {
    if (has_option(line, "--hash=sha1"))
      algo = GCRY_MD_SHA1;
    else if (has_option(line, "--hash=sha224"))
      algo = GCRY_MD_SHA224;
    else if (has_option(line, "--hash=sha256"))
      algo = GCRY_MD_SHA256;
    else if (has_option(line, "--hash=sha384"))
      algo = GCRY_MD_SHA384;
    else if (has_option(line, "--hash=sha512"))
      algo = GCRY_MD_SHA512;
    else if (has_option(line, "--hash=rmd160"))
      algo = GCRY_MD_RMD160;
    else if (has_option(line, "--hash=md5"))
      algo = GCRY_MD_MD5;
    else if (has_option(line, "--hash=tls-md5sha1"))
      algo = MD_USER_TLS_MD5SHA1;
    else
      return set_error(GPG_ERR_ASS_PARAMETER, "invalid hash algorithm");
  } else
    algo = 0;

  line = skip_options(line);

  if (!algo) {
    /* No hash option has been given: require an algo number instead  */
    algo = (int)strtoul(line, &endp, 10);
    for (line = endp; *line == ' ' || *line == '\t'; line++)
      ;
    if (!algo || gcry_md_test_algo(algo))
      return set_error(GPG_ERR_UNSUPPORTED_ALGORITHM, NULL);
  }
  ctrl->digest.algo = algo;
  ctrl->digest.raw_value = 0;

  /* Parse the hash value. */
  n = 0;
  rc = parse_hexstring(ctx, line, &n);
  if (rc) return rc;
  n /= 2;
  if (algo == MD_USER_TLS_MD5SHA1 && n == 36)
    ;
  else if (n != 16 && n != 20 && n != 24 && n != 28 && n != 32 && n != 48 &&
           n != 64)
    return set_error(GPG_ERR_ASS_PARAMETER, "unsupported length of hash");

  if (n > MAX_DIGEST_LEN)
    return set_error(GPG_ERR_ASS_PARAMETER, "hash value to long");

  buf = ctrl->digest.value;
  ctrl->digest.valuelen = n;
  for (p = line, n = 0; n < ctrl->digest.valuelen; p += 2, n++)
    buf[n] = xtoi_2(p);
  for (; n < ctrl->digest.valuelen; n++) buf[n] = 0;
  return 0;
}

static const char hlp_pksign[] =
    "PKSIGN [<options>] [<cache_nonce>]\n"
    "\n"
    "Perform the actual sign operation.  Neither input nor output are\n"
    "sensitive to eavesdropping.";
static gpg_error_t cmd_pksign(assuan_context_t ctx, char *line) {
  int rc;
  cache_mode_t cache_mode = CACHE_MODE_NORMAL;
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  membuf_t outbuf;
  char *cache_nonce = NULL;
  char *p;

  line = skip_options(line);

  for (p = line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  *p = '\0';
  if (*line) cache_nonce = xtrystrdup(line);

  if (opt.ignore_cache_for_signing)
    cache_mode = CACHE_MODE_IGNORE;
  else if (!ctrl->server_local->use_cache_for_signing)
    cache_mode = CACHE_MODE_IGNORE;

  init_membuf(&outbuf, 512);

  rc = agent_pksign(ctrl, cache_nonce, ctrl->server_local->keydesc, &outbuf,
                    cache_mode);
  if (rc)
    clear_outbuf(&outbuf);
  else
    rc = write_and_clear_outbuf(ctx, &outbuf);

  xfree(cache_nonce);
  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return leave_cmd(ctx, rc);
}

static const char hlp_pkdecrypt[] =
    "PKDECRYPT [<options>]\n"
    "\n"
    "Perform the actual decrypt operation.  Input is not\n"
    "sensitive to eavesdropping.";
static gpg_error_t cmd_pkdecrypt(assuan_context_t ctx, char *line) {
  int rc;
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  unsigned char *value;
  size_t valuelen;
  membuf_t outbuf;
  int padding;

  (void)line;

  /* First inquire the data to decrypt */
  rc = print_assuan_status(ctx, "INQUIRE_MAXLEN", "%u", MAXLEN_CIPHERTEXT);
  if (!rc)
    rc =
        assuan_inquire(ctx, "CIPHERTEXT", &value, &valuelen, MAXLEN_CIPHERTEXT);
  if (rc) return rc;

  init_membuf(&outbuf, 512);

  rc = agent_pkdecrypt(ctrl, ctrl->server_local->keydesc, value, valuelen,
                       &outbuf, &padding);
  xfree(value);
  if (rc)
    clear_outbuf(&outbuf);
  else {
    if (padding != -1)
      rc = print_assuan_status(ctx, "PADDING", "%d", padding);
    else
      rc = 0;
    if (!rc) rc = write_and_clear_outbuf(ctx, &outbuf);
  }
  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return leave_cmd(ctx, rc);
}

static const char hlp_genkey[] =
    "GENKEY [--no-protection] [--inq-passwd]\n"
    "       [--passwd-nonce=<s>] [<cache_nonce>]\n"
    "\n"
    "Generate a new key, store the secret part and return the public\n"
    "part.  Here is an example transaction:\n"
    "\n"
    "  C: GENKEY\n"
    "  S: INQUIRE KEYPARAM\n"
    "  C: D (genkey (rsa (nbits  2048)))\n"
    "  C: END\n"
    "  S: D (public-key\n"
    "  S: D   (rsa (n 326487324683264) (e 10001)))\n"
    "  S: OK key created\n"
    "\n"
    "When --inq-passwd is used an inquire\n"
    "with the keyword NEWPASSWD is used to request the passphrase for the\n"
    "new key.  When a --passwd-nonce is used, the corresponding cached\n"
    "passphrase is used to protect the new key.";
static gpg_error_t cmd_genkey(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc;
  int no_protection;
  unsigned char *value;
  size_t valuelen;
  char *newpasswd = NULL;
  membuf_t outbuf;
  char *cache_nonce = NULL;
  char *passwd_nonce = NULL;
  int opt_inq_passwd;
  size_t n;
  char *p, *pend;
  int c;

  no_protection = has_option(line, "--no-protection");
  opt_inq_passwd = has_option(line, "--inq-passwd");
  passwd_nonce = option_value(line, "--passwd-nonce");
  if (passwd_nonce) {
    for (pend = passwd_nonce; *pend && !spacep(pend); pend++)
      ;
    c = *pend;
    *pend = '\0';
    passwd_nonce = xtrystrdup(passwd_nonce);
    *pend = c;
    if (!passwd_nonce) {
      rc = gpg_error_from_syserror();
      goto leave;
    }
  }
  line = skip_options(line);

  for (p = line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  *p = '\0';
  if (*line) cache_nonce = xtrystrdup(line);

  /* First inquire the parameters */
  rc = print_assuan_status(ctx, "INQUIRE_MAXLEN", "%u", MAXLEN_KEYPARAM);
  if (!rc)
    rc = assuan_inquire(ctx, "KEYPARAM", &value, &valuelen, MAXLEN_KEYPARAM);
  if (rc) return rc;

  init_membuf(&outbuf, 512);

  /* If requested, ask for the password to be used for the key.  If
     this is not used the regular Pinentry mechanism is used.  */
  if (opt_inq_passwd && !no_protection) {
    /* (N is used as a dummy) */
    assuan_begin_confidential(ctx);
    rc = assuan_inquire(ctx, "NEWPASSWD", (unsigned char **)(&newpasswd), &n,
                        256);
    assuan_end_confidential(ctx);
    if (rc) goto leave;
    if (!*newpasswd) {
      /* Empty password given - switch to no-protection mode.  */
      xfree(newpasswd);
      newpasswd = NULL;
      no_protection = 1;
    }

  } else if (passwd_nonce)
    newpasswd = agent_get_cache(passwd_nonce, CACHE_MODE_NONCE);

  rc = agent_genkey(ctrl, cache_nonce, (char *)value, valuelen, no_protection,
                    newpasswd, &outbuf);

leave:
  if (newpasswd) {
    /* Assuan_inquire does not allow us to read into secure memory
       thus we need to wipe it ourself.  */
    wipememory(newpasswd, strlen(newpasswd));
    xfree(newpasswd);
  }
  xfree(value);
  if (rc)
    clear_outbuf(&outbuf);
  else
    rc = write_and_clear_outbuf(ctx, &outbuf);
  xfree(cache_nonce);
  xfree(passwd_nonce);
  return leave_cmd(ctx, rc);
}

static const char hlp_readkey[] =
    "READKEY <hexstring_with_keygrip>\n"
    "        --card <keyid>\n"
    "\n"
    "Return the public key for the given keygrip or keyid.\n"
    "With --card, private key file with card information will be created.";
static gpg_error_t cmd_readkey(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc;
  unsigned char grip[20];
  gcry_sexp_t s_pkey = NULL;
  unsigned char *pkbuf = NULL;
  char *serialno = NULL;
  size_t pkbuflen;
  const char *opt_card;

  opt_card = has_option_name(line, "--card");
  line = skip_options(line);

  if (opt_card) {
    const char *keyid = opt_card;

    rc = agent_card_getattr(ctrl, "SERIALNO", &serialno);
    if (rc) {
      log_error(_("error getting serial number of card: %s\n"),
                gpg_strerror(rc));
      goto leave;
    }

    rc = agent_card_readkey(ctrl, keyid, &pkbuf);
    if (rc) goto leave;
    pkbuflen = gcry_sexp_canon_len(pkbuf, 0, NULL, NULL);
    rc = gcry_sexp_sscan(&s_pkey, NULL, (char *)pkbuf, pkbuflen);
    if (rc) goto leave;

    if (!gcry_pk_get_keygrip(s_pkey, grip)) {
      rc = gcry_pk_testkey(s_pkey);
      if (rc == 0) rc = GPG_ERR_INTERNAL;

      goto leave;
    }

    rc = agent_write_shadow_key(grip, serialno, keyid, pkbuf, 0);
    if (rc) goto leave;

    rc = assuan_send_data(ctx, pkbuf, pkbuflen);
  } else {
    rc = parse_keygrip(ctx, line, grip);
    if (rc) goto leave;

    rc = agent_public_key_from_file(ctrl, grip, &s_pkey);
    if (!rc) {
      pkbuflen = gcry_sexp_sprint(s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);
      log_assert(pkbuflen);
      pkbuf = (unsigned char *)xtrymalloc(pkbuflen);
      if (!pkbuf)
        rc = gpg_error_from_syserror();
      else {
        gcry_sexp_sprint(s_pkey, GCRYSEXP_FMT_CANON, pkbuf, pkbuflen);
        rc = assuan_send_data(ctx, pkbuf, pkbuflen);
      }
    }
  }

leave:
  xfree(serialno);
  xfree(pkbuf);
  gcry_sexp_release(s_pkey);
  return leave_cmd(ctx, rc);
}

static const char hlp_keyinfo[] =
    "KEYINFO [--list] [--data] <keygrip>\n"
    "\n"
    "Return information about the key specified by the KEYGRIP.  If the\n"
    "key is not available GPG_ERR_NOT_FOUND is returned.  If the option\n"
    "--list is given the keygrip is ignored and information about all\n"
    "available keys are returned.  Unless --data\n"
    "is given, the information is returned as a status line using the format:\n"
    "\n"
    "  KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> "
    "<fpr>\n"
    "\n"
    "KEYGRIP is the keygrip.\n"
    "\n"
    "TYPE is describes the type of the key:\n"
    "    'D' - Regular key stored on disk,\n"
    "    'T' - Key is stored on a smartcard (token),\n"
    "    'X' - Unknown type,\n"
    "    '-' - Key is missing.\n"
    "\n"
    "SERIALNO is an ASCII string with the serial number of the\n"
    "         smartcard.  If the serial number is not known a single\n"
    "         dash '-' is used instead.\n"
    "\n"
    "IDSTR is the IDSTR used to distinguish keys on a smartcard.  If it\n"
    "      is not known a dash is used instead.\n"
    "\n"
    "CACHED is 1 if the passphrase for the key was found in the key cache.\n"
    "       If not, a '-' is used instead.\n"
    "\n"
    "PROTECTION describes the key protection type:\n"
    "    'P' - The key is protected with a passphrase,\n"
    "    'C' - The key is not protected,\n"
    "    '-' - Unknown protection.\n"
    "\n"
    "TTL is the TTL in seconds for that key or '-' if n/a.\n"
    "\n"
    "FLAGS is a word consisting of one-letter flags:\n"
    "      'D' - The key has been disabled,\n"
    "      'c' - Use of the key needs to be confirmed,\n"
    "      '-' - No flags given.\n"
    "\n"
    "More information may be added in the future.";
static gpg_error_t do_one_keyinfo(ctrl_t ctrl, const unsigned char *grip,
                                  assuan_context_t ctx, int data, int ttl,
                                  int disabled, int confirm) {
  gpg_error_t err;
  char hexgrip[40 + 1];
  char *fpr = NULL;
  int keytype;
  unsigned char *shadow_info = NULL;
  char *serialno = NULL;
  char *idstr = NULL;
  const char *keytypestr;
  const char *cached;
  const char *protectionstr;
  char *pw;
  int missing_key = 0;
  char ttlbuf[20];
  char flagsbuf[5];

  err = agent_key_info_from_file(ctrl, grip, &keytype, &shadow_info);
  if (err) goto leave;

  /* Reformat the grip so that we use uppercase as good style. */
  bin2hex(grip, 20, hexgrip);

  if (ttl > 0)
    snprintf(ttlbuf, sizeof ttlbuf, "%d", ttl);
  else
    strcpy(ttlbuf, "-");

  *flagsbuf = 0;
  if (disabled) strcat(flagsbuf, "D");
  if (confirm) strcat(flagsbuf, "c");
  if (!*flagsbuf) strcpy(flagsbuf, "-");

  if (missing_key) {
    protectionstr = "-";
    keytypestr = "-";
  } else {
    switch (keytype) {
      case PRIVATE_KEY_CLEAR:
      case PRIVATE_KEY_OPENPGP_NONE:
        protectionstr = "C";
        keytypestr = "D";
        break;
      case PRIVATE_KEY_PROTECTED:
        protectionstr = "P";
        keytypestr = "D";
        break;
      case PRIVATE_KEY_SHADOWED:
        protectionstr = "-";
        keytypestr = "T";
        break;
      default:
        protectionstr = "-";
        keytypestr = "X";
        break;
    }
  }

  /* Here we have a little race by doing the cache check separately
     from the retrieval function.  Given that the cache flag is only a
     hint, it should not really matter.  */
  pw = agent_get_cache(hexgrip, CACHE_MODE_NORMAL);
  cached = pw ? "1" : "-";
  xfree(pw);

  if (shadow_info) {
    err = parse_shadow_info(shadow_info, &serialno, &idstr, NULL);
    if (err) goto leave;
  }

  if (!data)
    err = agent_write_status(ctrl, "KEYINFO", hexgrip, keytypestr,
                             serialno ? serialno : "-", idstr ? idstr : "-",
                             cached, protectionstr, fpr ? fpr : "-", ttlbuf,
                             flagsbuf, NULL);
  else {
    char *string;

    string =
        xtryasprintf("%s %s %s %s %s %s %s %s %s\n", hexgrip, keytypestr,
                     serialno ? serialno : "-", idstr ? idstr : "-", cached,
                     protectionstr, fpr ? fpr : "-", ttlbuf, flagsbuf);
    if (!string)
      err = gpg_error_from_syserror();
    else
      err = assuan_send_data(ctx, string, strlen(string));
    xfree(string);
  }

leave:
  xfree(fpr);
  xfree(shadow_info);
  xfree(serialno);
  xfree(idstr);
  return err;
}

/* Entry int for the command KEYINFO.  This function handles the
   command option processing.  For details see hlp_keyinfo above.  */
static gpg_error_t cmd_keyinfo(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int err;
  unsigned char grip[20];
  DIR *dir = NULL;
  int list_mode;
  int opt_data;
  char hexgrip[41];
  int disabled, ttl, confirm;

  list_mode = has_option(line, "--list");
  opt_data = has_option(line, "--data");
  line = skip_options(line);

  if (list_mode) {
    char *dirname;
    struct dirent *dir_entry;

    dirname = make_filename_try(gnupg_homedir(), GNUPG_PRIVATE_KEYS_DIR, NULL);
    if (!dirname) {
      err = gpg_error_from_syserror();
      goto leave;
    }
    dir = opendir(dirname);
    if (!dir) {
      err = gpg_error_from_syserror();
      xfree(dirname);
      goto leave;
    }
    xfree(dirname);

    while ((dir_entry = readdir(dir))) {
      if (strlen(dir_entry->d_name) != 44 ||
          strcmp(dir_entry->d_name + 40, ".key"))
        continue;
      strncpy(hexgrip, dir_entry->d_name, 40);
      hexgrip[40] = 0;

      if (hex2bin(hexgrip, grip, 20) < 0) continue; /* Bad hex string.  */

      disabled = ttl = confirm = 0;

      err = do_one_keyinfo(ctrl, grip, ctx, opt_data, ttl, disabled, confirm);
      if (err) goto leave;
    }
    err = 0;
  } else {
    err = parse_keygrip(ctx, line, grip);
    if (err) goto leave;
    disabled = ttl = confirm = 0;

    err = do_one_keyinfo(ctrl, grip, ctx, opt_data, ttl, disabled, confirm);
  }

leave:
  if (dir) closedir(dir);
  if (err && err != GPG_ERR_NOT_FOUND) leave_cmd(ctx, err);
  return err;
}

/* Helper for cmd_get_passphrase.  */
static int send_back_passphrase(assuan_context_t ctx, int via_data,
                                const char *pw) {
  size_t n;
  int rc;

  assuan_begin_confidential(ctx);
  n = strlen(pw);
  if (via_data)
    rc = assuan_send_data(ctx, pw, n);
  else {
    Botan::secure_vector<char> p(n * 2 + 1);
    bin2hex(pw, n, p.data());
    rc = assuan_set_okay_line(ctx, p.data());
  }
  return rc;
}

static const char hlp_get_passphrase[] =
    "GET_PASSPHRASE [--data] [--check] [--no-ask] [--repeat[=N]]\n"
    "               [--qualitybar] <cache_id>\n"
    "               [<error_message> <prompt> <description>]\n"
    "\n"
    "This function is usually used to ask for a passphrase to be used\n"
    "for conventional encryption, but may also be used by programs which\n"
    "need specal handling of passphrases.  This command uses a syntax\n"
    "which helps clients to use the agent with minimum effort.  The\n"
    "agent either returns with an error or with a OK followed by the hex\n"
    "encoded passphrase.  Note that the length of the strings is\n"
    "implicitly limited by the maximum length of a command.\n"
    "\n"
    "If the option \"--data\" is used the passphrase is returned by usual\n"
    "data lines and not on the okay line.\n"
    "\n"
    "If the option \"--no-ask\" is used and the passphrase is not in the\n"
    "cache the user will not be asked to enter a passphrase but the error\n"
    "code GPG_ERR_NO_DATA is returned.  \n";
static gpg_error_t cmd_get_passphrase(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc;
  char *pw;
  char *response;
  char *cacheid = NULL, *desc = NULL, *prompt = NULL, *errtext = NULL;
  const char *desc2 = _("Please re-enter this passphrase");
  char *p;
  int opt_data, opt_no_ask;
  int opt_repeat = 0;
  char *entry_errtext = NULL;

  opt_data = has_option(line, "--data");
  opt_no_ask = has_option(line, "--no-ask");
  if (has_option_name(line, "--repeat")) {
    p = option_value(line, "--repeat");
    if (p)
      opt_repeat = atoi(p);
    else
      opt_repeat = 1;
  }
  line = skip_options(line);

  cacheid = line;
  p = strchr(cacheid, ' ');
  if (p) {
    *p++ = 0;
    while (*p == ' ') p++;
    errtext = p;
    p = strchr(errtext, ' ');
    if (p) {
      *p++ = 0;
      while (*p == ' ') p++;
      prompt = p;
      p = strchr(prompt, ' ');
      if (p) {
        *p++ = 0;
        while (*p == ' ') p++;
        desc = p;
        p = strchr(desc, ' ');
        if (p) *p = 0; /* Ignore trailing garbage. */
      }
    }
  }
  if (!*cacheid || strlen(cacheid) > 50)
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid length of cacheID");
  if (!desc) return set_error(GPG_ERR_ASS_PARAMETER, "no description given");

  if (!strcmp(cacheid, "X")) cacheid = NULL;
  if (!strcmp(errtext, "X")) errtext = NULL;
  if (!strcmp(prompt, "X")) prompt = NULL;
  if (!strcmp(desc, "X")) desc = NULL;

  pw = cacheid ? agent_get_cache(cacheid, CACHE_MODE_USER) : NULL;
  if (pw) {
    rc = send_back_passphrase(ctx, opt_data, pw);
    xfree(pw);
  } else if (opt_no_ask)
    rc = GPG_ERR_NO_DATA;
  else {
    /* Note, that we only need to replace the + characters and
       should leave the other escaping in place because the escaped
       string is send verbatim to the pinentry which does the
       unescaping (but not the + replacing) */
    if (errtext) plus_to_blank(errtext);
    if (prompt) plus_to_blank(prompt);
    if (desc) plus_to_blank(desc);

  next_try:
    rc = agent_get_passphrase(ctrl, &response, desc, prompt,
                              entry_errtext ? entry_errtext : errtext, cacheid,
                              CACHE_MODE_USER);
    xfree(entry_errtext);
    entry_errtext = NULL;
    if (!rc) {
      if (cacheid) agent_put_cache(cacheid, CACHE_MODE_USER, response, 0);
      rc = send_back_passphrase(ctx, opt_data, response);
      xfree(response);
    }
  }

  return leave_cmd(ctx, rc);
}

static const char hlp_clear_passphrase[] =
    "CLEAR_PASSPHRASE [--mode=normal] <cache_id>\n"
    "\n"
    "may be used to invalidate the cache entry for a passphrase.  The\n"
    "function returns with OK even when there is no cached passphrase.\n"
    "The --mode=normal option is used to clear an entry for a cacheid\n"
    "added by the agent.\n";
static gpg_error_t cmd_clear_passphrase(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  char *cacheid = NULL;
  char *p;
  int opt_normal;

  opt_normal = has_option(line, "--mode=normal");
  line = skip_options(line);

  /* parse the stuff */
  for (p = line; *p == ' '; p++)
    ;
  cacheid = p;
  p = strchr(cacheid, ' ');
  if (p) *p = 0; /* ignore garbage */
  if (!*cacheid || strlen(cacheid) > 50)
    return set_error(GPG_ERR_ASS_PARAMETER, "invalid length of cacheID");

  agent_put_cache(cacheid, opt_normal ? CACHE_MODE_NORMAL : CACHE_MODE_USER,
                  NULL, 0);

  agent_clear_passphrase(ctrl, cacheid,
                         opt_normal ? CACHE_MODE_NORMAL : CACHE_MODE_USER);

  return 0;
}

static const char hlp_get_confirmation[] =
    "GET_CONFIRMATION <description>\n"
    "\n"
    "This command may be used to ask for a simple confirmation.\n"
    "DESCRIPTION is displayed along with a Okay and Cancel button.  This\n"
    "command uses a syntax which helps clients to use the agent with\n"
    "minimum effort.  The agent either returns with an error or with a\n"
    "OK.  Note, that the length of DESCRIPTION is implicitly limited by\n"
    "the maximum length of a command. DESCRIPTION should not contain\n"
    "any spaces, those must be encoded either percent escaped or simply\n"
    "as '+'.";
static gpg_error_t cmd_get_confirmation(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc;
  char *desc = NULL;
  char *p;

  /* parse the stuff */
  for (p = line; *p == ' '; p++)
    ;
  desc = p;
  p = strchr(desc, ' ');
  if (p) *p = 0; /* We ignore any garbage -may be later used for other args. */

  if (!*desc) return set_error(GPG_ERR_ASS_PARAMETER, "no description given");

  if (!strcmp(desc, "X")) desc = NULL;

  /* Note, that we only need to replace the + characters and should
     leave the other escaping in place because the escaped string is
     send verbatim to the pinentry which does the unescaping (but not
     the + replacing) */
  if (desc) plus_to_blank(desc);

  rc = agent_get_confirmation(ctrl, desc, NULL, NULL, 0);
  return leave_cmd(ctx, rc);
}

static const char hlp_learn[] =
    "LEARN [--send] [--sendinfo] [--force]\n"
    "\n"
    "Learn something about the currently inserted smartcard.  With\n"
    "--sendinfo information about the card is returned; with --send\n"
    "the available certificates are returned as D lines; with --force\n"
    "private key storage will be updated by the result.";
static gpg_error_t cmd_learn(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  gpg_error_t err;
  int send, sendinfo, force;

  send = has_option(line, "--send");
  sendinfo = send ? 1 : has_option(line, "--sendinfo");
  force = has_option(line, "--force");

  err = agent_handle_learn(ctrl, send, sendinfo ? ctx : NULL, force);
  return leave_cmd(ctx, err);
}

static const char hlp_passwd[] =
    "PASSWD [--cache-nonce=<c>] [--passwd-nonce=<s>]\n"
    "       [--verify] <hexkeygrip>\n"
    "\n"
    "Change the passphrase/PIN for the key identified by keygrip in LINE.\n"
    "If --verify is used the command asks for the passphrase and verifies\n"
    "that the passphrase valid.\n";
static gpg_error_t cmd_passwd(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  gpg_error_t err;
  int c;
  char *cache_nonce = NULL;
  char *passwd_nonce = NULL;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  unsigned char *shadow_info = NULL;
  char *passphrase = NULL;
  char *pend;
  int opt_verify;

  cache_nonce = option_value(line, "--cache-nonce");
  opt_verify = has_option(line, "--verify");
  if (cache_nonce) {
    for (pend = cache_nonce; *pend && !spacep(pend); pend++)
      ;
    c = *pend;
    *pend = '\0';
    cache_nonce = xtrystrdup(cache_nonce);
    *pend = c;
    if (!cache_nonce) {
      err = gpg_error_from_syserror();
      goto leave;
    }
  }

  passwd_nonce = option_value(line, "--passwd-nonce");
  if (passwd_nonce) {
    for (pend = passwd_nonce; *pend && !spacep(pend); pend++)
      ;
    c = *pend;
    *pend = '\0';
    passwd_nonce = xtrystrdup(passwd_nonce);
    *pend = c;
    if (!passwd_nonce) {
      err = gpg_error_from_syserror();
      goto leave;
    }
  }

  line = skip_options(line);

  err = parse_keygrip(ctx, line, grip);
  if (err) goto leave;

  ctrl->in_passwd++;
  err = agent_key_from_file(ctrl, opt_verify ? NULL : cache_nonce,
                            ctrl->server_local->keydesc, grip, &shadow_info,
                            CACHE_MODE_IGNORE, NULL, &s_skey, &passphrase);
  if (err)
    ;
  else if (shadow_info) {
    log_error("changing a smartcard PIN is not yet supported\n");
    err = GPG_ERR_NOT_IMPLEMENTED;
  } else if (opt_verify) {
    /* All done.  */
    if (passphrase) {
      if (!passwd_nonce) {
        char buf[12];
        gcry_create_nonce(buf, 12);
        passwd_nonce = bin2hex(buf, 12, NULL);
      }
      if (passwd_nonce &&
          !agent_put_cache(passwd_nonce, CACHE_MODE_NONCE, passphrase,
                           CACHE_TTL_NONCE)) {
        assuan_write_status(ctx, "PASSWD_NONCE", passwd_nonce);
        xfree(ctrl->server_local->last_passwd_nonce);
        ctrl->server_local->last_passwd_nonce = passwd_nonce;
        passwd_nonce = NULL;
      }
    }
  } else {
    char *newpass = NULL;

    if (passwd_nonce) newpass = agent_get_cache(passwd_nonce, CACHE_MODE_NONCE);
    err = agent_protect_and_store(ctrl, s_skey, &newpass);
    if (!err && passphrase) {
      /* A passphrase existed on the old key and the change was
         successful.  Return a nonce for that old passphrase to
         let the caller try to unprotect the other subkeys with
         the same key.  */
      if (!cache_nonce) {
        char buf[12];
        gcry_create_nonce(buf, 12);
        cache_nonce = bin2hex(buf, 12, NULL);
      }
      if (cache_nonce &&
          !agent_put_cache(cache_nonce, CACHE_MODE_NONCE, passphrase,
                           CACHE_TTL_NONCE)) {
        assuan_write_status(ctx, "CACHE_NONCE", cache_nonce);
        xfree(ctrl->server_local->last_cache_nonce);
        ctrl->server_local->last_cache_nonce = cache_nonce;
        cache_nonce = NULL;
      }
      if (newpass) {
        /* If we have a new passphrase (which might be empty) we
           store it under a passwd nonce so that the caller may
           send that nonce again to use it for another key. */
        if (!passwd_nonce) {
          char buf[12];
          gcry_create_nonce(buf, 12);
          passwd_nonce = bin2hex(buf, 12, NULL);
        }
        if (passwd_nonce &&
            !agent_put_cache(passwd_nonce, CACHE_MODE_NONCE, newpass,
                             CACHE_TTL_NONCE)) {
          assuan_write_status(ctx, "PASSWD_NONCE", passwd_nonce);
          xfree(ctrl->server_local->last_passwd_nonce);
          ctrl->server_local->last_passwd_nonce = passwd_nonce;
          passwd_nonce = NULL;
        }
      }
    }
    xfree(newpass);
  }
  ctrl->in_passwd--;

  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

leave:
  xfree(passphrase);
  gcry_sexp_release(s_skey);
  xfree(shadow_info);
  xfree(cache_nonce);
  xfree(passwd_nonce);
  return leave_cmd(ctx, err);
}

static const char hlp_scd[] =
    "SCD <commands to pass to the scdaemon>\n"
    " \n"
    "This is a general quote command to redirect everything to the\n"
    "SCdaemon.";
static gpg_error_t cmd_scd(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc;

  rc = divert_generic_cmd(ctrl, line, ctx);

  return rc;
}

static const char hlp_import_key[] =
    "IMPORT_KEY [--unattended] [--force] [<cache_nonce>]\n"
    "\n"
    "Import a secret key into the key store.  This function takes\n"
    "no arguments but uses the inquiry \"KEYDATA\" to ask for the actual\n"
    "key data.  The key must be a canonical S-expression.  The\n"
    "option --unattended tries to import the key as-is without any\n"
    "re-encryption.  Existing key can be overwritten with --force.";
static gpg_error_t cmd_import_key(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  gpg_error_t err;
  int opt_unattended;
  int force;
  unsigned char *key = NULL;
  size_t keylen, realkeylen;
  char *passphrase = NULL;
  unsigned char *finalkey = NULL;
  size_t finalkeylen;
  unsigned char grip[20];
  gcry_sexp_t openpgp_sexp = NULL;
  char *cache_nonce = NULL;
  char *p;

  opt_unattended = has_option(line, "--unattended");
  force = has_option(line, "--force");
  line = skip_options(line);

  for (p = line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  *p = '\0';
  if (*line) cache_nonce = xtrystrdup(line);

  assuan_begin_confidential(ctx);
  err = assuan_inquire(ctx, "KEYDATA", &key, &keylen, MAXLEN_KEYDATA);
  assuan_end_confidential(ctx);
  if (err) goto leave;
  if (keylen < 16) {
    err = GPG_ERR_INV_LENGTH;
    goto leave;
  }

  realkeylen = gcry_sexp_canon_len(key, keylen, NULL, &err);
  if (!realkeylen) goto leave; /* Invalid canonical encoded S-expression.  */

  err = keygrip_from_canon_sexp(key, realkeylen, grip);
  if (err) {
    /* This might be due to an unsupported S-expression format.
       Check whether this is openpgp-private-key and trigger that
       import code.  */
    if (!gcry_sexp_sscan(&openpgp_sexp, NULL, (const char *)(key),
                         realkeylen)) {
      const char *tag;
      size_t taglen;

      tag = gcry_sexp_nth_data(openpgp_sexp, 0, &taglen);
      if (tag && taglen == 19 && !memcmp(tag, "openpgp-private-key", 19))
        ;
      else {
        gcry_sexp_release(openpgp_sexp);
        openpgp_sexp = NULL;
      }
    }
    if (!openpgp_sexp) goto leave; /* Note that ERR is still set.  */
  }

  if (openpgp_sexp) {
    /* In most cases the key is encrypted and thus the conversion
       function from the OpenPGP format to our internal format will
       ask for a passphrase.  That passphrase will be returned and
       used to protect the key using the same code as for regular
       key import. */

    xfree(key);
    key = NULL;
    err = convert_from_openpgp(ctrl, openpgp_sexp, force, grip,
                               ctrl->server_local->keydesc, cache_nonce, &key,
                               opt_unattended ? NULL : &passphrase);
    if (err) goto leave;
    realkeylen = gcry_sexp_canon_len(key, 0, NULL, &err);
    if (!realkeylen) goto leave; /* Invalid canonical encoded S-expression.  */
    if (passphrase) {
      assert(!opt_unattended);
      if (!cache_nonce) {
        char buf[12];
        gcry_create_nonce(buf, 12);
        cache_nonce = bin2hex(buf, 12, NULL);
      }
      if (cache_nonce &&
          !agent_put_cache(cache_nonce, CACHE_MODE_NONCE, passphrase,
                           CACHE_TTL_NONCE))
        assuan_write_status(ctx, "CACHE_NONCE", cache_nonce);
    }
  } else if (opt_unattended) {
    err = set_error(GPG_ERR_ASS_PARAMETER,
                    "\"--unattended\" may only be used with OpenPGP keys");
    goto leave;
  } else {
    if (!force && !agent_key_available(grip))
      err = GPG_ERR_EEXIST;
    else {
      char *prompt =
          xtryasprintf(_("Please enter the passphrase to protect the "
                         "imported object within the %s system."),
                       GNUPG_NAME);
      if (!prompt)
        err = gpg_error_from_syserror();
      else
        err = agent_ask_new_passphrase(ctrl, prompt, &passphrase);
      xfree(prompt);
    }
    if (err) goto leave;
  }

  if (passphrase) {
    err = agent_protect(key, passphrase, &finalkey, &finalkeylen,
                        ctrl->s2k_count, -1);
    if (!err) err = agent_write_private_key(grip, finalkey, finalkeylen, force);
  } else
    err = agent_write_private_key(grip, key, realkeylen, force);

leave:
  gcry_sexp_release(openpgp_sexp);
  xfree(finalkey);
  xfree(passphrase);
  xfree(key);
  xfree(cache_nonce);
  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  return leave_cmd(ctx, err);
}

static const char hlp_export_key[] =
    "EXPORT_KEY [--cache-nonce=<nonce>] [--openpgp] <hexstring_with_keygrip>\n"
    "\n"
    "Export a secret key from the key store.  The function takes the keygrip "
    "as argument.\n"
    "\n"
    "If --openpgp is used, the secret key material will be exported in RFC "
    "4880\n"
    "compatible passphrase-protected form.  Without --openpgp, the secret key\n"
    "material will be exported in the clear (after prompting the user to "
    "unlock\n"
    "it, if needed).\n";
static gpg_error_t cmd_export_key(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  gpg_error_t err;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  unsigned char *key = NULL;
  size_t keylen;
  int openpgp;
  char *cache_nonce;
  char *passphrase = NULL;
  unsigned char *shadow_info = NULL;
  char *pend;
  int c;

  openpgp = has_option(line, "--openpgp");
  cache_nonce = option_value(line, "--cache-nonce");
  if (cache_nonce) {
    for (pend = cache_nonce; *pend && !spacep(pend); pend++)
      ;
    c = *pend;
    *pend = '\0';
    cache_nonce = xtrystrdup(cache_nonce);
    *pend = c;
    if (!cache_nonce) {
      err = gpg_error_from_syserror();
      goto leave;
    }
  }
  line = skip_options(line);

  err = parse_keygrip(ctx, line, grip);
  if (err) goto leave;

  if (agent_key_available(grip)) {
    err = GPG_ERR_NO_SECKEY;
    goto leave;
  }

  /* Get the key from the file.  With the openpgp flag we also ask for
     the passphrase so that we can use it to re-encrypt it.  */
  err = agent_key_from_file(ctrl, cache_nonce, ctrl->server_local->keydesc,
                            grip, &shadow_info, CACHE_MODE_IGNORE, NULL,
                            &s_skey, openpgp ? &passphrase : NULL);
  if (err) goto leave;
  if (shadow_info) {
    /* Key is on a smartcard.  */
    err = GPG_ERR_UNUSABLE_SECKEY;
    goto leave;
  }

  if (openpgp) {
    /* The openpgp option changes the key format into the OpenPGP
       key transfer format.  The result is already a padded
       canonical S-expression.  */
    if (!passphrase) {
      err = agent_ask_new_passphrase(
          ctrl, _("This key (or subkey) is not protected with a passphrase."
                  "  Please enter a new passphrase to export it."),
          &passphrase);
      if (err) goto leave;
    }
    err = convert_to_openpgp(ctrl, s_skey, passphrase, &key, &keylen);
    if (!err && passphrase) {
      if (!cache_nonce) {
        char buf[12];
        gcry_create_nonce(buf, 12);
        cache_nonce = bin2hex(buf, 12, NULL);
      }
      if (cache_nonce &&
          !agent_put_cache(cache_nonce, CACHE_MODE_NONCE, passphrase,
                           CACHE_TTL_NONCE)) {
        assuan_write_status(ctx, "CACHE_NONCE", cache_nonce);
        xfree(ctrl->server_local->last_cache_nonce);
        ctrl->server_local->last_cache_nonce = cache_nonce;
        cache_nonce = NULL;
      }
    }
  } else {
    /* Convert into a canonical S-expression and wrap that.  */
    err = make_canon_sexp_pad(s_skey, 1, &key, &keylen);
  }
  if (err) goto leave;
  gcry_sexp_release(s_skey);
  s_skey = NULL;

  assuan_begin_confidential(ctx);
  err = assuan_send_data(ctx, key, keylen);
  assuan_end_confidential(ctx);

leave:
  xfree(cache_nonce);
  xfree(passphrase);
  xfree(key);
  gcry_sexp_release(s_skey);
  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;
  xfree(shadow_info);

  return leave_cmd(ctx, err);
}

static const char hlp_delete_key[] =
    "DELETE_KEY [--force|--stub-only] <hexstring_with_keygrip>\n"
    "\n"
    "Delete a secret key from the key store.  If --force is used\n"
    "and a loopback pinentry is allowed, the agent will not ask\n"
    "the user for confirmation.  If --stub-only is used the key will\n"
    "only be deleted if it is a reference to a token.";
static gpg_error_t cmd_delete_key(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  gpg_error_t err;
  int force, stub_only;
  unsigned char grip[20];

  force = has_option(line, "--force");
  stub_only = has_option(line, "--stub-only");
  line = skip_options(line);

  err = parse_keygrip(ctx, line, grip);
  if (err) goto leave;

  err = agent_delete_key(ctrl, ctrl->server_local->keydesc, grip, force,
                         stub_only);
  if (err) goto leave;

leave:
  xfree(ctrl->server_local->keydesc);
  ctrl->server_local->keydesc = NULL;

  return leave_cmd(ctx, err);
}

#if SIZEOF_TIME_T > SIZEOF_UNSIGNED_LONG
#define KEYTOCARD_TIMESTAMP_FORMAT "(10:created-at10:%010llu))"
#else
#define KEYTOCARD_TIMESTAMP_FORMAT "(10:created-at10:%010lu))"
#endif

static const char hlp_keytocard[] =
    "KEYTOCARD [--force] <hexstring_with_keygrip> <serialno> <id> <timestamp>\n"
    "\n";
static gpg_error_t cmd_keytocard(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int force;
  gpg_error_t err = 0;
  unsigned char grip[20];
  gcry_sexp_t s_skey = NULL;
  Botan::secure_vector<unsigned char> keydata;
  size_t keydatalen;
  const char *serialno, *timestamp_str, *id;
  unsigned char *shadow_info = NULL;
  time_t timestamp;

  force = has_option(line, "--force");
  line = skip_options(line);

  err = parse_keygrip(ctx, line, grip);
  if (err) goto leave;

  if (agent_key_available(grip)) {
    err = GPG_ERR_NO_SECKEY;
    goto leave;
  }

  line += 40;
  while (*line && (*line == ' ' || *line == '\t')) line++;
  serialno = line;
  while (*line && (*line != ' ' && *line != '\t')) line++;
  if (!*line) {
    err = GPG_ERR_MISSING_VALUE;
    goto leave;
  }
  *line = '\0';
  line++;
  while (*line && (*line == ' ' || *line == '\t')) line++;
  id = line;
  while (*line && (*line != ' ' && *line != '\t')) line++;
  if (!*line) {
    err = GPG_ERR_MISSING_VALUE;
    goto leave;
  }
  *line = '\0';
  line++;
  while (*line && (*line == ' ' || *line == '\t')) line++;
  timestamp_str = line;
  while (*line && (*line != ' ' && *line != '\t')) line++;
  if (*line) *line = '\0';

  if ((timestamp = isotime2epoch(timestamp_str)) == (time_t)(-1)) {
    err = GPG_ERR_INV_TIME;
    goto leave;
  }

  err =
      agent_key_from_file(ctrl, NULL, ctrl->server_local->keydesc, grip,
                          &shadow_info, CACHE_MODE_IGNORE, NULL, &s_skey, NULL);
  if (err) {
    xfree(shadow_info);
    goto leave;
  }
  if (shadow_info) {
    /* Key is on a smartcard already.  */
    xfree(shadow_info);
    gcry_sexp_release(s_skey);
    err = GPG_ERR_UNUSABLE_SECKEY;
    goto leave;
  }

  keydatalen = gcry_sexp_sprint(s_skey, GCRYSEXP_FMT_CANON, NULL, 0);
  keydata.resize(keydatalen + 30);

  gcry_sexp_sprint(s_skey, GCRYSEXP_FMT_CANON, keydata.data(), keydatalen);
  gcry_sexp_release(s_skey);
  keydatalen--; /* Decrement for last '\0'.  */
  /* Add timestamp "created-at" in the private key */
  snprintf((char *)(keydata.data() + keydatalen - 1), 30,
           KEYTOCARD_TIMESTAMP_FORMAT, timestamp);
  keydatalen += 10 + 19 - 1;
  err = divert_writekey(ctrl, force, serialno, id,
                        (const char *)(keydata.data()), keydatalen);

leave:
  return leave_cmd(ctx, err);
}

static const char hlp_getinfo[] =
    "GETINFO <what>\n"
    "\n"
    "Multipurpose function to return a variety of information.\n"
    "Supported values for WHAT are:\n"
    "\n"
    "  version     - Return the version of the program.\n"
    "  pid         - Return the process id of the server.\n"
    "  s2k_count   - Return the calibrated S2K count.\n"
    "  cmd_has_option\n"
    "              - Returns OK if the command CMD implements the option OPT.\n"
    "  connections - Return number of active connections.\n";
static gpg_error_t cmd_getinfo(assuan_context_t ctx, char *line) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  int rc = 0;

  if (!strcmp(line, "version")) {
    const char *s = VERSION;
    rc = assuan_send_data(ctx, s, strlen(s));
  } else if (!strncmp(line, "cmd_has_option", 14) &&
             (line[14] == ' ' || line[14] == '\t' || !line[14])) {
    char *cmd, *cmdopt;
    line += 14;
    while (*line == ' ' || *line == '\t') line++;
    if (!*line)
      rc = GPG_ERR_MISSING_VALUE;
    else {
      cmd = line;
      while (*line && (*line != ' ' && *line != '\t')) line++;
      if (!*line)
        rc = GPG_ERR_MISSING_VALUE;
      else {
        *line++ = 0;
        while (*line == ' ' || *line == '\t') line++;
        if (!*line)
          rc = GPG_ERR_MISSING_VALUE;
        else {
          cmdopt = line;
          if (!command_has_option(cmd, cmdopt)) rc = GPG_ERR_GENERAL;
        }
      }
    }
  } else if (!strcmp(line, "s2k_count")) {
    char numbuf[50];

    snprintf(numbuf, sizeof numbuf, "%lu", get_standard_s2k_count());
    rc = assuan_send_data(ctx, numbuf, strlen(numbuf));
  } else
    rc = set_error(GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");
  return rc;
}

/* This function is called by Libassuan to parse the OPTION command.
   It has been registered similar to the other Assuan commands.  */
static gpg_error_t option_handler(assuan_context_t ctx, const char *key,
                                  const char *value) {
  ctrl_t ctrl = (ctrl_t)assuan_get_pointer(ctx);
  gpg_error_t err = 0;

  if (!strcmp(key, "lc-ctype")) {
    if (ctrl->lc_ctype) xfree(ctrl->lc_ctype);
    ctrl->lc_ctype = xtrystrdup(value);
    if (!ctrl->lc_ctype) return gpg_error_from_syserror();
  } else if (!strcmp(key, "lc-messages")) {
    if (ctrl->lc_messages) xfree(ctrl->lc_messages);
    ctrl->lc_messages = xtrystrdup(value);
    if (!ctrl->lc_messages) return gpg_error_from_syserror();
  } else if (!strcmp(key, "use-cache-for-signing"))
    ctrl->server_local->use_cache_for_signing = *value ? !!atoi(value) : 0;
  else if (!strcmp(key, "s2k-count")) {
    ctrl->s2k_count = *value ? strtoul(value, NULL, 10) : 0;
    if (ctrl->s2k_count && ctrl->s2k_count < 65536) {
      ctrl->s2k_count = 0;
    }
  } else
    err = GPG_ERR_UNKNOWN_OPTION;

  return err;
}

/* Return true if the command CMD implements the option OPT.  */
static int command_has_option(const char *cmd, const char *cmdopt) {
  if (!strcmp(cmd, "GET_PASSPHRASE")) {
    if (!strcmp(cmdopt, "repeat")) return 1;
  }

  return 0;
}

/* Tell Libassuan about our commands.  Also register the other Assuan
   handlers. */
static int register_commands(assuan_context_t ctx) {
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char *const help;
  } table[] = {{"ISTRUSTED", cmd_istrusted, hlp_istrusted},
               {"HAVEKEY", cmd_havekey, hlp_havekey},
               {"KEYINFO", cmd_keyinfo, hlp_keyinfo},
               {"SIGKEY", cmd_sigkey, hlp_sigkey},
               {"SETKEY", cmd_sigkey, hlp_sigkey},
               {"SETKEYDESC", cmd_setkeydesc, hlp_setkeydesc},
               {"SETHASH", cmd_sethash, hlp_sethash},
               {"PKSIGN", cmd_pksign, hlp_pksign},
               {"PKDECRYPT", cmd_pkdecrypt, hlp_pkdecrypt},
               {"GENKEY", cmd_genkey, hlp_genkey},
               {"READKEY", cmd_readkey, hlp_readkey},
               {"GET_PASSPHRASE", cmd_get_passphrase, hlp_get_passphrase},
               {"CLEAR_PASSPHRASE", cmd_clear_passphrase, hlp_clear_passphrase},
               {"GET_CONFIRMATION", cmd_get_confirmation, hlp_get_confirmation},
               {"LISTTRUSTED", cmd_listtrusted, hlp_listtrusted},
               {"MARKTRUSTED", cmd_marktrusted, hlp_martrusted},
               {"LEARN", cmd_learn, hlp_learn},
               {"PASSWD", cmd_passwd, hlp_passwd},
               {"INPUT", NULL, NULL},
               {"OUTPUT", NULL, NULL},
               {"SCD", cmd_scd, hlp_scd},
               {"IMPORT_KEY", cmd_import_key, hlp_import_key},
               {"EXPORT_KEY", cmd_export_key, hlp_export_key},
               {"DELETE_KEY", cmd_delete_key, hlp_delete_key},
               {"GETINFO", cmd_getinfo, hlp_getinfo},
               {"KEYTOCARD", cmd_keytocard, hlp_keytocard},
               {NULL, NULL, NULL}};
  int i, rc;

  for (i = 0; table[i].name; i++) {
    rc = assuan_register_command(ctx, table[i].name, table[i].handler,
                                 table[i].help);
    if (rc) return rc;
  }
  assuan_register_reset_notify(ctx, reset_notify);
  assuan_register_option_handler(ctx, option_handler);
  return 0;
}

/* Startup the server.  CTRL is the control structure for this
   connection; it has only the basic initialization. */
void start_command_handler(ctrl_t ctrl) {
  int rc;
  assuan_context_t ctx = NULL;
  assuan_fd_t filedes[2];

  rc = assuan_new(&ctx);
  if (rc) {
    log_error("failed to allocate assuan context: %s\n", gpg_strerror(rc));
    agent_exit(2);
  }

  filedes[0] = assuan_fdopen(0);
  filedes[1] = assuan_fdopen(1);
  rc = assuan_init_pipe_server(ctx, filedes);
  if (rc) {
    log_error("failed to initialize the server: %s\n", gpg_strerror(rc));
    agent_exit(2);
  }
  rc = register_commands(ctx);
  if (rc) {
    log_error("failed to register commands with Assuan: %s\n",
              gpg_strerror(rc));
    agent_exit(2);
  }

  assuan_set_pointer(ctx, ctrl);
  ctrl->server_local = (server_local_s *)xcalloc(1, sizeof *ctrl->server_local);
  ctrl->server_local->assuan_ctx = ctx;
  ctrl->server_local->use_cache_for_signing = 1;

  ctrl->digest.raw_value = 0;

  for (;;) {
    rc = assuan_accept(ctx);
    if (rc == GPG_ERR_EOF || rc == -1) {
      break;
    } else if (rc) {
      log_info("Assuan accept problem: %s\n", gpg_strerror(rc));
      break;
    }

    rc = assuan_process(ctx);
    if (rc) {
      log_info("Assuan processing failed: %s\n", gpg_strerror(rc));
      continue;
    }
  }

  /* Reset the nonce caches.  */
  clear_nonce_cache(ctrl);

  /* Reset the SCD if needed. */
  agent_reset_scd(ctrl);

  /* Reset the pinentry (in case of popup messages). */
  agent_reset_query(ctrl);

  /* Cleanup.  */
  assuan_release(ctx);
  xfree(ctrl->server_local->keydesc);
  xfree(ctrl->server_local);
  ctrl->server_local = NULL;
}

/* Helper for the pinentry loopback mode.  It merely passes the
   parameters on to the client.  */
gpg_error_t pinentry_loopback(ctrl_t ctrl, const char *keyword,
                              unsigned char **buffer, size_t *size,
                              size_t max_length) {
  gpg_error_t rc;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  rc = print_assuan_status(ctx, "INQUIRE_MAXLEN", "%zu", max_length);
  if (rc) return rc;

  assuan_begin_confidential(ctx);
  rc = assuan_inquire(ctx, keyword, buffer, size, max_length);
  assuan_end_confidential(ctx);
  return rc;
}
