/* call-agent.c - Divert GPG operations to the agent.
 * Copyright (C) 2001-2003, 2006-2011, 2013 Free Software Foundation, Inc.
 * Copyright (C) 2013-2015  Werner Koch
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include <boost/algorithm/string.hpp>

#include <assuan.h>
#include "../common/asshelp.h"
#include "../common/host2net.h"
#include "../common/membuf.h"
#include "../common/status.h"
#include "../common/sysutils.h"
#include "../common/util.h"
#include "call-agent.h"
#include "gpg.h"
#include "options.h"

#define CONTROL_D ('D' - 'A' + 1)

static assuan_context_t agent_ctx = NULL;
static int did_early_card_test;

struct default_inq_parm_s {
  ctrl_t ctrl;
  assuan_context_t ctx;
  struct {
    u32 *keyid;
    u32 *mainkeyid;
    int pubkey_algo;
  } keyinfo;
};

struct cipher_parm_s {
  struct default_inq_parm_s *dflt;
  assuan_context_t ctx;
  unsigned char *ciphertext;
  size_t ciphertextlen;
};

struct writecert_parm_s {
  struct default_inq_parm_s *dflt;
  const unsigned char *certdata;
  size_t certdatalen;
};

struct writekey_parm_s {
  struct default_inq_parm_s *dflt;
  const unsigned char *keydata;
  size_t keydatalen;
};

struct genkey_parm_s {
  struct default_inq_parm_s *dflt;
  const char *keyparms;
  const char *passphrase;
};

struct import_key_parm_s {
  struct default_inq_parm_s *dflt;
  const void *key;
  size_t keylen;
};

struct cache_nonce_parm_s {
  char **cache_nonce_addr;
  char **passwd_nonce_addr;
};

static gpg_error_t learn_status_cb(void *opaque, const char *line);

/* If RC is not 0, write an appropriate status message. */
static void status_sc_op_failure(int rc) {
  switch (rc) {
    case 0:
      break;
    case GPG_ERR_CANCELED:
    case GPG_ERR_FULLY_CANCELED:
      write_status_text(STATUS_SC_OP_FAILURE, "1");
      break;
    case GPG_ERR_BAD_PIN:
      write_status_text(STATUS_SC_OP_FAILURE, "2");
      break;
    default:
      write_status(STATUS_SC_OP_FAILURE);
      break;
  }
}

/* This is the default inquiry callback.  It mainly handles the
   Pinentry notifications.  */
static gpg_error_t default_inq_cb(void *opaque, const char *line) {
  gpg_error_t err = 0;
  struct default_inq_parm_s *parm = (default_inq_parm_s *)opaque;

  if (has_leading_keyword(line, "PASSPHRASE") ||
      has_leading_keyword(line, "NEW_PASSPHRASE")) {
    if (have_static_passphrase()) {
      const char *s = get_static_passphrase();
      err = assuan_send_data(parm->ctx, s, strlen(s));
    } else {
      Botan::secure_vector<char> *pw;
      char buf[32];

      if (parm->keyinfo.keyid)
        emit_status_need_passphrase(parm->ctrl, parm->keyinfo.keyid,
                                    parm->keyinfo.mainkeyid,
                                    parm->keyinfo.pubkey_algo);

      snprintf(buf, sizeof(buf), "%u", 100);
      write_status_text(STATUS_INQUIRE_MAXLEN, buf);
      pw = cpr_get_hidden("passphrase.enter", _("Enter passphrase: "));
      cpr_kill_prompt();
      if ((*pw)[0] == CONTROL_D && !(*pw)[1])
        err = GPG_ERR_CANCELED;
      else
        err = assuan_send_data(parm->ctx, pw->data(), strlen(pw->data()));
      delete pw;
    }
  } else
    log_debug("ignoring gpg-agent inquiry '%s'\n", line);

  return err;
}

#define FLAG_FOR_CARD_SUPPRESS_ERRORS 2

/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int start_agent(ctrl_t ctrl, int flag_for_card) {
  int rc;

  (void)ctrl; /* Not yet used.  */

  /* Fixme: We need a context for each thread or serialize the access
     to the agent. */
  if (agent_ctx)
    rc = 0;
  else {
    rc = start_new_gpg_agent(&agent_ctx,
                             opt.lc_ctype ? opt.lc_ctype->c_str() : NULL,
                             opt.lc_messages ? opt.lc_messages->c_str() : NULL,
                             opt.verbose, DBG_IPC);
  }

  if (!rc && flag_for_card && !did_early_card_test) {
    /* Request the serial number of the card for an early test.  */
    struct agent_card_info_s info;

    memset(&info, 0, sizeof info);

    if (!rc)
      rc = assuan_transact(agent_ctx, "SCD SERIALNO openpgp", NULL, NULL, NULL,
                           NULL, learn_status_cb, &info);
    if (rc && !(flag_for_card & FLAG_FOR_CARD_SUPPRESS_ERRORS)) {
      switch (rc) {
        case GPG_ERR_NOT_SUPPORTED:
        case GPG_ERR_NO_SCDAEMON:
          write_status_text(STATUS_CARDCTRL, "6");
          break;
        case GPG_ERR_OBJ_TERM_STATE:
          write_status_text(STATUS_CARDCTRL, "7");
          break;
        default:
          write_status_text(STATUS_CARDCTRL, "4");
          log_info("selecting openpgp failed: %s\n", gpg_strerror(rc));
          break;
      }
    }

    if (!rc && is_status_enabled() && info.serialno) {
      char *buf;

      buf = xasprintf("3 %s", info.serialno);
      write_status_text(STATUS_CARDCTRL, buf);
      xfree(buf);
    }

    agent_release_card_info(&info);

    if (!rc) did_early_card_test = 1;
  }

  return rc;
}

/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *unescape_status_string(const unsigned char *s) {
  return percent_plus_unescape((const char *)(s), 0xff);
}

/* Take a 20 byte hexencoded string and put it into the provided
   20 byte buffer FPR in binary format. */
static int unhexify_fpr(const char *hexstr, unsigned char *fpr) {
  const char *s;
  int n;

  for (s = hexstr, n = 0; hexdigitp(s); s++, n++)
    ;
  if (*s || (n != 40)) return 0; /* no fingerprint (invalid or wrong length). */
  for (s = hexstr, n = 0; *s; s += 2, n++) fpr[n] = xtoi_2(s);
  return 1; /* okay */
}

/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned. */
static char *store_serialno(const char *line) {
  const char *s;
  char *p;

  for (s = line; hexdigitp(s); s++)
    ;
  p = (char *)xtrymalloc(s + 1 - line);
  if (p) {
    memcpy(p, line, s - line);
    p[s - line] = 0;
  }
  return p;
}

/* This is a dummy data line callback.  */
static gpg_error_t dummy_data_cb(void *opaque, const void *buffer,
                                 size_t length) {
  (void)opaque;
  (void)buffer;
  (void)length;
  return 0;
}

/* A simple callback used to return the serialnumber of a card.  */
static gpg_error_t get_serialno_cb(void *opaque, const char *line) {
  char **serialno = (char **)opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen = 0; *line && !spacep(line); line++, keywordlen++)
    ;
  while (spacep(line)) line++;

  if (keywordlen == 8 && !memcmp(keyword, "SERIALNO", keywordlen)) {
    if (*serialno) return GPG_ERR_CONFLICT; /* Unexpected status line. */
    for (n = 0, s = line; hexdigitp(s); s++, n++)
      ;
    if (!n || (n & 1) || !(spacep(s) || !*s)) return GPG_ERR_ASS_PARAMETER;
    *serialno = (char *)xtrymalloc(n + 1);
    if (!*serialno) return gpg_error_from_syserror();
    memcpy(*serialno, line, n);
    (*serialno)[n] = 0;
  }

  return 0;
}

/* Release the card info structure INFO. */
void agent_release_card_info(struct agent_card_info_s *info) {
  int i;

  if (!info) return;

  xfree(info->reader);
  info->reader = NULL;
  xfree(info->serialno);
  info->serialno = NULL;
  xfree(info->apptype);
  info->apptype = NULL;
  xfree(info->disp_name);
  info->disp_name = NULL;
  xfree(info->disp_lang);
  info->disp_lang = NULL;
  xfree(info->pubkey_url);
  info->pubkey_url = NULL;
  xfree(info->login_data);
  info->login_data = NULL;
  info->cafpr1valid = info->cafpr2valid = info->cafpr3valid = 0;
  info->fpr1valid = info->fpr2valid = info->fpr3valid = 0;
  for (i = 0; i < DIM(info->private_do); i++) {
    xfree(info->private_do[i]);
    info->private_do[i] = NULL;
  }
}

static gpg_error_t learn_status_cb(void *opaque, const char *line) {
  struct agent_card_info_s *parm = (agent_card_info_s *)opaque;
  const char *keyword = line;
  int keywordlen;
  int i;

  for (keywordlen = 0; *line && !spacep(line); line++, keywordlen++)
    ;
  while (spacep(line)) line++;

  if (keywordlen == 6 && !memcmp(keyword, "READER", keywordlen)) {
    xfree(parm->reader);
    parm->reader = unescape_status_string((const unsigned char *)(line));
  } else if (keywordlen == 8 && !memcmp(keyword, "SERIALNO", keywordlen)) {
    xfree(parm->serialno);
    parm->serialno = store_serialno(line);
    parm->is_v2 =
        (strlen(parm->serialno) >= 16 && xtoi_2(parm->serialno + 12) >= 2);
  } else if (keywordlen == 7 && !memcmp(keyword, "APPTYPE", keywordlen)) {
    xfree(parm->apptype);
    parm->apptype = unescape_status_string((const unsigned char *)(line));
  } else if (keywordlen == 9 && !memcmp(keyword, "DISP-NAME", keywordlen)) {
    xfree(parm->disp_name);
    parm->disp_name = unescape_status_string((const unsigned char *)(line));
  } else if (keywordlen == 9 && !memcmp(keyword, "DISP-LANG", keywordlen)) {
    xfree(parm->disp_lang);
    parm->disp_lang = unescape_status_string((const unsigned char *)(line));
  } else if (keywordlen == 8 && !memcmp(keyword, "DISP-SEX", keywordlen)) {
    parm->disp_sex = *line == '1' ? 1 : *line == '2' ? 2 : 0;
  } else if (keywordlen == 10 && !memcmp(keyword, "PUBKEY-URL", keywordlen)) {
    xfree(parm->pubkey_url);
    parm->pubkey_url = unescape_status_string((const unsigned char *)(line));
  } else if (keywordlen == 10 && !memcmp(keyword, "LOGIN-DATA", keywordlen)) {
    xfree(parm->login_data);
    parm->login_data = unescape_status_string((const unsigned char *)(line));
  } else if (keywordlen == 11 && !memcmp(keyword, "SIG-COUNTER", keywordlen)) {
    parm->sig_counter = strtoul(line, NULL, 0);
  } else if (keywordlen == 10 && !memcmp(keyword, "CHV-STATUS", keywordlen)) {
    char *p, *buf;

    buf = p = unescape_status_string((const unsigned char *)(line));
    if (buf) {
      while (spacep(p)) p++;
      parm->chv1_cached = atoi(p);
      while (*p && !spacep(p)) p++;
      while (spacep(p)) p++;
      for (i = 0; *p && i < 3; i++) {
        parm->chvmaxlen[i] = atoi(p);
        while (*p && !spacep(p)) p++;
        while (spacep(p)) p++;
      }
      for (i = 0; *p && i < 3; i++) {
        parm->chvretry[i] = atoi(p);
        while (*p && !spacep(p)) p++;
        while (spacep(p)) p++;
      }
      xfree(buf);
    }
  } else if (keywordlen == 6 && !memcmp(keyword, "EXTCAP", keywordlen)) {
    char *p, *p2, *buf;
    int abool;

    buf = p = unescape_status_string((const unsigned char *)(line));
    if (buf) {
      for (p = strtok(buf, " "); p; p = strtok(NULL, " ")) {
        p2 = strchr(p, '=');
        if (p2) {
          *p2++ = 0;
          abool = (*p2 == '1');
          if (!strcmp(p, "ki"))
            parm->extcap.ki = abool;
          else if (!strcmp(p, "aac"))
            parm->extcap.aac = abool;
          else if (!strcmp(p, "si"))
            parm->status_indicator = strtoul(p2, NULL, 10);
        }
      }
      xfree(buf);
    }
  } else if (keywordlen == 7 && !memcmp(keyword, "KEY-FPR", keywordlen)) {
    int no = atoi(line);
    while (*line && !spacep(line)) line++;
    while (spacep(line)) line++;
    if (no == 1)
      parm->fpr1valid = unhexify_fpr(line, (unsigned char *)(parm->fpr1));
    else if (no == 2)
      parm->fpr2valid = unhexify_fpr(line, (unsigned char *)(parm->fpr2));
    else if (no == 3)
      parm->fpr3valid = unhexify_fpr(line, (unsigned char *)(parm->fpr3));
  } else if (keywordlen == 8 && !memcmp(keyword, "KEY-TIME", keywordlen)) {
    int no = atoi(line);
    while (*line && !spacep(line)) line++;
    while (spacep(line)) line++;
    if (no == 1)
      parm->fpr1time = strtoul(line, NULL, 10);
    else if (no == 2)
      parm->fpr2time = strtoul(line, NULL, 10);
    else if (no == 3)
      parm->fpr3time = strtoul(line, NULL, 10);
  } else if (keywordlen == 6 && !memcmp(keyword, "CA-FPR", keywordlen)) {
    int no = atoi(line);
    while (*line && !spacep(line)) line++;
    while (spacep(line)) line++;
    if (no == 1)
      parm->cafpr1valid = unhexify_fpr(line, (unsigned char *)(parm->cafpr1));
    else if (no == 2)
      parm->cafpr2valid = unhexify_fpr(line, (unsigned char *)(parm->cafpr2));
    else if (no == 3)
      parm->cafpr3valid = unhexify_fpr(line, (unsigned char *)(parm->cafpr3));
  } else if (keywordlen == 8 && !memcmp(keyword, "KEY-ATTR", keywordlen)) {
    int keyno = 0;
    int algo = PUBKEY_ALGO_RSA;
    int n = 0;

    sscanf(line, "%d %d %n", &keyno, &algo, &n);
    keyno--;
    if (keyno < 0 || keyno >= DIM(parm->key_attr)) return 0;

    parm->key_attr[keyno].algo = algo;
    if (algo == PUBKEY_ALGO_RSA)
      parm->key_attr[keyno].nbits = strtoul(line + n + 3, NULL, 10);
    else if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA ||
             algo == PUBKEY_ALGO_EDDSA)
      parm->key_attr[keyno].curve =
          openpgp_is_curve_supported(line + n, NULL, NULL);
  } else if (keywordlen == 12 && !memcmp(keyword, "PRIVATE-DO-", 11) &&
             strchr("1234", keyword[11])) {
    int no = keyword[11] - '1';
    log_assert(no >= 0 && no <= 3);
    xfree(parm->private_do[no]);
    parm->private_do[no] =
        unescape_status_string((const unsigned char *)(line));
  }

  return 0;
}

/* Call the scdaemon to learn about a smartcard */
int agent_scd_learn(struct agent_card_info_s *info, int force) {
  int rc;
  struct default_inq_parm_s parm;
  struct agent_card_info_s dummyinfo;

  if (!info) info = &dummyinfo;
  memset(info, 0, sizeof *info);
  memset(&parm, 0, sizeof parm);

  rc = start_agent(NULL, 1);
  if (rc) return rc;

  parm.ctx = agent_ctx;
  rc = assuan_transact(
      agent_ctx, force ? "LEARN --sendinfo --force" : "LEARN --sendinfo",
      dummy_data_cb, NULL, default_inq_cb, &parm, learn_status_cb, info);
  /* Also try to get the key attributes.  */
  if (!rc) agent_scd_getattr("KEY-ATTR", info);

  if (info == &dummyinfo) agent_release_card_info(info);

  return rc;
}

/* Send an APDU to the current card.  On success the status word is
   stored at R_SW.  With HEXAPDU being NULL only a RESET command is
   send to scd.  With HEXAPDU being the string "undefined" the command
   "SERIALNO undefined" is send to scd. */
gpg_error_t agent_scd_apdu(const char *hexapdu, unsigned int *r_sw) {
  gpg_error_t err;

  /* Start the agent but not with the card flag so that we do not
     autoselect the openpgp application.  */
  err = start_agent(NULL, 0);
  if (err) return err;

  if (!hexapdu) {
    err = assuan_transact(agent_ctx, "SCD RESET", NULL, NULL, NULL, NULL, NULL,
                          NULL);

  } else if (!strcmp(hexapdu, "undefined")) {
    err = assuan_transact(agent_ctx, "SCD SERIALNO undefined", NULL, NULL, NULL,
                          NULL, NULL, NULL);
  } else {
    char line[ASSUAN_LINELENGTH];
    membuf_t mb;
    unsigned char *data;
    size_t datalen;

    init_membuf(&mb, 256);

    snprintf(line, DIM(line), "SCD APDU %s", hexapdu);
    err = assuan_transact(agent_ctx, line, put_membuf_cb, &mb, NULL, NULL, NULL,
                          NULL);
    if (!err) {
      data = (unsigned char *)get_membuf(&mb, &datalen);
      if (!data)
        err = gpg_error_from_syserror();
      else if (datalen < 2) /* Ooops */
        err = GPG_ERR_CARD;
      else {
        *r_sw = buf16_to_uint(data + datalen - 2);
      }
      xfree(data);
    }
  }

  return err;
}

int agent_keytocard(const char *hexgrip, int keyno, int force,
                    const char *serialno, const char *timestamp) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s parm;

  memset(&parm, 0, sizeof parm);

  snprintf(line, DIM(line), "KEYTOCARD %s%s %s OPENPGP.%d %s",
           force ? "--force " : "", hexgrip, serialno, keyno, timestamp);

  rc = start_agent(NULL, 1);
  if (rc) return rc;
  parm.ctx = agent_ctx;

  rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &parm, NULL,
                       NULL);
  if (rc) return rc;

  return rc;
}

/* Call the agent to retrieve a data object.  This function returns
   the data in the same structure as used by the learn command.  It is
   allowed to update such a structure using this command. */
int agent_scd_getattr(const char *name, struct agent_card_info_s *info) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s parm;

  memset(&parm, 0, sizeof parm);

  if (!*name) return GPG_ERR_INV_VALUE;

  /* We assume that NAME does not need escaping. */
  if (12 + strlen(name) > DIM(line) - 1) return GPG_ERR_TOO_LARGE;
  stpcpy(stpcpy(line, "SCD GETATTR "), name);

  rc = start_agent(NULL, 1);
  if (rc) return rc;

  parm.ctx = agent_ctx;
  rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &parm,
                       learn_status_cb, info);

  return rc;
}

/* Send an setattr command to the SCdaemon.  SERIALNO is not actually
   used here but required by gpg 1.4's implementation of this code in
   cardglue.c. */
int agent_scd_setattr(const char *name, const unsigned char *value,
                      size_t valuelen, const char *serialno) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  char *p;
  struct default_inq_parm_s parm;

  memset(&parm, 0, sizeof parm);

  (void)serialno;

  if (!*name || !valuelen) return GPG_ERR_INV_VALUE;

  /* We assume that NAME does not need escaping. */
  if (12 + strlen(name) > DIM(line) - 1) return GPG_ERR_TOO_LARGE;

  p = stpcpy(stpcpy(line, "SCD SETATTR "), name);
  *p++ = ' ';
  for (; valuelen; value++, valuelen--) {
    if (p >= line + DIM(line) - 5) return GPG_ERR_TOO_LARGE;
    if (*value < ' ' || *value == '+' || *value == '%') {
      sprintf(p, "%%%02X", *value);
      p += 3;
    } else if (*value == ' ')
      *p++ = '+';
    else
      *p++ = *value;
  }
  *p = 0;

  rc = start_agent(NULL, 1);
  if (!rc) {
    parm.ctx = agent_ctx;
    rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &parm,
                         NULL, NULL);
  }

  status_sc_op_failure(rc);
  return rc;
}

/* Handle a CERTDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the END
   command. */
static gpg_error_t inq_writecert_parms(void *opaque, const char *line) {
  int rc;
  struct writecert_parm_s *parm = (writecert_parm_s *)opaque;

  if (has_leading_keyword(line, "CERTDATA")) {
    rc = assuan_send_data(parm->dflt->ctx, parm->certdata, parm->certdatalen);
  } else
    rc = default_inq_cb(parm->dflt, line);

  return rc;
}

/* Send a WRITECERT command to the SCdaemon. */
int agent_scd_writecert(const char *certidstr, const unsigned char *certdata,
                        size_t certdatalen) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct writecert_parm_s parms;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  rc = start_agent(NULL, 1);
  if (rc) return rc;

  memset(&parms, 0, sizeof parms);

  snprintf(line, DIM(line), "SCD WRITECERT %s", certidstr);
  dfltparm.ctx = agent_ctx;
  parms.dflt = &dfltparm;
  parms.certdata = certdata;
  parms.certdatalen = certdatalen;

  rc = assuan_transact(agent_ctx, line, NULL, NULL, inq_writecert_parms, &parms,
                       NULL, NULL);

  return rc;
}

/* Handle a KEYDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t inq_writekey_parms(void *opaque, const char *line) {
  int rc;
  struct writekey_parm_s *parm = (writekey_parm_s *)opaque;

  if (has_leading_keyword(line, "KEYDATA")) {
    rc = assuan_send_data(parm->dflt->ctx, parm->keydata, parm->keydatalen);
  } else
    rc = default_inq_cb(parm->dflt, line);

  return rc;
}

/* Send a WRITEKEY command to the SCdaemon. */
int agent_scd_writekey(int keyno, const char *serialno,
                       const unsigned char *keydata, size_t keydatalen) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct writekey_parm_s parms;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  (void)serialno;

  rc = start_agent(NULL, 1);
  if (rc) return rc;

  memset(&parms, 0, sizeof parms);

  snprintf(line, DIM(line), "SCD WRITEKEY --force OPENPGP.%d", keyno);
  dfltparm.ctx = agent_ctx;
  parms.dflt = &dfltparm;
  parms.keydata = keydata;
  parms.keydatalen = keydatalen;

  rc = assuan_transact(agent_ctx, line, NULL, NULL, inq_writekey_parms, &parms,
                       NULL, NULL);

  status_sc_op_failure(rc);
  return rc;
}

/* Status callback for the SCD GENKEY command. */
static gpg_error_t scd_genkey_cb(void *opaque, const char *line) {
  u32 *createtime = (u32 *)opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen = 0; *line && !spacep(line); line++, keywordlen++)
    ;
  while (spacep(line)) line++;

  if (keywordlen == 14 && !memcmp(keyword, "KEY-CREATED-AT", keywordlen)) {
    *createtime = (u32)strtoul(line, NULL, 10);
  } else if (keywordlen == 8 && !memcmp(keyword, "PROGRESS", keywordlen)) {
    write_status_text(STATUS_PROGRESS, line);
  }

  return 0;
}

/* Send a GENKEY command to the SCdaemon.  If *CREATETIME is not 0,
  the value will be passed to SCDAEMON with --timestamp option so that
  the key is created with this.  Otherwise, timestamp was generated by
  SCDEAMON.  On success, creation time is stored back to
  CREATETIME.  */
int agent_scd_genkey(int keyno, int force, u32 *createtime) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  gnupg_isotime_t tbuf;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  rc = start_agent(NULL, 1);
  if (rc) return rc;

  if (*createtime)
    epoch2isotime(tbuf, *createtime);
  else
    *tbuf = 0;

  snprintf(line, DIM(line), "SCD GENKEY %s%s %s %d",
           *tbuf ? "--timestamp=" : "", tbuf, force ? "--force" : "", keyno);

  dfltparm.ctx = agent_ctx;
  rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                       scd_genkey_cb, createtime);

  status_sc_op_failure(rc);
  return rc;
}

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
int agent_scd_serialno(char **r_serialno, const char *demand) {
  int err;
  char *serialno = NULL;
  char line[ASSUAN_LINELENGTH];

  err = start_agent(NULL, 1 | FLAG_FOR_CARD_SUPPRESS_ERRORS);
  if (err) return err;

  if (!demand)
    strcpy(line, "SCD SERIALNO");
  else
    snprintf(line, DIM(line), "SCD SERIALNO --demand=%s", demand);

  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  if (err) {
    xfree(serialno);
    return err;
  }

  *r_serialno = serialno;
  return 0;
}

/* Send a READCERT command to the SCdaemon. */
int agent_scd_readcert(const char *certidstr, void **r_buf, size_t *r_buflen) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  *r_buf = NULL;
  rc = start_agent(NULL, 1);
  if (rc) return rc;

  dfltparm.ctx = agent_ctx;

  init_membuf(&data, 2048);

  snprintf(line, DIM(line), "SCD READCERT %s", certidstr);
  rc = assuan_transact(agent_ctx, line, put_membuf_cb, &data, default_inq_cb,
                       &dfltparm, NULL, NULL);
  if (rc) {
    xfree(get_membuf(&data, &len));
    return rc;
  }
  *r_buf = get_membuf(&data, r_buflen);
  if (!*r_buf) return GPG_ERR_ENOMEM;

  return 0;
}

struct card_cardlist_parm_s {
  int error{0};
  std::vector<std::string> list;
};

/* Callback function for agent_card_cardlist.  */
static gpg_error_t card_cardlist_cb(void *opaque, const char *line) {
  struct card_cardlist_parm_s *parm = (card_cardlist_parm_s *)opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen = 0; *line && !spacep(line); line++, keywordlen++)
    ;
  while (spacep(line)) line++;

  if (keywordlen == 8 && !memcmp(keyword, "SERIALNO", keywordlen)) {
    const char *s;
    int n;

    for (n = 0, s = line; hexdigitp(s); s++, n++)
      ;

    if (!n || (n & 1) || *s)
      parm->error = GPG_ERR_ASS_PARAMETER;
    else
      parm->list.emplace_back(line);
  }

  return 0;
}

/* Return cardlist.  */
int agent_scd_cardlist(std::vector<std::string> &result) {
  int err;
  char line[ASSUAN_LINELENGTH];
  struct card_cardlist_parm_s parm;

  result.clear();
  err = start_agent(NULL, 1);
  if (err) return err;

  strcpy(line, "SCD GETINFO card_list");

  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL,
                        card_cardlist_cb, &parm);
  if (!err && parm.error) err = parm.error;

  if (!err) result = parm.list;

  return 0;
}

/* Change the PIN of an OpenPGP card or reset the retry counter.
   CHVNO 1: Change the PIN
         2: For v1 cards: Same as 1.
            For v2 cards: Reset the PIN using the Reset Code.
         3: Change the admin PIN
       101: Set a new PIN and reset the retry counter
       102: For v1 cars: Same as 101.
            For v2 cards: Set a new Reset Code.
   SERIALNO is not used.
 */
int agent_scd_change_pin(int chvno, const char *serialno) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  const char *reset = "";
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  (void)serialno;

  if (chvno >= 100) reset = "--reset";
  chvno %= 100;

  rc = start_agent(NULL, 1);
  if (rc) return rc;
  dfltparm.ctx = agent_ctx;

  snprintf(line, DIM(line), "SCD PASSWD %s %d", reset, chvno);
  rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                       NULL, NULL);
  status_sc_op_failure(rc);
  return rc;
}

/* Perform a CHECKPIN operation.  SERIALNO should be the serial
   number of the card - optionally followed by the fingerprint;
   however the fingerprint is ignored here. */
int agent_scd_checkpin(const char *serialno) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  rc = start_agent(NULL, 1);
  if (rc) return rc;
  dfltparm.ctx = agent_ctx;

  snprintf(line, DIM(line), "SCD CHECKPIN %s", serialno);
  rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                       NULL, NULL);
  status_sc_op_failure(rc);
  return rc;
}

/* Dummy function, only used by the gpg 1.4 implementation. */
void agent_clear_pin_cache(const char *sn) { (void)sn; }

/* Note: All strings shall be UTF-8. On success the caller needs to
   free the string stored at R_PASSPHRASE. On error NULL will be
   stored at R_PASSPHRASE and an appropriate fpf error code
   returned. */
gpg_error_t agent_get_passphrase(const char *cache_id, const char *err_msg,
                                 const char *prompt, const char *desc_msg,
                                 int repeat, int check, char **r_passphrase) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  char *arg1 = NULL;
  char *arg2 = NULL;
  char *arg3 = NULL;
  char *arg4 = NULL;
  membuf_t data;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  *r_passphrase = NULL;

  rc = start_agent(NULL, 0);
  if (rc) return rc;
  dfltparm.ctx = agent_ctx;

  /* Check that the gpg-agent understands the repeat option.  */
  if (assuan_transact(agent_ctx, "GETINFO cmd_has_option GET_PASSPHRASE repeat",
                      NULL, NULL, NULL, NULL, NULL, NULL))
    return GPG_ERR_NOT_SUPPORTED;

  if (cache_id && *cache_id)
    if (!(arg1 = percent_plus_escape(cache_id))) goto no_mem;
  if (err_msg && *err_msg)
    if (!(arg2 = percent_plus_escape(err_msg))) goto no_mem;
  if (prompt && *prompt)
    if (!(arg3 = percent_plus_escape(prompt))) goto no_mem;
  if (desc_msg && *desc_msg)
    if (!(arg4 = percent_plus_escape(desc_msg))) goto no_mem;

  snprintf(line, DIM(line),
           "GET_PASSPHRASE --data --repeat=%d%s -- %s %s %s %s", repeat,
           check ? " --check --qualitybar" : "", arg1 ? arg1 : "X",
           arg2 ? arg2 : "X", arg3 ? arg3 : "X", arg4 ? arg4 : "X");
  xfree(arg1);
  xfree(arg2);
  xfree(arg3);
  xfree(arg4);

  init_membuf_secure(&data, 64);
  rc = assuan_transact(agent_ctx, line, put_membuf_cb, &data, default_inq_cb,
                       &dfltparm, NULL, NULL);

  if (rc)
    xfree(get_membuf(&data, NULL));
  else {
    put_membuf(&data, "", 1);
    *r_passphrase = (char *)get_membuf(&data, NULL);
    if (!*r_passphrase) rc = gpg_error_from_syserror();
  }
  return rc;
no_mem:
  rc = gpg_error_from_syserror();
  xfree(arg1);
  xfree(arg2);
  xfree(arg3);
  xfree(arg4);
  return rc;
}

gpg_error_t agent_clear_passphrase(const char *cache_id) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  if (!cache_id || !*cache_id) return 0;

  rc = start_agent(NULL, 0);
  if (rc) return rc;
  dfltparm.ctx = agent_ctx;

  snprintf(line, DIM(line), "CLEAR_PASSPHRASE %s", cache_id);
  return assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                         NULL, NULL);
}

/* Ask the agent to pop up a confirmation dialog with the text DESC
   and an okay and cancel button. */
gpg_error_t gpg_agent_get_confirmation(const char *desc) {
  int rc;
  char *tmp;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);

  rc = start_agent(NULL, 0);
  if (rc) return rc;
  dfltparm.ctx = agent_ctx;

  tmp = percent_plus_escape(desc);
  if (!tmp) return gpg_error_from_syserror();
  snprintf(line, DIM(line), "GET_CONFIRMATION %s", tmp);
  xfree(tmp);

  rc = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                       NULL, NULL);
  return rc;
}

/* Return the S2K iteration count as computed by gpg-agent.  */
gpg_error_t agent_get_s2k_count(unsigned long *r_count) {
  gpg_error_t err;
  membuf_t data;
  char *buf;

  *r_count = 0;

  err = start_agent(NULL, 0);
  if (err) return err;

  init_membuf(&data, 32);
  err = assuan_transact(agent_ctx, "GETINFO s2k_count", put_membuf_cb, &data,
                        NULL, NULL, NULL, NULL);
  if (err)
    xfree(get_membuf(&data, NULL));
  else {
    put_membuf(&data, "", 1);
    buf = (char *)get_membuf(&data, NULL);
    if (!buf)
      err = gpg_error_from_syserror();
    else {
      *r_count = strtoul(buf, NULL, 10);
      xfree(buf);
    }
  }
  return err;
}

/* Ask the agent whether a secret key for the given public key is
   available.  Returns 0 if available.  */
gpg_error_t agent_probe_secret_key(ctrl_t ctrl, PKT_public_key *pk) {
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  char *hexgrip;

  err = start_agent(ctrl, 0);
  if (err) return err;

  err = hexkeygrip_from_pk(pk, &hexgrip);
  if (err) return err;

  snprintf(line, sizeof line, "HAVEKEY %s", hexgrip);
  xfree(hexgrip);

  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  return err;
}

/* Ask the agent whether a secret key is available for any of the
   keys (primary or sub) in KEYBLOCK.  Returns 0 if available.  */
gpg_error_t agent_probe_any_secret_key(ctrl_t ctrl, kbnode_t keyblock) {
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  char *p;
  kbnode_t kbctx, node;
  int nkeys;
  unsigned char grip[20];

  err = start_agent(ctrl, 0);
  if (err) return err;

  err = GPG_ERR_NO_SECKEY; /* Just in case no key was
                                          found in KEYBLOCK.  */
  p = stpcpy(line, "HAVEKEY");
  for (kbctx = NULL, nkeys = 0; (node = walk_kbnode(keyblock, &kbctx, 0));)
    if (node->pkt->pkttype == PKT_PUBLIC_KEY ||
        node->pkt->pkttype == PKT_PUBLIC_SUBKEY ||
        node->pkt->pkttype == PKT_SECRET_KEY ||
        node->pkt->pkttype == PKT_SECRET_SUBKEY) {
      if (nkeys && ((p - line) + 41) > (ASSUAN_LINELENGTH - 2)) {
        err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL,
                              NULL);
        if (err != GPG_ERR_NO_SECKEY)
          break; /* Seckey available or unexpected error - ready.  */
        p = stpcpy(line, "HAVEKEY");
        nkeys = 0;
      }

      err = keygrip_from_pk(node->pkt->pkt.public_key, grip);
      if (err) return err;
      *p++ = ' ';
      bin2hex(grip, 20, p);
      p += 40;
      nkeys++;
    }

  if (!err && nkeys)
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);

  return err;
}

struct keyinfo_data_parm_s {
  char *serialno;
  int cleartext;
};

static gpg_error_t keyinfo_status_cb(void *opaque, const char *line) {
  struct keyinfo_data_parm_s *data = (keyinfo_data_parm_s *)opaque;
  int is_smartcard;
  char *s;

  if ((s = has_leading_keyword(line, "KEYINFO")) && data) {
    /* Parse the arguments:
     *      0        1        2        3       4          5
     *   <keygrip> <type> <serialno> <idstr> <cached> <protection>
     */
    std::vector<std::string> fields;
    boost::split(fields, s, boost::is_any_of(" "));
    if (fields.size() == 6) {
      is_smartcard = (fields[1][0] == 'T');
      if (is_smartcard && !data->serialno && fields[2] != "-")
        data->serialno = xtrystrdup(fields[2].c_str());
      /* 'P' for protected, 'C' for clear */
      data->cleartext = (fields[5][0] == 'C');
    }
  }
  return 0;
}

/* Return the serial number for a secret key.  If the returned serial
   number is NULL, the key is not stored on a smartcard.  Caller needs
   to free R_SERIALNO.

   if r_cleartext is not NULL, the referenced int will be set to 1 if
   the agent's copy of the key is stored in the clear, or 0 otherwise
*/
gpg_error_t agent_get_keyinfo(ctrl_t ctrl, const char *hexkeygrip,
                              char **r_serialno, int *r_cleartext) {
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct keyinfo_data_parm_s keyinfo;

  memset(&keyinfo, 0, sizeof keyinfo);

  *r_serialno = NULL;

  err = start_agent(ctrl, 0);
  if (err) return err;

  if (!hexkeygrip || strlen(hexkeygrip) != 40) return GPG_ERR_INV_VALUE;

  snprintf(line, DIM(line), "KEYINFO %s", hexkeygrip);

  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL,
                        keyinfo_status_cb, &keyinfo);
  if (!err && keyinfo.serialno) {
    /* Sanity check for bad characters.  */
    if (strpbrk(keyinfo.serialno, ":\n\r")) err = GPG_ERR_INV_VALUE;
  }
  if (err)
    xfree(keyinfo.serialno);
  else {
    *r_serialno = keyinfo.serialno;
    if (r_cleartext) *r_cleartext = keyinfo.cleartext;
  }
  return err;
}

/* Status callback for agent_import_key, agent_export_key and
   agent_genkey.  */
static gpg_error_t cache_nonce_status_cb(void *opaque, const char *line) {
  struct cache_nonce_parm_s *parm = (cache_nonce_parm_s *)opaque;
  const char *s;

  if ((s = has_leading_keyword(line, "CACHE_NONCE"))) {
    if (parm->cache_nonce_addr) {
      xfree(*parm->cache_nonce_addr);
      *parm->cache_nonce_addr = xtrystrdup(s);
    }
  } else if ((s = has_leading_keyword(line, "PASSWD_NONCE"))) {
    if (parm->passwd_nonce_addr) {
      xfree(*parm->passwd_nonce_addr);
      *parm->passwd_nonce_addr = xtrystrdup(s);
    }
  } else if ((s = has_leading_keyword(line, "PROGRESS"))) {
    if (opt.enable_progress_filter) write_status_text(STATUS_PROGRESS, s);
  }

  return 0;
}

/* Handle a KEYPARMS inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t inq_genkey_parms(void *opaque, const char *line) {
  struct genkey_parm_s *parm = (genkey_parm_s *)opaque;
  gpg_error_t err;

  if (has_leading_keyword(line, "KEYPARAM")) {
    err = assuan_send_data(parm->dflt->ctx, parm->keyparms,
                           strlen(parm->keyparms));
  } else if (has_leading_keyword(line, "NEWPASSWD") && parm->passphrase) {
    err = assuan_send_data(parm->dflt->ctx, parm->passphrase,
                           strlen(parm->passphrase));
  } else
    err = default_inq_cb(parm->dflt, line);

  return err;
}

/* Call the agent to generate a new key.  KEYPARMS is the usual
   S-expression giving the parameters of the key.  gpg-agent passes it
   gcry_pk_genkey.  If NO_PROTECTION is true the agent is advised not
   to protect the generated key.  If NO_PROTECTION is not set and
   PASSPHRASE is not NULL the agent is requested to protect the key
   with that passphrase instead of asking for one.  */
gpg_error_t agent_genkey(ctrl_t ctrl, char **cache_nonce_addr,
                         char **passwd_nonce_addr, const char *keyparms,
                         int no_protection, const char *passphrase,
                         gcry_sexp_t *r_pubkey) {
  gpg_error_t err;
  struct genkey_parm_s gk_parm;
  struct cache_nonce_parm_s cn_parm;
  struct default_inq_parm_s dfltparm;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  char line[ASSUAN_LINELENGTH];

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;

  *r_pubkey = NULL;
  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  if (passwd_nonce_addr && *passwd_nonce_addr)
    ; /* A RESET would flush the passwd nonce cache.  */
  else {
    err =
        assuan_transact(agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  init_membuf(&data, 1024);
  gk_parm.dflt = &dfltparm;
  gk_parm.keyparms = keyparms;
  gk_parm.passphrase = passphrase;
  snprintf(line, sizeof line, "GENKEY%s%s%s%s%s",
           no_protection ? " --no-protection"
                         : passphrase ? " --inq-passwd" :
                                      /*          */ "",
           passwd_nonce_addr && *passwd_nonce_addr ? " --passwd-nonce=" : "",
           passwd_nonce_addr && *passwd_nonce_addr ? *passwd_nonce_addr : "",
           cache_nonce_addr && *cache_nonce_addr ? " " : "",
           cache_nonce_addr && *cache_nonce_addr ? *cache_nonce_addr : "");
  cn_parm.cache_nonce_addr = cache_nonce_addr;
  cn_parm.passwd_nonce_addr = NULL;
  err = assuan_transact(agent_ctx, line, put_membuf_cb, &data, inq_genkey_parms,
                        &gk_parm, cache_nonce_status_cb, &cn_parm);
  if (err) {
    xfree(get_membuf(&data, &len));
    return err;
  }

  buf = (unsigned char *)get_membuf(&data, &len);
  if (!buf)
    err = gpg_error_from_syserror();
  else {
    err = gcry_sexp_sscan(r_pubkey, NULL, (const char *)(buf), len);
    xfree(buf);
  }
  return err;
}

/* Call the agent to read the public key part for a given keygrip.  If
   FROMCARD is true, the key is directly read from the current
   smartcard. In this case HEXKEYGRIP should be the keyID
   (e.g. OPENPGP.3). */
gpg_error_t agent_readkey(ctrl_t ctrl, int fromcard, const char *hexkeygrip,
                          unsigned char **r_pubkey) {
  gpg_error_t err;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;

  *r_pubkey = NULL;
  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  err = assuan_transact(agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (err) return err;

  snprintf(line, DIM(line), "READKEY %s%s", fromcard ? "--card " : "",
           hexkeygrip);

  init_membuf(&data, 1024);
  err = assuan_transact(agent_ctx, line, put_membuf_cb, &data, default_inq_cb,
                        &dfltparm, NULL, NULL);
  if (err) {
    xfree(get_membuf(&data, &len));
    return err;
  }
  buf = (unsigned char *)get_membuf(&data, &len);
  if (!buf) return gpg_error_from_syserror();
  if (!gcry_sexp_canon_len(buf, len, NULL, NULL)) {
    xfree(buf);
    return GPG_ERR_INV_SEXP;
  }
  *r_pubkey = buf;
  return 0;
}

/* Call the agent to do a sign operation using the key identified by
   the hex string KEYGRIP.  DESC is a description of the key to be
   displayed if the agent needs to ask for the PIN.  DIGEST and
   DIGESTLEN is the hash value to sign and DIGESTALGO the algorithm id
   used to compute the digest.  If CACHE_NONCE is used the agent is
   advised to first try a passphrase associated with that nonce. */
gpg_error_t agent_pksign(ctrl_t ctrl, const char *cache_nonce,
                         const char *keygrip, const char *desc, u32 *keyid,
                         u32 *mainkeyid, int pubkey_algo, unsigned char *digest,
                         size_t digestlen, int digestalgo,
                         gcry_sexp_t *r_sigval) {
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;
  dfltparm.keyinfo.keyid = keyid;
  dfltparm.keyinfo.mainkeyid = mainkeyid;
  dfltparm.keyinfo.pubkey_algo = pubkey_algo;

  *r_sigval = NULL;
  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  if (digestlen * 2 + 50 > DIM(line)) return GPG_ERR_GENERAL;

  err = assuan_transact(agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (err) return err;

  snprintf(line, DIM(line), "SIGKEY %s", keygrip);
  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err) return err;

  if (desc) {
    snprintf(line, DIM(line), "SETKEYDESC %s", desc);
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  snprintf(line, sizeof line, "SETHASH %d ", digestalgo);
  bin2hex(digest, digestlen, line + strlen(line));
  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err) return err;

  init_membuf(&data, 1024);

  snprintf(line, sizeof line, "PKSIGN%s%s", cache_nonce ? " -- " : "",
           cache_nonce ? cache_nonce : "");
  err = assuan_transact(agent_ctx, line, put_membuf_cb, &data, default_inq_cb,
                        &dfltparm, NULL, NULL);
  if (err)
    xfree(get_membuf(&data, NULL));
  else {
    unsigned char *buf;
    size_t len;

    buf = (unsigned char *)get_membuf(&data, &len);
    if (!buf)
      err = gpg_error_from_syserror();
    else {
      err = gcry_sexp_sscan(r_sigval, NULL, (const char *)(buf), len);
      xfree(buf);
    }
  }
  return err;
}

/* Handle a CIPHERTEXT inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the END. */
static gpg_error_t inq_ciphertext_cb(void *opaque, const char *line) {
  struct cipher_parm_s *parm = (cipher_parm_s *)opaque;
  int rc;

  if (has_leading_keyword(line, "CIPHERTEXT")) {
    assuan_begin_confidential(parm->ctx);
    rc = assuan_send_data(parm->dflt->ctx, parm->ciphertext,
                          parm->ciphertextlen);
    assuan_end_confidential(parm->ctx);
  } else
    rc = default_inq_cb(parm->dflt, line);

  return rc;
}

/* Check whether there is any padding info from the agent.  */
static gpg_error_t padding_info_cb(void *opaque, const char *line) {
  int *r_padding = (int *)opaque;
  const char *s;

  if ((s = has_leading_keyword(line, "PADDING"))) {
    *r_padding = atoi(s);
  }

  return 0;
}

/* Call the agent to do a decrypt operation using the key identified
   by the hex string KEYGRIP and the input data S_CIPHERTEXT.  On the
   success the decoded value is stored verbatim at R_BUF and its
   length at R_BUF; the callers needs to release it.  KEYID, MAINKEYID
   and PUBKEY_ALGO are used to construct additional promots or status
   messages.   The padding information is stored at R_PADDING with -1
   for not known.  */
gpg_error_t agent_pkdecrypt(ctrl_t ctrl, const char *keygrip, const char *desc,
                            u32 *keyid, u32 *mainkeyid, int pubkey_algo,
                            gcry_sexp_t s_ciphertext, unsigned char **r_buf,
                            size_t *r_buflen, int *r_padding) {
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t n, len;
  char *p, *buf, *endp;
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;
  dfltparm.keyinfo.keyid = keyid;
  dfltparm.keyinfo.mainkeyid = mainkeyid;
  dfltparm.keyinfo.pubkey_algo = pubkey_algo;

  if (!keygrip || strlen(keygrip) != 40 || !s_ciphertext || !r_buf ||
      !r_buflen || !r_padding)
    return GPG_ERR_INV_VALUE;

  *r_buf = NULL;
  *r_padding = -1;

  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  err = assuan_transact(agent_ctx, "RESET", NULL, NULL, NULL, NULL, NULL, NULL);
  if (err) return err;

  snprintf(line, sizeof line, "SETKEY %s", keygrip);
  err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err) return err;

  if (desc) {
    snprintf(line, DIM(line), "SETKEYDESC %s", desc);
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  init_membuf_secure(&data, 1024);
  {
    struct cipher_parm_s parm;

    parm.dflt = &dfltparm;
    parm.ctx = agent_ctx;
    err = make_canon_sexp(s_ciphertext, &parm.ciphertext, &parm.ciphertextlen);
    if (err) return err;
    err = assuan_transact(agent_ctx, "PKDECRYPT", put_membuf_cb, &data,
                          inq_ciphertext_cb, &parm, padding_info_cb, r_padding);
    xfree(parm.ciphertext);
  }
  if (err) {
    xfree(get_membuf(&data, &len));
    return err;
  }

  put_membuf(&data, "", 1); /* Make sure it is 0 terminated.  */
  buf = (char *)get_membuf(&data, &len);
  if (!buf) return gpg_error_from_syserror();
  log_assert(len); /* (we forced Nul termination.)  */

  if (*buf != '(') {
    xfree(buf);
    return GPG_ERR_INV_SEXP;
  }

  if (len < 13 || memcmp(buf, "(5:value", 8)) /* "(5:valueN:D)\0" */
  {
    xfree(buf);
    return GPG_ERR_INV_SEXP;
  }
  len -= 10;   /* Count only the data of the second part. */
  p = buf + 8; /* Skip leading parenthesis and the value tag. */

  n = strtoul(p, &endp, 10);
  if (!n || *endp != ':') {
    xfree(buf);
    return GPG_ERR_INV_SEXP;
  }
  endp++;
  if (endp - p + n > len) {
    xfree(buf);
    return GPG_ERR_INV_SEXP; /* Oops: Inconsistent S-Exp. */
  }

  memmove(buf, endp, n);

  *r_buflen = n;
  *r_buf = (unsigned char *)buf;
  return 0;
}

/* Handle the inquiry for an IMPORT_KEY command.  */
static gpg_error_t inq_import_key_parms(void *opaque, const char *line) {
  struct import_key_parm_s *parm = (import_key_parm_s *)opaque;
  gpg_error_t err;

  if (has_leading_keyword(line, "KEYDATA")) {
    err = assuan_send_data(parm->dflt->ctx, parm->key, parm->keylen);
  } else
    err = default_inq_cb(parm->dflt, line);

  return err;
}

/* Call the agent to import a key into the agent.  */
gpg_error_t agent_import_key(ctrl_t ctrl, const char *desc,
                             char **cache_nonce_addr, const void *key,
                             size_t keylen, int unattended, int force) {
  gpg_error_t err;
  struct import_key_parm_s parm;
  struct cache_nonce_parm_s cn_parm;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;

  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  if (desc) {
    snprintf(line, DIM(line), "SETKEYDESC %s", desc);
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  parm.dflt = &dfltparm;
  parm.key = key;
  parm.keylen = keylen;

  snprintf(line, sizeof line, "IMPORT_KEY%s%s%s%s",
           unattended ? " --unattended" : "", force ? " --force" : "",
           cache_nonce_addr && *cache_nonce_addr ? " " : "",
           cache_nonce_addr && *cache_nonce_addr ? *cache_nonce_addr : "");
  cn_parm.cache_nonce_addr = cache_nonce_addr;
  cn_parm.passwd_nonce_addr = NULL;
  err = assuan_transact(agent_ctx, line, NULL, NULL, inq_import_key_parms,
                        &parm, cache_nonce_status_cb, &cn_parm);
  return err;
}

/* Receive a secret key from the agent.  HEXKEYGRIP is the hexified
   keygrip, DESC a prompt to be displayed with the agent's passphrase
   question (needs to be plus+percent escaped).  if OPENPGP_PROTECTED
   is not zero, ensure that the key material is returned in RFC
   4880-compatible passphrased-protected form.  If CACHE_NONCE_ADDR is
   not NULL the agent is advised to first try a passphrase associated
   with that nonce.  On success the key is stored as a canonical
   S-expression at R_RESULT and R_RESULTLEN.  */
gpg_error_t agent_export_key(ctrl_t ctrl, const char *hexkeygrip,
                             const char *desc, int openpgp_protected,
                             char **cache_nonce_addr, unsigned char **r_result,
                             size_t *r_resultlen) {
  gpg_error_t err;
  struct cache_nonce_parm_s cn_parm;
  membuf_t data;
  size_t len;
  unsigned char *buf;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;

  *r_result = NULL;

  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  if (desc) {
    snprintf(line, DIM(line), "SETKEYDESC %s", desc);
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  snprintf(line, DIM(line), "EXPORT_KEY %s%s%s %s",
           openpgp_protected ? "--openpgp " : "",
           cache_nonce_addr && *cache_nonce_addr ? "--cache-nonce=" : "",
           cache_nonce_addr && *cache_nonce_addr ? *cache_nonce_addr : "",
           hexkeygrip);

  init_membuf_secure(&data, 1024);
  cn_parm.cache_nonce_addr = cache_nonce_addr;
  cn_parm.passwd_nonce_addr = NULL;
  err = assuan_transact(agent_ctx, line, put_membuf_cb, &data, default_inq_cb,
                        &dfltparm, cache_nonce_status_cb, &cn_parm);
  if (err) {
    xfree(get_membuf(&data, &len));
    return err;
  }
  buf = (unsigned char *)get_membuf(&data, &len);
  if (!buf) return gpg_error_from_syserror();
  *r_result = buf;
  *r_resultlen = len;
  return 0;
}

/* Ask the agent to delete the key identified by HEXKEYGRIP.  If DESC
   is not NULL, display DESC instead of the default description
   message.  If FORCE is true the agent is advised not to ask for
   confirmation. */
gpg_error_t agent_delete_key(ctrl_t ctrl, const char *hexkeygrip,
                             const char *desc, int force) {
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;

  err = start_agent(ctrl, 0);
  if (err) return err;

  if (!hexkeygrip || strlen(hexkeygrip) != 40) return GPG_ERR_INV_VALUE;

  if (desc) {
    snprintf(line, DIM(line), "SETKEYDESC %s", desc);
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  snprintf(line, DIM(line), "DELETE_KEY%s %s", force ? " --force" : "",
           hexkeygrip);
  err = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                        NULL, NULL);
  return err;
}

/* Ask the agent to change the passphrase of the key identified by
 * HEXKEYGRIP.  If DESC is not NULL, display DESC instead of the
 * default description message.  If CACHE_NONCE_ADDR is not NULL the
 * agent is advised to first try a passphrase associated with that
 * nonce.  If PASSWD_NONCE_ADDR is not NULL the agent will try to use
 * the passphrase associated with that nonce for the new passphrase.
 * If VERIFY is true the passphrase is only verified.  */
gpg_error_t agent_passwd(ctrl_t ctrl, const char *hexkeygrip, const char *desc,
                         int verify, char **cache_nonce_addr,
                         char **passwd_nonce_addr) {
  gpg_error_t err;
  struct cache_nonce_parm_s cn_parm;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset(&dfltparm, 0, sizeof dfltparm);
  dfltparm.ctrl = ctrl;

  err = start_agent(ctrl, 0);
  if (err) return err;
  dfltparm.ctx = agent_ctx;

  if (!hexkeygrip || strlen(hexkeygrip) != 40) return GPG_ERR_INV_VALUE;

  if (desc) {
    snprintf(line, DIM(line), "SETKEYDESC %s", desc);
    err = assuan_transact(agent_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) return err;
  }

  if (verify)
    snprintf(line, DIM(line), "PASSWD %s%s --verify %s",
             cache_nonce_addr && *cache_nonce_addr ? "--cache-nonce=" : "",
             cache_nonce_addr && *cache_nonce_addr ? *cache_nonce_addr : "",
             hexkeygrip);
  else
    snprintf(line, DIM(line), "PASSWD %s%s %s%s %s",
             cache_nonce_addr && *cache_nonce_addr ? "--cache-nonce=" : "",
             cache_nonce_addr && *cache_nonce_addr ? *cache_nonce_addr : "",
             passwd_nonce_addr && *passwd_nonce_addr ? "--passwd-nonce=" : "",
             passwd_nonce_addr && *passwd_nonce_addr ? *passwd_nonce_addr : "",
             hexkeygrip);
  cn_parm.cache_nonce_addr = cache_nonce_addr;
  cn_parm.passwd_nonce_addr = passwd_nonce_addr;
  err = assuan_transact(agent_ctx, line, NULL, NULL, default_inq_cb, &dfltparm,
                        cache_nonce_status_cb, &cn_parm);
  return err;
}

/* Return the version reported by gpg-agent.  */
gpg_error_t agent_get_version(ctrl_t ctrl, char **r_version) {
  gpg_error_t err;

  err = start_agent(ctrl, 0);
  if (err) return err;

  err = get_assuan_server_version(agent_ctx, 0, r_version);
  return err;
}
