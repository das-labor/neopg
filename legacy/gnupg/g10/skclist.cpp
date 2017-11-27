/* skclist.c - Build a list of secret keys
 * Copyright (C) 1998, 1999, 2000, 2001, 2006,
 *               2010 Free Software Foundation, Inc.
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

#include "../common/status.h"
#include "../common/util.h"
#include "call-agent.h"
#include "gpg.h"
#include "keydb.h"
#include "options.h"
#include "packet.h"

void release_sk_list(SK_LIST sk_list) {
  SK_LIST sk_rover;

  for (; sk_list; sk_list = sk_rover) {
    sk_rover = sk_list->next;
    free_public_key(sk_list->pk);
    xfree(sk_list);
  }
}

/* Check that we are only using keys which don't have
 * the string "(insecure!)" or "not secure" or "do not use"
 * in one of the user ids.  */
static int is_insecure(ctrl_t ctrl, PKT_public_key *pk) {
  u32 keyid[2];
  KBNODE node = NULL, u;
  int insecure = 0;

  keyid_from_pk(pk, keyid);
  node = get_pubkeyblock(ctrl, keyid);
  for (u = node; u; u = u->next) {
    if (u->pkt->pkttype == PKT_USER_ID) {
      PKT_user_id *id = u->pkt->pkt.user_id;
      if (id->attrib_data) continue; /* skip attribute packets */
      if (strstr(id->name, "(insecure!)") || strstr(id->name, "not secure") ||
          strstr(id->name, "do not use") || strstr(id->name, "(INSECURE!)")) {
        insecure = 1;
        break;
      }
    }
  }
  release_kbnode(node);

  return insecure;
}

static int key_present_in_sk_list(SK_LIST sk_list, PKT_public_key *pk) {
  for (; sk_list; sk_list = sk_list->next) {
    if (!cmp_public_keys(sk_list->pk, pk)) return 0;
  }
  return -1;
}

gpg_error_t build_sk_list(
    ctrl_t ctrl,
    const std::vector<std::pair<std::string, unsigned int>> &locusr,
    SK_LIST *ret_sk_list, unsigned int use) {
  gpg_error_t err;
  SK_LIST sk_list = NULL;

  /* XXX: Change this function to use get_pubkeys instead of
     getkey_byname to detect ambiguous key specifications and warn
     about duplicate keyblocks.  For ambiguous key specifications on
     the command line or provided interactively, prompt the user to
     select the best key.  If a key specification is ambiguous and we
     are in batch mode, die.  */

  if (locusr.empty()) /* No user ids given - use the card key or the default
                         key.  */
  {
    struct agent_card_info_s info;
    PKT_public_key *pk;
    char *serialno;

    memset(&info, 0, sizeof(info));
    pk = (PKT_public_key *)xmalloc_clear(sizeof *pk);
    pk->req_usage = use;

    /* Check if a card is available.  If any, use the key as a hint.  */
    err = agent_scd_serialno(&serialno, NULL);
    if (!err) {
      xfree(serialno);
      err = agent_scd_getattr("KEY-FPR", &info);
      if (err)
        log_error("error retrieving key fingerprint from card: %s\n",
                  gpg_strerror(err));
    }

    err = get_seckey_default_or_card(
        ctrl, pk, (const byte *)(info.fpr1valid ? info.fpr1 : NULL), 20);
    if (err) {
      free_public_key(pk);
      pk = NULL;
      log_error("no default secret key: %s\n", gpg_strerror(err));
      write_status_text(STATUS_INV_SGNR, get_inv_recpsgnr_code(err));
    } else if ((err = openpgp_pk_test_algo2((pubkey_algo_t)(pk->pubkey_algo),
                                            use))) {
      free_public_key(pk);
      pk = NULL;
      log_error("invalid default secret key: %s\n", gpg_strerror(err));
      write_status_text(STATUS_INV_SGNR, get_inv_recpsgnr_code(err));
    } else {
      SK_LIST r;

      r = (SK_LIST)xmalloc(sizeof *r);
      r->pk = pk;
      pk = NULL;
      r->next = sk_list;
      r->mark = 0;
      sk_list = r;
    }
  } else /* Check the given user ids.  */
  {
    for (auto &locusr_ : locusr) {
      const char *usr = locusr_.first.c_str();
      PKT_public_key *pk;

      err = 0;
      /* Do an early check against duplicated entries.  However
       * this won't catch all duplicates because the user IDs may
       * be specified in different ways.  */
      if (std::find(locusr.begin(), locusr.end(), locusr_) != locusr.end()) {
        log_info(_("skipped \"%s\": duplicated\n"), locusr_.first.c_str());
        continue;
      }
      pk = (PKT_public_key *)xmalloc_clear(sizeof *pk);
      pk->req_usage = use;
      if ((err = getkey_byname(ctrl, NULL, pk, usr, 1, NULL))) {
        free_public_key(pk);
        pk = NULL;
        log_error(_("skipped \"%s\": %s\n"), usr, gpg_strerror(err));
        write_status_text_and_buffer(
            STATUS_INV_SGNR, get_inv_recpsgnr_code(err), usr, strlen(usr), -1);
      } else if (!key_present_in_sk_list(sk_list, pk)) {
        free_public_key(pk);
        pk = NULL;
        log_info(_("skipped: secret key already present\n"));
      } else if ((err = openpgp_pk_test_algo2((pubkey_algo_t)(pk->pubkey_algo),
                                              use))) {
        free_public_key(pk);
        pk = NULL;
        log_error("skipped \"%s\": %s\n", usr, gpg_strerror(err));
        write_status_text_and_buffer(
            STATUS_INV_SGNR, get_inv_recpsgnr_code(err), usr, strlen(usr), -1);
      } else {
        SK_LIST r;

        if (pk->version == 4 && (use & PUBKEY_USAGE_SIG) &&
            pk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E) {
          log_info(_("skipped \"%s\": %s\n"), usr,
                   _("this is a PGP generated Elgamal key which"
                     " is not secure for signatures!"));
          free_public_key(pk);
          pk = NULL;
          write_status_text_and_buffer(
              STATUS_INV_SGNR, get_inv_recpsgnr_code(GPG_ERR_WRONG_KEY_USAGE),
              usr, strlen(usr), -1);
        } else {
          r = (SK_LIST)xmalloc(sizeof *r);
          r->pk = pk;
          pk = NULL;
          r->next = sk_list;
          r->mark = 0;
          sk_list = r;
        }
      }
    }
  }

  if (!err && !sk_list) {
    log_error("no valid signators\n");
    write_status_text(STATUS_NO_SGNR, "0");
    err = GPG_ERR_NO_USER_ID;
  }

  if (err)
    release_sk_list(sk_list);
  else
    *ret_sk_list = sk_list;
  return err;
}
