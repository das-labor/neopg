/* Output of mkstrtable.awk.  DO NOT EDIT.  */

/* status.h - Status codes
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

/* The purpose of this complex string table is to produce
   optimal code with a minimum of relocations.  */

static const char statusstr_msgstr[] = 
  "ENTER" "\0"
  "LEAVE" "\0"
  "ABORT" "\0"
  "GOODSIG" "\0"
  "BADSIG" "\0"
  "ERRSIG" "\0"
  "BADARMOR" "\0"
  "TRUST_UNDEFINED" "\0"
  "TRUST_NEVER" "\0"
  "TRUST_MARGINAL" "\0"
  "TRUST_FULLY" "\0"
  "TRUST_ULTIMATE" "\0"
  "NEED_PASSPHRASE" "\0"
  "VALIDSIG" "\0"
  "SIG_ID" "\0"
  "ENC_TO" "\0"
  "NODATA" "\0"
  "BAD_PASSPHRASE" "\0"
  "NO_PUBKEY" "\0"
  "NO_SECKEY" "\0"
  "NEED_PASSPHRASE_SYM" "\0"
  "DECRYPTION_KEY" "\0"
  "DECRYPTION_INFO" "\0"
  "DECRYPTION_FAILED" "\0"
  "DECRYPTION_OKAY" "\0"
  "MISSING_PASSPHRASE" "\0"
  "GOOD_PASSPHRASE" "\0"
  "GOODMDC" "\0"
  "BADMDC" "\0"
  "ERRMDC" "\0"
  "IMPORTED" "\0"
  "IMPORT_OK" "\0"
  "IMPORT_PROBLEM" "\0"
  "IMPORT_RES" "\0"
  "IMPORT_CHECK" "\0"
  "EXPORTED" "\0"
  "EXPORT_RES" "\0"
  "FILE_START" "\0"
  "FILE_DONE" "\0"
  "FILE_ERROR" "\0"
  "BEGIN_DECRYPTION" "\0"
  "END_DECRYPTION" "\0"
  "BEGIN_ENCRYPTION" "\0"
  "END_ENCRYPTION" "\0"
  "BEGIN_SIGNING" "\0"
  "DELETE_PROBLEM" "\0"
  "GET_BOOL" "\0"
  "GET_LINE" "\0"
  "GET_HIDDEN" "\0"
  "GOT_IT" "\0"
  "PROGRESS" "\0"
  "SIG_CREATED" "\0"
  "SESSION_KEY" "\0"
  "NOTATION_NAME" "\0"
  "NOTATION_FLAGS" "\0"
  "NOTATION_DATA" "\0"
  "POLICY_URL" "\0"
  "KEY_CREATED" "\0"
  "USERID_HINT" "\0"
  "UNEXPECTED" "\0"
  "INV_RECP" "\0"
  "INV_SGNR" "\0"
  "NO_RECP" "\0"
  "NO_SGNR" "\0"
  "KEY_CONSIDERED" "\0"
  "ALREADY_SIGNED" "\0"
  "KEYEXPIRED" "\0"
  "KEYREVOKED" "\0"
  "EXPSIG" "\0"
  "EXPKEYSIG" "\0"
  "ATTRIBUTE" "\0"
  "REVKEYSIG" "\0"
  "NEWSIG" "\0"
  "SIG_SUBPACKET" "\0"
  "PLAINTEXT" "\0"
  "PLAINTEXT_LENGTH" "\0"
  "KEY_NOT_CREATED" "\0"
  "NEED_PASSPHRASE_PIN" "\0"
  "CARDCTRL" "\0"
  "SC_OP_FAILURE" "\0"
  "SC_OP_SUCCESS" "\0"
  "BACKUP_KEY_CREATED" "\0"
  "PKA_TRUST_BAD" "\0"
  "PKA_TRUST_GOOD" "\0"
  "TOFU_USER" "\0"
  "TOFU_STATS" "\0"
  "TOFU_STATS_SHORT" "\0"
  "TOFU_STATS_LONG" "\0"
  "TRUNCATED" "\0"
  "MOUNTPOINT" "\0"
  "BLOCKDEV" "\0"
  "PINENTRY_LAUNCHED" "\0"
  "PLAINTEXT_FOLLOWS" "\0"
  "ERROR" "\0"
  "WARNING" "\0"
  "SUCCESS" "\0"
  "FAILURE" "\0"
  "INQUIRE_MAXLEN";

static const int statusstr_msgidx[] =
  {
    0,
    6,
    12,
    18,
    26,
    33,
    40,
    49,
    65,
    77,
    92,
    104,
    119,
    135,
    144,
    151,
    158,
    165,
    180,
    190,
    200,
    220,
    235,
    251,
    269,
    285,
    304,
    320,
    328,
    335,
    342,
    351,
    361,
    376,
    387,
    400,
    409,
    420,
    431,
    441,
    452,
    469,
    484,
    501,
    516,
    530,
    545,
    554,
    563,
    574,
    581,
    590,
    602,
    614,
    628,
    643,
    657,
    668,
    680,
    692,
    703,
    712,
    721,
    729,
    737,
    752,
    767,
    778,
    789,
    796,
    806,
    816,
    826,
    833,
    847,
    857,
    874,
    890,
    910,
    919,
    933,
    947,
    966,
    980,
    995,
    1005,
    1016,
    1033,
    1049,
    1059,
    1070,
    1079,
    1097,
    1115,
    1121,
    1129,
    1137,
    1145,
    
  };

#define statusstr_msgidxof(code) (0 ? -1 \
  : ((code >= 0) && (code <= 97)) ? (code - 0) \
  : -1)
