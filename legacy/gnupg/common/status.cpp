/* status.c - status code helper functions
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

#include <config.h>
#include <stdlib.h>

#include "status.h"
#include "util.h"

/* Return the status string for code NO. */
const char *get_status_string(int no) {
  switch (no) {
    case STATUS_ENTER:
      return "ENTER";
    case STATUS_LEAVE:
      return "LEAVE";
    case STATUS_ABORT:
      return "ABORT";
    case STATUS_GOODSIG:
      return "GOODSIG";
    case STATUS_BADSIG:
      return "BADSIG";
    case STATUS_ERRSIG:
      return "ERRSIG";
    case STATUS_BADARMOR:
      return "BADARMOR";
    case STATUS_TRUST_UNDEFINED:
      return "TRUST_UNDEFINED";
    case STATUS_TRUST_NEVER:
      return "TRUST_NEVER";
    case STATUS_TRUST_MARGINAL:
      return "TRUST_MARGINAL";
    case STATUS_TRUST_FULLY:
      return "TRUST_FULLY";
    case STATUS_TRUST_ULTIMATE:
      return "TRUST_ULTIMATE";
    case STATUS_NEED_PASSPHRASE:
      return "NEED_PASSPHRASE";
    case STATUS_VALIDSIG:
      return "VALIDSIG";
    case STATUS_SIG_ID:
      return "SIG_ID";
    case STATUS_ENC_TO:
      return "ENC_TO";
    case STATUS_NODATA:
      return "NODATA";
    case STATUS_BAD_PASSPHRASE:
      return "BAD_PASSPHRASE";
    case STATUS_NO_PUBKEY:
      return "NO_PUBKEY";
    case STATUS_NO_SECKEY:
      return "NO_SECKEY";
    case STATUS_NEED_PASSPHRASE_SYM:
      return "NEED_PASSPHRASE_SYM";
    case STATUS_DECRYPTION_KEY:
      return "DECRYPTION_KEY";
    case STATUS_DECRYPTION_INFO:
      return "DECRYPTION_INFO";
    case STATUS_DECRYPTION_FAILED:
      return "DECRYPTION_FAILED";
    case STATUS_DECRYPTION_OKAY:
      return "DECRYPTION_OKAY";
    case STATUS_MISSING_PASSPHRASE:
      return "MISSING_PASSPHRASE";
    case STATUS_GOOD_PASSPHRASE:
      return "GOOD_PASSPHRASE";
    case STATUS_GOODMDC:
      return "GOODMDC";
    case STATUS_BADMDC:
      return "BADMDC";
    case STATUS_ERRMDC:
      return "ERRMDC";
    case STATUS_IMPORTED:
      return "IMPORTED";
    case STATUS_IMPORT_OK:
      return "IMPORT_OK";
    case STATUS_IMPORT_PROBLEM:
      return "IMPORT_PROBLEM";
    case STATUS_IMPORT_RES:
      return "IMPORT_RES";
    case STATUS_IMPORT_CHECK:
      return "IMPORT_CHECK";
    case STATUS_EXPORTED:
      return "EXPORTED";
    case STATUS_EXPORT_RES:
      return "EXPORT_RES";
    case STATUS_FILE_START:
      return "FILE_START";
    case STATUS_FILE_DONE:
      return "FILE_DONE";
    case STATUS_FILE_ERROR:
      return "FILE_ERROR";
    case STATUS_BEGIN_DECRYPTION:
      return "BEGIN_DECRYPTION";
    case STATUS_END_DECRYPTION:
      return "END_DECRYPTION";
    case STATUS_BEGIN_ENCRYPTION:
      return "BEGIN_ENCRYPTION";
    case STATUS_END_ENCRYPTION:
      return "END_ENCRYPTION";
    case STATUS_BEGIN_SIGNING:
      return "BEGIN_SIGNING";
    case STATUS_DELETE_PROBLEM:
      return "DELETE_PROBLEM";
    case STATUS_GET_BOOL:
      return "GET_BOOL";
    case STATUS_GET_LINE:
      return "GET_LINE";
    case STATUS_GET_HIDDEN:
      return "GET_HIDDEN";
    case STATUS_GOT_IT:
      return "GOT_IT";
    case STATUS_PROGRESS:
      return "PROGRESS";
    case STATUS_SIG_CREATED:
      return "SIG_CREATED";
    case STATUS_SESSION_KEY:
      return "SESSION_KEY";
    case STATUS_NOTATION_NAME:
      return "NOTATION_NAME";
    case STATUS_NOTATION_FLAGS:
      return "NOTATION_FLAGS";
    case STATUS_NOTATION_DATA:
      return "NOTATION_DATA";
    case STATUS_POLICY_URL:
      return "POLICY_URL";
    case STATUS_KEY_CREATED:
      return "KEY_CREATED";
    case STATUS_USERID_HINT:
      return "USERID_HINT";
    case STATUS_UNEXPECTED:
      return "UNEXPECTED";
    case STATUS_INV_RECP:
      return "INV_RECP";
    case STATUS_INV_SGNR:
      return "INV_SGNR";
    case STATUS_NO_RECP:
      return "NO_RECP";
    case STATUS_NO_SGNR:
      return "NO_SGNR";
    case STATUS_KEY_CONSIDERED:
      return "KEY_CONSIDERED";
    case STATUS_ALREADY_SIGNED:
      return "ALREADY_SIGNED";
    case STATUS_KEYEXPIRED:
      return "KEYEXPIRED";
    case STATUS_KEYREVOKED:
      return "KEYREVOKED";
    case STATUS_EXPSIG:
      return "EXPSIG";
    case STATUS_EXPKEYSIG:
      return "EXPKEYSIG";
    case STATUS_ATTRIBUTE:
      return "ATTRIBUTE";
    case STATUS_REVKEYSIG:
      return "REVKEYSIG";
    case STATUS_NEWSIG:
      return "NEWSIG";
    case STATUS_SIG_SUBPACKET:
      return "SIG_SUBPACKET";
    case STATUS_PLAINTEXT:
      return "PLAINTEXT";
    case STATUS_PLAINTEXT_LENGTH:
      return "PLAINTEXT_LENGTH";
    case STATUS_KEY_NOT_CREATED:
      return "KEY_NOT_CREATED";
    case STATUS_NEED_PASSPHRASE_PIN:
      return "NEED_PASSPHRASE_PIN";
    case STATUS_CARDCTRL:
      return "CARDCTRL";
    case STATUS_SC_OP_FAILURE:
      return "SC_OP_FAILURE";
    case STATUS_SC_OP_SUCCESS:
      return "SC_OP_SUCCESS";
    case STATUS_BACKUP_KEY_CREATED:
      return "BACKUP_KEY_CREATED";
    case STATUS_PKA_TRUST_BAD:
      return "PKA_TRUST_BAD";
    case STATUS_PKA_TRUST_GOOD:
      return "PKA_TRUST_GOOD";
    case STATUS_TOFU_USER:
      return "TOFU_USER";
    case STATUS_TOFU_STATS:
      return "TOFU_STATS";
    case STATUS_TOFU_STATS_SHORT:
      return "TOFU_STATS_SHORT";
    case STATUS_TOFU_STATS_LONG:
      return "TOFU_STATS_LONG";
    case STATUS_ENCRYPTION_COMPLIANCE_MODE:
      return "ENCRYPTION_COMPLIANCE_MODE";
    case STATUS_DECRYPTION_COMPLIANCE_MODE:
      return "DECRYPTION_COMPLIANCE_MODE";
    case STATUS_VERIFICATION_COMPLIANCE_MODE:
      return "VERIFICATION_COMPLIANCE_MODE";
    case STATUS_TRUNCATED:
      return "TRUNCATED";
    case STATUS_MOUNTPOINT:
      return "MOUNTPOINT";
    case STATUS_BLOCKDEV:
      return "BLOCKDEV";
    case STATUS_PINENTRY_LAUNCHED:
      return "PINENTRY_LAUNCHED";
    case STATUS_PLAINTEXT_FOLLOWS:
      return "PLAINTEXT_FOLLOWS";
    case STATUS_ERROR:
      return "ERROR";
    case STATUS_WARNING:
      return "WARNING";
    case STATUS_SUCCESS:
      return "SUCCESS";
    case STATUS_FAILURE:
      return "FAILURE";
    case STATUS_INQUIRE_MAXLEN:
      return "INQUIRE_MAXLEN";
    default:
      return "?";
  }
}

const char *get_inv_recpsgnr_code(gpg_error_t err) {
  const char *errstr;

  switch (err) {
    case GPG_ERR_NO_PUBKEY:
      errstr = "1";
      break;
    case GPG_ERR_AMBIGUOUS_NAME:
      errstr = "2";
      break;
    case GPG_ERR_WRONG_KEY_USAGE:
      errstr = "3";
      break;
    case GPG_ERR_CERT_REVOKED:
      errstr = "4";
      break;
    case GPG_ERR_CERT_EXPIRED:
      errstr = "5";
      break;
    case GPG_ERR_NO_CRL_KNOWN:
      errstr = "6";
      break;
    case GPG_ERR_CRL_TOO_OLD:
      errstr = "7";
      break;
    case GPG_ERR_NO_POLICY_MATCH:
      errstr = "8";
      break;

    case GPG_ERR_UNUSABLE_SECKEY:
    case GPG_ERR_NO_SECKEY:
      errstr = "9";
      break;

    case GPG_ERR_NOT_TRUSTED:
      errstr = "10";
      break;
    case GPG_ERR_MISSING_CERT:
      errstr = "11";
      break;
    case GPG_ERR_MISSING_ISSUER_CERT:
      errstr = "12";
      break;
    default:
      errstr = "0";
      break;
  }

  return errstr;
}
