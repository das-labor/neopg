/* strerror.c - Describing an error code.
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

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpg-error.h>

#include "gettext.h"

static const char *err_code(gpg_error_t err) {
  switch (err) {
    case GPG_ERR_NO_ERROR:
      return gettext_noop("Success");
    case GPG_ERR_GENERAL:
      return gettext_noop("General error");
    case GPG_ERR_UNKNOWN_PACKET:
      return gettext_noop("Unknown packet");
    case GPG_ERR_UNKNOWN_VERSION:
      return gettext_noop("Unknown version in packet");
    case GPG_ERR_PUBKEY_ALGO:
      return gettext_noop("Invalid public key algorithm");
    case GPG_ERR_DIGEST_ALGO:
      return gettext_noop("Invalid digest algorithm");
    case GPG_ERR_BAD_PUBKEY:
      return gettext_noop("Bad public key");
    case GPG_ERR_BAD_SECKEY:
      return gettext_noop("Bad secret key");
    case GPG_ERR_BAD_SIGNATURE:
      return gettext_noop("Bad signature");
    case GPG_ERR_NO_PUBKEY:
      return gettext_noop("No public key");
    case GPG_ERR_CHECKSUM:
      return gettext_noop("Checksum error");
    case GPG_ERR_BAD_PASSPHRASE:
      return gettext_noop("Bad passphrase");
    case GPG_ERR_CIPHER_ALGO:
      return gettext_noop("Invalid cipher algorithm");
    case GPG_ERR_KEYRING_OPEN:
      return gettext_noop("Cannot open keyring");
    case GPG_ERR_INV_PACKET:
      return gettext_noop("Invalid packet");
    case GPG_ERR_INV_ARMOR:
      return gettext_noop("Invalid armor");
    case GPG_ERR_NO_USER_ID:
      return gettext_noop("No user ID");
    case GPG_ERR_NO_SECKEY:
      return gettext_noop("No secret key");
    case GPG_ERR_WRONG_SECKEY:
      return gettext_noop("Wrong secret key used");
    case GPG_ERR_BAD_KEY:
      return gettext_noop("Bad session key");
    case GPG_ERR_COMPR_ALGO:
      return gettext_noop("Unknown compression algorithm");
    case GPG_ERR_NO_PRIME:
      return gettext_noop("Number is not prime");
    case GPG_ERR_NO_ENCODING_METHOD:
      return gettext_noop("Invalid encoding method");
    case GPG_ERR_NO_ENCRYPTION_SCHEME:
      return gettext_noop("Invalid encryption scheme");
    case GPG_ERR_NO_SIGNATURE_SCHEME:
      return gettext_noop("Invalid signature scheme");
    case GPG_ERR_INV_ATTR:
      return gettext_noop("Invalid attribute");
    case GPG_ERR_NO_VALUE:
      return gettext_noop("No value");
    case GPG_ERR_NOT_FOUND:
      return gettext_noop("Not found");
    case GPG_ERR_VALUE_NOT_FOUND:
      return gettext_noop("Value not found");
    case GPG_ERR_SYNTAX:
      return gettext_noop("Syntax error");
    case GPG_ERR_BAD_MPI:
      return gettext_noop("Bad MPI value");
    case GPG_ERR_INV_PASSPHRASE:
      return gettext_noop("Invalid passphrase");
    case GPG_ERR_SIG_CLASS:
      return gettext_noop("Invalid signature class");
    case GPG_ERR_RESOURCE_LIMIT:
      return gettext_noop("Resources exhausted");
    case GPG_ERR_INV_KEYRING:
      return gettext_noop("Invalid keyring");
    case GPG_ERR_TRUSTDB:
      return gettext_noop("Trust DB error");
    case GPG_ERR_BAD_CERT:
      return gettext_noop("Bad certificate");
    case GPG_ERR_INV_USER_ID:
      return gettext_noop("Invalid user ID");
    case GPG_ERR_UNEXPECTED:
      return gettext_noop("Unexpected error");
    case GPG_ERR_TIME_CONFLICT:
      return gettext_noop("Time conflict");
    case GPG_ERR_KEYSERVER:
      return gettext_noop("Keyserver error");
    case GPG_ERR_WRONG_PUBKEY_ALGO:
      return gettext_noop("Wrong public key algorithm");
    case GPG_ERR_TRIBUTE_TO_D_A:
      return gettext_noop("Tribute to D. A.");
    case GPG_ERR_WEAK_KEY:
      return gettext_noop("Weak encryption key");
    case GPG_ERR_INV_KEYLEN:
      return gettext_noop("Invalid key length");
    case GPG_ERR_INV_ARG:
      return gettext_noop("Invalid argument");
    case GPG_ERR_BAD_URI:
      return gettext_noop("Syntax error in URI");
    case GPG_ERR_INV_URI:
      return gettext_noop("Invalid URI");
    case GPG_ERR_NETWORK:
      return gettext_noop("Network error");
    case GPG_ERR_UNKNOWN_HOST:
      return gettext_noop("Unknown host");
    case GPG_ERR_SELFTEST_FAILED:
      return gettext_noop("Selftest failed");
    case GPG_ERR_NOT_ENCRYPTED:
      return gettext_noop("Data not encrypted");
    case GPG_ERR_NOT_PROCESSED:
      return gettext_noop("Data not processed");
    case GPG_ERR_UNUSABLE_PUBKEY:
      return gettext_noop("Unusable public key");
    case GPG_ERR_UNUSABLE_SECKEY:
      return gettext_noop("Unusable secret key");
    case GPG_ERR_INV_VALUE:
      return gettext_noop("Invalid value");
    case GPG_ERR_BAD_CERT_CHAIN:
      return gettext_noop("Bad certificate chain");
    case GPG_ERR_MISSING_CERT:
      return gettext_noop("Missing certificate");
    case GPG_ERR_NO_DATA:
      return gettext_noop("No data");
    case GPG_ERR_BUG:
      return gettext_noop("Bug");
    case GPG_ERR_NOT_SUPPORTED:
      return gettext_noop("Not supported");
    case GPG_ERR_INV_OP:
      return gettext_noop("Invalid operation code");
    case GPG_ERR_TIMEOUT:
      return gettext_noop("Timeout");
    case GPG_ERR_INTERNAL:
      return gettext_noop("Internal error");
    case GPG_ERR_EOF_GCRYPT:
      return gettext_noop("EOF (gcrypt)");
    case GPG_ERR_INV_OBJ:
      return gettext_noop("Invalid object");
    case GPG_ERR_TOO_SHORT:
      return gettext_noop("Provided object is too short");
    case GPG_ERR_TOO_LARGE:
      return gettext_noop("Provided object is too large");
    case GPG_ERR_NO_OBJ:
      return gettext_noop("Missing item in object");
    case GPG_ERR_NOT_IMPLEMENTED:
      return gettext_noop("Not implemented");
    case GPG_ERR_CONFLICT:
      return gettext_noop("Conflicting use");
    case GPG_ERR_INV_CIPHER_MODE:
      return gettext_noop("Invalid cipher mode");
    case GPG_ERR_INV_FLAG:
      return gettext_noop("Invalid flag");
    case GPG_ERR_INV_HANDLE:
      return gettext_noop("Invalid handle");
    case GPG_ERR_TRUNCATED:
      return gettext_noop("Result truncated");
    case GPG_ERR_INCOMPLETE_LINE:
      return gettext_noop("Incomplete line");
    case GPG_ERR_INV_RESPONSE:
      return gettext_noop("Invalid response");
    case GPG_ERR_NO_AGENT:
      return gettext_noop("No agent running");
    case GPG_ERR_AGENT:
      return gettext_noop("Agent error");
    case GPG_ERR_INV_DATA:
      return gettext_noop("Invalid data");
    case GPG_ERR_ASSUAN_SERVER_FAULT:
      return gettext_noop("Unspecific Assuan server fault");
    case GPG_ERR_ASSUAN:
      return gettext_noop("General Assuan error");
    case GPG_ERR_INV_SESSION_KEY:
      return gettext_noop("Invalid session key");
    case GPG_ERR_INV_SEXP:
      return gettext_noop("Invalid S-expression");
    case GPG_ERR_UNSUPPORTED_ALGORITHM:
      return gettext_noop("Unsupported algorithm");
    case GPG_ERR_NO_PIN_ENTRY:
      return gettext_noop("No pinentry");
    case GPG_ERR_PIN_ENTRY:
      return gettext_noop("pinentry error");
    case GPG_ERR_BAD_PIN:
      return gettext_noop("Bad PIN");
    case GPG_ERR_INV_NAME:
      return gettext_noop("Invalid name");
    case GPG_ERR_BAD_DATA:
      return gettext_noop("Bad data");
    case GPG_ERR_INV_PARAMETER:
      return gettext_noop("Invalid parameter");
    case GPG_ERR_WRONG_CARD:
      return gettext_noop("Wrong card");
    case GPG_ERR_NO_DIRMNGR:
      return gettext_noop("No dirmngr");
    case GPG_ERR_DIRMNGR:
      return gettext_noop("dirmngr error");
    case GPG_ERR_CERT_REVOKED:
      return gettext_noop("Certificate revoked");
    case GPG_ERR_NO_CRL_KNOWN:
      return gettext_noop("No CRL known");
    case GPG_ERR_CRL_TOO_OLD:
      return gettext_noop("CRL too old");
    case GPG_ERR_LINE_TOO_LONG:
      return gettext_noop("Line too long");
    case GPG_ERR_NOT_TRUSTED:
      return gettext_noop("Not trusted");
    case GPG_ERR_CANCELED:
      return gettext_noop("Operation cancelled");
    case GPG_ERR_BAD_CA_CERT:
      return gettext_noop("Bad CA certificate");
    case GPG_ERR_CERT_EXPIRED:
      return gettext_noop("Certificate expired");
    case GPG_ERR_CERT_TOO_YOUNG:
      return gettext_noop("Certificate too young");
    case GPG_ERR_UNSUPPORTED_CERT:
      return gettext_noop("Unsupported certificate");
    case GPG_ERR_UNKNOWN_SEXP:
      return gettext_noop("Unknown S-expression");
    case GPG_ERR_UNSUPPORTED_PROTECTION:
      return gettext_noop("Unsupported protection");
    case GPG_ERR_CORRUPTED_PROTECTION:
      return gettext_noop("Corrupted protection");
    case GPG_ERR_AMBIGUOUS_NAME:
      return gettext_noop("Ambiguous name");
    case GPG_ERR_CARD:
      return gettext_noop("Card error");
    case GPG_ERR_CARD_RESET:
      return gettext_noop("Card reset required");
    case GPG_ERR_CARD_REMOVED:
      return gettext_noop("Card removed");
    case GPG_ERR_INV_CARD:
      return gettext_noop("Invalid card");
    case GPG_ERR_CARD_NOT_PRESENT:
      return gettext_noop("Card not present");
    case GPG_ERR_NO_PKCS15_APP:
      return gettext_noop("No PKCS15 application");
    case GPG_ERR_NOT_CONFIRMED:
      return gettext_noop("Not confirmed");
    case GPG_ERR_CONFIGURATION:
      return gettext_noop("Configuration error");
    case GPG_ERR_NO_POLICY_MATCH:
      return gettext_noop("No policy match");
    case GPG_ERR_INV_INDEX:
      return gettext_noop("Invalid index");
    case GPG_ERR_INV_ID:
      return gettext_noop("Invalid ID");
    case GPG_ERR_NO_SCDAEMON:
      return gettext_noop("No SmartCard daemon");
    case GPG_ERR_SCDAEMON:
      return gettext_noop("SmartCard daemon error");
    case GPG_ERR_UNSUPPORTED_PROTOCOL:
      return gettext_noop("Unsupported protocol");
    case GPG_ERR_BAD_PIN_METHOD:
      return gettext_noop("Bad PIN method");
    case GPG_ERR_CARD_NOT_INITIALIZED:
      return gettext_noop("Card not initialized");
    case GPG_ERR_UNSUPPORTED_OPERATION:
      return gettext_noop("Unsupported operation");
    case GPG_ERR_WRONG_KEY_USAGE:
      return gettext_noop("Wrong key usage");
    case GPG_ERR_NOTHING_FOUND:
      return gettext_noop("Nothing found");
    case GPG_ERR_WRONG_BLOB_TYPE:
      return gettext_noop("Wrong blob type");
    case GPG_ERR_MISSING_VALUE:
      return gettext_noop("Missing value");
    case GPG_ERR_HARDWARE:
      return gettext_noop("Hardware problem");
    case GPG_ERR_PIN_BLOCKED:
      return gettext_noop("PIN blocked");
    case GPG_ERR_USE_CONDITIONS:
      return gettext_noop("Conditions of use not satisfied");
    case GPG_ERR_PIN_NOT_SYNCED:
      return gettext_noop("PINs are not synced");
    case GPG_ERR_INV_CRL:
      return gettext_noop("Invalid CRL");
    case GPG_ERR_BAD_BER:
      return gettext_noop("BER error");
    case GPG_ERR_INV_BER:
      return gettext_noop("Invalid BER");
    case GPG_ERR_ELEMENT_NOT_FOUND:
      return gettext_noop("Element not found");
    case GPG_ERR_IDENTIFIER_NOT_FOUND:
      return gettext_noop("Identifier not found");
    case GPG_ERR_INV_TAG:
      return gettext_noop("Invalid tag");
    case GPG_ERR_INV_LENGTH:
      return gettext_noop("Invalid length");
    case GPG_ERR_INV_KEYINFO:
      return gettext_noop("Invalid key info");
    case GPG_ERR_UNEXPECTED_TAG:
      return gettext_noop("Unexpected tag");
    case GPG_ERR_NOT_DER_ENCODED:
      return gettext_noop("Not DER encoded");
    case GPG_ERR_NO_CMS_OBJ:
      return gettext_noop("No CMS object");
    case GPG_ERR_INV_CMS_OBJ:
      return gettext_noop("Invalid CMS object");
    case GPG_ERR_UNKNOWN_CMS_OBJ:
      return gettext_noop("Unknown CMS object");
    case GPG_ERR_UNSUPPORTED_CMS_OBJ:
      return gettext_noop("Unsupported CMS object");
    case GPG_ERR_UNSUPPORTED_ENCODING:
      return gettext_noop("Unsupported encoding");
    case GPG_ERR_UNSUPPORTED_CMS_VERSION:
      return gettext_noop("Unsupported CMS version");
    case GPG_ERR_UNKNOWN_ALGORITHM:
      return gettext_noop("Unknown algorithm");
    case GPG_ERR_INV_ENGINE:
      return gettext_noop("Invalid crypto engine");
    case GPG_ERR_PUBKEY_NOT_TRUSTED:
      return gettext_noop("Public key not trusted");
    case GPG_ERR_DECRYPT_FAILED:
      return gettext_noop("Decryption failed");
    case GPG_ERR_KEY_EXPIRED:
      return gettext_noop("Key expired");
    case GPG_ERR_SIG_EXPIRED:
      return gettext_noop("Signature expired");
    case GPG_ERR_ENCODING_PROBLEM:
      return gettext_noop("Encoding problem");
    case GPG_ERR_INV_STATE:
      return gettext_noop("Invalid state");
    case GPG_ERR_DUP_VALUE:
      return gettext_noop("Duplicated value");
    case GPG_ERR_MISSING_ACTION:
      return gettext_noop("Missing action");
    case GPG_ERR_MODULE_NOT_FOUND:
      return gettext_noop("ASN.1 module not found");
    case GPG_ERR_INV_OID_STRING:
      return gettext_noop("Invalid OID string");
    case GPG_ERR_INV_TIME:
      return gettext_noop("Invalid time");
    case GPG_ERR_INV_CRL_OBJ:
      return gettext_noop("Invalid CRL object");
    case GPG_ERR_UNSUPPORTED_CRL_VERSION:
      return gettext_noop("Unsupported CRL version");
    case GPG_ERR_INV_CERT_OBJ:
      return gettext_noop("Invalid certificate object");
    case GPG_ERR_UNKNOWN_NAME:
      return gettext_noop("Unknown name");
    case GPG_ERR_LOCALE_PROBLEM:
      return gettext_noop("A locale function failed");
    case GPG_ERR_NOT_LOCKED:
      return gettext_noop("Not locked");
    case GPG_ERR_PROTOCOL_VIOLATION:
      return gettext_noop("Protocol violation");
    case GPG_ERR_INV_MAC:
      return gettext_noop("Invalid MAC");
    case GPG_ERR_INV_REQUEST:
      return gettext_noop("Invalid request");
    case GPG_ERR_UNKNOWN_EXTN:
      return gettext_noop("Unknown extension");
    case GPG_ERR_UNKNOWN_CRIT_EXTN:
      return gettext_noop("Unknown critical extension");
    case GPG_ERR_LOCKED:
      return gettext_noop("Locked");
    case GPG_ERR_UNKNOWN_OPTION:
      return gettext_noop("Unknown option");
    case GPG_ERR_UNKNOWN_COMMAND:
      return gettext_noop("Unknown command");
    case GPG_ERR_NOT_OPERATIONAL:
      return gettext_noop("Not operational");
    case GPG_ERR_NO_PASSPHRASE:
      return gettext_noop("No passphrase given");
    case GPG_ERR_NO_PIN:
      return gettext_noop("No PIN given");
    case GPG_ERR_NOT_ENABLED:
      return gettext_noop("Not enabled");
    case GPG_ERR_NO_ENGINE:
      return gettext_noop("No crypto engine");
    case GPG_ERR_MISSING_KEY:
      return gettext_noop("Missing key");
    case GPG_ERR_TOO_MANY:
      return gettext_noop("Too many objects");
    case GPG_ERR_LIMIT_REACHED:
      return gettext_noop("Limit reached");
    case GPG_ERR_NOT_INITIALIZED:
      return gettext_noop("Not initialized");
    case GPG_ERR_MISSING_ISSUER_CERT:
      return gettext_noop("Missing issuer certificate");
    case GPG_ERR_NO_KEYSERVER:
      return gettext_noop("No keyserver available");
    case GPG_ERR_INV_CURVE:
      return gettext_noop("Invalid elliptic curve");
    case GPG_ERR_UNKNOWN_CURVE:
      return gettext_noop("Unknown elliptic curve");
    case GPG_ERR_DUP_KEY:
      return gettext_noop("Duplicated key");
    case GPG_ERR_AMBIGUOUS:
      return gettext_noop("Ambiguous result");
    case GPG_ERR_NO_CRYPT_CTX:
      return gettext_noop("No crypto context");
    case GPG_ERR_WRONG_CRYPT_CTX:
      return gettext_noop("Wrong crypto context");
    case GPG_ERR_BAD_CRYPT_CTX:
      return gettext_noop("Bad crypto context");
    case GPG_ERR_CRYPT_CTX_CONFLICT:
      return gettext_noop("Conflict in the crypto context");
    case GPG_ERR_BROKEN_PUBKEY:
      return gettext_noop("Broken public key");
    case GPG_ERR_BROKEN_SECKEY:
      return gettext_noop("Broken secret key");
    case GPG_ERR_MAC_ALGO:
      return gettext_noop("Invalid MAC algorithm");
    case GPG_ERR_FULLY_CANCELED:
      return gettext_noop("Operation fully cancelled");
    case GPG_ERR_UNFINISHED:
      return gettext_noop("Operation not yet finished");
    case GPG_ERR_BUFFER_TOO_SHORT:
      return gettext_noop("Buffer too short");

    case GPG_ERR_SEXP_INV_LEN_SPEC:
      return gettext_noop("Invalid length specifier in S-expression");
    case GPG_ERR_SEXP_STRING_TOO_LONG:
      return gettext_noop("String too long in S-expression");
    case GPG_ERR_SEXP_UNMATCHED_PAREN:
      return gettext_noop("Unmatched parentheses in S-expression");
    case GPG_ERR_SEXP_NOT_CANONICAL:
      return gettext_noop("S-expression not canonical");
    case GPG_ERR_SEXP_BAD_CHARACTER:
      return gettext_noop("Bad character in S-expression");
    case GPG_ERR_SEXP_BAD_QUOTATION:
      return gettext_noop("Bad quotation in S-expression");
    case GPG_ERR_SEXP_ZERO_PREFIX:
      return gettext_noop("Zero prefix in S-expression");
    case GPG_ERR_SEXP_NESTED_DH:
      return gettext_noop("Nested display hints in S-expression");
    case GPG_ERR_SEXP_UNMATCHED_DH:
      return gettext_noop("Unmatched display hints");
    case GPG_ERR_SEXP_UNEXPECTED_PUNC:
      return gettext_noop("Unexpected reserved punctuation in S-expression");
    case GPG_ERR_SEXP_BAD_HEX_CHAR:
      return gettext_noop("Bad hexadecimal character in S-expression");
    case GPG_ERR_SEXP_ODD_HEX_NUMBERS:
      return gettext_noop("Odd hexadecimal numbers in S-expression");
    case GPG_ERR_SEXP_BAD_OCT_CHAR:
      return gettext_noop("Bad octal character in S-expression");

    case GPG_ERR_SUBKEYS_EXP_OR_REV:
      return gettext_noop("All subkeys are expired or revoked");
    case GPG_ERR_DB_CORRUPTED:
      return gettext_noop("Database is corrupted");
    case GPG_ERR_SERVER_FAILED:
      return gettext_noop("Server indicated a failure");
    case GPG_ERR_NO_NAME:
      return gettext_noop("No name");
    case GPG_ERR_NO_KEY:
      return gettext_noop("No key");
    case GPG_ERR_LEGACY_KEY:
      return gettext_noop("Legacy key");
    case GPG_ERR_REQUEST_TOO_SHORT:
      return gettext_noop("Request too short");
    case GPG_ERR_REQUEST_TOO_LONG:
      return gettext_noop("Request too long");
    case GPG_ERR_OBJ_TERM_STATE:
      return gettext_noop("Object is in termination state");
    case GPG_ERR_NO_CERT_CHAIN:
      return gettext_noop("No certificate chain");
    case GPG_ERR_CERT_TOO_LARGE:
      return gettext_noop("Certificate is too large");
    case GPG_ERR_INV_RECORD:
      return gettext_noop("Invalid record");
    case GPG_ERR_BAD_MAC:
      return gettext_noop("The MAC does not verify");
    case GPG_ERR_UNEXPECTED_MSG:
      return gettext_noop("Unexpected message");
    case GPG_ERR_COMPR_FAILED:
      return gettext_noop("Compression or decompression failed");
    case GPG_ERR_WOULD_WRAP:
      return gettext_noop("A counter would wrap");
    case GPG_ERR_FATAL_ALERT:
      return gettext_noop("Fatal alert message received");
    case GPG_ERR_NO_CIPHER:
      return gettext_noop("No cipher algorithm");
    case GPG_ERR_MISSING_CLIENT_CERT:
      return gettext_noop("Missing client certificate");
    case GPG_ERR_CLOSE_NOTIFY:
      return gettext_noop("Close notification received");
    case GPG_ERR_TICKET_EXPIRED:
      return gettext_noop("Ticket expired");
    case GPG_ERR_BAD_TICKET:
      return gettext_noop("Bad ticket");
    case GPG_ERR_UNKNOWN_IDENTITY:
      return gettext_noop("Unknown identity");
    case GPG_ERR_BAD_HS_CERT:
      return gettext_noop("Bad certificate message in handshake");
    case GPG_ERR_BAD_HS_CERT_REQ:
      return gettext_noop("Bad certificate request message in handshake");
    case GPG_ERR_BAD_HS_CERT_VER:
      return gettext_noop("Bad certificate verify message in handshake");
    case GPG_ERR_BAD_HS_CHANGE_CIPHER:
      return gettext_noop("Bad change cipher message in handshake");
    case GPG_ERR_BAD_HS_CLIENT_HELLO:
      return gettext_noop("Bad client hello message in handshake");
    case GPG_ERR_BAD_HS_SERVER_HELLO:
      return gettext_noop("Bad server hello message in handshake");
    case GPG_ERR_BAD_HS_SERVER_HELLO_DONE:
      return gettext_noop("Bad server hello done message in handshake");
    case GPG_ERR_BAD_HS_FINISHED:
      return gettext_noop("Bad finished message in handshake");
    case GPG_ERR_BAD_HS_SERVER_KEX:
      return gettext_noop("Bad server key exchange message in handshake");
    case GPG_ERR_BAD_HS_CLIENT_KEX:
      return gettext_noop("Bad client key exchange message in handshake");
    case GPG_ERR_BOGUS_STRING:
      return gettext_noop("Bogus string");
    case GPG_ERR_FORBIDDEN:
      return gettext_noop("Forbidden");
    case GPG_ERR_KEY_DISABLED:
      return gettext_noop("Key disabled");
    case GPG_ERR_KEY_ON_CARD:
      return gettext_noop("Not possible with a card based key");
    case GPG_ERR_INV_LOCK_OBJ:
      return gettext_noop("Invalid lock object");

    case GPG_ERR_TRUE:
      return gettext_noop("True");
    case GPG_ERR_FALSE:
      return gettext_noop("False");

    case GPG_ERR_ASS_GENERAL:
      return gettext_noop("General IPC error");
    case GPG_ERR_ASS_ACCEPT_FAILED:
      return gettext_noop("IPC accept call failed");
    case GPG_ERR_ASS_CONNECT_FAILED:
      return gettext_noop("IPC connect call failed");
    case GPG_ERR_ASS_INV_RESPONSE:
      return gettext_noop("Invalid IPC response");
    case GPG_ERR_ASS_INV_VALUE:
      return gettext_noop("Invalid value passed to IPC");
    case GPG_ERR_ASS_INCOMPLETE_LINE:
      return gettext_noop("Incomplete line passed to IPC");
    case GPG_ERR_ASS_LINE_TOO_LONG:
      return gettext_noop("Line passed to IPC too long");
    case GPG_ERR_ASS_NESTED_COMMANDS:
      return gettext_noop("Nested IPC commands");
    case GPG_ERR_ASS_NO_DATA_CB:
      return gettext_noop("No data callback in IPC");
    case GPG_ERR_ASS_NO_INQUIRE_CB:
      return gettext_noop("No inquire callback in IPC");
    case GPG_ERR_ASS_NOT_A_SERVER:
      return gettext_noop("Not an IPC server");
    case GPG_ERR_ASS_NOT_A_CLIENT:
      return gettext_noop("Not an IPC client");
    case GPG_ERR_ASS_SERVER_START:
      return gettext_noop("Problem starting IPC server");
    case GPG_ERR_ASS_READ_ERROR:
      return gettext_noop("IPC read error");
    case GPG_ERR_ASS_WRITE_ERROR:
      return gettext_noop("IPC write error");

    case GPG_ERR_ASS_TOO_MUCH_DATA:
      return gettext_noop("Too much data for IPC layer");
    case GPG_ERR_ASS_UNEXPECTED_CMD:
      return gettext_noop("Unexpected IPC command");
    case GPG_ERR_ASS_UNKNOWN_CMD:
      return gettext_noop("Unknown IPC command");
    case GPG_ERR_ASS_SYNTAX:
      return gettext_noop("IPC syntax error");
    case GPG_ERR_ASS_CANCELED:
      return gettext_noop("IPC call has been cancelled");
    case GPG_ERR_ASS_NO_INPUT:
      return gettext_noop("No input source for IPC");
    case GPG_ERR_ASS_NO_OUTPUT:
      return gettext_noop("No output source for IPC");
    case GPG_ERR_ASS_PARAMETER:
      return gettext_noop("IPC parameter error");
    case GPG_ERR_ASS_UNKNOWN_INQUIRE:
      return gettext_noop("Unknown IPC inquire");

    case GPG_ERR_ENGINE_TOO_OLD:
      return gettext_noop("Crypto engine too old");
    case GPG_ERR_WINDOW_TOO_SMALL:
      return gettext_noop("Screen or window too small");
    case GPG_ERR_WINDOW_TOO_LARGE:
      return gettext_noop("Screen or window too large");
    case GPG_ERR_MISSING_ENVVAR:
      return gettext_noop("Required environment variable not set");
    case GPG_ERR_USER_ID_EXISTS:
      return gettext_noop("User ID already exists");
    case GPG_ERR_NAME_EXISTS:
      return gettext_noop("Name already exists");
    case GPG_ERR_DUP_NAME:
      return gettext_noop("Duplicated name");
    case GPG_ERR_TOO_YOUNG:
      return gettext_noop("Object is too young");
    case GPG_ERR_TOO_OLD:
      return gettext_noop("Object is too old");
    case GPG_ERR_UNKNOWN_FLAG:
      return gettext_noop("Unknown flag");
    case GPG_ERR_INV_ORDER:
      return gettext_noop("Invalid execution order");
    case GPG_ERR_ALREADY_FETCHED:
      return gettext_noop("Already fetched");
    case GPG_ERR_TRY_LATER:
      return gettext_noop("Try again later");
    case GPG_ERR_WRONG_NAME:
      return gettext_noop("Wrong name");

    case GPG_ERR_SYSTEM_BUG:
      return gettext_noop("System bug detected");

    case GPG_ERR_DNS_UNKNOWN:
      return gettext_noop("Unknown DNS error");
    case GPG_ERR_DNS_SECTION:
      return gettext_noop("Invalid DNS section");
    case GPG_ERR_DNS_ADDRESS:
      return gettext_noop("Invalid textual address form");
    case GPG_ERR_DNS_NO_QUERY:
      return gettext_noop("Missing DNS query packet");
    case GPG_ERR_DNS_NO_ANSWER:
      return gettext_noop("Missing DNS answer packet");
    case GPG_ERR_DNS_CLOSED:
      return gettext_noop("Connection closed in DNS");
    case GPG_ERR_DNS_VERIFY:
      return gettext_noop("Verification failed in DNS");
    case GPG_ERR_DNS_TIMEOUT:
      return gettext_noop("DNS Timeout");

    case GPG_ERR_LDAP_GENERAL:
      return gettext_noop("General LDAP error");
    case GPG_ERR_LDAP_ATTR_GENERAL:
      return gettext_noop("General LDAP attribute error");
    case GPG_ERR_LDAP_NAME_GENERAL:
      return gettext_noop("General LDAP name error");
    case GPG_ERR_LDAP_SECURITY_GENERAL:
      return gettext_noop("General LDAP security error");
    case GPG_ERR_LDAP_SERVICE_GENERAL:
      return gettext_noop("General LDAP service error");
    case GPG_ERR_LDAP_UPDATE_GENERAL:
      return gettext_noop("General LDAP update error");
    case GPG_ERR_LDAP_E_GENERAL:
      return gettext_noop("Experimental LDAP error code");
    case GPG_ERR_LDAP_X_GENERAL:
      return gettext_noop("Private LDAP error code");
    case GPG_ERR_LDAP_OTHER_GENERAL:
      return gettext_noop("Other general LDAP error");
    case GPG_ERR_LDAP_X_CONNECTING:
      return gettext_noop("LDAP connecting failed (X)");
    case GPG_ERR_LDAP_REFERRAL_LIMIT:
      return gettext_noop("LDAP referral limit exceeded");
    case GPG_ERR_LDAP_CLIENT_LOOP:
      return gettext_noop("LDAP client loop");

    case GPG_ERR_LDAP_NO_RESULTS:
      return gettext_noop("No LDAP results returned");
    case GPG_ERR_LDAP_CONTROL_NOT_FOUND:
      return gettext_noop("LDAP control not found");
    case GPG_ERR_LDAP_NOT_SUPPORTED:
      return gettext_noop("Not supported by LDAP");
    case GPG_ERR_LDAP_CONNECT:
      return gettext_noop("LDAP connect error");
    case GPG_ERR_LDAP_NO_MEMORY:
      return gettext_noop("Out of memory in LDAP");
    case GPG_ERR_LDAP_PARAM:
      return gettext_noop("Bad parameter to an LDAP routine");
    case GPG_ERR_LDAP_USER_CANCELLED:
      return gettext_noop("User cancelled LDAP operation");
    case GPG_ERR_LDAP_FILTER:
      return gettext_noop("Bad LDAP search filter");
    case GPG_ERR_LDAP_AUTH_UNKNOWN:
      return gettext_noop("Unknown LDAP authentication method");
    case GPG_ERR_LDAP_TIMEOUT:
      return gettext_noop("Timeout in LDAP");
    case GPG_ERR_LDAP_DECODING:
      return gettext_noop("LDAP decoding error");
    case GPG_ERR_LDAP_ENCODING:
      return gettext_noop("LDAP encoding error");
    case GPG_ERR_LDAP_LOCAL:
      return gettext_noop("LDAP local error");
    case GPG_ERR_LDAP_SERVER_DOWN:
      return gettext_noop("Cannot contact LDAP server");
    case GPG_ERR_LDAP_SUCCESS:
      return gettext_noop("LDAP success");
    case GPG_ERR_LDAP_OPERATIONS:
      return gettext_noop("LDAP operations error");
    case GPG_ERR_LDAP_PROTOCOL:
      return gettext_noop("LDAP protocol error");
    case GPG_ERR_LDAP_TIMELIMIT:
      return gettext_noop("Time limit exceeded in LDAP");
    case GPG_ERR_LDAP_SIZELIMIT:
      return gettext_noop("Size limit exceeded in LDAP");
    case GPG_ERR_LDAP_COMPARE_FALSE:
      return gettext_noop("LDAP compare false");
    case GPG_ERR_LDAP_COMPARE_TRUE:
      return gettext_noop("LDAP compare true");
    case GPG_ERR_LDAP_UNSUPPORTED_AUTH:
      return gettext_noop("LDAP authentication method not supported");
    case GPG_ERR_LDAP_STRONG_AUTH_RQRD:
      return gettext_noop("Strong(er) LDAP authentication required");
    case GPG_ERR_LDAP_PARTIAL_RESULTS:
      return gettext_noop("Partial LDAP results+referral received");
    case GPG_ERR_LDAP_REFERRAL:
      return gettext_noop("LDAP referral");
    case GPG_ERR_LDAP_ADMINLIMIT:
      return gettext_noop("Administrative LDAP limit exceeded");
    case GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN:
      return gettext_noop("Critical LDAP extension is unavailable");
    case GPG_ERR_LDAP_CONFIDENT_RQRD:
      return gettext_noop("Confidentiality required by LDAP");
    case GPG_ERR_LDAP_SASL_BIND_INPROG:
      return gettext_noop("LDAP SASL bind in progress");

    case GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE:
      return gettext_noop("No such LDAP attribute");
    case GPG_ERR_LDAP_UNDEFINED_TYPE:
      return gettext_noop("Undefined LDAP attribute type");
    case GPG_ERR_LDAP_BAD_MATCHING:
      return gettext_noop("Inappropriate matching in LDAP");
    case GPG_ERR_LDAP_CONST_VIOLATION:
      return gettext_noop("Constraint violation in LDAP");
    case GPG_ERR_LDAP_TYPE_VALUE_EXISTS:
      return gettext_noop("LDAP type or value exists");
    case GPG_ERR_LDAP_INV_SYNTAX:
      return gettext_noop("Invalid syntax in LDAP");

    case GPG_ERR_LDAP_NO_SUCH_OBJ:
      return gettext_noop("No such LDAP object");
    case GPG_ERR_LDAP_ALIAS_PROBLEM:
      return gettext_noop("LDAP alias problem");
    case GPG_ERR_LDAP_INV_DN_SYNTAX:
      return gettext_noop("Invalid DN syntax in LDAP");
    case GPG_ERR_LDAP_IS_LEAF:
      return gettext_noop("LDAP entry is a leaf");
    case GPG_ERR_LDAP_ALIAS_DEREF:
      return gettext_noop("LDAP alias dereferencing problem");

    case GPG_ERR_LDAP_X_PROXY_AUTH_FAIL:
      return gettext_noop("LDAP proxy authorization failure (X)");
    case GPG_ERR_LDAP_BAD_AUTH:
      return gettext_noop("Inappropriate LDAP authentication");
    case GPG_ERR_LDAP_INV_CREDENTIALS:
      return gettext_noop("Invalid LDAP credentials");
    case GPG_ERR_LDAP_INSUFFICIENT_ACC:
      return gettext_noop("Insufficient access for LDAP");
    case GPG_ERR_LDAP_BUSY:
      return gettext_noop("LDAP server is busy");
    case GPG_ERR_LDAP_UNAVAILABLE:
      return gettext_noop("LDAP server is unavailable");
    case GPG_ERR_LDAP_UNWILL_TO_PERFORM:
      return gettext_noop("LDAP server is unwilling to perform");
    case GPG_ERR_LDAP_LOOP_DETECT:
      return gettext_noop("Loop detected by LDAP");

    case GPG_ERR_LDAP_NAMING_VIOLATION:
      return gettext_noop("LDAP naming violation");
    case GPG_ERR_LDAP_OBJ_CLS_VIOLATION:
      return gettext_noop("LDAP object class violation");
    case GPG_ERR_LDAP_NOT_ALLOW_NONLEAF:
      return gettext_noop("LDAP operation not allowed on non-leaf");
    case GPG_ERR_LDAP_NOT_ALLOW_ON_RDN:
      return gettext_noop("LDAP operation not allowed on RDN");
    case GPG_ERR_LDAP_ALREADY_EXISTS:
      return gettext_noop("Already exists (LDAP)");
    case GPG_ERR_LDAP_NO_OBJ_CLASS_MODS:
      return gettext_noop("Cannot modify LDAP object class");
    case GPG_ERR_LDAP_RESULTS_TOO_LARGE:
      return gettext_noop("LDAP results too large");
    case GPG_ERR_LDAP_AFFECTS_MULT_DSAS:
      return gettext_noop("LDAP operation affects multiple DSAs");

    case GPG_ERR_LDAP_VLV:
      return gettext_noop("Virtual LDAP list view error");

    case GPG_ERR_LDAP_OTHER:
      return gettext_noop("Other LDAP error");

    case GPG_ERR_LDAP_CUP_RESOURCE_LIMIT:
      return gettext_noop("Resources exhausted in LCUP");
    case GPG_ERR_LDAP_CUP_SEC_VIOLATION:
      return gettext_noop("Security violation in LCUP");
    case GPG_ERR_LDAP_CUP_INV_DATA:
      return gettext_noop("Invalid data in LCUP");
    case GPG_ERR_LDAP_CUP_UNSUP_SCHEME:
      return gettext_noop("Unsupported scheme in LCUP");
    case GPG_ERR_LDAP_CUP_RELOAD:
      return gettext_noop("Reload required in LCUP");
    case GPG_ERR_LDAP_CANCELLED:
      return gettext_noop("LDAP cancelled");
    case GPG_ERR_LDAP_NO_SUCH_OPERATION:
      return gettext_noop("No LDAP operation to cancel");
    case GPG_ERR_LDAP_TOO_LATE:
      return gettext_noop("Too late to cancel LDAP");
    case GPG_ERR_LDAP_CANNOT_CANCEL:
      return gettext_noop("Cannot cancel LDAP");
    case GPG_ERR_LDAP_ASSERTION_FAILED:
      return gettext_noop("LDAP assertion failed");
    case GPG_ERR_LDAP_PROX_AUTH_DENIED:
      return gettext_noop("Proxied authorization denied by LDAP");

    case GPG_ERR_USER_1:
      return gettext_noop("User defined error code 1");
    case GPG_ERR_USER_2:
      return gettext_noop("User defined error code 2");
    case GPG_ERR_USER_3:
      return gettext_noop("User defined error code 3");
    case GPG_ERR_USER_4:
      return gettext_noop("User defined error code 4");
    case GPG_ERR_USER_5:
      return gettext_noop("User defined error code 5");
    case GPG_ERR_USER_6:
      return gettext_noop("User defined error code 6");
    case GPG_ERR_USER_7:
      return gettext_noop("User defined error code 7");
    case GPG_ERR_USER_8:
      return gettext_noop("User defined error code 8");
    case GPG_ERR_USER_9:
      return gettext_noop("User defined error code 9");
    case GPG_ERR_USER_10:
      return gettext_noop("User defined error code 10");
    case GPG_ERR_USER_11:
      return gettext_noop("User defined error code 11");
    case GPG_ERR_USER_12:
      return gettext_noop("User defined error code 12");
    case GPG_ERR_USER_13:
      return gettext_noop("User defined error code 13");
    case GPG_ERR_USER_14:
      return gettext_noop("User defined error code 14");
    case GPG_ERR_USER_15:
      return gettext_noop("User defined error code 15");
    case GPG_ERR_USER_16:
      return gettext_noop("User defined error code 16");

    case GPG_ERR_MISSING_ERRNO:
      return gettext_noop("System error w/o errno");
    case GPG_ERR_UNKNOWN_ERRNO:
      return gettext_noop("Unknown system error");
    case GPG_ERR_EOF:
      return gettext_noop("End of file");

    case GPG_ERR_CODE_DIM:
    default:
      break;
  }
  return gettext_noop("Unknown error code");
}

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  This function is not thread-safe.  */
const char *_gpg_strerror(gpg_error_t err) {
  if (err & GPG_ERR_SYSTEM_ERROR) {
    int no = gpg_error_to_errno(err);
    if (no)
      return strerror(no);
    else
      err = GPG_ERR_UNKNOWN_ERRNO;
  }
  return dgettext(PACKAGE, err_code(err));
}

/* Return the error string for ERR in the user-supplied buffer BUF of
   size BUFLEN.  This function is, in contrast to gpg_strerror,
   thread-safe if a thread-safe strerror_r() function is provided by
   the system.  If the function succeeds, 0 is returned and BUF
   contains the string describing the error.  If the buffer was not
   large enough, ERANGE is returned and BUF contains as much of the
   beginning of the error string as fits into the buffer.  */
int _gpg_strerror_r(gpg_error_t err, char *buf, size_t buflen) {
  const char *errstr;
  size_t errstr_len;
  size_t cpy_len;

  if (err & GPG_ERR_SYSTEM_ERROR) {
    int no = gpg_error_to_errno(err);
    if (no) {
      int system_err = strerror_r(no, buf, buflen);

      if (system_err != EINVAL) {
        if (buflen) buf[buflen - 1] = '\0';
        return system_err;
      }
    }
    err = GPG_ERR_UNKNOWN_ERRNO;
  }

  errstr = dgettext(PACKAGE, err_code(err));
  errstr_len = strlen(errstr) + 1;
  cpy_len = errstr_len < buflen ? errstr_len : buflen;
  memcpy(buf, errstr, cpy_len);
  if (buflen) buf[buflen - 1] = '\0';

  return cpy_len == errstr_len ? 0 : ERANGE;
}
