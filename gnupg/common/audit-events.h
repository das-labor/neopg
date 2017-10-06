/* Output of mkstrtable.awk.  DO NOT EDIT.  */

/* audit.h - Definitions for the audit subsystem
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

/* The purpose of this complex string table is to produce
   optimal code with a minimum of relocations.  */

static const char eventstr_msgstr[] = 
  "null event" "\0"
  "setup ready" "\0"
  "agent ready" "\0"
  "dirmngr ready" "\0"
  "gpg ready" "\0"
  "gpgsm ready" "\0"
  "g13 ready" "\0"
  "got data" "\0"
  "detached signature" "\0"
  "cert only sig" "\0"
  "data hash algo" "\0"
  "attr hash algo" "\0"
  "data cipher algo" "\0"
  "bad data hash algo" "\0"
  "bad data cipher algo" "\0"
  "data hashing" "\0"
  "read error" "\0"
  "write error" "\0"
  "usage error" "\0"
  "save cert" "\0"
  "new sig" "\0"
  "sig name" "\0"
  "sig status" "\0"
  "new recp" "\0"
  "recp name" "\0"
  "recp result" "\0"
  "decryption result" "\0"
  "validate chain" "\0"
  "chain begin" "\0"
  "chain cert" "\0"
  "chain rootcert" "\0"
  "chain end" "\0"
  "chain status" "\0"
  "root trusted" "\0"
  "crl check" "\0"
  "got recipients" "\0"
  "session key" "\0"
  "encrypted to" "\0"
  "encryption done" "\0"
  "signed by" "\0"
  "signing done";

static const int eventstr_msgidx[] =
  {
    0,
    11,
    23,
    35,
    49,
    59,
    71,
    81,
    90,
    109,
    123,
    138,
    153,
    170,
    189,
    210,
    223,
    234,
    246,
    258,
    268,
    276,
    285,
    296,
    305,
    315,
    327,
    345,
    360,
    372,
    383,
    398,
    408,
    421,
    434,
    444,
    459,
    471,
    484,
    500,
    510,
    
  };

#define eventstr_msgidxof(code) (0 ? -1 \
  : ((code >= 0) && (code <= 40)) ? (code - 0) \
  : -1)
