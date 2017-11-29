/* cipher.c - En-/De-ciphering filter
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2006, 2009 Free Software Foundation, Inc.
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

#include "../common/iobuf.h"
#include "../common/status.h"
#include "../common/util.h"
#include "filter.h"
#include "gpg.h"
#include "main.h"
#include "options.h"
#include "packet.h"

#define MIN_PARTIAL_SIZE 512

static void write_header(cipher_filter_context_t *cfx, IOBUF a) {
  gpg_error_t err;
  PACKET pkt;
  PKT_encrypted ed;
  byte temp[18];
  unsigned int blocksize;
  unsigned int nprefix;

  blocksize = openpgp_cipher_get_algo_blklen(cfx->dek->algo);
  if (blocksize < 8 || blocksize > 16)
    log_fatal("unsupported blocksize %u\n", blocksize);

  memset(&ed, 0, sizeof ed);
  ed.len = cfx->datalen;
  ed.extralen = blocksize + 2;
  ed.new_ctb = !ed.len;

  ed.mdc_method = DIGEST_ALGO_SHA1;
  cfx->mdc_hash = Botan::HashFunction::create_or_throw("SHA-1");

  {
    char buf[20];

    sprintf(buf, "%d %d", ed.mdc_method, cfx->dek->algo);
    write_status_text(STATUS_BEGIN_ENCRYPTION, buf);
  }

  init_packet(&pkt);
  pkt.pkttype = PKT_ENCRYPTED_MDC;
  pkt.pkt.encrypted = &ed;
  if (build_packet(a, &pkt)) log_bug("build_packet(ENCR_DATA) failed\n");
  nprefix = blocksize;
  gcry_randomize(temp, nprefix);
  temp[nprefix] = temp[nprefix - 2];
  temp[nprefix + 1] = temp[nprefix - 1];
  print_cipher_algo_note((cipher_algo_t)(cfx->dek->algo));
  err = openpgp_cipher_open(&cfx->cipher_hd, cfx->dek->algo,
                            GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
  if (err) {
    /* We should never get an error here cause we already checked,
     * that the algorithm is available.  */
    BUG();
  }

  /*   log_hexdump( "thekey", cfx->dek->key, cfx->dek->keylen );*/
  gcry_cipher_setkey(cfx->cipher_hd, cfx->dek->key, cfx->dek->keylen);
  gcry_cipher_setiv(cfx->cipher_hd, NULL, 0);
  /*  log_hexdump( "prefix", temp, nprefix+2 ); */
  if (cfx->mdc_hash) /* Hash the "IV". */
    cfx->mdc_hash->update(temp, nprefix + 2);
  gcry_cipher_encrypt(cfx->cipher_hd, temp, nprefix + 2, NULL, 0);
  gcry_cipher_sync(cfx->cipher_hd);
  iobuf_write(a, temp, nprefix + 2);
  cfx->header = 1;
}

/****************
 * This filter is used to en/de-cipher data with a conventional algorithm
 */
int cipher_filter(void *opaque, int control, IOBUF a, byte *buf,
                  size_t *ret_len) {
  size_t size = *ret_len;
  cipher_filter_context_t *cfx = (cipher_filter_context_t *)opaque;
  int rc = 0;

  if (control == IOBUFCTRL_UNDERFLOW) {    /* decrypt */
    rc = -1;                               /* not yet used */
  } else if (control == IOBUFCTRL_FLUSH) { /* encrypt */
    log_assert(a);
    if (!cfx->header) {
      write_header(cfx, a);
    }
    if (cfx->mdc_hash) cfx->mdc_hash->update(buf, size);
    gcry_cipher_encrypt(cfx->cipher_hd, buf, size, NULL, 0);
    rc = iobuf_write(a, buf, size);
  } else if (control == IOBUFCTRL_FREE) {
    if (cfx->mdc_hash) {
      byte temp[22];

      /* We must hash the prefix of the MDC packet here. */
      temp[0] = 0xd3;
      temp[1] = 0x14;
      cfx->mdc_hash->update(temp, 2);

      std::vector<uint8_t> hash = cfx->mdc_hash->final_stdvec();
      memcpy(temp + 2, hash.data(), 20);
      gcry_cipher_encrypt(cfx->cipher_hd, temp, 22, NULL, 0);
      cfx->mdc_hash = nullptr;
      if (iobuf_write(a, temp, 22)) log_error("writing MDC packet failed\n");
    }
    gcry_cipher_close(cfx->cipher_hd);
  } else if (control == IOBUFCTRL_DESC) {
    mem2str((char *)(buf), "cipher_filter", *ret_len);
  }
  return rc;
}
