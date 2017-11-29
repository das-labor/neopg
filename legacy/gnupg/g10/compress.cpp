/* compress.c - compress filter
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2003, 2006, 2010 Free Software Foundation, Inc.
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

/* Note that the code in compress-bz2.c is nearly identical to the
   code here, so if you fix a bug here, look there to see if a
   matching bug needs to be fixed.  I tried to have one set of
   functions that could do ZIP, ZLIB, and BZIP2, but it became
   dangerously unreadable with #ifdefs and if(algo) -dshaw */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <map>

#include <botan/compression.h>

#include "../common/util.h"
#include "filter.h"
#include "gpg.h"
#include "main.h"
#include "options.h"
#include "packet.h"

const std::map<int, std::string> algo_to_spec{{COMPRESS_ALGO_ZIP, "deflate"},
                                              {COMPRESS_ALGO_ZLIB, "zlib"},
                                              {COMPRESS_ALGO_BZIP2, "bz2"}};

int compress_filter(void *opaque, int control, IOBUF a, byte *buf,
                    size_t *ret_len) {
  size_t size = *ret_len;
  compress_filter_context_t *zfx = (compress_filter_context_t *)opaque;
  int rc = 0;

  if (control == IOBUFCTRL_UNDERFLOW) {
    if (!zfx->status) {
      /* We just found out we are used as a decompressor.  */
      std::string algo = algo_to_spec.at(zfx->algo);
      auto decompressor = Botan::make_decompressor(algo);
      auto input = new Botan::secure_vector<uint8_t>;
      zfx->opaque =
          new std::pair<Botan::Decompression_Algorithm *,
                        Botan::secure_vector<uint8_t> *>(decompressor, input);
      decompressor->start();
      zfx->status = 1;
    }
    auto *opaque_ = (std::pair<Botan::Decompression_Algorithm *,
                               Botan::secure_vector<uint8_t> *> *)zfx->opaque;
    auto decompressor = opaque_->first;
    auto input = opaque_->second;
    while (input->empty() && decompressor) {
      input->resize(2048);
      int nread = iobuf_read(a, input->data(), input->size());
      if (nread <= 0) {
        input->clear();
        decompressor->finish(*input);
        delete decompressor;
        decompressor = nullptr;
        opaque_->first = nullptr;
      } else {
        input->resize(nread);
        decompressor->update(*input);
      }
    }
    if (!input->empty()) {
      size_t amount = std::min(input->size(), size);
      memcpy(buf, input->data(), amount);
      *ret_len = amount;
      input->erase(input->begin(), input->begin() + amount);
    } else {
      *ret_len = 0;
      rc = -1;
    }
  } else if (control == IOBUFCTRL_FLUSH) {
    if (!zfx->status) {
      PACKET pkt;
      PKT_compressed cd;

      memset(&cd, 0, sizeof cd);
      cd.len = 0;
      cd.algorithm = zfx->algo;
      init_packet(&pkt);
      pkt.pkttype = PKT_COMPRESSED;
      pkt.pkt.compressed = &cd;
      if (build_packet(a, &pkt))
        log_bug("build_packet(PKT_COMPRESSED) failed\n");
      std::string algo = algo_to_spec.at(zfx->algo);
      zfx->opaque = Botan::make_compressor(algo);
      auto compression = (Botan::Compression_Algorithm *)zfx->opaque;
      compression->start(0);  // compression level: default
      zfx->status = 2;
    }

    Botan::secure_vector<uint8_t> input(size);
    memcpy(input.data(), buf, size);
    auto compression = (Botan::Compression_Algorithm *)zfx->opaque;
    compression->update(input, 0, false);
    if ((rc = iobuf_write(a, input.data(), input.size()))) {
      log_debug("bzCompress: iobuf_write failed\n");
      return rc;
    }
  } else if (control == IOBUFCTRL_FREE) {
    if (zfx->status == 1) {
      auto opaque_ = (std::pair<Botan::Decompression_Algorithm *,
                                Botan::secure_vector<uint8_t> *> *)zfx->opaque;
      auto decompressor = opaque_->first;
      auto input = opaque_->second;
      if (decompressor) delete decompressor;
      delete input;
      delete opaque_;
      zfx->opaque = NULL;
    } else if (zfx->status == 2) {
      Botan::secure_vector<uint8_t> input;
      auto compression = (Botan::Compression_Algorithm *)zfx->opaque;

      compression->update(input, 0, true);
      if ((rc = iobuf_write(a, input.data(), input.size()))) {
        log_debug("bzCompress: iobuf_write failed\n");
        return rc;
      }

      input.clear();
      compression->finish(input, 0);
      if ((rc = iobuf_write(a, input.data(), input.size()))) {
        log_debug("bzCompress: iobuf_write failed\n");
        return rc;
      }

      delete compression;
      zfx->opaque = NULL;
    }
    if (zfx->release) zfx->release(zfx);
  } else if (control == IOBUFCTRL_DESC)
    mem2str((char *)(buf), "compress_filter", *ret_len);
  return rc;
}

static void release_context(compress_filter_context_t *ctx) { xfree(ctx); }

/****************
 * Handle a compressed packet
 */
int handle_compressed(ctrl_t ctrl, void *procctx, PKT_compressed *cd,
                      int (*callback)(IOBUF, void *), void *passthru) {
  compress_filter_context_t *cfx;
  int rc;

  if (check_compress_algo(cd->algorithm)) return GPG_ERR_COMPR_ALGO;
  cfx = (compress_filter_context_t *)xmalloc_clear(sizeof *cfx);
  cfx->release = release_context;
  cfx->algo = cd->algorithm;
  push_compress_filter(cd->buf, cfx, cd->algorithm);
  if (callback)
    rc = callback(cd->buf, passthru);
  else
    rc = proc_packets(ctrl, procctx, cd->buf);
  cd->buf = NULL;
  return rc;
}

void push_compress_filter(IOBUF out, compress_filter_context_t *zfx, int algo) {
  push_compress_filter2(out, zfx, algo, 0);
}

void push_compress_filter2(IOBUF out, compress_filter_context_t *zfx, int algo,
                           int rel) {
  if (algo >= 0)
    zfx->algo = algo;
  else
    zfx->algo = DEFAULT_COMPRESS_ALGO;

  switch (zfx->algo) {
    case COMPRESS_ALGO_NONE:
      break;

    case COMPRESS_ALGO_ZIP:
    case COMPRESS_ALGO_ZLIB:
    case COMPRESS_ALGO_BZIP2:
      iobuf_push_filter2(out, compress_filter, zfx, rel);
      break;

    default:
      BUG();
  }
}
