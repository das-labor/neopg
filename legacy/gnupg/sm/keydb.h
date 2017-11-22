/* keydb.h - Key database
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

#ifndef GNUPG_KEYDB_H
#define GNUPG_KEYDB_H

#include <ksba.h>

#include "../common/userids.h"

typedef struct keydb_handle *KEYDB_HANDLE;

/* Flag value used with KEYBOX_FLAG_VALIDITY. */
#define VALIDITY_REVOKED (1 << 5)

/*-- keydb.c --*/
gpg_error_t sm_keydb_add_resource(ctrl_t ctrl, const char *url, int force,
                                  int *auto_created);
KEYDB_HANDLE sm_keydb_new(void);
void sm_keydb_release(KEYDB_HANDLE hd);
int sm_keydb_set_ephemeral(KEYDB_HANDLE hd, int yes);
const char *sm_keydb_get_resource_name(KEYDB_HANDLE hd);
gpg_error_t sm_keydb_lock(KEYDB_HANDLE hd);

gpg_error_t sm_keydb_get_flags(KEYDB_HANDLE hd, int which, int idx,
                               unsigned int *value);
gpg_error_t sm_keydb_set_flags(KEYDB_HANDLE hd, int which, int idx,
                               unsigned int value);
void sm_keydb_push_found_state(KEYDB_HANDLE hd);
void sm_keydb_pop_found_state(KEYDB_HANDLE hd);
int sm_keydb_get_cert(KEYDB_HANDLE hd, ksba_cert_t *r_cert);
int sm_keydb_insert_cert(KEYDB_HANDLE hd, ksba_cert_t cert);
int sm_keydb_update_cert(KEYDB_HANDLE hd, ksba_cert_t cert);

int sm_keydb_delete(KEYDB_HANDLE hd, int unlock);

int sm_keydb_locate_writable(KEYDB_HANDLE hd, const char *reserved);

gpg_error_t sm_keydb_search_reset(KEYDB_HANDLE hd);
int sm_keydb_search(ctrl_t ctrl, KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                    size_t ndesc);
int sm_keydb_search_first(ctrl_t ctrl, KEYDB_HANDLE hd);
int sm_keydb_search_next(ctrl_t ctrl, KEYDB_HANDLE hd);
int sm_keydb_search_kid(ctrl_t ctrl, KEYDB_HANDLE hd, u32 *kid);
int sm_keydb_search_fpr(ctrl_t ctrl, KEYDB_HANDLE hd, const byte *fpr);
int sm_keydb_search_issuer(ctrl_t ctrl, KEYDB_HANDLE hd, const char *issuer);
int sm_keydb_search_issuer_sn(ctrl_t ctrl, KEYDB_HANDLE hd, const char *issuer,
                              const unsigned char *serial);
int sm_keydb_search_subject(ctrl_t ctrl, KEYDB_HANDLE hd, const char *issuer);

int sm_keydb_store_cert(ctrl_t ctrl, ksba_cert_t cert, int ephemeral,
                        int *existed);
gpg_error_t sm_keydb_set_cert_flags(ctrl_t ctrl, ksba_cert_t cert,
                                    int ephemeral, int which, int idx,
                                    unsigned int mask, unsigned int value);

void sm_keydb_clear_some_cert_flags(ctrl_t ctrl, strlist_t names);

#endif /*GNUPG_KEYDB_H*/
