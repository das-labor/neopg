/* convert.h
 * Copyright (C) 2001, 2012 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
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
 * KSBA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CONVERT_H
#define CONVERT_H

#include "asn1-func.h"

/*-- time.c --*/
gpg_error_t _ksba_asntime_to_iso (const char *buffer, size_t length,
                                  int is_utctime, ksba_isotime_t timebuf);
gpg_error_t _ksba_assert_time_format (const ksba_isotime_t atime);
void _ksba_copy_time (ksba_isotime_t d, const ksba_isotime_t s);
int _ksba_cmp_time (const ksba_isotime_t a, const ksba_isotime_t b);
void _ksba_current_time (ksba_isotime_t timebuf);


/*-- dn.c --*/
gpg_error_t _ksba_dn_to_str (const unsigned char *image, AsnNode node,
                           char **r_string);
gpg_error_t _ksba_derdn_to_str (const unsigned char *der, size_t derlen,
                              char **r_string);
gpg_error_t _ksba_dn_from_str (const char *string, char **rbuf, size_t *rlength);

/*-- oid.c --*/
char *_ksba_oid_node_to_str (const unsigned char *image, AsnNode node);
gpg_error_t _ksba_oid_from_buf (const void *buffer, size_t buflen,
                                unsigned char **rbuf, size_t *rlength);


/*-- name.c --*/
gpg_error_t _ksba_name_new_from_der (ksba_name_t *r_name,
                                     const unsigned char *image,
                                     size_t imagelen);


#endif /*CONVERT_H*/
