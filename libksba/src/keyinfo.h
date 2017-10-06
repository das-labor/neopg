/* keyinfo.h - Parse and build a keyInfo structure
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

#ifndef KEYINFO_H
#define KEYINFO_H

#include "asn1-func.h"


gpg_error_t
_ksba_parse_algorithm_identifier (const unsigned char *der,
                                  size_t derlen,
                                  size_t *r_nread,
                                  char **r_oid);
gpg_error_t
_ksba_parse_algorithm_identifier2 (const unsigned char *der, size_t derlen,
                                   size_t *r_nread, char **r_oid,
                                   char **r_parm, size_t *r_parmlen);


gpg_error_t _ksba_keyinfo_to_sexp (const unsigned char *der, size_t derlen,
                                   ksba_sexp_t *r_string)
     _KSBA_VISIBILITY_DEFAULT;

gpg_error_t _ksba_keyinfo_from_sexp (ksba_const_sexp_t sexp,
                                     unsigned char **r_der, size_t *r_derlen)
     _KSBA_VISIBILITY_DEFAULT;

gpg_error_t _ksba_algoinfo_from_sexp (ksba_const_sexp_t sexp,
                                      unsigned char **r_der, size_t *r_derlen);

gpg_error_t _ksba_sigval_to_sexp (const unsigned char *der, size_t derlen,
                                ksba_sexp_t *r_string);
gpg_error_t _ksba_encval_to_sexp (const unsigned char *der, size_t derlen,
                                ksba_sexp_t *r_string);

int _ksba_node_with_oid_to_digest_algo (const unsigned char *image,
                                        AsnNode node);



#endif /*KEYINFO_H*/
