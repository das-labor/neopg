/* mischelp.h - Miscellaneous helper macros and functions
 * Copyright (C) 1999, 2000, 2001, 2002, 2003,
 *               2006, 2007, 2009  Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_MISCHELP_H
#define GNUPG_COMMON_MISCHELP_H

#define DIM(v) (sizeof(v) / sizeof((v)[0]))
#define DIMof(type, member) DIM(((type *)0)->member)

/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#define wipememory2(_ptr, _set, _len)               \
  do {                                              \
    volatile char *_vptr = (volatile char *)(_ptr); \
    size_t _vlen = (size_t)(_len);                  \
    while (_vlen) {                                 \
      *_vptr = (_set);                              \
      _vptr++;                                      \
      _vlen--;                                      \
    }                                               \
  } while (0)
#define wipememory(_ptr, _len) wipememory2(_ptr, 0, _len)

#ifndef SUN_LEN
#define SUN_LEN(ptr) \
  ((size_t)(((struct sockaddr_un *)0)->sun_path) + strlen((ptr)->sun_path))
#endif /*SUN_LEN*/

#endif /*GNUPG_COMMON_MISCHELP_H*/
