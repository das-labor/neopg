/* utf8conf.h
 *	Copyright (C) 2003, 2006 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_UTF8CONF_H
#define GNUPG_COMMON_UTF8CONF_H

#include <string>

int set_native_charset(const char *newset);
const char *get_native_charset(void);
int is_native_utf8(void);

std::string native_to_utf8(const std::string &string);
std::string utf8_to_native(const char *string, size_t length, int delim);

#ifdef HAVE_W32_SYSTEM
char *wchar_to_native(const wchar_t *string);
wchar_t *native_to_wchar(const char *string);
char *wchar_to_utf8(const wchar_t *string);
wchar_t *utf8_to_wchar(const char *string);
#endif /*HAVE_W32_SYSTEM*/

#endif /*GNUPG_COMMON_UTF8CONF_H*/
