/* passphrase.c -  Get a passphrase
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2006, 2007, 2009, 2011 Free Software Foundation, Inc.
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
#include <unistd.h>

#include "../common/ttyio.h"
#include "gpgsm.h"
#include "passphrase.h"

static std::unique_ptr<Botan::secure_vector<char>> fd_passwd;

int sm_have_static_passphrase() { return !!fd_passwd; }

/* Return a static passphrase.  The returned value is only valid as
   long as no other passphrase related function is called.  NULL may
   be returned if no passphrase has been set; better use
   have_static_passphrase first.  */
const char *sm_get_static_passphrase(void) {
  if (!fd_passwd)
    return NULL;
  else
    return fd_passwd->data();
}

void sm_read_passphrase_from_fd(int fd) {
  int i, len;

  auto pw = std::unique_ptr<Botan::secure_vector<char>>(
      new Botan::secure_vector<char>);
  while (true) {
    char next;
    int res;
    res = read(fd, &next, 1);
    if (res != 1 || next == '\n') break;
    pw->push_back(next);
  }
  /* Build a C string.  */
  pw->push_back(0);
  fd_passwd = std::move(pw);
}
