/* socks5.c - Check the SOCKS5 client feature
 * Copyright (C) 2015 g10 Code GmbH
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
#endif /*!HAVE_W32_SYSTEM*/

#include "../src/assuan.h"
#include "common.h"


/*

     M A I N

*/
int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpg_error_t err;
  int only_v6 = 0;
  int only_v4 = 0;
  int use_tor = 0;
  int opt_have_proxy = 0;
  int disable_socks = 0;
  int opt_byname = 0;
  const char *user = NULL;
  const char *pass = NULL;
  assuan_fd_t sock = ASSUAN_INVALID_FD;
  estream_t infp, outfp;
  int c;
  int lf_seen;

  gpgrt_init ();
  if (argc)
    {
      log_set_prefix (*argv);
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          puts (
                "usage: ./socks5 [options] HOST PORT\n"
                "\n"
                "Options:\n"
                "  --verbose        Show what is going on\n"
                "  --use-tor        Use port 9050 instead of 1080\n"
                "  --inet6-only     Use only IPv6\n"
                "  --inet4-only     Use only IPv4\n"
                "  --disable-socks  Connect w/o SOCKS\n"
                "  --have-proxy     Check whether the proxy is available\n"
                "  --byname         Use assuan_sock_connect_byname\n"
                "  --user STRING    Use STRING as user for authentication\n"
                "  --pass STRING    Use STRING as password for authentication\n"
                );
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "-6") || !strcmp (*argv, "--inet6-only"))
        {
          only_v6 = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "-4") || !strcmp (*argv, "--inet4-only"))
        {
          only_v4 = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--use-tor"))
        {
          use_tor = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--disable-socks"))
        {
          disable_socks = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--byname"))
        {
          opt_byname = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--have-proxy"))
        {
          opt_have_proxy = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--user"))
        {
          argc--; argv++;
          if (argc)
            {
              user = *argv;
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "--pass"))
        {
          argc--; argv++;
          if (argc)
            {
              pass = *argv;
              argc--; argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        {
          log_error ("unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (argc != 2 && !opt_have_proxy)
    {
      fputs ("usage: socks5 HOST PORT\n", stderr);
      exit (1);
    }

  assuan_set_assuan_log_prefix (log_prefix);

  if (!assuan_check_version (ASSUAN_VERSION))
    log_error ("assuan_check_version returned an error\n");

  assuan_sock_init ();

  if (!disable_socks
      && assuan_sock_set_flag (ASSUAN_INVALID_FD,
                               use_tor? "tor-mode":"socks", 1))
    {
      err = gpg_error_from_syserror ();
      log_fatal ("setting %s mode failed: %s\n",
                 use_tor? "TOR": "SOCKS", gpg_strerror (err));
    }

  if (opt_have_proxy)
    {
      char *cred;

      if (user || pass)
        cred = xstrconcat (user?user:"", ":", pass, NULL);
      else
        cred = NULL;

      sock = assuan_sock_connect_byname
        (NULL, 0, 0, cred, use_tor? ASSUAN_SOCK_TOR : ASSUAN_SOCK_SOCKS);
      if (sock == ASSUAN_INVALID_FD)
        {
          err = gpg_error_from_syserror ();
          log_error ("SOCKS proxy is not available (%s)\n", gpg_strerror (err));
          exit (1);
        }
      xfree (cred);
      assuan_sock_close (sock);
      if (verbose)
        log_info ("SOCKS proxy available\n");
      exit (0);
    }
  else if (opt_byname)
    {
      unsigned short port;
      char *cred;

      if (user || pass)
        cred = xstrconcat (user?user:"", ":", pass, NULL);
      else
        cred = NULL;

      port = strtoul (argv[1], NULL, 10);
      if (port < 0 || port > 65535)
        log_fatal ("port number out of range\n");

      sock = assuan_sock_connect_byname (argv[0], port, 0, cred,
                                         ASSUAN_SOCK_TOR);
      if (sock == ASSUAN_INVALID_FD)
        {
          err = gpg_error_from_syserror ();
          log_error ("assuan_sock_connect_byname (%s) failed: %s\n",
                     argv[0], gpg_strerror (err));
          exit (1);
        }
      xfree (cred);
    }
  else
    {
#ifdef HAVE_GETADDRINFO
      struct addrinfo hints, *res, *ai;
      int ret;
      int anyok = 0;

      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_STREAM;
      ret = getaddrinfo (argv[0], argv[1], &hints, &res);
      if (ret)
        {
          log_error ("error resolving '%s': %s\n", argv[0], gai_strerror (ret));
          exit (1);
        }

      for (ai = res; ai; ai = ai->ai_next)
        {
          if (ai->ai_family == AF_INET && only_v6)
            continue;
          if (ai->ai_family == AF_INET6 && only_v4)
            continue;

          if (sock != ASSUAN_INVALID_FD)
            assuan_sock_close (sock);
          sock = assuan_sock_new (ai->ai_family, ai->ai_socktype,
                                  ai->ai_protocol);
          if (sock == ASSUAN_INVALID_FD)
            {
              err = gpg_error_from_syserror ();
              log_error ("error creating socket: %s\n", gpg_strerror (err));
              freeaddrinfo (res);
              exit (1);
            }

          if (assuan_sock_connect (sock,  ai->ai_addr, ai->ai_addrlen))
            {
              err = gpg_error_from_syserror ();
              log_error ("assuan_sock_connect (%s) failed: %s\n",
                         ai->ai_family == AF_INET6? "v6" :
                         ai->ai_family == AF_INET ? "v4" : "?",
                         gpg_strerror (err));
            }
          else
            {
              log_info ("assuan_sock_connect succeeded (%s)\n",
                        ai->ai_family == AF_INET6? "v6" :
                        ai->ai_family == AF_INET ? "v4" : "?");
              anyok = 1;
              break;
            }
        }
      freeaddrinfo (res);
      if (!anyok)
        exit (1);
#else /*!HAVE_GETADDRINFO*/
      (void)only_v4;
      (void)only_v6;
      fputs ("socks5: getaddrinfo not supported\n", stderr);
      exit (77); /* Skip test.  */
#endif /*!HAVE_GETADDRINFO*/
    }

  infp = es_fdopen_nc (sock, "rb");
  if (!infp)
    {
      err = gpg_error_from_syserror ();
      assuan_sock_close (sock);
      log_fatal ("opening inbound stream failed: %s\n", gpg_strerror (err));
    }
  outfp = es_fdopen (sock, "wb");
  if (!outfp)
    {
      err = gpg_error_from_syserror ();
      es_fclose (infp);
      assuan_sock_close (sock);
      log_fatal ("opening outbound stream failed: %s\n", gpg_strerror (err));
    }
  es_fputs ("GET / HTTP/1.0\r\n\r\n", outfp);
  if (es_fflush (outfp))
    {
      err = gpg_error_from_syserror ();
      log_error ("es_fflush failed: %s\n", gpg_strerror (err));
    }
  lf_seen = 0;
  while ((c = es_fgetc (infp)) != EOF)
    {
      if (c == '\r')
        continue;
      putchar (c);
      if (c == '\n')
        {
          if (lf_seen)
            break;
          lf_seen = 1;
        }
      else
        lf_seen = 0;
    }
  if (es_ferror (infp))
    {
      err = gpg_error_from_syserror ();
      log_error ("es_fgetc failed: %s\n", gpg_strerror (err));
    }
  es_fclose (infp);
  es_fclose (outfp);

  return errorcount ? 1 : 0;
}
