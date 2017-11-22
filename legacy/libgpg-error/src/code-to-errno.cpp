/* code-to-errno.c - Mapping error codes to errnos.
   Copyright (C) 2003 g10 Code GmbH

   This file is part of libgpg-error.

   libgpg-error is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   libgpg-error is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with libgpg-error; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>

#include <gpg-error.h>

static int code_to_errno(gpg_error_t code) {
  switch (code) {
    case GPG_ERR_E2BIG:
#ifdef E2BIG
      return E2BIG;
#else
#ifdef WSAE2BIG
      return WSAE2BIG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EACCES:
#ifdef EACCES
      return EACCES;
#else
#ifdef WSAEACCES
      return WSAEACCES;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EADDRINUSE:
#ifdef EADDRINUSE
      return EADDRINUSE;
#else
#ifdef WSAEADDRINUSE
      return WSAEADDRINUSE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EADDRNOTAVAIL:
#ifdef EADDRNOTAVAIL
      return EADDRNOTAVAIL;
#else
#ifdef WSAEADDRNOTAVAIL
      return WSAEADDRNOTAVAIL;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EADV:
#ifdef EADV
      return EADV;
#else
#ifdef WSAEADV
      return WSAEADV;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EAFNOSUPPORT:
#ifdef EAFNOSUPPORT
      return EAFNOSUPPORT;
#else
#ifdef WSAEAFNOSUPPORT
      return WSAEAFNOSUPPORT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EAGAIN:
#ifdef EAGAIN
      return EAGAIN;
#else
#ifdef WSAEAGAIN
      return WSAEAGAIN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EALREADY:
#ifdef EALREADY
      return EALREADY;
#else
#ifdef WSAEALREADY
      return WSAEALREADY;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EAUTH:
#ifdef EAUTH
      return EAUTH;
#else
#ifdef WSAEAUTH
      return WSAEAUTH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBACKGROUND:
#ifdef EBACKGROUND
      return EBACKGROUND;
#else
#ifdef WSAEBACKGROUND
      return WSAEBACKGROUND;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADE:
#ifdef EBADE
      return EBADE;
#else
#ifdef WSAEBADE
      return WSAEBADE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADF:
#ifdef EBADF
      return EBADF;
#else
#ifdef WSAEBADF
      return WSAEBADF;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADFD:
#ifdef EBADFD
      return EBADFD;
#else
#ifdef WSAEBADFD
      return WSAEBADFD;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADMSG:
#ifdef EBADMSG
      return EBADMSG;
#else
#ifdef WSAEBADMSG
      return WSAEBADMSG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADR:
#ifdef EBADR
      return EBADR;
#else
#ifdef WSAEBADR
      return WSAEBADR;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADRPC:
#ifdef EBADRPC
      return EBADRPC;
#else
#ifdef WSAEBADRPC
      return WSAEBADRPC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADRQC:
#ifdef EBADRQC
      return EBADRQC;
#else
#ifdef WSAEBADRQC
      return WSAEBADRQC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBADSLT:
#ifdef EBADSLT
      return EBADSLT;
#else
#ifdef WSAEBADSLT
      return WSAEBADSLT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBFONT:
#ifdef EBFONT
      return EBFONT;
#else
#ifdef WSAEBFONT
      return WSAEBFONT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EBUSY:
#ifdef EBUSY
      return EBUSY;
#else
#ifdef WSAEBUSY
      return WSAEBUSY;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECANCELED:
#ifdef ECANCELED
      return ECANCELED;
#else
#ifdef WSAECANCELED
      return WSAECANCELED;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECHILD:
#ifdef ECHILD
      return ECHILD;
#else
#ifdef WSAECHILD
      return WSAECHILD;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECHRNG:
#ifdef ECHRNG
      return ECHRNG;
#else
#ifdef WSAECHRNG
      return WSAECHRNG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECOMM:
#ifdef ECOMM
      return ECOMM;
#else
#ifdef WSAECOMM
      return WSAECOMM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECONNABORTED:
#ifdef ECONNABORTED
      return ECONNABORTED;
#else
#ifdef WSAECONNABORTED
      return WSAECONNABORTED;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECONNREFUSED:
#ifdef ECONNREFUSED
      return ECONNREFUSED;
#else
#ifdef WSAECONNREFUSED
      return WSAECONNREFUSED;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ECONNRESET:
#ifdef ECONNRESET
      return ECONNRESET;
#else
#ifdef WSAECONNRESET
      return WSAECONNRESET;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ED:
#ifdef ED
      return ED;
#else
#ifdef WSAED
      return WSAED;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDEADLK:
#ifdef EDEADLK
      return EDEADLK;
#else
#ifdef WSAEDEADLK
      return WSAEDEADLK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDEADLOCK:
#ifdef EDEADLOCK
      return EDEADLOCK;
#else
#ifdef WSAEDEADLOCK
      return WSAEDEADLOCK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDESTADDRREQ:
#ifdef EDESTADDRREQ
      return EDESTADDRREQ;
#else
#ifdef WSAEDESTADDRREQ
      return WSAEDESTADDRREQ;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDIED:
#ifdef EDIED
      return EDIED;
#else
#ifdef WSAEDIED
      return WSAEDIED;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDOM:
#ifdef EDOM
      return EDOM;
#else
#ifdef WSAEDOM
      return WSAEDOM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDOTDOT:
#ifdef EDOTDOT
      return EDOTDOT;
#else
#ifdef WSAEDOTDOT
      return WSAEDOTDOT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EDQUOT:
#ifdef EDQUOT
      return EDQUOT;
#else
#ifdef WSAEDQUOT
      return WSAEDQUOT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EEXIST:
#ifdef EEXIST
      return EEXIST;
#else
#ifdef WSAEEXIST
      return WSAEEXIST;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EFAULT:
#ifdef EFAULT
      return EFAULT;
#else
#ifdef WSAEFAULT
      return WSAEFAULT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EFBIG:
#ifdef EFBIG
      return EFBIG;
#else
#ifdef WSAEFBIG
      return WSAEFBIG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EFTYPE:
#ifdef EFTYPE
      return EFTYPE;
#else
#ifdef WSAEFTYPE
      return WSAEFTYPE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EGRATUITOUS:
#ifdef EGRATUITOUS
      return EGRATUITOUS;
#else
#ifdef WSAEGRATUITOUS
      return WSAEGRATUITOUS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EGREGIOUS:
#ifdef EGREGIOUS
      return EGREGIOUS;
#else
#ifdef WSAEGREGIOUS
      return WSAEGREGIOUS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EHOSTDOWN:
#ifdef EHOSTDOWN
      return EHOSTDOWN;
#else
#ifdef WSAEHOSTDOWN
      return WSAEHOSTDOWN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EHOSTUNREACH:
#ifdef EHOSTUNREACH
      return EHOSTUNREACH;
#else
#ifdef WSAEHOSTUNREACH
      return WSAEHOSTUNREACH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EIDRM:
#ifdef EIDRM
      return EIDRM;
#else
#ifdef WSAEIDRM
      return WSAEIDRM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EIEIO:
#ifdef EIEIO
      return EIEIO;
#else
#ifdef WSAEIEIO
      return WSAEIEIO;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EILSEQ:
#ifdef EILSEQ
      return EILSEQ;
#else
#ifdef WSAEILSEQ
      return WSAEILSEQ;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EINPROGRESS:
#ifdef EINPROGRESS
      return EINPROGRESS;
#else
#ifdef WSAEINPROGRESS
      return WSAEINPROGRESS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EINTR:
#ifdef EINTR
      return EINTR;
#else
#ifdef WSAEINTR
      return WSAEINTR;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EINVAL:
#ifdef EINVAL
      return EINVAL;
#else
#ifdef WSAEINVAL
      return WSAEINVAL;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EIO:
#ifdef EIO
      return EIO;
#else
#ifdef WSAEIO
      return WSAEIO;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EISCONN:
#ifdef EISCONN
      return EISCONN;
#else
#ifdef WSAEISCONN
      return WSAEISCONN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EISDIR:
#ifdef EISDIR
      return EISDIR;
#else
#ifdef WSAEISDIR
      return WSAEISDIR;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EISNAM:
#ifdef EISNAM
      return EISNAM;
#else
#ifdef WSAEISNAM
      return WSAEISNAM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EL2HLT:
#ifdef EL2HLT
      return EL2HLT;
#else
#ifdef WSAEL2HLT
      return WSAEL2HLT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EL2NSYNC:
#ifdef EL2NSYNC
      return EL2NSYNC;
#else
#ifdef WSAEL2NSYNC
      return WSAEL2NSYNC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EL3HLT:
#ifdef EL3HLT
      return EL3HLT;
#else
#ifdef WSAEL3HLT
      return WSAEL3HLT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EL3RST:
#ifdef EL3RST
      return EL3RST;
#else
#ifdef WSAEL3RST
      return WSAEL3RST;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELIBACC:
#ifdef ELIBACC
      return ELIBACC;
#else
#ifdef WSAELIBACC
      return WSAELIBACC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELIBBAD:
#ifdef ELIBBAD
      return ELIBBAD;
#else
#ifdef WSAELIBBAD
      return WSAELIBBAD;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELIBEXEC:
#ifdef ELIBEXEC
      return ELIBEXEC;
#else
#ifdef WSAELIBEXEC
      return WSAELIBEXEC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELIBMAX:
#ifdef ELIBMAX
      return ELIBMAX;
#else
#ifdef WSAELIBMAX
      return WSAELIBMAX;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELIBSCN:
#ifdef ELIBSCN
      return ELIBSCN;
#else
#ifdef WSAELIBSCN
      return WSAELIBSCN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELNRNG:
#ifdef ELNRNG
      return ELNRNG;
#else
#ifdef WSAELNRNG
      return WSAELNRNG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ELOOP:
#ifdef ELOOP
      return ELOOP;
#else
#ifdef WSAELOOP
      return WSAELOOP;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EMEDIUMTYPE:
#ifdef EMEDIUMTYPE
      return EMEDIUMTYPE;
#else
#ifdef WSAEMEDIUMTYPE
      return WSAEMEDIUMTYPE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EMFILE:
#ifdef EMFILE
      return EMFILE;
#else
#ifdef WSAEMFILE
      return WSAEMFILE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EMLINK:
#ifdef EMLINK
      return EMLINK;
#else
#ifdef WSAEMLINK
      return WSAEMLINK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EMSGSIZE:
#ifdef EMSGSIZE
      return EMSGSIZE;
#else
#ifdef WSAEMSGSIZE
      return WSAEMSGSIZE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EMULTIHOP:
#ifdef EMULTIHOP
      return EMULTIHOP;
#else
#ifdef WSAEMULTIHOP
      return WSAEMULTIHOP;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENAMETOOLONG:
#ifdef ENAMETOOLONG
      return ENAMETOOLONG;
#else
#ifdef WSAENAMETOOLONG
      return WSAENAMETOOLONG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENAVAIL:
#ifdef ENAVAIL
      return ENAVAIL;
#else
#ifdef WSAENAVAIL
      return WSAENAVAIL;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENEEDAUTH:
#ifdef ENEEDAUTH
      return ENEEDAUTH;
#else
#ifdef WSAENEEDAUTH
      return WSAENEEDAUTH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENETDOWN:
#ifdef ENETDOWN
      return ENETDOWN;
#else
#ifdef WSAENETDOWN
      return WSAENETDOWN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENETRESET:
#ifdef ENETRESET
      return ENETRESET;
#else
#ifdef WSAENETRESET
      return WSAENETRESET;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENETUNREACH:
#ifdef ENETUNREACH
      return ENETUNREACH;
#else
#ifdef WSAENETUNREACH
      return WSAENETUNREACH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENFILE:
#ifdef ENFILE
      return ENFILE;
#else
#ifdef WSAENFILE
      return WSAENFILE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOANO:
#ifdef ENOANO
      return ENOANO;
#else
#ifdef WSAENOANO
      return WSAENOANO;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOBUFS:
#ifdef ENOBUFS
      return ENOBUFS;
#else
#ifdef WSAENOBUFS
      return WSAENOBUFS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOCSI:
#ifdef ENOCSI
      return ENOCSI;
#else
#ifdef WSAENOCSI
      return WSAENOCSI;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENODATA:
#ifdef ENODATA
      return ENODATA;
#else
#ifdef WSAENODATA
      return WSAENODATA;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENODEV:
#ifdef ENODEV
      return ENODEV;
#else
#ifdef WSAENODEV
      return WSAENODEV;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOENT:
#ifdef ENOENT
      return ENOENT;
#else
#ifdef WSAENOENT
      return WSAENOENT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOEXEC:
#ifdef ENOEXEC
      return ENOEXEC;
#else
#ifdef WSAENOEXEC
      return WSAENOEXEC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOLCK:
#ifdef ENOLCK
      return ENOLCK;
#else
#ifdef WSAENOLCK
      return WSAENOLCK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOLINK:
#ifdef ENOLINK
      return ENOLINK;
#else
#ifdef WSAENOLINK
      return WSAENOLINK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOMEDIUM:
#ifdef ENOMEDIUM
      return ENOMEDIUM;
#else
#ifdef WSAENOMEDIUM
      return WSAENOMEDIUM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOMEM:
#ifdef ENOMEM
      return ENOMEM;
#else
#ifdef WSAENOMEM
      return WSAENOMEM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOMSG:
#ifdef ENOMSG
      return ENOMSG;
#else
#ifdef WSAENOMSG
      return WSAENOMSG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENONET:
#ifdef ENONET
      return ENONET;
#else
#ifdef WSAENONET
      return WSAENONET;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOPKG:
#ifdef ENOPKG
      return ENOPKG;
#else
#ifdef WSAENOPKG
      return WSAENOPKG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOPROTOOPT:
#ifdef ENOPROTOOPT
      return ENOPROTOOPT;
#else
#ifdef WSAENOPROTOOPT
      return WSAENOPROTOOPT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOSPC:
#ifdef ENOSPC
      return ENOSPC;
#else
#ifdef WSAENOSPC
      return WSAENOSPC;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOSR:
#ifdef ENOSR
      return ENOSR;
#else
#ifdef WSAENOSR
      return WSAENOSR;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOSTR:
#ifdef ENOSTR
      return ENOSTR;
#else
#ifdef WSAENOSTR
      return WSAENOSTR;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOSYS:
#ifdef ENOSYS
      return ENOSYS;
#else
#ifdef WSAENOSYS
      return WSAENOSYS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTBLK:
#ifdef ENOTBLK
      return ENOTBLK;
#else
#ifdef WSAENOTBLK
      return WSAENOTBLK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTCONN:
#ifdef ENOTCONN
      return ENOTCONN;
#else
#ifdef WSAENOTCONN
      return WSAENOTCONN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTDIR:
#ifdef ENOTDIR
      return ENOTDIR;
#else
#ifdef WSAENOTDIR
      return WSAENOTDIR;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTEMPTY:
#ifdef ENOTEMPTY
      return ENOTEMPTY;
#else
#ifdef WSAENOTEMPTY
      return WSAENOTEMPTY;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTNAM:
#ifdef ENOTNAM
      return ENOTNAM;
#else
#ifdef WSAENOTNAM
      return WSAENOTNAM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTSOCK:
#ifdef ENOTSOCK
      return ENOTSOCK;
#else
#ifdef WSAENOTSOCK
      return WSAENOTSOCK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTSUP:
#ifdef ENOTSUP
      return ENOTSUP;
#else
#ifdef WSAENOTSUP
      return WSAENOTSUP;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTTY:
#ifdef ENOTTY
      return ENOTTY;
#else
#ifdef WSAENOTTY
      return WSAENOTTY;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENOTUNIQ:
#ifdef ENOTUNIQ
      return ENOTUNIQ;
#else
#ifdef WSAENOTUNIQ
      return WSAENOTUNIQ;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ENXIO:
#ifdef ENXIO
      return ENXIO;
#else
#ifdef WSAENXIO
      return WSAENXIO;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EOPNOTSUPP:
#ifdef EOPNOTSUPP
      return EOPNOTSUPP;
#else
#ifdef WSAEOPNOTSUPP
      return WSAEOPNOTSUPP;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EOVERFLOW:
#ifdef EOVERFLOW
      return EOVERFLOW;
#else
#ifdef WSAEOVERFLOW
      return WSAEOVERFLOW;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPERM:
#ifdef EPERM
      return EPERM;
#else
#ifdef WSAEPERM
      return WSAEPERM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPFNOSUPPORT:
#ifdef EPFNOSUPPORT
      return EPFNOSUPPORT;
#else
#ifdef WSAEPFNOSUPPORT
      return WSAEPFNOSUPPORT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPIPE:
#ifdef EPIPE
      return EPIPE;
#else
#ifdef WSAEPIPE
      return WSAEPIPE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROCLIM:
#ifdef EPROCLIM
      return EPROCLIM;
#else
#ifdef WSAEPROCLIM
      return WSAEPROCLIM;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROCUNAVAIL:
#ifdef EPROCUNAVAIL
      return EPROCUNAVAIL;
#else
#ifdef WSAEPROCUNAVAIL
      return WSAEPROCUNAVAIL;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROGMISMATCH:
#ifdef EPROGMISMATCH
      return EPROGMISMATCH;
#else
#ifdef WSAEPROGMISMATCH
      return WSAEPROGMISMATCH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROGUNAVAIL:
#ifdef EPROGUNAVAIL
      return EPROGUNAVAIL;
#else
#ifdef WSAEPROGUNAVAIL
      return WSAEPROGUNAVAIL;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROTO:
#ifdef EPROTO
      return EPROTO;
#else
#ifdef WSAEPROTO
      return WSAEPROTO;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROTONOSUPPORT:
#ifdef EPROTONOSUPPORT
      return EPROTONOSUPPORT;
#else
#ifdef WSAEPROTONOSUPPORT
      return WSAEPROTONOSUPPORT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EPROTOTYPE:
#ifdef EPROTOTYPE
      return EPROTOTYPE;
#else
#ifdef WSAEPROTOTYPE
      return WSAEPROTOTYPE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ERANGE:
#ifdef ERANGE
      return ERANGE;
#else
#ifdef WSAERANGE
      return WSAERANGE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EREMCHG:
#ifdef EREMCHG
      return EREMCHG;
#else
#ifdef WSAEREMCHG
      return WSAEREMCHG;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EREMOTE:
#ifdef EREMOTE
      return EREMOTE;
#else
#ifdef WSAEREMOTE
      return WSAEREMOTE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EREMOTEIO:
#ifdef EREMOTEIO
      return EREMOTEIO;
#else
#ifdef WSAEREMOTEIO
      return WSAEREMOTEIO;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ERESTART:
#ifdef ERESTART
      return ERESTART;
#else
#ifdef WSAERESTART
      return WSAERESTART;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EROFS:
#ifdef EROFS
      return EROFS;
#else
#ifdef WSAEROFS
      return WSAEROFS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ERPCMISMATCH:
#ifdef ERPCMISMATCH
      return ERPCMISMATCH;
#else
#ifdef WSAERPCMISMATCH
      return WSAERPCMISMATCH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESHUTDOWN:
#ifdef ESHUTDOWN
      return ESHUTDOWN;
#else
#ifdef WSAESHUTDOWN
      return WSAESHUTDOWN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESOCKTNOSUPPORT:
#ifdef ESOCKTNOSUPPORT
      return ESOCKTNOSUPPORT;
#else
#ifdef WSAESOCKTNOSUPPORT
      return WSAESOCKTNOSUPPORT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESPIPE:
#ifdef ESPIPE
      return ESPIPE;
#else
#ifdef WSAESPIPE
      return WSAESPIPE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESRCH:
#ifdef ESRCH
      return ESRCH;
#else
#ifdef WSAESRCH
      return WSAESRCH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESRMNT:
#ifdef ESRMNT
      return ESRMNT;
#else
#ifdef WSAESRMNT
      return WSAESRMNT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESTALE:
#ifdef ESTALE
      return ESTALE;
#else
#ifdef WSAESTALE
      return WSAESTALE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ESTRPIPE:
#ifdef ESTRPIPE
      return ESTRPIPE;
#else
#ifdef WSAESTRPIPE
      return WSAESTRPIPE;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ETIME:
#ifdef ETIME
      return ETIME;
#else
#ifdef WSAETIME
      return WSAETIME;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ETIMEDOUT:
#ifdef ETIMEDOUT
      return ETIMEDOUT;
#else
#ifdef WSAETIMEDOUT
      return WSAETIMEDOUT;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ETOOMANYREFS:
#ifdef ETOOMANYREFS
      return ETOOMANYREFS;
#else
#ifdef WSAETOOMANYREFS
      return WSAETOOMANYREFS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_ETXTBSY:
#ifdef ETXTBSY
      return ETXTBSY;
#else
#ifdef WSAETXTBSY
      return WSAETXTBSY;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EUCLEAN:
#ifdef EUCLEAN
      return EUCLEAN;
#else
#ifdef WSAEUCLEAN
      return WSAEUCLEAN;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EUNATCH:
#ifdef EUNATCH
      return EUNATCH;
#else
#ifdef WSAEUNATCH
      return WSAEUNATCH;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EUSERS:
#ifdef EUSERS
      return EUSERS;
#else
#ifdef WSAEUSERS
      return WSAEUSERS;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EWOULDBLOCK:
#ifdef EWOULDBLOCK
      return EWOULDBLOCK;
#else
#ifdef WSAEWOULDBLOCK
      return WSAEWOULDBLOCK;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EXDEV:
#ifdef EXDEV
      return EXDEV;
#else
#ifdef WSAEXDEV
      return WSAEXDEV;
#else
      return 0;
#endif
#endif
    case GPG_ERR_EXFULL:
#ifdef EXFULL
      return EXFULL;
#else
#ifdef WSAEXFULL
      return WSAEXFULL;
#else
      return 0;
#endif
#endif
    default:
      break;
  }
  return 0;
}

/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int gpg_error_to_errno(gpg_error_t code) {
  if (!(code & GPG_ERR_SYSTEM_ERROR)) return 0;
  code &= ~GPG_ERR_SYSTEM_ERROR;

  return code_to_errno(code);
}
