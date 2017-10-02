/* code-from-errno.c - Mapping errnos to error codes.
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

#include <errno.h>

#include <gpg-error.h>

static gpg_err_code_t
code_from_errno(int err)
{
  switch (err) {
#ifdef E2BIG
  case E2BIG:
    return GPG_ERR_E2BIG;
#endif
#ifdef EACCES
  case EACCES:
    return GPG_ERR_EACCES;
#endif
#ifdef EADDRINUSE
  case EADDRINUSE:
    return GPG_ERR_EADDRINUSE;
#endif
#ifdef EADDRNOTAVAIL
  case EADDRNOTAVAIL:
    return GPG_ERR_EADDRNOTAVAIL;
#endif
#ifdef EADV
  case EADV:
    return GPG_ERR_EADV;
#endif
#ifdef EAFNOSUPPORT
  case EAFNOSUPPORT:
    return GPG_ERR_EAFNOSUPPORT;
#endif
#if defined(EAGAIN) || defined(EWOULDBLOCK)
#ifdef EAGAIN
  case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
  case EWOULDBLOCK:
#endif
    return GPG_ERR_EAGAIN;
#endif
#ifdef EALREADY
  case EALREADY:
    return GPG_ERR_EALREADY;
#endif
#ifdef EAUTH
  case EAUTH:
    return GPG_ERR_EAUTH;
#endif
#ifdef EBACKGROUND
  case EBACKGROUND:
    return GPG_ERR_EBACKGROUND;
#endif
#ifdef EBADE
  case EBADE:
    return GPG_ERR_EBADE;
#endif
#ifdef EBADF
  case EBADF:
    return GPG_ERR_EBADF;
#endif
#ifdef EBADFD
  case EBADFD:
    return GPG_ERR_EBADFD;
#endif
#ifdef EBADMSG
  case EBADMSG:
    return GPG_ERR_EBADMSG;
#endif
#ifdef EBADR
  case EBADR:
    return GPG_ERR_EBADR;
#endif
#ifdef EBADRPC
  case EBADRPC:
    return GPG_ERR_EBADRPC;
#endif
#ifdef EBADRQC
  case EBADRQC:
    return GPG_ERR_EBADRQC;
#endif
#ifdef EBADSLT
  case EBADSLT:
    return GPG_ERR_EBADSLT;
#endif
#ifdef EBFONT
  case EBFONT:
    return GPG_ERR_EBFONT;
#endif
#ifdef EBUSY
  case EBUSY:
    return GPG_ERR_EBUSY;
#endif
#ifdef ECANCELED
  case ECANCELED:
    return GPG_ERR_ECANCELED;
#endif
#ifdef ECHILD
  case ECHILD:
    return GPG_ERR_ECHILD;
#endif
#ifdef ECHRNG
  case ECHRNG:
    return GPG_ERR_ECHRNG;
#endif
#ifdef ECOMM
  case ECOMM:
    return GPG_ERR_ECOMM;
#endif
#ifdef ECONNABORTED
  case ECONNABORTED:
    return GPG_ERR_ECONNABORTED;
#endif
#ifdef ECONNREFUSED
  case ECONNREFUSED:
    return GPG_ERR_ECONNREFUSED;
#endif
#ifdef ECONNRESET
  case ECONNRESET:
    return GPG_ERR_ECONNRESET;
#endif
#ifdef ED
  case ED:
    return GPG_ERR_ED;
#endif
#if defined(EDEADLK) || defined(EDEADLOCK)
#ifdef EDEADLK
  case EDEADLK:
#endif
#if defined(EDEADLOCK) && (EDEADLOCK != EDEADLK)
  case EDEADLOCK:
#endif
    return GPG_ERR_EDEADLK;
#endif
#ifdef EDESTADDRREQ
  case EDESTADDRREQ:
    return GPG_ERR_EDESTADDRREQ;
#endif
#ifdef EDIED
  case EDIED:
    return GPG_ERR_EDIED;
#endif
#ifdef EDOM
  case EDOM:
    return GPG_ERR_EDOM;
#endif
#ifdef EDOTDOT
  case EDOTDOT:
    return GPG_ERR_EDOTDOT;
#endif
#ifdef EDQUOT
  case EDQUOT:
    return GPG_ERR_EDQUOT;
#endif
#ifdef EEXIST
  case EEXIST:
    return GPG_ERR_EEXIST;
#endif
#ifdef EFAULT
  case EFAULT:
    return GPG_ERR_EFAULT;
#endif
#ifdef EFBIG
  case EFBIG:
    return GPG_ERR_EFBIG;
#endif
#ifdef EFTYPE
  case EFTYPE:
    return GPG_ERR_EFTYPE;
#endif
#ifdef EGRATUITOUS
  case EGRATUITOUS:
    return GPG_ERR_EGRATUITOUS;
#endif
#ifdef EGREGIOUS
  case EGREGIOUS:
    return GPG_ERR_EGREGIOUS;
#endif
#ifdef EHOSTDOWN
  case EHOSTDOWN:
    return GPG_ERR_EHOSTDOWN;
#endif
#ifdef EHOSTUNREACH
  case EHOSTUNREACH:
    return GPG_ERR_EHOSTUNREACH;
#endif
#ifdef EIDRM
  case EIDRM:
    return GPG_ERR_EIDRM;
#endif
#ifdef EIEIO
  case EIEIO:
    return GPG_ERR_EIEIO;
#endif
#ifdef EILSEQ
  case EILSEQ:
    return GPG_ERR_EILSEQ;
#endif
#ifdef EINPROGRESS
  case EINPROGRESS:
    return GPG_ERR_EINPROGRESS;
#endif
#ifdef EINTR
  case EINTR:
    return GPG_ERR_EINTR;
#endif
#ifdef EINVAL
  case EINVAL:
    return GPG_ERR_EINVAL;
#endif
#ifdef EIO
  case EIO:
    return GPG_ERR_EIO;
#endif
#ifdef EISCONN
  case EISCONN:
    return GPG_ERR_EISCONN;
#endif
#ifdef EISDIR
  case EISDIR:
    return GPG_ERR_EISDIR;
#endif
#ifdef EISNAM
  case EISNAM:
    return GPG_ERR_EISNAM;
#endif
#ifdef EL2HLT
  case EL2HLT:
    return GPG_ERR_EL2HLT;
#endif
#ifdef EL2NSYNC
  case EL2NSYNC:
    return GPG_ERR_EL2NSYNC;
#endif
#ifdef EL3HLT
  case EL3HLT:
    return GPG_ERR_EL3HLT;
#endif
#ifdef EL3RST
  case EL3RST:
    return GPG_ERR_EL3RST;
#endif
#ifdef ELIBACC
  case ELIBACC:
    return GPG_ERR_ELIBACC;
#endif
#ifdef ELIBBAD
  case ELIBBAD:
    return GPG_ERR_ELIBBAD;
#endif
#ifdef ELIBEXEC
  case ELIBEXEC:
    return GPG_ERR_ELIBEXEC;
#endif
#ifdef ELIBMAX
  case ELIBMAX:
    return GPG_ERR_ELIBMAX;
#endif
#ifdef ELIBSCN
  case ELIBSCN:
    return GPG_ERR_ELIBSCN;
#endif
#ifdef ELNRNG
  case ELNRNG:
    return GPG_ERR_ELNRNG;
#endif
#ifdef ELOOP
  case ELOOP:
    return GPG_ERR_ELOOP;
#endif
#ifdef EMEDIUMTYPE
  case EMEDIUMTYPE:
    return GPG_ERR_EMEDIUMTYPE;
#endif
#ifdef EMFILE
  case EMFILE:
    return GPG_ERR_EMFILE;
#endif
#ifdef EMLINK
  case EMLINK:
    return GPG_ERR_EMLINK;
#endif
#ifdef EMSGSIZE
  case EMSGSIZE:
    return GPG_ERR_EMSGSIZE;
#endif
#ifdef EMULTIHOP
  case EMULTIHOP:
    return GPG_ERR_EMULTIHOP;
#endif
#ifdef ENAMETOOLONG
  case ENAMETOOLONG:
    return GPG_ERR_ENAMETOOLONG;
#endif
#ifdef ENAVAIL
  case ENAVAIL:
    return GPG_ERR_ENAVAIL;
#endif
#ifdef ENEEDAUTH
  case ENEEDAUTH:
    return GPG_ERR_ENEEDAUTH;
#endif
#ifdef ENETDOWN
  case ENETDOWN:
    return GPG_ERR_ENETDOWN;
#endif
#ifdef ENETRESET
  case ENETRESET:
    return GPG_ERR_ENETRESET;
#endif
#ifdef ENETUNREACH
  case ENETUNREACH:
    return GPG_ERR_ENETUNREACH;
#endif
#ifdef ENFILE
  case ENFILE:
    return GPG_ERR_ENFILE;
#endif
#ifdef ENOANO
  case ENOANO:
    return GPG_ERR_ENOANO;
#endif
#ifdef ENOBUFS
  case ENOBUFS:
    return GPG_ERR_ENOBUFS;
#endif
#ifdef ENOCSI
  case ENOCSI:
    return GPG_ERR_ENOCSI;
#endif
#ifdef ENODATA
  case ENODATA:
    return GPG_ERR_ENODATA;
#endif
#ifdef ENODEV
  case ENODEV:
    return GPG_ERR_ENODEV;
#endif
#ifdef ENOENT
  case ENOENT:
    return GPG_ERR_ENOENT;
#endif
#ifdef ENOEXEC
  case ENOEXEC:
    return GPG_ERR_ENOEXEC;
#endif
#ifdef ENOLCK
  case ENOLCK:
    return GPG_ERR_ENOLCK;
#endif
#ifdef ENOLINK
  case ENOLINK:
    return GPG_ERR_ENOLINK;
#endif
#ifdef ENOMEDIUM
  case ENOMEDIUM:
    return GPG_ERR_ENOMEDIUM;
#endif
#ifdef ENOMEM
  case ENOMEM:
    return GPG_ERR_ENOMEM;
#endif
#ifdef ENOMSG
  case ENOMSG:
    return GPG_ERR_ENOMSG;
#endif
#ifdef ENONET
  case ENONET:
    return GPG_ERR_ENONET;
#endif
#ifdef ENOPKG
  case ENOPKG:
    return GPG_ERR_ENOPKG;
#endif
#ifdef ENOPROTOOPT
  case ENOPROTOOPT:
    return GPG_ERR_ENOPROTOOPT;
#endif
#ifdef ENOSPC
  case ENOSPC:
    return GPG_ERR_ENOSPC;
#endif
#ifdef ENOSR
  case ENOSR:
    return GPG_ERR_ENOSR;
#endif
#ifdef ENOSTR
  case ENOSTR:
    return GPG_ERR_ENOSTR;
#endif
#ifdef ENOSYS
  case ENOSYS:
    return GPG_ERR_ENOSYS;
#endif
#ifdef ENOTBLK
  case ENOTBLK:
    return GPG_ERR_ENOTBLK;
#endif
#ifdef ENOTCONN
  case ENOTCONN:
    return GPG_ERR_ENOTCONN;
#endif
#ifdef ENOTDIR
  case ENOTDIR:
    return GPG_ERR_ENOTDIR;
#endif
#ifdef ENOTEMPTY
  case ENOTEMPTY:
    return GPG_ERR_ENOTEMPTY;
#endif
#ifdef ENOTNAM
  case ENOTNAM:
    return GPG_ERR_ENOTNAM;
#endif
#ifdef ENOTSOCK
  case ENOTSOCK:
    return GPG_ERR_ENOTSOCK;
#endif
#if defined(ENOTSUP) || defined(EOPNOTSUPP)
#ifdef ENOTSUP
  case ENOTSUP:
#endif
#if defined(EOPNOTSUPP) && (EOPNOTSUPP != ENOTSUP)
  case EOPNOTSUPP:
#endif
    return GPG_ERR_ENOTSUP;
#endif
#ifdef ENOTTY
  case ENOTTY:
    return GPG_ERR_ENOTTY;
#endif
#ifdef ENOTUNIQ
  case ENOTUNIQ:
    return GPG_ERR_ENOTUNIQ;
#endif
#ifdef ENXIO
  case ENXIO:
    return GPG_ERR_ENXIO;
#endif
#ifdef EOVERFLOW
  case EOVERFLOW:
    return GPG_ERR_EOVERFLOW;
#endif
#ifdef EPERM
  case EPERM:
    return GPG_ERR_EPERM;
#endif
#ifdef EPFNOSUPPORT
  case EPFNOSUPPORT:
    return GPG_ERR_EPFNOSUPPORT;
#endif
#ifdef EPIPE
  case EPIPE:
    return GPG_ERR_EPIPE;
#endif
#ifdef EPROCLIM
  case EPROCLIM:
    return GPG_ERR_EPROCLIM;
#endif
#ifdef EPROCUNAVAIL
  case EPROCUNAVAIL:
    return GPG_ERR_EPROCUNAVAIL;
#endif
#ifdef EPROGMISMATCH
  case EPROGMISMATCH:
    return GPG_ERR_EPROGMISMATCH;
#endif
#ifdef EPROGUNAVAIL
  case EPROGUNAVAIL:
    return GPG_ERR_EPROGUNAVAIL;
#endif
#ifdef EPROTO
  case EPROTO:
    return GPG_ERR_EPROTO;
#endif
#ifdef EPROTONOSUPPORT
  case EPROTONOSUPPORT:
    return GPG_ERR_EPROTONOSUPPORT;
#endif
#ifdef EPROTOTYPE
  case EPROTOTYPE:
    return GPG_ERR_EPROTOTYPE;
#endif
#ifdef ERANGE
  case ERANGE:
    return GPG_ERR_ERANGE;
#endif
#ifdef EREMCHG
  case EREMCHG:
    return GPG_ERR_EREMCHG;
#endif
#ifdef EREMOTE
  case EREMOTE:
    return GPG_ERR_EREMOTE;
#endif
#ifdef EREMOTEIO
  case EREMOTEIO:
    return GPG_ERR_EREMOTEIO;
#endif
#ifdef ERESTART
  case ERESTART:
    return GPG_ERR_ERESTART;
#endif
#ifdef EROFS
  case EROFS:
    return GPG_ERR_EROFS;
#endif
#ifdef ERPCMISMATCH
  case ERPCMISMATCH:
    return GPG_ERR_ERPCMISMATCH;
#endif
#ifdef ESHUTDOWN
  case ESHUTDOWN:
    return GPG_ERR_ESHUTDOWN;
#endif
#ifdef ESOCKTNOSUPPORT
  case ESOCKTNOSUPPORT:
    return GPG_ERR_ESOCKTNOSUPPORT;
#endif
#ifdef ESPIPE
  case ESPIPE:
    return GPG_ERR_ESPIPE;
#endif
#ifdef ESRCH
  case ESRCH:
    return GPG_ERR_ESRCH;
#endif
#ifdef ESRMNT
  case ESRMNT:
    return GPG_ERR_ESRMNT;
#endif
#ifdef ESTALE
  case ESTALE:
    return GPG_ERR_ESTALE;
#endif
#ifdef ESTRPIPE
  case ESTRPIPE:
    return GPG_ERR_ESTRPIPE;
#endif
#ifdef ETIME
  case ETIME:
    return GPG_ERR_ETIME;
#endif
#ifdef ETIMEDOUT
  case ETIMEDOUT:
    return GPG_ERR_ETIMEDOUT;
#endif
#ifdef ETOOMANYREFS
  case ETOOMANYREFS:
    return GPG_ERR_ETOOMANYREFS;
#endif
#ifdef ETXTBSY
  case ETXTBSY:
    return GPG_ERR_ETXTBSY;
#endif
#ifdef EUCLEAN
  case EUCLEAN:
    return GPG_ERR_EUCLEAN;
#endif
#ifdef EUNATCH
  case EUNATCH:
    return GPG_ERR_EUNATCH;
#endif
#ifdef EUSERS
  case EUSERS:
    return GPG_ERR_EUSERS;
#endif
#ifdef EXDEV
  case EXDEV:
    return GPG_ERR_EXDEV;
#endif
#ifdef EXFULL
  case EXFULL:
    return GPG_ERR_EXFULL;
#endif
  default:
    break;
  }
  return GPG_ERR_UNKNOWN_ERRNO;
}



/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gpg_err_code_t
gpg_err_code_from_errno (int err)
{
  if (!err)
    return GPG_ERR_NO_ERROR;

  return GPG_ERR_SYSTEM_ERROR | code_from_errno(err);
}


/* Retrieve the error code directly from the ERRNO variable.  This
   returns GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped
   (report this) and GPG_ERR_MISSING_ERRNO if ERRNO has the value 0. */
gpg_err_code_t
gpg_err_code_from_syserror (void)
{
  int err = errno;

  if (!err)
    return GPG_ERR_MISSING_ERRNO;

  return GPG_ERR_SYSTEM_ERROR | code_from_errno(err);
}
