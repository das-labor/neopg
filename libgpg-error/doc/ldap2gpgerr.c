/* ldap2gpgerr.c - Mapping of LDAP error codes to gpg-error codes.
 * Written in 2015 by Werner Koch <wk@gnupg.org>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide.  This software is distributed without
 * any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software.  If not, see
 *                 <https://creativecommons.org/publicdomain/zero/1.0/>.
 */

/*
 * These functions are not part of libgpg-error so not to introduce a
 * dependency on a specific LDAP implementation.  Feel free to copy
 * and distribute them with your code.
 */

#ifdef _WIN32
# include <winsock2.h>
# include <winldap.h>
#else
# include <ldap.h>
#endif
#include <gpg-error.h>


/* Windows uses a few other names. Re-map them.  */
#ifdef _WIN32
# define LDAP_ADMINLIMIT_EXCEEDED            LDAP_ADMIN_LIMIT_EXCEEDED
# define LDAP_UNAVAILABLE_CRITICAL_EXTENSION LDAP_UNAVAILABLE_CRIT_EXTENSION
# define LDAP_TYPE_OR_VALUE_EXISTS           LDAP_ATTRIBUTE_OR_VALUE_EXISTS
# define LDAP_INSUFFICIENT_ACCESS            LDAP_INSUFFICIENT_RIGHTS
# define LDAP_VLV_ERROR                      LDAP_VIRTUAL_LIST_VIEW_ERROR
#endif


/* Map LDAP error CODE to an gpg_err_code_t.  */
gpg_err_code_t
map_ldap_to_gpg_error (int code)
{
  gpg_err_code_t ec;

  switch (code)
    {
#ifdef LDAP_X_CONNECTING
    case LDAP_X_CONNECTING: ec = GPG_ERR_LDAP_X_CONNECTING; break;
#endif

    case LDAP_REFERRAL_LIMIT_EXCEEDED: ec = GPG_ERR_LDAP_REFERRAL_LIMIT; break;
    case LDAP_CLIENT_LOOP: ec = GPG_ERR_LDAP_CLIENT_LOOP; break;
    case LDAP_NO_RESULTS_RETURNED: ec = GPG_ERR_LDAP_NO_RESULTS; break;
    case LDAP_CONTROL_NOT_FOUND: ec = GPG_ERR_LDAP_CONTROL_NOT_FOUND; break;
    case LDAP_NOT_SUPPORTED: ec = GPG_ERR_LDAP_NOT_SUPPORTED; break;
    case LDAP_CONNECT_ERROR: ec = GPG_ERR_LDAP_CONNECT; break;
    case LDAP_NO_MEMORY: ec = GPG_ERR_LDAP_NO_MEMORY; break;
    case LDAP_PARAM_ERROR: ec = GPG_ERR_LDAP_PARAM; break;
    case LDAP_USER_CANCELLED: ec = GPG_ERR_LDAP_USER_CANCELLED; break;
    case LDAP_FILTER_ERROR: ec = GPG_ERR_LDAP_FILTER; break;
    case LDAP_AUTH_UNKNOWN: ec = GPG_ERR_LDAP_AUTH_UNKNOWN; break;
    case LDAP_TIMEOUT: ec = GPG_ERR_LDAP_TIMEOUT; break;
    case LDAP_DECODING_ERROR: ec = GPG_ERR_LDAP_DECODING; break;
    case LDAP_ENCODING_ERROR: ec = GPG_ERR_LDAP_ENCODING; break;
    case LDAP_LOCAL_ERROR: ec = GPG_ERR_LDAP_LOCAL; break;
    case LDAP_SERVER_DOWN: ec = GPG_ERR_LDAP_SERVER_DOWN; break;

    case LDAP_SUCCESS: ec = GPG_ERR_LDAP_SUCCESS; break;

    case LDAP_OPERATIONS_ERROR: ec = GPG_ERR_LDAP_OPERATIONS; break;
    case LDAP_PROTOCOL_ERROR: ec = GPG_ERR_LDAP_PROTOCOL; break;
    case LDAP_TIMELIMIT_EXCEEDED: ec = GPG_ERR_LDAP_TIMELIMIT; break;
    case LDAP_SIZELIMIT_EXCEEDED: ec = GPG_ERR_LDAP_SIZELIMIT; break;
    case LDAP_COMPARE_FALSE: ec = GPG_ERR_LDAP_COMPARE_FALSE; break;
    case LDAP_COMPARE_TRUE: ec = GPG_ERR_LDAP_COMPARE_TRUE; break;
    case LDAP_AUTH_METHOD_NOT_SUPPORTED: ec=GPG_ERR_LDAP_UNSUPPORTED_AUTH;break;
    case LDAP_STRONG_AUTH_REQUIRED: ec = GPG_ERR_LDAP_STRONG_AUTH_RQRD; break;
    case LDAP_PARTIAL_RESULTS: ec = GPG_ERR_LDAP_PARTIAL_RESULTS; break;
    case LDAP_REFERRAL: ec = GPG_ERR_LDAP_REFERRAL; break;

#ifdef LDAP_ADMINLIMIT_EXCEEDED
    case LDAP_ADMINLIMIT_EXCEEDED: ec = GPG_ERR_LDAP_ADMINLIMIT; break;
#endif

#ifdef LDAP_UNAVAILABLE_CRITICAL_EXTENSION
    case LDAP_UNAVAILABLE_CRITICAL_EXTENSION:
                               ec = GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN; break;
#endif

    case LDAP_CONFIDENTIALITY_REQUIRED: ec = GPG_ERR_LDAP_CONFIDENT_RQRD; break;
    case LDAP_SASL_BIND_IN_PROGRESS: ec = GPG_ERR_LDAP_SASL_BIND_INPROG; break;
    case LDAP_NO_SUCH_ATTRIBUTE: ec = GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE; break;
    case LDAP_UNDEFINED_TYPE: ec = GPG_ERR_LDAP_UNDEFINED_TYPE; break;
    case LDAP_INAPPROPRIATE_MATCHING: ec = GPG_ERR_LDAP_BAD_MATCHING; break;
    case LDAP_CONSTRAINT_VIOLATION: ec = GPG_ERR_LDAP_CONST_VIOLATION; break;

#ifdef LDAP_TYPE_OR_VALUE_EXISTS
    case LDAP_TYPE_OR_VALUE_EXISTS: ec = GPG_ERR_LDAP_TYPE_VALUE_EXISTS; break;
#endif

    case LDAP_INVALID_SYNTAX: ec = GPG_ERR_LDAP_INV_SYNTAX; break;
    case LDAP_NO_SUCH_OBJECT: ec = GPG_ERR_LDAP_NO_SUCH_OBJ; break;
    case LDAP_ALIAS_PROBLEM: ec = GPG_ERR_LDAP_ALIAS_PROBLEM; break;
    case LDAP_INVALID_DN_SYNTAX: ec = GPG_ERR_LDAP_INV_DN_SYNTAX; break;
    case LDAP_IS_LEAF: ec = GPG_ERR_LDAP_IS_LEAF; break;
    case LDAP_ALIAS_DEREF_PROBLEM: ec = GPG_ERR_LDAP_ALIAS_DEREF; break;

#ifdef LDAP_X_PROXY_AUTHZ_FAILURE
    case LDAP_X_PROXY_AUTHZ_FAILURE: ec = GPG_ERR_LDAP_X_PROXY_AUTH_FAIL; break;
#endif

    case LDAP_INAPPROPRIATE_AUTH: ec = GPG_ERR_LDAP_BAD_AUTH; break;
    case LDAP_INVALID_CREDENTIALS: ec = GPG_ERR_LDAP_INV_CREDENTIALS; break;

#ifdef LDAP_INSUFFICIENT_ACCESS
    case LDAP_INSUFFICIENT_ACCESS: ec = GPG_ERR_LDAP_INSUFFICIENT_ACC; break;
#endif

    case LDAP_BUSY: ec = GPG_ERR_LDAP_BUSY; break;
    case LDAP_UNAVAILABLE: ec = GPG_ERR_LDAP_UNAVAILABLE; break;
    case LDAP_UNWILLING_TO_PERFORM: ec = GPG_ERR_LDAP_UNWILL_TO_PERFORM; break;
    case LDAP_LOOP_DETECT: ec = GPG_ERR_LDAP_LOOP_DETECT; break;
    case LDAP_NAMING_VIOLATION: ec = GPG_ERR_LDAP_NAMING_VIOLATION; break;
    case LDAP_OBJECT_CLASS_VIOLATION: ec = GPG_ERR_LDAP_OBJ_CLS_VIOLATION; break;
    case LDAP_NOT_ALLOWED_ON_NONLEAF: ec=GPG_ERR_LDAP_NOT_ALLOW_NONLEAF;break;
    case LDAP_NOT_ALLOWED_ON_RDN: ec = GPG_ERR_LDAP_NOT_ALLOW_ON_RDN; break;
    case LDAP_ALREADY_EXISTS: ec = GPG_ERR_LDAP_ALREADY_EXISTS; break;
    case LDAP_NO_OBJECT_CLASS_MODS: ec = GPG_ERR_LDAP_NO_OBJ_CLASS_MODS; break;
    case LDAP_RESULTS_TOO_LARGE: ec = GPG_ERR_LDAP_RESULTS_TOO_LARGE; break;
    case LDAP_AFFECTS_MULTIPLE_DSAS: ec = GPG_ERR_LDAP_AFFECTS_MULT_DSAS; break;

#ifdef LDAP_VLV_ERROR
    case LDAP_VLV_ERROR: ec = GPG_ERR_LDAP_VLV; break;
#endif

    case LDAP_OTHER: ec = GPG_ERR_LDAP_OTHER; break;

#ifdef LDAP_CUP_RESOURCES_EXHAUSTED
    case LDAP_CUP_RESOURCES_EXHAUSTED: ec=GPG_ERR_LDAP_CUP_RESOURCE_LIMIT;break;
    case LDAP_CUP_SECURITY_VIOLATION: ec=GPG_ERR_LDAP_CUP_SEC_VIOLATION; break;
    case LDAP_CUP_INVALID_DATA: ec = GPG_ERR_LDAP_CUP_INV_DATA; break;
    case LDAP_CUP_UNSUPPORTED_SCHEME: ec = GPG_ERR_LDAP_CUP_UNSUP_SCHEME; break;
    case LDAP_CUP_RELOAD_REQUIRED: ec = GPG_ERR_LDAP_CUP_RELOAD; break;
#endif

#ifdef LDAP_CANCELLED
    case LDAP_CANCELLED: ec = GPG_ERR_LDAP_CANCELLED; break;
#endif

#ifdef LDAP_NO_SUCH_OPERATION
    case LDAP_NO_SUCH_OPERATION: ec = GPG_ERR_LDAP_NO_SUCH_OPERATION; break;
#endif

#ifdef LDAP_TOO_LATE
    case LDAP_TOO_LATE: ec = GPG_ERR_LDAP_TOO_LATE; break;
#endif

#ifdef LDAP_CANNOT_CANCEL
    case LDAP_CANNOT_CANCEL: ec = GPG_ERR_LDAP_CANNOT_CANCEL; break;
#endif

#ifdef LDAP_ASSERTION_FAILED
    case LDAP_ASSERTION_FAILED: ec = GPG_ERR_LDAP_ASSERTION_FAILED; break;
#endif

#ifdef LDAP_PROXIED_AUTHORIZATION_DENIED
    case LDAP_PROXIED_AUTHORIZATION_DENIED:
                                      ec = GPG_ERR_LDAP_PROX_AUTH_DENIED; break;
#endif

    default:
#if defined(LDAP_E_ERROR) && defined(LDAP_X_ERROR)
      if (LDAP_E_ERROR (code))
        ec = GPG_ERR_LDAP_E_GENERAL;
      else if (LDAP_X_ERROR (code))
        ec = GPG_ERR_LDAP_X_GENERAL;
      else
#endif
        ec = GPG_ERR_LDAP_GENERAL;
      break;
    }

  return ec;
}
