/* gpg-agent.c  -  The GnuPG Agent
 * Copyright (C) 2000-2007, 2009-2010 Free Software Foundation, Inc.
 * Copyright (C) 2000-2016 Werner Koch
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_W32_SYSTEM
# ifndef WINVER
#  define WINVER 0x0500  /* Same as in common/sysutils.c */
# endif
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <aclapi.h>
# include <sddl.h>
#endif /*!HAVE_W32_SYSTEM*/
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <npth.h>

#define GNUPG_COMMON_NEED_AFLOCAL
#include "agent.h"
#include <assuan.h> /* Malloc hooks  and socket wrappers. */

#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/gc-opt-flags.h"
#include "../common/exechelp.h"
#include "../common/asshelp.h"
#include "../common/init.h"

struct options opt;

enum cmd_and_opt_values
{ aNull = 0,
  oQuiet	  = 'q',
  oVerbose	  = 'v',

  oNoVerbose = 500,
  aGPGConfList,
  aGPGConfTest,
  oOptions,
  oDebug,
  oDebugAll,
  oDebugLevel,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oLogFile,
  oServer,
  oBatch,

  oLCctype,
  oLCmessages,
  oScdaemonProgram,
  oDefCacheTTL,
  oMaxCacheTTL,
  oEnableExtendedKeyFormat,
  oFakedSystemTime,

  oIgnoreCacheForSigning,
  oAllowMarkTrusted,
  oNoAllowMarkTrusted,
  oNoAllowExternalCache,
  oDisableScdaemon,
  oWriteEnvFile
};


#ifndef ENAMETOOLONG
# define ENAMETOOLONG EINVAL
#endif


static ARGPARSE_OPTS opts[] = {

  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_group (301, N_("@Options:\n ")),

  ARGPARSE_s_n (oServer,  "server", N_("run in server mode (foreground)")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	  "quiet",     N_("be somewhat more quiet")),
  ARGPARSE_s_s (oOptions, "options", N_("|FILE|read options from FILE")),

  ARGPARSE_s_s (oDebug,	     "debug",       "@"),
  ARGPARSE_s_n (oDebugAll,   "debug-all",   "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level", "@"),

  ARGPARSE_s_n (oNoDetach,  "no-detach", N_("do not detach from the console")),
  ARGPARSE_s_s (oLogFile,   "log-file",  N_("use a log file for the server")),
  ARGPARSE_s_n (oDisableScdaemon, "disable-scdaemon",
                /* */             N_("do not use the SCdaemon") ),

  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),

  ARGPARSE_s_n (oBatch,      "batch",        "@"),
  ARGPARSE_s_s (oHomedir,    "homedir",      "@"),

  ARGPARSE_s_s (oLCctype,    "lc-ctype",    "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages", "@"),

  ARGPARSE_s_u (oDefCacheTTL,    "default-cache-ttl",
                                 N_("|N|expire cached PINs after N seconds")),
  ARGPARSE_s_u (oMaxCacheTTL,    "max-cache-ttl",         "@" ),

  ARGPARSE_s_n (oIgnoreCacheForSigning, "ignore-cache-for-signing",
                /* */    N_("do not use the PIN cache when signing")),
  ARGPARSE_s_n (oNoAllowExternalCache,  "no-allow-external-cache",
                /* */    N_("disallow the use of an external password cache")),
  ARGPARSE_s_n (oNoAllowMarkTrusted, "no-allow-mark-trusted",
                /* */    N_("disallow clients to mark keys as \"trusted\"")),
  ARGPARSE_s_n (oAllowMarkTrusted,   "allow-mark-trusted", "@"),
  ARGPARSE_s_n (oEnableExtendedKeyFormat, "enable-extended-key-format", "@"),

  /* Dummy options for backward compatibility.  */
  ARGPARSE_o_s (oWriteEnvFile, "write-env-file", "@"),

  {0} /* End of list */
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_IPC_VALUE    , "ipc"     },
    { 77, NULL } /* 77 := Do not exit on "help" or "?".  */
  };



#define DEFAULT_CACHE_TTL     (10*60)  /* 10 minutes */
#define MAX_CACHE_TTL         (120*60) /* 2 hours */
#define MIN_PASSPHRASE_LEN    (8)
#define MIN_PASSPHRASE_NONALPHA (1)
#define MAX_PASSPHRASE_DAYS   (0)

/* The timer tick used for housekeeping stuff.  For Windows we use a
   longer period as the SetWaitableTimer seems to signal earlier than
   the 2 seconds.  CHECK_OWN_SOCKET_INTERVAL defines how often we
   check our own socket in standard socket mode.  If that value is 0
   we don't check at all.   All values are in seconds. */
#if defined(HAVE_W32_SYSTEM)
# define TIMERTICK_INTERVAL          (4)
#else
# define TIMERTICK_INTERVAL          (2)
#endif


/* The signal mask at startup and a flag telling whether it is valid.  */
#ifdef HAVE_SIGPROCMASK
static sigset_t startup_signal_mask;
static int startup_signal_mask_valid;
#endif

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* Counter for the currently running own socket checks.  */
static int check_own_socket_running;

/* Flag indicating that we are in supervised mode.  */
static int is_supervised;

/* Flag to inhibit socket removal in cleanup.  */
static int inhibit_socket_removal;

/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Default values for options passed to the pinentry. */
static char *default_lc_ctype;
static char *default_lc_messages;

/* Name of a config file, which will be reread on a HUP if it is not NULL. */
static char *config_filename;

/* Helper to implement --debug-level */
static const char *debug_level;

/* Keep track of the current log file so that we can avoid updating
   the log file after a SIGHUP if it didn't changed. Malloced. */
static char *current_logfile;

/* The handle_tick() function may test whether a parent is still
   running.  We record the PID of the parent here or -1 if it should be
   watched. */
static pid_t parent_pid = (pid_t)(-1);

/* Number of active connections.  */
static int active_connections;

/* This object is used to dispatch progress messages from Libgcrypt to
 * the right thread.  Given that we will have at max only a few dozen
 * connections at a time, using a linked list is the easiest way to
 * handle this. */
struct progress_dispatch_s
{
  struct progress_dispatch_s *next;
  /* The control object of the connection.  If this is NULL no
   * connection is associated with this item and it is free for reuse
   * by new connections.  */
  ctrl_t ctrl;

  /* The thread id of (npth_self) of the connection.  */
  npth_t tid;

  /* The callback set by the connection.  This is similar to the
   * Libgcrypt callback but with the control object passed as the
   * first argument.  */
  void (*cb)(ctrl_t ctrl,
             const char *what, int printchar,
             int current, int total);
};
struct progress_dispatch_s *progress_dispatch_list;




/*
   Local prototypes.
 */

static void create_directories (void);

static void agent_init_default_ctrl (ctrl_t ctrl);
static void agent_deinit_default_ctrl (ctrl_t ctrl);

/* Pth wrapper function definitions. */
ASSUAN_SYSTEM_NPTH_IMPL;


/* Return strings describing this program.  The case values are
   described in common/argparse.c:strusage.  The values here override
   the default values given by strusage.  */
static const char *
my_strusage (int level)
{
  static char *ver_gcry;
  const char *p = NULL;

  switch (level)
    {
    case 11: p = "@GPG_AGENT@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
      /* TRANSLATORS: @EMAIL@ will get replaced by the actual bug
         reporting address.  This is so that we can change the
         reporting address without breaking the translations.  */
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p =  _("Usage: @GPG_AGENT@ [options] (-h for help)");
      break;
    case 41: p =  _("Syntax: @GPG_AGENT@ [options] [command [args]]\n"
                    "Secret key management for @GNUPG@\n");
    break;

    default: p = NULL;
    }
  return p;
}



/* Setup the debugging.  With the global variable DEBUG_LEVEL set to NULL
   only the active debug flags are propagated to the subsystems.  With
   DEBUG_LEVEL set, a specific set of debug flags is set; thus overriding
   all flags already set. Note that we don't fail here, because it is
   important to keep gpg-agent running even after re-reading the
   options due to a SIGHUP. */
static void
set_debug (void)
{
  int numok = (debug_level && digitp (debug_level));
  int numlvl = numok? atoi (debug_level) : 0;

  if (!debug_level)
    ;
  else if (!strcmp (debug_level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp (debug_level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp (debug_level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp (debug_level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE | DBG_CACHE_VALUE);
  else if (!strcmp (debug_level, "guru") || numok)
    {
      opt.debug = ~0;
      /* Unless the "guru" string has been used we don't want to allow
         hashing debugging.  The rationale is that people tend to
         select the highest debug value and would then clutter their
         disk with debug files which may reveal confidential data.  */
      if (numok)
        opt.debug &= ~(DBG_HASHING_VALUE);
    }
  else
    {
      log_error (_("invalid debug-level '%s' given\n"), debug_level);
      opt.debug = 0; /* Reset debugging, so that prior debug
                        statements won't have an undesired effect. */
    }

  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug && opt.quiet)
    opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}


/* Cleanup code for this program.  This is either called has an atexit
   handler or directly.  */
static void
cleanup (void)
{
  static int done;

  if (done)
    return;
  done = 1;
  deinitialize_module_cache ();
}



/* Handle options which are allowed to be reset after program start.
   Return true when the current option in PARGS could be handled and
   false if not.  As a special feature, passing a value of NULL for
   PARGS, resets the options to the default.  REREAD should be set
   true if it is not the initial option parsing. */
static int
parse_rereadable_options (ARGPARSE_ARGS *pargs, int reread)
{
  if (!pargs)
    { /* reset mode */
      opt.quiet = 0;
      opt.verbose = 0;
      opt.debug = 0;
      opt.no_grab = 0;
      opt.debug_pinentry = 0;
      opt.def_cache_ttl = DEFAULT_CACHE_TTL;
      opt.max_cache_ttl = MAX_CACHE_TTL;
      opt.enforce_passphrase_constraints = 0;
      opt.min_passphrase_len = MIN_PASSPHRASE_LEN;
      opt.min_passphrase_nonalpha = MIN_PASSPHRASE_NONALPHA;
      opt.check_passphrase_pattern = NULL;
      opt.max_passphrase_days = MAX_PASSPHRASE_DAYS;
      opt.enable_passphrase_history = 0;
      opt.enable_extended_key_format = 0;
      opt.ignore_cache_for_signing = 0;
      opt.allow_mark_trusted = 1;
      opt.allow_external_cache = 1;
      opt.disable_scdaemon = 0;
      return 1;
    }

  switch (pargs->r_opt)
    {
    case oQuiet: opt.quiet = 1; break;
    case oVerbose: opt.verbose++; break;

    case oDebug:
      parse_debug_flag (pargs->r.ret_str, &opt.debug, debug_flags);
      break;
    case oDebugAll: opt.debug = ~0; break;
    case oDebugLevel: debug_level = pargs->r.ret_str; break;

    case oLogFile:
      if (!reread)
        return 0; /* not handeld */
      if (!current_logfile || !pargs->r.ret_str
          || strcmp (current_logfile, pargs->r.ret_str))
        {
          log_set_file (pargs->r.ret_str);
          xfree (current_logfile);
          current_logfile = xtrystrdup (pargs->r.ret_str);
        }
      break;

    case oDisableScdaemon: opt.disable_scdaemon = 1; break;

    case oDefCacheTTL: opt.def_cache_ttl = pargs->r.ret_ulong; break;
    case oMaxCacheTTL: opt.max_cache_ttl = pargs->r.ret_ulong; break;

    case oEnableExtendedKeyFormat:
      opt.enable_extended_key_format = 1;
      break;

    case oIgnoreCacheForSigning: opt.ignore_cache_for_signing = 1; break;

    case oAllowMarkTrusted: opt.allow_mark_trusted = 1; break;
    case oNoAllowMarkTrusted: opt.allow_mark_trusted = 0; break;

    case oNoAllowExternalCache: opt.allow_external_cache = 0;
      break;

    default:
      return 0; /* not handled */
    }

  return 1; /* handled */
}


/* Fixup some options after all have been processed.  */
static void
finalize_rereadable_options (void)
{
}


static void
thread_init_once (void)
{
  static int npth_initialized = 0;

  if (!npth_initialized)
    {
      npth_initialized++;
      npth_init ();
    }
  gpgrt_set_syscall_clamp (npth_unprotect, npth_protect);
  /* Now that we have set the syscall clamp we need to tell Libgcrypt
   * that it should get them from libgpg-error.  Note that Libgcrypt
   * has already been initialized but at that point nPth was not
   * initialized and thus Libgcrypt could not set its system call
   * clamp.  */
#if GCRYPT_VERSION_NUMBER >= 0x010800 /* 1.8.0 */
  gcry_control (GCRYCTL_REINIT_SYSCALL_CLAMP, 0, 0);
#endif
}


static void
initialize_modules (void)
{
  thread_init_once ();
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  initialize_module_cache ();
  initialize_module_call_pinentry ();
  initialize_module_call_scd ();
  initialize_module_trustlist ();
}


/* The main entry point.  */
int
agent_main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  FILE *configfp = NULL;
  char *configname = NULL;
  const char *shell;
  unsigned configlineno;
  int parse_debug = 0;
  int default_config =1;
  int pipe_server = 0;
  int is_daemon = 0;
  int nodetach = 0;
  int csh_style = 0;
  char *logfile = NULL;
  int debug_wait = 0;
  int gpgconf_list = 0;
  gpg_error_t err;
  struct assuan_malloc_hooks malloc_hooks;

  early_system_init ();

  /* Before we do anything else we save the list of currently open
     file descriptors and the signal mask.  This info is required to
     do the exec call properly.  We don't need it on Windows.  */
#ifdef HAVE_SIGPROCMASK
  if (!sigprocmask (SIG_UNBLOCK, NULL, &startup_signal_mask))
    startup_signal_mask_valid = 1;
#endif /*HAVE_SIGPROCMASK*/

  /* Set program name etc.  */
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix (GPG_AGENT_NAME, GPGRT_LOG_WITH_PREFIX|GPGRT_LOG_WITH_PID);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks (&malloc_hooks);
  assuan_sock_init ();
  setup_libassuan_logging (&opt.debug, NULL);

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  disable_core_dumps ();

  /* Set default options.  */
  parse_rereadable_options (NULL, 0); /* Reset them to default values. */

  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;

  /* Check whether we have a config file on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
        parse_debug++;
      else if (pargs.r_opt == oOptions)
        { /* yes there is one, so we do not try the default one, but
	     read the option file when it is encountered at the
	     commandline */
          default_config = 0;
	}
	else if (pargs.r_opt == oNoOptions)
          default_config = 0; /* --no-options */
	else if (pargs.r_opt == oHomedir)
          gnupg_set_homedir (pargs.r.ret_str);
    }

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_BUFFER_SIZE, 0);
  maybe_setuid = 0;

  /*
     Now we are now working under our real uid
  */

  if (default_config)
    configname = make_filename (gnupg_homedir (),
                                GPG_AGENT_NAME EXTSEP_S "conf", NULL);

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (default_config)
            {
              if( parse_debug )
                log_info (_("Note: no default option file '%s'\n"),
                          configname );
              /* Save the default conf file name so that
                 reread_configuration is able to test whether the
                 config file has been created in the meantime.  */
              xfree (config_filename);
              config_filename = configname;
              configname = NULL;
	    }
          else
            {
              log_error (_("option file '%s': %s\n"),
                         configname, strerror(errno) );
              exit(2);
	    }
          xfree (configname);
          configname = NULL;
	}
      if (parse_debug && configname )
        log_info (_("reading options from '%s'\n"), configname );
      default_config = 0;
    }

  while (optfile_parse( configfp, configname, &configlineno, &pargs, opts) )
    {
      if (parse_rereadable_options (&pargs, 0))
        continue; /* Already handled */
      switch (pargs.r_opt)
        {
        case aGPGConfList: gpgconf_list = 1; break;
        case aGPGConfTest: gpgconf_list = 2; break;
        case oBatch: opt.batch=1; break;

        case oOptions:
          /* config files may not be nested (silently ignore them) */
          if (!configfp)
            {
		xfree(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
          break;
        case oNoVerbose: opt.verbose = 0; break;
        case oNoOptions: break; /* no-options */
        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;
        case oNoDetach: nodetach = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oServer: pipe_server = 1; break;

        case oLCctype: default_lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: default_lc_messages = xstrdup (pargs.r.ret_str);
          break;

        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oWriteEnvFile:
          obsolete_option (configname, configlineno, "write-env-file");
          break;

        default : pargs.err = configfp? 1:2; break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      /* Keep a copy of the name so that it can be read on SIGHUP. */
      if (config_filename != configname)
        {
          xfree (config_filename);
          config_filename = configname;
        }
      configname = NULL;
      goto next_pass;
    }

  xfree (configname);
  configname = NULL;
  if (log_get_errorcount(0))
    exit(2);

  finalize_rereadable_options ();

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }

#ifdef ENABLE_NLS
  /* gpg-agent usually does not output any messages because it runs in
     the background.  For log files it is acceptable to have messages
     always encoded in utf-8.  We switch here to utf-8, so that
     commands like --help still give native messages.  It is far
     easier to switch only once instead of for every message and it
     actually helps when more then one thread is active (avoids an
     extra copy step). */
    bind_textdomain_codeset (PACKAGE_GT, "UTF-8");
#endif

  if (!pipe_server && !is_daemon && !gpgconf_list && !is_supervised)
    {
     /* We have been called without any command and thus we merely
        check whether an agent is already running.  We do this right
        here so that we don't clobber a logfile with this check but
        print the status directly to stderr. */
      opt.debug = 0;
      set_debug ();
      agent_exit (0);
    }


  set_debug ();

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  /* Try to create missing directories. */
  create_directories ();

  if (debug_wait && pipe_server)
    {
      thread_init_once ();
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      gnupg_sleep (debug_wait);
      log_debug ("... okay\n");
    }

  if (gpgconf_list == 3)
    {
      /* We now use the standard socket always - return true for
         backward compatibility.  */
      agent_exit (0);
    }
  else if (gpgconf_list == 2)
    agent_exit (0);
  else if (gpgconf_list)
    {
      char *filename;
      char *filename_esc;

      /* List options and default values in the GPG Conf format.  */
      filename = make_filename (gnupg_homedir (),
                                GPG_AGENT_NAME EXTSEP_S "conf", NULL);
      filename_esc = percent_escape (filename, NULL);

      es_printf ("%s-%s.conf:%lu:\"%s\n",
                 GPGCONF_NAME, GPG_AGENT_NAME,
                 GC_OPT_FLAG_DEFAULT, filename_esc);
      xfree (filename);
      xfree (filename_esc);

      es_printf ("verbose:%lu:\n"
              "quiet:%lu:\n"
              "debug-level:%lu:\"none:\n"
              "log-file:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME );
      es_printf ("default-cache-ttl:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, DEFAULT_CACHE_TTL );
      es_printf ("max-cache-ttl:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, MAX_CACHE_TTL );
      es_printf ("enforce-passphrase-constraints:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("min-passphrase-len:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, MIN_PASSPHRASE_LEN );
      es_printf ("min-passphrase-nonalpha:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              MIN_PASSPHRASE_NONALPHA);
      es_printf ("check-passphrase-pattern:%lu:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME);
      es_printf ("max-passphrase-days:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              MAX_PASSPHRASE_DAYS);
      es_printf ("enable-passphrase-history:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("no-grab:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("ignore-cache-for-signing:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("no-allow-external-cache:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("no-allow-mark-trusted:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("disable-scdaemon:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      es_printf ("pinentry-timeout:%lu:0:\n",
                 GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME);
      es_printf ("enable-extended-key-format:%lu:\n",
                 GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);

      agent_exit (0);
    }

  /* Now start with logging to a file if this is desired. */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX
                             | GPGRT_LOG_WITH_TIME
                             | GPGRT_LOG_WITH_PID));
      current_logfile = xstrdup (logfile);
    }

  if (pipe_server)
    {
      /* This is the simple pipe based server */
      ctrl_t ctrl;

      initialize_modules ();

      ctrl = (ctrl_t)xtrycalloc (1, sizeof *ctrl);
      if (!ctrl)
        {
          log_error ("error allocating connection control data: %s\n",
                     strerror (errno) );
          agent_exit (1);
        }
      agent_init_default_ctrl (ctrl);
      start_command_handler (ctrl);
      agent_deinit_default_ctrl (ctrl);
      xfree (ctrl);
    }
  else if (!is_daemon)
    ; /* NOTREACHED */

  return 0;
}


/* Exit entry point.  This function should be called instead of a
   plain exit.  */
void
agent_exit (int rc)
{
  /*FIXME: update_random_seed_file();*/

  /* We run our cleanup handler because that may close cipher contexts
     stored in secure memory and thus this needs to be done before we
     explicitly terminate secure memory.  */
  cleanup ();

#if 1
  /* at this time a bit annoying */
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
#endif
  gcry_control (GCRYCTL_TERM_SECMEM );
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


/* Each thread has its own local variables conveyed by a control
   structure usually identified by an argument named CTRL.  This
   function is called immediately after allocating the control
   structure.  Its purpose is to setup the default values for that
   structure.  Note that some values may have already been set.  */
static void
agent_init_default_ctrl (ctrl_t ctrl)
{
  if (ctrl->lc_ctype)
    xfree (ctrl->lc_ctype);
  ctrl->lc_ctype = default_lc_ctype? xtrystrdup (default_lc_ctype) : NULL;

  if (ctrl->lc_messages)
    xfree (ctrl->lc_messages);
  ctrl->lc_messages = default_lc_messages? xtrystrdup (default_lc_messages)
                                    /**/ : NULL;
}


/* Release all resources allocated by default in the control
   structure.  This is the counterpart to agent_init_default_ctrl.  */
static void
agent_deinit_default_ctrl (ctrl_t ctrl)
{
  if (ctrl->lc_ctype)
    xfree (ctrl->lc_ctype);
  if (ctrl->lc_messages)
    xfree (ctrl->lc_messages);
}


/* Return the number of active connections. */
int
get_agent_active_connection_count (void)
{
  return active_connections;
}


/* Under W32, this function returns the handle of the scdaemon
   notification event.  Calling it the first time creates that
   event.  */
#if defined(HAVE_W32_SYSTEM)
void *
get_agent_scd_notify_event (void)
{
  static HANDLE the_event = INVALID_HANDLE_VALUE;

  if (the_event == INVALID_HANDLE_VALUE)
    {
      HANDLE h, h2;
      SECURITY_ATTRIBUTES sa = { sizeof (SECURITY_ATTRIBUTES), NULL, TRUE};

      /* We need to use a manual reset event object due to the way our
         w32-pth wait function works: If we would use an automatic
         reset event we are not able to figure out which handle has
         been signaled because at the time we single out the signaled
         handles using WFSO the event has already been reset due to
         the WFMO.  */
      h = CreateEvent (&sa, TRUE, FALSE, NULL);
      if (!h)
        log_error ("can't create scd notify event: %s\n", w32_strerror (-1) );
      else if (!DuplicateHandle (GetCurrentProcess(), h,
                                 GetCurrentProcess(), &h2,
                                 EVENT_MODIFY_STATE|SYNCHRONIZE, TRUE, 0))
        {
          log_error ("setting syncronize for scd notify event failed: %s\n",
                     w32_strerror (-1) );
          CloseHandle (h);
        }
      else
        {
          CloseHandle (h);
          the_event = h2;
        }
    }

  return the_event;
}
#endif /*HAVE_W32_SYSTEM */



/* Check that the directory for storing the private keys exists and
   create it if not.  This function won't fail as it is only a
   convenience function and not strictly necessary.  */
static void
create_private_keys_directory (const char *home)
{
  char *fname;
  struct stat statbuf;

  fname = make_filename (home, GNUPG_PRIVATE_KEYS_DIR, NULL);
  if (stat (fname, &statbuf) && errno == ENOENT)
    {
      if (gnupg_mkdir (fname, "-rwx"))
        log_error (_("can't create directory '%s': %s\n"),
                   fname, strerror (errno) );
      else if (!opt.quiet)
        log_info (_("directory '%s' created\n"), fname);
    }
  if (gnupg_chmod (fname, "-rwx"))
    log_error (_("can't set permissions of '%s': %s\n"),
               fname, strerror (errno));
  xfree (fname);
}


/* Create the directory only if the supplied directory name is the
   same as the default one.  This way we avoid to create arbitrary
   directories when a non-default home directory is used.  To cope
   with HOME, we compare only the suffix if we see that the default
   homedir does start with a tilde.  We don't stop here in case of
   problems because other functions will throw an error anyway.*/
static void
create_directories (void)
{
  struct stat statbuf;
  const char *defhome = standard_homedir ();
  char *home;

  home = make_filename (gnupg_homedir (), NULL);
  if ( stat (home, &statbuf) )
    {
      if (errno == ENOENT)
        {
          if (
#ifdef HAVE_W32_SYSTEM
              ( !compare_filenames (home, defhome) )
#else
              (*defhome == '~'
                && (strlen (home) >= strlen (defhome+1)
                    && !strcmp (home + strlen(home)
                                - strlen (defhome+1), defhome+1)))
               || (*defhome != '~' && !strcmp (home, defhome) )
#endif
               )
            {
              if (gnupg_mkdir (home, "-rwx"))
                log_error (_("can't create directory '%s': %s\n"),
                           home, strerror (errno) );
              else
                {
                  if (!opt.quiet)
                    log_info (_("directory '%s' created\n"), home);
                  create_private_keys_directory (home);
                }
            }
        }
      else
        log_error (_("stat() failed for '%s': %s\n"), home, strerror (errno));
    }
  else if ( !S_ISDIR(statbuf.st_mode))
    {
      log_error (_("can't use '%s' as home directory\n"), home);
    }
  else /* exists and is a directory. */
    {
      create_private_keys_directory (home);
    }
  xfree (home);
}



