/* call-pinentry.c - Spawn the pinentry to query stuff from the user
 * Copyright (C) 2001, 2002, 2004, 2007, 2008,
 *               2010  Free Software Foundation, Inc.
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

#include <assert.h>
#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#endif
#include <npth.h>

#include <assuan.h>
#include "../common/sysutils.h"
#include "agent.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

/* Because access to the pinentry must be serialized (it is and shall
   be a global mutually exclusive dialog) we better timeout pending
   requests after some time.  1 minute seem to be a reasonable
   time. */
#define LOCK_TIMEOUT (1 * 60)

/* The assuan context of the current pinentry. */
static assuan_context_t entry_ctx;

/* A list of features of the current pinentry.  */
static struct {
  /* The Pinentry support RS+US tabbing.  This means that a RS (0x1e)
   * starts a new tabbing block in which a US (0x1f) followed by a
   * colon marks a colon.  A pinentry can use this to pretty print
   * name value pairs.  */
  unsigned int tabbing : 1;
} entry_features;

/* The control variable of the connection owning the current pinentry.
   This is only valid if ENTRY_CTX is not NULL.  Note, that we care
   only about the value of the pointer and that it should never be
   dereferenced.  */
static ctrl_t entry_owner;

/* A mutex used to serialize access to the pinentry. */
static npth_mutex_t entry_lock;

/* The thread ID of the popup working thread. */
static npth_t popup_tid;

/* A flag used in communication between the popup working thread and
   its stop function. */
static int popup_finished;

/* Data to be passed to our callbacks, */
struct entry_parm_s {
  int lines;
  size_t size;
  unsigned char *buffer;
};

/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
void initialize_module_call_pinentry(void) {
  static int initialized;

  if (!initialized) {
    if (npth_mutex_init(&entry_lock, NULL)) initialized = 1;
  }
}

/* This function may be called to print information pertaining to the
   current state of this module to the log. */
void agent_query_dump_state(void) {
  log_info("agent_query_dump_state: entry_ctx=%p pid=%ld popup_tid=%p\n",
           entry_ctx, (long)assuan_get_pid(entry_ctx), (void *)popup_tid);
}

/* Called to make sure that a popup window owned by the current
   connection gets closed. */
void agent_reset_query(ctrl_t ctrl) {
  if (entry_ctx && popup_tid && entry_owner == ctrl) {
    agent_popup_message_stop(ctrl);
  }
}

/* Unlock the pinentry so that another thread can start one and
   disconnect that pinentry - we do this after the unlock so that a
   stalled pinentry does not block other threads.  Fixme: We should
   have a timeout in Assuan for the disconnect operation. */
static gpg_error_t unlock_pinentry(gpg_error_t rc) {
  assuan_context_t ctx = entry_ctx;
  int err;

  if (rc) {
    if (DBG_IPC) log_debug("error calling pinentry: %s\n", gpg_strerror(rc));
  }

  entry_ctx = NULL;
  err = npth_mutex_unlock(&entry_lock);
  if (err) {
    log_error("failed to release the entry lock: %s\n", strerror(err));
    if (!rc) rc = gpg_error_from_errno(err);
  }
  assuan_release(ctx);
  return rc;
}

/* Status line callback for the FEATURES status.  */
static gpg_error_t getinfo_features_cb(void *opaque, const char *line) {
  const char *args;
  char **tokens;
  int i;

  (void)opaque;

  if ((args = has_leading_keyword(line, "FEATURES"))) {
    tokens = strtokenize(args, " ");
    if (!tokens) return gpg_error_from_syserror();
    for (i = 0; tokens[i]; i++)
      if (!strcmp(tokens[i], "tabbing")) entry_features.tabbing = 1;
    xfree(tokens);
  }

  return 0;
}

static gpg_error_t getinfo_pid_cb(void *opaque, const void *buffer,
                                  size_t length) {
  unsigned long *pid = (long unsigned int *)opaque;
  char pidbuf[50];

  /* There is only the pid in the server's response.  */
  if (length >= sizeof pidbuf) length = sizeof pidbuf - 1;
  if (length) {
    strncpy(pidbuf, (const char *)(buffer), length);
    pidbuf[length] = 0;
    *pid = strtoul(pidbuf, NULL, 10);
  }
  return 0;
}

enum {
  PINENTRY_STATUS_CLOSE_BUTTON = 1 << 0,
  PINENTRY_STATUS_PIN_REPEATED = 1 << 8,
  PINENTRY_STATUS_PASSWORD_FROM_CACHE = 1 << 9
};

/* Check the button_info line for a close action.  Also check for the
   PIN_REPEATED flag.  */
static gpg_error_t pinentry_status_cb(void *opaque, const char *line) {
  unsigned int *flag = (unsigned int *)opaque;
  const char *args;

  if ((args = has_leading_keyword(line, "BUTTON_INFO"))) {
    if (!strcmp(args, "close")) *flag |= PINENTRY_STATUS_CLOSE_BUTTON;
  } else if (has_leading_keyword(line, "PIN_REPEATED")) {
    *flag |= PINENTRY_STATUS_PIN_REPEATED;
  } else if (has_leading_keyword(line, "PASSWORD_FROM_CACHE")) {
    *flag |= PINENTRY_STATUS_PASSWORD_FROM_CACHE;
  }

  return 0;
}

/* Build a SETDESC command line.  This is a dedicated function so that
 * it can remove control characters which are not supported by the
 * current Pinentry.  */
static void build_cmd_setdesc(char *line, size_t linelen, const char *desc) {
  char *src, *dst;

  snprintf(line, linelen, "SETDESC %s", desc);
  if (!entry_features.tabbing) {
    /* Remove RS and US.  */
    for (src = dst = line; *src; src++)
      if (!strchr("\x1e\x1f", *src)) *dst++ = *src;
    *dst = 0;
  }
}

/* Call the Entry and ask for the PIN.  We do check for a valid PIN
   number here and repeat it as long as we have invalid formed
   numbers.  KEYINFO and CACHE_MODE are used to tell pinentry something
   about the key. */
gpg_error_t agent_askpin(ctrl_t ctrl, const char *desc_text,
                         const char *prompt_text, const char *initial_errtext,
                         struct pin_entry_info_s *pininfo, const char *keyinfo,
                         cache_mode_t cache_mode) {
  gpg_error_t rc;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;
  const char *errtext = NULL;
  int is_pin = 0;
  int saveflag;
  unsigned int pinentry_status;

  if (opt.batch) return 0; /* fixme: we should return BAD PIN */

  {
    unsigned char *passphrase;
    size_t size;

    *pininfo->pin = 0; /* Reset the PIN. */
    rc = pinentry_loopback(ctrl, "PASSPHRASE", &passphrase, &size,
                           pininfo->max_length - 1);
    if (rc) return rc;

    memcpy(&pininfo->pin, passphrase, size);
    xfree(passphrase);
    pininfo->pin[size] = 0;
    if (pininfo->check_cb) {
      /* More checks by utilizing the optional callback. */
      pininfo->cb_errtext = NULL;
      rc = pininfo->check_cb(pininfo);
    }
    return rc;
  }

#if 0
  if (!pininfo || pininfo->max_length < 1)
    return GPG_ERR_INV_VALUE;
  if (!desc_text && pininfo->min_digits)
    desc_text = L_("Please enter your PIN, so that the secret key "
                   "can be unlocked for this session");
  else if (!desc_text)
    desc_text = L_("Please enter your passphrase, so that the secret key "
                   "can be unlocked for this session");

  if (prompt_text)
    is_pin = !!strstr (prompt_text, "PIN");
  else
    is_pin = desc_text && strstr (desc_text, "PIN");

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  /* If we have a KEYINFO string and are normal, user, or ssh cache
     mode, we tell that the Pinentry so it may use it for own caching
     purposes.  Most pinentries won't have this implemented and thus
     we do not error out in this case.  */
  if (keyinfo && (cache_mode == CACHE_MODE_NORMAL
                  || cache_mode == CACHE_MODE_USER
                  || cache_mode == CACHE_MODE_SSH))
    snprintf (line, DIM(line), "SETKEYINFO %c/%s",
	      cache_mode == CACHE_MODE_USER? 'u' :
	      cache_mode == CACHE_MODE_SSH? 's' : 'n',
	      keyinfo);
  else
    snprintf (line, DIM(line), "SETKEYINFO --clear");

  rc = assuan_transact (entry_ctx, line,
			NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc && rc != GPG_ERR_ASS_UNKNOWN_CMD)
    return unlock_pinentry (rc);

  build_cmd_setdesc (line, DIM(line), desc_text);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  snprintf (line, DIM(line), "SETPROMPT %s",
            prompt_text? prompt_text : is_pin? L_("PIN:") : L_("Passphrase:"));
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  if (initial_errtext)
    {
      snprintf (line, DIM(line), "SETERROR %s", initial_errtext);
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  if (pininfo->with_repeat)
    {
      snprintf (line, DIM(line), "SETREPEATERROR %s",
                L_("does not match - try again"));
      rc = assuan_transact (entry_ctx, line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        pininfo->with_repeat = 0; /* Pinentry does not support it.  */
    }
  pininfo->repeat_okay = 0;

  for (;pininfo->failed_tries < pininfo->max_tries; pininfo->failed_tries++)
    {
      memset (&parm, 0, sizeof parm);
      parm.size = pininfo->max_length;
      *pininfo->pin = 0; /* Reset the PIN. */
      parm.buffer = (unsigned char*)pininfo->pin;

      if (errtext)
        {
          /* TRANSLATORS: The string is appended to an error message in
             the pinentry.  The %s is the actual error message, the
             two %d give the current and maximum number of tries. */
          snprintf (line, DIM(line), L_("SETERROR %s (try %d of %d)"),
                    errtext, pininfo->failed_tries+1, pininfo->max_tries);
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (rc);
          errtext = NULL;
        }

      if (pininfo->with_repeat)
        {
          snprintf (line, DIM(line), "SETREPEAT %s", L_("Repeat:"));
          rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
          if (rc)
            return unlock_pinentry (rc);
        }

      saveflag = assuan_get_flag (entry_ctx, ASSUAN_CONFIDENTIAL);
      assuan_begin_confidential (entry_ctx);
      pinentry_status = 0;
      rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, &parm,
                            NULL, entry_ctx,
                            pinentry_status_cb, &pinentry_status);
      assuan_set_flag (entry_ctx, ASSUAN_CONFIDENTIAL, saveflag);
      /* Most pinentries out in the wild return the old Assuan error code
         for canceled which gets translated to an assuan Cancel error and
         not to the code for a user cancel.  Fix this here. */
      if (rc == GPG_ERR_ASS_CANCELED)
        rc = GPG_ERR_CANCELED;


      /* Change error code in case the window close button was clicked
         to cancel the operation.  */
      if ((pinentry_status & PINENTRY_STATUS_CLOSE_BUTTON)
	  && rc == GPG_ERR_CANCELED)
        rc = GPG_ERR_FULLY_CANCELED;

      if (rc == GPG_ERR_ASS_TOO_MUCH_DATA)
        errtext = is_pin? L_("PIN too long")
                        : L_("Passphrase too long");
      else if (rc)
        return unlock_pinentry (rc);

      if (!errtext && pininfo->min_digits)
        {
          /* do some basic checks on the entered PIN. */
          if (!all_digitsp (pininfo->pin))
            errtext = L_("Invalid characters in PIN");
          else if (pininfo->max_digits
                   && strlen (pininfo->pin) > pininfo->max_digits)
            errtext = L_("PIN too long");
          else if (strlen (pininfo->pin) < pininfo->min_digits)
            errtext = L_("PIN too short");
        }

      if (!errtext && pininfo->check_cb)
        {
          /* More checks by utilizing the optional callback. */
          pininfo->cb_errtext = NULL;
          rc = pininfo->check_cb (pininfo);
          if (rc == GPG_ERR_BAD_PASSPHRASE
              && pininfo->cb_errtext)
            errtext = pininfo->cb_errtext;
          else if (rc == GPG_ERR_BAD_PASSPHRASE
                   || rc == GPG_ERR_BAD_PIN)
            errtext = (is_pin? L_("Bad PIN") : L_("Bad Passphrase"));
          else if (rc)
            return unlock_pinentry (rc);
        }

      if (!errtext)
        {
          if (pininfo->with_repeat
	      && (pinentry_status & PINENTRY_STATUS_PIN_REPEATED))
            pininfo->repeat_okay = 1;
          return unlock_pinentry (0); /* okay, got a PIN or passphrase */
        }

      if ((pinentry_status & PINENTRY_STATUS_PASSWORD_FROM_CACHE))
	/* The password was read from the cache.  Don't count this
	   against the retry count.  */
	pininfo->failed_tries --;
    }

  return unlock_pinentry (pininfo->min_digits? GPG_ERR_BAD_PIN
                          : GPG_ERR_BAD_PASSPHRASE);
#endif
}

/* Ask for the passphrase using the supplied arguments.  The returned
   passphrase needs to be freed by the caller. */
int agent_get_passphrase(ctrl_t ctrl, char **retpass, const char *desc,
                         const char *prompt, const char *errtext,
                         const char *keyinfo, cache_mode_t cache_mode) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct entry_parm_s parm;
  int saveflag;
  unsigned int pinentry_status;

  *retpass = NULL;
  if (opt.batch) return GPG_ERR_BAD_PASSPHRASE;

  {
    size_t size;

    return pinentry_loopback(ctrl, "PASSPHRASE", (unsigned char **)retpass,
                             &size, MAX_PASSPHRASE_LEN);
  }

#if 0
  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (!prompt)
    prompt = desc && strstr (desc, "PIN")? L_("PIN:"): L_("Passphrase:");


  /* If we have a KEYINFO string and are normal, user, or ssh cache
     mode, we tell that the Pinentry so it may use it for own caching
     purposes.  Most pinentries won't have this implemented and thus
     we do not error out in this case.  */
  if (keyinfo && (cache_mode == CACHE_MODE_NORMAL
                  || cache_mode == CACHE_MODE_USER
                  || cache_mode == CACHE_MODE_SSH))
    snprintf (line, DIM(line), "SETKEYINFO %c/%s",
	      cache_mode == CACHE_MODE_USER? 'u' :
	      cache_mode == CACHE_MODE_SSH? 's' : 'n',
	      keyinfo);
  else
    snprintf (line, DIM(line), "SETKEYINFO --clear");

  rc = assuan_transact (entry_ctx, line,
			NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc && rc != GPG_ERR_ASS_UNKNOWN_CMD)
    return unlock_pinentry (rc);


  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  snprintf (line, DIM(line), "SETPROMPT %s", prompt);
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  if (errtext)
    {
      snprintf (line, DIM(line), "SETERROR %s", errtext);
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  memset (&parm, 0, sizeof parm);
  parm.size = ASSUAN_LINELENGTH/2 - 5;
  parm.buffer = (unsigned char*) gcry_malloc_secure (parm.size+10);
  if (!parm.buffer)
    return unlock_pinentry (gpg_error_from_syserror ());

  saveflag = assuan_get_flag (entry_ctx, ASSUAN_CONFIDENTIAL);
  assuan_begin_confidential (entry_ctx);
  pinentry_status = 0;
  rc = assuan_transact (entry_ctx, "GETPIN", getpin_cb, &parm,
                        NULL, entry_ctx,
                        pinentry_status_cb, &pinentry_status);
  assuan_set_flag (entry_ctx, ASSUAN_CONFIDENTIAL, saveflag);
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc == GPG_ERR_ASS_CANCELED)
    rc = GPG_ERR_CANCELED;
  /* Change error code in case the window close button was clicked
     to cancel the operation.  */
  if ((pinentry_status & PINENTRY_STATUS_CLOSE_BUTTON)
      && rc == GPG_ERR_CANCELED)
    rc = GPG_ERR_FULLY_CANCELED;

  if (rc)
    xfree (parm.buffer);
  else
    *retpass = (char*) parm.buffer;
  return unlock_pinentry (rc);
#endif
}

/* Pop up the PIN-entry, display the text and the prompt and ask the
   user to confirm this.  We return 0 for success, ie. the user
   confirmed it, GPG_ERR_NOT_CONFIRMED for what the text says or an
   other error.  If WITH_CANCEL it true an extra cancel button is
   displayed to allow the user to easily return a GPG_ERR_CANCELED.
   if the Pinentry does not support this, the user can still cancel by
   closing the Pinentry window.  */
int agent_get_confirmation(ctrl_t ctrl, const char *desc, const char *ok,
                           const char *notok, int with_cancel) {
  int rc;
  char line[ASSUAN_LINELENGTH];

  return GPG_ERR_NO_PIN_ENTRY;

#if 0
  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc && rc == GPG_ERR_ASS_CANCELED)
    rc = GPG_ERR_CANCELED;

  if (rc)
    return unlock_pinentry (rc);

  if (ok)
    {
      snprintf (line, DIM(line), "SETOK %s", ok);
      rc = assuan_transact (entry_ctx,
                            line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }
  if (notok)
    {
      /* Try to use the newer NOTOK feature if a cancel button is
         requested.  If no cancel button is requested we keep on using
         the standard cancel.  */
      if (with_cancel)
        {
          snprintf (line, DIM(line), "SETNOTOK %s", notok);
          rc = assuan_transact (entry_ctx,
                                line, NULL, NULL, NULL, NULL, NULL, NULL);
        }
      else
        rc = GPG_ERR_ASS_UNKNOWN_CMD;

      if (rc == GPG_ERR_ASS_UNKNOWN_CMD)
	{
	  snprintf (line, DIM(line), "SETCANCEL %s", notok);
	  rc = assuan_transact (entry_ctx, line,
                                NULL, NULL, NULL, NULL, NULL, NULL);
	}
      if (rc)
        return unlock_pinentry (rc);
    }

  rc = assuan_transact (entry_ctx, "CONFIRM",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc == GPG_ERR_ASS_CANCELED)
    rc = GPG_ERR_CANCELED;

  return unlock_pinentry (rc);
#endif
}

/* Pop up the PINentry, display the text DESC and a button with the
   text OK_BTN (which may be NULL to use the default of "OK") and wait
   for the user to hit this button.  The return value is not
   relevant.  */
int agent_show_message(ctrl_t ctrl, const char *desc, const char *ok_btn) {
  int rc;
  char line[ASSUAN_LINELENGTH];

  return GPG_ERR_CANCELED;

#if 0  
  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  /* Most pinentries out in the wild return the old Assuan error code
     for canceled which gets translated to an assuan Cancel error and
     not to the code for a user cancel.  Fix this here. */
  if (rc == GPG_ERR_ASS_CANCELED)
    rc = GPG_ERR_CANCELED;

  if (rc)
    return unlock_pinentry (rc);

  if (ok_btn)
    {
      snprintf (line, DIM(line), "SETOK %s", ok_btn);
      rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL,
                            NULL, NULL, NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  rc = assuan_transact (entry_ctx, "CONFIRM --one-button", NULL, NULL, NULL,
                        NULL, NULL, NULL);
  if (rc == GPG_ERR_ASS_CANCELED)
    rc = GPG_ERR_CANCELED;

  return unlock_pinentry (rc);
#endif
}

/* The thread running the popup message. */
static void *popup_message_thread(void *arg) {
  (void)arg;

  /* We use the --one-button hack instead of the MESSAGE command to
     allow the use of old Pinentries.  Those old Pinentries will then
     show an additional Cancel button but that is mostly a visual
     annoyance. */
  assuan_transact(entry_ctx, "CONFIRM --one-button", NULL, NULL, NULL, NULL,
                  NULL, NULL);
  popup_finished = 1;
  return NULL;
}

/* Pop up a message window similar to the confirm one but keep it open
   until agent_popup_message_stop has been called.  It is crucial for
   the caller to make sure that the stop function gets called as soon
   as the message is not anymore required because the message is
   system modal and all other attempts to use the pinentry will fail
   (after a timeout). */
int agent_popup_message_start(ctrl_t ctrl, const char *desc,
                              const char *ok_btn) {
  int rc;
  char line[ASSUAN_LINELENGTH];
  npth_attr_t tattr;
  int err;

  return GPG_ERR_CANCELED;

#if 0
  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  if (desc)
    build_cmd_setdesc (line, DIM(line), desc);
  else
    snprintf (line, DIM(line), "RESET");
  rc = assuan_transact (entry_ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    return unlock_pinentry (rc);

  if (ok_btn)
    {
      snprintf (line, DIM(line), "SETOK %s", ok_btn);
      rc = assuan_transact (entry_ctx, line, NULL,NULL,NULL,NULL,NULL,NULL);
      if (rc)
        return unlock_pinentry (rc);
    }

  err = npth_attr_init (&tattr);
  if (err)
    return unlock_pinentry (gpg_error_from_errno (err));
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  popup_finished = 0;
  err = npth_create (&popup_tid, &tattr, popup_message_thread, NULL);
  npth_attr_destroy (&tattr);
  if (err)
    {
      rc = gpg_error_from_errno (err);
      log_error ("error spawning popup message handler: %s\n",
                 strerror (err) );
      return unlock_pinentry (rc);
    }
  npth_setname_np (popup_tid, "popup-message");

  return 0;
#endif
}

/* Close a popup window. */
void agent_popup_message_stop(ctrl_t ctrl) {
  int rc;
  pid_t pid;

  (void)ctrl;

  return;
#if 0
  if (!popup_tid || !entry_ctx) {
    log_debug("agent_popup_message_stop called with no active popup\n");
    return;
  }

  pid = assuan_get_pid(entry_ctx);
  if (pid == (pid_t)(-1))
    ; /* No pid available can't send a kill. */
  else if (popup_finished)
    ; /* Already finished and ready for joining. */
#ifdef HAVE_W32_SYSTEM
  /* Older versions of assuan set PID to 0 on Windows to indicate an
     invalid value.  */
  else if (pid != (pid_t)INVALID_HANDLE_VALUE && pid != 0) {
    HANDLE process = (HANDLE)pid;

    /* Arbitrary error code.  */
    TerminateProcess(process, 1);
  }
#else
  else if (pid && ((rc = waitpid(pid, NULL, WNOHANG)) == -1 ||
                   (rc == pid))) { /* The daemon already died.  No need to send
                                      a kill.  However
                                      because we already waited for the process,
                                      we need to tell
                                      assuan that it should not wait again (done
                                      by
                                      unlock_pinentry). */
    if (rc == pid) assuan_set_flag(entry_ctx, ASSUAN_NO_WAITPID, 1);
  } else if (pid > 0)
    kill(pid, SIGINT);
#endif

  /* Now wait for the thread to terminate. */
  rc = npth_join(popup_tid, NULL);
  if (rc)
    log_debug("agent_popup_message_stop: pth_join failed: %s\n", strerror(rc));
  /* Thread IDs are opaque, but we try our best here by resetting it
     to the same content that a static global variable has.  */
  memset(&popup_tid, '\0', sizeof(popup_tid));
  entry_owner = NULL;

  /* Now we can close the connection. */
  unlock_pinentry(0);
#endif
}

int agent_clear_passphrase(ctrl_t ctrl, const char *keyinfo,
                           cache_mode_t cache_mode) {
#if 0
  int rc;
  char line[ASSUAN_LINELENGTH];

  if (! (keyinfo && (cache_mode == CACHE_MODE_NORMAL
		     || cache_mode == CACHE_MODE_USER
		     || cache_mode == CACHE_MODE_SSH)))
    return GPG_ERR_NOT_SUPPORTED;

  rc = start_pinentry (ctrl);
  if (rc)
    return rc;

  snprintf (line, DIM(line), "CLEARPASSPHRASE %c/%s",
	    cache_mode == CACHE_MODE_USER? 'u' :
	    cache_mode == CACHE_MODE_SSH? 's' : 'n',
	    keyinfo);
  rc = assuan_transact (entry_ctx, line,
			NULL, NULL, NULL, NULL, NULL, NULL);

  return unlock_pinentry (rc);
#endif
  return 0;
}
