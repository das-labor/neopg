/* gpgcempr.c - Manager for GPG CE devices
   Copyright (C) 2010 Free Software Foundation, Inc.

   This file is part of Assuan.

   Assuan is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 3 of
   the License, or (at your option) any later version.

   Assuan is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define _WIN32_WCE 0x0500

#include <stdio.h>
#include <windows.h>

#define PGM "gpgcemgr"

#define GPGCEDEV_KEY_NAME  L"Drivers\\GnuPG_Device"
#define GPGCEDEV_KEY_NAME2 L"Drivers\\GnuPG_Log"
#define GPGCEDEV_DLL_NAME  L"gpgcedev.dll"
#define GPGCEDEV_PREFIX    L"GPG"


static char *
wchar_to_utf8 (const wchar_t *string)
{
  int n;
  size_t length = wcslen (string);
  char *result;

  n = WideCharToMultiByte (CP_UTF8, 0, string, length, NULL, 0, NULL, NULL);
  if (n < 0 || (n+1) <= 0)
    abort ();

  result = malloc (n+1);
  if (!result)
    abort ();
  n = WideCharToMultiByte (CP_ACP, 0, string, length, result, n, NULL, NULL);
  if (n < 0)
    abort ();
  
  result[n] = 0;
  return result;
}


static wchar_t *
utf8_to_wchar (const char *string)
{
  int n;
  size_t nbytes;
  wchar_t *result;

  if (!string)
    abort ();

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, NULL, 0);
  if (n < 0)
    abort ();
  nbytes = (size_t)(n+1) * sizeof(*result);
  if (nbytes / sizeof(*result) != (n+1)) 
    abort ();
  result = malloc (nbytes);
  if (!result)
    abort ();

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, result, n);
  if (n < 0)
    abort ();
  return result;
}


static int
install (void)
{
  HKEY handle;
  DWORD disp, dw;
  int rc;
  
  if ((rc=RegCreateKeyEx (HKEY_LOCAL_MACHINE, GPGCEDEV_KEY_NAME, 0, NULL, 0,
                          KEY_WRITE, NULL, &handle, &disp)))
    {
      fprintf (stderr, PGM": error creating registry key 1: rc=%d\n", rc);
      return 1;
    }

  RegSetValueEx (handle, L"dll", 0, REG_SZ, 
                 (void*)GPGCEDEV_DLL_NAME, sizeof (GPGCEDEV_DLL_NAME));
  RegSetValueEx (handle, L"prefix", 0, REG_SZ,
                 (void*)GPGCEDEV_PREFIX, sizeof (GPGCEDEV_PREFIX));

  dw = 1;
  RegSetValueEx (handle, L"Index", 0, REG_DWORD, (void*)&dw, sizeof dw);
  
  RegCloseKey (handle);

  fprintf (stderr, PGM": registry key 1 created\n");

  if ((rc=RegCreateKeyEx (HKEY_LOCAL_MACHINE, GPGCEDEV_KEY_NAME2, 0, NULL, 0,
                          KEY_WRITE, NULL, &handle, &disp)))
    {
      fprintf (stderr, PGM": error creating registry key 2: rc=%d\n", rc);
      return 1;
    }

  RegSetValueEx (handle, L"dll", 0, REG_SZ, 
                 (void*)GPGCEDEV_DLL_NAME, sizeof (GPGCEDEV_DLL_NAME));
  RegSetValueEx (handle, L"prefix", 0, REG_SZ,
                 (void*)GPGCEDEV_PREFIX, sizeof (GPGCEDEV_PREFIX));

  dw = 2;
  RegSetValueEx (handle, L"Index", 0, REG_DWORD, (void*)&dw, sizeof dw);
  
  RegCloseKey (handle);

  fprintf (stderr, PGM": registry key 2 created\n");


  return 0;
}


static int
deinstall (wchar_t *name)
{
  int result = 0;
  HANDLE shd;
  DEVMGR_DEVICE_INFORMATION dinfo;

  memset (&dinfo, 0, sizeof dinfo);
  dinfo.dwSize = sizeof dinfo;
  shd = FindFirstDevice (DeviceSearchByLegacyName, name, &dinfo);
  if (shd == INVALID_HANDLE_VALUE)
    {
      if (GetLastError () == 18)
        fprintf (stderr, PGM": device not found\n");
      else
        {
          fprintf (stderr, PGM": FindFirstDevice failed: rc=%d\n", 
                   (int)GetLastError ());
          result = 1;
        }
    }
  else
    {
      fprintf (stderr, PGM": ActivateDevice handle is %p\n", dinfo.hDevice);
      if (dinfo.hDevice && dinfo.hDevice != INVALID_HANDLE_VALUE)
        {
          if (!DeactivateDevice (dinfo.hDevice))
            {
              fprintf (stderr, PGM": DeactivateDevice failed: rc=%d\n",
                       (int)GetLastError ());
              result = 1;
            }
          else
            fprintf (stderr, PGM": DeactivateDevice succeeded\n");
        }
      FindClose (shd);
    }

  return result;
}


static int
enable_debug (int yes)
{
  HKEY handle;
  DWORD disp;
  int rc;
  
  if ((rc=RegCreateKeyEx (HKEY_LOCAL_MACHINE, GPGCEDEV_KEY_NAME, 0, NULL, 0,
                          KEY_WRITE, NULL, &handle, &disp)))
    {
      fprintf (stderr, PGM": error creating debug registry key: rc=%d\n", rc);
      return 1;
    }
  
  RegSetValueEx (handle, L"debugDriver", 0, REG_SZ, 
                 (void*)(yes? L"1":L"0"), sizeof L"0");
  RegCloseKey (handle);
  return 0;
}


static int
enable_log (int yes)
{
  HKEY handle;
  DWORD disp;
  int rc;
  
  if ((rc=RegCreateKeyEx (HKEY_LOCAL_MACHINE, GPGCEDEV_KEY_NAME2, 0, NULL, 0,
                          KEY_WRITE, NULL, &handle, &disp)))
    {
      fprintf (stderr, PGM": error creating debug registry key: rc=%d\n", rc);
      return 1;
    }
  
  RegSetValueEx (handle, L"enableLog", 0, REG_SZ, 
                 (void*)(yes? L"1":L"0"), sizeof L"0");
  RegCloseKey (handle);
  return 0;
}



/* Kudos to Scott Seligman <scott@scottandmichelle.net> for his work
   on the reverse engineering.  */
struct htc_sensor_s
{
  SHORT   tilt_x;         // From -1000 to 1000 (about), 0 is flat
  SHORT   tilt_y;         // From -1000 to 1000 (about), 0 is flat
  SHORT   tilt_z;         // From -1000 to 1000 (about)
  DWORD   angle_x;        // 0 .. 359
  DWORD   angle_y;        // From 0 to 359
  DWORD   orientation;    // 0.. 5?
  DWORD   unknown;        // Handle?
};
typedef struct htc_sensor_s *htc_sensor_t;

static HANDLE (WINAPI *HTCSensorOpen) (DWORD);
static void   (WINAPI *HTCSensorClose) (HANDLE);
static DWORD  (WINAPI *HTCSensorGetDataOutput) (HANDLE, htc_sensor_t);

static int
load_sensor_api (void)
{
  static HMODULE dll_hd;

  if (dll_hd)
    return 0;

  dll_hd = LoadLibrary (L"HTCSensorSDK.dll");
  if (!dll_hd)
    {
      fprintf (stderr, PGM": error loading sensor DLL: rc=%d\n",
               (int)GetLastError ());
      return 1;
    }

  HTCSensorOpen = (void*)GetProcAddress (dll_hd, L"HTCSensorOpen");
  if (HTCSensorOpen)
    HTCSensorClose = (void*)GetProcAddress (dll_hd, L"HTCSensorClose");
  if (HTCSensorClose)
    HTCSensorGetDataOutput = (void*)
      GetProcAddress (dll_hd, L"HTCSensorGetDataOutput");
  if (!HTCSensorGetDataOutput)
    {
      fprintf (stderr, PGM": error loading function from sensor DLL: rc=%d\n",
               (int)GetLastError ());
      CloseHandle (dll_hd);
      return 1;
    }
  return 0;
}


static int 
gravity (void)
{
  int rc;
  HANDLE sensor;
  struct htc_sensor_s lastdata;
  struct htc_sensor_s data;

  rc = load_sensor_api ();
  if (rc)
    return rc;

  sensor = HTCSensorOpen (1 /* tilt sensor */);
  if (!sensor  || sensor == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, PGM": error opening gravity sensor: rc=%d\n",
               (int)GetLastError ());
      HTCSensorClose (sensor);
      return 1;
    }

  memset (&lastdata, 0, sizeof lastdata);
  while (HTCSensorGetDataOutput (sensor, &data))
    {
      if (lastdata.tilt_x/10 != data.tilt_x/10
          || lastdata.tilt_y/10 != data.tilt_y/10
          || lastdata.tilt_z/10 != data.tilt_z/10
          || lastdata.angle_x/5 != data.angle_x/5
          || lastdata.angle_y/5 != data.angle_y/5
          || lastdata.orientation != data.orientation)
        {
          lastdata = data;
          printf ("tilt: x=%-5d y=%-5d z=%-5d  "
                  "angle: x=%-3d y=%-3d  "
                  "ori: %d\n",
                  (int)data.tilt_x, (int)data.tilt_y, (int)data.tilt_z,
                  (int)data.angle_x, (int)data.angle_y,
                  (int)data.orientation);
        }
      Sleep (200);
    }
  fprintf (stderr, PGM": reading sensor data failed: rc=%d\n",
           (int)GetLastError ());
  HTCSensorClose (sensor);
  return 0;
}



/* No GPD1 device on the HTC Touch Pro 2.  */
# if 0
static int
gps_raw (void)
{
  HANDLE hd;
  char buffer[1000];
  unsigned long nread;
  int count;

  hd = CreateFile (L"GPD1:", GENERIC_READ, FILE_SHARE_READ,
                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hd == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, PGM": can't open `GPD1': rc=%d\n",
               (int)GetLastError ());
      return 1;
    }
  fprintf (stderr, PGM": GPS device successfully opened\n");

  for (count=0; count < 100; count++)
    {
      if (!ReadFile (hd, buffer, sizeof buffer-1, &nread, NULL))
        {
          fprintf (stderr, PGM": error reading `GPD1': rc=%d\n",
                   (int)GetLastError ());
          CloseHandle (hd);
          return 1;
        }
      buffer[nread-1] = 0;
      fputs (buffer, stdout);
    }

  CloseHandle (hd);
  return 0;
}
#endif

/* Untested samples for CE6.  */
#if 0
static int
gps (void)
{
  HANDLE hd;
  GPS_POSITION pos;

  hd = GPSOpenDevice (NULL, NULL, NULL, 0);
  if (hd == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, PGM": GPSOpenDevice failed: rc=%d\n",
               (int)GetLastError ());
      return 1;
    }
  fprintf (stderr, PGM": GPS device successfully opened\n");

  if (GPSGetPosition (hd, &pos, 2000, 0))
    {
      fprintf (stderr, PGM": GPSGetPosition failed: rc=%d\n",
               (int)GetLastError ());
      GPSCloseDevice (hd);
      return 1;
    }


  GPSCloseDevice (hd);
  return 0;
}
#endif


static void
set_show_registry (const wchar_t *key, const wchar_t *name, const char *value)
{
  HKEY handle;
  DWORD disp, nbytes, n1, type;
  int rc;
  
  if ((rc=RegCreateKeyEx (HKEY_LOCAL_MACHINE, key, 0, NULL, 0,
                          KEY_WRITE, NULL, &handle, &disp)))
    {
      fprintf (stderr, PGM": error creating registry key: rc=%d\n", rc);
      return;
    }

  if (value && !stricmp (value, "none"))
    {
      if ((rc=RegDeleteValue (handle, name)))
        fprintf (stderr, PGM": error deleting registry value: rc=%d\n", rc);
    }
  else if (value)
    {
      wchar_t *tmp = utf8_to_wchar (value);
      if ((rc=RegSetValueEx (handle, name, 0, REG_SZ, 
                             (void*)tmp, wcslen (tmp)*sizeof(wchar_t))))
        fprintf (stderr, PGM": error setting registry value: rc=%d\n", rc);
      free (tmp);
    }
  else
    {
      nbytes = 2;
      if ((rc=RegQueryValueEx (handle, name, 0, NULL, NULL, &nbytes)))
        {
          if (rc == ERROR_FILE_NOT_FOUND)
            fprintf (stderr, PGM": registry value not set\n"); 
          else
            fprintf (stderr, PGM": error reading registry value: rc=%d\n", rc); 
        }
      else
        {
          char *result = malloc ((n1=nbytes+2));
          if (!result)
            fprintf (stderr, PGM": malloc failed: rc=%d\n", 
                     (int)GetLastError ());
          else if ((rc=RegQueryValueEx (handle, name, 0, &type,
                                         (void*)result, &n1)))
            {
              fprintf (stderr, PGM": error reading registry value (2): "
                       "rc=%d\n", rc);
              free (result);
            }
          else
            {
              result[nbytes] = 0;   /* Make sure it is a string.  */
              result[nbytes+1] = 0; 
              if (type == REG_SZ)
                {
                  wchar_t *tmp = (void*)result;
                  result = wchar_to_utf8 (tmp);
                  free (tmp);
                  printf ("%s\n", result);
                }
              else
                fprintf (stderr, PGM": registry value is not a string\n");
              free (result);
            }
        }
    }
  
  RegCloseKey (handle);
}



int
main (int argc, char **argv)
{
  int result = 0;

  if (argc > 1 && !strcmp (argv[1], "--register"))
    result = install ();
  else if (argc > 1 && !strcmp (argv[1], "--deactivate"))
    {
      if (deinstall (L"GPG1:"))
        result = 1;
      if (deinstall (L"GPG2:"))
        result = 1;
    }
  else if (argc > 1 && !strcmp (argv[1], "--activate"))
    {
      HANDLE hd;

      /* This is mainly for testing.  The activation is usually done
         right before the device is opened.  */
      if (ActivateDevice (GPGCEDEV_KEY_NAME, 0) == INVALID_HANDLE_VALUE)
        {
          fprintf (stderr, PGM": ActivateDevice 1 failed: rc=%d\n",
                   (int)GetLastError ());
          result = 1;
        }
      else if (ActivateDevice (GPGCEDEV_KEY_NAME2, 0) == INVALID_HANDLE_VALUE)
        {
          fprintf (stderr, PGM": ActivateDevice 2 failed: rc=%d\n",
                   (int)GetLastError ());
          result = 1;
        }
      else
        {
          fprintf (stderr, PGM": devices activated\n");
          hd = CreateFile (L"GPG1:", GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
          if (hd == INVALID_HANDLE_VALUE)
            {
              fprintf (stderr, PGM": opening `GPG1:' failed: rc=%d\n",
                       (int)GetLastError ());
              result = 1;
            }
          else
            {
              fprintf (stderr, PGM": device `GPG1:' seems to work\n");
              CloseHandle (hd);
            }

          hd = CreateFile (L"GPG2:", GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
          if (hd == INVALID_HANDLE_VALUE)
            {
              fprintf (stderr, PGM": opening `GPG2:' failed: rc=%d\n",
                       (int)GetLastError ());
              result = 1;
            }
          else
            {
              fprintf (stderr, PGM": device `GPG2:' seems to work\n");
              CloseHandle (hd);
            }
          
        }
    }
  else if (argc > 1 && !strcmp (argv[1], "--gravity"))
    result = gravity ();
  /* else if (argc > 1 && !strcmp (argv[1], "--gps")) */
  /*   result = gps (); */
  else if (argc > 1 && !strcmp (argv[1], "--log"))
    {
      HANDLE hd;

      hd = CreateFile (L"GPG2:", GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if (hd == INVALID_HANDLE_VALUE)
        {
          fprintf (stderr, PGM": opening `GPG2:' failed: rc=%d\n",
                   (int)GetLastError ());
          result = 1;
        }
      else
        {
          char marktwain[] = "I have never let my schooling interfere"
            " with my education.\n";
          DWORD nwritten;
          int i;

          for (i=0; i < 3; i++) 
            {
              if (!WriteFile (hd, marktwain, strlen (marktwain),
                              &nwritten, NULL))
                {
                  fprintf (stderr, PGM": writing `GPG2:' failed: rc=%d\n",
                           (int)GetLastError ());
                  result = 1;
                }
              Sleep (200);
            }
          CloseHandle (hd);
        }
    }
  else if (argc > 1 && !strcmp (argv[1], "--enable-debug"))
    result = enable_debug (1);
  else if (argc > 1 && !strcmp (argv[1], "--disable-debug"))
    result = enable_debug (0);
  else if (argc > 1 && !strcmp (argv[1], "--enable-log"))
    result = enable_log (1);
  else if (argc > 1 && !strcmp (argv[1], "--disable-log"))
    result = enable_log (0);
  else if (argc > 1 && !strcmp (argv[1], "--gpgme-log"))
    set_show_registry (L"Software\\GNU\\gpgme", L"debug", 
                                argc > 2? argv[2] : NULL); 
  else if (argc > 1 && !strcmp (argv[1], "--gnupg-log"))
    set_show_registry (L"Software\\GNU\\GnuPG", L"DefaultLogFile", 
                                argc > 2? argv[2] : NULL);
 else
    {
      fprintf (stderr,
               "usage: " PGM " COMMAND\n"
               "Commands are:\n"
               "  --register        Register the GPGCEDEV device\n"
               "  --deactivate      Deactivate the GPGCEDEV device\n"
               "  --activate        Activate the GPGCEDEV devive\n"
               "  --enable-debug    Enable debugging of GPGCEDEV device\n"
               "  --disable-debug   Disable debugging of GPGCEDEV device\n"
               "  --gravity         Show output of the gravity sensor\n"
               "  --enable-log      Enable logging via \"GPG2:\"\n"
               "  --disable-log     Disable logging via \"GPG2:\"\n"
               "  --log             Write a test string to \"GPG2:\"\n"
               "  --gpgme-log [ARG] Show or set GPGME log output\n"
               "  --gnupg-log [ARG] Show or set GnuPG default log file\n"
               "                    (No ARG shows, \"none\" disables)\n"
               );
      result = 1;
    }

  fflush (stdout);
  fflush (stderr);
  Sleep (1000);
  return result;
}


