# Notes

$ mkdir build
$ cd build
$ cmake ../src
$ make
$ make test # or ./gpg-error-test


# Things accomplished

* libgpg-error
** No dynamic code generation (except preprocessor).
** No lock objects.
** Removed: gpg-error, gpg-error-config, documentation
* libassuan
** No dynamic code generation
* libgcrypt
** No dynamic code generation

* format strings for list-keys etc

metriken:
- sloccount
- coverage
- libksba

windows
- chocolatey

macos
- brew (homebrew)
