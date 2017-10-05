# NeoPG implements the OpenPGP standard.

## Dependencies

Aside from a working C++ toolchain you'll need the following libraries.

1. SQLite >= 3.0
1. Botan >= 2.0
1. CMake >= 3.2
1. Google Test (GTest) >= 1.8
1. Boost >= 1.64.0

## Install

With all dependencies installed NeoPG can be build with CMake.

```bash
$ cd build
$ cmake ../src
$ make
$ make test # or ./gpg-error-test
```

## Things accomplished

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
