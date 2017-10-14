# NeoPG implements the OpenPGP standard.

NeoPG is written in C++11 and released under the permissive
`Simplified BSD` license (the same license as Botan, the cryptography
library).

Some (many) parts of NeoPG are currently under a more restrictive
license, because they are derived from other projects (in particular
GnuPG).  Please refer to the copyright notice at the top of every
file.

The dependencies are also released under their respective various
licenses.

## Dependencies

Aside from a working C++ toolchain you'll need the following libraries.

1. SQLite >= 3.0
1. Botan >= 2.0
1. CMake >= 3.2
1. Boost >= 1.64.0
1. openldap
1. zlib
1. bzip2

## Install

With all dependencies installed NeoPG can be build with CMake.

```bash
$ git submodule update --init
$ mkdir build
$ cd build
$ cmake ..   # or cmake -C ../src/clang.txt ..
$ make
$ make test # or ./gpg-error-test
```

## Things accomplished

* build with clang (portability and allowing static analysis)
* libgpg-error
** No dynamic code generation (except preprocessor).
** No lock objects.
** Removed: gpg-error, gpg-error-config, documentation
* libassuan
** No dynamic code generation
* libgcrypt
** No dynamic code generation

TOOD:

* format strings for list-keys etc

metriken:
- sloccount
- coverage
- libksba
- secretgrind

windows
- chocolatey

macos
- brew (homebrew)
ascii armor default
auto keylocate default auto keyretrieve
dirmngr: hkps connections should default to system trust if --hkp-cacert is not given
