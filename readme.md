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

## Optional

```
$ make pretty
$ make lint
```

```
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make; make coverage # FIXME: Add proper dependencies to target.
$ make; make coverage-data
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

## TODO

* format strings for list-keys etc

Code metrics:
- sloccount
- secretgrind
- sonarqube

Windows
- chocolatey

macOS
- brew (homebrew)

openpgp profile
- ascii armor default
- auto keylocate default auto keyretrieve
- dirmngr: hkps connections should default to system trust if --hkp-cacert is not given

## Hacking

### Fedora
To get started on a Fedora 26, do the following

```
# Fedora 26 only comes with Botan 1.10. Here we enable a copr repo for Botan 2
$ sudo dnf copr enable bkircher/botan2

# Install dev dependencies
$ sudo dnf install -y \
    boost-devel \
    botan2-devel \
    cmake \
    gcc-c++ \
    gcovr \
    git \
    lcov \
    libusb-devel \
    python \
    sqlite-devel \

# Clone repo and build
$ git clone --recursive git@github.com:zaolin/neopg.git
$ cd neopg/build
$ cmake ..
$ make
```
Have fun!
