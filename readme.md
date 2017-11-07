[![Gitter](https://badges.gitter.im/das-labor/neopg.svg)](https://gitter.im/das-labor/neopg)
[![Build Status](https://travis-ci.org/das-labor/neopg.svg?branch=master)](https://travis-ci.org/das-labor/neopg)
[![Code Coverage](https://codecov.io/gh/das-labor/neopg/branch/master/graph/badge.svg)](https://codecov.io/gh/das-labor/neopg)

# NeoPG implements the OpenPGP standard.

NeoPG is written in C++11.  It starts out as an opinionated fork of
the GnuPG code base, and hopefully will evolve to something entirely
different.

For now, many parts of NeoPG are licensed by the upstream authors
under various licenses, including GPL and LGPL variants.  Please refer
to the copyright notice at the top of every file.

New source code contributed by the NeoPG authors is licensed under the
permissive `Simplified BSD` license (the same license as Botan, the
cryptography library we want to use).

The dependencies are also released under their respective various
licenses.


## Dependencies

Aside from a working C++ toolchain you'll need the following libraries.

1. SQLite >= 3.0
1. Botan >= 2.0
1. CMake >= 3.2
1. Boost >= 1.64.0
1. zlib
1. bzip2
1. gcovr (debug builds only)
1. clang-format (debug builds only)
1. cppcheck (debug builds only)
1. doxygen (debug builds only)

## Install

With all dependencies installed NeoPG can be build with CMake.

```bash
$ git submodule update --init
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
  # or cmake -DCMAKE_BUILD_TYPE=Release -C ../src/clang.txt ..
$ make
$ make test # opt: ARGS=-V or CTEST_OUTPUT_ON_FAILURE=1
```

## Optional

You need to have `gcovr`, `clang-format`, `doxygen` and `cppcheck` installed.

```
$ make pretty
$ make lint
```

```
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make; make coverage      # Just coverage.info for codecov.io
$ make; make coverage-html # Local HTML report
$ make; make coverage-data # Cobertura XML report
```

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
$ git clone --recursive git@github.com:das-labor/neopg.git
$ cd neopg/build
$ cmake ..
$ make
```

### macOS

To get started on macOS, follow these steps.
For the dependencies use a package manager like [Homebrew](https://brew.sh):

```
$ brew install botan boost cmake doxygen gettext
```

gettext from Homebrew won't be symlinked to `/usr/local` for the build process
to pick up the headers and libraries you need to configure the following environment
variables: `CMAKE_INCLUDE_PATH`, `CMAKE_LIBRARY_PATH` and `CPATH`.

For the default macOS shell:

```
$ export CMAKE_INCLUDE_PATH=/usr/local/opt/gettext/include
$ export CMAKE_LIBRARY_PATH=/usr/local/opt/gettext/lib
$ export CPATH=/usr/local/opt/gettext/include
```

Build it!

```
# Clone repo and build
$ git clone --recursive git@github.com:das-labor/neopg.git
$ cd neopg/build
$ cmake ..
$ make
```

Have fun!
