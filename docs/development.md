---
layout: default
title: NeoPG Development Guide
---
# NeoPG Development Guide

## Idiomatic Programming

NeoPG is written in C++11 and leans heavily on the standard library
(especially STL), Botan (for cryptographic primitives) and Boost.
This means that we are pushing a lot of platform dependencies and
portability concerns to these layers.  Feel free to take full
advantage of this.

Leveraging these high-level abstractions allows to write very
efficient code, and should be preferred over micro-managing pointers
or other anti-patterns.

Sometimes, it is easier to always use a strong primitive than to
differentiate.  For example, all random we are using is
cryptographically strong, and all Hashes are calculated in secure
memory. In general, this is not a problem.

## Coding-style

We use `clang-format -style=Google`.  The file `.clang-format` already
sets this.  It is recommended to configure your editor to run this
everytime the file is saved.

You can run `make pretty` to reformat all source code lines.  Some
legacy files are not stable under this operation, unfortunately.
There is no CI for source formatting yet for this reason.

## Directory Layout

Header files and unit tests are located next to the source file.
Header files are copied to `build/include/neopg` and
`build/include/neopg-tool` in a flat directory.  This is a bit
unorthodox, but makes it easier to edit them along with the source
file.  Integration tests are located in the tests/ directory.

## Translations

We use gettext-tools (at build time) and boost::locale (at runtime)
for translations.  Translatable strings are marked with the macro `_`.
Comments preceeding such strings are passed to the translators if they
address them with the phrase "Translators".  We use boost::format to
parametrize strings with variable content.

```
// Translators, good luck translating this one!
std::cout << boost::format(_("%s is a trusted introducer for %s")) % introducer % subject;
```

## Character Encodings

Character encoding conversion is done with boost::locale::conv.
Unfortunately, boost does not allow conversion into a securely
allocated memory buffer, so converting passwords (to guess the right
encoding) currently has a race condition where the password is
exposed.  This is currently only used in the p12 export function.

See: [Boost Trac #13312](https://svn.boost.org/trac10/ticket/13312)
