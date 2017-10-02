# Notes

* cmake rules don't work yet

## libgpg-error

* Build with "libtoolize; autoreconf -f -i; configure --enable-maintainer-mode; make -j 32; make check" (dunno how I broke autoreconf's libtool support)
* Windows build is broken (at least for the locking support, maybe more).
* POSIX lock interface stuff in gpg-error.h is half-baked.
* Things accomplished:
** No dynamic code generation (except preprocessor).
** No lock objects.
** Removed: gpg-error, gpg-error-config, documentation
