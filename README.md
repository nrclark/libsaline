## Introduction ##

This repo holds a cleaned-up, de-obfuscated fork of tweetnacl-20140427.

## Differences from tweetnacl ##

Libtweetnacl's internal workings are identical to tweetnacl-20140427.
No code structure was changed, nor were any algorithms or values.

The changes of interest are:

1. Cleaned up most of tweetnacl.h's macro-soup. Left the basic structure
   of the header intact, in a familiar format to those who've used the
   library before.

2. Removed tweetnacl's FOR() macros.

4. Used clang-format and astyle to reformat original source files
   for clearer reading.

5. Fixed several unsigned-to-signed comparison warnings found
   when compiling with -Wall -Wextra.

6. Fixed several undefined-behavior warnings caused by integer left-shifts.
   These warnings were found using GCC's sanitizers. The underlying code
   structure is still the same, but the left-shift is now performed as an
   unsigned type.

7. Added a configurable implementation of randombytes(), which
   is needed by nacl.

8. Added a Makefile for easy compilation and installation.

## Build Instructions ##

1. Generate `randombytes_config.h` to select your system's random-number
   generator (see `randombytes.h` for more information).

2. Build `libtweetnacl.a` by running `make`.

3. (optional) Install with `make install`. Supports `prefix` and `DESTDIR`.

## Current Status ##

At the current time, this library should be fully functional, and
should work identically to tweetnacl-20140427.
