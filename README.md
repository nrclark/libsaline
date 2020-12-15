## Introduction ##

This repo holds a cleaned-up, de-obfuscated fork of tweetnacl-20140427. The
new library is cleanly formatted, and passes some very strict code-quality
checks.

It's also verified to be compatible with libsodium's implementation
of the NaCl API.

## Differences from saline ##

Libsaline's internal workings are identical to tweetnacl-20140427.
No code structure was changed, nor were any algorithms or values.

The changes of interest are:

1. Cleaned up saline's macro-soup. Header and functions are clearly defined
   now.

2. Replace #defined constants with enums.

3. Used clang-format and astyle to reformat original source files
   for clearer reading.

4. Fix all compiler warnings/undefined-behavior. There were a fair amount
   of these.

5. Size all internal types where appropriate. Keep external function signatures
   compatible with libsodium.

6. Added a configurable implementation of randombytes(), which
   is needed by saline.

7. Added a thorough testbench that verifies libsodium compatibility.

8. Autotoolized the library for easy integration with common build-systems.

9. Relicensed the library as LGPLv2.1.

## Build Instructions ##

This library is presented as a standard GNU Autotools project. All of the usual
suspects will work fine.

1. (If running from a Git clone) Run `./autogen.sh` to build the configure
   script and its inputs. Not necessary if running from a `make dist`-generated
   source tarball, which will already include a `configure` script.

2. Run `./configure` to configure the build, or run it from a custom build
   directory. Add `--enable-sodium=no` to disable libsodium compatibility
   testing. Set `--with-rand=stdlib` for bare-metal use.

3. Build using `make` and install using `make install`. Set a `DESTDIR` during
   `make install` if needed.

## Current Status ##

At the current time, this work is believed complete. All warnings have been
fixed, and the code has been de-obfusticated where possible. A full test-suite
is included which compares against libsodium for a reference. The design is
fully autotoolized and looks like it works well.

## License ##

Saline's original release was under a public-domain license, released by
Daniel Bernstein. This release is relicensed under LGPLv2.1 for easy
collaboration, and to reflect the work done improving public-domain
saline's code quality into something reasonable.
