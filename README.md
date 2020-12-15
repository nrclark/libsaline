## Introduction ##

This repo holds a cleaned-up, de-obfuscated fork of tweetnacl-20140427. The
new library is cleanly formatted, and passes some very strict code-quality
checks.

It's also verified to be compatible with libsodium's implementation
of the NaCl API.

## Differences from Tweetnacl ##

Libsaline is forked from tweetnacl-20140427. There are a number of changes
and improvements. The changes of interest are:

1. Cleaned up tweetnacl's macro-soup. Header and functions are clearly defined
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

9. Relicense the library with an ISC license.

## Comparison to Libsodium ##

Libsodium is a great library, written and maintained by sharp people. If your
project can use libsodium, that'll almost certainly be the right choice for
you.

Libsodium isn't the right fit for all software projects though. It's hard to
embed in a custom codebase, and it's not well very suited for bare-metal
applications.

Libsaline is minimalistic and very portable, and is suitable for use in places
where libsodium doesn't fit well for whatever reason. Libsaline's performance
is performance is much lower than libsodium, but it's also a much smaller
codebase with a focus on portability.

Libsaline doesn't provide all of the functions available with libsodium, but it
does fully implement the original NaCl API. A comprehensive test suite verifies
that libsaline's provided functions are all libsodium-compatible. So if your
project can compile against libsaline, then it can also compile against
libsodium without changing anything other than the include files.

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

Alternatively, you can just grab the files you need and pull them into your
design.

## Current Status ##

At the current time, this work is believed complete. All warnings have been
fixed, and the code has been de-obfusticated where possible. A full test-suite
is included which compares against libsodium for a reference. The design is
fully autotoolized and looks like it works well.

## License ##

Libsaline's original release was under a public-domain license, released by
Daniel Bernstein. This release is relicensed with an ISC license for easy
collaboration, and to reflect the work done improving public-domain
tweetnacl's code quality into something reasonable.
