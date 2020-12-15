
#------------------------------------------------------------------------------#

m4_include([m4/semantic_version.m4])
SEMANTIC_VERSION_SET_FILE([VERSION])
AC_INIT([libsaline], SEMANTIC_VERSION, [nicholas.clark@gmail.com])
AC_SUBST([LIB_RELEASE],[SEMANTIC_VERSION])

#------------------------ Configure Source Locations  -------------------------#

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/saline.h])
AC_CONFIG_HEADERS([config.h])

#------------------------- Init Automake / Autoconf  --------------------------#

AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([foreign])
AC_USE_SYSTEM_EXTENSIONS

#------------------------ Confirm Rand() Requirements  ------------------------#

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AM_PROG_AR
AM_PROG_LIBTOOL
LT_INIT

AC_ENABLE_SHARED

# Checks for header files.
AC_CHECK_HEADERS([stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_UINT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_INT64_T

AC_TYPE_SSIZE_T

#--------------------------- Custom Autoconf Macros  --------------------------#

# Checks to make sure that a header is present. Throws a MSG_ERROR if missing.

AC_DEFUN([AC_REQUIRE_HEADER], [AC_CHECK_HEADER([$1],,
         [AC_MSG_ERROR([Missing header "$1" required for '$2'.])])])

# Checks to make sure that a function is present. Throws a MSG_ERROR if missing.
AC_DEFUN([AC_REQUIRE_FUNCTION], [AC_CHECK_FUNC([$1],,
         [AC_MSG_ERROR([Missing function "$1" required for '$2'.])])])

# Creates a visually-delineated block in ./configure's --help section.
# Useful for library-specific options.

AC_DEFUN([AC_CREATE_HELP_SECTION],[AC_ARG_WITH([__dummy_with__],
[
$1:], [],[])])

# Guesses the value of rand_source from the value of host_os (the OS of the
# machine which will be running the compiled code). Assumes stdlib if the
# host OS is unknown/unspecified, and urandom otherwise.

AC_DEFUN([AC_GUESS_RAND],
[AC_REQUIRE([AC_CANONICAL_HOST])
 AS_CASE([x$host_os], [x], [rand_source=stdlib],
                      [xunknown], [rand_source=stdlib],
                      [xnone], [rand_source=stdlib],
                      [rand_source='urandom'])
 AC_MSG_NOTICE([Assuming --with-rand=$rand_source (from host: $host_os)])
])

#----------------------------- Add Custom Options  ----------------------------#

AC_PRESERVE_HELP_ORDER
AC_CREATE_HELP_SECTION([Custom Options])

AC_ARG_WITH([rand],
            [AS_HELP_STRING([--with-rand], [Source to use for random data.
             Can be 'stdlib' for stdlib.h rand(), 'urandom' for /dev/urandom,
             or 'devrandom' for /dev/random. Most Unix-like targets should use
             'urandom'. Standalone targets should use 'stdlib'. Nobody should
             use 'devrandom'.])],
            [rand_source=$withval],
            [AC_GUESS_RAND])

AX_CREATE_ENABLE_HELP_SECTION([Features to enable])
AX_MAKE_ENABLE_OPT([sanitizers], [no], [Build with GCC sanitizers enabled])
AX_MAKE_ENABLE_OPT([lint], [no], [Build with every warning GCC can emit])
AX_MAKE_ENABLE_OPT([warnings], [yes], [Build with -Wall -Wextra -pedantic])
AX_MAKE_ENABLE_OPT([werror], [yes], [Build with -Werror])
AX_MAKE_ENABLE_OPT([sodium], [yes], [Test for compatiblity with libsodium])

#---------------------- Configure For Optional Sanitizers  --------------------#

CONFIGURE_SCRIPT_DIR="`dirname $0`"
AS_IF([test "x$enable_lint" = xno], [], [
  AX_ENABLE_CFLAGS([-std=c99])
  AX_ENABLE_EVERY_WARNING([-Wtraditional -Wtraditional-conversion -Wabi
                           -Wold-style-definition -Wstrict-prototypes
                           -Wsystem-headers -Wunused-macros])
])

AS_IF([test "x$enable_warnings" = xno], [], [
  AX_ENABLE_CFLAGS([
    -Wall
    -Wextra
    -pedantic
  ])
])

AS_IF([test "x$enable_sanitizers" = xno], [], [
  AX_ENABLE_CFLAGS([
    -O0
    -g
    -fstack-protector-strong
    -fstack-protector-all
    -fsanitize=shift
    -fsanitize=undefined
    -fsanitize=address
    -fsanitize=alignment
    -fsanitize=bool
    -fsanitize=bounds
    -fsanitize=bounds-strict
    -fsanitize=enum
    -fsanitize=float-cast-overflow
    -fsanitize=float-divide-by-zero
    -fsanitize=integer-divide-by-zero
    -fsanitize=null
    -fsanitize=object-size
    -fno-sanitize-recover=all
    -fsanitize=return
    -fsanitize=returns-nonnull-attribute
    -fsanitize=signed-integer-overflow
  ])
])

AS_IF([test "x$enable_werror" = xno], [], [
  AS_VAR_APPEND([CFLAGS],[" -Werror"])
])

AS_IF([test "x$enable_sodium" = xno], [have_libsodium=no], [
  AC_CHECK_LIB(sodium, crypto_box, [have_libsodium=yes],
               [AC_MSG_ERROR([Couldn't find a working libsodium])])
])

AM_CONDITIONAL([HAVE_LIBSODIUM],[test x$have_libsodium = xyes])
AC_SUBST([HAVE_LIBSODIUM], $have_libsodium)

#-------------------- Place rand() selection into config.h  -------------------#

AS_CASE($rand_source,
     [urandom],
     [AC_DEFINE([RANDOMBYTES_USE_URANDOM], [1],
      [Use /dev/urandom to generate random numbers. Ideal for use on Linux])],
     [devrandom],
     [AC_DEFINE([RANDOMBYTES_USE_DEVRANDOM], [1],
      [Use /dev/random to generate random numbers. Not for use on Linux])],
     [stdlib],
     [AC_DEFINE([RANDOMBYTES_USE_STDLIB], [1],
      [Use the deterministic stdlib for "random" numbers])],
     [yes],
     [AC_MSG_ERROR([No value given for --with-rand. See --help for details.])],
     [AC_MSG_ERROR([Unknown value for --with-rand: '$rand_source'.])])

#------------------------ Confirm Rand() Requirements  ------------------------#

AS_CASE($rand_source,
     [*random],
     [AC_REQUIRE_HEADER([fcntl.h],[$rand_source])
      AC_REQUIRE_HEADER([unistd.h],[$rand_source])
      AC_REQUIRE_HEADER([sys/stat.h],[$rand_source])
      AC_REQUIRE_FUNCTION([open],[$rand_source])
      AC_REQUIRE_FUNCTION([read],[$rand_source])],

     [stdlib],
     [AC_REQUIRE_HEADER([stdlib.h],[$rand_source])
      AC_REQUIRE_FUNCTION([rand],[$rand_source])],

     [])

#------------------------------ Generate Outputs ------------------------------#

AH_TOP([#ifndef __CONFIG_H__
#define __CONFIG_H__])
AH_BOTTOM([#endif])

AC_CONFIG_FILES([Makefile src/Makefile src/test/crypto/crypto.json])
AC_OUTPUT
