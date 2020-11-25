ACLOCAL_AMFLAGS = -I m4 --install
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libtweetnacl.la
libtweetnacl_la_SOURCES = randombytes.c tweetnacl.c

include_HEADERS = randombytes.h tweetnacl.h
libtweetnacl_la_LDFLAGS = -release @LIB_RELEASE@

libcryptosodium_la_SOURCES = \
    test/crypto_box_wrapper.c test/crypto_auth_wrapper.c \
    test/crypto_misc_wrapper.c test/crypto_onetimeauth_wrapper.c \
    test/crypto_scalarmult_wrapper.c test/crypto_secretbox_wrapper.c \
    test/crypto_sign_wrapper.c test/crypto_stream_wrapper.c

libcryptotweet_la_SOURCES = \
    test/crypto_box_wrapper.c test/crypto_auth_wrapper.c \
    test/crypto_misc_wrapper.c test/crypto_onetimeauth_wrapper.c \
    test/crypto_scalarmult_wrapper.c test/crypto_secretbox_wrapper.c \
    test/crypto_sign_wrapper.c test/crypto_stream_wrapper.c

libcryptosodium_la_LDFLAGS = -rpath /foo $(AM_LDFLAGS)
libcryptotweet_la_LDFLAGS = -rpath /foo $(AM_LDFLAGS)

libcryptosodium_la_LIBADD = -lsodium
libcryptotweet_la_LIBADD = libtweetnacl.la

check_LTLIBRARIES = libcryptosodium.la libcryptotweet.la