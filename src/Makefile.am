ACLOCAL_AMFLAGS = -I m4 --install
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libtweetnacl.la
libtweetnacl_la_SOURCES = randombytes.c tweetnacl.c tweetnacl_auth.c

include_HEADERS = randombytes.h tweetnacl.h
libtweetnacl_la_LDFLAGS = -release @LIB_RELEASE@

cryptosodium_la_SOURCES = \
    test/crypto_box_wrapper.c test/crypto_auth_wrapper.c \
    test/crypto_misc_wrapper.c test/crypto_onetimeauth_wrapper.c \
    test/crypto_scalarmult_wrapper.c test/crypto_secretbox_wrapper.c \
    test/crypto_sign_wrapper.c test/crypto_stream_wrapper.c

cryptotweet_la_SOURCES = \
    test/crypto_box_wrapper.c test/crypto_auth_wrapper.c \
    test/crypto_misc_wrapper.c test/crypto_onetimeauth_wrapper.c \
    test/crypto_scalarmult_wrapper.c test/crypto_secretbox_wrapper.c \
    test/crypto_sign_wrapper.c test/crypto_stream_wrapper.c \
    $(libtweetnacl_la_SOURCES)

cryptotweet_la_CFLAGS = -D USE_TWEETNACL $(AM_LDFLAGS)

cryptosodium_la_LDFLAGS = -module -avoid-version -rpath / $(AM_LDFLAGS)
cryptotweet_la_LDFLAGS = -module -avoid-version -rpath / $(AM_LDFLAGS)

cryptosodium_la_LIBADD = -lsodium

check_LTLIBRARIES = cryptosodium.la cryptotweet.la

check: cryptosodium.la cryptotweet.la
	echo "TEST"
	echo $^
