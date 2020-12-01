#------------------------------------------------------------------------------#

ACLOCAL_AMFLAGS = -I m4 --install
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libtweetnacl.la
libtweetnacl_la_SOURCES = randombytes.c tweetnacl.new.c tweetnacl_auth.new.c

include_HEADERS = randombytes.h tweetnacl.new.h
libtweetnacl_la_LDFLAGS = -release @LIB_RELEASE@

#------------------------------------------------------------------------------#

cryptosodium_la_SOURCES = \
    test/crypto_box_wrapper.c test/crypto_auth_wrapper.c \
    test/crypto_misc_wrapper.c test/crypto_onetimeauth_wrapper.c \
    test/crypto_scalarmult_wrapper.c test/crypto_secretbox_wrapper.c \
    test/crypto_sign_wrapper.c test/crypto_stream_wrapper.c

cryptosodium_la_LDFLAGS = -module -avoid-version -rpath / $(AM_LDFLAGS)
cryptosodium_la_LIBADD = -lsodium

#------------------------------------------------------------------------------#

SUFFIXES = .tweet.c

.c.tweet.c:
	cp $< $@

clean-local:
	rm -f test/*.tweet.c

cryptotweet_la_SOURCES = \
    test/crypto_box_wrapper.tweet.c test/crypto_auth_wrapper.tweet.c \
    test/crypto_misc_wrapper.tweet.c test/crypto_onetimeauth_wrapper.tweet.c \
    test/crypto_scalarmult_wrapper.tweet.c \
    test/crypto_secretbox_wrapper.tweet.c test/crypto_sign_wrapper.tweet.c \
    test/crypto_stream_wrapper.tweet.c $(libtweetnacl_la_SOURCES)

cryptotweet_la_CFLAGS = -D USE_TWEETNACL $(AM_LDFLAGS)
cryptotweet_la_LDFLAGS = -module -avoid-version -rpath / $(AM_LDFLAGS)

#------------------------------------------------------------------------------#

check_LTLIBRARIES = cryptosodium.la cryptotweet.la

check: $(srcdir)/test/test_crypto.py
	LD_LIBRARY_PATH=$(builddir)/.libs python3 $<

#------------------------------------------------------------------------------#
