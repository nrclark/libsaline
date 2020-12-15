#------------------------------------------------------------------------------#

ACLOCAL_AMFLAGS = -I m4 --install
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libsaline.la
libsaline_la_SOURCES = randombytes.c saline.c saline_auth.c

include_HEADERS = randombytes.h saline.h
libsaline_la_LDFLAGS = -release @LIB_RELEASE@

check_LTLIBRARIES = cryptosaline.la

#------------------------------------------------------------------------------#

if HAVE_LIBSODIUM
    cryptosodium_la_SOURCES = \
        test/crypto_box_wrapper.c test/crypto_auth_wrapper.c \
        test/crypto_misc_wrapper.c test/crypto_onetimeauth_wrapper.c \
        test/crypto_scalarmult_wrapper.c test/crypto_secretbox_wrapper.c \
        test/crypto_sign_wrapper.c test/crypto_stream_wrapper.c

    cryptosodium_la_LDFLAGS = -module -avoid-version -rpath / $(AM_LDFLAGS)
    cryptosodium_la_LIBADD = -lsodium

    check_LTLIBRARIES += cryptosodium.la
endif

#------------------------------------------------------------------------------#

SUFFIXES = .saline.c

.c.saline.c:
	cp $< $@

clean-local:
	rm -f test/*.saline.c

cryptosaline_la_SOURCES = \
    test/crypto_box_wrapper.saline.c test/crypto_auth_wrapper.saline.c \
    test/crypto_misc_wrapper.saline.c test/crypto_onetimeauth_wrapper.saline.c \
    test/crypto_scalarmult_wrapper.saline.c \
    test/crypto_secretbox_wrapper.saline.c test/crypto_sign_wrapper.saline.c \
    test/crypto_stream_wrapper.saline.c $(libsaline_la_SOURCES)

cryptosaline_la_CFLAGS = -D USE_SALINE $(AM_CFLAGS)
cryptosaline_la_LDFLAGS = -module -avoid-version -rpath / $(AM_LDFLAGS)

#------------------------------------------------------------------------------#

check: $(srcdir)/test/test_crypto.py
	LD_LIBRARY_PATH=$(builddir)/.libs python3 $<

EXTRA_DIST = \
    test/crypto_wrappers.h \
    test/test_crypto.py \
    test/reference.json \
    test/crypto/__init__.py \
    test/crypto/wrappers.py

#------------------------------------------------------------------------------#
