ACLOCAL_AMFLAGS = -I m4 --install

include $(top_srcdir)/man/Makefile.am

EXTRA_DIST = LICENSE README.md VERSION autogen.sh

SUBDIRS = src

if !HAVE_LIBSODIUM
    DISTCHECK_CONFIGURE_FLAGS = --enable-sodium=no
endif
