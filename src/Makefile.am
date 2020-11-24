ACLOCAL_AMFLAGS = -I m4 --install

lib_LTLIBRARIES = libtweetnacl.la
libtweetnacl_la_SOURCES = randombytes.c tweetnacl.c

include_HEADERS = randombytes.h tweetnacl.h
libtweetnacl_la_LDFLAGS = -release @LIB_RELEASE@