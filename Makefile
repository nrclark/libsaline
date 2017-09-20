################################################################################
# @file Makefike
# @brief Makefile building nacl CLI tools.
#
# @copyright Copyright 2017 Universal Audio, Inc. All Rights Reserved.
#
# THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE of Universal Audio
# Inc. The copyright notice above does not evidence any actual or intended
# publication of such source code.
################################################################################

#------------------------------------------------------------------------------#

LIBRARY := libtweetnacl.a
SRC := $(wildcard src/*.c) $(wildcard src/*.h)

CFLAGS ?= -O2 -Wall -Wextra -pedantic
CC ?= gcc

all: $(LIBRARY) include

#------------------------------------------------------------------------------#

deps/%.d: src/%.c
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -E -MG -MM -MD $< -MF $@

DEPS := $(filter %.d,$(SRC:src/%.c=deps/%.d))
depend: $(DEPS)

.PHONY: test
test:
	echo $(SRC)
	echo $(DEPS)

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

#------------------------------------------------------------------------------#

define \n


endef

get_objs = $(patsubst src/%.c,%.o,$(filter %.c,$1))
get_libs = $(patsubst %.c,lib%.a,$(filter %.c,$1))
get_headers = $(filter %.h,$1)

#------------------------------------------------------------------------------#

.PHONY: include
include: $(filter %.h,$(SRC:src/%.h=include/%.h))

include/%.h: src/%.h
	install -D -m644 $< $@

clean::
	rm -rf include

#------------------------------------------------------------------------------#

%.o: src/%.c
	$(CC) $(CFLAGS) -I $(dir $<) -c $< -o $@

libtweetnacl.a: $(call get_objs,$(SRC))
	rm -f $@
	ar -cvq $@ $^

clean::
	rm -f *.o *.a

#------------------------------------------------------------------------------#

syntax:
	$(foreach x,$(SRC),$(CC) $(CFLAGS) -fsyntax-only $(x)$(\n))

#------------------------------------------------------------------------------#
