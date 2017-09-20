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

LIBNAME := tweetnacl
LIBRARY := lib$(LIBNAME).a
SRC := $(wildcard src/*.c) $(wildcard src/*.h)
TESTS := $(wildcard test/*.c)

CFLAGS ?= -O2 -Wall -Wextra -pedantic
CC ?= gcc

all: $(LIBRARY) include

#------------------------------------------------------------------------------#

deps/%.d: src/%.c
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I . -I $(dir $<) -E -MG -MM -MD $< -MF $@

DEPS := $(filter %.d,$(SRC:src/%.c=deps/%.d))
depend: $(DEPS)

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

clean::
	rm -rf deps

#------------------------------------------------------------------------------#

define \n


endef

get_objs = $(patsubst src/%.c,%.o,$(filter %.c,$1))
get_libs = $(patsubst %.c,lib%.a,$(filter %.c,$1))
get_headers = $(filter %.h,$1)

#------------------------------------------------------------------------------#

.PHONY: include
INCLUDES := $(filter %.h,$(SRC:src/%.h=include/%.h))
include: $(INCLUDES)

include/%.h: src/%.h
	install -D -m644 $< $@

clean::
	rm -rf include

#------------------------------------------------------------------------------#

%.o: src/%.c
	$(CC) $(CFLAGS) -I. -I $(dir $<) -c $< -o $@

$(LIBRARY): $(call get_objs,$(SRC))
	rm -f $@
	ar -cvq $@ $^

clean::
	rm -f *.o *.a

#------------------------------------------------------------------------------#

syntax:
	$(foreach x,$(SRC),$(CC) $(CFLAGS) -fsyntax-only $(x)$(\n))

#------------------------------------------------------------------------------#

$(TESTS:test/%.c=%): %: test/%.c $(LIBRARY) $(INCLUDES)
	$(CC) $(CFLAGS) -I include $< -l $(LIBNAME) -L . -o $@

run-%: %
	./$*

$(foreach x,$(TESTS),$(eval $(x:test/%.c=%):))
$(foreach x,$(TESTS),$(eval $(x:test/%.c=run-%):))

.PHONY: test

test: $(TESTS:test/%.c=run-%)

clean::
	rm -rf $(TESTS:test/%.c=%) 
