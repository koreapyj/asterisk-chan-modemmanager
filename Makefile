# Makefile for chan_modemmanager, an out-of-tree Asterisk channel driver.
#
# All library flags come from pkg-config so the same Makefile serves native
# Debian/Ubuntu builds, OpenWrt cross builds (override CC/PKG_CONFIG/
# ASTERISK_INCLUDE from the package recipe) and manual builds.

CC         ?= gcc
PKG_CONFIG ?= pkg-config
INSTALL    ?= install

MODULE_NAME := chan_modemmanager
MODULE      := $(MODULE_NAME).so

# Asterisk ships no pkg-config file; its headers install straight into
# $(ASTERISK_INCLUDE)/asterisk*. Debian/Ubuntu: /usr/include (default).
# OpenWrt: $(STAGING_DIR)/usr/include.
ASTERISK_INCLUDE ?= /usr/include
MODULES_DIR      ?= /usr/lib/asterisk/modules
ASTETCDIR        ?= /etc/asterisk
DESTDIR          ?=

PKGCONFIG_LIBS := glib-2.0 gio-2.0 gobject-2.0 mm-glib alsa

# src/mms/vendor/*.c is mmsd-tng's codec (see provenance headers in that
# directory); src/mms/*.c is this driver's own boundary code around it.
SRCS := $(wildcard src/*.c) $(wildcard src/mms/*.c) $(wildcard src/mms/vendor/*.c)
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:.o=.d)

WARN_CFLAGS := -Wall -Wextra -Wno-unused-parameter

CFLAGS ?= -O2 -g
override CFLAGS += -std=gnu11 -fPIC $(WARN_CFLAGS) \
	-I$(ASTERISK_INCLUDE) \
	-DAST_MODULE=\"$(MODULE_NAME)\" \
	-DAST_MODULE_SELF_SYM=__internal_$(MODULE_NAME)_self \
	$(shell $(PKG_CONFIG) --cflags $(PKGCONFIG_LIBS))

LDLIBS := -lm -lpthread $(shell $(PKG_CONFIG) --libs $(PKGCONFIG_LIBS))

all: $(MODULE)

build:
	@mkdir -p build

# Single generic pattern rule builds build/%.o for every src/%.c, including
# the src/mms/ and src/mms/vendor/ subdirectories (build/mms/%.o,
# build/mms/vendor/%.o): `mkdir -p $(dir $@)` creates whatever subdirectory
# under build/ the object needs, instead of hand-listing one pattern rule
# per subdirectory.
build/%.o: src/%.c | build
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Vendored mmsd-tng code (src/mms/vendor/*.c; see the provenance header at
# the top of each file) trips one upstream warning under -Wextra:
# mms_encode_send_req_part_header() in mmsutil.c passes an
# `enum mms_part_header` where an `enum mms_header` is expected (both are
# just small header-code enums; this is upstream's code, not ours, so it's
# suppressed here rather than hand-edited). Scoped to just the vendor
# objects -- everything else, including the rest of this driver, still
# builds under the full WARN_CFLAGS above.
build/mms/vendor/%.o: WARN_CFLAGS += -Wno-enum-conversion

$(MODULE): $(OBJS) src/$(MODULE_NAME).exports
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS) \
		-Wl,--version-script,src/$(MODULE_NAME).exports -Wl,--warn-common

-include $(DEPS)

install: $(MODULE)
	$(INSTALL) -d $(DESTDIR)$(MODULES_DIR)
	$(INSTALL) -m 0755 $(MODULE) $(DESTDIR)$(MODULES_DIR)/
	$(INSTALL) -d $(DESTDIR)$(ASTETCDIR)
	$(INSTALL) -m 0644 modemmanager.conf.sample $(DESTDIR)$(ASTETCDIR)/

TEST_BINS := tests/test_audio_detect tests/test_at_tty tests/test_mms_codec

check: $(TEST_BINS)
	tests/test_audio_detect
	tests/test_at_tty
	tests/test_mms_codec

# Host unit tests: pure libc, no Asterisk/GLib needed
tests/test_audio_detect: tests/test_audio_detect.c src/audio_detect.c src/audio_detect.h
	$(CC) -Wall -Wextra -std=gnu11 -g -o $@ tests/test_audio_detect.c src/audio_detect.c

tests/test_at_tty: tests/test_at_tty.c src/at_tty.c src/at_tty.h
	$(CC) -Wall -Wextra -std=gnu11 -g -o $@ tests/test_at_tty.c src/at_tty.c -lpthread

# Host unit test for the MMS codec: pure GLib (via pkg-config), no
# Asterisk/libmm-glib needed -- see src/mms/mms_codec.h. -Wno-unused-parameter
# and -Wno-enum-conversion apply only because src/mms/vendor/*.c is vendored
# mmsd-tng code (same two warnings suppressed the same way for the .so build
# above); src/mms/mms_codec.c and tests/test_mms_codec.c are independently
# clean under plain -Wall -Wextra.
tests/test_mms_codec: tests/test_mms_codec.c src/mms/mms_codec.c src/mms/mms_codec.h \
		src/mms/vendor/wsputil.c src/mms/vendor/wsputil.h \
		src/mms/vendor/mmsutil.c src/mms/vendor/mmsutil.h \
		src/mms/vendor/vendor_shim.h
	$(CC) -Wall -Wextra -Wno-unused-parameter -Wno-enum-conversion -std=gnu11 -g -o $@ \
		tests/test_mms_codec.c src/mms/mms_codec.c \
		src/mms/vendor/wsputil.c src/mms/vendor/mmsutil.c \
		$(shell $(PKG_CONFIG) --cflags --libs glib-2.0)

clean:
	rm -rf build
	rm -f $(MODULE) $(TEST_BINS)

.PHONY: all check clean install
