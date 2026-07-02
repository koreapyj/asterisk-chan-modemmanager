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

SRCS := chan_modemmanager.c audio_detect.c
OBJS := $(SRCS:.c=.o)
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

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(MODULE): $(OBJS) $(MODULE_NAME).exports
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS) \
		-Wl,--version-script,$(MODULE_NAME).exports -Wl,--warn-common

-include $(DEPS)

install: $(MODULE)
	$(INSTALL) -d $(DESTDIR)$(MODULES_DIR)
	$(INSTALL) -m 0755 $(MODULE) $(DESTDIR)$(MODULES_DIR)/
	$(INSTALL) -d $(DESTDIR)$(ASTETCDIR)
	$(INSTALL) -m 0644 modemmanager.conf.sample $(DESTDIR)$(ASTETCDIR)/

check: tests/test_audio_detect
	tests/test_audio_detect

# Host unit tests: pure libc, no Asterisk/GLib needed
tests/test_audio_detect: tests/test_audio_detect.c audio_detect.c audio_detect.h
	$(CC) -Wall -Wextra -std=gnu11 -g -o $@ tests/test_audio_detect.c audio_detect.c

clean:
	rm -f $(OBJS) $(DEPS) $(MODULE) tests/test_audio_detect

.PHONY: all check clean install
