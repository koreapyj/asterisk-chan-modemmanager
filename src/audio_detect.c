/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * Yoonji Park <koreapyj@dcmys.kr>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 * \brief USB sysfs to ALSA card correlation
 *
 * Deliberately free of Asterisk/GLib dependencies so the host unit tests
 * can exercise it against a synthetic sysfs tree.
 */

#include "audio_detect.h"

#include <ctype.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*! \brief Match the kernel's USB device address naming: busnum-port[.port...] */
static int is_usb_port_component(const char *s, size_t len)
{
	size_t i = 0;
	int expect_digit;

	while (i < len && isdigit((unsigned char)s[i])) {
		i++;
	}
	if (!i || i >= len || s[i] != '-') {
		return 0;
	}
	i++;
	if (i >= len || !isdigit((unsigned char)s[i])) {
		return 0;
	}
	expect_digit = 0;
	for (; i < len; i++) {
		if (isdigit((unsigned char)s[i])) {
			expect_digit = 0;
		} else if (s[i] == '.' && !expect_digit) {
			expect_digit = 1;
		} else {
			return 0;
		}
	}
	return !expect_digit;
}

static int is_usb_root_component(const char *s, size_t len)
{
	size_t i;

	if (len < 4 || strncmp(s, "usb", 3)) {
		return 0;
	}
	for (i = 3; i < len; i++) {
		if (!isdigit((unsigned char)s[i])) {
			return 0;
		}
	}
	return 1;
}

int mm_audio_usb_root_token(const char *path, char *out, size_t out_len)
{
	const char *p = path;
	const char *best = NULL;
	size_t best_len = 0;
	int seen_usb_root = 0;

	while (*p) {
		const char *start;
		size_t len;

		while (*p == '/') {
			p++;
		}
		start = p;
		while (*p && *p != '/') {
			p++;
		}
		len = p - start;
		if (!len) {
			continue;
		}

		if (is_usb_root_component(start, len)) {
			seen_usb_root = 1;
		} else if (seen_usb_root && is_usb_port_component(start, len)) {
			/* deepest match wins: hubs come before the device itself */
			best = start;
			best_len = len;
		}
	}

	if (!best || best_len >= out_len) {
		return -1;
	}
	memcpy(out, best, best_len);
	out[best_len] = '\0';
	return 0;
}

int mm_audio_card_for_physdev(const char *sysfs_root, const char *modem_phys,
	int *out_card, char *err, size_t err_len)
{
	char token[64];
	char pattern[PATH_MAX];
	glob_t gl;
	size_t i;
	int matches = 0;
	int found = -1;

	if (mm_audio_usb_root_token(modem_phys, token, sizeof(token))) {
		snprintf(err, err_len, "no USB device address in modem path '%s'", modem_phys);
		return -1;
	}

	snprintf(pattern, sizeof(pattern), "%s/class/sound/card*/device", sysfs_root);
	if (glob(pattern, 0, NULL, &gl)) {
		snprintf(err, err_len, "no sound cards under %s/class/sound", sysfs_root);
		return -1;
	}

	for (i = 0; i < gl.gl_pathc; i++) {
		char real[PATH_MAX];
		char card_token[64];
		const char *cardname;
		int card;

		if (!realpath(gl.gl_pathv[i], real)) {
			continue;
		}
		if (mm_audio_usb_root_token(real, card_token, sizeof(card_token))
			|| strcmp(card_token, token)) {
			continue;
		}

		/* .../class/sound/cardN/device -> parse N */
		cardname = strstr(gl.gl_pathv[i], "/card");
		if (!cardname || sscanf(cardname, "/card%d/", &card) != 1) {
			continue;
		}
		matches++;
		found = card;
	}
	globfree(&gl);

	if (matches == 1) {
		*out_card = found;
		return 0;
	}
	if (!matches) {
		snprintf(err, err_len, "no ALSA card shares USB device '%s'", token);
	} else {
		snprintf(err, err_len, "%d ALSA cards share USB device '%s' (ambiguous)",
			matches, token);
	}
	return -1;
}
