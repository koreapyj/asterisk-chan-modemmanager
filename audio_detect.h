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
 * \brief USB sysfs to ALSA card correlation (pure libc, unit-testable)
 *
 * ModemManager reports a modem's physical device as a sysfs path
 * (e.g. /sys/devices/.../usb1/1-2). The modem's USB audio function shows
 * up as a sound card whose sysfs parent chain contains the same USB
 * device address ("1-2", "1-2.3", ...). These helpers correlate the two
 * so call audio needs no manual ALSA configuration.
 */

#ifndef CHAN_MM_AUDIO_DETECT_H
#define CHAN_MM_AUDIO_DETECT_H

#include <stddef.h>

/*!
 * \brief Extract the deepest USB device address component from a sysfs path.
 *
 * The address is the kernel's "busnum-port[.port...]" naming (e.g. "1-2",
 * "1-2.3"); only components after a "usbN" root hub component qualify, and
 * interface components ("1-2:1.4") are ignored. The deepest match is the
 * device itself rather than a hub it hangs off.
 *
 * \retval 0 token written to \a out
 * \retval -1 no USB device address in \a path
 */
int mm_audio_usb_root_token(const char *path, char *out, size_t out_len);

/*!
 * \brief Find the ALSA card whose USB device matches a modem's physdev path.
 *
 * Scans the <sysfs_root>/class/sound/cardN/device symlinks and compares
 * USB device addresses.
 *
 * \param sysfs_root normally "/sys"; tests point this at a fixture tree
 * \param modem_phys the modem's physical device sysfs path
 * \param out_card unique matching card index
 * \param err diagnostic on failure (no match / ambiguous match)
 *
 * \retval 0 exactly one card matched
 * \retval -1 zero or multiple matches; \a err describes which
 */
int mm_audio_card_for_physdev(const char *sysfs_root, const char *modem_phys,
	int *out_card, char *err, size_t err_len);

#endif /* CHAN_MM_AUDIO_DETECT_H */
