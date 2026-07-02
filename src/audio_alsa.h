/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 * \brief ALSA-direct audio backend.
 *
 * Capture runs on one pthread per active call (blocking poll + readi,
 * one 20ms voice frame per period). Playback is written inline from the
 * channel write callback. Devices are opened requesting exactly 8000
 * then 16000 Hz; the channel format follows whichever rate opened.
 */

#ifndef CHAN_MM_AUDIO_ALSA_H
#define CHAN_MM_AUDIO_ALSA_H

#include "mm_glue.h"

/*!
 * \brief Open capture+playback PCMs and set modem->rate/format.
 * \note Expects the pvt lock to be held. Idempotent while open.
 * \retval 0 both PCMs open, format chosen
 */
int open_stream(modem_pvt_t *modem);

/*! \brief Start the capture stream/thread. Takes the pvt lock itself. */
int start_stream(modem_pvt_t *modem);

/*! \brief Stop the capture thread and close both PCMs. Takes the pvt lock. */
int stop_stream(modem_pvt_t *modem);

/*! \brief Write one voice frame to the playback PCM (channel write path) */
int alsa_write_frame(modem_pvt_t *modem, struct ast_frame *frame);

/*!
 * \brief Correlate the modem's USB sysfs path with an ALSA card and cache
 * the result in modem->detected_device. Runs once per modem appearance.
 */
void alsa_autodetect_devices(modem_pvt_t *modem);

/*! \brief List ALSA PCM devices on a CLI fd */
void alsa_cli_list_devices(int fd);

#endif /* CHAN_MM_AUDIO_ALSA_H */
