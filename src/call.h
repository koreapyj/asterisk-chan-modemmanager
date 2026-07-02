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
 * \brief MMCall lifecycle: attach/detach, incoming calls, state changes.
 */

#ifndef CHAN_MM_CALL_H
#define CHAN_MM_CALL_H

#include "mm_glue.h"

/*!
 * \brief Store a call on the modem (+ref) and connect its signals.
 * Replaces (detaching) any previous call.
 * \note Expects the modem pvt lock to be held.
 */
void call_attach(modem_pvt_t *modem, MMCall *call, sim_pvt_t *sim);

/*!
 * \brief Disconnect call signals and drop the modem's call reference.
 * \note Expects the modem pvt lock to be held. Safe when no call is attached.
 */
void call_detach(modem_pvt_t *modem);

/*!
 * \brief MMModemVoice "call-added" signal handler (GMainLoop thread).
 * user_data is a referenced sim_pvt_t (managed by the connection closure).
 */
void on_voice_call_added(MMModemVoice *voice, const char *path, void *data);

#endif /* CHAN_MM_CALL_H */
