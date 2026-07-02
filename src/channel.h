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
 * \brief ast_channel_tech callbacks and channel construction.
 */

#ifndef CHAN_MM_CHANNEL_H
#define CHAN_MM_CHANNEL_H

#include "mm_glue.h"

extern struct ast_channel_tech modemmanager_tech;

/*!
 * \brief Allocate the Asterisk channel for a call on this SIM.
 *
 * Sets modem->owner and bumps the module usecount. Callers must have run
 * open_stream(modem) beforehand (with no locks held) so the channel format
 * is fixed. Does NOT start the PBX — callers do that after releasing the
 * pvt lock.
 *
 * \note Expects the modem pvt lock to be held; \a modem is the caller's
 *       grabbed reference (sim_grab_modem), never a bare sim->modem read.
 */
struct ast_channel *modemmanager_new(sim_pvt_t *sim, modem_pvt_t *modem,
	const char *cid, const char *ext,
	const char *ctx, int state, const struct ast_assigned_ids *assignedids,
	const struct ast_channel *requestor);

#endif /* CHAN_MM_CHANNEL_H */
