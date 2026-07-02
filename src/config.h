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
 * \brief modemmanager.conf loading and reload semantics.
 */

#ifndef CHAN_MM_CONFIG_H
#define CHAN_MM_CONFIG_H

/*!
 * \brief Load or reload modemmanager.conf and resolve devices.
 *
 * Reload keeps the mark-destroy/rebuild pattern and prunes pvts that are
 * no longer configured (modems with an active call survive until it
 * ends), then re-resolves every MMManager object idempotently.
 *
 * \retval 0 success
 */
int load_config(int reload);

#endif /* CHAN_MM_CONFIG_H */
