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
 * \brief modem_pvt container management and MM object attachment.
 */

#ifndef CHAN_MM_MODEM_H
#define CHAN_MM_MODEM_H

#include "mm_glue.h"

int modem_container_init(void);
void modem_container_destroy(void);

/*! \brief Look up a configured modem by DeviceIdentifier (+1 ref) */
modem_pvt_t *find_modem(const char *identifier);

/*! \brief Create or refresh a modem pvt from one config category */
void build_modem(struct ast_config *cfg, const char *name);

/*! \brief Mark every modem pvt for destroy (reload sweep start) */
void modem_mark_destroy_all(void);

/*! \brief Unlink pvts still marked destroy after a reload config walk */
void modem_prune_destroyed(void);

/*!
 * \brief Resolve every MMManager object against the configured pvts.
 *
 * Attaches MMModem/MMModemVoice/MMModemMessaging and the MMSim to the
 * matching modem/sim pvts, connects signals (disconnect-before-connect,
 * so calling this again on reload cannot double-connect), runs ALSA
 * autodetection, and creates the per-modem serializer.
 */
void modem_resolve_all(void);

/*! \brief Disconnect signals and drop MM object refs for every modem/sim */
void modem_detach_all(void);

/*! \brief Subscribe to MMManager object-added/removed (hotplug) */
int modem_watch_manager(void);
void modem_unwatch_manager(void);

#endif /* CHAN_MM_MODEM_H */
