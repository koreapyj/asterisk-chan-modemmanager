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
 * \brief sim_pvt container management.
 */

#ifndef CHAN_MM_SIM_H
#define CHAN_MM_SIM_H

#include "mm_glue.h"

int sim_container_init(void);
void sim_container_destroy(void);

/*! \brief Look up a configured SIM by SimIdentifier/ICCID (+1 ref) */
sim_pvt_t *find_sim(const char *identifier);

/*! \brief Create or refresh a sim pvt from one config category */
void build_sim(struct ast_config *cfg, const char *name);

void sim_mark_destroy_all(void);
void sim_prune_destroyed(void);

/*! \brief Drop MM object and modem references (unload path) */
void sim_detach_all(void);

#endif /* CHAN_MM_SIM_H */
