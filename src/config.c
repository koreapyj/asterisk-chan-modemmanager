/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "mm_glue.h"

#include "asterisk/config.h"
#include "asterisk/logger.h"

#include "config.h"
#include "modem.h"
#include "sim.h"

static const char config_file[] = "modemmanager.conf";

int load_config(int reload)
{
	struct ast_config *cfg;
	struct ast_flags config_flags = { 0 };
	struct ast_category *context = NULL;

	if (!(cfg = ast_config_load(config_file, config_flags))) {
		ast_log(LOG_NOTICE, "Unable to open configuration file %s!\n", config_file);
		return -1;
	} else if (cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_NOTICE, "Config file %s has an invalid format\n", config_file);
		return -1;
	}

	modem_mark_destroy_all();
	sim_mark_destroy_all();

	while ((context = ast_category_browse_filtered(cfg, NULL, context, "type=^modem$"))) {
		build_modem(cfg, ast_category_get_name(context));
	}

	while ((context = ast_category_browse_filtered(cfg, NULL, context, "type=^sim$"))) {
		build_sim(cfg, ast_category_get_name(context));
	}

	ast_config_destroy(cfg);

	if (reload) {
		modem_prune_destroyed();
		sim_prune_destroyed();
	}

	modem_resolve_all();

	return 0;
}
