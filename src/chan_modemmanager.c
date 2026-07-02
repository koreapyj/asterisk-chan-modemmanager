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
 * \brief ModemManager channel driver
 *
 * \author Yoonji Park <koreapyj@dcmys.kr>
 *
 * \note Some of the code in this project came from chan_oss, chan_alsa
 *       and chan_console.
 *       chan_console,  Russell Bryant <russell@digium.com>
 *       chan_oss,      Mark Spencer <markster@digium.com>
 *       chan_oss,      Luigi Rizzo
 *       chan_alsa,     Matthew Fredrickson <creslin@digium.com>
 *
 * \ingroup channel_drivers
 *
 * Module lifecycle only — the implementation lives in the sibling files:
 * mm_bus.c (D-Bus/GMainLoop), modem.c/sim.c (device model), channel.c
 * (channel tech), call.c (call lifecycle), sms.c (messaging),
 * audio_alsa.c/audio_detect.c (audio), cli.c (CLI), config.c (config).
 */

/*! \li \ref chan_modemmanager.c uses the configuration file \ref modemmanager.conf
 * \addtogroup configuration_file
 */

/*! \page modemmanager.conf modemmanager.conf
 * \verbinclude modemmanager.conf.sample
 */

/*** MODULEINFO
	<depend>alsa</depend>
	<support_level>extended</support_level>
 ***/

#include "mm_glue.h"

#include "asterisk/format_cache.h"
#include "asterisk/logger.h"
#include "asterisk/message.h"
#include "asterisk/module.h"

#include "channel.h"
#include "cli.h"
#include "config.h"
#include "mm_bus.h"
#include "modem.h"
#include "sim.h"
#include "sms.h"

static int unload_module(void)
{
	/* Stop new work first: no new channels, messages or CLI. */
	ast_channel_unregister(&modemmanager_tech);
	ast_msg_tech_unregister(&mm_msg_tech);
	mm_cli_unregister();

	/* No new hotplug resolution. */
	modem_unwatch_manager();

	/* Stop streams (joins capture threads), disconnect every GObject
	 * signal, drop MM object refs. */
	modem_detach_all();
	sim_detach_all();

	/* Quit and join the GMainLoop thread, shut the worker pool down,
	 * then drop the manager/bus. */
	mm_bus_stop();

	modem_container_destroy();
	sim_container_destroy();

	ao2_cleanup(modemmanager_tech.capabilities);
	modemmanager_tech.capabilities = NULL;

	return 0;
}

static int load_module(void)
{
	if (!(modemmanager_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_append(modemmanager_tech.capabilities, ast_format_slin16, 0);
	ast_format_cap_append(modemmanager_tech.capabilities, ast_format_slin, 0);

	if (modem_container_init() || sim_container_init()) {
		goto return_error;
	}

	if (mm_bus_start()) {
		goto return_error;
	}

	if (load_config(0)) {
		goto return_error_bus;
	}

	if (modem_watch_manager()) {
		goto return_error_bus;
	}

	if (ast_channel_register(&modemmanager_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel type 'ModemManager'\n");
		goto return_error_watch;
	}

	if (ast_msg_tech_register(&mm_msg_tech)) {
		ast_log(LOG_ERROR, "Unable to register message type 'ModemManager'\n");
		goto return_error_chan;
	}

	if (mm_cli_register()) {
		goto return_error_msg;
	}

	return AST_MODULE_LOAD_SUCCESS;

return_error_msg:
	ast_msg_tech_unregister(&mm_msg_tech);
return_error_chan:
	ast_channel_unregister(&modemmanager_tech);
return_error_watch:
	modem_unwatch_manager();
return_error_bus:
	modem_detach_all();
	sim_detach_all();
	mm_bus_stop();
return_error:
	modem_container_destroy();
	sim_container_destroy();
	ao2_cleanup(modemmanager_tech.capabilities);
	modemmanager_tech.capabilities = NULL;

	return AST_MODULE_LOAD_DECLINE;
}

static int reload(void)
{
	return load_config(1);
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "ModemManager Channel Driver",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
);
