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

#include <unistd.h>

#include "asterisk/logger.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"

#include "at_tty.h"
#include "atinit.h"

/*! \brief Per-command response timeout */
#define AT_TIMEOUT_MS       5000
/*! \brief Liveness probe ("AT") timeout */
#define AT_PROBE_TIMEOUT_MS 2000

/*!
 * \brief Try candidate ports until one answers the "AT" liveness probe.
 *
 * The probe converts "guess who owns the port" into a runtime test: a
 * port whose responses are stolen by a competing reader (e.g. MM holding
 * it without TIOCEXCL) times out and is abandoned rather than fought over.
 *
 * \return open fd or -1
 */
static int at_pick_port(modem_pvt_t *modem, const char *init_port, MMModem *device,
	char *chosen, size_t chosen_len)
{
	int fd = -1;

	if (!ast_strlen_zero(init_port)) {
		fd = at_tty_open(init_port);
		if (fd < 0) {
			ast_log(LOG_WARNING, "atinit: cannot open configured init_port '%s' "
				"on modem '%s': %s\n", init_port, modem->identifier, strerror(errno));
			return -1;
		}
		if (at_tty_command(fd, "AT", AT_PROBE_TIMEOUT_MS)) {
			ast_log(LOG_WARNING, "atinit: configured init_port '%s' did not answer "
				"the AT probe on modem '%s'\n", init_port, modem->identifier);
			close(fd);
			return -1;
		}
		ast_copy_string(chosen, init_port, chosen_len);
		return fd;
	}

	{
		MMModemPortInfo *ports = NULL;
		guint n_ports = 0, i;
		const char *primary = mm_modem_get_primary_port(device);

		if (!mm_modem_get_ports(device, &ports, &n_ports)) {
			ast_log(LOG_WARNING, "atinit: modem '%s' reports no port list\n",
				modem->identifier);
			return -1;
		}
		for (i = 0; i < n_ports && fd < 0; i++) {
			char path[128];

			if (ports[i].type != MM_MODEM_PORT_TYPE_AT) {
				continue;
			}
			if (primary && !strcmp(ports[i].name, primary)) {
				continue;
			}
			snprintf(path, sizeof(path), "/dev/%s", ports[i].name);
			fd = at_tty_open(path);
			if (fd < 0) {
				ast_debug(1, "atinit: cannot open %s: %s\n", path, strerror(errno));
				continue;
			}
			if (at_tty_command(fd, "AT", AT_PROBE_TIMEOUT_MS)) {
				ast_debug(1, "atinit: %s did not answer the AT probe; trying next\n", path);
				close(fd);
				fd = -1;
				continue;
			}
			ast_copy_string(chosen, path, chosen_len);
		}
		mm_modem_port_info_array_free(ports, n_ports);
	}

	if (fd < 0) {
		ast_log(LOG_WARNING, "atinit: no usable non-primary AT port on modem '%s'; "
			"set init_port (optionally on a port tagged ID_MM_PORT_IGNORE=1 via udev)\n",
			modem->identifier);
	}
	return fd;
}

static int atinit_task(void *data)
{
	modem_pvt_t *modem = data;
	MMModem *device = NULL;
	char *commands = NULL;
	char *init_port = NULL;
	char chosen[128] = "";
	char *cmd, *rest;
	int fd = -1;
	int ran = 0, failed = 0;

	modemmanager_pvt_lock(modem);
	if (modem->atinit_done || ast_strlen_zero(modem->init_commands) || !modem->device) {
		modemmanager_pvt_unlock(modem);
		goto done;
	}
	/* Once per appearance, even if commands fail: no retry storms. */
	modem->atinit_done = 1;
	commands = ast_strdup(modem->init_commands);
	init_port = ast_strdup(modem->init_port);
	device = g_object_ref(modem->device);
	modemmanager_pvt_unlock(modem);

	if (!commands) {
		goto done;
	}

	fd = at_pick_port(modem, init_port, device, chosen, sizeof(chosen));
	if (fd < 0) {
		goto done;
	}

	rest = commands;
	while ((cmd = strsep(&rest, ";"))) {
		int res;

		cmd = ast_strip(cmd);
		if (ast_strlen_zero(cmd)) {
			continue;
		}
		res = at_tty_command(fd, cmd, AT_TIMEOUT_MS);
		ran++;
		if (res) {
			failed++;
			ast_log(LOG_WARNING, "atinit: '%s' %s on modem '%s' (port %s)\n",
				cmd, res == -2 ? "timed out" : "returned an error",
				modem->identifier, chosen);
		} else {
			ast_debug(1, "atinit: '%s' OK on modem '%s'\n", cmd, modem->identifier);
		}
	}

	if (ran) {
		ast_verb(2, "Modem '%s': ran %d init command(s) on %s (%d failed)\n",
			modem->identifier, ran, chosen, failed);
	}

done:
	if (fd >= 0) {
		close(fd);
	}
	if (device) {
		g_object_unref(device);
	}
	ast_free(commands);
	ast_free(init_port);
	unref_modem(modem);
	return 0;
}

void atinit_kick(modem_pvt_t *modem)
{
	int skip;

	modemmanager_pvt_lock(modem);
	skip = modem->atinit_done || ast_strlen_zero(modem->init_commands)
		|| !modem->serializer || !modem->device;
	modemmanager_pvt_unlock(modem);
	if (skip) {
		return;
	}

	if (ast_taskprocessor_push(modem->serializer, atinit_task, ref_modem(modem))) {
		unref_modem(modem);
	}
}
