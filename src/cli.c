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

#include "asterisk/cli.h"

#include "audio_alsa.h"
#include "cli.h"
#include "mm_bus.h"

static char *cli_list_available(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	GError *error = NULL;
	GList *objects, *l;

	if (cmd == CLI_INIT) {
		e->command = "modemmanager list available";
		e->usage =
			"Usage: modemmanager list available\n"
			"       List all available modems and ALSA devices.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		return NULL;
	}

	if (a->argc != e->args) {
		return CLI_SHOWUSAGE;
	}

	ast_cli(a->fd, "\nAvailable modems\n");

	objects = g_dbus_object_manager_get_objects(G_DBUS_OBJECT_MANAGER(mm_bus_manager()));
	if (!objects) {
		ast_cli(a->fd, "\t(none)\n");
	}
	for (l = objects; l; l = g_list_next(l)) {
		MMModem *modem = mm_object_peek_modem(MM_OBJECT(l->data));
		MMModemVoice *modem_voice = mm_object_peek_modem_voice(MM_OBJECT(l->data));
		MMSim *sim;
		gchar *own_numbers_string;

		if (!modem) {
			continue;
		}

		ast_cli(a->fd, "\nModem '%s'\n"
			"\tManufacturer: %s\n"
			"\tModel: %s\n"
			"\tRevision: %s\n"
			"\tEquipmentIdentifier: %s\n"
			"\tState: %d\n"
			"\tVoice: %s\n"
			"\tEmergency Only: %s\n",
			mm_modem_get_device_identifier(modem),
			mm_modem_get_manufacturer(modem),
			mm_modem_get_model(modem),
			mm_modem_get_revision(modem),
			mm_modem_get_equipment_identifier(modem),
			mm_modem_get_state(modem),
			modem_voice ? mm_modem_voice_get_path(modem_voice) : "(not supported)",
			modem_voice ? AST_YESNO(mm_modem_voice_get_emergency_only(modem_voice)) : "(not supported)"
		);

		own_numbers_string = g_strjoinv(", ", (gchar **)mm_modem_get_own_numbers(modem));
		ast_cli(a->fd, "\tOwnNumbers: %s\n", S_OR(own_numbers_string, ""));
		g_free(own_numbers_string);

		sim = mm_modem_get_sim_sync(modem, NULL, &error);
		if (error) {
			ast_cli(a->fd, "\tFailed to get Sim - (%d) %s\n",
				error->code, error->message);
			g_clear_error(&error);
		} else if (sim) {
			ast_cli(a->fd, "\tSim %s:\n"
				"\t\tImsi: %s\n"
				"\t\tOperatorIdentifier: %s\n"
				"\t\tOperatorName: %s\n",
				mm_sim_get_identifier(sim),
				mm_sim_get_imsi(sim),
				mm_sim_get_operator_identifier(sim),
				mm_sim_get_operator_name(sim)
			);
			g_object_unref(sim);
		}
	}
	g_list_free_full(objects, g_object_unref);

	alsa_cli_list_devices(a->fd);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_modemmanager[] = {
	AST_CLI_DEFINE(cli_list_available, "List available devices"),
};

int mm_cli_register(void)
{
	return ast_cli_register_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager));
}

void mm_cli_unregister(void)
{
	ast_cli_unregister_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager));
}
