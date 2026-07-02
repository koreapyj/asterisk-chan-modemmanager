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

#include "asterisk/logger.h"
#include "asterisk/message.h"
#include "asterisk/utils.h"

#include "mm_bus.h"
#include "mms/mms.h"
#include "sim.h"
#include "sms.h"

/*!
 * \brief ast_msg_tech send callback.
 *
 * Destination format: ModemManager:<number>@<sim identifier>
 */
static int modemmanager_msg_send(const struct ast_msg *msg, const char *to, const char *from)
{
	int res = 0;
	GError *error = NULL;
	sim_pvt_t *sim = NULL;
	MMModemMessaging *messaging = NULL;
	MMSmsProperties *props = NULL;
	MMSms *sms = NULL;

	char *_to = ast_alloca(strlen(to) + 1);
	strcpy(_to, to); /* safe: exact-size copy onto the stack */
	char *number = strchr(_to, ':');
	char *simid = strchr(_to, '@');
	if (!number || !simid || simid < number) {
		ast_log(LOG_WARNING, "Invalid destination '%s' - expected ModemManager:<number>@<sim>\n", to);
		return -1;
	}
	*number++ = '\0';
	*simid++ = '\0';

	sim = find_sim(simid);
	if (!sim) {
		ast_log(LOG_WARNING, "Unable to find sim '%s'\n", simid);
		return -1;
	}
	{
		modem_pvt_t *modem = sim_grab_modem(sim);

		if (modem) {
			modemmanager_pvt_lock(modem);
			messaging = modem->messaging ? g_object_ref(modem->messaging) : NULL;
			modemmanager_pvt_unlock(modem);
			unref_modem(modem);
		}
	}
	if (!messaging) {
		ast_log(LOG_WARNING, "Sim '%s' has no resolved modem with messaging support\n", simid);
		res = -1;
		goto done;
	}

	props = mm_sms_properties_new();
	mm_sms_properties_set_text(props, ast_msg_get_body(msg));
	mm_sms_properties_set_number(props, number);

	sms = mm_modem_messaging_create_sync(messaging, props, NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to create message - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		res = -1;
		goto done;
	}

	mm_sms_send_sync(sms, NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to send message - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		res = -1;
	}

	mm_modem_messaging_delete_sync(messaging, mm_sms_get_path(sms), NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to delete sent message - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
	}

done:
	if (sms) {
		g_object_unref(sms);
	}
	if (props) {
		g_object_unref(props);
	}
	if (messaging) {
		g_object_unref(messaging);
	}
	unref_sim(sim);
	return res;
}

const struct ast_msg_tech mm_msg_tech = {
	.name = "ModemManager",
	.msg_send = modemmanager_msg_send,
};

/*!
 * \brief Deliver one received text SMS to the Asterisk message bus.
 */
static void deliver_text_sms(sim_pvt_t *sim, MMSms *message)
{
	struct ast_msg *msg;
	int res = 0;

	ast_verb(3, "Incoming SMS from %s on sim %s\n",
		mm_sms_get_number(message), sim->identifier);

	msg = ast_msg_alloc();
	if (!msg) {
		ast_log(LOG_WARNING, "Failed to allocate message\n");
		return;
	}
	res |= ast_msg_set_context(msg, "%s", S_OR(sim->message_context, sim->context));
	res |= ast_msg_set_exten(msg, "%s", S_OR(sim->exten, ""));
	res |= ast_msg_set_to(msg, "%s", S_OR(sim->exten, ""));
	res |= ast_msg_set_from(msg, "%s", mm_sms_get_number(message));
	res |= ast_msg_set_body(msg, "%s", mm_sms_get_text(message));
	res |= ast_msg_set_tech(msg, "%s", "ModemManager");
	res |= ast_msg_set_endpoint(msg, "%s", sim->identifier);
	if (res) {
		ast_log(LOG_WARNING, "Failed to build message\n");
		ast_msg_destroy(msg);
		return;
	}

	if (!ast_msg_has_destination(msg)) {
		ast_log(LOG_WARNING, "SMS received, but no dialplan handler wanted it "
			"(context '%s', exten '%s')\n",
			S_OR(sim->message_context, sim->context), S_OR(sim->exten, ""));
		ast_msg_destroy(msg);
		return;
	}
	ast_msg_queue(msg);
}

struct message_added_task {
	sim_pvt_t *sim;
	char *path;
};

static int task_message_added(void *data)
{
	struct message_added_task *t = data;
	sim_pvt_t *sim = t->sim;
	modem_pvt_t *modem = sim_grab_modem(sim);
	MMModemMessaging *messaging = NULL;
	MMSms *message = NULL;
	GError *error = NULL;
	GList *messages, *l;

	if (!modem) {
		goto done;
	}
	modemmanager_pvt_lock(modem);
	if (modem->messaging) {
		messaging = g_object_ref(modem->messaging);
	}
	modemmanager_pvt_unlock(modem);
	if (!messaging) {
		goto done;
	}

	mm_bus_push_context();
	messages = mm_modem_messaging_list_sync(messaging, NULL, &error);
	mm_bus_pop_context();
	if (error) {
		ast_log(LOG_WARNING, "Failed to list messages - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		goto done;
	}
	for (l = messages; l; l = g_list_next(l)) {
		if (!message && !g_strcmp0(t->path, mm_sms_get_path(MM_SMS(l->data)))) {
			message = g_object_ref(MM_SMS(l->data));
		}
	}
	g_list_free_full(messages, g_object_unref);

	if (!message) {
		ast_log(LOG_WARNING, "Added message %s not found\n", t->path);
		goto done;
	}

	if (mm_sms_get_state(message) == MM_SMS_STATE_RECEIVED) {
		const char *text = mm_sms_get_text(message);

		if (text && strcmp(text, "(null)")) {
			deliver_text_sms(sim, message);
		} else {
			/* Binary payload: WAP push carrying an MMS notification */
			gsize data_len = 0;
			const guint8 *data = mm_sms_get_data(message, &data_len);

			if (data && data_len) {
				mms_on_wap_push_sms(sim, data, data_len,
					mm_sms_get_number(message), t->path);
			} else {
				ast_debug(1, "Received SMS %s has neither text nor data\n", t->path);
			}
		}
	}

done:
	if (message) {
		g_object_unref(message);
	}
	if (messaging) {
		g_object_unref(messaging);
	}
	unref_modem(modem);
	unref_sim(sim);
	ast_free(t->path);
	ast_free(t);
	return 0;
}

void on_message_added(MMModemMessaging *messaging, const char *path, gboolean received, void *data)
{
	sim_pvt_t *sim = data;
	modem_pvt_t *modem;
	struct message_added_task *t;

	ast_debug(1, "Message added - %s received: %d (sim %s)\n", path, received, sim->identifier);

	if (!received) {
		return;
	}
	modem = sim_grab_modem(sim);
	if (!modem) {
		return;
	}
	if (!modem->serializer) {
		unref_modem(modem);
		return;
	}

	t = ast_calloc(1, sizeof(*t));
	if (!t) {
		unref_modem(modem);
		return;
	}
	t->sim = ref_sim(sim);
	t->path = ast_strdup(path);

	if (ast_taskprocessor_push(modem->serializer, task_message_added, t)) {
		unref_sim(t->sim);
		ast_free(t->path);
		ast_free(t);
	}
	unref_modem(modem);
}
