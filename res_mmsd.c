/*
 * res_mmsd -- mmsd-tng channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * Yoonji Park <koreapyj@dcmys.kr>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \li \ref res_mmsd.c uses the configuration file \ref mmsd.conf
 * \addtogroup configuration_file Configuration Files
 */

#define AST_MODULE "res_mmsd"

#include "asterisk.h"

#include <gio/gio.h>
#include <glib.h>

#include "asterisk/module.h"
#include "asterisk/manager.h"
#include "asterisk/app.h"
#include "asterisk/mwi.h"
#include "asterisk/message.h"
#include "asterisk/manager.h"
#include "asterisk/cli.h"
#include "asterisk/config_options.h"
#include "asterisk/json.h"

GDBusConnection *dbus = NULL;
pthread_t ptmainloop = AST_PTHREADT_NULL;
GMainLoop *loop;

static int mmsd_send(const struct ast_msg *msg, const char *to, const char *from) {
	return -1;
}

static char *cli_list_messages(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	GError *error = NULL;
	int ret;

	if (cmd == CLI_INIT) {
		e->command = "mmsd list mms";
		e->usage =
			"Usage: mmsd list mms\n"
			"       List all mms messages.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

	if (a->argc != e->args)
		return CLI_SHOWUSAGE;

	if (dbus == NULL) {
		ast_cli(a->fd, "Session DBus is not connected. MMS disabled.");
		return NULL;
	}

	GVariant *res;
	res = g_dbus_connection_call_sync(dbus, "org.ofono.mms", "/org/ofono/mms/modemmanager", "org.ofono.mms.Service", "GetMessages", NULL, g_variant_type_new("(a(oa{sv}))"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to list mms - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		return;
	}

	GVariant *mmsarr;
	GVariantIter *mmsiter;
	g_variant_get(res, "(@a(oa{sv}))", &mmsarr);
	g_variant_get(mmsarr, "a(oa{sv})", &mmsiter);

	gchar *path;
	GVariant *props;
	while (g_variant_iter_loop(mmsiter, "(o@a{sv})", &path, &props)) {
		ast_cli(a->fd, "Path: %s (%s)\n", path, g_variant_get_type_string(props));

      	GVariantDict dict;
		g_variant_dict_init (&dict, props);
      	char *subject, *date, *status, *sender, *number;
		g_variant_dict_lookup(&dict, "Subject", "s", &subject);
		g_variant_dict_lookup(&dict, "Date", "s", &date);
		g_variant_dict_lookup(&dict, "Status", "s", &status);
		g_variant_dict_lookup(&dict, "Sender", "s", &sender);
		g_variant_dict_lookup(&dict, "Modem Number", "s", &number);

		ast_cli(a->fd,
			"\tSubject: %s\n"
			"\tDate: %s\n"
			"\tStatus: %s\n"
			"\tSender: %s\n"
			"\tModem Number: %s\n"
			,
			subject?subject:"(null)",
			date?date:"(null)",
			status?status:"(null)",
			sender?sender:"(null)",
			number?number:"(null)"
		);
		g_variant_dict_clear(&dict);
	}

	g_variant_unref(res);

	return CLI_SUCCESS;
}

static void on_message_added(GDBusConnection *conn, const gchar* sender_name, const gchar* object_path, const gchar* interface_name, const gchar* signal_name, GVariant* parameters, gpointer user_data)
{
	GError *error = NULL;
	gchar *msgpath = NULL;
	GVariant *props;
	g_variant_get(parameters, "(o@a{sv})", &msgpath, &props);
	ast_verb(1, "Message added: %s (%s)\n", msgpath, g_variant_get_type_string(props));
	g_free(msgpath);

	GVariantDict dict;
	g_variant_dict_init (&dict, props);
	char *subject, *date, *status, *_sender, *_number;
	g_variant_dict_lookup(&dict, "Subject", "s", &subject);
	g_variant_dict_lookup(&dict, "Date", "s", &date);
	g_variant_dict_lookup(&dict, "Status", "s", &status);
	g_variant_dict_lookup(&dict, "Sender", "s", &_sender);
	g_variant_dict_lookup(&dict, "Modem Number", "s", &_number);

	gchar **senderv = g_strsplit(_sender, " ", 0), **numberv = g_strsplit(_number, " ", 0);
	gchar *sender = g_strjoinv(NULL, senderv), *number = g_strjoinv(NULL, numberv);
	g_strfreev(senderv); g_strfreev(numberv);

	ast_verb(1,
		"\tSubject: %s\n"
		"\tDate: %s\n"
		"\tStatus: %s\n"
		"\tSender: %s\n"
		"\tModem Number: %s\n"
		,
		subject?subject:"(null)",
		date?date:"(null)",
		status?status:"(null)",
		sender?sender:"(null)",
		number?number:"(null)"
	);

	GVariant *attachments;
	g_variant_dict_lookup(&dict, "Attachments", "@a(ssstt)", &attachments);
	GVariantIter *attachiter;
	g_variant_get(attachments, "a(ssstt)", &attachiter);
	ast_verb(1, "Attachment found %s\n", g_variant_get_type_string(attachments));
	char *id, *content_type, *filename;
	uint64_t offset, len;
  	while (g_variant_iter_loop (attachiter, "(ssstt)", &id, &content_type, &filename, &offset, &len)) {
		ast_verb(1,
			"\tId: %s\n"
			"\tContent-Type: %s\n"
			"\tFilename: %s\n"
			"\tOffset: %llu\n"
			"\tLen: %llu\n"
			,
			id?id:"(null)",
			content_type?content_type:"(null)",
			filename?filename:"(null)",
			offset?offset:-1,
			len?len:-1
		);
		if(!ast_begins_with(content_type, "text/plain")) {
			ast_verb(1, "Content type is not acceptable. skip read content.\n");
			continue;
		}

		FILE *fp = fopen(filename, "r");
		if(fp == NULL) {
			ast_log(LOG_WARNING, "Failed to open file %s\n", filename);
			continue;
		}
		if(fseek(fp, offset, SEEK_SET)) {
			ast_log(LOG_WARNING, "Failed to seek file %s\n", filename);
			fclose(fp);
			continue;
		}
		char *content = ast_alloca(len+1);
		int num = fread(content, sizeof(char), len, fp);
		if(!num) {
			if (ferror(fp))
				ast_log(LOG_WARNING, "Error reading content of file" );
			else if ( feof(fp))
				ast_log(LOG_WARNING, "EOF found" );
			fclose(fp);
			continue;
		}
		content[num] = '\0';
		ast_verb(1, "Content: %s\n", content);
		fclose(fp);

		struct ast_msg *msg = ast_msg_alloc();
		ast_verb(1, "Created ast_msg\n");
		int res = 0;
		if (!msg) {
			ast_log(LOG_WARNING, "Failed to create ast_msg\n");
			return;
		}
		res |= ast_msg_set_context(msg, "%s", "from-mobile-message");
		res |= ast_msg_set_exten(msg, "%s", number);
		res |= ast_msg_set_to(msg, "%s", number);
		res |= ast_msg_set_from(msg, "%s", sender);
		res |= ast_msg_set_body(msg, "%s", content);
		res |= ast_msg_set_tech(msg, "%s", "mmsd");
		res |= ast_msg_set_endpoint(msg, "%s", number);
		if(res) {
			ast_log(LOG_WARNING, "Failed to set ast_msg variables\n");
			ast_msg_destroy(msg);
			continue;
		}

		if (!ast_msg_has_destination(msg)) {
			ast_log(LOG_WARNING, "MESSAGE request received, but no handler wanted it\n");
			ast_msg_destroy(msg);
			continue;
		}
		ast_msg_queue(msg);
	}
	g_variant_iter_free(attachiter);
	g_variant_unref(attachments);
	g_free(number);
	g_free(sender);
}

static void create_mainloop() {
	ast_verb(1, "GMainLoop started\n");
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	g_main_loop_unref(loop);
	ast_verb(1, "GMainLoop stopped\n");
}

static struct ast_cli_entry cli_mmsd[] = {
	AST_CLI_DEFINE(cli_list_messages, "List MMS messages"),
};

static const struct ast_msg_tech msg_tech = {
	.name = "mmsd",
	.msg_send = mmsd_send,
};

static int unload_module(void)
{
	ast_msg_tech_unregister(&msg_tech);
	ast_cli_unregister_multiple(cli_mmsd, ARRAY_LEN(cli_mmsd));
	g_main_loop_quit(loop);

	return 0;
}

/*!
 * \brief Load the module
 *
 * Module loading including tests for configuration or dependencies.
 * This function can return AST_MODULE_LOAD_FAILURE, AST_MODULE_LOAD_DECLINE,
 * or AST_MODULE_LOAD_SUCCESS. If a dependency or environment variable fails
 * tests return AST_MODULE_LOAD_FAILURE. If the module can not load the
 * configuration file or other non-critical problem return
 * AST_MODULE_LOAD_DECLINE. On success return AST_MODULE_LOAD_SUCCESS.
 */
static int load_module(void)
{
	GError *error = NULL;
	dbus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to connect session DBus daemon - MMS unavailable - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
	}

	ast_msg_tech_register(&msg_tech);

	ast_cli_register_multiple(cli_mmsd, ARRAY_LEN(cli_mmsd));

	g_dbus_connection_signal_subscribe(dbus, "org.ofono.mms", "org.ofono.mms.Service", "MessageAdded", "/org/ofono/mms/modemmanager", NULL, G_DBUS_SIGNAL_FLAGS_NONE, G_CALLBACK(on_message_added), NULL, NULL);

	ast_pthread_create_background(&ptmainloop, NULL, create_mainloop, NULL);

	return AST_MODULE_LOAD_SUCCESS;
}

static int reload(void)
{
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Asterisk MMSD Interface",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.load_pri = AST_MODPRI_CHANNEL_DEPEND,
);
