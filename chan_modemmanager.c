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
 * \note Some of the code in this file came from chan_oss, chan_alsa and chan_console.
 *       chan_console,  Russell Bryant <russell@digium.com>
 *       chan_oss,      Mark Spencer <markster@digium.com>
 *       chan_oss,      Luigi Rizzo
 *       chan_alsa,     Matthew Fredrickson <creslin@digium.com>
 *
 * \ingroup channel_drivers
 *
 * Portaudio http://www.portaudio.com/
 *
 * To install portaudio v19 from svn, check it out using the following command:
 *  - svn co https://www.portaudio.com/repos/portaudio/branches/v19-devel
 */

/*! \li \ref chan_modemmanager.c uses the configuration file \ref modemmanager.conf
 * \addtogroup configuration_file
 */

/*! \page modemmanager.conf modemmanager.conf
 * \verbinclude modemmanager.conf.sample
 */

/*** MODULEINFO
	<depend>portaudio</depend>
	<support_level>extended</support_level>
 ***/
#define AST_MODULE "chan_modemmanager"

#include "asterisk.h"

#include <signal.h>  /* SIGURG */

#include <portaudio.h>
#include <ModemManager/ModemManager.h>
#include <gio/gio.h>
#include <glib.h>
#include <libmm-glib.h>

#include "asterisk/message.h"
#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/causes.h"
#include "asterisk/cli.h"
#include "asterisk/musiconhold.h"
#include "asterisk/callerid.h"
#include "asterisk/astobj2.h"
#include "asterisk/stasis_channels.h"
#include "asterisk/format_cache.h"

/*!
 * \brief The sample rate to request from PortAudio
 *
 * \todo Make this optional.  If this is only going to talk to 8 kHz endpoints,
 *       then it makes sense to use 8 kHz natively.
 */
#define SAMPLE_RATE      8000

/*!
 * \brief The number of samples to configure the portaudio stream for
 *
 * 320 samples (20 ms) is the most common frame size in Asterisk.  So, the code
 * in this module reads 320 sample frames from the portaudio stream and queues
 * them up on the Asterisk channel.  Frames of any size can be written to a
 * portaudio stream, but the portaudio documentation does say that for high
 * performance applications, the data should be written to Pa_WriteStream in
 * the same size as what is used to initialize the stream.
 */
#define NUM_SAMPLES      160

/*! \brief Mono Input */
#define INPUT_CHANNELS   1

/*! \brief Mono Output */
#define OUTPUT_CHANNELS  1

/*!
 * \brief Maximum text message length
 * \note This should be changed if there is a common definition somewhere
 *       that defines the maximum length of a text message.
 */
#define TEXT_SIZE	256

/*! \brief Dance, Kirby, Dance! @{ */
#define V_BEGIN " --- <(\"<) --- "
#define V_END   " --- (>\")> ---\n"
/*! @} */

static const char config_file[] = "modemmanager.conf";

/*!
 * \brief abstract pvt structure
 */
typedef struct abstract_pvt {
	AST_DECLARE_STRING_FIELDS(
		/*! ModemManager identifier for modem */
		AST_STRING_FIELD(identifier);
	);
} abstract_pvt_t;

/*!
 * \brief ModemManager modem pvt structure
 */
typedef struct modem_pvt {
	AST_DECLARE_STRING_FIELDS(
		/*! ModemManager identifier for modem */
		AST_STRING_FIELD(identifier);
		AST_STRING_FIELD(input_device);
		AST_STRING_FIELD(output_device);
	);
	/*! Current channel for this device */
	struct ast_channel *owner;
	/*! Current PortAudio stream for this device */
	PaStream *stream;
	/*! A frame for preparing to queue on to the channel */
	struct ast_frame fr;
	/*! Running = 1, Not running = 0 */
	unsigned int streamstate:1;
	/*! Abort stream processing? */
	unsigned int abort:1;
	/*! On-hook = 0, Off-hook = 1 */
	unsigned int hookstate:1;
	/*! Unmuted = 0, Muted = 1 */
	unsigned int muted:1;
	/*! Modem device */
	MMModem *device;
	/*! Modem voice */
	MMModemVoice *voice;
	/*! Modem messaging */
	MMModemMessaging *messaging;
	/*! Current call */
	MMCall *call;
	/*! Jitterbuffer */
	struct ast_jb_conf jbconf;
	/*! Set during a reload so that we know to destroy this if it is no longer
	 *  in the configuration file. */
	unsigned int destroy:1;
	/*! ID for the stream monitor thread */
	pthread_t thread;
} modem_pvt_t;

/*!
 * \brief ModemManager sim pvt structure
 */
typedef struct sim_pvt {
	AST_DECLARE_STRING_FIELDS(
		/*! ModemManager identifier for sim */
		AST_STRING_FIELD(identifier);
		/*! Default context for incoming calls */
		AST_STRING_FIELD(context);
		/*! Default context for incoming messages */
		AST_STRING_FIELD(message_context);
		/*! Default extension for incoming calls */
		AST_STRING_FIELD(exten);
		/*! Default MOH class to listen to, if:
		 *    - No MOH class set on the channel
		 *    - Peer channel putting this device on hold did not suggest a class */
		AST_STRING_FIELD(mohinterpret);
		/*! Default language */
		AST_STRING_FIELD(language);
		/*! Default parkinglot */
		AST_STRING_FIELD(parkinglot);
	);
	/*! Automatically answer incoming calls */
	unsigned int autoanswer:1;
	/*! Ignore context in the console dial CLI command */
	unsigned int overridecontext:1;
	/*! Assigned modem */
	modem_pvt_t *modem;
	/*! Sim device */
	MMSim *device;
	/*! Set during a reload so that we know to destroy this if it is no longer
	 *  in the configuration file. */
	unsigned int destroy:1;
} sim_pvt_t;

static struct ao2_container *modems;
static struct ao2_container *sims;
#define NUM_PVT_BUCKETS 7

pthread_t ptmainloop = AST_PTHREADT_NULL;
GMainLoop *loop;
GDBusConnection *dbus;
MMManager *manager;

/*!
 * \brief Global jitterbuffer configuration
 *
 * \note Disabled by default.
 * \note Values shown here match the defaults shown in console.conf.sample
 */
static struct ast_jb_conf default_jbconf = {
	.flags = 0,
	.max_size = 200,
	.resync_threshold = 1000,
	.impl = "fixed",
	.target_extra = 40,
};

/*! Channel Technology Callbacks @{ */
static struct ast_channel *modemmanager_request(const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause);
static int modemmanager_digit_begin(struct ast_channel *c, char digit);
static int modemmanager_digit_end(struct ast_channel *c, char digit, unsigned int duration);
static int modemmanager_text(struct ast_channel *c, const char *text);
static int modemmanager_hangup(struct ast_channel *c);
static int modemmanager_answer(struct ast_channel *c);
static struct ast_channel *modemmanager_new(sim_pvt_t *sim, const char *cid, const char *ext, const char *ctx, int state, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor);
static struct ast_frame *modemmanager_read(struct ast_channel *chan);
static int modemmanager_call(struct ast_channel *c, const char *dest, int timeout);
static int modemmanager_write(struct ast_channel *chan, struct ast_frame *f);
static int modemmanager_indicate(struct ast_channel *chan, int cond,
	const void *data, size_t datalen);
static int modemmanager_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
/*! @} */
static int modemmanager_send(const struct ast_msg *msg, const char *to, const char *from);

static void oncalldtmfreceived(MMCall *call, char *dtmf, sim_pvt_t *sim);
static void oncallstatechanged(MMCall *call, MMCallState old, MMCallState new, MMCallStateReason reason, sim_pvt_t *sim);

static struct ast_channel_tech modemmanager_tech = {
	.type = "ModemManager",
	.description = "ModemManager Channel Driver",
	.requester = modemmanager_request,
	.send_digit_begin = modemmanager_digit_begin,
	.send_digit_end = modemmanager_digit_end,
	// .send_text = modemmanager_text,
	.hangup = modemmanager_hangup,
	.answer = modemmanager_answer,
	.read = modemmanager_read,
	.call = modemmanager_call,
	.write = modemmanager_write,
	.indicate = modemmanager_indicate,
	// .fixup = modemmanager_fixup,
};

static const struct ast_msg_tech msg_tech = {
	.name = "ModemManager",
	.msg_send = modemmanager_send,
};

/*! \brief lock a modemmanager_pvt struct */
#define modemmanager_pvt_lock(pvt) ao2_lock(pvt)

/*! \brief unlock a modemmanager_pvt struct */
#define modemmanager_pvt_unlock(pvt) ao2_unlock(pvt)

static inline modem_pvt_t *ref_modem(modem_pvt_t *pvt)
{
	if (pvt)
		ao2_ref(pvt, +1);
	return pvt;
}

static inline modem_pvt_t *unref_modem(modem_pvt_t *pvt)
{
	ao2_ref(pvt, -1);
	return NULL;
}

static inline sim_pvt_t *ref_sim(sim_pvt_t *pvt)
{
	if (pvt)
		ao2_ref(pvt, +1);
	return pvt;
}

static inline sim_pvt_t *unref_sim(sim_pvt_t *pvt)
{
	ao2_ref(pvt, -1);
	return NULL;
}

/*!
 * \brief Set default values for a sim pvt
 *
 * \note This function expects the pvt lock to be held.
 */
static void set_sim_defaults(sim_pvt_t *pvt)
{
	ast_string_field_set(pvt, mohinterpret, "default");
	ast_string_field_set(pvt, context, "default");
	ast_string_field_set(pvt, message_context, NULL);
	ast_string_field_set(pvt, exten, NULL);
	ast_string_field_set(pvt, language, "");
	ast_string_field_set(pvt, parkinglot, "");

	pvt->overridecontext = 0;
	pvt->autoanswer = 0;
}

/*!
 * \brief Store a configuration parameter in a modem pvt struct
 *
 * \note This function expects the pvt lock to be held.
 */
static void store_config_modem(modem_pvt_t *pvt, const char *var, const char *value)
{
	ast_log(LOG_NOTICE, "Storing '%s' => %s\n", var, value);
	if(!ast_jb_read_conf(&pvt->jbconf, var, value)) {
		return;
	}
	CV_START(var, value);

	CV_STRFIELD("identifier", pvt, identifier);
	CV_STRFIELD("input_device", pvt, input_device);
	CV_STRFIELD("output_device", pvt, output_device);
	CV_F("type", NULL);

	ast_log(LOG_WARNING, "Unknown option '%s'\n", var);

	CV_END;
}

static modem_pvt_t *find_modem(const char *identifier)
{
	modem_pvt_t tmp_pvt = {
		.identifier = identifier,
	};

	return ao2_find(modems, &tmp_pvt, OBJ_POINTER);
}

static void modem_destructor(void *obj)
{
	modem_pvt_t *pvt = obj;
	g_object_unref(pvt->device);
	ast_string_field_free_memory(pvt);
}

static int init_modem(modem_pvt_t *pvt, const char *identifier)
{
	pvt->thread = AST_PTHREADT_NULL;

	if (ast_string_field_init(pvt, 32))
		return -1;

	ast_string_field_set(pvt, identifier, S_OR(identifier, ""));

	pvt->device = NULL;
	memcpy(&pvt->jbconf, &default_jbconf, sizeof(&pvt->jbconf));

	return 0;
}

static void build_modem(struct ast_config *cfg, const char *name)
{
	struct ast_variable *v;
	modem_pvt_t *pvt;
	int new = 0;

	if ((pvt = find_modem(name))) {
		modemmanager_pvt_lock(pvt);
		pvt->destroy = 0;
	} else {
		if (!(pvt = ao2_alloc(sizeof(*pvt), modem_destructor)))
			return;
		init_modem(pvt, name);
		new = 1;
	}

	for (v = ast_variable_browse(cfg, name); v; v = v->next)
		store_config_modem(pvt, v->name, v->value);

	if (new)
		ao2_link(modems, pvt);
	else
		modemmanager_pvt_unlock(pvt);

	unref_modem(pvt);
}

static int modem_mark_destroy_cb(void *obj, void *arg, int flags)
{
	modem_pvt_t *pvt = obj;
	pvt->destroy = 1;
	return 0;
}

/*!
 * \brief Store a configuration parameter in a sim pvt struct
 *
 * \note This function expects the pvt lock to be held.
 */
static void store_config_sim(sim_pvt_t *pvt, const char *var, const char *value)
{
	ast_log(LOG_NOTICE, "Storing '%s' => %s\n", var, value);
	CV_START(var, value);

	CV_STRFIELD("identifier", pvt, identifier);
	CV_BOOL("autoanswer", pvt->autoanswer);
	CV_STRFIELD("context", pvt, context);
	CV_STRFIELD("message_context", pvt, message_context);
	CV_STRFIELD("extension", pvt, exten);
	CV_STRFIELD("language", pvt, language);
	CV_BOOL("overridecontext", pvt->overridecontext);
	CV_STRFIELD("mohinterpret", pvt, mohinterpret);
	CV_STRFIELD("parkinglot", pvt, parkinglot);
	CV_F("type", NULL);

	ast_log(LOG_WARNING, "Unknown option '%s'\n", var);

	CV_END;
}

static sim_pvt_t *find_sim(const char *identifier)
{
	sim_pvt_t tmp_pvt = {
		.identifier = identifier,
	};

	return ao2_find(sims, &tmp_pvt, OBJ_POINTER);
}

static void sim_destructor(void *obj)
{
	sim_pvt_t *pvt = obj;
	g_object_unref(pvt->device);
	ast_string_field_free_memory(pvt);
}

static int init_sim(sim_pvt_t *pvt, const char *identifier)
{
	if (ast_string_field_init(pvt, 32))
		return -1;

	ast_string_field_set(pvt, identifier, S_OR(identifier, ""));

	return 0;
}

static void build_sim(struct ast_config *cfg, const char *name)
{
	struct ast_variable *v;
	sim_pvt_t *pvt;
	int new = 0;

	if ((pvt = find_sim(name))) {
		modemmanager_pvt_lock(pvt);
		set_sim_defaults(pvt);
		pvt->destroy = 0;
	} else {
		if (!(pvt = ao2_alloc(sizeof(*pvt), sim_destructor)))
			return;
		init_sim(pvt, name);
		set_sim_defaults(pvt);
		new = 1;
	}

	for (v = ast_variable_browse(cfg, name); v; v = v->next)
		store_config_sim(pvt, v->name, v->value);

	if (new)
		ao2_link(sims, pvt);
	else
		modemmanager_pvt_unlock(pvt);

	unref_sim(pvt);
}

static int sim_mark_destroy_cb(void *obj, void *arg, int flags)
{
	sim_pvt_t *pvt = obj;
	pvt->destroy = 1;
	return 0;
}

static void debug_print_config(struct ast_config *cfg, const char *name)
{
	struct ast_variable *v;
	for (v = ast_variable_browse(cfg, name); v; v = v->next)
	{
		ast_log(LOG_NOTICE, "'%s' => '%s'\n", v->name, v->value);
	}
}

static void on_modem_state_changed(MMModem *modem, MMModemState old_state, MMModemState new_state, MMModemStateChangeReason reason, void *data)
{
	sim_pvt_t *sim = data;
	ast_log(LOG_NOTICE, "Modem state changed from %d to %d (Reason: %d / uid: %s)\n", old_state, new_state, reason, sim->identifier);
}

static void on_voice_call_added(MMModemVoice *voice, const char *path, void *data)
{
	GError *error = NULL;
	sim_pvt_t *sim = data;
	ast_log(LOG_NOTICE, "Call added - %s (uid: %s)\n", path, sim->identifier);

	GList *calls = mm_modem_voice_list_calls_sync(sim->modem->voice, NULL, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to list calls - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		return;
	}
	GList *l;
	MMCall *call = NULL;
	for (l = calls; l; l = g_list_next (l)) {
		if(g_strcmp0(path, mm_call_get_path(MM_CALL(l->data))) == 0) {
			call = MM_CALL(l->data);
			continue;
		}
		g_object_unref(l->data);
	}
	g_list_free(calls);

	if(!call) {
		ast_log(LOG_WARNING, "Call not found!\n");
		return;
	}

	if(mm_call_get_direction(call) == MM_CALL_DIRECTION_INCOMING) {
		struct ast_channel *chan;
		ast_log(LOG_NOTICE, "Incoming call from %s to %s (uid: %s)\n", mm_call_get_number(call), sim->exten, sim->identifier);
		modemmanager_pvt_lock(sim->modem);
		chan = modemmanager_new(sim, mm_call_dup_number(call), sim->exten, sim->context, AST_STATE_RINGING, NULL, NULL);
		sim->modem->call = call;
		modemmanager_pvt_unlock(sim->modem);
		g_signal_connect(sim->modem->call, "state-changed", G_CALLBACK(oncallstatechanged), sim);
		g_signal_connect(sim->modem->call, "dtmf-received", G_CALLBACK(oncalldtmfreceived), sim);
		if (!chan) {
			ast_log(LOG_WARNING, "Unable to create new channel\n");
			g_object_unref(call);
		}
	}
}

static int modemmanager_send(const struct ast_msg *msg, const char *to, const char *from) {
	int res = 0;
	GError *error = NULL;
	char *_to = ast_alloca(strlen(to));
	strcpy(_to, to);
	char *number = strchr(_to, ':');
	char *simid = strchr(_to, '@');
	if(number == NULL || simid == NULL) {
		ast_log(LOG_WARNING, "Invalid to address %s\n", to);
		return -1;
	}
	ast_log(LOG_NOTICE, "addr ok\n");
	number[0]='\0';
	simid[0]='\0';
	number += 1;
	simid += 1;
	ast_log(LOG_NOTICE, "number=%s, simid=%s\n", number, simid);
	// return;
	sim_pvt_t *sim = find_sim(simid);
	if(number == NULL || simid == NULL) {
		ast_log(LOG_WARNING, "Unable to find sim %s\n", simid);
		return -1;
	}
	ast_log(LOG_NOTICE, "sim ok mid=%s\n", sim->modem->identifier);
	MMSmsProperties *props = mm_sms_properties_new();
	if(props == NULL) {
		ast_log(LOG_WARNING, "Unable to create sms props %s\n", simid);
		return -1;
	}
	mm_sms_properties_set_text(props, ast_msg_get_body(msg));
	mm_sms_properties_set_number(props, number);

	MMSms *sms = mm_modem_messaging_create_sync(sim->modem->messaging, props, NULL, &error);
	g_object_unref(props);
	if(error) {
		ast_log(LOG_WARNING, "Failed to create messages - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		return -1;
	}

	mm_sms_send_sync(sms, NULL, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to send messages - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		res = -1;
	}
	mm_modem_messaging_delete_sync(sim->modem->messaging, mm_sms_get_path(sms), NULL, &error);
	g_object_unref(sms);
	return res;
}

static void on_message_added(MMModemMessaging *messaging, const char *path, gboolean received, void *data)
{
	GError *error = NULL;
	sim_pvt_t *sim = data;
	ast_log(LOG_NOTICE, "Message added - %s Received: %s (uid: %s)\n", path, AST_YESNO(received), sim->identifier);

	GList *messages = mm_modem_messaging_list_sync(sim->modem->messaging, NULL, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to list messages - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		return;
	}
	GList *l;
	MMSms *message = NULL;
	for (l = messages; l; l = g_list_next (l)) {
		if(g_strcmp0(path, mm_sms_get_path(MM_SMS(l->data))) == 0) {
			message = MM_SMS(l->data);
			continue;
		}
		g_object_unref(l->data);
	}
	g_list_free(messages);

	if(!message) {
		ast_log(LOG_WARNING, "Message not found!\n");
		return;
	}

	if(received) {
		ast_log(LOG_NOTICE, "Incoming SMS from %s to %s (uid: %s)\n", mm_sms_get_number(message), sim->exten, sim->identifier);
		ast_log(LOG_NOTICE, "PDU Type %d, SMSC %s, Ref %d, Class %d, TS %s, DCTS %s\n",
			mm_sms_get_pdu_type(message),
			mm_sms_get_smsc(message),
			mm_sms_get_message_reference(message),
			mm_sms_get_class(message),
			mm_sms_get_timestamp(message),
			mm_sms_get_discharge_timestamp(message)
		);
		const char *text = mm_sms_get_text(message);
		if(!text) {
			ast_log(LOG_WARNING, "Failed to retrieve sms text\n");
			return;
		}
		if(strcmp(text, "(null)") == 0) {
			/* Possibly MMS but currently we don't implement mms support */
		}
		else {
			ast_log(LOG_NOTICE, "Text %s\n", mm_sms_get_text(message), sim->exten, sim->identifier);
			/* PJSIP method */
			struct ast_msg *msg = ast_msg_alloc();
			ast_log(LOG_NOTICE, "Created ast_msg\n");
			int res = 0;
			if (!msg) {
				ast_log(LOG_WARNING, "Failed to create ast_msg\n");
				return;
			}
			res |= ast_msg_set_context(msg, "%s", S_OR(sim->message_context, sim->context));
			res |= ast_msg_set_exten(msg, "%s", sim->exten);
			res |= ast_msg_set_to(msg, "%s", sim->exten);
			res |= ast_msg_set_from(msg, "%s", mm_sms_get_number(message));
			res |= ast_msg_set_body(msg, "%s", mm_sms_get_text(message));
			res |= ast_msg_set_tech(msg, "%s", "ModemManager");
			res |= ast_msg_set_endpoint(msg, "%s", sim->identifier);
			if(res) {
				ast_log(LOG_WARNING, "Failed to set ast_msg variables2\n");
				ast_msg_destroy(msg);
				return;
			}

			if (!ast_msg_has_destination(msg)) {
				ast_log(LOG_WARNING, "MESSAGE request received, but no handler wanted it\n");
				ast_msg_destroy(msg);
				return;
			}
			ast_msg_queue(msg);
		}
	}
}

/*!
 * \brief Load the configuration
 * \param reload if this was called due to a reload
 * \retval 0 success
 * \retval -1 failure
 */
static int load_config(int reload)
{
	struct ast_config *cfg;
	struct ast_variable *v;
	struct ast_flags config_flags = { 0 };
	struct ast_category *context = NULL;

	if (!(cfg = ast_config_load(config_file, config_flags))) {
		ast_log(LOG_NOTICE, "Unable to open configuration file %s!\n", config_file);
		return -1;
	} else if (cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_NOTICE, "Config file %s has an invalid format\n", config_file);
		return -1;
	}

	ao2_callback(modems, OBJ_NODATA, modem_mark_destroy_cb, NULL);
	ao2_callback(sims, OBJ_NODATA, sim_mark_destroy_cb, NULL);

	while ((context = ast_category_browse_filtered(cfg, NULL, context, "type=^modem$"))) {
		build_modem(cfg, (const char*)context);
	}

	while ((context = ast_category_browse_filtered(cfg, NULL, context, "type=^sim$"))) {
		build_sim(cfg, (const char*)context);
	}

	ast_config_destroy(cfg);

	ast_log(LOG_NOTICE, "Loading modems...");
	GList *mm_objs = g_dbus_object_manager_get_objects(G_DBUS_OBJECT_MANAGER(manager));
	GError *error = NULL;
	if (mm_objs)
	{
		GList *l;
		for (l = mm_objs; l; l = g_list_next (l)) {
			GList *ifaces = g_dbus_object_get_interfaces(G_DBUS_OBJECT(l->data)), *iface = NULL;
			MMModem *mm_modem = NULL;
			MMModemVoice *mm_voice = NULL;
			MMModemMessaging *mm_msg = NULL;
			for(iface=ifaces;iface;iface = g_list_next(iface)) {
				GDBusInterfaceInfo *info = g_dbus_interface_get_info(G_DBUS_INTERFACE(iface->data));
				ast_log(LOG_NOTICE, "Dbg DBUS_INTERFACE %s\n",
					g_dbus_interface_get_info(G_DBUS_INTERFACE(iface->data))->name);
				if (g_strcmp0(info->name, MM_DBUS_INTERFACE_MODEM) == 0) {
					mm_modem = mm_object_get_modem(MM_OBJECT(l->data));
				}
				else if (g_strcmp0(info->name, MM_DBUS_INTERFACE_MODEM_VOICE) == 0) {
					mm_voice = mm_object_get_modem_voice(MM_OBJECT(l->data));
				}
				else if (g_strcmp0(info->name, MM_DBUS_INTERFACE_MODEM_MESSAGING) == 0) {
					mm_msg = mm_object_get_modem_messaging(MM_OBJECT(l->data));
				}
			}
			g_list_free_full(ifaces, (GDestroyNotify) g_object_unref);
			if(!mm_modem || !mm_voice) {
				goto unref_mm;
			}
			MMSim *mm_sim = mm_modem_get_sim_sync(mm_modem, NULL, &error);
			if(error) {
				ast_log(LOG_WARNING, "Failed to initialize modem %s - Sim error (%d) %s\n",
					mm_modem_get_path(mm_modem),
					error->code, error->message);
				g_clear_error(&error);
				goto unref_mm;
			}
			modem_pvt_t *modem = find_modem(mm_modem_get_device_identifier(mm_modem));
			if(!modem) {
				goto unref_mm;
			}
			modem->device = mm_modem;
			modem->voice = mm_voice;
			modem->messaging = mm_msg;
			ast_log(LOG_NOTICE, "Resolved modem %s at %s",
				mm_modem_get_device_identifier(mm_modem),
				mm_modem_get_path(mm_modem));
			sim_pvt_t *sim = find_sim(mm_sim_get_identifier(mm_sim));
			if(!sim) {
				goto unref_mm;
			}
			ast_log(LOG_NOTICE, "Resolved sim %s at %s",
				mm_sim_get_identifier(mm_sim),
				mm_sim_get_path(mm_sim));
			sim->device = mm_sim;
			sim->modem = modem;
			if(ast_strlen_zero(sim->exten)) {
				ast_string_field_set(sim, exten, (gchar**)mm_modem_get_own_numbers(mm_modem)[0]);
			}
			ast_log(LOG_NOTICE, "Resolved sim %s exten %s",
				mm_sim_get_identifier(mm_sim),
				sim->exten);
			g_signal_connect(mm_modem, "state-changed", G_CALLBACK(on_modem_state_changed), sim);
			g_signal_connect(mm_voice, "call-added", G_CALLBACK(on_voice_call_added), sim);
			g_signal_connect(mm_msg, "added", G_CALLBACK(on_message_added), sim);
			continue;
unref_mm:
			g_object_unref(mm_modem);
			g_object_unref(mm_voice);
			g_object_unref(mm_sim);
		}
		g_list_free(mm_objs);
	}

	return 0;
}

static int pvt_hash_cb(const void *obj, const int flags)
{
	const abstract_pvt_t *pvt = obj;

	return ast_str_case_hash(pvt->identifier);
}

static int pvt_cmp_cb(void *obj, void *arg, int flags)
{
	abstract_pvt_t *pvt = obj, *pvt2 = arg;

	return !strcasecmp(pvt->identifier, pvt2->identifier) ? CMP_MATCH | CMP_STOP : 0;
}

/*!
 * \brief Stream monitor thread
 *
 * \arg data A pointer to the console_pvt structure that contains the portaudio
 *      stream that needs to be monitored.
 *
 * This function runs in its own thread to monitor data coming in from a
 * portaudio stream.  When enough data is available, it is queued up to
 * be read from the Asterisk channel.
 */
static void *stream_monitor(void *data)
{
	sim_pvt_t *sim = data;
	char buf[NUM_SAMPLES * sizeof(int16_t)];
	PaError res;
	struct ast_frame f = {
		.frametype = AST_FRAME_VOICE,
		.subclass.format = ast_format_slin,
		.src = "modemmanager_stream_monitor",
		.data.ptr = buf,
		.datalen = sizeof(buf),
		.samples = sizeof(buf) / sizeof(int16_t),
	};

	for (;;) {
		modemmanager_pvt_lock(sim->modem);
		res = Pa_ReadStream(sim->modem->stream, buf, sizeof(buf) / sizeof(int16_t));
		modemmanager_pvt_unlock(sim->modem);

		if (!sim->modem->owner || sim->modem->abort) {
			ast_log(LOG_NOTICE, "aborting...\n");
			sim->modem->abort = 0;
			return NULL;
		}

		if (res == paNoError) {
			ast_queue_frame(sim->modem->owner, &f);
		} else {
			ast_log(LOG_WARNING, "Console ReadStream failed: %s\n", Pa_GetErrorText(res));
		}
	}

	return NULL;
}

static int open_stream(sim_pvt_t *sim)
{
	int res = paInternalError;

	if (!strcasecmp(sim->modem->input_device, "default") &&
		!strcasecmp(sim->modem->output_device, "default")) {
		res = Pa_OpenDefaultStream(&sim->modem->stream, INPUT_CHANNELS, OUTPUT_CHANNELS,
			paInt16, SAMPLE_RATE, NUM_SAMPLES, NULL, NULL);
	} else {
		PaStreamParameters input_params = {
			.channelCount = 1,
			.sampleFormat = paInt16,
			.suggestedLatency = (1.0 / 100.0), /* 20 ms */
			.device = paNoDevice,
		};
		PaStreamParameters output_params = {
			.channelCount = 1,
			.sampleFormat = paInt16,
			.suggestedLatency = (1.0 / 100.0), /* 20 ms */
			.device = paNoDevice,
		};
		PaDeviceIndex idx, num_devices, def_input, def_output;

		if (!(num_devices = Pa_GetDeviceCount()))
			return res;

		def_input = Pa_GetDefaultInputDevice();
		def_output = Pa_GetDefaultOutputDevice();

		for (idx = 0;
			idx < num_devices && (input_params.device == paNoDevice
				|| output_params.device == paNoDevice);
			idx++)
		{
			const PaDeviceInfo *dev = Pa_GetDeviceInfo(idx);

			if (dev->maxInputChannels) {
				if ( (idx == def_input && !strcasecmp(sim->modem->input_device, "default")) ||
					!strcasecmp(sim->modem->input_device, dev->name) )
					input_params.device = idx;
			}

			if (dev->maxOutputChannels) {
				if ( (idx == def_output && !strcasecmp(sim->modem->output_device, "default")) ||
					!strcasecmp(sim->modem->output_device, dev->name) )
					output_params.device = idx;
			}
		}

		if (input_params.device == paNoDevice)
			ast_log(LOG_ERROR, "No input device found for modem '%s'\n", sim->modem->identifier);
		if (output_params.device == paNoDevice)
			ast_log(LOG_ERROR, "No output device found for modem '%s'\n", sim->modem->identifier);

		res = Pa_OpenStream(&sim->modem->stream, &input_params, &output_params,
			SAMPLE_RATE, NUM_SAMPLES, paNoFlag, NULL, NULL);
	}

	return res;
}

static int start_stream(sim_pvt_t *sim)
{
	PaError res;
	int ret_val = 0;

	modemmanager_pvt_lock(sim->modem);

	/* It is possible for modemmanager_hangup to be called before the
	 * stream is started, if this is the case sim->modem->owner will be NULL
	 * and start_stream should be aborted. */
	if (sim->modem->streamstate || !sim->modem->owner) {
		ast_log(LOG_NOTICE, "Unable to start stream.\n");
		goto return_unlock;
	}

	sim->modem->streamstate = 1;
	ast_log(LOG_NOTICE, "Starting stream\n");

	res = open_stream(sim);
	if (res != paNoError) {
		ast_log(LOG_WARNING, "Failed to open stream - (%d) %s\n",
			res, Pa_GetErrorText(res));
		ret_val = -1;
		goto return_unlock;
	}

	res = Pa_StartStream(sim->modem->stream);
	if (res != paNoError) {
		ast_log(LOG_WARNING, "Failed to start stream - (%d) %s\n",
			res, Pa_GetErrorText(res));
		ret_val = -1;
		goto return_unlock;
	}

	if (ast_pthread_create_background(&sim->modem->thread, NULL, stream_monitor, sim)) {
		ast_log(LOG_ERROR, "Failed to start stream monitor thread\n");
		ret_val = -1;
	}

return_unlock:
	modemmanager_pvt_unlock(sim->modem);

	return ret_val;
}

static int stop_stream(sim_pvt_t *sim)
{
	if (!sim->modem->streamstate || sim->modem->thread == AST_PTHREADT_NULL) {
		ast_log(LOG_NOTICE, "Not in streaming or thread is dead (stream=%s, thread=%d). exit.\n", AST_YESNO(sim->modem->streamstate), sim->modem->thread);
		return 0;
	}

	sim->modem->abort = 1;
	/* Wait for sim->modem->thread to exit cleanly, to avoid killing it while it's holding a lock. */
	pthread_kill(sim->modem->thread, SIGURG); /* Wake it up if needed, but don't cancel it */
	pthread_join(sim->modem->thread, NULL);

	modemmanager_pvt_lock(sim->modem);
	Pa_AbortStream(sim->modem->stream);
	Pa_CloseStream(sim->modem->stream);
	sim->modem->stream = NULL;
	sim->modem->streamstate = 0;
	modemmanager_pvt_unlock(sim->modem);

	ast_log(LOG_NOTICE, "Unlocked stream.\n");

	return 0;
}

/*!
 * \note Called with the pvt struct locked
 */
static struct ast_channel *modemmanager_new(sim_pvt_t *sim, const char *cid, const char *ext, const char *ctx, int state, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor)
{
	struct ast_format_cap *caps;
	struct ast_channel *chan;

	caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!caps) {
		return NULL;
	}

	if (!(chan = ast_channel_alloc(1, state, cid, NULL, NULL,
		ext, ctx, assignedids, requestor, 0, "ModemManager/%s", mm_sim_get_identifier(sim->device)))) {
		ao2_ref(caps, -1);
		return NULL;
	}

	ast_channel_stage_snapshot(chan);

	ast_channel_tech_set(chan, &modemmanager_tech);
	ast_channel_set_readformat(chan, ast_format_slin);
	ast_channel_set_writeformat(chan, ast_format_slin);
	ast_format_cap_append(caps, ast_format_slin, 0);
	ast_channel_nativeformats_set(chan, caps);
	ao2_ref(caps, -1);
	ast_channel_tech_pvt_set(chan, ref_sim(sim));

	sim->modem->owner = chan;

	if (!ast_strlen_zero(sim->language))
		ast_channel_language_set(chan, sim->language);

	ast_jb_configure(chan, &sim->modem->jbconf);

	ast_channel_stage_snapshot_done(chan);
	ast_channel_unlock(chan);

	if (state != AST_STATE_DOWN) {
		if (ast_pbx_start(chan)) {
			ast_channel_hangupcause_set(chan, AST_CAUSE_SWITCH_CONGESTION);
			ast_hangup(chan);
			chan = NULL;
		}
	}

	return chan;
}

static void oncalldtmfreceived(MMCall *call, char *dtmf, sim_pvt_t *sim)
{
	ast_log(LOG_NOTICE, "DTMF received %s\n", dtmf, sim->identifier);
}

static void oncallstatechanged(MMCall *call, MMCallState old, MMCallState new, MMCallStateReason reason, sim_pvt_t *sim)
{
	GError *error = NULL;
	ast_log(LOG_NOTICE, "Call state changed from %d to %d (Reason: %d) at line %s\n", old, new, reason, sim->identifier);
	switch(new) {
		case MM_CALL_STATE_DIALING:
			ast_queue_control(sim->modem->owner, AST_CONTROL_PROCEEDING);
			break;
		case MM_CALL_STATE_RINGING_OUT:
			ast_queue_control(sim->modem->owner, AST_CONTROL_RINGING);
			start_stream(sim);
			break;
		case MM_CALL_STATE_ACTIVE:
			ast_queue_control(sim->modem->owner, AST_CONTROL_ANSWER);
			break;
		case MM_CALL_STATE_TERMINATED:
			if(sim->modem->owner) {
				ast_queue_control(sim->modem->owner, AST_CONTROL_HANGUP);
				ast_queue_hangup(sim->modem->owner);
			}

			mm_modem_voice_delete_call_sync(sim->modem->voice, mm_call_get_path(sim->modem->call), NULL, &error);
			if(error) {
				ast_log(LOG_WARNING, "Failed to delete call - (%d) %s\n",
					error->code, error->message);
				g_clear_error(&error);
			}
			break;
	}
}

static struct ast_channel *modemmanager_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause)
{
	GError *error = NULL;
	struct ast_channel *chan = NULL;
	sim_pvt_t *sim;

	ast_log(LOG_NOTICE, "requested type %s, data %s\n", type, data);

	const char *number = strchr(data, '/');
	if(!number) {
		ast_log(LOG_NOTICE, "Invalid request %s - missing identifier\n", data);
		return NULL;
	}
	number++;

	char *identifier = ast_alloca(number - data + 1);
	if(!identifier) {
		ast_log(LOG_ERROR, "Allocation failed\n");
		return NULL;
	}
	ast_copy_string(identifier, data, number - data);

	if (!(sim = find_sim(identifier))) {
		ast_log(LOG_NOTICE, "Sim '%s' not found\n", identifier);
		return NULL;
	}

	ast_log(LOG_NOTICE, "Sim '%s' resolved. (Modem: %s)\n", identifier, sim->modem->identifier);

	if (!(ast_format_cap_iscompatible(cap, modemmanager_tech.capabilities))) {
		struct ast_str *cap_buf = ast_str_alloca(AST_FORMAT_CAP_NAMES_LEN);
		ast_log(LOG_NOTICE, "Channel requested with unsupported format(s): '%s'\n",
			ast_format_cap_get_names(cap, &cap_buf));
		goto return_unref;
	}

	if (sim->modem->owner) {
		ast_log(LOG_NOTICE, "Line is busy\n");
		*cause = AST_CAUSE_BUSY;
		goto return_unref;
	}

	MMModemState device_state = mm_modem_get_state(sim->modem->device);
	if(device_state < MM_MODEM_STATE_REGISTERED) {
		ast_log(LOG_NOTICE, "Line is unavailable state (MMModemState %d)\n", device_state);
		*cause = AST_CAUSE_FACILITY_NOT_SUBSCRIBED;
		goto return_unref;
	}

	MMCallProperties *call_props = mm_call_properties_new();
	mm_call_properties_set_number(call_props, number);
	sim->modem->call = mm_modem_voice_create_call_sync(sim->modem->voice, call_props, NULL, &error);
	g_object_unref(call_props);
	if(error) {
		ast_log(LOG_WARNING, "Failed to create call - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		goto return_unref;
	}
	ast_log(LOG_NOTICE, "Call %s created.\n", mm_call_get_path(sim->modem->call));

	modemmanager_pvt_lock(sim->modem);
	chan = modemmanager_new(sim, NULL, NULL, NULL, AST_STATE_DOWN, assignedids, requestor);
	modemmanager_pvt_unlock(sim->modem);
	if (!chan) {
		ast_log(LOG_WARNING, "Unable to create new channel\n");
		goto return_unref;
	}

	g_signal_connect(sim->modem->call, "state-changed", G_CALLBACK(oncallstatechanged), sim);
	g_signal_connect(sim->modem->call, "dtmf-received", G_CALLBACK(oncalldtmfreceived), sim);
	mm_call_start_sync(sim->modem->call, NULL, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to start call - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		goto return_unref;
	}
	ast_log(LOG_NOTICE, "Call %s started (port: %s)\n", mm_call_get_path(sim->modem->call), mm_call_get_audio_port(sim->modem->call));
return_unref:
	unref_sim(sim);
	return chan;
}

static void ondtmfsent(GObject *source_object, GAsyncResult *res, gpointer data) {
	sim_pvt_t *sim = data;
	GError *error = NULL;
	mm_call_send_dtmf_finish(sim->modem->call, res, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to send dtmf - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
	}
}

static int modemmanager_digit_begin(struct ast_channel *c, char digit)
{
	sim_pvt_t *sim = ast_channel_tech_pvt(c);
	const gchar dtmf[2] = {digit, '\0'};
	mm_call_send_dtmf(sim->modem->call, dtmf, NULL, G_CALLBACK(ondtmfsent), sim);
	return 0;
}

static int modemmanager_digit_end(struct ast_channel *c, char digit, unsigned int duration)
{
	sim_pvt_t *sim = ast_channel_tech_pvt(c);
	return 0;
}

static int modemmanager_hangup(struct ast_channel *c)
{
	GError *error = NULL;
	sim_pvt_t *sim = ast_channel_tech_pvt(c);

	ast_log(LOG_NOTICE, "Hanging up %s", sim->identifier);

	sim->modem->hookstate = 0;
	sim->modem->owner = NULL;
	stop_stream(sim);
	ast_log(LOG_NOTICE, "Stop stream succeded %s", sim->identifier);

	if(mm_call_get_state(sim->modem->call) != MM_CALL_STATE_TERMINATED) {
		mm_call_hangup_sync(sim->modem->call, NULL, &error);
		if(error) {
			ast_log(LOG_WARNING, "Failed to hangup call - (%d) %s\n",
				error->code, error->message);
			g_clear_error(&error);
		}
	}

	ast_channel_tech_pvt_set(c, unref_sim(sim));

	return 0;
}

static int modemmanager_answer(struct ast_channel *c)
{
	GError *error = NULL;
	sim_pvt_t *sim = ast_channel_tech_pvt(c);

	ast_verb(1, V_BEGIN "Call from Console has been Answered" V_END);

	mm_call_accept_sync(sim->modem->call, NULL, &error);
	if(error) {
		ast_log(LOG_WARNING, "Failed to accept call - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		ast_queue_hangup_with_cause(c, AST_CAUSE_FAILURE);
		return;
	}

	ast_setstate(c, AST_STATE_UP);

	return start_stream(sim);
}

static struct ast_frame *modemmanager_read(struct ast_channel *chan)
{
	ast_debug(1, "I should not be called ...\n");

	return &ast_null_frame;
}

static int modemmanager_call(struct ast_channel *c, const char *dest, int timeout)
{
	return 0;
}

static int modemmanager_write(struct ast_channel *chan, struct ast_frame *f)
{
	if (f->frametype != AST_FRAME_VOICE
		|| ast_format_cmp(f->subclass.format, ast_format_slin) != AST_FORMAT_CMP_EQUAL) {
		return 0;
	}

	sim_pvt_t *sim = ast_channel_tech_pvt(chan);

	modemmanager_pvt_lock(sim->modem);
	Pa_WriteStream(sim->modem->stream, f->data.ptr, f->samples);
	modemmanager_pvt_unlock(sim->modem);

	return 0;
}

static int modemmanager_indicate(struct ast_channel *chan, int cond, const void *data, size_t datalen) {
	ast_debug(1, "Requested indication %d on channel %s\n", cond, ast_channel_name(chan));
	return 0;
}

static char *cli_list_available(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	PaDeviceIndex idx, num, def_input, def_output;
	GError *error = NULL;
	int ret;

	if (cmd == CLI_INIT) {
		e->command = "modemmanager list available";
		e->usage =
			"Usage: modemmanager list available\n"
			"       List all available modems.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE)
		return NULL;

	if (a->argc != e->args)
		return CLI_SHOWUSAGE;

	ast_cli(a->fd, "\nAvailable modems");

	GList *modems = g_dbus_object_manager_get_objects(G_DBUS_OBJECT_MANAGER(manager));
	g_print ("\n");
	if (!modems)
		ast_cli(a->fd, "\t (none)\n");
	else {
		GList *l;
		for (l = modems; l; l = g_list_next (l)) {
			MMModem *modem = mm_object_peek_modem(MM_OBJECT(l->data));
			MMModemVoice *modem_voice = mm_object_peek_modem_voice(MM_OBJECT(l->data));
			ast_cli(a->fd, "\nModem '%s'\n"
				"\tManufacturer: %s\n"
				"\tModel: %s\n"
				"\tRevision: %s\n"
				"\tEquipmentIdentifier: %s\n"
				"\tState: %d\n"
				"\tVoice: %s\n"
				"\tEmergency Only: %s\n"
				,
				mm_modem_get_device_identifier(modem),
				mm_modem_get_manufacturer(modem),
				mm_modem_get_model(modem),
				mm_modem_get_revision(modem),
				mm_modem_get_equipment_identifier(modem),
				mm_modem_get_state(modem),
				modem_voice ? mm_modem_voice_get_path(modem_voice) : "(not supported)",
				modem_voice ? AST_YESNO(mm_modem_voice_get_emergency_only(modem_voice)) : "(not supported)"
			);

			gchar *own_numbers_string = g_strjoinv(", ", (gchar **)mm_modem_get_own_numbers (modem));
			ast_cli(a->fd, "\tOwnNumbers: %s\n", own_numbers_string);
			g_free(own_numbers_string);

			MMSim *sim = mm_modem_get_sim_sync(modem, NULL, &error);
			if(error) {
				ast_cli(a->fd, "Failed to get Sim - (%d) %s\n",
					error->code, error->message);
				g_clear_error(&error);
			}
			else {
				ast_cli(a->fd, "\tSim %s:\n"
					"\t\tImsi: %s\n"
					"\t\tOperatorIdentifier: %s\n"
					"\t\tOperatorName: %s\n"
					,
					mm_sim_get_identifier(sim),
					mm_sim_get_imsi(sim),
					mm_sim_get_operator_identifier(sim),
					mm_sim_get_operator_name(sim)
				);
				g_object_unref(sim);
			}
		}
		g_list_free_full(modems, (GDestroyNotify) g_object_unref);
	}

	ast_cli(a->fd, "\nAvailable audio devices (I: Default input device, i: Input device, O: Default output device, o: Output device)\n\n");

	num = Pa_GetDeviceCount();
	if (!num) {
		ast_cli(a->fd, "(None)\n");
		return CLI_SUCCESS;
	}

	def_input = Pa_GetDefaultInputDevice();
	def_output = Pa_GetDefaultOutputDevice();
	for (idx = 0; idx < num; idx++) {
		const PaDeviceInfo *dev = Pa_GetDeviceInfo(idx);
		if (!dev)
			continue;
		ast_cli(a->fd, "Device '%s' - %s%s\n",
			dev->name,
			dev->maxInputChannels ? idx == def_input ? "I" : "i" : "",
			dev->maxOutputChannels ? idx == def_output ? "O" : "o" : ""
		);
	}


	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_modemmanager[] = {
	AST_CLI_DEFINE(cli_list_available,     "List available devices"),
};

static void g_unref_modem(modem_pvt_t *dev) {
	g_object_unref(dev->device);
}

static void g_unref_sim(sim_pvt_t *dev) {
	g_object_unref(dev->device);
}

static int unload_module(void)
{
	ao2_ref(modemmanager_tech.capabilities, -1);
	modemmanager_tech.capabilities = NULL;
	ast_channel_unregister(&modemmanager_tech);
	ast_msg_tech_unregister(&msg_tech);
	ast_cli_unregister_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager));

	g_object_unref(manager);
	g_object_unref(dbus);

	Pa_Terminate();

	ao2_callback(modems, 0, g_unref_modem, NULL);
	ao2_ref(modems, -1);
	ao2_callback(sims, 0, g_unref_sim, NULL);
	ao2_ref(sims, -1);

	g_main_loop_quit(loop);

	return 0;
}

static void create_mainloop() {
	ast_log(LOG_NOTICE, "GMainLoop started\n");
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	g_main_loop_unref(loop);
	ast_log(LOG_NOTICE, "GMainLoop stopped\n");
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
	PaError res;
	GDBusConnection *connection = NULL;
	GError *error = NULL;

	if (!(modemmanager_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_append(modemmanager_tech.capabilities, ast_format_slin, 0);

	modems = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, NUM_PVT_BUCKETS,
		pvt_hash_cb, NULL, pvt_cmp_cb);
	if (!modems)
		goto return_error;

	sims = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, NUM_PVT_BUCKETS,
		pvt_hash_cb, NULL, pvt_cmp_cb);
	if (!sims)
		goto return_error;

	dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to connect DBus daemon - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		goto return_error_dbus_init;
	}

	manager = mm_manager_new_sync(dbus, 0, NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to create MMManager - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		goto return_error_mm_init;
	}

	if (load_config(0))
		goto return_error;

	res = Pa_Initialize();
	if (res != paNoError) {
		ast_log(LOG_WARNING, "Failed to initialize audio system - (%d) %s\n",
			res, Pa_GetErrorText(res));
		goto return_error_pa_init;
	}

	if (ast_channel_register(&modemmanager_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel type 'ModemManager'\n");
		goto return_error_chan_reg;
	}

	if (ast_msg_tech_register(&msg_tech)) {
		ast_log(LOG_ERROR, "Unable to register message type 'ModemManager'\n");
		goto return_error_msg_reg;
	}

	if (ast_cli_register_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager)))
		goto return_error_cli_reg;

	ast_pthread_create_background(&ptmainloop, NULL, create_mainloop, NULL);
	return AST_MODULE_LOAD_SUCCESS;

return_error_cli_reg:
	ast_cli_unregister_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager));
return_error_msg_reg:
	ast_msg_tech_unregister(&msg_tech);
return_error_chan_reg:
	ast_channel_unregister(&modemmanager_tech);
return_error_pa_init:
	Pa_Terminate();
return_error_mm_init:
	g_object_unref(dbus);
return_error_dbus_init:
return_error:
	ao2_ref(modemmanager_tech.capabilities, -1);
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
