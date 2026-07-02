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
 * Call audio flows over the modem's USB audio (UAC) function, accessed
 * directly through ALSA (plughw so the plug layer handles rate conversion
 * for cards that are not natively 8/16 kHz).
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
#define AST_MODULE "chan_modemmanager"

#include "asterisk.h"

#include <signal.h>  /* SIGURG */

#include <alsa/asoundlib.h>
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

#include "audio_detect.h"

/*!
 * \brief Samples per 20ms frame at the highest supported rate (16kHz).
 * Sizes the per-modem input buffer; the actual per-frame count is
 * rate / 50 (160 at 8kHz, 320 at 16kHz).
 */
#define NUM_SAMPLES      320

/*! \brief Frame length in milliseconds (one Asterisk voice frame per period) */
#define FRAME_MS         20

/*! \brief Periods in the ALSA ring buffer (4 x 20ms = 80ms of resilience) */
#define ALSA_PERIODS     4

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
		/*! ALSA device autodetected from the modem's USB sysfs path */
		AST_STRING_FIELD(detected_device);
	);
	/*! Current channel for this device */
	struct ast_channel *owner;
	/*! ALSA PCM handles for the modem's audio function */
	snd_pcm_t *capture_pcm;
	snd_pcm_t *playback_pcm;
	/*! Sample rate both PCMs were opened at (8000 or 16000) */
	unsigned int rate;
	struct ast_format *format;
	/*! Running = 1, Not running = 0 */
	unsigned int streamstate:1;
	/*! Tells the capture thread to exit */
	unsigned int stream_stop:1;
	/*! On-hook = 0, Off-hook = 1 */
	unsigned int hookstate:1;
	/*! Unmuted = 0, Muted = 1 */
	unsigned int muted:1;
	/*! Input buffer */
	char inbuf[NUM_SAMPLES*sizeof(int16_t) + AST_FRIENDLY_OFFSET];
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
static void alsa_autodetect_devices(modem_pvt_t *modem);

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
	ast_verb(1, "Storing '%s' => %s\n", var, value);
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

	pvt->format = ast_format_none;
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
	ast_verb(1, "Storing '%s' => %s\n", var, value);
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
	ast_verb(1, "Modem state changed from %d to %d (Reason: %d / uid: %s)\n", old_state, new_state, reason, sim->identifier);
}

static void on_voice_call_added(MMModemVoice *voice, const char *path, void *data)
{
	GError *error = NULL;
	sim_pvt_t *sim = data;
	ast_verb(1, "Call added - %s (uid: %s)\n", path, sim->identifier);

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
		ast_verb(1, "Incoming call from %s to %s (uid: %s)\n", mm_call_get_number(call), sim->exten, sim->identifier);
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
	ast_verb(1, "addr ok\n");
	number[0]='\0';
	simid[0]='\0';
	number += 1;
	simid += 1;
	ast_verb(1, "number=%s, simid=%s\n", number, simid);
	// return;
	sim_pvt_t *sim = find_sim(simid);
	if(number == NULL || simid == NULL) {
		ast_log(LOG_WARNING, "Unable to find sim %s\n", simid);
		return -1;
	}
	ast_verb(1, "sim ok mid=%s\n", sim->modem->identifier);
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
	ast_verb(1, "Message added - %s Received: %s (uid: %s)\n", path, AST_YESNO(received), sim->identifier);

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
		ast_verb(1, "Incoming SMS from %s to %s (uid: %s)\n", mm_sms_get_number(message), sim->exten, sim->identifier);
		ast_verb(1, "PDU Type %d, SMSC %s, Ref %d, Class %d, TS %s, DCTS %s\n",
			mm_sms_get_pdu_type(message),
			mm_sms_get_smsc(message),
			mm_sms_get_message_reference(message),
			mm_sms_get_class(message),
			mm_sms_get_timestamp(message),
			mm_sms_get_discharge_timestamp(message)
		);
		const char *text = mm_sms_get_text(message);
		if(text == NULL || strcmp(text, "(null)") == 0) {
			/* Possibly MMS but currently we don't implement mms support */
		}
		else {
			ast_verb(1, "Text %s\n", mm_sms_get_text(message));
			/* PJSIP method */
			struct ast_msg *msg = ast_msg_alloc();
			ast_verb(1, "Created ast_msg\n");
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
				ast_log(LOG_WARNING, "Failed to set ast_msg variables\n");
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

	ast_verb(1, "Loading modems...");
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
			ast_verb(1, "Resolved modem %s at %s",
				mm_modem_get_device_identifier(mm_modem),
				mm_modem_get_path(mm_modem));
			if (ast_strlen_zero(modem->input_device)
				|| !strcasecmp(modem->input_device, "auto")
				|| ast_strlen_zero(modem->output_device)
				|| !strcasecmp(modem->output_device, "auto")) {
				alsa_autodetect_devices(modem);
			}
			sim_pvt_t *sim = find_sim(mm_sim_get_identifier(mm_sim));
			if(!sim) {
				goto unref_mm;
			}
			ast_verb(1, "Resolved sim %s at %s",
				mm_sim_get_identifier(mm_sim),
				mm_sim_get_path(mm_sim));
			sim->device = mm_sim;
			sim->modem = modem;
			if(ast_strlen_zero(sim->exten)) {
				ast_string_field_set(sim, exten, ((const gchar**)mm_modem_get_own_numbers(mm_modem))[0]);
			}
			ast_verb(1, "Resolved sim %s exten %s",
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
 * \brief Recover an ALSA PCM from xrun/suspend.
 * \retval 0 recovered, caller may retry the I/O
 * \retval -1 unrecoverable
 */
static int alsa_pcm_recover(snd_pcm_t *pcm, int err)
{
	switch (err) {
	case -EPIPE:
		err = snd_pcm_prepare(pcm);
		if (err < 0) {
			ast_log(LOG_WARNING, "Failed to recover from xrun: %s\n", snd_strerror(err));
			return -1;
		}
		return 0;
	case -ESTRPIPE:
		while ((err = snd_pcm_resume(pcm)) == -EAGAIN) {
			usleep(10000);
		}
		if (err < 0) {
			err = snd_pcm_prepare(pcm);
		}
		if (err < 0) {
			ast_log(LOG_WARNING, "Failed to recover from suspend: %s\n", snd_strerror(err));
			return -1;
		}
		return 0;
	default:
		return -1;
	}
}

/*!
 * \brief Recover a capture PCM and restart it.
 *
 * snd_pcm_prepare() leaves the stream in PREPARED, but capture streams do
 * not auto-start from snd_pcm_wait(), so recovery must explicitly restart.
 */
static int alsa_capture_recover(snd_pcm_t *pcm, int err)
{
	if (alsa_pcm_recover(pcm, err)) {
		return -1;
	}
	if (snd_pcm_state(pcm) == SND_PCM_STATE_PREPARED && snd_pcm_start(pcm) < 0) {
		return -1;
	}
	return 0;
}

/*!
 * \brief Open one PCM at an exact rate: mono S16_LE, 20ms periods.
 */
static int alsa_open_pcm(snd_pcm_t **out, const char *device, snd_pcm_stream_t dir, unsigned int rate)
{
	snd_pcm_t *pcm = NULL;
	snd_pcm_hw_params_t *hw;
	snd_pcm_sw_params_t *sw;
	snd_pcm_uframes_t period = rate * FRAME_MS / 1000;
	snd_pcm_uframes_t buffer = period * ALSA_PERIODS;
	int err;

	err = snd_pcm_open(&pcm, device, dir, 0);
	if (err < 0) {
		ast_log(LOG_ERROR, "Failed to open ALSA device '%s' (%s): %s\n",
			device, dir == SND_PCM_STREAM_CAPTURE ? "capture" : "playback",
			snd_strerror(err));
		return err;
	}

	snd_pcm_hw_params_alloca(&hw);
	snd_pcm_sw_params_alloca(&sw);

	if ((err = snd_pcm_hw_params_any(pcm, hw)) < 0
		|| (err = snd_pcm_hw_params_set_access(pcm, hw, SND_PCM_ACCESS_RW_INTERLEAVED)) < 0
		|| (err = snd_pcm_hw_params_set_format(pcm, hw, SND_PCM_FORMAT_S16_LE)) < 0
		|| (err = snd_pcm_hw_params_set_channels(pcm, hw, 1)) < 0
		|| (err = snd_pcm_hw_params_set_rate(pcm, hw, rate, 0)) < 0
		|| (err = snd_pcm_hw_params_set_period_size_near(pcm, hw, &period, NULL)) < 0
		|| (err = snd_pcm_hw_params_set_buffer_size_near(pcm, hw, &buffer)) < 0
		|| (err = snd_pcm_hw_params(pcm, hw)) < 0) {
		ast_debug(1, "ALSA device '%s' does not accept %u Hz mono S16_LE: %s\n",
			device, rate, snd_strerror(err));
		snd_pcm_close(pcm);
		return err;
	}

	if ((err = snd_pcm_sw_params_current(pcm, sw)) < 0
		|| (err = snd_pcm_sw_params_set_avail_min(pcm, sw, period)) < 0
		|| (err = snd_pcm_sw_params_set_start_threshold(pcm, sw,
			dir == SND_PCM_STREAM_PLAYBACK ? period : 1)) < 0
		|| (err = snd_pcm_sw_params(pcm, sw)) < 0) {
		ast_log(LOG_WARNING, "Failed to set ALSA sw params on '%s': %s\n",
			device, snd_strerror(err));
		snd_pcm_close(pcm);
		return err;
	}

	if ((err = snd_pcm_prepare(pcm)) < 0) {
		ast_log(LOG_WARNING, "Failed to prepare ALSA device '%s': %s\n",
			device, snd_strerror(err));
		snd_pcm_close(pcm);
		return err;
	}

	*out = pcm;
	return 0;
}

/*!
 * \brief Resolve the ALSA device to use for one direction.
 *
 * Precedence: explicit config value (anything but empty/"auto", including
 * "default") > autodetected device > nothing (audio refused with a clear
 * error rather than silently guessing).
 */
static const char *alsa_pick_device(const ast_string_field configured, const ast_string_field detected)
{
	if (!ast_strlen_zero(configured) && strcasecmp(configured, "auto")) {
		return configured;
	}
	if (!ast_strlen_zero(detected)) {
		return detected;
	}
	return NULL;
}

/*!
 * \brief Correlate the modem's USB sysfs path with an ALSA card.
 *
 * Runs once per modem appearance (from the config/device resolution pass);
 * the result is cached in detected_device so per-call stream setup does no
 * sysfs walking.
 */
static void alsa_autodetect_devices(modem_pvt_t *modem)
{
	const char *phys = mm_modem_get_device(modem->device);
	char err[256];
	char dev[32];
	int card;

	if (ast_strlen_zero(phys)) {
		ast_log(LOG_WARNING, "Modem '%s' reports no physical device path; "
			"cannot autodetect audio. Set input_device/output_device.\n",
			modem->identifier);
		return;
	}
	if (mm_audio_card_for_physdev("/sys", phys, &card, err, sizeof(err))) {
		ast_log(LOG_WARNING, "ALSA autodetect failed for modem '%s': %s. "
			"Set input_device/output_device in modemmanager.conf.\n",
			modem->identifier, err);
		return;
	}
	snprintf(dev, sizeof(dev), "plughw:%d,0", card);
	ast_string_field_set(modem, detected_device, dev);
	ast_verb(2, "Modem '%s': autodetected ALSA device '%s'\n", modem->identifier, dev);
}

/*!
 * \brief Capture thread: blocking reads, one Asterisk frame per period.
 *
 * Waits with a timeout so stop_stream() only has to set stream_stop and
 * join; no cross-thread snd_pcm calls are needed.
 */
static void *capture_thread_fn(void *data)
{
	sim_pvt_t *sim = data;
	modem_pvt_t *modem = sim->modem;
	snd_pcm_uframes_t period = modem->rate * FRAME_MS / 1000;
	snd_pcm_sframes_t n;
	int err;

	while (!modem->stream_stop) {
		err = snd_pcm_wait(modem->capture_pcm, 100);
		if (modem->stream_stop) {
			break;
		}
		if (err == 0) {
			continue;
		}
		if (err < 0 && alsa_capture_recover(modem->capture_pcm, err)) {
			ast_log(LOG_WARNING, "ALSA capture wait failed on modem '%s': %s\n",
				modem->identifier, snd_strerror(err));
			break;
		}

		n = snd_pcm_readi(modem->capture_pcm, &modem->inbuf[AST_FRIENDLY_OFFSET], period);
		if (n < 0) {
			if (alsa_capture_recover(modem->capture_pcm, n)) {
				ast_log(LOG_WARNING, "ALSA capture failed on modem '%s': %s\n",
					modem->identifier, snd_strerror(n));
				break;
			}
			continue;
		}
		if (n == 0 || !modem->owner) {
			continue;
		}

		struct ast_frame f = {
			.frametype = AST_FRAME_VOICE,
			.subclass.format = modem->format,
			.src = "chan_modemmanager_capture",
			.data.ptr = &modem->inbuf[AST_FRIENDLY_OFFSET],
			.offset = AST_FRIENDLY_OFFSET,
			.datalen = (int)(n * sizeof(int16_t)),
			.samples = (int)n,
		};
		ast_queue_frame(modem->owner, &f);
	}

	return NULL;
}

static void close_stream(modem_pvt_t *modem)
{
	if (modem->capture_pcm) {
		snd_pcm_close(modem->capture_pcm);
		modem->capture_pcm = NULL;
	}
	if (modem->playback_pcm) {
		snd_pcm_close(modem->playback_pcm);
		modem->playback_pcm = NULL;
	}
}

/*!
 * \brief Open capture+playback at a common rate and pick the channel format.
 *
 * Requests exactly 8000 Hz first, then 16000 Hz; opened through plug-capable
 * device strings the plug layer converts for cards whose native rate
 * differs, so a failure here means the device is genuinely unusable. The
 * channel format follows whichever rate succeeded — the old behavior of
 * silently ending up with ast_format_none is impossible.
 *
 * \note This function expects the pvt lock to be held.
 */
static int open_stream(sim_pvt_t *sim)
{
	modem_pvt_t *modem = sim->modem;
	static const unsigned int rates[] = { 8000, 16000 };
	const char *in_dev = alsa_pick_device(modem->input_device, modem->detected_device);
	const char *out_dev = alsa_pick_device(modem->output_device, modem->detected_device);
	size_t i;

	if (modem->capture_pcm || modem->playback_pcm) {
		return 0;
	}

	if (!in_dev || !out_dev) {
		ast_log(LOG_ERROR, "No ALSA device for modem '%s' (autodetect failed or "
			"did not run); set input_device/output_device in modemmanager.conf\n",
			modem->identifier);
		return -1;
	}

	for (i = 0; i < ARRAY_LEN(rates); i++) {
		if (alsa_open_pcm(&modem->capture_pcm, in_dev, SND_PCM_STREAM_CAPTURE, rates[i])) {
			continue;
		}
		if (alsa_open_pcm(&modem->playback_pcm, out_dev, SND_PCM_STREAM_PLAYBACK, rates[i])) {
			snd_pcm_close(modem->capture_pcm);
			modem->capture_pcm = NULL;
			continue;
		}
		modem->rate = rates[i];
		modem->format = rates[i] == 16000 ? ast_format_slin16 : ast_format_slin;
		ast_verb(3, "Opened ALSA capture '%s' / playback '%s' at %u Hz\n",
			in_dev, out_dev, modem->rate);
		return 0;
	}

	ast_log(LOG_ERROR, "Unable to open ALSA devices '%s'/'%s' at 8 or 16 kHz for modem '%s'\n",
		in_dev, out_dev, modem->identifier);
	return -1;
}

static int start_stream(sim_pvt_t *sim)
{
	int ret_val = 0;

	modemmanager_pvt_lock(sim->modem);

	/* It is possible for modemmanager_hangup to be called before the
	 * stream is started, if this is the case sim->modem->owner will be NULL
	 * and start_stream should be aborted. */
	if (sim->modem->streamstate || !sim->modem->owner) {
		ast_debug(1, "Unable to start stream\n");
		goto return_unlock;
	}

	if (open_stream(sim)) {
		ret_val = -1;
		goto return_unlock;
	}

	/* Capture streams do not auto-start from snd_pcm_wait(); without this
	 * the capture thread would poll forever and no frames would flow. */
	if (snd_pcm_state(sim->modem->capture_pcm) == SND_PCM_STATE_PREPARED) {
		int err = snd_pcm_start(sim->modem->capture_pcm);
		if (err < 0) {
			ast_log(LOG_ERROR, "Failed to start ALSA capture for modem '%s': %s\n",
				sim->modem->identifier, snd_strerror(err));
			close_stream(sim->modem);
			ret_val = -1;
			goto return_unlock;
		}
	}

	sim->modem->stream_stop = 0;
	if (ast_pthread_create_background(&sim->modem->thread, NULL, capture_thread_fn, sim)) {
		ast_log(LOG_ERROR, "Failed to create capture thread for modem '%s'\n",
			sim->modem->identifier);
		close_stream(sim->modem);
		ret_val = -1;
		goto return_unlock;
	}
	sim->modem->streamstate = 1;
	ast_debug(1, "Stream started\n");

return_unlock:
	modemmanager_pvt_unlock(sim->modem);

	return ret_val;
}

static int stop_stream(sim_pvt_t *sim)
{
	pthread_t thread = AST_PTHREADT_NULL;

	modemmanager_pvt_lock(sim->modem);
	if (sim->modem->streamstate) {
		sim->modem->streamstate = 0;
		sim->modem->stream_stop = 1;
		thread = sim->modem->thread;
		sim->modem->thread = AST_PTHREADT_NULL;
	}
	modemmanager_pvt_unlock(sim->modem);

	/* The capture thread polls with a timeout, so it notices stream_stop
	 * on its own; no cross-thread snd_pcm calls are needed. */
	if (thread != AST_PTHREADT_NULL) {
		pthread_join(thread, NULL);
	}

	modemmanager_pvt_lock(sim->modem);
	/* PCMs are opened by modemmanager_new() before the stream starts, so
	 * close them even when the capture thread never ran. */
	close_stream(sim->modem);
	modemmanager_pvt_unlock(sim->modem);

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

	/* Opening the PCMs here (not at stream start) both validates the audio
	 * device before the call proceeds and determines the channel format
	 * from the rate that actually opened. */
	if (open_stream(sim)) {
		ao2_ref(caps, -1);
		return NULL;
	}
	ast_format_cap_append(caps, sim->modem->format, 0);

	if (!(chan = ast_channel_alloc(1, state, cid, NULL, NULL,
		ext, ctx, assignedids, requestor, 0, "ModemManager/%s", mm_sim_get_identifier(sim->device)))) {
		ao2_ref(caps, -1);
		return NULL;
	}

	ast_channel_stage_snapshot(chan);
	ast_channel_tech_set(chan, &modemmanager_tech);

	if (!ast_format_cap_empty(caps)) {
		struct ast_format *fmt;

		fmt = ast_format_cap_get_best_by_type(caps, AST_MEDIA_TYPE_AUDIO);
		if (!fmt) {
			/* Since our capabilities aren't empty, this will succeed */
			fmt = ast_format_cap_get_format(caps, 0);
		}
		ast_channel_set_writeformat(chan, fmt);
		ast_channel_set_readformat(chan, fmt);
		ao2_ref(fmt, -1);
	}

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
	ast_log(LOG_NOTICE, "DTMF received %s from modem %s\n", dtmf, sim->identifier);
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

	ast_verb(1, "requested type %s, data %s\n", type, data);

	const char *number = strchr(data, '/');
	if(!number) {
		ast_verb(1, "Invalid request %s - missing identifier\n", data);
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
		ast_verb(1, "Sim '%s' not found\n", identifier);
		return NULL;
	}

	ast_verb(1, "Sim '%s' resolved. (Modem: %s)\n", identifier, sim->modem->identifier);

	if (!(ast_format_cap_iscompatible(cap, modemmanager_tech.capabilities))) {
		struct ast_str *cap_buf = ast_str_alloca(AST_FORMAT_CAP_NAMES_LEN);
		ast_verb(1, "Channel requested with unsupported format(s): '%s'\n",
			ast_format_cap_get_names(cap, &cap_buf));
		goto return_unref;
	}

	if (sim->modem->owner) {
		ast_verb(1, "Line is busy\n");
		*cause = AST_CAUSE_BUSY;
		goto return_unref;
	}

	MMModemState device_state = mm_modem_get_state(sim->modem->device);
	if(device_state < MM_MODEM_STATE_REGISTERED) {
		ast_verb(1, "Line is unavailable state (MMModemState %d)\n", device_state);
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
	ast_verb(1, "Call %s created.\n", mm_call_get_path(sim->modem->call));

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
	ast_verb(1, "Call %s started (port: %s)\n", mm_call_get_path(sim->modem->call), mm_call_get_audio_port(sim->modem->call));
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
	mm_call_send_dtmf(sim->modem->call, dtmf, NULL, ondtmfsent, sim);
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

	ast_verb(1, "Hanging up %s", sim->identifier);

	sim->modem->hookstate = 0;
	sim->modem->owner = NULL;
	stop_stream(sim);
	ast_verb(1, "Stop stream succeded %s", sim->identifier);

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
		return -1;
	}

	ast_setstate(c, AST_STATE_UP);

	return start_stream(sim);
}

static struct ast_frame *modemmanager_read(struct ast_channel *chan)
{
	ast_verb(1, "I should not be called ...\n");

	return &ast_null_frame;
}

static int modemmanager_call(struct ast_channel *c, const char *dest, int timeout)
{
	return 0;
}

static int modemmanager_write(struct ast_channel *chan, struct ast_frame *frame)
{
	sim_pvt_t *sim = ast_channel_tech_pvt(chan);
	snd_pcm_sframes_t n = 0;

	switch(frame->frametype) {
		case AST_FRAME_VOICE:
			modemmanager_pvt_lock(sim->modem);
			if (sim->modem->playback_pcm == NULL || !sim->modem->streamstate) {
				modemmanager_pvt_unlock(sim->modem);
				break;
			}
			n = snd_pcm_writei(sim->modem->playback_pcm, frame->data.ptr, frame->samples);
			if (n < 0 && !alsa_pcm_recover(sim->modem->playback_pcm, n)) {
				n = snd_pcm_writei(sim->modem->playback_pcm, frame->data.ptr, frame->samples);
			}
			modemmanager_pvt_unlock(sim->modem);
			if (n < 0) {
				ast_log(LOG_WARNING, "ALSA playback failed: %s\n", snd_strerror(n));
			}
			break;
		default:
			ast_log(LOG_WARNING, "Can't send %u type frames with ModemManager\n", frame->frametype);
	}

	return 0;
}

static int modemmanager_indicate(struct ast_channel *chan, int cond, const void *data, size_t datalen) {
	ast_verb(1, "Requested indication %d on channel %s\n", cond, ast_channel_name(chan));
	sim_pvt_t *sim = ast_channel_tech_pvt(chan);
	int res = 0;

	switch (cond) {
	case AST_CONTROL_BUSY:
	case AST_CONTROL_CONGESTION:
	case AST_CONTROL_RINGING:
	case AST_CONTROL_INCOMPLETE:
	case AST_CONTROL_PVT_CAUSE_CODE:
	case -1:
		res = -1;  /* Ask for inband indications */
		break;
	case AST_CONTROL_PROGRESS:
	case AST_CONTROL_PROCEEDING:
	case AST_CONTROL_VIDUPDATE:
	case AST_CONTROL_SRCUPDATE:
	case AST_CONTROL_SRCCHANGE:
		break;
	case AST_CONTROL_HOLD:
		ast_verb(1, V_BEGIN "Console Has Been Placed on Hold" V_END);
		ast_moh_start(chan, data, sim->mohinterpret);
		break;
	case AST_CONTROL_UNHOLD:
		ast_verb(1, V_BEGIN "Console Has Been Retrieved from Hold" V_END);
		ast_moh_stop(chan);
		break;
	default:
		ast_log(LOG_WARNING, "Don't know how to display condition %d on %s\n",
			cond, ast_channel_name(chan));
		/* The core will play inband indications for us if appropriate */
		res = -1;
	}
	return res;
}

static char *cli_list_available(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	GError *error = NULL;

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

	ast_cli(a->fd, "\nAvailable ALSA PCM devices (use the name as input_device/output_device)\n\n");

	void **hints = NULL;
	if (snd_device_name_hint(-1, "pcm", &hints) < 0 || !hints) {
		ast_cli(a->fd, "(none)\n");
		return CLI_SUCCESS;
	}
	for (void **h = hints; *h; h++) {
		char *name = snd_device_name_get_hint(*h, "NAME");
		char *desc = snd_device_name_get_hint(*h, "DESC");
		char *ioid = snd_device_name_get_hint(*h, "IOID");

		if (name) {
			/* DESC may span lines; indent them under the device name */
			ast_cli(a->fd, "Device '%s'%s%s\n", name,
				ioid ? " - " : "", S_OR(ioid, ""));
			if (desc) {
				char *line, *rest = desc;
				while ((line = strsep(&rest, "\n"))) {
					ast_cli(a->fd, "\t%s\n", line);
				}
			}
		}

		ast_std_free(name);
		ast_std_free(desc);
		ast_std_free(ioid);
	}
	snd_device_name_free_hint(hints);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_modemmanager[] = {
	AST_CLI_DEFINE(cli_list_available,     "List available devices"),
};

static int g_unref_modem(void *obj, void *arg, int flags)
{
	modem_pvt_t *dev = obj;
	if (dev->device) {
		g_object_unref(dev->device);
		dev->device = NULL;
	}
	return 0;
}

static int g_unref_sim(void *obj, void *arg, int flags)
{
	sim_pvt_t *dev = obj;
	if (dev->device) {
		g_object_unref(dev->device);
		dev->device = NULL;
	}
	return 0;
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

	ao2_callback(modems, OBJ_NODATA, g_unref_modem, NULL);
	ao2_ref(modems, -1);
	ao2_callback(sims, OBJ_NODATA, g_unref_sim, NULL);
	ao2_ref(sims, -1);

	g_main_loop_quit(loop);

	return 0;
}

static void *create_mainloop() {
	ast_verb(1, "GMainLoop started\n");
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	g_main_loop_unref(loop);
	ast_verb(1, "GMainLoop stopped\n");
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

	if (!(modemmanager_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_append(modemmanager_tech.capabilities, ast_format_slin16, 0);
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
