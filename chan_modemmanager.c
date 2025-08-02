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
#define NUM_SAMPLES      320

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
	/*! Set during a reload so that we know to destroy this if it is no longer
	 *  in the configuration file. */
	unsigned int destroy:1;
} modem_pvt_t;

/*!
 * \brief ModemManager sim pvt structure
 */
typedef struct sim_pvt {
	AST_DECLARE_STRING_FIELDS(
		/*! ModemManager identifier for sim */
		AST_STRING_FIELD(identifier);
		/*! Default context for outgoing calls */
		AST_STRING_FIELD(context);
		/*! Default extension for outgoing calls */
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

GDBusConnection *dbus;
MMManager *manager;

/*! Channel Technology Callbacks @{ */
static struct ast_channel *modemmanager_request(const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause);
static int modemmanager_digit_begin(struct ast_channel *c, char digit);
static int modemmanager_digit_end(struct ast_channel *c, char digit, unsigned int duration);
static int modemmanager_text(struct ast_channel *c, const char *text);
static int modemmanager_hangup(struct ast_channel *c);
static int modemmanager_answer(struct ast_channel *c);
static struct ast_frame *modemmanager_read(struct ast_channel *chan);
static int modemmanager_call(struct ast_channel *c, const char *dest, int timeout);
static int modemmanager_write(struct ast_channel *chan, struct ast_frame *f);
static int modemmanager_indicate(struct ast_channel *chan, int cond,
	const void *data, size_t datalen);
static int modemmanager_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
/*! @} */

static struct ast_channel_tech modemmanager_tech = {
	.type = "ModemManager",
	.description = "ModemManager Channel Driver",
	.requester = modemmanager_request,
	// .send_digit_begin = modemmanager_digit_begin,
	// .send_digit_end = modemmanager_digit_end,
	// .send_text = modemmanager_text,
	.hangup = modemmanager_hangup,
	// .answer = modemmanager_answer,
	.read = modemmanager_read,
	.call = modemmanager_call,
	.write = modemmanager_write,
	// .indicate = modemmanager_indicate,
	// .fixup = modemmanager_fixup,
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
    ast_string_field_set(pvt, exten, "s");
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
	// pvt->thread = AST_PTHREADT_NULL;

	if (ast_string_field_init(pvt, 32))
		return -1;

	ast_string_field_set(pvt, identifier, S_OR(identifier, ""));

    pvt->device = NULL;

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
	GList *mm_modems = g_dbus_object_manager_get_objects(G_DBUS_OBJECT_MANAGER(manager));
    GError *error = NULL;
    if (mm_modems)
    {
        GList *l;
        for (l = mm_modems; l; l = g_list_next (l)) {
            MMModem *mm_modem = mm_object_get_modem(MM_OBJECT(l->data));
            MMSim *mm_sim = mm_modem_get_sim_sync(mm_modem, NULL, &error);
            if(error) {
                ast_log(LOG_WARNING, "Failed to initialize modem %s - Sim error (%d) %s\n",
                    mm_modem_get_path(mm_modem),
                    error->code, error->message);
                g_clear_error(&error);
                g_object_unref(mm_modem);
                continue;
            }
            modem_pvt_t *modem = find_modem(mm_modem_get_device_identifier(mm_modem));
            if(!modem) {
                g_object_unref(mm_modem);
                g_object_unref(mm_sim);
                continue;
            }
            modem->device = mm_modem;
            ast_log(LOG_NOTICE, "Resolved modem %s at %s",
                mm_modem_get_device_identifier(mm_modem),
                mm_modem_get_path(mm_modem));
            sim_pvt_t *sim = find_sim(mm_sim_get_identifier(mm_sim));
            if(!sim) {
                g_object_unref(mm_sim);
            }
            ast_log(LOG_NOTICE, "Resolved sim %s at %s",
                mm_sim_get_identifier(mm_sim),
                mm_sim_get_path(mm_sim));
            sim->device = mm_sim;
            sim->modem = modem;
        }
        g_list_free_full(mm_modems, (GDestroyNotify) g_object_unref);
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



static struct ast_channel *modemmanager_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause)
{
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
    strncpy(identifier, data, number - data);
    identifier[number - data - 1] = '\0';

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
		ast_log(LOG_NOTICE, "Channel is busy\n");
		*cause = AST_CAUSE_BUSY;
		goto return_unref;
	}

    /* Todo: create channel */

	modemmanager_pvt_lock(sim->modem);
	chan = modemmanager_new(sim->modem, NULL, NULL, AST_STATE_DOWN, assignedids, requestor);
	modemmanager_pvt_unlock(sim->modem);

	if (!chan)
		ast_log(LOG_WARNING, "Unable to create new channel\n");

return_unref:
	unref_sim(sim);
    return NULL;
}

static int modemmanager_hangup(struct ast_channel *c)
{
    return 0;
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
            ast_cli(a->fd, "\nModem '%s'\n"
                "\tManufacturer: %s\n"
                "\tModel: %s\n"
                "\tRevision: %s\n"
                "\tEquipmentIdentifier: %s\n"
                "\tState: %d\n"
                ,
                mm_modem_get_device_identifier(modem),
                mm_modem_get_manufacturer(modem),
                mm_modem_get_model(modem),
                mm_modem_get_revision(modem),
                mm_modem_get_equipment_identifier(modem),
                mm_modem_get_state(modem)
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

static int unload_module(void)
{
	ao2_ref(modemmanager_tech.capabilities, -1);
	modemmanager_tech.capabilities = NULL;
	ast_channel_unregister(&modemmanager_tech);
	ast_cli_unregister_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager));

    g_object_unref(manager);
    g_object_unref(dbus);

	Pa_Terminate();

	ao2_ref(modems, -1);
	ao2_ref(sims, -1);

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

	if (ast_cli_register_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager)))
		goto return_error_cli_reg;

	return AST_MODULE_LOAD_SUCCESS;

return_error_cli_reg:
	ast_cli_unregister_multiple(cli_modemmanager, ARRAY_LEN(cli_modemmanager));
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
