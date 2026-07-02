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

#include "asterisk/abstract_jb.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/utils.h"

#include "audio_alsa.h"
#include "call.h"
#include "mm_bus.h"
#include "modem.h"
#include "pvt_container.h"
#include "sim.h"
#include "sms.h"

static struct ao2_container *modems;

/*! Serializer for MMManager object-added/removed resolution work */
static struct ast_taskprocessor *resolve_tps;
static gulong sig_object_added;
static gulong sig_object_removed;

/*!
 * \brief Global jitterbuffer configuration (disabled by default)
 */
static const struct ast_jb_conf default_jbconf = {
	.flags = 0,
	.max_size = 200,
	.resync_threshold = 1000,
	.impl = "fixed",
	.target_extra = 40,
};

int modem_container_init(void)
{
	modems = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, NUM_PVT_BUCKETS,
		pvt_hash_cb, NULL, pvt_cmp_cb);
	return modems ? 0 : -1;
}

void modem_container_destroy(void)
{
	if (modems) {
		ao2_ref(modems, -1);
		modems = NULL;
	}
}

modem_pvt_t *find_modem(const char *identifier)
{
	return ao2_find(modems, identifier, OBJ_SEARCH_KEY);
}

/*!
 * \brief Disconnect device signals and drop MM object references.
 * \note Expects the pvt lock to be held (or exclusive access).
 */
static void modem_detach_locked(modem_pvt_t *pvt)
{
	if (pvt->device && pvt->sig_state_changed) {
		g_signal_handler_disconnect(pvt->device, pvt->sig_state_changed);
	}
	if (pvt->voice && pvt->sig_call_added) {
		g_signal_handler_disconnect(pvt->voice, pvt->sig_call_added);
	}
	if (pvt->messaging && pvt->sig_message_added) {
		g_signal_handler_disconnect(pvt->messaging, pvt->sig_message_added);
	}
	pvt->sig_state_changed = pvt->sig_call_added = pvt->sig_message_added = 0;
	call_detach(pvt);
	g_clear_object(&pvt->device);
	g_clear_object(&pvt->voice);
	g_clear_object(&pvt->messaging);
}

static void modem_destructor(void *obj)
{
	modem_pvt_t *pvt = obj;

	modem_detach_locked(pvt);
	if (pvt->serializer) {
		ast_taskprocessor_unreference(pvt->serializer);
		pvt->serializer = NULL;
	}
	ast_string_field_free_memory(pvt);
}

/*!
 * \note This function expects the pvt lock to be held.
 */
static void store_config_modem(modem_pvt_t *pvt, const char *var, const char *value)
{
	if (!ast_jb_read_conf(&pvt->jbconf, var, value)) {
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

static int init_modem(modem_pvt_t *pvt, const char *identifier)
{
	pvt->thread = AST_PTHREADT_NULL;

	if (ast_string_field_init(pvt, 32)) {
		return -1;
	}

	ast_string_field_set(pvt, identifier, S_OR(identifier, ""));

	pvt->jbconf = default_jbconf;

	return 0;
}

void build_modem(struct ast_config *cfg, const char *name)
{
	struct ast_variable *v;
	modem_pvt_t *pvt;
	int new = 0;

	if ((pvt = find_modem(name))) {
		modemmanager_pvt_lock(pvt);
		pvt->destroy = 0;
	} else {
		if (!(pvt = ao2_alloc(sizeof(*pvt), modem_destructor))) {
			return;
		}
		if (init_modem(pvt, name)) {
			unref_modem(pvt);
			return;
		}
		new = 1;
	}

	for (v = ast_variable_browse(cfg, name); v; v = v->next) {
		store_config_modem(pvt, v->name, v->value);
	}

	if (new) {
		ao2_link(modems, pvt);
	} else {
		modemmanager_pvt_unlock(pvt);
	}

	unref_modem(pvt);
}

static int mark_destroy_cb(void *obj, void *arg, int flags)
{
	modem_pvt_t *pvt = obj;

	pvt->destroy = 1;
	return 0;
}

void modem_mark_destroy_all(void)
{
	ao2_callback(modems, OBJ_NODATA, mark_destroy_cb, NULL);
}

static int prune_cb(void *obj, void *arg, int flags)
{
	modem_pvt_t *pvt = obj;

	if (!pvt->destroy) {
		return 0;
	}
	modemmanager_pvt_lock(pvt);
	if (pvt->owner) {
		/* Active call: keep until it ends; the next reload sweeps it. */
		modemmanager_pvt_unlock(pvt);
		ast_verb(2, "Modem '%s' removed from config but has an active call; "
			"keeping until it ends\n", pvt->identifier);
		return 0;
	}
	modem_detach_locked(pvt);
	modemmanager_pvt_unlock(pvt);
	ast_verb(2, "Removing modem '%s' (no longer configured)\n", pvt->identifier);
	return CMP_MATCH;
}

void modem_prune_destroyed(void)
{
	ao2_callback(modems, OBJ_NODATA | OBJ_MULTIPLE | OBJ_UNLINK, prune_cb, NULL);
}

static void sim_closure_unref(gpointer data, GClosure *closure)
{
	unref_sim(data);
}

static void on_modem_state_changed(MMModem *device, MMModemState old_state,
	MMModemState new_state, MMModemStateChangeReason reason, void *data)
{
	sim_pvt_t *sim = data;

	ast_debug(1, "Modem state changed from %d to %d (reason: %d, sim %s)\n",
		old_state, new_state, reason, sim->identifier);
}

/*!
 * \brief Attach one MMObject to its configured modem/sim pvts.
 *
 * Idempotent: signals are disconnected before reconnecting, so running
 * this again for the same object (reload, object-added after restart)
 * cannot double-connect or leak references.
 */
static void resolve_object(MMObject *obj)
{
	GError *error = NULL;
	MMModem *mm_modem = mm_object_get_modem(obj);
	MMModemVoice *mm_voice = mm_object_get_modem_voice(obj);
	MMModemMessaging *mm_msg = mm_object_get_modem_messaging(obj);
	MMSim *mm_sim = NULL;
	modem_pvt_t *modem = NULL;
	sim_pvt_t *sim = NULL;

	if (!mm_modem || !mm_voice) {
		ast_debug(1, "Skipping %s: no voice interface\n",
			g_dbus_object_get_object_path(G_DBUS_OBJECT(obj)));
		goto done;
	}

	modem = find_modem(mm_modem_get_device_identifier(mm_modem));
	if (!modem) {
		ast_verb(3, "Modem '%s' at %s is not configured\n",
			mm_modem_get_device_identifier(mm_modem), mm_modem_get_path(mm_modem));
		goto done;
	}

	mm_bus_push_context();
	mm_sim = mm_modem_get_sim_sync(mm_modem, NULL, &error);
	mm_bus_pop_context();
	if (error) {
		ast_log(LOG_WARNING, "Failed to get SIM of modem '%s' - (%d) %s\n",
			modem->identifier, error->code, error->message);
		g_clear_error(&error);
		goto done;
	}

	sim = find_sim(mm_sim_get_identifier(mm_sim));
	if (!sim) {
		ast_verb(3, "Sim '%s' on modem '%s' is not configured\n",
			mm_sim_get_identifier(mm_sim), modem->identifier);
		goto done;
	}

	modemmanager_pvt_lock(modem);
	modem_detach_locked(modem);
	modem->device = g_object_ref(mm_modem);
	modem->voice = g_object_ref(mm_voice);
	modem->messaging = mm_msg ? g_object_ref(mm_msg) : NULL;
	if (!modem->serializer) {
		char tps_name[AST_TASKPROCESSOR_MAX_NAME + 1];

		ast_taskprocessor_build_name(tps_name, sizeof(tps_name),
			"mm/%s", modem->identifier);
		modem->serializer = ast_threadpool_serializer(tps_name, mm_bus_threadpool());
		if (!modem->serializer) {
			ast_log(LOG_ERROR, "Failed to create serializer for modem '%s'\n",
				modem->identifier);
		}
	}
	modem->sig_state_changed = g_signal_connect_data(modem->device, "state-changed",
		G_CALLBACK(on_modem_state_changed), ref_sim(sim), sim_closure_unref, 0);
	modem->sig_call_added = g_signal_connect_data(modem->voice, "call-added",
		G_CALLBACK(on_voice_call_added), ref_sim(sim), sim_closure_unref, 0);
	if (modem->messaging) {
		modem->sig_message_added = g_signal_connect_data(modem->messaging, "added",
			G_CALLBACK(on_message_added), ref_sim(sim), sim_closure_unref, 0);
	}
	modemmanager_pvt_unlock(modem);

	modemmanager_pvt_lock(sim);
	g_clear_object(&sim->device);
	sim->device = g_object_ref(mm_sim);
	unref_modem(sim->modem);
	sim->modem = ref_modem(modem);
	if (ast_strlen_zero(sim->exten)) {
		const gchar *const *numbers =
			(const gchar *const *)mm_modem_get_own_numbers(mm_modem);

		if (numbers && numbers[0]) {
			ast_string_field_set(sim, exten, numbers[0]);
		}
	}
	modemmanager_pvt_unlock(sim);

	if (ast_strlen_zero(modem->input_device)
		|| !strcasecmp(modem->input_device, "auto")
		|| ast_strlen_zero(modem->output_device)
		|| !strcasecmp(modem->output_device, "auto")) {
		alsa_autodetect_devices(modem);
	}

	ast_verb(2, "Resolved modem '%s' at %s with sim '%s' (exten %s)\n",
		modem->identifier, mm_modem_get_path(mm_modem),
		sim->identifier, S_OR(sim->exten, "<none>"));

done:
	if (mm_sim) {
		g_object_unref(mm_sim);
	}
	if (mm_msg) {
		g_object_unref(mm_msg);
	}
	if (mm_voice) {
		g_object_unref(mm_voice);
	}
	if (mm_modem) {
		g_object_unref(mm_modem);
	}
	unref_sim(sim);
	unref_modem(modem);
}

void modem_resolve_all(void)
{
	GList *objs, *l;

	objs = g_dbus_object_manager_get_objects(G_DBUS_OBJECT_MANAGER(mm_bus_manager()));
	for (l = objs; l; l = g_list_next(l)) {
		resolve_object(MM_OBJECT(l->data));
	}
	g_list_free_full(objs, g_object_unref);
}

static int detach_cb(void *obj, void *arg, int flags)
{
	modem_pvt_t *pvt = obj;

	stop_stream(pvt);
	modemmanager_pvt_lock(pvt);
	modem_detach_locked(pvt);
	modemmanager_pvt_unlock(pvt);
	return 0;
}

void modem_detach_all(void)
{
	ao2_callback(modems, OBJ_NODATA, detach_cb, NULL);
}

/* --- MMManager object-added/removed (event-driven hotplug) --- */

static int task_resolve_object(void *data)
{
	MMObject *obj = data;

	resolve_object(obj);
	g_object_unref(obj);
	return 0;
}

struct detach_by_path {
	const char *path;
};

static int detach_by_path_cb(void *obj, void *arg, int flags)
{
	modem_pvt_t *pvt = obj;
	struct detach_by_path *d = arg;

	modemmanager_pvt_lock(pvt);
	if (pvt->device && !g_strcmp0(mm_modem_get_path(pvt->device), d->path)) {
		struct ast_channel *owner = pvt->owner ? ast_channel_ref(pvt->owner) : NULL;

		ast_verb(2, "Modem '%s' disappeared (%s)\n", pvt->identifier, d->path);
		modem_detach_locked(pvt);
		modemmanager_pvt_unlock(pvt);
		if (owner) {
			ast_queue_hangup(owner);
			ast_channel_unref(owner);
		}
		return 0;
	}
	modemmanager_pvt_unlock(pvt);
	return 0;
}

static int task_object_removed(void *data)
{
	char *path = data;
	struct detach_by_path d = { .path = path };

	ao2_callback(modems, OBJ_NODATA, detach_by_path_cb, &d);
	ast_free(path);
	return 0;
}

static void on_object_added(GDBusObjectManager *manager, GDBusObject *object, gpointer user_data)
{
	if (!resolve_tps) {
		return;
	}
	g_object_ref(object);
	if (ast_taskprocessor_push(resolve_tps, task_resolve_object, object)) {
		g_object_unref(object);
	}
}

static void on_object_removed(GDBusObjectManager *manager, GDBusObject *object, gpointer user_data)
{
	char *path;

	if (!resolve_tps) {
		return;
	}
	path = ast_strdup(g_dbus_object_get_object_path(object));
	if (!path) {
		return;
	}
	if (ast_taskprocessor_push(resolve_tps, task_object_removed, path)) {
		ast_free(path);
	}
}

int modem_watch_manager(void)
{
	MMManager *manager = mm_bus_manager();

	resolve_tps = ast_threadpool_serializer("mm/resolve", mm_bus_threadpool());
	if (!resolve_tps) {
		return -1;
	}
	sig_object_added = g_signal_connect(manager, "object-added",
		G_CALLBACK(on_object_added), NULL);
	sig_object_removed = g_signal_connect(manager, "object-removed",
		G_CALLBACK(on_object_removed), NULL);
	return 0;
}

void modem_unwatch_manager(void)
{
	MMManager *manager = mm_bus_manager();

	if (manager && sig_object_added) {
		g_signal_handler_disconnect(manager, sig_object_added);
	}
	if (manager && sig_object_removed) {
		g_signal_handler_disconnect(manager, sig_object_removed);
	}
	sig_object_added = sig_object_removed = 0;
	if (resolve_tps) {
		ast_taskprocessor_unreference(resolve_tps);
		resolve_tps = NULL;
	}
}
