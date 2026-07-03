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

#include "asterisk/causes.h"
#include "asterisk/logger.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"

#include "audio_alsa.h"
#include "call.h"
#include "channel.h"
#include "mm_bus.h"

static void on_call_dtmf_received(MMCall *call, char *dtmf, sim_pvt_t *sim)
{
	ast_verb(3, "DTMF received %s from modem %s\n", dtmf, sim->identifier);
}

static void sim_closure_unref(gpointer data, GClosure *closure)
{
	unref_sim(data);
}

static void on_call_state_changed(MMCall *call, MMCallState old, MMCallState new,
	MMCallStateReason reason, sim_pvt_t *sim);
static void on_call_state_notify(GObject *object, GParamSpec *pspec, gpointer data);

void call_attach(modem_pvt_t *modem, MMCall *call, sim_pvt_t *sim)
{
	call_detach(modem);
	modem->call = g_object_ref(call);
	modem->last_call_state = mm_call_get_state(call);
	modem->sig_call_state_changed = g_signal_connect_data(call, "state-changed",
		G_CALLBACK(on_call_state_changed), ref_sim(sim), sim_closure_unref, 0);
	/* Belt and braces: some proxy/context combinations deliver call state
	 * only through the property cache (PropertiesChanged -> notify) while
	 * the explicit StateChanged D-Bus signal never reaches this proxy
	 * (observed live: MM emitted StateChanged on the bus, the handler
	 * above stayed silent). Transitions are deduped via last_call_state. */
	modem->sig_call_notify = g_signal_connect_data(call, "notify::state",
		G_CALLBACK(on_call_state_notify), ref_sim(sim), sim_closure_unref, 0);
	modem->sig_call_dtmf = g_signal_connect_data(call, "dtmf-received",
		G_CALLBACK(on_call_dtmf_received), ref_sim(sim), sim_closure_unref, 0);
}

void call_detach(modem_pvt_t *modem)
{
	if (!modem->call) {
		return;
	}
	if (modem->sig_call_state_changed) {
		g_signal_handler_disconnect(modem->call, modem->sig_call_state_changed);
		modem->sig_call_state_changed = 0;
	}
	if (modem->sig_call_notify) {
		g_signal_handler_disconnect(modem->call, modem->sig_call_notify);
		modem->sig_call_notify = 0;
	}
	if (modem->sig_call_dtmf) {
		g_signal_handler_disconnect(modem->call, modem->sig_call_dtmf);
		modem->sig_call_dtmf = 0;
	}
	g_clear_object(&modem->call);
}

/*!
 * \brief Serializer task: delete the terminated call from ModemManager and
 * drop the modem's reference to it.
 */
static int task_call_terminated(void *data)
{
	sim_pvt_t *sim = data;
	modem_pvt_t *modem = sim_grab_modem(sim);
	MMModemVoice *voice = NULL;
	char *path = NULL;
	GError *error = NULL;

	if (!modem) {
		unref_sim(sim);
		return 0;
	}

	modemmanager_pvt_lock(modem);
	if (modem->call) {
		path = ast_strdup(mm_call_get_path(modem->call));
	}
	if (modem->voice) {
		voice = g_object_ref(modem->voice);
	}
	call_detach(modem);
	modemmanager_pvt_unlock(modem);

	if (path && voice) {
		mm_modem_voice_delete_call_sync(voice, path, NULL, &error);
		if (error) {
			ast_log(LOG_WARNING, "Failed to delete call - (%d) %s\n",
				error->code, error->message);
			g_clear_error(&error);
		}
	}
	if (voice) {
		g_object_unref(voice);
	}
	ast_free(path);
	unref_modem(modem);
	unref_sim(sim);
	return 0;
}

/*! \brief Serializer task: bring the audio stream up (RINGING_OUT path). */
static int task_start_stream(void *data)
{
	sim_pvt_t *sim = data;
	modem_pvt_t *modem = sim_grab_modem(sim);

	if (modem) {
		start_stream(modem);
		unref_modem(modem);
	}
	unref_sim(sim);
	return 0;
}

static void push_sim_task(sim_pvt_t *sim, int (*task)(void *))
{
	modem_pvt_t *modem = sim_grab_modem(sim);

	if (!modem) {
		return;
	}
	if (modem->serializer
		&& ast_taskprocessor_push(modem->serializer, task, ref_sim(sim))) {
		unref_sim(sim);
	}
	unref_modem(modem);
}

/*!
 * \brief MMCall state-changed handler (GMainLoop thread).
 *
 * Only queues channel indications and pushes blocking work (D-Bus calls,
 * ALSA opens) onto the modem serializer.
 */
/*!
 * \brief Common call-state transition logic; runs on the GMainLoop thread.
 *
 * Reached from both the StateChanged D-Bus signal and the property-cache
 * notify::state path; last_call_state dedupes double delivery.
 */
static void handle_call_state(MMCall *call, MMCallState new, MMCallStateReason reason,
	sim_pvt_t *sim)
{
	struct ast_channel *owner;
	modem_pvt_t *modem = sim_grab_modem(sim);

	if (!modem) {
		return;
	}

	modemmanager_pvt_lock(modem);
	if (modem->call != call || modem->last_call_state == (int)new) {
		modemmanager_pvt_unlock(modem);
		unref_modem(modem);
		return;
	}
	modem->last_call_state = new;
	modemmanager_pvt_unlock(modem);

	ast_debug(1, "Call state now %d (reason: %d) on sim %s\n",
		new, reason, sim->identifier);

	switch (new) {
	case MM_CALL_STATE_DIALING:
		if ((owner = modem_grab_owner(modem))) {
			ast_queue_control(owner, AST_CONTROL_PROCEEDING);
			ast_channel_unref(owner);
		}
		break;
	case MM_CALL_STATE_RINGING_OUT:
		if ((owner = modem_grab_owner(modem))) {
			ast_queue_control(owner, AST_CONTROL_RINGING);
			ast_channel_unref(owner);
		}
		push_sim_task(sim, task_start_stream);
		break;
	case MM_CALL_STATE_ACTIVE:
		if ((owner = modem_grab_owner(modem))) {
			ast_queue_control(owner, AST_CONTROL_ANSWER);
			ast_channel_unref(owner);
		}
		break;
	case MM_CALL_STATE_TERMINATED:
		if ((owner = modem_grab_owner(modem))) {
			ast_queue_hangup(owner);
			ast_channel_unref(owner);
		}
		push_sim_task(sim, task_call_terminated);
		break;
	default:
		ast_debug(1, "Unhandled call state %d on sim %s\n", new, sim->identifier);
		break;
	}
	unref_modem(modem);
}

static void on_call_state_changed(MMCall *call, MMCallState old, MMCallState new,
	MMCallStateReason reason, sim_pvt_t *sim)
{
	ast_debug(1, "StateChanged signal %d -> %d on sim %s\n", old, new, sim->identifier);
	handle_call_state(call, new, reason, sim);
}

static void on_call_state_notify(GObject *object, GParamSpec *pspec, gpointer data)
{
	MMCall *call = MM_CALL(object);
	sim_pvt_t *sim = data;

	handle_call_state(call, mm_call_get_state(call),
		mm_call_get_state_reason(call), sim);
}

/*!
 * \brief Serializer task: resolve a newly added call and, if incoming,
 * create the Asterisk channel for it.
 */
struct call_added_task {
	sim_pvt_t *sim;
	char *path;
};

static int task_call_added(void *data)
{
	struct call_added_task *t = data;
	sim_pvt_t *sim = t->sim;
	modem_pvt_t *modem = sim_grab_modem(sim);
	MMModemVoice *voice = NULL;
	MMCall *call = NULL;
	GError *error = NULL;
	GList *calls, *l;

	if (!modem) {
		goto done;
	}

	modemmanager_pvt_lock(modem);
	if (modem->voice) {
		voice = g_object_ref(modem->voice);
	}
	modemmanager_pvt_unlock(modem);
	if (!voice) {
		goto done;
	}

	/* Bind new MMCall proxies to the module context so their signals
	 * dispatch on our GMainLoop thread. */
	mm_bus_push_context();
	calls = mm_modem_voice_list_calls_sync(voice, NULL, &error);
	mm_bus_pop_context();
	if (error) {
		ast_log(LOG_WARNING, "Failed to list calls - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		goto done;
	}
	for (l = calls; l; l = g_list_next(l)) {
		if (!call && !g_strcmp0(t->path, mm_call_get_path(MM_CALL(l->data)))) {
			call = g_object_ref(MM_CALL(l->data));
		}
	}
	g_list_free_full(calls, g_object_unref);

	if (!call) {
		ast_log(LOG_WARNING, "Added call %s not found on modem '%s'\n",
			t->path, modem->identifier);
		goto done;
	}

	if (mm_call_get_direction(call) == MM_CALL_DIRECTION_INCOMING) {
		struct ast_channel *chan;

		ast_verb(3, "Incoming call from %s on sim %s\n",
			mm_call_get_number(call), sim->identifier);

		/* Blocking device opens must not run under the pvt lock */
		if (open_stream(modem)) {
			ast_log(LOG_WARNING, "Rejecting incoming call on modem '%s': no audio\n",
				modem->identifier);
			mm_call_hangup_sync(call, NULL, NULL);
			goto done;
		}

		modemmanager_pvt_lock(modem);
		if (modem->owner || modem->call) {
			modemmanager_pvt_unlock(modem);
			ast_log(LOG_WARNING, "Rejecting incoming call on busy modem '%s'\n",
				modem->identifier);
			mm_call_hangup_sync(call, NULL, NULL);
			goto done;
		}
		call_attach(modem, call, sim);
		chan = modemmanager_new(sim, modem, mm_call_get_number(call), sim->exten,
			sim->context, AST_STATE_RINGING, NULL, NULL);
		if (!chan) {
			call_detach(modem);
			modemmanager_pvt_unlock(modem);
			ast_log(LOG_WARNING, "Unable to create channel for incoming call\n");
			mm_call_hangup_sync(call, NULL, NULL);
			stop_stream(modem);
			goto done;
		}
		modemmanager_pvt_unlock(modem);

		/* Never under the pvt lock: the PBX may immediately call back
		 * into the channel tech. */
		if (ast_pbx_start(chan)) {
			ast_channel_hangupcause_set(chan, AST_CAUSE_SWITCH_CONGESTION);
			ast_hangup(chan);
		}
	}

done:
	if (call) {
		g_object_unref(call);
	}
	if (voice) {
		g_object_unref(voice);
	}
	unref_modem(modem);
	unref_sim(sim);
	ast_free(t->path);
	ast_free(t);
	return 0;
}

void on_voice_call_added(MMModemVoice *voice, const char *path, void *data)
{
	sim_pvt_t *sim = data;
	modem_pvt_t *modem = sim_grab_modem(sim);
	struct call_added_task *t;

	ast_debug(1, "Call added - %s (sim %s)\n", path, sim->identifier);

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

	if (ast_taskprocessor_push(modem->serializer, task_call_added, t)) {
		unref_sim(t->sim);
		ast_free(t->path);
		ast_free(t);
	}
	unref_modem(modem);
}
