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

#include "asterisk/callerid.h"
#include "asterisk/causes.h"
#include "asterisk/cli.h"
#include "asterisk/format_cache.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"
#include "asterisk/musiconhold.h"
#include "asterisk/pbx.h"
#include "asterisk/stasis_channels.h"
#include "asterisk/utils.h"

#include "audio_alsa.h"
#include "call.h"
#include "channel.h"
#include "mm_bus.h"
#include "sim.h"

static struct ast_channel *modemmanager_request(const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor,
	const char *data, int *cause);
static int modemmanager_digit_begin(struct ast_channel *c, char digit);
static int modemmanager_digit_end(struct ast_channel *c, char digit, unsigned int duration);
static int modemmanager_hangup(struct ast_channel *c);
static int modemmanager_answer(struct ast_channel *c);
static struct ast_frame *modemmanager_read(struct ast_channel *chan);
static int modemmanager_call(struct ast_channel *c, const char *dest, int timeout);
static int modemmanager_write(struct ast_channel *chan, struct ast_frame *f);
static int modemmanager_indicate(struct ast_channel *chan, int cond,
	const void *data, size_t datalen);

struct ast_channel_tech modemmanager_tech = {
	.type = "ModemManager",
	.description = "ModemManager Channel Driver",
	.requester = modemmanager_request,
	.send_digit_begin = modemmanager_digit_begin,
	.send_digit_end = modemmanager_digit_end,
	.hangup = modemmanager_hangup,
	.answer = modemmanager_answer,
	.read = modemmanager_read,
	.call = modemmanager_call,
	.write = modemmanager_write,
	.indicate = modemmanager_indicate,
};

struct ast_channel *modemmanager_new(sim_pvt_t *sim, modem_pvt_t *modem,
	const char *cid, const char *ext,
	const char *ctx, int state, const struct ast_assigned_ids *assignedids,
	const struct ast_channel *requestor)
{
	struct ast_format_cap *caps;
	struct ast_channel *chan;

	caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!caps) {
		return NULL;
	}

	/* Callers already ran open_stream() (with no locks held), which
	 * validated the audio device and fixed modem->format. */
	if (!modem->format || modem->format == ast_format_none) {
		ao2_ref(caps, -1);
		return NULL;
	}
	ast_format_cap_append(caps, modem->format, 0);

	if (!(chan = ast_channel_alloc(1, state, cid, NULL, NULL,
		ext, ctx, assignedids, requestor, 0, "ModemManager/%s", sim->identifier))) {
		ao2_ref(caps, -1);
		return NULL;
	}

	ast_channel_stage_snapshot(chan);
	ast_channel_tech_set(chan, &modemmanager_tech);

	ast_channel_set_writeformat(chan, modem->format);
	ast_channel_set_readformat(chan, modem->format);
	ast_channel_nativeformats_set(chan, caps);
	ao2_ref(caps, -1);

	ast_channel_tech_pvt_set(chan, ref_sim(sim));

	modem->owner = chan;

	if (!ast_strlen_zero(sim->language)) {
		ast_channel_language_set(chan, sim->language);
	}

	ast_jb_configure(chan, &modem->jbconf);

	ast_channel_stage_snapshot_done(chan);
	ast_channel_unlock(chan);

	/* Keep the module loaded while any channel is alive: the loader only
	 * refuses `module unload` when the usecount is non-zero. Dropped in
	 * modemmanager_hangup(). */
	ast_module_ref(AST_MODULE_SELF);

	return chan;
}

static struct ast_channel *modemmanager_request(const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor,
	const char *data, int *cause)
{
	GError *error = NULL;
	struct ast_channel *chan = NULL;
	MMCallProperties *call_props;
	MMCall *call = NULL;
	MMModem *device = NULL;
	MMModemVoice *voice = NULL;
	modem_pvt_t *modem = NULL;
	sim_pvt_t *sim;
	MMModemState device_state;

	ast_debug(1, "Requested type %s, data %s\n", type, data);

	const char *number = strchr(data, '/');
	if (!number) {
		ast_log(LOG_WARNING, "Invalid dial string '%s' - expected ModemManager/<sim>/<number>\n", data);
		return NULL;
	}
	number++;

	char *identifier = ast_alloca(number - data + 1);
	ast_copy_string(identifier, data, number - data);

	if (!(sim = find_sim(identifier))) {
		ast_log(LOG_WARNING, "Sim '%s' not found\n", identifier);
		return NULL;
	}

	modem = sim_grab_modem(sim);
	if (modem) {
		modemmanager_pvt_lock(modem);
		device = modem->device ? g_object_ref(modem->device) : NULL;
		voice = modem->voice ? g_object_ref(modem->voice) : NULL;
		modemmanager_pvt_unlock(modem);
	}
	if (!modem || !device || !voice) {
		ast_log(LOG_WARNING, "Sim '%s' has no resolved modem\n", identifier);
		*cause = AST_CAUSE_CHANNEL_UNACCEPTABLE;
		goto return_unref;
	}

	if (!(ast_format_cap_iscompatible(cap, modemmanager_tech.capabilities))) {
		struct ast_str *cap_buf = ast_str_alloca(AST_FORMAT_CAP_NAMES_LEN);

		ast_log(LOG_NOTICE, "Channel requested with unsupported format(s): '%s'\n",
			ast_format_cap_get_names(cap, &cap_buf));
		goto return_unref;
	}

	modemmanager_pvt_lock(modem);
	if (modem->owner) {
		modemmanager_pvt_unlock(modem);
		ast_debug(1, "Line is busy\n");
		*cause = AST_CAUSE_BUSY;
		goto return_unref;
	}
	modemmanager_pvt_unlock(modem);

	device_state = mm_modem_get_state(device);
	if (device_state < MM_MODEM_STATE_REGISTERED) {
		ast_log(LOG_WARNING, "Modem '%s' is not registered (state %d)\n",
			modem->identifier, device_state);
		*cause = AST_CAUSE_FACILITY_NOT_SUBSCRIBED;
		goto return_unref;
	}

	/* Validate the audio path (and fix the channel format) before any
	 * call exists on the modem; blocking opens run with no locks held. */
	if (open_stream(modem)) {
		*cause = AST_CAUSE_CHANNEL_UNACCEPTABLE;
		goto return_unref;
	}

	call_props = mm_call_properties_new();
	mm_call_properties_set_number(call_props, number);
	/* Bind the new MMCall proxy to the module context so its signals
	 * dispatch on our GMainLoop thread. */
	mm_bus_push_context();
	call = mm_modem_voice_create_call_sync(voice, call_props, NULL, &error);
	mm_bus_pop_context();
	g_object_unref(call_props);
	if (error) {
		ast_log(LOG_WARNING, "Failed to create call - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		stop_stream(modem);
		goto return_unref;
	}
	ast_debug(1, "Call %s created\n", mm_call_get_path(call));

	modemmanager_pvt_lock(modem);
	call_attach(modem, call, sim);
	chan = modemmanager_new(sim, modem, NULL, NULL, NULL, AST_STATE_DOWN, assignedids, requestor);
	if (!chan) {
		call_detach(modem);
		modemmanager_pvt_unlock(modem);
		ast_log(LOG_WARNING, "Unable to create new channel\n");
		stop_stream(modem);
		goto return_unref;
	}
	modemmanager_pvt_unlock(modem);

	mm_call_start_sync(call, NULL, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to start call - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		/* Tear the just-created channel down instead of handing the core
		 * a channel whose call never started. */
		ast_hangup(chan);
		chan = NULL;
		goto return_unref;
	}
	ast_debug(1, "Call %s started\n", mm_call_get_path(call));

return_unref:
	if (call) {
		g_object_unref(call);
	}
	if (voice) {
		g_object_unref(voice);
	}
	if (device) {
		g_object_unref(device);
	}
	unref_modem(modem);
	unref_sim(sim);
	return chan;
}

static void on_dtmf_sent(GObject *source_object, GAsyncResult *res, gpointer data)
{
	MMCall *call = MM_CALL(source_object);
	GError *error = NULL;

	mm_call_send_dtmf_finish(call, res, &error);
	if (error) {
		ast_log(LOG_WARNING, "Failed to send dtmf - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
	}
}

static int modemmanager_digit_begin(struct ast_channel *c, char digit)
{
	sim_pvt_t *sim = ast_channel_tech_pvt(c);
	const gchar dtmf[2] = { digit, '\0' };
	modem_pvt_t *modem = sim_grab_modem(sim);
	MMCall *call = NULL;

	if (!modem) {
		return -1;
	}
	modemmanager_pvt_lock(modem);
	if (modem->call) {
		call = g_object_ref(modem->call);
	}
	modemmanager_pvt_unlock(modem);
	unref_modem(modem);
	if (!call) {
		return -1;
	}

	mm_call_send_dtmf(call, dtmf, NULL, on_dtmf_sent, NULL);
	g_object_unref(call);
	return 0;
}

static int modemmanager_digit_end(struct ast_channel *c, char digit, unsigned int duration)
{
	return 0;
}

static int modemmanager_hangup(struct ast_channel *c)
{
	GError *error = NULL;
	sim_pvt_t *sim = ast_channel_tech_pvt(c);
	modem_pvt_t *modem = sim_grab_modem(sim);
	MMCall *call = NULL;

	ast_debug(1, "Hanging up %s\n", sim->identifier);

	if (modem) {
		modemmanager_pvt_lock(modem);
		modem->owner = NULL;
		if (modem->call) {
			call = g_object_ref(modem->call);
		}
		modemmanager_pvt_unlock(modem);

		stop_stream(modem);
		unref_modem(modem);
	}

	if (call) {
		if (mm_call_get_state(call) != MM_CALL_STATE_TERMINATED) {
			mm_call_hangup_sync(call, NULL, &error);
			if (error) {
				ast_log(LOG_WARNING, "Failed to hangup call - (%d) %s\n",
					error->code, error->message);
				g_clear_error(&error);
			}
		}
		/* The TERMINATED state-change task deletes the call from MM and
		 * detaches it from the modem. */
		g_object_unref(call);
	}

	ast_channel_tech_pvt_set(c, NULL);
	unref_sim(sim);

	/* Balances the ast_module_ref taken in modemmanager_new() */
	ast_module_unref(AST_MODULE_SELF);

	return 0;
}

static int modemmanager_answer(struct ast_channel *c)
{
	GError *error = NULL;
	sim_pvt_t *sim = ast_channel_tech_pvt(c);
	modem_pvt_t *modem = sim_grab_modem(sim);
	MMCall *call = NULL;

	if (!modem) {
		return -1;
	}
	modemmanager_pvt_lock(modem);
	if (modem->call) {
		call = g_object_ref(modem->call);
	}
	modemmanager_pvt_unlock(modem);
	if (!call) {
		unref_modem(modem);
		return -1;
	}

	mm_call_accept_sync(call, NULL, &error);
	g_object_unref(call);
	if (error) {
		ast_log(LOG_WARNING, "Failed to accept call - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		ast_queue_hangup_with_cause(c, AST_CAUSE_FAILURE);
		unref_modem(modem);
		return -1;
	}

	ast_setstate(c, AST_STATE_UP);

	{
		int res = start_stream(modem);

		unref_modem(modem);
		return res;
	}
}

static struct ast_frame *modemmanager_read(struct ast_channel *chan)
{
	/* Voice frames are queued by the capture thread; nothing to read here. */
	return &ast_null_frame;
}

static int modemmanager_call(struct ast_channel *c, const char *dest, int timeout)
{
	return 0;
}

static int modemmanager_write(struct ast_channel *chan, struct ast_frame *frame)
{
	sim_pvt_t *sim = ast_channel_tech_pvt(chan);
	modem_pvt_t *modem;

	switch (frame->frametype) {
	case AST_FRAME_VOICE:
		modem = sim_grab_modem(sim);
		if (modem) {
			alsa_write_frame(modem, frame);
			unref_modem(modem);
		}
		break;
	default:
		ast_log(LOG_WARNING, "Can't send %u type frames with ModemManager\n",
			frame->frametype);
	}

	return 0;
}

static int modemmanager_indicate(struct ast_channel *chan, int cond, const void *data, size_t datalen)
{
	sim_pvt_t *sim = ast_channel_tech_pvt(chan);
	int res = 0;

	ast_debug(1, "Requested indication %d on channel %s\n", cond, ast_channel_name(chan));

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
		ast_moh_start(chan, data, sim->mohinterpret);
		break;
	case AST_CONTROL_UNHOLD:
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
