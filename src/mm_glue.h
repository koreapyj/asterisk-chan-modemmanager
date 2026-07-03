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
 * \brief Shared private structures for the chan_modemmanager module.
 *
 * Threading model (see also mm_bus.h):
 * - One GMainLoop thread iterates a private GMainContext; every
 *   GLib/libmm-glib signal handler runs there and must never block
 *   (no _sync D-Bus calls, no ALSA I/O). Handlers snapshot what they
 *   need and push a task onto the owning modem's serializer.
 * - Per-modem serializers (ast_threadpool_serializer) run the blocking
 *   work; ordering is preserved per modem, and one slow modem cannot
 *   stall another.
 * - Asterisk core threads run the channel tech callbacks and may call
 *   _sync D-Bus functions directly (GDBus proxies are thread-safe).
 * - One ALSA capture pthread runs per active call (audio_alsa.c).
 *
 * Locking: the ao2 lock on a pvt guards only metadata (owner, call,
 * GObject pointers, signal ids, stream state). It is never held across
 * a blocking D-Bus call, ALSA I/O, ast_pbx_start() or a thread join.
 */

#ifndef CHAN_MM_GLUE_H
#define CHAN_MM_GLUE_H

#include "asterisk.h"

#include <alsa/asoundlib.h>
#include <ModemManager/ModemManager.h>
#include <gio/gio.h>
#include <glib.h>
#include <libmm-glib.h>

#include "asterisk/abstract_jb.h"
#include "asterisk/astobj2.h"
#include "asterisk/channel.h"
#include "asterisk/stringfields.h"
#include "asterisk/taskprocessor.h"

/*!
 * \brief Samples per 20ms frame at the highest supported rate (16kHz).
 * Sizes the per-modem input buffer; the actual per-frame count is
 * rate / 50 (160 at 8kHz, 320 at 16kHz).
 */
#define NUM_SAMPLES      320

/*! \brief Maximum text message length */
#define TEXT_SIZE	256

/*!
 * \brief abstract pvt structure
 *
 * Only used as the common prefix for hashing/comparing modem and sim
 * pvts by identifier in one container implementation.
 */
typedef struct abstract_pvt {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(identifier);
	);
} abstract_pvt_t;

/*!
 * \brief ModemManager modem pvt structure
 */
typedef struct modem_pvt {
	AST_DECLARE_STRING_FIELDS(
		/*! ModemManager DeviceIdentifier for the modem */
		AST_STRING_FIELD(identifier);
		AST_STRING_FIELD(input_device);
		AST_STRING_FIELD(output_device);
		/*! ALSA device autodetected from the modem's USB sysfs path */
		AST_STRING_FIELD(detected_device);
		/*! Semicolon-separated init AT commands (audio bring-up) */
		AST_STRING_FIELD(init_commands);
		/*! Explicit AT port for init commands (optional) */
		AST_STRING_FIELD(init_port);
	);
	/*! Current channel for this device */
	struct ast_channel *owner;
	/*! Guards the PCM handle pointers and the playback write path, so
	 *  blocking ALSA I/O never happens under the ao2 lock. The capture
	 *  thread reads capture_pcm without it: stop_stream() joins the
	 *  thread before the handles are closed. */
	ast_mutex_t pcm_lock;
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
	/*! Set during a reload so that we know to destroy this if it is no
	 *  longer in the configuration file. */
	unsigned int destroy:1;
	/*! Init AT commands already ran for the current modem appearance */
	unsigned int atinit_done:1;
	/*! Input buffer */
	char inbuf[NUM_SAMPLES * sizeof(int16_t) + AST_FRIENDLY_OFFSET];
	/*! Modem device (owned ref, NULL when unresolved) */
	MMModem *device;
	/*! Modem voice (owned ref) */
	MMModemVoice *voice;
	/*! Modem messaging (owned ref, may be NULL) */
	MMModemMessaging *messaging;
	/*! Current call (owned ref, managed by call_attach/call_detach) */
	MMCall *call;
	/*! Signal handler ids on device/voice/messaging (0 = not connected) */
	gulong sig_state_changed;
	gulong sig_call_added;
	gulong sig_message_added;
	/*! Signal handler ids on the current call */
	gulong sig_call_state_changed;
	gulong sig_call_notify;
	gulong sig_call_dtmf;
	/*! Raw D-Bus StateChanged subscription for the current call (0 = none) */
	guint sub_call_state;
	/*! Last call state acted upon (dedupes signal vs property-notify) */
	int last_call_state;
	/*! Serialized taskprocessor: all blocking work for this modem */
	struct ast_taskprocessor *serializer;
	/*! Jitterbuffer */
	struct ast_jb_conf jbconf;
	/*! ID for the ALSA capture thread */
	pthread_t thread;
} modem_pvt_t;

/*!
 * \brief ModemManager sim pvt structure
 */
typedef struct sim_pvt {
	AST_DECLARE_STRING_FIELDS(
		/*! ModemManager SimIdentifier (normally the ICCID) */
		AST_STRING_FIELD(identifier);
		/*! Default context for incoming calls */
		AST_STRING_FIELD(context);
		/*! Default context for incoming messages */
		AST_STRING_FIELD(message_context);
		/*! Default extension for incoming calls */
		AST_STRING_FIELD(exten);
		/*! Default MOH class */
		AST_STRING_FIELD(mohinterpret);
		/*! Default language */
		AST_STRING_FIELD(language);
		/*! Default parkinglot */
		AST_STRING_FIELD(parkinglot);
		/*! MMSC base URL; unset = MMS disabled for this SIM */
		AST_STRING_FIELD(mmsc);
		/*! MMS proxy "host:port" (plain HTTP forward proxy) */
		AST_STRING_FIELD(mms_proxy);
		/*! Bind MMS fetches to this netdev (the MMS APN bearer) */
		AST_STRING_FIELD(mms_interface);
		/*! Context for delivered MMS (falls back to message_context/context) */
		AST_STRING_FIELD(mms_context);
		/*! User-Agent override for MMSC requests */
		AST_STRING_FIELD(mms_user_agent);
		/*! Attachment spool directory */
		AST_STRING_FIELD(mms_spool);
	);
	/*! Response size cap in bytes */
	unsigned int mms_max_size;
	/*! Whole-transfer timeout in seconds */
	unsigned int mms_fetch_timeout;
	/*! Fetch attempts before giving up */
	unsigned int mms_max_retries;
	/*! Automatically answer incoming calls */
	unsigned int autoanswer:1;
	/*! Ignore context in the console dial CLI command */
	unsigned int overridecontext:1;
	/*! Send M-NotifyResp.ind after a successful fetch */
	unsigned int mms_ack:1;
	/*! "MMS disabled" already logged for this SIM this load */
	unsigned int mms_warned:1;
	/*! Set during a reload for destroy-if-unconfigured semantics */
	unsigned int destroy:1;
	/*! Assigned modem (owned ao2 ref, NULL when unresolved) */
	modem_pvt_t *modem;
	/*! Sim device (owned ref, NULL when unresolved) */
	MMSim *device;
} sim_pvt_t;

#define modemmanager_pvt_lock(pvt) ao2_lock(pvt)
#define modemmanager_pvt_unlock(pvt) ao2_unlock(pvt)

static inline modem_pvt_t *ref_modem(modem_pvt_t *pvt)
{
	if (pvt) {
		ao2_ref(pvt, +1);
	}
	return pvt;
}

static inline modem_pvt_t *unref_modem(modem_pvt_t *pvt)
{
	if (pvt) {
		ao2_ref(pvt, -1);
	}
	return NULL;
}

static inline sim_pvt_t *ref_sim(sim_pvt_t *pvt)
{
	if (pvt) {
		ao2_ref(pvt, +1);
	}
	return pvt;
}

static inline sim_pvt_t *unref_sim(sim_pvt_t *pvt)
{
	if (pvt) {
		ao2_ref(pvt, -1);
	}
	return NULL;
}

/*!
 * \brief Snapshot the owner channel under the pvt lock, taking a channel ref.
 * \return referenced channel or NULL; release with ast_channel_unref().
 */
static inline struct ast_channel *modem_grab_owner(modem_pvt_t *modem)
{
	struct ast_channel *chan;

	modemmanager_pvt_lock(modem);
	chan = modem->owner ? ast_channel_ref(modem->owner) : NULL;
	modemmanager_pvt_unlock(modem);
	return chan;
}

/*!
 * \brief Snapshot the SIM's modem under the sim lock, taking an ao2 ref.
 *
 * sim->modem is reassigned by resolve_object() on reload/hotplug and
 * cleared at unload; never read it bare outside the sim lock. Release
 * with unref_modem().
 */
static inline modem_pvt_t *sim_grab_modem(sim_pvt_t *sim)
{
	modem_pvt_t *modem;

	modemmanager_pvt_lock(sim);
	modem = ref_modem(sim->modem);
	modemmanager_pvt_unlock(sim);
	return modem;
}

#endif /* CHAN_MM_GLUE_H */
