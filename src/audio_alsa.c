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
#include "asterisk/format_cache.h"
#include "asterisk/logger.h"
#include "asterisk/utils.h"

#include "audio_alsa.h"
#include "audio_detect.h"

/*! \brief Frame length in milliseconds (one Asterisk voice frame per period) */
#define FRAME_MS         20

/*! \brief Periods in the ALSA ring buffer (4 x 20ms = 80ms of resilience) */
#define ALSA_PERIODS     4

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

void alsa_autodetect_devices(modem_pvt_t *modem)
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

static void close_stream_locked(modem_pvt_t *modem)
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

int open_stream(modem_pvt_t *modem)
{
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

/*!
 * \brief Capture thread: blocking poll + read, one Asterisk frame per period.
 *
 * Holds an ao2 ref on the modem for its whole lifetime. Reads the owner
 * pointer via modem_grab_owner() so a hangup on another thread cannot
 * leave it queueing into a destroyed channel.
 */
static void *capture_thread_fn(void *data)
{
	modem_pvt_t *modem = data;
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
		if (n > 0) {
			struct ast_channel *owner = modem_grab_owner(modem);

			if (owner) {
				struct ast_frame f = {
					.frametype = AST_FRAME_VOICE,
					.subclass.format = modem->format,
					.src = "chan_modemmanager_capture",
					.data.ptr = &modem->inbuf[AST_FRIENDLY_OFFSET],
					.offset = AST_FRIENDLY_OFFSET,
					.datalen = (int)(n * sizeof(int16_t)),
					.samples = (int)n,
				};
				ast_queue_frame(owner, &f);
				ast_channel_unref(owner);
			}
		}
	}

	unref_modem(modem);
	return NULL;
}

int start_stream(modem_pvt_t *modem)
{
	int ret_val = 0;

	modemmanager_pvt_lock(modem);

	/* It is possible for a hangup to land before the stream is started;
	 * in that case owner is NULL and starting would be pointless. */
	if (modem->streamstate || !modem->owner) {
		ast_debug(1, "Unable to start stream\n");
		goto return_unlock;
	}

	if (open_stream(modem)) {
		ret_val = -1;
		goto return_unlock;
	}

	/* Capture streams do not auto-start from snd_pcm_wait(); without this
	 * the capture thread would poll forever and no frames would flow. */
	if (snd_pcm_state(modem->capture_pcm) == SND_PCM_STATE_PREPARED) {
		int err = snd_pcm_start(modem->capture_pcm);
		if (err < 0) {
			ast_log(LOG_ERROR, "Failed to start ALSA capture for modem '%s': %s\n",
				modem->identifier, snd_strerror(err));
			close_stream_locked(modem);
			ret_val = -1;
			goto return_unlock;
		}
	}

	modem->stream_stop = 0;
	ref_modem(modem);
	if (ast_pthread_create_background(&modem->thread, NULL, capture_thread_fn, modem)) {
		ast_log(LOG_ERROR, "Failed to create capture thread for modem '%s'\n",
			modem->identifier);
		unref_modem(modem);
		close_stream_locked(modem);
		ret_val = -1;
		goto return_unlock;
	}
	modem->streamstate = 1;
	ast_debug(1, "Stream started\n");

return_unlock:
	modemmanager_pvt_unlock(modem);

	return ret_val;
}

int stop_stream(modem_pvt_t *modem)
{
	pthread_t thread = AST_PTHREADT_NULL;

	modemmanager_pvt_lock(modem);
	if (modem->streamstate) {
		modem->streamstate = 0;
		modem->stream_stop = 1;
		thread = modem->thread;
		modem->thread = AST_PTHREADT_NULL;
	}
	modemmanager_pvt_unlock(modem);

	/* The capture thread polls with a timeout, so it notices stream_stop
	 * on its own; no cross-thread snd_pcm calls are needed. */
	if (thread != AST_PTHREADT_NULL) {
		pthread_join(thread, NULL);
	}

	modemmanager_pvt_lock(modem);
	/* PCMs are opened at channel creation, before the stream starts, so
	 * close them even when the capture thread never ran. */
	close_stream_locked(modem);
	modemmanager_pvt_unlock(modem);

	return 0;
}

int alsa_write_frame(modem_pvt_t *modem, struct ast_frame *frame)
{
	snd_pcm_sframes_t n;

	modemmanager_pvt_lock(modem);
	if (modem->playback_pcm == NULL || !modem->streamstate) {
		modemmanager_pvt_unlock(modem);
		return 0;
	}
	n = snd_pcm_writei(modem->playback_pcm, frame->data.ptr, frame->samples);
	if (n < 0 && !alsa_pcm_recover(modem->playback_pcm, n)) {
		n = snd_pcm_writei(modem->playback_pcm, frame->data.ptr, frame->samples);
	}
	modemmanager_pvt_unlock(modem);
	if (n < 0) {
		ast_log(LOG_WARNING, "ALSA playback failed: %s\n", snd_strerror(n));
		return -1;
	}
	return 0;
}

void alsa_cli_list_devices(int fd)
{
	void **hints = NULL;

	ast_cli(fd, "\nAvailable ALSA PCM devices (use the name as input_device/output_device)\n\n");

	if (snd_device_name_hint(-1, "pcm", &hints) < 0 || !hints) {
		ast_cli(fd, "(none)\n");
		return;
	}
	for (void **h = hints; *h; h++) {
		char *name = snd_device_name_get_hint(*h, "NAME");
		char *desc = snd_device_name_get_hint(*h, "DESC");
		char *ioid = snd_device_name_get_hint(*h, "IOID");

		if (name) {
			ast_cli(fd, "Device '%s'%s%s\n", name,
				ioid ? " - " : "", S_OR(ioid, ""));
			if (desc) {
				char *line, *rest = desc;

				while ((line = strsep(&rest, "\n"))) {
					ast_cli(fd, "\t%s\n", line);
				}
			}
		}

		ast_std_free(name);
		ast_std_free(desc);
		ast_std_free(ioid);
	}
	snd_device_name_free_hint(hints);
}
