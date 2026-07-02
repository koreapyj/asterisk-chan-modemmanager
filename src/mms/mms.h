/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 * \brief Native MMS receive subsystem — public boundary.
 *
 * Pipeline: sms.c hands over binary SMS payloads; the WSP push envelope
 * is parsed (mms_codec.h) and MMS notifications are deduplicated by
 * (sim, transaction id) and queued. A dedicated worker thread fetches
 * m-retrieve.conf from the carrier MMSC over libcurl (proxy/interface
 * binding per SIM config), decodes it, delivers text parts to the
 * Asterisk message bus, spools attachments and best-effort acks with
 * M-NotifyResp.ind. The notification SMS is only deleted from the modem
 * once the message reaches a terminal state, so a restart re-discovers
 * pending notifications (memory-only state).
 *
 * Threading: intake runs on modem serializers; all blocking HTTP runs on
 * the MMS worker thread (never a modem serializer, never the GMainLoop
 * thread); SMS deletion is pushed back onto the owning modem's
 * serializer.
 */

#ifndef CHAN_MM_MMS_H
#define CHAN_MM_MMS_H

#include "../mm_glue.h"

/*! \brief Start the MMS worker (module load). \retval 0 success */
int mms_init(void);

/*! \brief Stop and join the MMS worker, drop pending state (module unload) */
void mms_shutdown(void);

/*!
 * \brief Hand over one received binary SMS payload (WAP push candidate).
 *
 * Non-MMS pushes and duplicates are dropped quietly. When the SIM has no
 * mmsc configured, the notification is left on the modem and a single
 * notice is logged per SIM.
 *
 * \param sim owning SIM (a ref is taken as needed)
 * \param data raw SMS payload (copied as needed; caller keeps ownership)
 * \param orig_number sender of the carrying SMS (fallback From)
 * \param sms_path ModemManager D-Bus path of the SMS (deleted on terminal state)
 */
void mms_on_wap_push_sms(sim_pvt_t *sim, const guint8 *data, gsize len,
	const char *orig_number, const char *sms_path);

#endif /* CHAN_MM_MMS_H */
