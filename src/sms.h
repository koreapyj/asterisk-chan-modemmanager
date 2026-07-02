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
 * \brief SMS send/receive via the Asterisk message bus.
 */

#ifndef CHAN_MM_SMS_H
#define CHAN_MM_SMS_H

#include "mm_glue.h"

#include "asterisk/message.h"

extern const struct ast_msg_tech mm_msg_tech;

/*!
 * \brief MMModemMessaging "added" signal handler (GMainLoop thread).
 * user_data is a referenced sim_pvt_t (managed by the connection closure).
 */
void on_message_added(MMModemMessaging *messaging, const char *path, gboolean received, void *data);

/*!
 * \brief Rescan SMS already stored on the modem (serializer task).
 *
 * Feeds stored BINARY messages (WAP-push MMS notifications) through the
 * MMS intake — they stay on the modem until the MMS reaches a terminal
 * state, so notifications that arrived while the module was not watching
 * are recovered on every modem (re)appearance. Stored text SMS are
 * skipped: they were delivered when they arrived, and re-delivering on
 * every reload would duplicate them.
 */
void sms_rescan_stored(sim_pvt_t *sim);

#endif /* CHAN_MM_SMS_H */
