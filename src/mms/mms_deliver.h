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
 * \brief MMS delivery: ast_msg construction and attachment spooling.
 */

#ifndef CHAN_MM_MMS_DELIVER_H
#define CHAN_MM_MMS_DELIVER_H

#include "../mm_glue.h"

struct mms_message;

/*!
 * \brief Deliver one decoded m-retrieve.conf to the Asterisk message bus.
 *
 * Text/plain parts are concatenated (SMIL skipped); other parts are
 * written under <spool>/<txn>/ and referenced via MMS_ATTACHMENT_* vars.
 * A message with no text part still delivers with a placeholder body.
 *
 * \param pdu the fetched body the attachment offsets index into
 * \param from_fallback used when the carrier omitted/tokenized From
 */
void mms_deliver(sim_pvt_t *sim, struct mms_message *msg,
	const uint8_t *pdu, size_t pdu_len,
	const char *txn_id, const char *from_fallback, const char *spool);

#endif /* CHAN_MM_MMS_DELIVER_H */
