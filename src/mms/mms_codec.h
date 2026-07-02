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
 * \brief MMS-over-SMS codec: WAP Push envelope extraction + MMS PDU decode.
 *
 * This is the clean boundary between the vendored mmsd-tng codec
 * (src/mms/vendor/{wsputil,mmsutil}.{c,h}) and the rest of the driver.
 * It depends on GLib only -- no Asterisk headers, no libmm-glib -- so it
 * builds and is unit-testable as a plain host binary (see
 * tests/test_mms_codec.c).
 *
 * Wire path this exists to serve (wiring itself lands in a later step):
 * ModemManager reports a WAP Push MMS notification as a binary SMS.
 * Depending on the modem/network, the SMS user-data payload handed to us
 * may or may not still carry the port-addressing UDH (the transport-layer
 * detail that says "this is addressed to WSP port 2948"); either way, the
 * payload's actual content is a WSP Push PDU whose body is an MMS PDU --
 * almost always an m-notification.ind (struct mms_notification_ind) that
 * the caller then fetches and decodes as an m-retrieve.conf (struct
 * mms_retrieve_conf + attachments) once retrieved from the MMSC.
 *
 * Port 2948 also carries WAP Service Indication / Service Loading / OTA
 * provisioning pushes, which are not MMS; mms_codec_wap_push_extract()
 * rejects those (and anything else that isn't
 * "application/vnd.wap.mms-message") rather than mis-decoding them.
 *
 * Ownership / lifetime contract (read before wiring this into sms.c):
 *
 *   - mms_codec_wap_push_extract() never allocates or copies: *out_body
 *     is a pointer INTO the caller-owned `data` buffer. The caller must
 *     keep `data` alive and unmodified for as long as *out_body is used,
 *     which includes the entire lifetime of any struct mms_message later
 *     decoded from it (see next point) -- not just the extract() call
 *     itself.
 *
 *   - mms_codec_decode_notification() / mms_codec_decode_retrieve() heap
 *     allocate and return a new struct mms_message (via GLib, mirroring
 *     upstream mmsd-tng's own g_try_new0() + mms_message_decode(pdu, len,
 *     msg) usage). Critically, the vendored decoder does NOT copy
 *     attachment payloads: struct mms_attachment's `offset`/`length`
 *     fields are byte offsets into the *original* `pdu` buffer passed to
 *     the decode call (its `data` field is left NULL/unused). This means
 *     `pdu` must remain valid and unmodified for the entire lifetime of
 *     the returned struct mms_message, not just for the duration of the
 *     decode call. This matters most for mms_codec_decode_retrieve(),
 *     whose whole point is exposing attachment parts.
 *
 *   - mms_codec_message_free() frees the struct mms_message itself (its
 *     fields and the struct); it never touches the `pdu`/`data` buffer
 *     the caller supplied, which remains the caller's to free.
 *
 * Fields that matter per PDU type (see src/mms/vendor/mmsutil.h for the
 * full struct mms_message / union definitions):
 *
 *   Notification (msg->type == MMS_MESSAGE_TYPE_NOTIFICATION_IND, access
 *   via msg->ni, struct mms_notification_ind):
 *     - msg->transaction_id  (char *)  X-Mms-Transaction-Id; echo this
 *       back verbatim in the eventual M-NotifyResp.ind.
 *     - msg->version         (unsigned char) MMS version, e.g. 0x90 =
 *       1.0 (high nibble = major, low nibble = minor: (v&0x70)>>4 . v&0x0f).
 *     - msg->ni.from          (char *, may be NULL) sender address.
 *     - msg->ni.cls           (char *) X-Mms-Message-Class (e.g. "Personal").
 *     - msg->ni.size          (unsigned int) X-Mms-Message-Size in bytes.
 *     - msg->ni.expiry        (time_t) absolute expiry, already resolved
 *       from either an absolute or relative-to-now encoding upstream.
 *     - msg->ni.location      (char *) X-Mms-Content-Location: the URL to
 *       fetch the m-retrieve.conf from.
 *
 *   Retrieve (msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF, access via
 *   msg->rc, struct mms_retrieve_conf):
 *     - msg->transaction_id, msg->version as above.
 *     - msg->rc.from/to/subject/cls/priority/msgid, msg->rc.date (time_t).
 *     - msg->attachments (GSList of struct mms_attachment *): each part's
 *       bytes are pdu[attach->offset .. attach->offset+attach->length),
 *       with attach->content_type (char *, e.g. "text/plain;charset=utf-8")
 *       and attach->content_id (char *, e.g. "<Text_us-ascii.txt>", the
 *       SMIL-referenced part id -- mmsd-tng synthesizes a random one via
 *       g_uuid_string_random() if a part omits it).
 */

#ifndef CHAN_MM_MMS_CODEC_H
#define CHAN_MM_MMS_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "vendor/mmsutil.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Validate and unwrap a WAP Push SMS payload down to its MMS body.
 *
 * Defensively parses \a data as a WSP Push PDU:
 *
 *   TID(1) PDU-Type(1) Headers-Length(uintvar) Content-Type Headers Data
 *
 * (PDU-Type 0x06 Push or 0x07 ConfirmedPush; see WAP-230-WSP section
 * 8.2). If that fails structural validation, retries after detecting and
 * skipping a leading GSM SMS User Data Header (UDHL + IEI/IEL entries),
 * so this copes whether or not the WSP-port-addressing UDH (IEI 0x05
 * 16-bit, or 0x04 8-bit; destination port 2948) is still present on the
 * payload handed to us -- ModemManager may or may not have already
 * stripped it. If a port-addressing IE *is* present but names a port
 * other than 2948, the payload is rejected outright (it is provably not
 * a WSP push): a mismatched port is a hard reject, but a UDH that simply
 * doesn't carry a port IE at all (e.g. only a concatenation IE) does not
 * block the retry -- the WSP parse after skipping the UDH is still
 * attempted and stands or falls on its own.
 *
 * On success, *out_body / *out_len point at the M-*.ind PDU carried as the
 * push body (still inside \a data -- nothing is copied; see the
 * ownership contract in this file's header comment). Only succeeds when
 * the push's Content-Type is exactly "application/vnd.wap.mms-message",
 * whether encoded as the WSP well-known short-integer form (0x3E | 0x80
 * = 0xBE) or as the literal text token; anything else -- notably WAP
 * Service Indication/Loading (SI/SL, e.g. "application/vnd.wap.sic")
 * which also rides port 2948 -- is rejected.
 *
 * \param data raw SMS user-data payload (with or without UDH)
 * \param len length of \a data in bytes
 * \param out_body set on success to a pointer inside \a data
 * \param out_len set on success to the length of *out_body
 * \retval 0 \a data is an MMS WAP Push; *out_body / *out_len are valid
 * \retval -1 malformed, truncated, or a non-MMS push (SI/SL/OTA/etc.)
 */
int mms_codec_wap_push_extract(const uint8_t *data, size_t len,
	const uint8_t **out_body, size_t *out_len);

/*!
 * \brief Decode an M-Notification.ind PDU (the WAP Push body).
 *
 * Thin wrapper around the vendored mms_message_decode() that additionally
 * verifies the decoded PDU really is a notification-ind (rejects any
 * other MMS message type as a decode failure). See this file's header
 * comment for the ownership contract (\a pdu must outlive *out) and which
 * struct mms_message fields are populated for this type.
 *
 * \param pdu M-Notification.ind bytes, e.g. *out_body from
 *            mms_codec_wap_push_extract()
 * \param len length of \a pdu in bytes
 * \param out set on success to a newly heap-allocated struct mms_message;
 *            release with mms_codec_message_free(). Untouched on failure.
 * \retval 0 decoded successfully and msg->type == MMS_MESSAGE_TYPE_NOTIFICATION_IND
 * \retval -1 malformed PDU, or it decoded but was not a notification-ind
 */
int mms_codec_decode_notification(const uint8_t *pdu, size_t len,
	struct mms_message **out);

/*!
 * \brief Decode an M-Retrieve.conf PDU (the body fetched from the MMSC).
 *
 * Same contract as mms_codec_decode_notification(), for retrieve-conf.
 * \a pdu must remain valid for the lifetime of *out: attachment parts
 * reference it directly by offset/length rather than owning a copy (see
 * this file's header comment).
 *
 * \retval 0 decoded successfully and msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF
 * \retval -1 malformed PDU, or it decoded but was not a retrieve-conf
 */
int mms_codec_decode_retrieve(const uint8_t *pdu, size_t len,
	struct mms_message **out);

/*!
 * \brief Release a struct mms_message returned by either decode call above.
 *
 * Delegates to the vendored mms_message_free(), which frees the struct's
 * fields (including the struct mms_attachment list, if any) and the
 * struct itself. Never touches the caller's original \a pdu/\a data
 * buffer. NULL-safe (no-op on NULL, matching the free()-family
 * convention used throughout this driver).
 */
void mms_codec_message_free(struct mms_message *msg);

#ifdef __cplusplus
}
#endif

#endif /* CHAN_MM_MMS_CODEC_H */
