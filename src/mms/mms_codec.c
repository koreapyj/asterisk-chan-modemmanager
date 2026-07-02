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
 * \brief MMS-over-SMS codec implementation. See mms_codec.h for the API
 * contract; this file only implements it.
 *
 * The WAP Push envelope parsing here (mms_codec_wap_push_extract() and its
 * helpers) is new code written for chan_modemmanager: mmsd-tng is a full
 * MMSC HTTP client and never has to unwrap an SMS transport envelope, so
 * nothing in the vendored src/mms/vendor/ tree covers it. It does reuse
 * the vendored wsputil primitives (wsp_decode_uintvar(),
 * wsp_decode_content_type()) for the WSP-encoded pieces of that envelope,
 * since those are exactly the well-known-value / text-value parsing
 * rules the WSP Push Content-Type header follows.
 */

#include <string.h>
#include <limits.h>

#include <glib.h>

#include "mms_codec.h"
#include "vendor/wsputil.h"
#include "vendor/mmsutil.h"

/* WSP PDU types relevant to a Push received over a connectionless bearer
 * (WAP-230-WSP section 8.2.3.3 / section 8.2.4). Only these two are valid
 * for what a WDP/SMS port-2948 payload can carry. */
#define WSP_PDU_TYPE_PUSH               0x06
#define WSP_PDU_TYPE_CONFIRMED_PUSH     0x07

/* The one Content-Type this codec accepts; everything else on port 2948
 * (SI, SL, OTA provisioning, ...) is deliberately not MMS. */
#define MMS_PUSH_CONTENT_TYPE           "application/vnd.wap.mms-message"

/* GSM 03.40 SMS User Data Header: Information Element Identifiers for
 * application port addressing. */
#define UDH_IEI_PORT_8BIT                0x04
#define UDH_IEI_PORT_16BIT               0x05
#define UDH_IEI_PORT_8BIT_LEN            2
#define UDH_IEI_PORT_16BIT_LEN           4

/* Well-known WSP port that WAP Push (MMS notifications, SI, SL, ...)
 * arrives on. */
#define WSP_PUSH_PORT                    2948

/*!
 * \brief Try a direct (no UDH) WSP Push parse of \a data.
 *
 * \see mms_codec_wap_push_extract() for the exact PDU layout this expects.
 */
static int wsp_push_try_parse(const uint8_t *data, size_t len,
	const uint8_t **out_body, size_t *out_len)
{
	size_t pos;
	unsigned int headers_len = 0;
	unsigned int consumed = 0;
	unsigned int ct_consumed = 0;
	const void *content_type = NULL;
	size_t headers_end;

	/* TID(1) + PDU-Type(1) + at least one Headers-Length octet. */
	if (len < 3) {
		return -1;
	}

	pos = 1; /* data[0] is the TID; its value is not otherwise checked. */

	if (data[pos] != WSP_PDU_TYPE_PUSH && data[pos] != WSP_PDU_TYPE_CONFIRMED_PUSH) {
		return -1;
	}
	pos++;

	if (wsp_decode_uintvar(data + pos, len - pos, &headers_len, &consumed) == FALSE) {
		return -1;
	}
	pos += consumed;

	/* Headers-Length must at minimum cover a Content-Type value; also
	 * guard the bounds check itself against size_t overflow. */
	if (headers_len == 0 || headers_len > len - pos) {
		return -1;
	}
	headers_end = pos + headers_len;

	if (wsp_decode_content_type(data + pos, headers_len, &content_type,
			&ct_consumed, NULL) == FALSE) {
		return -1;
	}
	if (content_type == NULL || ct_consumed > headers_len) {
		return -1;
	}

	/* Any bytes between the Content-Type value and headers_end are other
	 * WSP push headers (e.g. X-Wap-Application-Id); we don't need any of
	 * them to identify/extract the MMS body, so they're intentionally
	 * skipped rather than iterated. */

	if (strcmp((const char *) content_type, MMS_PUSH_CONTENT_TYPE) != 0) {
		return -1;
	}

	if (out_body) {
		*out_body = data + headers_end;
	}
	if (out_len) {
		*out_len = len - headers_end;
	}
	return 0;
}

/*!
 * \brief Detect a leading SMS UDH and compute how many bytes to skip.
 *
 * Walks the UDHL-prefixed IEI/IEL/IE-data chain. If an application port
 * addressing IE (0x04 8-bit or 0x05 16-bit) names a destination port
 * other than 2948, this is provably not our UDH and the whole payload is
 * rejected (*out_skip is not a valid retry point). If no port IE is
 * present at all (e.g. only a concatenation IE), the UDH is still valid
 * to skip; the caller's subsequent WSP parse decides pass/fail on its
 * own merits.
 *
 * \retval 0 *out_skip is the total UDH length (UDHL byte + UDHL bytes)
 * \retval -1 no usable UDH here (malformed, truncated, or wrong port)
 */
static int udh_skip_len(const uint8_t *data, size_t len, size_t *out_skip)
{
	uint8_t udhl;
	size_t pos, end;
	int saw_port_ie = 0;
	int port_matched = 0;

	if (len < 1) {
		return -1;
	}

	udhl = data[0];
	if ((size_t) udhl + 1 > len) {
		return -1;
	}

	pos = 1;
	end = 1 + (size_t) udhl;

	while (pos + 2 <= end) {
		uint8_t iei = data[pos];
		uint8_t iel = data[pos + 1];
		const uint8_t *ie = data + pos + 2;

		if (pos + 2 + (size_t) iel > end) {
			return -1; /* IE claims to run past the declared UDH length */
		}

		if (iei == UDH_IEI_PORT_16BIT && iel == UDH_IEI_PORT_16BIT_LEN) {
			unsigned int dest_port = ((unsigned int) ie[0] << 8) | ie[1];
			saw_port_ie = 1;
			port_matched = (dest_port == WSP_PUSH_PORT);
		} else if (iei == UDH_IEI_PORT_8BIT && iel == UDH_IEI_PORT_8BIT_LEN) {
			unsigned int dest_port = ie[0];
			saw_port_ie = 1;
			port_matched = (dest_port == WSP_PUSH_PORT);
		}

		pos += 2 + iel;
	}

	if (pos != end) {
		return -1; /* IE chain didn't consume exactly UDHL bytes: malformed */
	}

	if (saw_port_ie && !port_matched) {
		return -1;
	}

	*out_skip = end;
	return 0;
}

int mms_codec_wap_push_extract(const uint8_t *data, size_t len,
	const uint8_t **out_body, size_t *out_len)
{
	size_t skip;

	if (!data || len == 0) {
		return -1;
	}

	if (wsp_push_try_parse(data, len, out_body, out_len) == 0) {
		return 0;
	}

	if (udh_skip_len(data, len, &skip) == 0 && skip < len) {
		return wsp_push_try_parse(data + skip, len - skip, out_body, out_len);
	}

	return -1;
}

/*!
 * \brief Shared decode core for both public decode entry points.
 *
 * Allocates *out via GLib (matching what the vendored mms_message_free()
 * expects to release, per upstream mmsd-tng's own g_try_new0() +
 * mms_message_decode() usage), decodes, and additionally enforces that
 * the decoded PDU is the expected message type -- mms_message_decode()
 * itself will happily decode any recognised MMS PDU type based solely on
 * the leading X-Mms-Message-Type octet, so a caller asking specifically
 * for a notification-ind (say) must not be handed back some other type.
 */
static int decode_as(const uint8_t *pdu, size_t len,
	enum mms_message_type want, struct mms_message **out)
{
	struct mms_message *msg;

	if (!pdu || !out) {
		return -1;
	}
	if (len > UINT_MAX) {
		/* mms_message_decode() takes an unsigned int length; SMS/MMS PDUs
		 * are nowhere near this large, so this is purely defensive. */
		return -1;
	}

	msg = g_try_new0(struct mms_message, 1);
	if (!msg) {
		return -1;
	}

	if (mms_message_decode(pdu, (unsigned int) len, msg) == FALSE || msg->type != want) {
		mms_message_free(msg);
		return -1;
	}

	*out = msg;
	return 0;
}

int mms_codec_decode_notification(const uint8_t *pdu, size_t len,
	struct mms_message **out)
{
	return decode_as(pdu, len, MMS_MESSAGE_TYPE_NOTIFICATION_IND, out);
}

int mms_codec_decode_retrieve(const uint8_t *pdu, size_t len,
	struct mms_message **out)
{
	return decode_as(pdu, len, MMS_MESSAGE_TYPE_RETRIEVE_CONF, out);
}

void mms_codec_message_free(struct mms_message *msg)
{
	if (msg) {
		mms_message_free(msg);
	}
}
