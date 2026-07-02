/*
 * Unit tests for the MMS-over-SMS codec (src/mms/mms_codec.c and the
 * vendored src/mms/vendor/{wsputil,mmsutil}.c).
 *
 * Two kinds of fixtures are used:
 *
 *  - Hand-crafted WSP/MMS PDUs (byte arrays below, built directly from the
 *    WAP-230-WSP / OMA-TS-MMS_ENC binary encoding rules -- each byte group
 *    is commented with what it encodes). These exercise the WAP Push
 *    envelope unwrapping (with/without a leading SMS UDH), the SI-push
 *    rejection path, garbage rejection, and part extraction from an
 *    M-Retrieve.conf.
 *
 *  - Two PDUs copied byte-for-byte from mmsd-tng's own test corpus
 *    (unit/test-mmsutil.c, same upstream commit as the vendored code --
 *    see src/mms/vendor/mmsutil.c's provenance header), used here as a
 *    regression check that mms_codec_decode_notification()/
 *    mms_codec_decode_retrieve() reproduce the exact upstream-documented
 *    decode of PDUs this codec did not itself construct.
 *
 * Run with `make check`.
 */

#include "../src/mms/mms_codec.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int failures;

#define CHECK(cond, name) do { \
	if (cond) { \
		printf("ok   %s\n", name); \
	} else { \
		printf("FAIL %s\n", name); \
		failures++; \
	} \
} while (0)

/*
 * ---------------------------------------------------------------------
 * (a) WAP Push M-Notification.ind, WITH a leading SMS UDH addressing
 * port 2948.
 *
 * UDH (7 bytes):
 *   0x06                    UDHL: 6 bytes of UDH follow
 *   0x05                    IEI: application port addressing, 16-bit
 *   0x04                    IEL: 4 bytes of IE data follow
 *   0x0B, 0x84               dest port = 2948 (0x0B84, the WSP push port)
 *   0x00, 0x00               orig port = 0 (unused/arbitrary)
 *
 * WSP Push envelope (4 bytes):
 *   0x00                    TID (arbitrary, unused by the parser)
 *   0x06                    PDU-Type: Push
 *   0x01                    Headers-Length uintvar = 1
 *   0xBE                    Content-Type, well-known short-integer form:
 *                           0x3E (application/vnd.wap.mms-message) | 0x80
 *
 * M-Notification.ind body (44 bytes):
 *   0x8C, 0x82               X-Mms-Message-Type = m-notification-ind (0x82/130)
 *   0x98, "T1\0"              X-Mms-Transaction-Id = "T1"
 *   0x8D, 0x90               X-Mms-MMS-Version = 1.0 (0x90)
 *   0x8A, 0x80               X-Mms-Message-Class = Personal (short-int 128)
 *   0x8E, 0x02, 0x04,0x00     X-Mms-Message-Size: Long-Integer, 2 octets,
 *                             value 0x0400 = 1024
 *   0x88, 0x04,               X-Mms-Expiry: Long-Integer, 4 octets:
 *     0x81,                     Relative-token (129)
 *     0x02, 0x0E,0x10           nested Long-Integer: 2 octets, 0x0E10 = 3600s
 *   0x83, "http://mmsc.example/x1\0"  X-Mms-Content-Location
 * ---------------------------------------------------------------------
 */
static const uint8_t ni_with_udh[] = {
	/* UDH */
	0x06, 0x05, 0x04, 0x0B, 0x84, 0x00, 0x00,
	/* WSP Push envelope */
	0x00, 0x06, 0x01, 0xBE,
	/* M-Notification.ind */
	0x8C, 0x82,
	0x98, 'T', '1', 0x00,
	0x8D, 0x90,
	0x8A, 0x80,
	0x8E, 0x02, 0x04, 0x00,
	0x88, 0x04, 0x81, 0x02, 0x0E, 0x10,
	0x83, 'h', 't', 't', 'p', ':', '/', '/', 'm', 'm', 's', 'c', '.',
	'e', 'x', 'a', 'm', 'p', 'l', 'e', '/', 'x', '1', 0x00,
};

/*
 * (b) The exact same WAP Push + M-Notification.ind as above, but WITHOUT
 * the leading UDH -- as if ModemManager (or the modem firmware) already
 * stripped the port-addressing header before handing us the SMS payload.
 */
static const uint8_t ni_no_udh[] = {
	/* WSP Push envelope */
	0x00, 0x06, 0x01, 0xBE,
	/* M-Notification.ind (identical to ni_with_udh's tail) */
	0x8C, 0x82,
	0x98, 'T', '1', 0x00,
	0x8D, 0x90,
	0x8A, 0x80,
	0x8E, 0x02, 0x04, 0x00,
	0x88, 0x04, 0x81, 0x02, 0x0E, 0x10,
	0x83, 'h', 't', 't', 'p', ':', '/', '/', 'm', 'm', 's', 'c', '.',
	'e', 'x', 'a', 'm', 'p', 'l', 'e', '/', 'x', '1', 0x00,
};

/*
 * (c) WAP Push whose Content-Type is Service Indication
 * ("application/vnd.wap.sic", well-known short-integer 0x2E | 0x80 =
 * 0xAE) rather than MMS. Also rides port 2948; must be cleanly rejected
 * rather than mis-decoded as MMS.
 */
static const uint8_t si_push[] = {
	0x00,       /* TID */
	0x06,       /* PDU-Type: Push */
	0x01,       /* Headers-Length uintvar = 1 */
	0xAE,       /* Content-Type: application/vnd.wap.sic (SI) */
	0x00,       /* single-byte "body" (irrelevant; rejected before this) */
};

/*
 * (d) Garbage: not a valid WSP Push envelope under any interpretation
 * (direct or UDH-prefixed).
 */
static const uint8_t garbage[] = {
	0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02,
};

/*
 * (f) Bonus robustness case: a UDH IS present and DOES carry a 16-bit
 * port-addressing IE, but it names port 1 instead of 2948. This is
 * provably not a WSP push for us and must be rejected outright (not
 * silently retried as if no UDH were present).
 */
static const uint8_t wrong_port_udh[] = {
	0x06, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00,        /* UDH: dest port = 1 */
	0x00, 0x06, 0x01, 0xBE,                           /* WSP push envelope */
	0x8C, 0x82, 0x98, 'T', '1', 0x00, 0x8D, 0x90,      /* (truncated; never
	                                                      reached) */
};

/*
 * ---------------------------------------------------------------------
 * (e) Minimal M-Retrieve.conf with one text/plain part, "hello mms".
 *
 *   0x8C, 0x84                X-Mms-Message-Type = m-retrieve-conf (0x84/132)
 *   0x98, "R1\0"                X-Mms-Transaction-Id = "R1"
 *   0x8D, 0x90                X-Mms-MMS-Version = 1.0
 *   0x89, 0x0E,                From: Value-length=14, then:
 *     0x80,                      Address-present-token (128)
 *     "+15550001111\0"           Encoded-string-value (plain text, 13 bytes)
 *   0x85, 0x04,                Date: Long-Integer, 4 octets:
 *     0x65,0x53,0xF1,0x00        epoch seconds 1700000000
 *   0x84,                      Content-Type header (0x04|0x80) -- this is
 *                              what wsputil's MMS-multipart detection keys
 *                              off of; everything after it is the
 *                              multipart body, not more plain headers:
 *     0xA3,                      overall Content-Type: well-known
 *                                short-integer 0x23 = "multipart/mixed"
 *     0x01,                      part count uintvar = 1 (informational)
 *     0x0B,                      part 1 headers-length uintvar = 11
 *                                (1 content-type byte + 10 header bytes)
 *     0x09,                      part 1 body-length uintvar = 9
 *     0x83,                      part 1 Content-Type: text/plain
 *                                (well-known short-integer 0x03)
 *     0xC0, 0x22,"<hello>\0"     part 1 Content-ID header (0x40|0x80):
 *                                quoted-string "<hello>" (leading 0x22='"'
 *                                marks it as a WSP quoted Text-string;
 *                                mmsutil's wsp_decode_quoted_string()
 *                                strips just that leading quote)
 *     "hello mms"                part 1 body, 9 raw bytes (no NUL --
 *                                length-delimited by body-length above)
 * ---------------------------------------------------------------------
 */
static const uint8_t retrieve_conf[] = {
	0x8C, 0x84,
	0x98, 'R', '1', 0x00,
	0x8D, 0x90,
	0x89, 0x0E, 0x80, '+', '1', '5', '5', '5', '0', '0', '0', '1', '1',
	'1', '1', 0x00,
	0x85, 0x04, 0x65, 0x53, 0xF1, 0x00,
	0x84,
	0xA3, 0x01, 0x0B, 0x09, 0x83, 0xC0, 0x22, '<', 'h', 'e', 'l', 'l',
	'o', '>', 0x00, 'h', 'e', 'l', 'l', 'o', ' ', 'm', 'm', 's',
};

/*
 * ---------------------------------------------------------------------
 * Two fixtures copied verbatim from mmsd-tng's own test suite:
 * unit/test-mmsutil.c, mms_m_notify_ind_1 and mms_m_retrieve_conf_1
 * (https://gitlab.com/kop316/mmsd, commit
 * 341117141f8d30949fb1294cc71ee44af9b4c90f -- the same commit vendored
 * into src/mms/vendor/). Upstream's own comments (reproduced below)
 * document the expected decode; used here as-is via
 * mms_codec_decode_notification()/mms_codec_decode_retrieve() directly
 * (no WSP Push wrapper: these are bare MMS PDU bytes, exactly what
 * mms_codec_wap_push_extract() would hand back as *out_body).
 * ---------------------------------------------------------------------
 */

/*
 * Upstream comment (unit/test-mmsutil.c, mms_m_notify_ind_1):
 *   Overall message size: 68
 *   MMS message type: notification-ind
 *   MMS transaction id: OgQKKB
 *   MMS version: 1.0
 *   From: Erotik
 *   Subject: Pin-Ups
 *   Class: Personal
 *   Size: 16384
 *   Expiry: 2011-05-19T10:56:340200
 *   Location: http://eps3.de/O/Z9IZO
 */
static const uint8_t upstream_notify_ind_1[] = {
	0x8C, 0x82, 0x98, 0x4F, 0x67, 0x51, 0x4B, 0x4B,
	0x42, 0x00, 0x8D, 0x90, 0x89, 0x08, 0x80, 0x45,
	0x72, 0x6F, 0x74, 0x69, 0x6B, 0x00, 0x96, 0x50,
	0x69, 0x6E, 0x2D, 0x55, 0x70, 0x73, 0x00, 0x8A,
	0x80, 0x8E, 0x02, 0x40, 0x00, 0x88, 0x05, 0x81,
	0x03, 0x03, 0xF4, 0x80, 0x83, 0x68, 0x74, 0x74,
	0x70, 0x3A, 0x2F, 0x2F, 0x65, 0x70, 0x73, 0x33,
	0x2E, 0x64, 0x65, 0x2F, 0x4F, 0x2F, 0x5A, 0x39,
	0x49, 0x5A, 0x4F, 0x00,
};

/*
 * Upstream comment (unit/test-mmsutil.c, mms_m_retrieve_conf_1):
 *   Overall message size: 200
 *   MMS message type: retrieve-conf
 *   MMS transaction id: 1201657238
 *   MMS version: 1.3
 *   From: 49891000/TYPE=PLMN
 *   To: (null)
 *   Subject: MMS-1.3-con-212
 *   Class: (null)
 *   Priority: (null)
 *   Msg-Id: mt-212
 *   Date: 2008-01-30T02:40:380100
 * (one text/plain;charset=us-ascii part, content-id
 * <Text_us-ascii.txt>, body "The quick brown fox jumped over the lazy
 * dog 1234567890/!()")
 */
static const uint8_t upstream_retrieve_conf_1[] = {
	0x8C, 0x84, 0x98, 0x31, 0x32, 0x30, 0x31, 0x36,
	0x35, 0x37, 0x32, 0x33, 0x38, 0x00, 0x8D, 0x93,
	0x8B, 0x6D, 0x74, 0x2D, 0x32, 0x31, 0x32, 0x00,
	0x85, 0x04, 0x47, 0x9F, 0xD5, 0x96, 0x89, 0x15,
	0x80, 0x2B, 0x34, 0x39, 0x38, 0x39, 0x31, 0x30,
	0x30, 0x30, 0x2F, 0x54, 0x59, 0x50, 0x45, 0x3D,
	0x50, 0x4C, 0x4D, 0x4E, 0x00, 0x96, 0x11, 0x83,
	0x4D, 0x4D, 0x53, 0x2D, 0x31, 0x2E, 0x33, 0x2D,
	0x63, 0x6F, 0x6E, 0x2D, 0x32, 0x31, 0x32, 0x00,
	0x84, 0xA3, 0x01, 0x40, 0x3B, 0x14, 0x83, 0x85,
	0x54, 0x65, 0x78, 0x74, 0x5F, 0x75, 0x73, 0x2D,
	0x61, 0x73, 0x63, 0x69, 0x69, 0x2E, 0x74, 0x78,
	0x74, 0x00, 0x81, 0x83, 0xC0, 0x22, 0x3C, 0x54,
	0x65, 0x78, 0x74, 0x5F, 0x75, 0x73, 0x2D, 0x61,
	0x73, 0x63, 0x69, 0x69, 0x2E, 0x74, 0x78, 0x74,
	0x3E, 0x00, 0x8E, 0x54, 0x65, 0x78, 0x74, 0x5F,
	0x75, 0x73, 0x2D, 0x61, 0x73, 0x63, 0x69, 0x69,
	0x2E, 0x74, 0x78, 0x74, 0x00, 0x54, 0x68, 0x65,
	0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62,
	0x72, 0x6F, 0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78,
	0x20, 0x6A, 0x75, 0x6D, 0x70, 0x65, 0x64, 0x20,
	0x6F, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F,
	0x67, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x30, 0x2F, 0x21, 0x28, 0x29,
};

/*!
 * \brief Decode notification-ind fixture \a body and check the fields a
 * later wiring step would rely on (transaction id, version, class, size,
 * location; expiry checked as "roughly now + delta" since it is resolved
 * against wall-clock time at decode time for the relative encoding used
 * in fixtures (a)/(b)).
 */
static void check_notification(const uint8_t *body, size_t body_len,
	const char *label, const char *transaction_id, const char *cls,
	unsigned int size, const char *location, long expiry_delta_hint)
{
	struct mms_message *msg = NULL;
	char name[128];
	int rc;

	rc = mms_codec_decode_notification(body, body_len, &msg);
	snprintf(name, sizeof(name), "%s: decode_notification succeeds", label);
	CHECK(rc == 0, name);
	if (rc != 0) {
		return;
	}

	snprintf(name, sizeof(name), "%s: type == NOTIFICATION_IND", label);
	CHECK(msg->type == MMS_MESSAGE_TYPE_NOTIFICATION_IND, name);

	snprintf(name, sizeof(name), "%s: transaction_id == \"%s\"", label, transaction_id);
	CHECK(msg->transaction_id && !strcmp(msg->transaction_id, transaction_id), name);

	snprintf(name, sizeof(name), "%s: version == 1.0 (0x90)", label);
	CHECK(msg->version == 0x90, name);

	snprintf(name, sizeof(name), "%s: class == \"%s\"", label, cls);
	CHECK(msg->ni.cls && !strcmp(msg->ni.cls, cls), name);

	snprintf(name, sizeof(name), "%s: size == %u", label, size);
	CHECK(msg->ni.size == size, name);

	snprintf(name, sizeof(name), "%s: location == \"%s\"", label, location);
	CHECK(msg->ni.location && !strcmp(msg->ni.location, location), name);

	if (expiry_delta_hint >= 0) {
		long delta = (long) msg->ni.expiry - (long) time(NULL);

		snprintf(name, sizeof(name), "%s: expiry ~= now + %lds", label, expiry_delta_hint);
		/* Generous +-60s window: this test doesn't race the clock. */
		CHECK(delta > expiry_delta_hint - 60 && delta < expiry_delta_hint + 60, name);
	}

	mms_codec_message_free(msg);
}

int main(void)
{
	const uint8_t *body;
	size_t body_len;
	int rc;

	/* (a) WAP Push M-Notification.ind, with UDH. */
	rc = mms_codec_wap_push_extract(ni_with_udh, sizeof(ni_with_udh), &body, &body_len);
	CHECK(rc == 0, "(a) wap_push_extract succeeds (UDH present)");
	if (rc == 0) {
		check_notification(body, body_len, "(a)", "T1", "Personal", 1024,
			"http://mmsc.example/x1", 3600);
	}

	/* (b) Same push, no UDH. */
	rc = mms_codec_wap_push_extract(ni_no_udh, sizeof(ni_no_udh), &body, &body_len);
	CHECK(rc == 0, "(b) wap_push_extract succeeds (no UDH)");
	if (rc == 0) {
		check_notification(body, body_len, "(b)", "T1", "Personal", 1024,
			"http://mmsc.example/x1", 3600);
	}

	/* (c) SI push must be rejected as not-MMS. */
	rc = mms_codec_wap_push_extract(si_push, sizeof(si_push), &body, &body_len);
	CHECK(rc == -1, "(c) SI push (application/vnd.wap.sic) is rejected");

	/* (d) Garbage must be rejected. */
	rc = mms_codec_wap_push_extract(garbage, sizeof(garbage), &body, &body_len);
	CHECK(rc == -1, "(d) garbage bytes are rejected");

	/* (f) UDH present but naming the wrong port must be rejected. */
	rc = mms_codec_wap_push_extract(wrong_port_udh, sizeof(wrong_port_udh), &body, &body_len);
	CHECK(rc == -1, "(f) UDH naming a non-2948 port is rejected");

	/* (e) M-Retrieve.conf with one text/plain part. */
	{
		struct mms_message *msg = NULL;

		rc = mms_codec_decode_retrieve(retrieve_conf, sizeof(retrieve_conf), &msg);
		CHECK(rc == 0, "(e) decode_retrieve succeeds");
		if (rc == 0) {
			CHECK(msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF, "(e) type == RETRIEVE_CONF");
			CHECK(msg->transaction_id && !strcmp(msg->transaction_id, "R1"),
				"(e) transaction_id == \"R1\"");
			CHECK(msg->rc.from && !strcmp(msg->rc.from, "+15550001111"),
				"(e) from == \"+15550001111\"");
			CHECK(g_slist_length(msg->attachments) == 1, "(e) exactly one attachment");

			if (msg->attachments) {
				struct mms_attachment *a = msg->attachments->data;

				CHECK(a->content_type && !strcmp(a->content_type, "text/plain"),
					"(e) part content-type == \"text/plain\"");
				CHECK(a->content_id && !strcmp(a->content_id, "<hello>"),
					"(e) part content-id == \"<hello>\"");
				CHECK(a->length == 9, "(e) part length == 9");
				CHECK(!memcmp(retrieve_conf + a->offset, "hello mms", 9),
					"(e) part body == \"hello mms\" (via offset into original PDU)");
			}

			mms_codec_message_free(msg);
		}
	}

	/* Upstream mmsd-tng fixture: notification-ind. */
	check_notification(upstream_notify_ind_1, sizeof(upstream_notify_ind_1),
		"(upstream ni_1)", "OgQKKB", "Personal", 16384, "http://eps3.de/O/Z9IZO", -1);

	/* Upstream mmsd-tng fixture: retrieve-conf with one attachment. */
	{
		struct mms_message *msg = NULL;

		rc = mms_codec_decode_retrieve(upstream_retrieve_conf_1,
			sizeof(upstream_retrieve_conf_1), &msg);
		CHECK(rc == 0, "(upstream rc_1) decode_retrieve succeeds");
		if (rc == 0) {
			CHECK(msg->transaction_id && !strcmp(msg->transaction_id, "1201657238"),
				"(upstream rc_1) transaction_id == \"1201657238\"");
			CHECK(msg->rc.from && !strcmp(msg->rc.from, "+49891000/TYPE=PLMN"),
				"(upstream rc_1) from == \"+49891000/TYPE=PLMN\"");
			CHECK(g_slist_length(msg->attachments) == 1, "(upstream rc_1) exactly one attachment");

			if (msg->attachments) {
				struct mms_attachment *a = msg->attachments->data;
				static const char expected_body[] =
					"The quick brown fox jumped over the lazy dog 1234567890/!()";

				CHECK(a->content_type
						&& !strcmp(a->content_type, "text/plain;charset=us-ascii"),
					"(upstream rc_1) part content-type == \"text/plain;charset=us-ascii\"");
				CHECK(a->content_id && !strcmp(a->content_id, "<Text_us-ascii.txt>"),
					"(upstream rc_1) part content-id == \"<Text_us-ascii.txt>\"");
				CHECK(a->length == strlen(expected_body), "(upstream rc_1) part length matches");
				CHECK(!memcmp(upstream_retrieve_conf_1 + a->offset, expected_body,
						strlen(expected_body)),
					"(upstream rc_1) part body matches (via offset into original PDU)");
			}

			mms_codec_message_free(msg);
		}
	}

	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
