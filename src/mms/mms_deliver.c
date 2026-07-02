/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "../mm_glue.h"

#include <sys/stat.h>

#include "asterisk/logger.h"
#include "asterisk/message.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"

#include "mms_deliver.h"
#include "vendor/mmsutil.h"

/*! \brief Keep [A-Za-z0-9._-]; everything else becomes '_' */
static void sanitize(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	for (i = 0; src && src[i] && i < dst_len - 1; i++) {
		char c = src[i];

		dst[i] = (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-')
			? c : '_';
	}
	dst[i] = '\0';
	if (!dst[0]) {
		ast_copy_string(dst, "part", dst_len);
	}
}

/*!
 * \brief From addresses arrive as "num/TYPE=PLMN" or an insert-address
 * token; reduce to a plain number or fall back to the carrying SMS sender.
 */
static void pick_from(char *dst, size_t dst_len, const char *rc_from, const char *fallback)
{
	char *slash;

	if (ast_strlen_zero(rc_from) || strcasestr(rc_from, "insert-address")) {
		ast_copy_string(dst, S_OR(fallback, ""), dst_len);
		return;
	}
	ast_copy_string(dst, rc_from, dst_len);
	slash = strchr(dst, '/');
	if (slash) {
		*slash = '\0';
	}
}

void mms_deliver(sim_pvt_t *sim, struct mms_message *msg,
	const uint8_t *pdu, size_t pdu_len,
	const char *txn_id, const char *from_fallback, const char *spool)
{
	struct ast_str *body = ast_str_create(1024);
	struct ast_msg *amsg = NULL;
	char from[128];
	char txn_safe[64];
	GSList *l;
	int attachment_count = 0;
	int res = 0;

	if (!body) {
		return;
	}

	sanitize(txn_safe, sizeof(txn_safe), txn_id);
	pick_from(from, sizeof(from), msg->rc.from, from_fallback);

	amsg = ast_msg_alloc();
	if (!amsg) {
		ast_free(body);
		return;
	}

	for (l = msg->attachments; l; l = g_slist_next(l)) {
		struct mms_attachment *part = l->data;

		if (!part || part->offset + part->length > pdu_len) {
			continue;
		}
		if (part->content_type && ast_begins_with(part->content_type, "application/smil")) {
			continue;
		}
		if (part->content_type && ast_begins_with(part->content_type, "text/plain")) {
			if (ast_str_strlen(body)) {
				ast_str_append(&body, 0, "\n\n");
			}
			ast_str_append_substr(&body, 0,
				(const char *)pdu + part->offset, part->length);
			continue;
		}

		/* Binary attachment: spool to disk, reference via message vars */
		{
			char dir[PATH_MAX - 256];
			char file[PATH_MAX];
			char name_safe[128];
			char var[32];
			FILE *fp;

			if ((size_t)snprintf(dir, sizeof(dir), "%s/%s", spool, txn_safe) >= sizeof(dir)) {
				ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] spool path too long\n",
					sim->identifier, txn_id);
				continue;
			}
			if (ast_mkdir(dir, 0755)) {
				ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] cannot create spool dir %s: %s\n",
					sim->identifier, txn_id, dir, strerror(errno));
				continue;
			}
			sanitize(name_safe, sizeof(name_safe), part->content_id);
			snprintf(file, sizeof(file), "%s/%d-%s.bin", dir,
				attachment_count, name_safe);
			fp = fopen(file, "wx");
			if (!fp && errno == EEXIST) {
				fp = fopen(file, "w");
			}
			if (!fp) {
				ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] cannot write %s: %s\n",
					sim->identifier, txn_id, file, strerror(errno));
				continue;
			}
			if (fwrite(pdu + part->offset, 1, part->length, fp) != part->length) {
				ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] short write to %s\n",
					sim->identifier, txn_id, file);
			}
			fclose(fp);

			attachment_count++;
			snprintf(var, sizeof(var), "MMS_ATTACHMENT_FILE_%d", attachment_count);
			res |= ast_msg_set_var(amsg, var, file);
			snprintf(var, sizeof(var), "MMS_ATTACHMENT_TYPE_%d", attachment_count);
			res |= ast_msg_set_var(amsg, var, S_OR(part->content_type, "application/octet-stream"));
		}
	}

	{
		char count_str[12];

		snprintf(count_str, sizeof(count_str), "%d", attachment_count);
		res |= ast_msg_set_var(amsg, "MMS_ATTACHMENT_COUNT", count_str);
	}
	res |= ast_msg_set_var(amsg, "MMS_TRANSACTION_ID", txn_id);
	if (!ast_strlen_zero(msg->rc.subject)) {
		res |= ast_msg_set_var(amsg, "MMS_SUBJECT", msg->rc.subject);
	}

	res |= ast_msg_set_context(amsg, "%s", S_OR(sim->mms_context,
		S_OR(sim->message_context, sim->context)));
	res |= ast_msg_set_exten(amsg, "%s", S_OR(sim->exten, ""));
	res |= ast_msg_set_to(amsg, "%s", S_OR(sim->exten, ""));
	res |= ast_msg_set_from(amsg, "%s", from);
	res |= ast_msg_set_body(amsg, "%s", ast_str_strlen(body)
		? ast_str_buffer(body) : "[MMS attachment]");
	res |= ast_msg_set_tech(amsg, "%s", "ModemManager");
	res |= ast_msg_set_endpoint(amsg, "%s", sim->identifier);
	ast_free(body);

	if (res) {
		ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] failed to build message\n",
			sim->identifier, txn_id);
		ast_msg_destroy(amsg);
		return;
	}

	if (!ast_msg_has_destination(amsg)) {
		ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] no dialplan handler wanted the "
			"message (context '%s', exten '%s')\n", sim->identifier, txn_id,
			S_OR(sim->mms_context, S_OR(sim->message_context, sim->context)),
			S_OR(sim->exten, ""));
		ast_msg_destroy(amsg);
		return;
	}

	ast_msg_queue(amsg);
	ast_verb(2, "[MMS sim=%s txn=%s] delivered (%d attachment(s))\n",
		sim->identifier, txn_id, attachment_count);
}
