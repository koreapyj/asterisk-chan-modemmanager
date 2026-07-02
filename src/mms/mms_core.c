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

#include <curl/curl.h>

#include "asterisk/logger.h"
#include "asterisk/strings.h"
#include "asterisk/taskprocessor.h"
#include "asterisk/utils.h"

#include "mms.h"
#include "mms_codec.h"
#include "mms_deliver.h"
#include "mms_fetch.h"
#include "vendor/mmsutil.h"

/*! Retry backoff per attempt (seconds); the last value repeats */
static const int backoff_s[] = { 30, 120, 600 };

enum txn_state {
	TXN_WAITING = 0,
	TXN_FETCHING,
};

/*!
 * \brief One tracked MMS notification, keyed (sim, transaction id).
 *
 * Everything needed for the fetch is copied out of the decoded
 * notification at intake, so no PDU buffers are retained.
 */
struct mms_txn {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(key);           /* "<sim>|<txn id>" */
		AST_STRING_FIELD(txn_id);
		AST_STRING_FIELD(location);      /* X-Mms-Content-Location */
		AST_STRING_FIELD(from_fallback); /* carrying SMS sender */
		AST_STRING_FIELD(sms_path);      /* MM D-Bus path of the SMS */
	);
	sim_pvt_t *sim;                      /* owned ref */
	enum txn_state state;
	int attempts;
	int decode_failures;
	time_t next_attempt;
	time_t expiry;                       /* 0 = none */
};

static struct ao2_container *txns;
static pthread_t worker_thread = AST_PTHREADT_NULL;
static ast_mutex_t worker_lock;
static ast_cond_t worker_cond;
static int worker_stop;

static void txn_destructor(void *obj)
{
	struct mms_txn *txn = obj;

	unref_sim(txn->sim);
	ast_string_field_free_memory(txn);
}

static int txn_hash_cb(const void *obj, const int flags)
{
	const char *key = (flags & OBJ_SEARCH_KEY)
		? obj : ((const struct mms_txn *)obj)->key;

	return ast_str_hash(key);
}

static int txn_cmp_cb(void *obj, void *arg, int flags)
{
	const struct mms_txn *txn = obj;
	const char *key = (flags & OBJ_SEARCH_KEY)
		? arg : ((const struct mms_txn *)arg)->key;

	return strcmp(txn->key, key) ? 0 : CMP_MATCH | CMP_STOP;
}

/* --- SMS deletion, back on the owning modem's serializer --- */

struct del_sms_task {
	sim_pvt_t *sim;
	char *path;
};

static int task_delete_sms(void *data)
{
	struct del_sms_task *t = data;
	modem_pvt_t *modem = sim_grab_modem(t->sim);
	MMModemMessaging *messaging = NULL;
	GError *error = NULL;

	if (modem) {
		modemmanager_pvt_lock(modem);
		if (modem->messaging) {
			messaging = g_object_ref(modem->messaging);
		}
		modemmanager_pvt_unlock(modem);
		unref_modem(modem);
	}
	if (messaging) {
		mm_modem_messaging_delete_sync(messaging, t->path, NULL, &error);
		if (error) {
			ast_log(LOG_WARNING, "[MMS sim=%s] failed to delete notification "
				"SMS %s - (%d) %s\n", t->sim->identifier, t->path,
				error->code, error->message);
			g_clear_error(&error);
		}
		g_object_unref(messaging);
	}
	unref_sim(t->sim);
	ast_free(t->path);
	ast_free(t);
	return 0;
}

static void delete_notification_sms(struct mms_txn *txn)
{
	modem_pvt_t *modem;
	struct del_sms_task *t;

	if (ast_strlen_zero(txn->sms_path)) {
		return;
	}
	modem = sim_grab_modem(txn->sim);
	if (!modem) {
		return;
	}
	if (!modem->serializer) {
		unref_modem(modem);
		return;
	}
	t = ast_calloc(1, sizeof(*t));
	if (!t) {
		unref_modem(modem);
		return;
	}
	t->sim = ref_sim(txn->sim);
	t->path = ast_strdup(txn->sms_path);
	if (ast_taskprocessor_push(modem->serializer, task_delete_sms, t)) {
		unref_sim(t->sim);
		ast_free(t->path);
		ast_free(t);
	}
	unref_modem(modem);
}

/* --- M-NotifyResp.ind acknowledgment --- */

/*!
 * \brief Hand-encode a minimal M-NotifyResp.ind (WAP-209 §6.2).
 *
 * Header codes are the WAP-209 assigned numbers | 0x80:
 * 0x8C message-type (m-notifyresp-ind = 131), 0x98 transaction id
 * (text-string), 0x8D MMS version (1.0), 0x95 status (retrieved = 129).
 */
static size_t encode_notifyresp(uint8_t *out, size_t out_len, const char *txn_id)
{
	size_t txn_len = strlen(txn_id);
	size_t need = 2 + 1 + txn_len + 1 + 2 + 2;
	size_t pos = 0;

	if (need > out_len) {
		return 0;
	}
	out[pos++] = 0x8C;
	out[pos++] = MMS_MESSAGE_TYPE_NOTIFYRESP_IND;
	out[pos++] = 0x98;
	memcpy(out + pos, txn_id, txn_len);
	pos += txn_len;
	out[pos++] = 0x00;
	out[pos++] = 0x8D;
	out[pos++] = 0x90;	/* version 1.0 */
	out[pos++] = 0x95;
	out[pos++] = 0x81;	/* retrieved */
	return pos;
}

/* --- worker --- */

/*! \brief Per-SIM fetch settings snapshotted under the sim lock */
struct sim_mms_cfg {
	char *mmsc;
	char *proxy;
	char *interface;
	char *user_agent;
	char *spool;
	unsigned int max_size;
	unsigned int timeout_s;
	unsigned int max_retries;
	unsigned int ack;
};

static void cfg_free(struct sim_mms_cfg *cfg)
{
	ast_free(cfg->mmsc);
	ast_free(cfg->proxy);
	ast_free(cfg->interface);
	ast_free(cfg->user_agent);
	ast_free(cfg->spool);
}

static void cfg_snapshot(sim_pvt_t *sim, struct sim_mms_cfg *cfg)
{
	modemmanager_pvt_lock(sim);
	cfg->mmsc = ast_strdup(sim->mmsc);
	cfg->proxy = ast_strlen_zero(sim->mms_proxy) ? NULL : ast_strdup(sim->mms_proxy);
	cfg->interface = ast_strlen_zero(sim->mms_interface) ? NULL : ast_strdup(sim->mms_interface);
	cfg->user_agent = ast_strlen_zero(sim->mms_user_agent) ? NULL : ast_strdup(sim->mms_user_agent);
	cfg->spool = ast_strdup(sim->mms_spool);
	cfg->max_size = sim->mms_max_size;
	cfg->timeout_s = sim->mms_fetch_timeout;
	cfg->max_retries = sim->mms_max_retries;
	cfg->ack = sim->mms_ack;
	modemmanager_pvt_unlock(sim);
}

static void txn_finish(struct mms_txn *txn, int delete_sms)
{
	if (delete_sms) {
		delete_notification_sms(txn);
	}
	ao2_unlink(txns, txn);
}

static void txn_retry(struct mms_txn *txn, unsigned int max_retries, const char *why)
{
	txn->attempts++;
	if ((unsigned int)txn->attempts >= max_retries) {
		ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] giving up after %d attempts (%s)\n",
			txn->sim->identifier, txn->txn_id, txn->attempts, why);
		txn_finish(txn, 1);
		return;
	}
	{
		int idx = txn->attempts - 1;

		if (idx >= (int)ARRAY_LEN(backoff_s)) {
			idx = ARRAY_LEN(backoff_s) - 1;
		}
		txn->next_attempt = time(NULL) + backoff_s[idx];
	}
	txn->state = TXN_WAITING;
	ast_debug(1, "[MMS sim=%s txn=%s] retrying in %lds (%s)\n",
		txn->sim->identifier, txn->txn_id,
		(long)(txn->next_attempt - time(NULL)), why);
}

/*! \brief Fetch, decode, deliver, ack — runs on the MMS worker thread. */
static void process_txn(struct mms_txn *txn)
{
	struct sim_mms_cfg cfg = { 0 };
	struct mms_fetch_params params = { 0 };
	struct mms_message *msg = NULL;
	char url[1024];
	char err[256];
	uint8_t *body = NULL;
	size_t body_len = 0;

	cfg_snapshot(txn->sim, &cfg);

	if (ast_strlen_zero(cfg.mmsc)) {
		/* mmsc removed on reload: drop but keep the SMS on the modem */
		txn_finish(txn, 0);
		goto done;
	}

	if (txn->expiry && time(NULL) > txn->expiry) {
		ast_log(LOG_NOTICE, "[MMS sim=%s txn=%s] expired before retrieval\n",
			txn->sim->identifier, txn->txn_id);
		txn_finish(txn, 1);
		goto done;
	}

	/* Some carriers send a bare path instead of an absolute URL. An
	 * absolute path ("/x/y") resolves against the MMSC's ORIGIN
	 * (scheme://host[:port]) — appending it to an MMSC URL that itself
	 * has a path component would produce a bogus URL — while a relative
	 * path is appended to the full MMSC base. */
	if (ast_begins_with(txn->location, "http://")
		|| ast_begins_with(txn->location, "https://")) {
		ast_copy_string(url, txn->location, sizeof(url));
	} else if (txn->location[0] == '/') {
		const char *authority = strstr(cfg.mmsc, "://");
		const char *path = authority ? strchr(authority + 3, '/') : NULL;
		size_t origin_len = path ? (size_t)(path - cfg.mmsc) : strlen(cfg.mmsc);

		snprintf(url, sizeof(url), "%.*s%s", (int)origin_len, cfg.mmsc,
			txn->location);
	} else {
		snprintf(url, sizeof(url), "%s%s%s", cfg.mmsc,
			ast_ends_with(cfg.mmsc, "/") ? "" : "/", txn->location);
	}

	params.url = url;
	params.proxy = cfg.proxy;
	params.interface = cfg.interface;
	params.user_agent = cfg.user_agent;
	params.timeout_s = cfg.timeout_s;
	params.max_size = cfg.max_size;

	if (mms_http_fetch(&params, &body, &body_len, err, sizeof(err))) {
		ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] fetch failed: %s\n",
			txn->sim->identifier, txn->txn_id, err);
		txn_retry(txn, cfg.max_retries, "fetch failed");
		goto done;
	}

	if (mms_codec_decode_retrieve(body, body_len, &msg)) {
		/* Carriers wrap error PDUs in HTTP 200; a wrong PDU will not fix
		 * itself indefinitely — one retry, then give up. */
		txn->decode_failures++;
		ast_log(LOG_WARNING, "[MMS sim=%s txn=%s] fetched body is not a valid "
			"m-retrieve.conf (%zu bytes, starts %02x %02x)\n",
			txn->sim->identifier, txn->txn_id, body_len,
			body_len > 0 ? body[0] : 0, body_len > 1 ? body[1] : 0);
		if (txn->decode_failures >= 2) {
			txn_finish(txn, 1);
		} else {
			txn_retry(txn, cfg.max_retries, "decode failed");
		}
		goto done;
	}

	mms_deliver(txn->sim, msg, body, body_len, txn->txn_id,
		txn->from_fallback, cfg.spool);

	if (cfg.ack) {
		uint8_t resp[512];
		size_t resp_len = encode_notifyresp(resp, sizeof(resp), txn->txn_id);
		uint8_t *ack_body = NULL;
		size_t ack_len = 0;

		if (resp_len) {
			struct mms_fetch_params ack_params = params;

			ack_params.url = cfg.mmsc;
			ack_params.post_data = resp;
			ack_params.post_len = resp_len;
			if (mms_http_fetch(&ack_params, &ack_body, &ack_len, err, sizeof(err))) {
				ast_debug(1, "[MMS sim=%s txn=%s] NotifyResp ack failed: %s\n",
					txn->sim->identifier, txn->txn_id, err);
			} else {
				ast_std_free(ack_body);
			}
		}
	}

	txn_finish(txn, 1);

done:
	if (msg) {
		mms_codec_message_free(msg);
	}
	ast_std_free(body);
	cfg_free(&cfg);
}

/*!
 * \brief Pick the next due txn (+1 ref) or report the earliest wakeup.
 */
static struct mms_txn *pick_due(time_t *wakeup)
{
	struct ao2_iterator it;
	struct mms_txn *txn, *due = NULL;
	time_t now = time(NULL);

	*wakeup = 0;
	it = ao2_iterator_init(txns, 0);
	while ((txn = ao2_iterator_next(&it))) {
		if (txn->state != TXN_WAITING) {
			ao2_ref(txn, -1);
			continue;
		}
		if (txn->next_attempt <= now) {
			due = txn;
			break;
		}
		if (!*wakeup || txn->next_attempt < *wakeup) {
			*wakeup = txn->next_attempt;
		}
		ao2_ref(txn, -1);
	}
	ao2_iterator_destroy(&it);
	return due;
}

static void *mms_worker(void *unused)
{
	ast_mutex_lock(&worker_lock);
	while (!worker_stop) {
		time_t wakeup = 0;
		struct mms_txn *due = pick_due(&wakeup);

		if (!due) {
			if (wakeup) {
				struct timespec ts = { .tv_sec = wakeup };

				ast_cond_timedwait(&worker_cond, &worker_lock, &ts);
			} else {
				ast_cond_wait(&worker_cond, &worker_lock);
			}
			continue;
		}
		due->state = TXN_FETCHING;
		ast_mutex_unlock(&worker_lock);

		process_txn(due);
		ao2_ref(due, -1);

		ast_mutex_lock(&worker_lock);
	}
	ast_mutex_unlock(&worker_lock);
	return NULL;
}

/* --- intake --- */

void mms_on_wap_push_sms(sim_pvt_t *sim, const guint8 *data, gsize len,
	const char *orig_number, const char *sms_path)
{
	const uint8_t *ni_pdu;
	size_t ni_len;
	struct mms_message *ni = NULL;
	struct mms_txn *txn;
	char key[512];

	if (!txns) {
		return;
	}

	if (mms_codec_wap_push_extract(data, len, &ni_pdu, &ni_len)) {
		ast_debug(1, "Binary SMS on sim %s is not an MMS WAP push; ignoring\n",
			sim->identifier);
		return;
	}

	if (ast_strlen_zero(sim->mmsc)) {
		modemmanager_pvt_lock(sim);
		if (!sim->mms_warned) {
			sim->mms_warned = 1;
			modemmanager_pvt_unlock(sim);
			ast_log(LOG_NOTICE, "MMS notification received on sim '%s' but no "
				"mmsc is configured; leaving it on the modem\n", sim->identifier);
		} else {
			modemmanager_pvt_unlock(sim);
		}
		return;
	}

	if (mms_codec_decode_notification(ni_pdu, ni_len, &ni)) {
		ast_log(LOG_WARNING, "Failed to decode MMS notification on sim '%s'\n",
			sim->identifier);
		return;
	}
	if (ast_strlen_zero(ni->transaction_id) || ast_strlen_zero(ni->ni.location)) {
		ast_log(LOG_WARNING, "MMS notification on sim '%s' lacks transaction id "
			"or content location\n", sim->identifier);
		goto done;
	}

	snprintf(key, sizeof(key), "%s|%s", sim->identifier, ni->transaction_id);
	txn = ao2_find(txns, key, OBJ_SEARCH_KEY);
	if (txn) {
		ast_debug(1, "[MMS sim=%s txn=%s] duplicate notification dropped\n",
			sim->identifier, ni->transaction_id);
		ao2_ref(txn, -1);
		goto done;
	}

	txn = ao2_alloc(sizeof(*txn), txn_destructor);
	if (!txn || ast_string_field_init(txn, 128)) {
		ao2_cleanup(txn);
		goto done;
	}
	ast_string_field_set(txn, key, key);
	ast_string_field_set(txn, txn_id, ni->transaction_id);
	ast_string_field_set(txn, location, ni->ni.location);
	ast_string_field_set(txn, from_fallback, S_OR(orig_number, ""));
	ast_string_field_set(txn, sms_path, S_OR(sms_path, ""));
	txn->sim = ref_sim(sim);
	txn->expiry = ni->ni.expiry;
	txn->next_attempt = time(NULL);
	txn->state = TXN_WAITING;

	ao2_link(txns, txn);
	ao2_ref(txn, -1);

	ast_verb(2, "[MMS sim=%s txn=%s] notification queued (from %s, %u bytes at MMSC)\n",
		sim->identifier, ni->transaction_id, S_OR(orig_number, "?"), ni->ni.size);

	ast_mutex_lock(&worker_lock);
	ast_cond_signal(&worker_cond);
	ast_mutex_unlock(&worker_lock);

done:
	mms_codec_message_free(ni);
}

/* --- lifecycle --- */

int mms_init(void)
{
	txns = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, 17,
		txn_hash_cb, NULL, txn_cmp_cb);
	if (!txns) {
		return -1;
	}
	curl_global_init(CURL_GLOBAL_DEFAULT);
	ast_mutex_init(&worker_lock);
	ast_cond_init(&worker_cond, NULL);
	worker_stop = 0;
	if (ast_pthread_create_background(&worker_thread, NULL, mms_worker, NULL)) {
		ast_log(LOG_ERROR, "Failed to create MMS worker thread\n");
		ao2_ref(txns, -1);
		txns = NULL;
		curl_global_cleanup();
		return -1;
	}
	return 0;
}

void mms_shutdown(void)
{
	if (!txns) {
		return;
	}
	ast_mutex_lock(&worker_lock);
	worker_stop = 1;
	ast_cond_signal(&worker_cond);
	ast_mutex_unlock(&worker_lock);
	if (worker_thread != AST_PTHREADT_NULL) {
		pthread_join(worker_thread, NULL);
		worker_thread = AST_PTHREADT_NULL;
	}
	ao2_ref(txns, -1);
	txns = NULL;
	ast_cond_destroy(&worker_cond);
	ast_mutex_destroy(&worker_lock);
	curl_global_cleanup();
}
