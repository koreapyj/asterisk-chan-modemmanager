/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "mms_fetch.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fetch_buf {
	uint8_t *data;
	size_t len;
	size_t max;
	int overflowed;
};

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct fetch_buf *buf = userdata;
	size_t n = size * nmemb;

	/* The cap is enforced here, mid-stream: carriers lie about
	 * Content-Length. Returning a short count aborts the transfer. */
	if (buf->len + n > buf->max) {
		buf->overflowed = 1;
		return 0;
	}
	{
		uint8_t *grown = realloc(buf->data, buf->len + n);

		if (!grown) {
			return 0;
		}
		buf->data = grown;
	}
	memcpy(buf->data + buf->len, ptr, n);
	buf->len += n;
	return n;
}

int mms_http_fetch(const struct mms_fetch_params *p, uint8_t **out, size_t *out_len,
	char *err, size_t err_len)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	struct fetch_buf buf = { .max = p->max_size };
	char curl_err[CURL_ERROR_SIZE] = "";
	long status = 0;
	int ret = -1;

	curl = curl_easy_init();
	if (!curl) {
		snprintf(err, err_len, "curl_easy_init failed");
		return -1;
	}

	headers = curl_slist_append(headers,
		"Accept: application/vnd.wap.mms-message, */*");
	if (p->post_data) {
		headers = curl_slist_append(headers,
			"Content-Type: application/vnd.wap.mms-message");
	}

	curl_easy_setopt(curl, CURLOPT_URL, p->url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)p->timeout_s);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	if (p->proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, p->proxy);
	}
	if (p->interface) {
		curl_easy_setopt(curl, CURLOPT_INTERFACE, p->interface);
	}
	if (p->user_agent) {
		curl_easy_setopt(curl, CURLOPT_USERAGENT, p->user_agent);
	}
	if (p->post_data) {
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)p->post_data);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)p->post_len);
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		if (buf.overflowed) {
			snprintf(err, err_len, "response exceeds %zu bytes", p->max_size);
		} else {
			snprintf(err, err_len, "%s", curl_err[0] ? curl_err : curl_easy_strerror(res));
		}
		goto done;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	if (status != 200) {
		snprintf(err, err_len, "HTTP %ld", status);
		goto done;
	}

	*out = buf.data;
	*out_len = buf.len;
	buf.data = NULL;
	ret = 0;

done:
	free(buf.data);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return ret;
}
