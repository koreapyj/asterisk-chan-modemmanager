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
 * \brief MMS HTTP transfer over libcurl (pure libc, unit-testable).
 *
 * Carrier MMSC access is plain HTTP/1.1, frequently through a forward
 * proxy, sometimes bound to a specific netdev (the MMS APN bearer).
 * Free of Asterisk/GLib types so host tests can exercise it against a
 * local stub server.
 */

#ifndef CHAN_MM_MMS_FETCH_H
#define CHAN_MM_MMS_FETCH_H

#include <stddef.h>
#include <stdint.h>

struct mms_fetch_params {
	const char *url;
	/*! Forward proxy "host:port", NULL = direct */
	const char *proxy;
	/*! Bind to this netdev/IP (CURLOPT_INTERFACE), NULL = default route */
	const char *interface;
	/*! NULL = libcurl default */
	const char *user_agent;
	/*! Non-NULL turns the transfer into a POST of this body */
	const uint8_t *post_data;
	size_t post_len;
	/*! Whole-transfer timeout in seconds */
	unsigned int timeout_s;
	/*! Response size cap, enforced mid-stream (Content-Length is not trusted) */
	size_t max_size;
};

/*!
 * \brief One HTTP transfer to the MMSC.
 *
 * Follows at most 3 redirects; only HTTP 200 counts as success. The
 * response body is returned in *out (malloc'd; release with free() — in
 * Asterisk TUs that is ast_std_free()).
 *
 * \retval 0 success
 * \retval -1 failure (err describes it); *out untouched
 */
int mms_http_fetch(const struct mms_fetch_params *p, uint8_t **out, size_t *out_len,
	char *err, size_t err_len);

#endif /* CHAN_MM_MMS_FETCH_H */
