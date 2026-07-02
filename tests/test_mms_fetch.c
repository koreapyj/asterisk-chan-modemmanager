/*
 * Integration test for the MMS HTTP fetch layer against a local one-shot
 * HTTP stub standing in for a carrier MMSC. No Asterisk, no carrier, no
 * network beyond 127.0.0.1. Run with `make check`.
 */

#define _GNU_SOURCE
#include "../src/mms/mms_fetch.h"
#include "../src/mms/mms_codec.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, name) do { \
	if (cond) { \
		printf("ok   %s\n", name); \
	} else { \
		printf("FAIL %s\n", name); \
		failures++; \
	} \
} while (0)

/* Same minimal m-retrieve.conf as tests/test_mms_codec.c (see the
 * byte-by-byte commentary there): txn "R1", From +15550001111, one
 * text/plain part "hello mms". */
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

struct stub {
	int listen_fd;
	int status;          /* HTTP status to answer */
	const uint8_t *body;
	size_t body_len;
	size_t claim_len;    /* Content-Length header value (may lie) */
	char last_request[512];
};

static void *stub_fn(void *data)
{
	struct stub *s = data;
	int fd = accept(s->listen_fd, NULL, NULL);
	char buf[2048];
	ssize_t n;
	char hdr[256];

	if (fd < 0) {
		return NULL;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		snprintf(s->last_request, sizeof(s->last_request), "%s", buf);
	}
	snprintf(hdr, sizeof(hdr),
		"HTTP/1.1 %d X\r\n"
		"Content-Type: application/vnd.wap.mms-message\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n\r\n",
		s->status, s->claim_len);
	(void)!write(fd, hdr, strlen(hdr));
	if (s->body) {
		(void)!write(fd, s->body, s->body_len);
	}
	close(fd);
	return NULL;
}

static int stub_start(struct stub *s, pthread_t *th, char *url, size_t url_len)
{
	struct sockaddr_in addr = { .sin_family = AF_INET };
	socklen_t alen = sizeof(addr);

	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (s->listen_fd < 0
		|| bind(s->listen_fd, (struct sockaddr *)&addr, sizeof(addr))
		|| listen(s->listen_fd, 1)
		|| getsockname(s->listen_fd, (struct sockaddr *)&addr, &alen)) {
		return -1;
	}
	snprintf(url, url_len, "http://127.0.0.1:%d/mms/x1", ntohs(addr.sin_port));
	return pthread_create(th, NULL, stub_fn, s);
}

int main(void)
{
	char url[64];
	char err[256];
	uint8_t *out = NULL;
	size_t out_len = 0;
	pthread_t th;

	/* happy path: fetch + decode roundtrip */
	{
		struct stub s = {
			.status = 200,
			.body = retrieve_conf,
			.body_len = sizeof(retrieve_conf),
			.claim_len = sizeof(retrieve_conf),
		};
		struct mms_fetch_params p = {
			.timeout_s = 5, .max_size = 65536,
			.user_agent = "chan_modemmanager-test",
		};
		struct mms_message *msg = NULL;

		if (stub_start(&s, &th, url, sizeof(url))) {
			perror("stub");
			return 1;
		}
		p.url = url;
		CHECK(!mms_http_fetch(&p, &out, &out_len, err, sizeof(err)),
			"fetch succeeds against stub MMSC");
		pthread_join(th, NULL);
		close(s.listen_fd);
		CHECK(out_len == sizeof(retrieve_conf)
			&& !memcmp(out, retrieve_conf, out_len),
			"body received byte-exact");
		CHECK(strstr(s.last_request, "GET /mms/x1") != NULL,
			"request line is a GET for the content location");
		CHECK(strstr(s.last_request, "application/vnd.wap.mms-message") != NULL,
			"Accept header sent");
		CHECK(!mms_codec_decode_retrieve(out, out_len, &msg) && msg,
			"fetched body decodes as m-retrieve.conf");
		if (msg) {
			mms_codec_message_free(msg);
		}
		free(out);
		out = NULL;
	}

	/* size cap enforced mid-stream inside the write callback (the header
	 * is not what stops it: curl is given no reason to abort early) */
	{
		static uint8_t big[4096];
		struct stub s = {
			.status = 200,
			.body = big, .body_len = sizeof(big),
			.claim_len = sizeof(big),
		};
		struct mms_fetch_params p = { .timeout_s = 5, .max_size = 1024 };

		if (stub_start(&s, &th, url, sizeof(url))) {
			return 1;
		}
		p.url = url;
		CHECK(mms_http_fetch(&p, &out, &out_len, err, sizeof(err)) == -1
			&& strstr(err, "exceeds"),
			"oversized body aborted by the write-callback cap");
		pthread_join(th, NULL);
		close(s.listen_fd);
	}

	/* non-200 is a failure even with a plausible body */
	{
		struct stub s = {
			.status = 404,
			.body = retrieve_conf,
			.body_len = sizeof(retrieve_conf),
			.claim_len = sizeof(retrieve_conf),
		};
		struct mms_fetch_params p = { .timeout_s = 5, .max_size = 65536 };

		if (stub_start(&s, &th, url, sizeof(url))) {
			return 1;
		}
		p.url = url;
		CHECK(mms_http_fetch(&p, &out, &out_len, err, sizeof(err)) == -1
			&& strstr(err, "404"),
			"HTTP 404 reported as failure");
		pthread_join(th, NULL);
		close(s.listen_fd);
	}

	/* POST path used by the NotifyResp ack */
	{
		static const uint8_t ack[] = { 0x8C, 0x83, 0x98, 'R', '1', 0x00,
			0x8D, 0x90, 0x95, 0x81 };
		struct stub s = { .status = 200, .claim_len = 0 };
		struct mms_fetch_params p = {
			.timeout_s = 5, .max_size = 1024,
			.post_data = ack, .post_len = sizeof(ack),
		};

		if (stub_start(&s, &th, url, sizeof(url))) {
			return 1;
		}
		p.url = url;
		CHECK(!mms_http_fetch(&p, &out, &out_len, err, sizeof(err)),
			"ack POST succeeds");
		pthread_join(th, NULL);
		close(s.listen_fd);
		CHECK(strstr(s.last_request, "POST /mms/x1") != NULL
			&& strstr(s.last_request, "Content-Type: application/vnd.wap.mms-message") != NULL,
			"ack is a POST with the MMS content type");
		free(out);
	}

	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
