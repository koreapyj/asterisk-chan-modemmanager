/*
 * Unit tests for the AT tty session primitives, run against a pty pair
 * with a scripted responder thread. Run with `make check`.
 */

#define _GNU_SOURCE
#include "../src/at_tty.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

struct responder {
	int fd;              /* pty master */
	const char *expect;  /* command to wait for */
	const char *reply;   /* raw bytes to send back */
};

static void *responder_fn(void *data)
{
	struct responder *r = data;
	char buf[256];
	size_t used = 0;

	for (;;) {
		ssize_t n = read(r->fd, buf + used, sizeof(buf) - 1 - used);

		if (n <= 0) {
			return NULL;
		}
		used += n;
		buf[used] = '\0';
		if (strstr(buf, r->expect)) {
			break;
		}
	}
	if (r->reply) {
		(void)!write(r->fd, r->reply, strlen(r->reply));
	}
	return NULL;
}

/*! Each case gets a fresh pty pair so exclusive-mode and EOF state from a
 * previous case cannot leak into the next one. */
static int run_case(const char *cmd, const char *expect, const char *reply, int timeout_ms)
{
	struct responder r = { .expect = expect, .reply = reply };
	pthread_t th;
	int master, fd, res;
	char *slave;

	master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0 || grantpt(master) || unlockpt(master) || !(slave = ptsname(master))) {
		perror("pty");
		return -99;
	}
	r.fd = master;

	pthread_create(&th, NULL, responder_fn, &r);
	fd = at_tty_open(slave);
	if (fd < 0) {
		pthread_cancel(th);
		pthread_join(th, NULL);
		close(master);
		return -99;
	}
	res = at_tty_command(fd, cmd, timeout_ms);
	close(fd);
	close(master);
	pthread_join(th, NULL);
	return res;
}

int main(void)
{
	CHECK(run_case("AT", "AT\r", "\r\nOK\r\n", 2000) == 0,
		"plain OK");
	CHECK(run_case("AT+QPCMV=1,2", "AT+QPCMV", "\r\nERROR\r\n", 2000) == -1,
		"ERROR result");
	CHECK(run_case("AT+FOO", "AT+FOO", "\r\n+CME ERROR: 100\r\n", 2000) == -1,
		"+CME ERROR result");
	CHECK(run_case("AT+BAR", "AT+BAR",
		"\r\n+QIND: \"csq\",20,99\r\nsome noise\r\nOK\r\n", 2000) == 0,
		"URC lines before OK are ignored");
	CHECK(run_case("AT+SPLIT", "AT+SPLIT", "\r\nO", 500) == -2,
		"partial line then silence times out (no false OK)");
	CHECK(run_case("AT+NOREPLY", "AT+NOREPLY", NULL, 300) == -2,
		"timeout with no response");

	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
