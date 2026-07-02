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
 * \brief Minimal AT tty session primitives
 *
 * Deliberately free of Asterisk/GLib dependencies so the host unit tests
 * can exercise the response parser against a pty pair.
 */

#include "at_tty.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

int at_tty_open(const char *path)
{
	struct termios tio;
	int fd;

	fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		return -1;
	}
	if (ioctl(fd, TIOCEXCL)
		|| tcgetattr(fd, &tio)) {
		close(fd);
		return -1;
	}
	cfmakeraw(&tio);
	tio.c_cflag |= CLOCAL | CREAD;
	tio.c_cflag &= ~CRTSCTS;
	cfsetispeed(&tio, B115200);
	cfsetospeed(&tio, B115200);
	if (tcsetattr(fd, TCSANOW, &tio)) {
		close(fd);
		return -1;
	}
	tcflush(fd, TCIOFLUSH);
	return fd;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int at_tty_command(int fd, const char *cmd, int timeout_ms)
{
	char buf[1024];
	size_t used = 0;
	long long deadline = now_ms() + timeout_ms;
	char line[256];
	int len = snprintf(line, sizeof(line), "%s\r", cmd);

	if (len < 0 || (size_t)len >= sizeof(line) || write(fd, line, len) != len) {
		return -2;
	}

	for (;;) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		long long remaining = deadline - now_ms();
		ssize_t n;
		size_t i, start;

		if (remaining <= 0) {
			return -2;
		}
		n = poll(&pfd, 1, (int)remaining);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -2;
		}
		if (n == 0) {
			return -2;
		}

		n = read(fd, buf + used, sizeof(buf) - 1 - used);
		if (n <= 0) {
			return -2;
		}
		used += n;

		/* Scan complete lines; keep any partial tail for the next read */
		start = 0;
		for (i = 0; i < used; i++) {
			if (buf[i] != '\r' && buf[i] != '\n') {
				continue;
			}
			buf[i] = '\0';
			if (buf[start]) {
				const char *l = buf + start;

				if (!strcmp(l, "OK")) {
					return 0;
				}
				if (!strcmp(l, "ERROR")
					|| !strncmp(l, "+CME ERROR", 10)
					|| !strncmp(l, "+CMS ERROR", 10)) {
					return -1;
				}
				/* anything else is an URC or echo: ignore */
			}
			start = i + 1;
		}
		memmove(buf, buf + start, used - start);
		used -= start;
		if (used >= sizeof(buf) - 1) {
			/* one absurdly long partial line: drop it */
			used = 0;
		}
	}
}
