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
 * \brief Minimal AT tty session primitives (pure libc, unit-testable).
 */

#ifndef CHAN_MM_AT_TTY_H
#define CHAN_MM_AT_TTY_H

/*!
 * \brief Open a tty for a short AT session: raw mode, no flow control,
 * TIOCEXCL so nothing else interleaves while we own it.
 * \return fd or -1 (errno set) — EBUSY means someone holds it exclusively
 */
int at_tty_open(const char *path);

/*!
 * \brief Send one AT command and wait for a final result code.
 *
 * Unsolicited lines arriving in between are ignored; only OK / ERROR /
 * +CME ERROR / +CMS ERROR terminate. Partial lines split across reads
 * are handled.
 *
 * \retval 0 command answered OK
 * \retval -1 ERROR/+CME/+CMS result
 * \retval -2 timeout or I/O error
 */
int at_tty_command(int fd, const char *cmd, int timeout_ms);

#endif /* CHAN_MM_AT_TTY_H */
