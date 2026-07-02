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
 * \brief Per-modem init AT commands over a spare AT tty port.
 *
 * Scope: this is the bring-up step of the audio side-channel the driver
 * owns (like the sysfs ALSA autodetect) — meant for commands that enable
 * functions the driver consumes, e.g. Quectel AT+QPCMV=1,2 to route
 * voice PCM over the USB audio function. It is not a general modem
 * provisioning interface; ModemManager keeps ownership of call/SMS
 * signaling.
 *
 * ModemManager's Command() D-Bus API is not used because it is disabled
 * in default builds on every target distro; commands go directly to an
 * AT port instead. Collision avoidance with MM's own port usage:
 *  - runs only after the MM modem object exists (probing finished),
 *  - candidates are MM-reported AT ports minus MM's primary port,
 *  - ports MM holds open with TIOCEXCL fail our open (skip to next),
 *  - a bare "AT" liveness probe must answer OK before real commands are
 *    sent, so a port with a competing reader is abandoned, not fought
 *    over,
 *  - we take TIOCEXCL ourselves only for the short session.
 */

#ifndef CHAN_MM_ATINIT_H
#define CHAN_MM_ATINIT_H

#include "mm_glue.h"

/*!
 * \brief Queue the init AT commands for this modem if they have not run
 * for the current appearance. Cheap no-op when there is nothing to do.
 *
 * The actual tty session runs on the modem's serializer.
 */
void atinit_kick(modem_pvt_t *modem);

#endif /* CHAN_MM_ATINIT_H */
