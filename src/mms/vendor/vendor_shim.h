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
 * \brief Minimal local shim standing in for mmsd-tng's daemon headers.
 *
 * src/mms/vendor/mmsutil.c is vendored from mmsd-tng
 * (https://gitlab.com/kop316/mmsd, commit
 * 341117141f8d30949fb1294cc71ee44af9b4c90f). Upstream, it pulls in the
 * whole daemon's composition header "mms.h" (which in turn drags in
 * plugin.h, service.h, store.h, itu-e212-iso.h, log.h -- the MMSC HTTP
 * client, D-Bus service objects, on-disk message store, etc). None of
 * that exists in this repo and none of it is needed: a full grep of the
 * vendored mmsutil.c shows the *only* symbol it actually uses from that
 * chain is the DBG() logging macro from mmsd-tng's log.h:
 *
 *     #define DBG(fmt, arg ...) do {                                \
 *           g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s:%s() " fmt, \
 *                  __FILE__, __FUNCTION__, ## arg);                 \
 *       } while (0)
 *
 * This header replaces "mms.h" in the vendored mmsutil.c's include list
 * (see the provenance comment at the top of that file) and reproduces
 * just that macro, routed through Asterisk-free, GLib-only debug output
 * so the codec keeps compiling and linking standalone, both in the host
 * unit tests (tests/test_mms_codec.c) and inside the .so.
 *
 * Not part of the upstream mmsd-tng source tree; this file is new code
 * written for chan_modemmanager.
 */

#ifndef CHAN_MM_MMS_VENDOR_SHIM_H
#define CHAN_MM_MMS_VENDOR_SHIM_H

#include <glib.h>

/*!
 * \brief Stand-in for mmsd-tng's log.h DBG() macro.
 *
 * Kept as a real (not no-op) trace so decode failures in the field are
 * diagnosable, but routed through GLib's own logging (G_LOG_DOMAIN,
 * default "MMS-CODEC" here) rather than a bespoke fprintf(), since the
 * vendored code is already built against GLib and every call site already
 * uses g_log()-style varargs. Verbosity is controlled the normal GLib way
 * (G_MESSAGES_DEBUG=all or a callers' own log handler); nothing here
 * writes to Asterisk's logger, keeping this file free of Asterisk headers.
 */
#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "MMS-CODEC"
#endif

#define DBG(fmt, arg ...) do {                                \
		g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s:%s() " fmt, \
		       __FILE__, __FUNCTION__, ## arg);                 \
	} while (0)

#endif /* CHAN_MM_MMS_VENDOR_SHIM_H */
