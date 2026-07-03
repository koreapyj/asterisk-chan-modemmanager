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
 * \brief D-Bus system bus, MMManager and GMainLoop thread lifecycle.
 *
 * A private GMainContext is used instead of the global default context:
 * other modules loaded into the same Asterisk process may also use GLib,
 * and two threads cannot iterate one context.
 *
 * Signal delivery contract: proxies created before the loop thread
 * starts (the manager and its interface proxies) dispatch on the loop.
 * Proxies constructed later from other threads (create_call_sync,
 * list_*_sync results) do NOT deliver GObject signals reliably — treat
 * them as method/property handles only, and receive signals through
 * connection-level subscriptions made on the loop thread instead (see
 * mm_bus_context()).
 */

#ifndef CHAN_MM_BUS_H
#define CHAN_MM_BUS_H

#include <gio/gio.h>
#include <libmm-glib.h>

#include "asterisk/threadpool.h"

/*!
 * \brief Connect to the system bus, create the MMManager, start the loop
 * thread and the worker threadpool.
 * \retval 0 success
 */
int mm_bus_start(void);

/*!
 * \brief Quit and join the loop thread, shut the threadpool down, drop
 * the manager and bus references.
 */
void mm_bus_stop(void);

/*! \brief The MMManager (borrowed reference, valid between start/stop) */
MMManager *mm_bus_manager(void);

/*! \brief The system bus connection (borrowed reference) */
GDBusConnection *mm_bus_connection(void);

/*! \brief Threadpool backing the per-modem serializers */
struct ast_threadpool *mm_bus_threadpool(void);

/*!
 * \brief The module's private GMainContext (borrowed).
 *
 * The loop thread OWNS this context: g_main_context_push_thread_default
 * from any other thread fails its acquire assertion and silently no-ops,
 * binding whatever it "wrapped" to the dead global default context.
 * Anything that must dispatch on the loop (signal subscriptions, source
 * attachment) has to execute ON the loop thread via
 * g_main_context_invoke(mm_bus_context(), ...).
 */
GMainContext *mm_bus_context(void);

#endif /* CHAN_MM_BUS_H */
