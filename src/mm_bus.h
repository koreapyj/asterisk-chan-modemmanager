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
 * and two threads cannot iterate one context. Every proxy this module
 * creates must be bound to this context so its signals dispatch on our
 * loop thread — use mm_bus_push_context()/mm_bus_pop_context() around
 * any libmm-glib call that constructs proxies (list_calls, create_call,
 * list_messages, ...) when calling from a non-loop thread.
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

/*! \brief Threadpool backing the per-modem serializers */
struct ast_threadpool *mm_bus_threadpool(void);

/*! \brief Bind the module's GMainContext to the calling thread */
void mm_bus_push_context(void);
void mm_bus_pop_context(void);

#endif /* CHAN_MM_BUS_H */
