/*
 * chan_modemmanager -- ModemManager channel driver
 *
 * Copyright (C) 2025 koreapyj
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "mm_glue.h"

#include "asterisk/logger.h"
#include "asterisk/utils.h"

#include "mm_bus.h"

static GMainContext *bus_context;
static GMainLoop *bus_loop;
static pthread_t bus_thread = AST_PTHREADT_NULL;
static GDBusConnection *bus_connection;
static MMManager *bus_manager;
static struct ast_threadpool *bus_pool;

MMManager *mm_bus_manager(void)
{
	return bus_manager;
}

GDBusConnection *mm_bus_connection(void)
{
	return bus_connection;
}

struct ast_threadpool *mm_bus_threadpool(void)
{
	return bus_pool;
}

GMainContext *mm_bus_context(void)
{
	return bus_context;
}

static void *bus_thread_fn(void *data)
{
	g_main_context_push_thread_default(bus_context);
	ast_debug(1, "GMainLoop thread started\n");
	g_main_loop_run(bus_loop);
	ast_debug(1, "GMainLoop thread stopping\n");
	g_main_context_pop_thread_default(bus_context);
	return NULL;
}

int mm_bus_start(void)
{
	GError *error = NULL;
	struct ast_threadpool_options pool_opts = {
		.version = AST_THREADPOOL_OPTIONS_VERSION,
		.idle_timeout = 60,
		.auto_increment = 1,
		.initial_size = 0,
		.max_size = 4,
	};

	bus_pool = ast_threadpool_create("modemmanager", NULL, &pool_opts);
	if (!bus_pool) {
		ast_log(LOG_ERROR, "Failed to create worker threadpool\n");
		return -1;
	}

	bus_context = g_main_context_new();
	bus_loop = g_main_loop_new(bus_context, FALSE);

	/* Create the connection and manager with our context as thread-default
	 * so every proxy the object manager hands out dispatches its signals
	 * on our loop thread. This is the ONLY safe moment to push the
	 * context from this thread: the loop thread has not started yet, so
	 * g_main_context_push_thread_default can still acquire it. Once
	 * g_main_loop_run owns the context, pushing from any other thread
	 * fails its 'acquired_context' assertion and silently no-ops --
	 * anything needing the context after this point must run ON the loop
	 * thread (g_main_context_invoke). */
	g_main_context_push_thread_default(bus_context);
	bus_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!error) {
		bus_manager = mm_manager_new_sync(bus_connection,
			G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE, NULL, &error);
	}
	g_main_context_pop_thread_default(bus_context);

	if (error) {
		ast_log(LOG_ERROR, "Failed to reach ModemManager on the system bus - (%d) %s\n",
			error->code, error->message);
		g_clear_error(&error);
		mm_bus_stop();
		return -1;
	}

	if (ast_pthread_create_background(&bus_thread, NULL, bus_thread_fn, NULL)) {
		ast_log(LOG_ERROR, "Failed to create GMainLoop thread\n");
		mm_bus_stop();
		return -1;
	}

	return 0;
}

void mm_bus_stop(void)
{
	if (bus_loop) {
		g_main_loop_quit(bus_loop);
	}
	if (bus_thread != AST_PTHREADT_NULL) {
		pthread_join(bus_thread, NULL);
		bus_thread = AST_PTHREADT_NULL;
	}

	g_clear_object(&bus_manager);
	g_clear_object(&bus_connection);
	if (bus_loop) {
		g_main_loop_unref(bus_loop);
		bus_loop = NULL;
	}
	if (bus_context) {
		g_main_context_unref(bus_context);
		bus_context = NULL;
	}

	if (bus_pool) {
		ast_threadpool_shutdown(bus_pool);
		bus_pool = NULL;
	}
}
