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

#include "asterisk/config.h"
#include "asterisk/logger.h"

#include "pvt_container.h"
#include "sim.h"

static struct ao2_container *sims;

int sim_container_init(void)
{
	sims = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, NUM_PVT_BUCKETS,
		pvt_hash_cb, NULL, pvt_cmp_cb);
	return sims ? 0 : -1;
}

void sim_container_destroy(void)
{
	if (sims) {
		ao2_ref(sims, -1);
		sims = NULL;
	}
}

sim_pvt_t *find_sim(const char *identifier)
{
	return ao2_find(sims, identifier, OBJ_SEARCH_KEY);
}

static void sim_destructor(void *obj)
{
	sim_pvt_t *pvt = obj;

	g_clear_object(&pvt->device);
	pvt->modem = unref_modem(pvt->modem);
	ast_string_field_free_memory(pvt);
}

/*!
 * \note This function expects the pvt lock to be held.
 */
static void set_sim_defaults(sim_pvt_t *pvt)
{
	ast_string_field_set(pvt, mohinterpret, "default");
	ast_string_field_set(pvt, context, "default");
	ast_string_field_set(pvt, message_context, NULL);
	ast_string_field_set(pvt, exten, NULL);
	ast_string_field_set(pvt, language, "");
	ast_string_field_set(pvt, parkinglot, "");

	pvt->overridecontext = 0;
	pvt->autoanswer = 0;
}

/*!
 * \note This function expects the pvt lock to be held.
 */
static void store_config_sim(sim_pvt_t *pvt, const char *var, const char *value)
{
	CV_START(var, value);

	CV_STRFIELD("identifier", pvt, identifier);
	CV_BOOL("autoanswer", pvt->autoanswer);
	CV_STRFIELD("context", pvt, context);
	CV_STRFIELD("message_context", pvt, message_context);
	CV_STRFIELD("extension", pvt, exten);
	CV_STRFIELD("language", pvt, language);
	CV_BOOL("overridecontext", pvt->overridecontext);
	CV_STRFIELD("mohinterpret", pvt, mohinterpret);
	CV_STRFIELD("parkinglot", pvt, parkinglot);
	CV_F("type", NULL);

	ast_log(LOG_WARNING, "Unknown option '%s'\n", var);

	CV_END;
}

static int init_sim(sim_pvt_t *pvt, const char *identifier)
{
	if (ast_string_field_init(pvt, 32)) {
		return -1;
	}

	ast_string_field_set(pvt, identifier, S_OR(identifier, ""));

	return 0;
}

void build_sim(struct ast_config *cfg, const char *name)
{
	struct ast_variable *v;
	sim_pvt_t *pvt;
	int new = 0;

	if ((pvt = find_sim(name))) {
		modemmanager_pvt_lock(pvt);
		set_sim_defaults(pvt);
		pvt->destroy = 0;
	} else {
		if (!(pvt = ao2_alloc(sizeof(*pvt), sim_destructor))) {
			return;
		}
		if (init_sim(pvt, name)) {
			unref_sim(pvt);
			return;
		}
		set_sim_defaults(pvt);
		new = 1;
	}

	for (v = ast_variable_browse(cfg, name); v; v = v->next) {
		store_config_sim(pvt, v->name, v->value);
	}

	if (new) {
		ao2_link(sims, pvt);
	} else {
		modemmanager_pvt_unlock(pvt);
	}

	unref_sim(pvt);
}

static int mark_destroy_cb(void *obj, void *arg, int flags)
{
	sim_pvt_t *pvt = obj;

	pvt->destroy = 1;
	return 0;
}

void sim_mark_destroy_all(void)
{
	ao2_callback(sims, OBJ_NODATA, mark_destroy_cb, NULL);
}

static int prune_cb(void *obj, void *arg, int flags)
{
	sim_pvt_t *pvt = obj;

	if (!pvt->destroy) {
		return 0;
	}
	ast_verb(2, "Removing sim '%s' (no longer configured)\n", pvt->identifier);
	return CMP_MATCH;
}

void sim_prune_destroyed(void)
{
	ao2_callback(sims, OBJ_NODATA | OBJ_MULTIPLE | OBJ_UNLINK, prune_cb, NULL);
}

static int detach_cb(void *obj, void *arg, int flags)
{
	sim_pvt_t *pvt = obj;

	modemmanager_pvt_lock(pvt);
	g_clear_object(&pvt->device);
	pvt->modem = unref_modem(pvt->modem);
	modemmanager_pvt_unlock(pvt);
	return 0;
}

void sim_detach_all(void)
{
	ao2_callback(sims, OBJ_NODATA, detach_cb, NULL);
}
