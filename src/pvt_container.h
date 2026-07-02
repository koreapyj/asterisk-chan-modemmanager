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
 * \brief Shared ao2 hash/cmp for identifier-keyed pvt containers.
 *
 * Lookups use OBJ_SEARCH_KEY with the identifier string, so no
 * throwaway stack pvt structs are needed.
 */

#ifndef CHAN_MM_PVT_CONTAINER_H
#define CHAN_MM_PVT_CONTAINER_H

#include "mm_glue.h"

#include "asterisk/strings.h"

#define NUM_PVT_BUCKETS 7

static inline int pvt_hash_cb(const void *obj, const int flags)
{
	const char *key = (flags & OBJ_SEARCH_KEY)
		? obj : ((const abstract_pvt_t *)obj)->identifier;

	return ast_str_case_hash(key);
}

static inline int pvt_cmp_cb(void *obj, void *arg, int flags)
{
	const abstract_pvt_t *pvt = obj;
	const char *key = (flags & OBJ_SEARCH_KEY)
		? arg : ((const abstract_pvt_t *)arg)->identifier;

	return !strcasecmp(pvt->identifier, key) ? CMP_MATCH | CMP_STOP : 0;
}

#endif /* CHAN_MM_PVT_CONTAINER_H */
