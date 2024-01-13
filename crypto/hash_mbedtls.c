// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>

#include "cerberus_utility_status_codes.h"
#include "hash_mbedtls.h"


/**
 * Free the active hash context.
 *
 * @param engine The hash engine whose context should be freed.
 */
static void hash_mbedtls_free_context (struct hash_engine_mbedtls *engine)
{
	switch (engine->active) {
		case HASH_ACTIVE_SHA256:
			mbedtls_sha256_free (&engine->context.sha256);
			break;
	}

	engine->active = HASH_ACTIVE_NONE;
}

static int hash_mbedtls_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (data == NULL) || (hash == NULL) || (length == 0)) {
		return STATUS_INVALID_INPUT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return STATUS_BUF_TOO_SMALL;
	}

	mbedtls_sha256 (data, length, hash, 0);

	return 0;
}

static int hash_mbedtls_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if (mbedtls == NULL) {
		return STATUS_INVALID_INPUT;
	}

	hash_mbedtls_free_context (mbedtls);

	mbedtls_sha256_init (&mbedtls->context.sha256);
	mbedtls_sha256_starts (&mbedtls->context.sha256, 0);
	mbedtls->active = HASH_ACTIVE_SHA256;

	return 0;
}

static int hash_mbedtls_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (data == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	switch (mbedtls->active) {
		case HASH_ACTIVE_SHA256:
			mbedtls_sha256_update (&mbedtls->context.sha256, data, length);
			break;

		default:
			return STATUS_UNEXPECTED_VALUE;
	}

	return 0;
}

static int hash_mbedtls_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (hash == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	switch (mbedtls->active) {
		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return STATUS_BUF_TOO_SMALL;
			}

			mbedtls_sha256_finish (&mbedtls->context.sha256, hash);
			break;

		default:
			return STATUS_UNEXPECTED_VALUE;
	}

	mbedtls->active = HASH_ACTIVE_NONE;
	return 0;
}

static void hash_mbedtls_cancel (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if (mbedtls) {
		mbedtls->active = HASH_ACTIVE_NONE;
	}
}

/**
 * Initialize an mbed TLS hash engine.
 *
 * @param engine The hash engine to initialize.
 *
 * @return 0 if the hash engine was successfully initialized or an error code.
 */
int hash_mbedtls_init (struct hash_engine_mbedtls *engine)
{
	if (engine == NULL) {
		return STATUS_INVALID_INPUT;
	}

	memset (engine, 0, sizeof (struct hash_engine_mbedtls));

	engine->base.calculate_sha256 = hash_mbedtls_calculate_sha256;
	engine->base.start_sha256 = hash_mbedtls_start_sha256;
	engine->base.update = hash_mbedtls_update;
	engine->base.finish = hash_mbedtls_finish;
	engine->base.cancel = hash_mbedtls_cancel;

	return 0;
}

/**
 * Release the resources used by an mbed TLS hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_mbedtls_release (struct hash_engine_mbedtls *engine)
{
	if (engine != NULL) {
		hash_mbedtls_free_context (engine);
	}
}
