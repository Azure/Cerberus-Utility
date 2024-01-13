// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_MBEDTLS_H_
#define HASH_MBEDTLS_H_

#include "hash.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"


/**
 * An mbed TLS context for calculating hashes.
 */
struct hash_engine_mbedtls {
	struct hash_engine base;			/**< The base hash engine. */
	union {
		mbedtls_sha256_context sha256;	/**< Context for SHA256 hashes. */
	} context;							/**< The hashing contexts. */
	uint8_t active;						/**< The active hash context. */
};


int hash_mbedtls_init (struct hash_engine_mbedtls *engine);
void hash_mbedtls_release (struct hash_engine_mbedtls *engine);


#endif /* HASH_MBEDTLS_H_ */
