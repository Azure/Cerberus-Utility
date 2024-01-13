// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "cerberus_utility_status_codes.h"
#include "aes_mbedtls.h"


static int aes_mbedtls_set_key (struct aes_engine *engine, const uint8_t *key, size_t length)
{
	struct aes_engine_mbedtls *mbedtls = (struct aes_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (key == NULL) || (length != (256 / 8))) {
		return STATUS_INVALID_INPUT;
	}

	return mbedtls_gcm_setkey (&mbedtls->context, MBEDTLS_CIPHER_ID_AES, key, 256);
}

static int aes_mbedtls_encrypt_data (struct aes_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length,
	uint8_t *tag, size_t tag_length)
{
	struct aes_engine_mbedtls *mbedtls = (struct aes_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (plaintext == NULL) || (length == 0) || (iv == NULL) ||
		(iv_length == 0) || (ciphertext == NULL) || (tag == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	if ((out_length < length) || (tag_length < 16)) {
		return STATUS_BUF_TOO_SMALL;
	}

	if (mbedtls->context.cipher_ctx.key_bitlen == 0) {
		return STATUS_NO_KEY;
	}

	return mbedtls_gcm_crypt_and_tag (&mbedtls->context, MBEDTLS_GCM_ENCRYPT, length, iv,
		iv_length, NULL, 0, plaintext, ciphertext, 16, tag);
}

static int aes_mbedtls_decrypt_data (struct aes_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
	size_t out_length)
{
	struct aes_engine_mbedtls *mbedtls = (struct aes_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (ciphertext == NULL) || (length == 0) || (tag == NULL) ||
		(iv == NULL) || (iv_length == 0) || (plaintext == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	if (out_length < length) {
		return STATUS_BUF_TOO_SMALL;
	}

	if (mbedtls->context.cipher_ctx.key_bitlen == 0) {
		return STATUS_NO_KEY;
	}

	return mbedtls_gcm_auth_decrypt (&mbedtls->context, length, iv, iv_length, NULL, 0, tag, 16,
		ciphertext, plaintext);
}

/**
 * Initialize an instance for run AES operations using mbedTLS.
 *
 * @param engine The AES engine to initialize.
 *
 * @return 0 if the AES engine was successfully initialized or an error code.
 */
int aes_mbedtls_init (struct aes_engine_mbedtls *engine)
{
	if (engine == NULL) {
		return STATUS_INVALID_INPUT;
	}

	memset (engine, 0, sizeof (struct aes_engine_mbedtls));

	mbedtls_gcm_init (&engine->context);

	engine->base.set_key = aes_mbedtls_set_key;
	engine->base.encrypt_data = aes_mbedtls_encrypt_data;
	engine->base.decrypt_data = aes_mbedtls_decrypt_data;

	return 0;
}

/**
 * Release an mbedTLS AES engine.
 *
 * @param engine The AES engine to release.
 */
void aes_mbedtls_release (struct aes_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_gcm_free (&engine->context);
	}
}
