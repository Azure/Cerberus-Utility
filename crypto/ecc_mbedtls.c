// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"
#include "ecc_mbedtls.h"
#include "unused.h"
#include "cerberus_utility_status_codes.h"
#include "unused.h"


/**
 * Get the mbedTLS ECC key pair instance for a public or private key instance.
 *
 * @return The mbedTLS ECC key pair.
 */
#define	ecc_mbedtls_get_ec_key_pair(x)	mbedtls_pk_ec (*((mbedtls_pk_context*) x->context))


/**
 * Allocate and initialize a context for an ECC key.
 *
 * @return The initialized key context or null.
 */
static mbedtls_pk_context* ecc_mbedtls_alloc_key_context ()
{
	mbedtls_pk_context *key = malloc (sizeof (mbedtls_pk_context));

	if (key != NULL) {
		mbedtls_pk_init (key);
	}

	return key;
}

/**
 * Zeroize an ECC key context and free the memory.
 *
 * @param context The context to free.
 */
static void ecc_mbedtls_free_key_context (void *context)
{
	mbedtls_pk_free ((mbedtls_pk_context*) context);
	free (context);
}

/**
 * Initialize a public key instance from a private key.
 *
 * @param key The private key instance to covert to a public key.
 * @param dup Flag indicating if a new key instance should be created for the public key.
 * @param error The error code for the operation.
 *
 * @return The public key instance or null if there was an error.
 */
static mbedtls_pk_context* ecc_mbedtls_convert_private_to_public (mbedtls_pk_context *key, bool dup,
	int *error)
{
	mbedtls_pk_context *pub = key;
	mbedtls_ecp_keypair *priv_ec;
	mbedtls_ecp_keypair *pub_ec;
	int status;

	if (dup) {
		pub = ecc_mbedtls_alloc_key_context ();
		if (pub == NULL) {
			status = STATUS_NO_MEM;
			goto error_alloc;
		}

		status = mbedtls_pk_setup (pub, mbedtls_pk_info_from_type (MBEDTLS_PK_ECKEY));
		if (status != 0) {
			goto error_exit;
		}

		priv_ec = mbedtls_pk_ec (*key);
		pub_ec = mbedtls_pk_ec (*pub);

		status = mbedtls_ecp_group_copy (&pub_ec->grp, &priv_ec->grp);
		if (status != 0) {
			goto error_exit;
		}

		status = mbedtls_ecp_copy (&pub_ec->Q, &priv_ec->Q);
		if (status != 0) {
			goto error_exit;
		}

		status = mbedtls_ecp_check_pub_priv (pub_ec, priv_ec);
		if (status != 0) {
			goto error_exit;
		}
	}
	else {
		pub_ec = mbedtls_pk_ec (*pub);
		mbedtls_mpi_free (&pub_ec->d);
	}

	*error = 0;
	return pub;

error_exit:
	ecc_mbedtls_free_key_context (pub);
	*error = status;

error_alloc:
	return NULL;
}

static int ecc_mbedtls_init_key_pair (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	mbedtls_pk_context *key_ctx;
	int status;

	if ((engine == NULL) || (key == NULL) || (key_length == 0)) {
		return STATUS_INVALID_INPUT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return STATUS_NO_MEM;
	}

	status = mbedtls_pk_parse_key (key_ctx, key, key_length, NULL, 0);
	if (status != 0) {
		goto error;
	}

	if (mbedtls_pk_get_type (key_ctx) != MBEDTLS_PK_ECKEY) {
		status = STATUS_INVALID_KEY;
		goto error;
	}

	if (pub_key) {
		pub_key->context = ecc_mbedtls_convert_private_to_public (key_ctx, (priv_key), &status);
		if (pub_key->context == NULL) {
			goto error;
		}
	}

	if (priv_key) {
		priv_key->context = key_ctx;
	}

	return 0;

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}

static int ecc_mbedtls_init_public_key (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key)
{
	mbedtls_pk_context *key_ctx;
	int status;

	if ((engine == NULL) || (key == NULL) || (key_length == 0) || (pub_key == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	memset (pub_key, 0, sizeof (struct ecc_public_key));

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return STATUS_NO_MEM;
	}

	status = mbedtls_pk_parse_public_key (key_ctx, key, key_length);
	if (status != 0) {
		goto error;
	}

	if (mbedtls_pk_get_type (key_ctx) != MBEDTLS_PK_ECKEY) {
		status = STATUS_INVALID_KEY;
		goto error;
	}

	pub_key->context = key_ctx;

	return 0;

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}

static int ecc_mbedtls_generate_derived_key_pair (struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_pk_context *key_ctx;
	mbedtls_ecp_keypair *ec;
	int status;

	if ((mbedtls == NULL) || (priv == NULL) || (key_length == 0)) {
		return STATUS_INVALID_INPUT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return STATUS_NO_MEM;
	}

	status = mbedtls_pk_setup (key_ctx, mbedtls_pk_info_from_type (MBEDTLS_PK_ECKEY));
	if (status != 0) {
		goto error;
	}

	ec = mbedtls_pk_ec (*key_ctx);

	status = mbedtls_ecp_group_load (&ec->grp, MBEDTLS_ECP_DP_SECP256R1);
	if (status != 0) {
		goto error;
	}

	status = mbedtls_mpi_read_binary (&ec->d, priv, key_length);
	if (status != 0) {
		goto error;
	}

	status = mbedtls_ecp_mul (&ec->grp, &ec->Q, &ec->d, &ec->grp.G, mbedtls_ctr_drbg_random,
		&mbedtls->ctr_drbg);
	if (status != 0) {
		goto error;
	}

	status = mbedtls_ecp_check_privkey (&ec->grp, &ec->d);
	if (status != 0) {
		goto error;
	}

	if (pub_key) {
		pub_key->context = ecc_mbedtls_convert_private_to_public (key_ctx, (priv_key), &status);
		if (pub_key->context == NULL) {
			goto error;
		}
	}

	if (priv_key) {
		priv_key->context = key_ctx;
	}

	return 0;

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}

static int ecc_mbedtls_generate_key_pair (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_pk_context *key_ctx;
	mbedtls_ecp_keypair *ec;
	int status;

	if (mbedtls == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return STATUS_NO_MEM;
	}

	status = mbedtls_pk_setup (key_ctx, mbedtls_pk_info_from_type (MBEDTLS_PK_ECKEY));
	if (status != 0) {
		goto error;
	}

	ec = mbedtls_pk_ec (*key_ctx);
	status = mbedtls_ecp_gen_key (MBEDTLS_ECP_DP_SECP256R1, ec, mbedtls_ctr_drbg_random,
		&mbedtls->ctr_drbg);
	if (status != 0) {
		goto error;
	}

	if (pub_key) {
		pub_key->context = ecc_mbedtls_convert_private_to_public (key_ctx, (priv_key), &status);
		if (pub_key->context == NULL) {
			goto error;
		}
	}

	if (priv_key) {
		priv_key->context = key_ctx;
	}

	return 0;

error:
	ecc_mbedtls_free_key_context (key_ctx);

	return status;
}

static void ecc_mbedtls_release_key_pair (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	UNUSED (engine);

	if (priv_key) {
		ecc_mbedtls_free_key_context (priv_key->context);
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}

	if (pub_key) {
		ecc_mbedtls_free_key_context (pub_key->context);
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}
}

static int ecc_mbedtls_get_signature_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key, size_t *max_len)
{
	if ((engine == NULL) || (key == NULL) || (max_len == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	*max_len = (mbedtls_pk_get_len ((mbedtls_pk_context*) key->context) + 3) * 2 + 3;

	return 0;
}

static int ecc_mbedtls_get_private_key_der (struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length)
{
	uint8_t tmp_der[29 + (3 * MBEDTLS_ECP_MAX_BYTES)];
	int status;

	if (der == NULL) {
		return STATUS_INVALID_INPUT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	if (ecc_mbedtls_get_ec_key_pair (key)->d.n == 0) {
		return STATUS_INVALID_KEY;
	}

	status = mbedtls_pk_write_key_der ((mbedtls_pk_context*) key->context, tmp_der,
		sizeof (tmp_der));
	if (status >= 0) {
		*der = malloc (status);

		if (*der == NULL) {
			return STATUS_NO_MEM;
		}

		memcpy (*der, &tmp_der[sizeof (tmp_der) - status], status);
		*length = status;
		status = 0;
	}

	return status;
}

static int ecc_mbedtls_get_public_key_der (struct ecc_engine *engine,
	const struct ecc_public_key *key, uint8_t **der, size_t *length)
{
	uint8_t tmp_der[30 + (2 * MBEDTLS_ECP_MAX_BYTES)];
	int status;

	if (der == NULL) {
		return STATUS_INVALID_INPUT;
	}

	*der = NULL;

	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	if (ecc_mbedtls_get_ec_key_pair (key)->d.n != 0) {
		return STATUS_INVALID_KEY;
	}

	status = mbedtls_pk_write_pubkey_der ((mbedtls_pk_context*) key->context, tmp_der,
		sizeof (tmp_der));
	if (status >= 0) {
		*der = malloc (status);
		if (*der == NULL) {
			return STATUS_NO_MEM;
		}

		memcpy (*der, &tmp_der[sizeof (tmp_der) - status], status);
		*length = status;
		status = 0;
	}

	return status;
}

static int ecc_mbedtls_sign (struct ecc_engine *engine, struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t *sig_length)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_ecp_keypair *ec;
	size_t max_sig_len;
	int status;

	if ((mbedtls == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	status = ecc_mbedtls_get_signature_max_length (engine, key, &max_sig_len);
	if (status != 0) {
		return status;
	}

	if (*sig_length < max_sig_len) {
		return STATUS_BUF_TOO_SMALL;
	}

	ec = ecc_mbedtls_get_ec_key_pair (key);
	status = mbedtls_ecp_check_privkey (&ec->grp, &ec->d);
	if (status != 0) {
		return status;
	}

	status = mbedtls_pk_sign ((mbedtls_pk_context*) key->context, MBEDTLS_MD_SHA256, digest, length,
		signature, sig_length, mbedtls_ctr_drbg_random, &mbedtls->ctr_drbg);
	if (status == 0) {
		*sig_length = status;
	}

	return status;
}

static int ecc_mbedtls_verify (struct ecc_engine *engine, struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	int status;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == 0)) {
		return STATUS_INVALID_INPUT;
	}

	status = mbedtls_pk_verify ((mbedtls_pk_context*) key->context, MBEDTLS_MD_SHA256, digest,
		length, signature, sig_length);
	if (status != 0) {
		if ((status == MBEDTLS_ERR_MPI_ALLOC_FAILED) ||
			(status == (MBEDTLS_ERR_MPI_ALLOC_FAILED + MBEDTLS_ERR_ECP_BAD_INPUT_DATA))) {
			return STATUS_NO_MEM;
		}
		else {
			return STATUS_SIG_VERIFY_FAIL;
		}
	}

	return status;
}

static int ecc_mbedtls_get_shared_secret_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key, size_t *max_secret_len)
{
	if ((engine == NULL) || (key == NULL) || (max_secret_len == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	*max_secret_len = mbedtls_pk_get_len ((mbedtls_pk_context*) key->context);
	if (*max_secret_len == 0) {
		return STATUS_CRYPTO_FAILURE;
	}

	return 0;
}

static int ecc_mbedtls_compute_shared_secret (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key, uint8_t *secret,
	size_t *secret_len)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_ecp_keypair *priv_ec;
	mbedtls_ecp_keypair *pub_ec;
	mbedtls_mpi out;
	size_t out_len;
	size_t max_len;
	int status;

	if ((mbedtls == NULL) || (priv_key == NULL) || (pub_key == NULL) || (secret == NULL) ||
		(secret_len == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	status = ecc_mbedtls_get_shared_secret_max_length (engine, priv_key, &max_len);
	if (status != 0) {
		return status;
	}
	if (*secret_len < max_len) {
		return STATUS_BUF_TOO_SMALL;
	}

	priv_ec = ecc_mbedtls_get_ec_key_pair (priv_key);
	pub_ec = ecc_mbedtls_get_ec_key_pair (pub_key);

	mbedtls_mpi_init (&out);

	status = mbedtls_ecdh_compute_shared (&priv_ec->grp, &out, &pub_ec->Q, &priv_ec->d,
		mbedtls_ctr_drbg_random, &mbedtls->ctr_drbg);
	if (status != 0) {
		goto error;
	}

	out_len = mbedtls_mpi_size (&out);
	if (out_len > max_len) {
		status = STATUS_BUF_TOO_SMALL;
		goto error;
	}

	memset (secret, 0, *secret_len);
	mbedtls_mpi_write_binary (&out, &secret[max_len - out_len], out_len);
	mbedtls_mpi_free (&out);

	*secret_len = max_len;

	return 0;

error:
	mbedtls_mpi_free (&out);

	return status;
}

/**
 * Initialize an instance for running ECC operations using mbedTLS.
 *
 * @param engine The ECC engine to initialize.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int ecc_mbedtls_init (struct ecc_engine_mbedtls *engine)
{
	int status;

	if (engine == NULL) {
		return STATUS_INVALID_INPUT;
	}

	memset (engine, 0, sizeof (struct ecc_engine_mbedtls));

	mbedtls_ctr_drbg_init (&engine->ctr_drbg);
	mbedtls_entropy_init (&engine->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->ctr_drbg, mbedtls_entropy_func, &engine->entropy, NULL,
		0);
	if (status != 0) {
		goto exit;
	}

	engine->base.init_key_pair = ecc_mbedtls_init_key_pair;
	engine->base.init_public_key = ecc_mbedtls_init_public_key;
	engine->base.generate_derived_key_pair = ecc_mbedtls_generate_derived_key_pair;
	engine->base.generate_key_pair = ecc_mbedtls_generate_key_pair;
	engine->base.release_key_pair = ecc_mbedtls_release_key_pair;
	engine->base.get_signature_max_length = ecc_mbedtls_get_signature_max_length;
	engine->base.get_private_key_der = ecc_mbedtls_get_private_key_der;
	engine->base.get_public_key_der = ecc_mbedtls_get_public_key_der;
	engine->base.sign = ecc_mbedtls_sign;
	engine->base.verify = ecc_mbedtls_verify;
	engine->base.get_shared_secret_max_length = ecc_mbedtls_get_shared_secret_max_length;
	engine->base.compute_shared_secret = ecc_mbedtls_compute_shared_secret;

	return 0;

exit:
	mbedtls_entropy_free (&engine->entropy);
	mbedtls_ctr_drbg_free (&engine->ctr_drbg);

	return status;
}

/**
 * Release an mbedTLS ECC engine.
 *
 * @param engine The ECC engine to release.
 */
void ecc_mbedtls_release (struct ecc_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_entropy_free (&engine->entropy);
		mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	}
}
