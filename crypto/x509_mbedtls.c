// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "x509_mbedtls.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/bignum.h"
#include "cerberus_utility_status_codes.h"
#include "unused.h"


/**
 * mbedTLS data for managing CA certificates.
 */
struct x509_mbedtls_ca_store_context {
	mbedtls_x509_crt *root_ca;			/**< The chain of trusted root certificates. */
	mbedtls_x509_crt *intermediate;		/**< The chain of intermediate CAs. */
};


/**
 * Create a new mbedTLS certificate instance.
 *
 * @return The allocated certificate or null.
 */
static mbedtls_x509_crt* x509_mbedtls_new_cert ()
{
	mbedtls_x509_crt *x509 = malloc (sizeof (mbedtls_x509_crt));

	if (x509 != NULL) {
		mbedtls_x509_crt_init (x509);
	}

	return x509;
}

/**
 * Free an mbedTLS certificate instance.
 *
 * @param cert The certificate to free.
 */
static void x509_mbedtls_free_cert (void *cert)
{
	mbedtls_x509_crt *x509 = (mbedtls_x509_crt*) cert;

	if (x509) {
		mbedtls_x509_crt_free (x509);
		free (x509);
	}
}

static int x509_mbedtls_load_certificate (struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length)
{
	mbedtls_x509_crt *x509;
	int status;

	if ((engine == NULL) || (cert == NULL) || (der == NULL) || (length == 0)) {
		return STATUS_INVALID_INPUT;
	}

	x509 = x509_mbedtls_new_cert ();
	if (x509 == NULL) {
		return STATUS_NO_MEM;
	}

	status = mbedtls_x509_crt_parse_der (x509, der, length);
	if (status == 0) {
		cert->context = x509;
	}
	else {
		x509_mbedtls_free_cert (x509);
	}

	return status;
}

static void x509_mbedtls_release_certificate (struct x509_engine *engine,
	struct x509_certificate *cert)
{
	UNUSED (engine);

	if (cert) {
		x509_mbedtls_free_cert (cert->context);
		memset (cert, 0, sizeof (struct x509_certificate));
	}
}

static int x509_mbedtls_get_certificate_version (struct x509_engine *engine,
	const struct x509_certificate *cert, int *cert_version)
{
	if ((engine == NULL) || (cert == NULL) || (cert_version == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	*cert_version = ((mbedtls_x509_crt*) cert->context)->version;

	return STATUS_SUCCESS;
}

static int x509_mbedtls_get_serial_number (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length, size_t *serial_num_len)
{
	mbedtls_x509_crt *x509;

	if ((engine == NULL) || (cert == NULL) || (serial_num == NULL) || (serial_num_len == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	x509 = (mbedtls_x509_crt*) cert->context;
	if (length < x509->serial.len) {
		return STATUS_BUF_TOO_SMALL;
	}

	memcpy (serial_num, x509->serial.p, x509->serial.len);

	*serial_num_len = x509->serial.len;

	return STATUS_SUCCESS;
}

static int x509_mbedtls_get_public_key_type (struct x509_engine *engine,
	const struct x509_certificate *cert, int *key_type)
{
	if ((engine == NULL) || (cert == NULL) || (key_type == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	switch (mbedtls_pk_get_type (&((mbedtls_x509_crt*) cert->context)->pk)) {
		case MBEDTLS_PK_ECKEY:
			*key_type = X509_PUBLIC_KEY_ECC;
			break;

		case MBEDTLS_PK_RSA:
			*key_type = X509_PUBLIC_KEY_RSA;
			break;

		case MBEDTLS_PK_NONE:
			return STATUS_UNEXPECTED_VALUE;

		default:
			return STATUS_UNSUPPORTED_FORMAT;
	}

	return STATUS_SUCCESS;
}

static int x509_mbedtls_get_public_key_length (struct x509_engine *engine,
	const struct x509_certificate *cert, size_t *key_len)
{
	if ((engine == NULL) || (cert == NULL) || (key_len == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	*key_len = mbedtls_pk_get_bitlen (&((mbedtls_x509_crt*) (cert->context))->pk);

	return STATUS_SUCCESS;
}

static int x509_mbedtls_get_public_key (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	struct x509_engine_mbedtls *mbedtls = (struct x509_engine_mbedtls*) engine;
	int status;

	if (key == NULL) {
		return STATUS_INVALID_INPUT;
	}

	*key = NULL;
	if ((mbedtls == NULL) || (cert == NULL) || (key_length == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	status = mbedtls_pk_write_pubkey_der (&((mbedtls_x509_crt*) cert->context)->pk,
		mbedtls->der_buf, X509_MAX_SIZE);
	if (status < 0) {
		return status;
	}

	*key = malloc (status);
	if (*key == NULL) {
		return STATUS_NO_MEM;
	}

	memcpy (*key, &mbedtls->der_buf[X509_MAX_SIZE - status], status);
	*key_length = status;

	return 0;
}

/**
 * Verify only the signature of a certificate.
 *
 * @param cert The certificate to verify.
 * @param key The key to use for verification.
 *
 * @return 0 if the signature is valid or an error code.
 */
static int x509_mbedtls_verify_cert_signature (mbedtls_x509_crt *cert, mbedtls_pk_context *key)
{
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info;
	int status;

	md_info = mbedtls_md_info_from_type (cert->sig_md);
	if (md_info == NULL) {
		return STATUS_CERT_SIG_TYPE_UNSUPPORTED;
	}

	mbedtls_md (md_info, cert->tbs.p, cert->tbs.len, hash);

	status = mbedtls_pk_verify_ext (cert->sig_pk, cert->sig_opts, key, cert->sig_md, hash,
	mbedtls_md_get_size (md_info), cert->sig.p, cert->sig.len);

	return status;
}

/**
 * Indicate if a certificate is self-signed.
 *
 * @param x509 The certificate to check.
 *
 * @return true if the certificate is self-signed or false if not.
 */
static bool x509_mbedtls_is_self_signed (mbedtls_x509_crt *x509)
{
	if ((x509->issuer_raw.len == x509->subject_raw.len) &&
		(memcmp (x509->issuer_raw.p, x509->subject_raw.p, x509->issuer_raw.len) == 0)) {
		return true;
	}
	else {
		return false;
	}
}

static int x509_mbedtls_init_ca_cert_store (struct x509_engine *engine, struct x509_ca_certs *store)
{
	struct x509_mbedtls_ca_store_context *store_ctx;

	if ((engine == NULL) || (store == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	store_ctx = malloc (sizeof (struct x509_mbedtls_ca_store_context));
	if (store_ctx == NULL) {
		return STATUS_NO_MEM;
	}

	memset (store_ctx, 0, sizeof (struct x509_mbedtls_ca_store_context));
	store->context = store_ctx;

	return 0;
}

static void x509_mbedtls_release_ca_cert_store (struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	UNUSED (engine);

	if (store && store->context) {
		struct x509_mbedtls_ca_store_context *store_ctx = store->context;

		mbedtls_x509_crt_free (store_ctx->root_ca);
		free (store_ctx->root_ca);

		mbedtls_x509_crt_free (store_ctx->intermediate);
		free (store_ctx->intermediate);

		free (store_ctx);
		memset (store, 0, sizeof (struct x509_ca_certs));
	}
}

static int x509_mbedtls_add_root_ca (struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	struct x509_mbedtls_ca_store_context *store_ctx;
	struct x509_certificate cert;
	mbedtls_x509_crt *x509;
	int status;

	if (store == NULL) {
		return STATUS_INVALID_INPUT;
	}

	status = x509_mbedtls_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_exit;
	}

	x509 = (mbedtls_x509_crt*) cert.context;

	if (!x509->ca_istrue) {
		status = STATUS_CERT_NOT_CA;
		goto err_free_cert;
	}

	if (!x509_mbedtls_is_self_signed (x509)) {
		status = STATUS_CERT_SELF_SIGNED;
		goto err_free_cert;
	}

	status = x509_mbedtls_verify_cert_signature (x509, &x509->pk);
	if (status != 0) {
		status = STATUS_CERT_INVALID_SIGNATURE;
		goto err_free_cert;
	}

	store_ctx = store->context;
	x509->next = store_ctx->root_ca;
	store_ctx->root_ca = x509;

	return 0;

err_free_cert:
	x509_mbedtls_release_certificate (engine, &cert);
err_exit:
	return status;
}

static int x509_mbedtls_add_intermediate_ca (struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length)
{
	struct x509_mbedtls_ca_store_context *store_ctx;
	struct x509_certificate cert;
	mbedtls_x509_crt *x509;
	int status;

	if (store == NULL) {
		return STATUS_INVALID_INPUT;
	}

	status = x509_mbedtls_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_exit;
	}

	x509 = (mbedtls_x509_crt*) cert.context;

	if (!x509->ca_istrue) {
		status = STATUS_CERT_NOT_CA;
		goto err_free_cert;
	}

	if (x509_mbedtls_is_self_signed (x509)) {
		status = STATUS_CERT_SELF_SIGNED;
		goto err_free_cert;
	}

	store_ctx = store->context;
	x509->next = store_ctx->intermediate;
	store_ctx->intermediate = x509;

	return 0;

err_free_cert:
	x509_mbedtls_release_certificate (engine, &cert);
err_exit:
	return status;
}

static int x509_mbedtls_authenticate (struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store)
{
	struct x509_engine_mbedtls *mbedtls = (struct x509_engine_mbedtls*) engine;
	struct x509_mbedtls_ca_store_context *store_ctx;
	mbedtls_x509_crt *x509;
	int status;
	uint32_t validation;

	if ((mbedtls == NULL) || (cert == NULL) || (store == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	store_ctx = store->context;
	x509 = (mbedtls_x509_crt*) cert->context;
	x509->next = store_ctx->intermediate;

	status = mbedtls_x509_crt_verify (x509, store_ctx->root_ca, NULL, NULL, &validation, NULL,
		NULL);
	if (status == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
		status = STATUS_CERT_INVALID_CERT;
	}

	x509->next = NULL;
	return status;
}

/**
 * Initialize an instance for handling X.509 certificates using mbedTLS.
 *
 * @param engine The X.509 engine to initialize.
 *
 * @return 0 if the X.509 engine  was successfully initialized or an error code.
 */
int x509_mbedtls_init (struct x509_engine_mbedtls *engine)
{
	int status;

	if (engine == NULL) {
		return STATUS_INVALID_INPUT;
	}

	memset (engine, 0, sizeof (struct x509_engine_mbedtls));

	mbedtls_ctr_drbg_init (&engine->ctr_drbg);
	mbedtls_entropy_init (&engine->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->ctr_drbg, mbedtls_entropy_func, &engine->entropy, NULL,
		0);
	if (status != 0) {
		goto exit;
	}

	engine->base.load_certificate = x509_mbedtls_load_certificate;
	engine->base.release_certificate = x509_mbedtls_release_certificate;
	engine->base.get_certificate_version = x509_mbedtls_get_certificate_version;
	engine->base.get_serial_number = x509_mbedtls_get_serial_number;
	engine->base.get_public_key_type = x509_mbedtls_get_public_key_type;
	engine->base.get_public_key_length = x509_mbedtls_get_public_key_length;
	engine->base.get_public_key = x509_mbedtls_get_public_key;
	engine->base.init_ca_cert_store = x509_mbedtls_init_ca_cert_store;
	engine->base.release_ca_cert_store = x509_mbedtls_release_ca_cert_store;
	engine->base.add_root_ca = x509_mbedtls_add_root_ca;
	engine->base.add_intermediate_ca = x509_mbedtls_add_intermediate_ca;
	engine->base.authenticate = x509_mbedtls_authenticate;

	return 0;

exit:
	mbedtls_entropy_free (&engine->entropy);
	mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	return status;
}

/**
 * Release an mbedTLS X.509 engine.
 *
 * @param engine The X.509 engine to release.
 */
void x509_mbedtls_release (struct x509_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_entropy_free (&engine->entropy);
		mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	}
}
