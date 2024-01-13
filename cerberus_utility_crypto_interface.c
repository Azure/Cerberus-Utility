// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifdef CERBERUS_ENABLE_CRYPTO

#include <stdlib.h>
#include <string.h>
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_cerberus_protocol.h"
#include "cerberus_utility_api.h"
#include "cerberus_utility_commands_internal.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_crypto_interface.h"
#include "crypto/aes_mbedtls.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/hash_mbedtls.h"
#include "crypto/kdf.h"
#include "crypto/rsa_mbedtls.h"
#include "crypto/x509_mbedtls.h"


/**
 * Command to walk and verify the certificate chain
 *
 * @param intf The Cerberus interface to utilize
 * @param chain Certificate chain to verify
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_crypto_verify_cert_chain (struct cerberus_interface *intf,
	struct cerberus_cert_chain *chain, uint8_t *root_ca, size_t root_ca_len)
{
	struct x509_ca_certs certs_chain;
	struct x509_certificate cert;
	int8_t i_cert = 0;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	status = intf->crypto->x509.base.init_ca_cert_store (&intf->crypto->x509.base, &certs_chain);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "Faile to init CA certificate store, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	if (root_ca != NULL) {
		status = intf->crypto->x509.base.add_root_ca (&intf->crypto->x509.base, &certs_chain,
			root_ca, root_ca_len);
		if (status != STATUS_SUCCESS) {
			snprintf (errorstr, sizeof (errorstr), "Failed to add root CA , code: 0x%x",
				status);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				errorstr);
			goto release_cert_store;
		}
	}
	else {
		status = intf->crypto->x509.base.add_root_ca (&intf->crypto->x509.base, &certs_chain,
			chain->cert[0].cert, chain->cert[0].cert_len);
		if (status != STATUS_SUCCESS) {
			snprintf (errorstr, sizeof (errorstr), "Failed to add root CA , code: 0x%x",
				status);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				errorstr);
			goto release_cert_store;
		}

		++i_cert;
	}

	for (; i_cert < (chain->num_cert - 1); ++i_cert) {
		status = intf->crypto->x509.base.add_intermediate_ca (&intf->crypto->x509.base,
			&certs_chain, chain->cert[i_cert].cert, chain->cert[i_cert].cert_len);
		if (status != STATUS_SUCCESS) {
			snprintf (errorstr, sizeof (errorstr), "Failed to add Intermediate CA , code: 0x%x",
				status);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				errorstr);
			goto release_cert_store;
		}
	}

	status = intf->crypto->x509.base.load_certificate (&intf->crypto->x509.base, &cert,
		chain->cert[chain->num_cert - 1].cert, chain->cert[chain->num_cert - 1].cert_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "Failed to load certificate , code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_cert_store;
	}

	status = intf->crypto->x509.base.authenticate (&intf->crypto->x509.base, &cert, &certs_chain);
	intf->crypto->x509.base.release_certificate (&intf->crypto->x509.base, &cert);

	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
	}

release_cert_store:
	intf->crypto->x509.base.release_ca_cert_store (&intf->crypto->x509.base, &certs_chain);

	return status;
}

/**
 * Command to extract public key from a certificate
 *
 * @param intf The Cerberus interface to utilize
 * @param cert Buffer containing certificate
 * @param cert_len Certificate length
 * @param key Buffer to be allocated and filled with retrieved key. CALLER RESPONSIBLE FOR FREEING!!
 * @param key_len Length of key retrieved
 * @param key_type Type of key retrieved
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_crypto_get_public_key_from_cert (struct cerberus_interface *intf, uint8_t *cert,
	size_t cert_len, uint8_t **key, size_t *key_len, int *key_type)
{
	struct x509_certificate x509_cert;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	status = intf->crypto->x509.base.load_certificate (&intf->crypto->x509.base, &x509_cert, cert,
		cert_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "Failed to load certificate, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	status = intf->crypto->x509.base.get_public_key_type (&intf->crypto->x509.base, &x509_cert,
		key_type);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to get public key type from certificate, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_certificate;
	}

	status = intf->crypto->x509.base.get_public_key (&intf->crypto->x509.base, &x509_cert, key,
		key_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to get public key from certificate, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_certificate;
	}

release_certificate:
	intf->crypto->x509.base.release_certificate (&intf->crypto->x509.base, &x509_cert);

	return status;
}

/**
 * Verify RSA signature using provided RSA public key.
 *
 * @param intf The Cerberus interface to utilize.
 * @param key RSA public key to utilize.
 * @param key_len RSA public key length.
 * @param sig Signature to verify.
 * @param sig_len Signature length.
 * @param digest Digest of signed payload.
 * @param digest_len Digest length.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int cerberus_crypto_verify_rsa_signature (struct cerberus_interface *intf, uint8_t *key,
	size_t key_len, uint8_t *sig, size_t sig_len, uint8_t *digest, size_t digest_len)
{
	struct rsa_public_key cerberus_pub_key;
	struct rsa_engine_mbedtls rsa;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	status = rsa_mbedtls_init (&rsa);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "rsa init failed, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	status = rsa.base.init_public_key (&rsa.base, &cerberus_pub_key, key, key_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "rsa public key init failed, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_rsa;
	}

	status = rsa.base.sig_verify (&rsa.base, &cerberus_pub_key, sig, sig_len, digest, digest_len);
	if (status != STATUS_SUCCESS) {
		status = STATUS_SIG_VERIFY_FAIL;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
	}

release_rsa:
	rsa_mbedtls_release (&rsa);

	return status;
}

/**
 * Verify ECC signature using provided ECC public key.
 *
 * @param intf The Cerberus interface to utilize.
 * @param key ECC public key to utilize.
 * @param key_len ECC public key length.
 * @param sig Signature to verify.
 * @param sig_len Signature length.
 * @param digest Digest of signed payload.
 * @param digest_len Digest length.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int cerberus_crypto_verify_ecc_signature (struct cerberus_interface *intf, uint8_t *key,
	size_t key_len, uint8_t *sig, size_t sig_len, uint8_t *digest, size_t digest_len)
{
	struct ecc_public_key cerberus_pub_key;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	status = intf->crypto->ecc.base.init_public_key (&intf->crypto->ecc.base, key, key_len,
		&cerberus_pub_key);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "ECC public key init failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
	}

	status = intf->crypto->ecc.base.verify (&intf->crypto->ecc.base, &cerberus_pub_key, digest,
		digest_len, sig, sig_len);
	intf->crypto->ecc.base.release_key_pair (&intf->crypto->ecc.base, NULL, &cerberus_pub_key);

	if (status != STATUS_SUCCESS) {
		status = STATUS_SIG_VERIFY_FAIL;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
	}

	return status;
}

/**
 * Perform the Cerberus attestation challenge flow using keys received from Cerberus device.
 *
 * @param intf The Cerberus interface to utilize.
 * @param hash Hash engine to utilize.
 * @param key Public key to utilize.
 * @param key_len Public key length.
 * @param key_type Public key cryptographic algorithm.
 * @param util_nonce_buf 32 byte buffer to optionally retrieve nonce generated by the utility. Set
 *  to NULL if not needed.
 * @param device_nonce_buf 32 byte buffer to optionally retrieve nonce generated by the device. Set
 *  to NULL if not needed.
 * @param pmr0_buf Buffer to optionally retrieve the device's PMR0 value. Set to NULL if not needed.
 * @param pmr0_buf_len  pmro_buff buffer length. Set to 0 if not needed.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int cerberus_crypto_perform_attestation_challenge (struct cerberus_interface *intf,
	struct hash_engine *hash, uint8_t *key, size_t key_len, int key_type, uint8_t *util_nonce_buf,
	uint8_t *device_nonce_buf, uint8_t *pmr0_buf, size_t pmr0_buf_len)
{
	uint8_t challenge[CERBERUS_CHALLENGE_NONCE_LEN + 2];
	uint8_t digest[SHA256_HASH_LENGTH];
	size_t response_len = 8 + CERBERUS_CHALLENGE_NONCE_LEN + CERBERUS_PCR_LEN;
	size_t payload_len;
	size_t sig_len;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	// Generate and send attestation challenge
	challenge[0] = 0;
	challenge[1] = 0;

	status = intf->crypto->rng.base.generate_random_buffer (&intf->crypto->rng.base,
		CERBERUS_CHALLENGE_NONCE_LEN, &challenge[2]);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "RNG generate buffer failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	memcpy (intf->cmd_buf, challenge, sizeof (challenge));

	payload_len = CERBERUS_CHALLENGE_NONCE_LEN + 2;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, intf->params->device_eid, false, intf->cmd_buf,
		&payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len <= response_len) {
		status = STATUS_UNEXPECTED_RLEN;
		snprintf (errorstr, sizeof (errorstr), cerberus_utility_get_errors_str (status),
			payload_len, response_len);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	sig_len = payload_len - response_len;

	// Process attestation response
	if (intf->cmd_buf[0] != 0) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), 0, intf->cmd_buf[0]);
		return STATUS_CMD_RESPONSE;
	}

	if (intf->cmd_buf[1] != 1) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), 1, intf->cmd_buf[1]);
		return STATUS_CMD_RESPONSE;
	}

	if ((intf->cmd_buf[2] > CERBERUS_PROTOCOL_MAX_VERSION) ||
		(intf->cmd_buf[3] < CERBERUS_PROTOCOL_MIN_VERSION)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_PROTOCOL_INCOMPATIBLE), intf->cmd_buf[3]);
		return STATUS_PROTOCOL_INCOMPATIBLE;
	}

	// Verify signature of response
	status = hash->start_sha256 (hash);
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			"Hash start failed, code: 0x%0x", status);
		return status;
	}

	status = hash->update (hash, challenge, sizeof (challenge));
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			"Hash update failed, code: 0x%0x", status);
		goto hash_cancel;
	}

	status = hash->update (hash, intf->cmd_buf, response_len);
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			"Hash update failed, code: 0x%0x", status);
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			"Hash finish failed, code: 0x%0x", status);
		goto hash_cancel;
	}

	if (key_type == X509_PUBLIC_KEY_ECC) {
		status = cerberus_crypto_verify_ecc_signature (intf, key,
			key_len, &intf->cmd_buf[response_len], sig_len, digest, sizeof (digest));
	}
	else if (key_type == X509_PUBLIC_KEY_RSA) {
		status = cerberus_crypto_verify_rsa_signature (intf, key,
			key_len, &intf->cmd_buf[response_len], sig_len, digest, sizeof (digest));
	}
	else {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
		return STATUS_UNSUPPORTED_OPERATION;
	}

	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (util_nonce_buf != NULL) {
		memcpy (util_nonce_buf, &challenge[2], CERBERUS_CHALLENGE_NONCE_LEN);
	}

	if (device_nonce_buf != NULL) {
		memcpy (device_nonce_buf, &intf->cmd_buf[6], CERBERUS_CHALLENGE_NONCE_LEN);
	}

	if (pmr0_buf != NULL) {
		memcpy (pmr0_buf, &intf->cmd_buf[8 + CERBERUS_CHALLENGE_NONCE_LEN], pmr0_buf_len);
	}

	return status;

hash_cancel:
	hash->cancel (hash);
	return status;
}

/**
 * Use provided Cerberus public key and nonce along with utility generated private key to generate
 * shared AES key and HMAC key for session encryption.
 *
 * @param intf The Cerberus interface to utilize.
 * @param ecc ECC engine to utilize.
 * @param hash Hash engine to utilize.
 * @param priv_key Utility ECC private key.
 * @param pub_key Cerberus ECC public key.
 * @param pub_key_len Cerberus ECC public key length.
 * @param util_nonce Random nonce generated by utility used for AES key generation.
 * @param device_nonce Random nonce generated by device used for AES key generation.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int cerberus_crypto_generate_encrypted_session_keys (struct cerberus_interface *intf,
	struct ecc_engine *ecc, struct hash_engine *hash, struct ecc_private_key *priv_key,
	const uint8_t *pub_key, size_t pub_key_len, uint8_t *util_nonce, uint8_t *device_nonce)
{
	uint8_t *shared_secret;
	struct ecc_public_key public_key;
	size_t secret_len;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	status = ecc->init_public_key (ecc, pub_key, pub_key_len, &public_key);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "ECC public key init failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	status = ecc->get_shared_secret_max_length (ecc, priv_key, &secret_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"ECC failure to get shared secret max length, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto free_public_key;
	}

	shared_secret = (uint8_t*) malloc (secret_len);
	if (shared_secret == NULL) {
		status = STATUS_NO_MEM;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
		goto free_public_key;
	}

	status = ecc->compute_shared_secret (ecc, priv_key, &public_key, shared_secret, &secret_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"ECC failure to compute shared secret, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto free_shared_secret;
	}

	status = kdf_nist800_108_counter_mode (hash, HMAC_SHA256, shared_secret, (uint32_t) secret_len,
		util_nonce, CERBERUS_CHALLENGE_NONCE_LEN, device_nonce, CERBERUS_CHALLENGE_NONCE_LEN,
		intf->crypto->session_key, sizeof (intf->crypto->session_key));
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Fail to get generate key using NIST SP800-108, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto free_shared_secret;
	}

	status = kdf_nist800_108_counter_mode (hash, HMAC_SHA256, shared_secret, (uint32_t) secret_len,
		device_nonce, CERBERUS_CHALLENGE_NONCE_LEN, util_nonce, CERBERUS_CHALLENGE_NONCE_LEN,
		intf->crypto->hmac_key, sizeof (intf->crypto->hmac_key));
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Fail to get generate key using NIST SP800-108, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
	}

free_shared_secret:
	free (shared_secret);

free_public_key:
	ecc->release_key_pair (ecc, NULL, &public_key);

	return status;
}

/**
 * Encrypt a Cerberus protocol message
 *
 * @param intf The Cerberus interface to utilize
 * @param payload Plaintext message to be encrypted. Encrypted message following the Cerberus
 * 	protocol format will be stored in the same buffer, with a CERBERUS_PROTOCOL_AES_GCM_TAG_LEN GCM
 *  tag and CERBERUS_PROTOCOL_AES_IV_LEN IV at the end.
 * @param payload_len Plaintext data length.
 * @param buffer_len Maximum buffer length incoming, and encrypted message length outgoing.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_crypto_interface_encrypt_payload (struct cerberus_interface *intf, uint8_t *payload,
	size_t payload_len, size_t *buffer_len)
{
	uint8_t *aes_iv;
	size_t trailer_len = CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if ((payload_len + trailer_len) > *buffer_len) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
		return STATUS_BUF_TOO_SMALL;
	}

	aes_iv = payload + payload_len + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN;

	status = cerberus_common_increment_byte_array (intf->crypto->aes_init_vector,
		CERBERUS_PROTOCOL_AES_IV_LEN, false);
	if ((status != STATUS_SUCCESS) || ((intf->crypto->aes_init_vector[11] & 0x80) == 0x80)) {
		snprintf (errorstr, sizeof (errorstr), "AES Initilization Vector generation failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	memcpy (aes_iv, intf->crypto->aes_init_vector, CERBERUS_PROTOCOL_AES_IV_LEN);

	status = intf->crypto->aes.base.encrypt_data (&intf->crypto->aes.base, payload, payload_len,
		aes_iv, CERBERUS_PROTOCOL_AES_IV_LEN, payload, *buffer_len - trailer_len,
		payload + payload_len, CERBERUS_PROTOCOL_AES_GCM_TAG_LEN);
	if (status == STATUS_SUCCESS) {
		*buffer_len = payload_len + trailer_len;
	}
	else {
		snprintf (errorstr, sizeof (errorstr), "AES encrypt data failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
	}

	return status;
}

/**
 * Decrypt a Cerberus protocol message
 *
 * @param intf The Cerberus interface to utilize
 * @param payload Encrypted message received from device to decrypt. The message is expected to
 * 	follow the Cerberus protocol format, with a CERBERUS_PROTOCOL_AES_GCM_TAG_LEN GCM tag and
 * 	CERBERUS_PROTOCOL_AES_IV_LEN IV at the end.
 * @param payload_len Encrypted payload length incoming, and decrypted payload length outgoing.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_crypto_interface_decrypt_payload (struct cerberus_interface *intf, uint8_t *payload,
	size_t *payload_len)
{
	size_t trailer_len = CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (*payload_len == 0) {
		return STATUS_SUCCESS;
	}

	if (*payload_len < trailer_len) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
		return STATUS_BUF_TOO_SMALL;
	}

	*payload_len = *payload_len - trailer_len;

	status = intf->crypto->aes.base.decrypt_data (&intf->crypto->aes.base, payload, *payload_len,
		payload + *payload_len, payload + *payload_len + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN,
		CERBERUS_PROTOCOL_AES_IV_LEN, payload, *payload_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "AES decrypt data failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
	}

	return status;
}

/**
 * Setup an encrypted channel using Cerberus crypto interface
 *
 * @param intf The Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_crypto_interface_setup_encrypted_channel (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len)
{
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	uint8_t *pub_key_der;
	uint8_t *key;
	size_t key_len;
	struct cerberus_cert_chain cerberus_chain;
	uint8_t keys_digest[SHA256_HASH_LENGTH];
	uint8_t rn1[CERBERUS_CHALLENGE_NONCE_LEN];
	uint8_t rn2[CERBERUS_CHALLENGE_NONCE_LEN];
	uint8_t computed_hmac[SHA256_HASH_LENGTH];
	uint8_t *pkresp;
	uint16_t pkresp_len;
	uint8_t *sig_buf;
	uint16_t sig_len;
	uint8_t *hmac_buf;
	uint16_t hmac_len;
	size_t pub_key_der_len;
	size_t payload_len;
	int key_type;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (((intf->remote.device_info & CERBERUS_DEVICE_AUTH) == 0) ||
		((intf->remote.pk_key_strength & intf->local.pk_key_strength) == 0) ||
		((intf->remote.enc_key_strength & intf->local.enc_key_strength) == 0)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
		return STATUS_UNSUPPORTED_OPERATION;
	}

	memset (intf->crypto->aes_init_vector, 0, CERBERUS_PROTOCOL_AES_IV_LEN);

	status = cerberus_get_cert_chain_with_key_exchange (intf, 0, &cerberus_chain,
		CERBERUS_ECDHE_KEY_EXCHANGE);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_crypto_verify_cert_chain (intf, &cerberus_chain, root_ca, root_ca_len);
	if (status != STATUS_SUCCESS) {
		goto release_cert_chain;
	}

	status = cerberus_crypto_get_public_key_from_cert (intf,
		cerberus_chain.cert[cerberus_chain.num_cert - 1].cert,
		cerberus_chain.cert[cerberus_chain.num_cert - 1].cert_len, &key, &key_len, &key_type);
	if (status != STATUS_SUCCESS) {
		goto release_cert_chain;
	}

	status = cerberus_crypto_perform_attestation_challenge (intf, &intf->crypto->hash.base, key,
		key_len, key_type, rn1, rn2, NULL, 0);
	if (status != STATUS_SUCCESS) {
		goto release_key;
	}

	status = intf->crypto->ecc.base.generate_key_pair (&intf->crypto->ecc.base, &priv_key,
		&pub_key);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "ECC key pair generation failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_key;
	}

	status = intf->crypto->ecc.base.get_public_key_der (&intf->crypto->ecc.base, &pub_key,
		&pub_key_der, &pub_key_der_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "ECC failed to get public key, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_key_pair;
	}

	intf->cmd_buf[0] = CERBERUS_PROTOCOL_SESSION_KEY;
	intf->cmd_buf[1] = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (&intf->cmd_buf[2], pub_key_der, pub_key_der_len);

	payload_len = 2 + pub_key_der_len;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_EXCHANGE_KEYS, intf->params->device_eid, true, intf->cmd_buf,
		&payload_len);
	if (status != STATUS_SUCCESS) {
		goto release_pub_key_der;
	}

	if (intf->cmd_buf[0] != CERBERUS_PROTOCOL_SESSION_KEY) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), CERBERUS_PROTOCOL_SESSION_KEY,
			intf->cmd_buf[0]);
		status = STATUS_CMD_RESPONSE;
		goto release_pub_key_der;
	}

	if (payload_len <= (2 + sizeof (uint16_t))) {
		snprintf (errorstr, sizeof (errorstr),
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len, 5);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		status = STATUS_UNEXPECTED_RLEN;
		goto release_pub_key_der;
	}

	memcpy (&pkresp_len, &intf->cmd_buf[2], sizeof (uint16_t));

	if (payload_len <= (2 + sizeof (uint16_t) + pkresp_len)) {
		snprintf (errorstr, sizeof (errorstr),
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len, pkresp_len + 5);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		status = STATUS_UNEXPECTED_RLEN;
		goto release_pub_key_der;
	}

	pkresp = &intf->cmd_buf[2 + sizeof (uint16_t)];
	memcpy (&sig_len, &intf->cmd_buf[2 + sizeof (uint16_t) + pkresp_len], sizeof (uint16_t));

	if (payload_len <= (2 + sizeof (uint16_t) * 2 + pkresp_len + sig_len)) {
		snprintf (errorstr, sizeof (errorstr),
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len,
			sig_len + pkresp_len + 7);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		status = STATUS_UNEXPECTED_RLEN;
		goto release_pub_key_der;
	}

	sig_buf = &intf->cmd_buf[2 + sizeof (uint16_t) * 2 + pkresp_len];
	memcpy (&hmac_len, &intf->cmd_buf[2 + sizeof (uint16_t) * 2 + pkresp_len + sig_len],
		sizeof (uint16_t));

	if (payload_len != (2 + sizeof (uint16_t) * 3 + pkresp_len + sig_len + hmac_len)) {
		snprintf (errorstr, sizeof (errorstr),
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len,
			hmac_len + sig_len + pkresp_len + 8);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		status = STATUS_UNEXPECTED_RLEN;
		goto release_pub_key_der;
	}

	hmac_buf = &intf->cmd_buf[2 + sizeof (uint16_t) * 3 + pkresp_len + sig_len];

	status = intf->crypto->hash.base.start_sha256 (&intf->crypto->hash.base);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 Hash engine failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_pub_key_der;
	}

	status = intf->crypto->hash.base.update (&intf->crypto->hash.base, pub_key_der,
		pub_key_der_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 Hash data update failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		intf->crypto->hash.base.cancel (&intf->crypto->hash.base);
		goto release_pub_key_der;
	}

	status = intf->crypto->hash.base.update (&intf->crypto->hash.base, pkresp, pkresp_len);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 Hash data update failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		intf->crypto->hash.base.cancel (&intf->crypto->hash.base);
		goto release_pub_key_der;
	}

	status = intf->crypto->hash.base.finish (&intf->crypto->hash.base, keys_digest,
		sizeof (keys_digest));
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 Hash failed to complete, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		intf->crypto->hash.base.cancel (&intf->crypto->hash.base);
		goto release_pub_key_der;
	}

	status = cerberus_crypto_verify_ecc_signature (intf, key, key_len, sig_buf, sig_len,
		keys_digest, sizeof (keys_digest));
	if (status != STATUS_SUCCESS) {
		goto release_pub_key_der;
	}

	status = cerberus_crypto_generate_encrypted_session_keys (intf, &intf->crypto->ecc.base,
		&intf->crypto->hash.base, &priv_key, pkresp, pkresp_len, (uint8_t*) rn1, (uint8_t*) rn2);
	if (status != STATUS_SUCCESS) {
		goto release_pub_key_der;
	}

	status = hash_generate_hmac (&intf->crypto->hash.base, intf->crypto->hmac_key,
		sizeof (intf->crypto->hmac_key), cerberus_chain.cert[cerberus_chain.num_cert - 1].cert,
		cerberus_chain.cert[cerberus_chain.num_cert - 1].cert_len, HMAC_SHA256, computed_hmac,
		sizeof (computed_hmac));
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 HMAC generation failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto release_pub_key_der;
	}

	if (memcmp (computed_hmac, hmac_buf, sizeof (computed_hmac)) == 0) {
		status = intf->crypto->aes.base.set_key (&intf->crypto->aes.base,
			intf->crypto->session_key, sizeof (intf->crypto->session_key));
		if (status != STATUS_SUCCESS) {
			snprintf (errorstr, sizeof (errorstr),
				"Failed to set key for AES operations, code: 0x%x", status);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, errorstr);
			goto release_pub_key_der;
		}

		intf->session_encrypted = true;
	}
	else {
		status = STATUS_SESSION_ESTABLISHMENT_FAILED;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
	}


release_pub_key_der:
	free (pub_key_der);

release_key_pair:
	intf->crypto->ecc.base.release_key_pair (&intf->crypto->ecc.base, &priv_key, &pub_key);

release_key:
	free (key);

release_cert_chain:
	cerberus_free_cert_chain (&cerberus_chain);

	return status;
}

/**
 * Close active encrypted channel.
 *
 * @param intf The Cerberus interface to utilize.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_crypto_interface_close_encrypted_channel (struct cerberus_interface *intf)
{
	size_t payload_len;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (!intf->session_encrypted) {
		return STATUS_SUCCESS;
	}

	intf->cmd_buf[0] = CERBERUS_PROTOCOL_DELETE_SESSION_KEY;

	status = hash_generate_hmac (&intf->crypto->hash.base, intf->crypto->hmac_key,
		sizeof (intf->crypto->hmac_key), intf->crypto->session_key,
		sizeof (intf->crypto->session_key), HMAC_SHA256, &intf->cmd_buf[1],
		cerberus_protocol_get_max_payload_len_per_msg (intf) - 1);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 HMAC generation failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	payload_len = 1 + CERBERUS_SHA256_HASH_LEN;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_EXCHANGE_KEYS, intf->params->device_eid, true, intf->cmd_buf,
		&payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len != 1) {
		snprintf (errorstr, sizeof (errorstr),
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len, 1);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return STATUS_UNEXPECTED_RLEN;
	}

	if (intf->cmd_buf[0] != CERBERUS_PROTOCOL_DELETE_SESSION_KEY) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), CERBERUS_PROTOCOL_DELETE_SESSION_KEY,
			intf->cmd_buf[0]);
		return STATUS_CMD_RESPONSE;
	}

	memset (intf->crypto->session_key, 0, sizeof (intf->crypto->session_key));

	intf->session_encrypted = false;

	return status;
}

/**
 * Perform the Cerberus attestation challenge flow on Cerberus device.
 *
 * @param intf The Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 * @param pmr0_buf Buffer to optionally retrieve the device's PMR0 value. Set to NULL if not needed.
 * @param pmr0_buf_len  pmro_buff buffer length. set to 0 if not needed.
 *
 * @return Completion status, 0 if success or an error code.
 */
int cerberus_crypto_interface_attestation_challenge (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len, uint8_t *pmr0_buf, size_t pmr0_buf_len)
{
	struct cerberus_cert_chain cerberus_chain;
	uint8_t *key;
	size_t key_len;
	int key_type;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_cert_chain_with_key_exchange (intf, 0, &cerberus_chain,
		CERBERUS_KEYS_EXCHANGE_NONE);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_crypto_verify_cert_chain (intf, &cerberus_chain, root_ca, root_ca_len);
	if (status != STATUS_SUCCESS) {
		goto release_cert_chain;
	}

	status = cerberus_crypto_get_public_key_from_cert (intf,
		cerberus_chain.cert[cerberus_chain.num_cert - 1].cert,
		cerberus_chain.cert[cerberus_chain.num_cert - 1].cert_len, &key, &key_len, &key_type);
	if (status != STATUS_SUCCESS) {
		goto release_cert_chain;
	}

	status = cerberus_crypto_perform_attestation_challenge (intf, &intf->crypto->hash.base, key,
		key_len, key_type, NULL, NULL, pmr0_buf, pmr0_buf_len);

	free (key);

release_cert_chain:
	cerberus_free_cert_chain (&cerberus_chain);

	return status;
}

/**
 * Setup a paired session with device binding using Cerberus crypto interface
 *
 * @param intf The Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_crypto_interface_setup_device_bindings (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len)
{
	char* label_str = "pairing";
	uint8_t label[CERBERUS_SESSION_KEY_LEN];
	uint16_t pairing_key_len;
	size_t payload_len;
	size_t msg_len;
	size_t r_len;
	int i_retry = 0;
	uint8_t mctp_fail_type = STATUS_SUCCESS;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	pairing_key_len = (uint16_t) sizeof (intf->crypto->pairing_key);

	status = cerberus_setup_encrypted_channel (intf, root_ca, root_ca_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = kdf_nist800_108_counter_mode (&intf->crypto->hash.base, HMAC_SHA256,
		intf->crypto->session_key, (uint32_t) sizeof (intf->crypto->session_key),
		(const uint8_t*) label_str, strlen (label_str), NULL, 0, intf->crypto->pairing_key,
		sizeof (intf->crypto->pairing_key));
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Fail to get generate key using NIST SP800-108, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	intf->cmd_buf[0] = CERBERUS_PROTOCOL_PAIRED_KEY_HMAC;

	memcpy (&intf->cmd_buf[1], &pairing_key_len, sizeof (pairing_key_len));

	status = hash_generate_hmac (&intf->crypto->hash.base, intf->crypto->hmac_key,
		sizeof (intf->crypto->hmac_key), intf->crypto->pairing_key,
		sizeof (intf->crypto->pairing_key), HMAC_SHA256, &intf->cmd_buf[3],
		cerberus_protocol_get_max_payload_len_per_msg (intf) - 3);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr), "SHA-256 HMAC generation failed, code: 0x%x",
			status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		return status;
	}

	payload_len = 3 + CERBERUS_SHA256_HASH_LEN;

	status = cerberus_device_mutex_lock (intf, CERBERUS_MUTEX_TIMEOUT_MS);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		status = cerberus_protocol_prepare_send_msg (intf, CERBERUS_PROTOCOL_EXCHANGE_KEYS,
			intf->cmd_buf, payload_len, &msg_len);
		if (status != STATUS_SUCCESS) {
			goto done;
		}

		status = intf->mctp_intf_msg_transaction (intf, intf->params->device_eid, intf->msg_buf, msg_len,
			intf->params->device_eid, true, intf->msg_buf, &r_len, &mctp_fail_type);
		if (status == STATUS_SUCCESS) {
			memcpy (label, intf->crypto->session_key, sizeof (label));

			status = kdf_nist800_108_counter_mode (&intf->crypto->hash.base, HMAC_SHA256,
				intf->crypto->pairing_key, (uint32_t) sizeof (intf->crypto->pairing_key), label,
				sizeof (label), NULL, 0, intf->crypto->session_key, sizeof (intf->crypto->session_key));
			if (status != STATUS_SUCCESS) {
				snprintf (errorstr, sizeof (errorstr),
					"Fail to get generate key using NIST SP800-108, code: 0x%x", status);
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
					errorstr);
				goto done;
			}

			status = intf->crypto->aes.base.set_key (&intf->crypto->aes.base, intf->crypto->session_key,
				sizeof (intf->crypto->session_key));
			if (status != STATUS_SUCCESS) {
				snprintf (errorstr, sizeof (errorstr),
					"Failed to set key for AES operations, code: 0x%x", status);
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
 					__LINE__, errorstr);
				goto done;
			}

			status = cerberus_protocol_process_read_variable_msg (intf, __func__, __LINE__,
				CERBERUS_PROTOCOL_EXCHANGE_KEYS, intf->msg_buf, r_len, intf->cmd_buf, &payload_len,
				NULL, NULL);
			if (status == STATUS_SUCCESS) {
 				break;
			}
		}
		else {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status));
			status = mctp_fail_type;
		}

		cerberus_common_sleep_ms (CERBERUS_CMD_RETRY_WAIT_TIME_MS);
	} while (i_retry++ < intf->params->num_mctp_retries);

	if (status != STATUS_SUCCESS) {
		goto done;
	}

	if (payload_len != 1) {
		snprintf (errorstr, sizeof (errorstr),
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len, 1);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		status = STATUS_UNEXPECTED_RLEN;
		goto done;
	}

	if (intf->cmd_buf[0] != CERBERUS_PROTOCOL_PAIRED_KEY_HMAC) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), CERBERUS_PROTOCOL_PAIRED_KEY_HMAC,
			intf->cmd_buf[0]);
		status = STATUS_CMD_RESPONSE;
	}

done:
	cerberus_device_mutex_unlock (intf);
	return status;
}

/**
 * Initialize cerberus crypto interface instance
 *
 * @param intf The Cerberus interface instance to be initialized with crypto interface.  MUST BE
 * FREED BY CALLER using crypto_interface_deinit ().
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_crypto_interface_init (struct cerberus_interface *intf)
{
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf->crypto =
		(struct cerberus_crypto_interface*) malloc (sizeof (struct cerberus_crypto_interface));
	if (intf->crypto == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	status = aes_mbedtls_init (&intf->crypto->aes);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to init AES engine, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, errorstr);
		return status;
	}

	status = rng_mbedtls_init (&intf->crypto->rng);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to init RNG engine, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, errorstr);
		aes_mbedtls_release (&intf->crypto->aes);
		return status;
	}

	status = hash_mbedtls_init (&intf->crypto->hash);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to init Hash engine, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, errorstr);
		hash_mbedtls_release (&intf->crypto->hash);
		return status;
	}

	status = ecc_mbedtls_init (&intf->crypto->ecc);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to init ECC engine, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, errorstr);
		ecc_mbedtls_release (&intf->crypto->ecc);
		return status;
	}

	status = x509_mbedtls_init (&intf->crypto->x509);
	if (status != STATUS_SUCCESS) {
		snprintf (errorstr, sizeof (errorstr),
			"Failed to init x509 engine, code: 0x%x", status);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, errorstr);
		x509_mbedtls_release (&intf->crypto->x509);
		return status;
	}

	return STATUS_SUCCESS;
}

/** Release Cerberus interface crypto instance
 *
 * @param intf The cerberus interface instance containing initialized crypto instance
 *
 */
void cerberus_crypto_interface_deinit (struct cerberus_interface *intf)
{
	if ((intf != NULL) && (intf->crypto != NULL)) {
		aes_mbedtls_release (&intf->crypto->aes);
		rng_mbedtls_release (&intf->crypto->rng);
		hash_mbedtls_release (&intf->crypto->hash);
		ecc_mbedtls_release (&intf->crypto->ecc);
		x509_mbedtls_release (&intf->crypto->x509);

		free (intf->crypto);
	}
}

#endif
