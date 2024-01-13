// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_CRYPTO_INTERFACE_
#define CERBERUS_UTILITY_CRYPTO_INTERFACE_

#include <stdint.h>
#include <stdbool.h>
#include "cerberus_utility_cerberus_protocol.h"
#include "cerberus_utility_interface.h"
#include "crypto/aes_mbedtls.h"
#include "crypto/rng_mbedtls.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/hash_mbedtls.h"
#include "crypto/x509_mbedtls.h"


#ifdef __cplusplus
extern "C" {
#endif


#define CERBERUS_SESSION_KEY_LEN			32
#define CERBERUS_HMAC_KEY_LEN				32


/**
 * Interface for encrypted communication with Cerberus.
 */
struct cerberus_crypto_interface {
	struct aes_engine_mbedtls aes;							/**< AES engine to use for session encryption */
	struct rng_engine_mbedtls rng;							/**< RNG engine to use for session encryption */
	struct hash_engine_mbedtls hash;						/**< Hash engine to use for session encryption */
	struct ecc_engine_mbedtls ecc;							/**< ECC engine to use for session encryption */
	struct x509_engine_mbedtls x509;						/**< x509 engine to use for session encryption */
	uint8_t session_key[CERBERUS_SESSION_KEY_LEN];			/**< Buffer for the session key */
	uint8_t pairing_key[CERBERUS_SESSION_KEY_LEN];			/**< Buffer for the pairing key */
	uint8_t hmac_key[CERBERUS_HMAC_KEY_LEN];				/**< Buffer for the HMAC key */
	uint8_t aes_init_vector[CERBERUS_PROTOCOL_AES_IV_LEN];	/**< AES Initialization vector used in encryption */
};


int cerberus_crypto_interface_init (struct cerberus_interface *intf);
void cerberus_crypto_interface_deinit (struct cerberus_interface *intf);

int cerberus_crypto_interface_encrypt_payload (struct cerberus_interface *intf, uint8_t *payload,
	size_t payload_len, size_t *buffer_len);
int cerberus_crypto_interface_decrypt_payload (struct cerberus_interface *intf, uint8_t *payload,
	size_t *payload_len);

int cerberus_crypto_interface_setup_encrypted_channel (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len);
int cerberus_crypto_interface_close_encrypted_channel (struct cerberus_interface *intf);

int cerberus_crypto_interface_setup_device_bindings (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len);

int cerberus_crypto_interface_attestation_challenge (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len, uint8_t *pmr0_buf, size_t pmr0_buf_len);

#ifdef __cplusplus
}
#endif


#endif //CERBERUS_UTILITY_CRYPTO_INTERFACE_