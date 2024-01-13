// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_H_
#define AES_H_


#include <stddef.h>
#include <stdint.h>


/**
 * The length of AES-GCM authentication tags.
 */
#define	AES_TAG_LENGTH		16


/**
 * A platform-independent API for encrypting data using AES.  AES engine instances are not
 * guaranteed to be thread-safe across different API calls.
 */
struct aes_engine {
	/**
	 * Set the key to use for AES operations.  This must be called at least once before any
	 * encryption operation can be performed, and again if a different key should be used.
	 *
	 * @param engine The AES engine to configure.
	 * @param key The encryption key to use.  The key does not need to remain in scope for
	 * encryption and decryption operations.
	 * @param length The length of the key.
	 *
	 * @return 0 if the AES key was configured successfully or an error code.
	 */
	int (*set_key) (struct aes_engine *engine, const uint8_t *key, size_t length);

	/**
	 * Encrypt data using AES-GCM mode.  The operation must be initialized with a key prior to
	 * calling this function.
	 *
	 * @param engine The AES engine to use for encryption.
	 * @param plaintext The data to encrypt.
	 * @param length The amount of data to encrypt.
	 * @param iv The initialization vector to use for encryption.
	 * @param iv_length The length of the IV.  A 12-byte IV is best.
	 * @param ciphertext The buffer to hold the encrypted data.  The ciphertext will be the same
	 * length as the plaintext.  This buffer may be the same as the input plaintext buffer.
	 * @param out_length The size of the output buffer.
	 * @param tag The buffer to hold the GCM authentication tag.  All tags will be 16 bytes.
	 * @param tag_length The size of the tag output buffer.
	 *
	 * @return 0 if the data was encrypted successfully or an error code.
	 */
	int (*encrypt_data) (struct aes_engine *engine, const uint8_t *plaintext, size_t length,
		const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length, uint8_t *tag,
		size_t tag_length);

	/**
	 * Decrypt data using AES-GCM mode.  The operation must be initialized with a key prior to
	 * calling this function.
	 *
	 * @param engine The AES engine to use for decryption.
	 * @param ciphertext The encrypted data to decrypt.
	 * @param length The length of the encrypted data.
	 * @param tag The GCM tag for the ciphertext.  This must be 16 bytes.
	 * @param iv The initialization vector used to generate the ciphertext.
	 * @param iv_length The length of the IV.
	 * @param plaintext The buffer to hold the decrypted data.  The plaintext will be the same
	 * length as the ciphertext.  This buffer may be the same as the input ciphertext buffer.
	 * @param out_length The size of the output buffer.
	 *
	 * @return 0 if the data was decrypted successfully or an error code.
	 */
	int (*decrypt_data) (struct aes_engine *engine, const uint8_t *ciphertext, size_t length,
		const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
		size_t out_length);
};


#endif /* AES_H_ */
