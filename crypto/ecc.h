// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_H_
#define ECC_H_


#include <stdint.h>
#include <stddef.h>


/**
 * An ECC private key.  A key instance is only usable by the engine that initialized it.
 */
struct ecc_private_key {
	void *context;		/**< The implementation context for the private key. */
};

/**
 * An ECC public key.  A key instance is only usable by the engine that initialized it.
 */
struct ecc_public_key {
	void *context;		/**< The implementation context for the public key. */
};

/**
 * A platform-independent API for generating and using ECC key pairs.  ECC engine instances are not
 * guaranteed to be thread-safe across different API calls.
 */
struct ecc_engine {
	/**
	 * Initialize an ECC key pair to be used by the ECC engine.
	 *
	 * @param engine The ECC engine to use for key initialization.
	 * @param key The private key to use for key initialization.
	 * @param key_length The length of the private key data.
	 * @param priv_key Output for the initialized private key.  This can be null to skip private key
	 * initialization.
	 * @param pub_key Output for the initialized public key.  This can be null to skip public key
	 * initialization.
	 *
	 * @return 0 if the key pair was successfully initialized or an error code.
	 */
	int (*init_key_pair) (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
		struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);

	/**
	 * Initialize an ECC public key to be used by the ECC engine.
	 *
	 * @param engine The ECC engine to use for key initialization.
	 * @param key The public key to use for key initialization.
	 * @param key_length The length of the public key data.
	 * @param pub_key Output for the initialized public key.
	 *
	 * @return 0 if the public key was successfully initialized or an error code.
	 */
	int (*init_public_key) (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
		struct ecc_public_key *pub_key);

	/**
	 * Generate an ECC key pair using a specified value for the private key.
	 *
	 * @param engine The ECC engine to use to generate the key pair.
	 * @param priv The private value to use for key generation.
	 * @param key_length The length of the private key.
	 * @param priv_key Output for the generated private key.  This can be null to skip private key
	 * generation.
	 * @param pub_key Output for the generated public key.  This can be null to skip public key
	 * generation.
	 *
	 * @return 0 if the key pair was successfully generated or an error code.
	 */
	int (*generate_derived_key_pair) (struct ecc_engine *engine, const uint8_t *priv,
		size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);

	/**
	 * Generate a random ECC key pair.
	 *
	 * @param engine The ECC engine to use to generate the key pair.
	 * @param priv_key Output for the generated private key.  This can be null to skip private key
	 * generation.
	 * @param pub_key Output for the generated public key.  This can be null to skip public key
	 * generation.
	 *
	 * @return 0 if the key pair was successfully generated or an error code.
	 */
	int (*generate_key_pair) (struct ecc_engine *engine, struct ecc_private_key *priv_key,
		struct ecc_public_key *pub_key);

	/**
	 * Release ECC keys.  The memory for released keys will be zeroed.
	 *
	 * @param engine The ECC engine used to generated the keys.
	 * @param priv_key The private key to release.  This can be null to not release a private key.
	 * @param pub_key The public key to release.  This can be null to not release a public key.
	 */
	void (*release_key_pair) (struct ecc_engine *engine, struct ecc_private_key *priv_key,
		struct ecc_public_key *pub_key);

	/**
	 * Get the maximum length for a ECDSA signature generated using a given key.
	 *
	 * @param engine The ECC engine to query.
	 * @param key The private key that would be used for the signature.
	 * @param max_len Container for the maximum number of signature bytes.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_signature_max_length) (struct ecc_engine *engine, struct ecc_private_key *key, 
		size_t *max_len);

	/**
	 * Encode an ECC private key in DER format.
	 *
	 * @param engine The ECC engine used to generate the key.
	 * @param key The private key to encode to DER.
	 * @param der Output buffer for the DER formatted private key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_private_key_der) (struct ecc_engine *engine, const struct ecc_private_key *key,
		uint8_t **der, size_t *length);

	/**
	 * Encode an ECC public key in DER format.
	 *
	 * @param engine The ECC engine used to generate the key.
	 * @param key The public key to encode to DER.
	 * @param der Output buffer for the DER formatted public key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_public_key_der) (struct ecc_engine *engine, const struct ecc_public_key *key,
		uint8_t **der, size_t *length);

	/**
	 * Create an ECDSA signature for a SHA-256 message digest.
	 *
	 * @param engine The ECC engine to use to sign the digest.
	 * @param key The private key to sign with.
	 * @param digest The message digest to use to generate the signature.
	 * @param length The length of the digest.
	 * @param signature Output buffer for the ECDSA signature.
	 * @param sig_length Container with the length of the signature buffer incoming, and actual 
	 * signature length afer returning.
	 *
	 * @return 0 if completed successfully or an error code.
	 */
	int (*sign) (struct ecc_engine *engine, struct ecc_private_key *key, const uint8_t *digest,
		size_t length, uint8_t *signature, size_t *sig_length);

	/**
	 * Verify an ECDSA signature against a SHA-256 message digest.
	 *
	 * @param engine The ECC engine to use for signature verification.
	 * @param key The public key to verify the signature with.
	 * @param digest The message digest to use for signature verification.
	 * @param length The length of the digest.
	 * @param signature The ECDSA signature to verify.
	 * @param sig_length The length of the signature.
	 *
	 * @return 0 if the signature matches the digest or an error code.
	 */
	int (*verify) (struct ecc_engine *engine, struct ecc_public_key *key, const uint8_t *digest,
		size_t length, const uint8_t *signature, size_t sig_length);

	/**
	 * Get the maximum length for an ECDH shared secret generated using a given key.
	 *
	 * @param engine The ECC engine to query.
	 * @param key The private key that would be used to generate the secret.
	 * @param max_secret_len Container for the maximum secret length.
	 *
	 * @return 0 if completed successfully or an error code.
	 */
	int (*get_shared_secret_max_length) (struct ecc_engine *engine, struct ecc_private_key *key,
		size_t *max_secret_len);

	/**
	 * Generate the ECDH shared secret for a pair of keys.
	 *
	 * @param engine The ECC engine to use to generate the secret.
	 * @param priv_key The private key to use to generate the secret.
	 * @param pub_key The public key to use to generate the secret.
	 * @param secret Output buffer to hold the generated secret.  This is the raw data generated by
	 * ECDH which can be fed into additional key derivation functions, as appropriate.
	 * @param secret_len Container with the length of the secret buffer incoming, and actual secret 
	 * length afer returning.
	 *
	 * @return 0 if completed successfully or an error code.
	 */
	int (*compute_shared_secret) (struct ecc_engine *engine, struct ecc_private_key *priv_key,
		struct ecc_public_key *pub_key, uint8_t *secret, size_t *secret_len);
};


#endif /* ECC_H_ */
