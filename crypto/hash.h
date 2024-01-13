// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_H_
#define HASH_H_


#include <stddef.h>
#include <stdint.h>


/* Hash lengths */
#define	SHA1_HASH_LENGTH	(160 / 8)
#define SHA256_HASH_LENGTH	(256 / 8)

#define	SHA1_BLOCK_SIZE		(512 / 8)
#define	SHA256_BLOCK_SIZE	(512 / 8)

/* Definitions of hash engine state for internal implementation use, as necessary. */
enum {
	HASH_ACTIVE_NONE = 0,	/**< No hash context is active. */
	HASH_ACTIVE_SHA1,		/**< SHA-1 context is active. */
	HASH_ACTIVE_SHA256,		/**< SHA-256 context is active. */
};


/**
 * The types of hashes supported by the hashing API.
 */
enum hash_type {
	HASH_TYPE_SHA1,			/**< SHA-1 hash */
	HASH_TYPE_SHA256		/**< SHA-256 hash */
};

/**
 * A platform-independent API for calculating hashes.  Hash engine instances are not guaranteed to
 * be thread-safe across different API calls.
 */
struct hash_engine {
	/**
	 * Calculate a SHA-256 hash on a complete set of data.
	 *
	 * @param engine The hash engine to use to calculate the hash.
	 * @param data The data to hash.
	 * @param length The length of the data.
	 * @param hash The buffer that will contain the generated hash.  It must be large enough to hold
	 * at least SHA256_HASH_LENGTH bytes.
	 * @param hash_length The size of the hash buffer.
	 *
	 * @return 0 if the hash calculated successfully or an error code.
	 */
	int (*calculate_sha256) (struct hash_engine *engine, const uint8_t *data, size_t length,
		uint8_t *hash, size_t hash_length);

	/**
	 * Configure the hash engine to process independent blocks of data to calculate a SHA-256 hash
	 * the aggregated data.
	 *
	 * Calling this function will reset any active hashing operation.
	 *
	 * Every call to start MUST be followed by either a call to finish or cancel.
	 *
	 * @param engine The hash engine to configure.
	 *
	 * @return 0 if the hash engine was configured successfully or an error code.
	 */
	int (*start_sha256) (struct hash_engine *engine);

	/**
	 * Update the current hash operation with a block of data.
	 *
	 * @param engine The hash engine to update.
	 * @param data The data that should be added to generate the final hash.
	 * @param length The length of the data.
	 *
	 * @return 0 if the hash operation was updated successfully or an error code.
	 */
	int (*update) (struct hash_engine *engine, const uint8_t *data, size_t length);

	/**
	 * Complete the current hash operation and get the calculated digest.
	 *
	 * If a call to finish fails, finish MUST be called until it succeeds or the operation can be
	 * terminated with a call to cancel.
	 *
	 * @param engine The hash engine to get the final hash from.
	 * @param hash The buffer to hold the completed hash.
	 * @param hash_length The length of the hash buffer.
	 *
	 * @return 0 if the hash was completed successfully or an error code.
	 */
	int (*finish) (struct hash_engine *engine, uint8_t *hash, size_t hash_length);

	/**
	 * Cancel an in-progress hash operation without getting the hash values.  After canceling, a new
	 * hash operation needs to be started.
	 *
	 * @param engine The hash engine to cancel.
	 */
	void (*cancel) (struct hash_engine *engine);
};


int hash_start_new_hash (struct hash_engine *engine, enum hash_type type);


/* HMAC functions */

/**
 * The types of hashes that can be used to generate an HMAC.
 */
enum hmac_hash {
	HMAC_SHA1 = HASH_TYPE_SHA1,			/**< HMAC with SHA-1 hash. */
	HMAC_SHA256 = HASH_TYPE_SHA256,		/**< HMAC with SHA-256 hash. */
};

/**
 * A context for generating an HMAC using partial sets of data.
 */
struct hmac_engine {
	struct hash_engine *hash;			/**< The hash engine to use when generating the HMAC. */
	enum hmac_hash type;				/**< The type of hash being used for the HMAC. */
	uint8_t key[SHA256_BLOCK_SIZE];		/**< The key for the HMAC operation. */
	uint8_t block_size;					/**< The block size for the hash algorithm. */
	uint8_t hash_length;				/**< The digest length for the hash algorithm. */
};


int hash_generate_hmac (struct hash_engine *engine, const uint8_t *key, size_t key_length,
	const uint8_t *data, size_t length, enum hmac_hash hash, uint8_t *hmac, size_t hmac_length);

int hash_hmac_init (struct hmac_engine *engine, struct hash_engine *hash, enum hmac_hash hash_type,
	const uint8_t *key, size_t key_length);
int hash_hmac_update (struct hmac_engine *engine, const uint8_t *data, size_t length);
int hash_hmac_finish (struct hmac_engine *engine, uint8_t *hmac, size_t hmac_length);
void hash_hmac_cancel (struct hmac_engine *engine);


#endif /* HASH_H_ */
