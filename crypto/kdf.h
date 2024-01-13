// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KDF_H_
#define KDF_H_


#include <stdint.h>
#include <stddef.h>
#include "hash.h"


int kdf_nist800_108_counter_mode (struct hash_engine *hash, enum hmac_hash hash_type, 
	const uint8_t *key_derivation_key, size_t key_derivation_key_len, const uint8_t *label, 
	size_t label_len, const uint8_t *context, size_t context_len, uint8_t *key, uint32_t key_len);


#endif /* KDF_H_ */
