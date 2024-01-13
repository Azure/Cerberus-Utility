// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_H_
#define RNG_H_

#include <stdint.h>


/**
 * A platform-independent API for generating random numbers.  Random number engine instances are not
 * guaranteed to be thread-safe.
 */
struct rng_engine {
	/**
	 * Generate variable length buffer of random numbers.
	 *
	 * @param engine The RNG engine to use for random number generation.
	 * @param rand_len The number of random bytes to generate.
	 * @param buf The random number buffer to fill. Must be large enough to accommodate rand_len.
	 *
	 * @return 0 if the random buffer was successfully filled or an error code.
	 */
	int (*generate_random_buffer) (struct rng_engine *engine, size_t rand_len, uint8_t *buf);
};


#endif /* RNG_H_ */
