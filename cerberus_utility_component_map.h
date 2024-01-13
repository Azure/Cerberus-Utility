#ifndef CERBERUS_UTILITY_COMPONENT_MAP_H_
#define CERBERUS_UTILITY_COMPONENT_MAP_H_

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include "cerberus_utility_api.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Attestation components mapping.
 */
struct cerberus_component_map {
	uint32_t component_id;									/**< Component ID */
	const char *component_str;								/**< Component name string */
};

struct cerberus_component_map component_map[] =
{
	// Pipeline removes below entry and fills this structure by parsing component_map.json file
	{UINT_MAX, "Unknown"},
};


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_COMPONENT_MAP_H_
