// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_DEBUG_COMMANDS_H
#define CERBERUS_UTILITY_DEBUG_COMMANDS_H

#include <stdint.h>
#include <stdbool.h>
#include "cerberus_utility_interface.h"


#ifdef __cplusplus
extern "C" {
#endif


/* Debug commands.  Only supported in special FW builds. */

int cerberus_debug_fill_log (struct cerberus_interface *intf);
int cerberus_debug_start_attestation (struct cerberus_interface *intf,
	uint8_t device_num);
int cerberus_debug_get_attestation_status (struct cerberus_interface *intf,
	uint8_t device_num, uint8_t *attestation_status);


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_DEBUG_COMMANDS_H