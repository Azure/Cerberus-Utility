// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "unused.h"
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_common.h"


/**
 * Initialize the platform specific command flow interface.
 * Register various platform specific methods in the cerberus_platform_interface structure.
 *
 * @param intf Cerberus interface instance to utilize.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_platform_interface_init (struct cerberus_interface *intf)
{
	UNUSED (intf);

	return STATUS_SUCCESS;
}
