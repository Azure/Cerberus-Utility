// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_AARDVARK_INTERFACE_
#define CERBERUS_UTILITY_AARDVARK_INTERFACE_

#include <stdint.h>
#include "cerberus_utility_interface.h"


int cerberus_utility_aardvark_init (struct cerberus_interface *intf,
	struct cerberus_interface_param *params);
void cerberus_utility_aardvark_deinit (struct cerberus_interface *intf);


#endif // CERBERUS_UTILITY_AARDVARK_INTERFACE_
