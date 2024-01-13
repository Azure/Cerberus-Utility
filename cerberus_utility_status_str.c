// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdio.h>
#include "cerberus_utility_status_codes.h"


extern const char *cerberus_utility_errors_str[];

/**
 * Return the formatted error string corresponding to the status code
 *
 * @param status_code Error status code
 *
 * @return Returns a formatted error string corresponding to the status code.
 */
const char *cerberus_utility_get_errors_str (int status_code)
{
	if ((status_code >= STATUS_SUCCESS) && (status_code < STATUS_PLATFORM_SPECIFIC_ERROR)) {
		return cerberus_utility_errors_str[status_code];
	}

	return NULL;
}
