// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include "cerberus_utility_common.h"
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_api.h"


/**
 * Get the list of interfaces supported on the platform by Cerberus utility.
 *
 * @param intf_list Output buffer containing a list of all supported interfaces.  Buffer is
 *  dynamically allocated MUST BE FREED BY CALLER using cerberus_free()
 * @param length Output length of the buffer containing all supported interfaces.
 * @param err_buf Optional output buffer for error message during initialization.
 * @param err_buf_size Error buffer size.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_supported_interfaces (uint32_t **intf_list, size_t *length,
	char *err_buf, size_t err_buf_size)
{
	if ((intf_list == NULL) || (length == NULL)) {
		if (err_buf != NULL) {
			cerberus_print_error (err_buf, err_buf_size, __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		}
		return STATUS_INVALID_INPUT;
	}

	*intf_list = malloc (CERBERUS_VENDOR_INTF_START);
	if (*intf_list == NULL) {
		if (err_buf != NULL) {
			cerberus_print_error (err_buf, err_buf_size, __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_NO_MEM));
		}
		return STATUS_NO_MEM;
	}

	*length = 0;

#ifdef CERBERUS_AARDVARK
	*intf_list[(*length)++] = CERBERUS_INTF_AARDVARK;
#endif

#ifdef CERBERUS_MBOX
	*intf_list[(*length)++] = CERBERUS_INTF_MBOX;
#endif

	return STATUS_SUCCESS;
}
