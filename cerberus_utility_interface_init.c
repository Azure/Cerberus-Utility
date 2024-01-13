// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cerberus_utility_common.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_commands_internal.h"
#include "cerberus_utility_api.h"


/**
 * Instantiate and initialize Cerberus interface instance for a given interface type with provided
 * interface parameters.
 *
 * @param intf_type Type of Cerberus utility interface.
 * @param params Initialized Cerberus parameter instance to utilize.
 * @param err_buf Optional output buffer for error message during initialization.
 * @param err_buf_size Error buffer size.
 *
 * @return returns cerberus_interface object on success, NULL on failure.
 */
LIB_EXPORT struct cerberus_interface* cerberus_interface_init (uint32_t intf_type,
	struct cerberus_interface_param *params, char *err_buf, size_t err_buf_size)
{
	int status;
	struct cerberus_interface *intf = NULL;

	if ((intf_type >= CERBERUS_VENDOR_INTF_START) || (params == NULL)) {
		if (err_buf) {
			cerberus_print_error (err_buf, err_buf_size, __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		}
		return NULL;
	}

	intf = (struct cerberus_interface*) malloc (sizeof (struct cerberus_interface));
	if (intf == NULL) {
		if (err_buf) {
			cerberus_print_error (err_buf, err_buf_size, __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_NO_MEM));
		}
		return NULL;
	}

	status = cerberus_utility_init (intf);
	if (status != STATUS_SUCCESS) {
		goto err_status;
	}

	/* Set print flag */
	cerberus_print_set_level (params->print_level);

	status = cerberus_interface_type_init (intf_type, intf, params);
	if (status != STATUS_SUCCESS) {
		goto err_status;
	}

	return intf;

err_status:
	if (err_buf) {
		snprintf (err_buf, err_buf_size, "%s", intf->cmd_err_msg);
	}

	if (params->debug_level & CERBERUS_DEBUG_CMD) {
		if (err_buf) {
			printf ("%s\n\n", err_buf);
		}
		else {
			cerberus_print_error (NULL, 0, __func__, __LINE__, "%s\n\n", intf->cmd_err_msg);
		}

	}

	cerberus_interface_deinit (intf);
	return NULL;
}

/**
 * Release Cerberus Utility interface instance.
 *
 * @param intf The Cerberus interface instance to release.
 *
 */
LIB_EXPORT void cerberus_interface_deinit (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return;
	}

	cerberus_interface_type_deinit (intf);

	cerberus_free (intf);
}

/**
 * Initialize Cerberus Interface Parameters.
 *
 * @param err_buf Optional output buffer for error message during initialization.
 * @param err_buf_size Error buffer size.
 *
 * @return Cerberus interface parameters instance on success, NULL on failure.
 */
LIB_EXPORT struct cerberus_interface_param* cerberus_interface_param_init (char *err_buf,
	size_t err_buf_size)
{
	struct cerberus_interface_param *intf_param = NULL;

	intf_param = (struct cerberus_interface_param*) malloc (sizeof (struct cerberus_interface_param));

	if (intf_param == NULL) {
		if (err_buf != NULL) {
			cerberus_print_error (err_buf, err_buf_size, __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_NO_MEM));
		}
		return NULL;
	}

	memset (intf_param, 0, sizeof (struct cerberus_interface_param));
	cerberus_interface_param_init_default (intf_param);

	return intf_param;
}

/**
 * De-initialize and release Cerberus interface parameters instance.
 *
 * @param intf_param Initialized Cerberus interface parameters instance.
 *
 */
LIB_EXPORT void cerberus_interface_param_deinit (struct cerberus_interface_param *intf_param)
{
	cerberus_free (intf_param);
}
