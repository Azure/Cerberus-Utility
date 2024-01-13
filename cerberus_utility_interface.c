// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_interface.h"
#ifdef CERBERUS_ENABLE_CRYPTO
#include "cerberus_utility_crypto_interface.h"
#endif

#ifdef CERBERUS_AARDVARK
#include "cerberus_utility_aardvark_interface.h"
#endif

#ifdef CERBERUS_MBOX
#include "cerberus_utility_mbox_linux_interface.h"
#endif


/**
 * Perform interface type specific initialization.
 *
 * @param intf_type Type of Cerberus utility interface.
 * @param intf The Cerberus interface to utilize
 * @param params Initialized Cerberus parameter instance to utilize.
 *
 * @return STATUS_SUCCESS if the initialization is successful or an error code.
 */
int cerberus_interface_type_init (uint32_t intf_type, struct cerberus_interface *intf,
	struct cerberus_interface_param *params)
{
	int status = STATUS_INVALID_INPUT;

	if ((intf == NULL) || (params == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	switch (intf_type) {
		case CERBERUS_INTF_AARDVARK:
#ifdef CERBERUS_AARDVARK
			status = cerberus_utility_aardvark_init (intf, params);
#endif
			break;

		case CERBERUS_INTF_MBOX:
#ifdef CERBERUS_MBOX
			status = cerberus_utility_mbox_linux_init (intf, params);
#endif

		default:
			break;
	}

	return status;

}

/**
 * Perform interface type specific de-initialization.
 *
 * @param intf The Cerberus interface to utilize
 *
 */
void cerberus_interface_type_deinit (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return;
	}

#if defined CERBERUS_AARDVARK
	cerberus_utility_aardvark_deinit (intf);
#elif defined CERBERUS_MBOX
	cerberus_utility_mbox_linux_deinit (intf);
#endif
}

/**
 * Initialize cerberus interface instance
 *
 * @param intf The Cerberus interface instance to initialize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_utility_init (struct cerberus_interface *intf)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	memset (intf, 0, sizeof (struct cerberus_interface));

	status = cerberus_utility_mutex_create (intf);
	if (status != STATUS_SUCCESS) {
		return status;
	}

#ifdef CERBERUS_ENABLE_CRYPTO
	return cerberus_crypto_interface_init (intf);
#else
	return STATUS_SUCCESS;
#endif
}

/**
 * Release cerberus interface instance
 *
 * @param intf The Cerberus interface instance to release
 */
void cerberus_utility_release (struct cerberus_interface *intf)
{
	if (intf != NULL) {
		cerberus_device_mutex_destroy (intf);

#ifdef CERBERUS_ENABLE_CRYPTO
		cerberus_crypto_interface_deinit (intf);
#endif
	}
}

/**
 * Set transaction as request to MCTP bridge
 *
 * @param intf The Cerberus interface instance to utilize
 *
 * @return STATUS_SUCCESS if request flag was set, error otherwise
 */
int cerberus_utility_set_bridge_request (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf->bridge_request = true;

	return STATUS_SUCCESS;
}

/**
 * Clear MCTP bridge transaction request.
 *
 * @param intf The Cerberus interface instance to utilize
 *
 * @return STATUS_SUCCESS if request flag was cleared, error otherwise
 */
int cerberus_utility_clear_bridge_request (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf->bridge_request = false;

	return STATUS_SUCCESS;
}

/**
 * Determine if transaction is a request to MCTP bridge
 *
 * @param intf The Cerberus interface instance to utilize
 *
 * @return True if MCTP bridge request, False otherwise
 */
bool cerberus_utility_get_bridge_request (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return false;
	}

	return intf->bridge_request;
}