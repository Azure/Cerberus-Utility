// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdio.h>
#include <string.h>
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_debug_commands.h"
#include "cerberus_utility_cerberus_protocol.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_common.h"


/**
 * Send a log fill request to Cerberus
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_debug_fill_log (struct cerberus_interface *intf)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
	}

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_DEBUG_FILL_LOG, intf->params->device_eid, false, NULL, 0);

	if (status == STATUS_SUCCESS) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			"Filling debug log completed successfully\n");
	}

	return status;
}

/**
 * Debug command to trigger Cerberus to attest device
 *
 * @param intf The Cerberus interface to utilize
 * @param device_num Device number to attest
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_debug_start_attestation (struct cerberus_interface *intf,
	uint8_t device_num)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
	}

	return cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_DEBUG_START_ATTESTATION, intf->params->device_eid, false,	&device_num,
		sizeof (device_num));
}

/**
 * Debug command to get back Cerberus attestation status of device
 *
 * @param intf The Cerberus interface to utilize
 * @param device_num Device number to get attestation status of
 * @param attestation_status Output buffer for the attestation status
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_debug_get_attestation_status (struct cerberus_interface *intf,
	uint8_t device_num, uint8_t *attestation_status)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (attestation_status == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
	return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = device_num;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_DEBUG_GET_ATTESTATION_STATE, intf->params->device_eid, sizeof (uint8_t), false,
		intf->cmd_buf, sizeof (device_num));
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (attestation_status, intf->cmd_buf, sizeof (uint8_t));

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Device (%i) authentication state: %i\n", device_num,
			*attestation_status);
	}

	return STATUS_SUCCESS;
}
