// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "cerberus_utility_mctp_interface.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_mctp_protocol.h"
#include "cerberus_utility_status_codes.h"


/**
 * Process a MCTP control message
 *
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param msg_buf Input buffer containing message
 * @param msg_len Length of incoming message
 * @param command Command code expected for response
 * @param instance_id Expected instance ID
 * @param request Expected request bit state
 * @param expected_payload_len Expected payload length
 * @param payload Output buffer with payload sent by Cerberus
 * @param err_buff Buffer storing error messages
 * @param err_buf_len Length of error buffer
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int mctp_protocol_process_msg (const char *func_name, int line_number, uint8_t *msg_buf,
	size_t msg_len, uint8_t command, uint8_t instance_id, bool request, size_t expected_payload_len,
	uint8_t *payload, char *err_buf, size_t err_buf_len)
{
	struct mctp_protocol_control_header *header;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (msg_len != (MCTP_PROTOCOL_MIN_MSG_LEN + expected_payload_len)) {
		sprintf (errorstr, cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN),
			(MCTP_PROTOCOL_MIN_MSG_LEN + expected_payload_len), msg_len);
		cerberus_print_error (err_buf, err_buf_len, func_name, line_number, errorstr);
		return STATUS_UNEXPECTED_RLEN;
	}

	header = (struct mctp_protocol_control_header*) msg_buf;

	if ((header->msg_type != MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG) ||
		(header->integrity_check != 0) || (header->rsvd != 0) || (header->d_bit != 0) ||
		(header->instance_id != instance_id) || (header->rq != request)) {
		cerberus_print_error (err_buf, err_buf_len, func_name, line_number,
			cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
		return STATUS_INVALID_PACKET;
	}

	if (header->command_code != command) {
		sprintf (errorstr, cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), command,
			header->command_code);
		cerberus_print_error (err_buf, err_buf_len, func_name, line_number, errorstr);
		return STATUS_CMD_RESPONSE;
	}

	memcpy (payload, &msg_buf[MCTP_PROTOCOL_MIN_MSG_LEN], msg_len - MCTP_PROTOCOL_MIN_MSG_LEN);

	return STATUS_SUCCESS;
}

/**
 * Prepare to send a MCTP control message to the PA-RoT Cerberus over MCTP
 *
 * @param command Command code for message to send
 * @param instance_id Instance ID to use
 * @param request Boolean indicating if message is a request
 * @param payload Input buffer with payload to write to Cerberus
 * @param payload_len Length of payload buffer to write to Cerberus
 * @param msg_buf Output buffer contains MCTP message transmission
 * @param msg_len Output parameter contains length of Output buffer
 *
 */
static void mctp_protocol_prepare_send_ctrl_msg (uint8_t command, uint8_t instance_id, bool request,
	uint8_t *payload, size_t payload_len, uint8_t *msg_buf,	size_t *msg_len)
{
	struct mctp_protocol_control_header *header = (struct mctp_protocol_control_header*) msg_buf;

	memset (header, 0, MCTP_PROTOCOL_MIN_MSG_LEN);

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->rq = request;
	header->instance_id = instance_id;
	header->command_code = command;

	memcpy (msg_buf + MCTP_PROTOCOL_MIN_MSG_LEN, payload, payload_len);
	*msg_len = MCTP_PROTOCOL_MIN_MSG_LEN + payload_len;
}

/**
 * Process the MCTP control message read from the PA-RoT Cerberus over MCTP
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code expected for response
 * @param instance_id Expected instance ID
 * @param request Expected request bit state
 * @param msg_buf Buffer containing MCTP control message read
 * @param msg_len Length of MCTP control message read
 * @param expected_payload_len Expected payload length
 * @param payload Output buffer with payload sent by Cerberus
 * @param payload_len Output buffer with payload length
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int mctp_protocol_process_read_ctrl_msg (struct cerberus_interface *intf,
	const char *func_name, int line_number, uint8_t command, uint8_t instance_id, bool request,
	uint8_t *msg_buf, size_t msg_len, size_t expected_payload_len, uint8_t *payload,
	size_t *payload_len)
{
	struct mctp_protocol_control_header *header;

	if ((int32_t) expected_payload_len != -1) {
		if (msg_len != (MCTP_PROTOCOL_MIN_MSG_LEN + expected_payload_len)) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name,
				line_number, cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN));
			return STATUS_UNEXPECTED_RLEN;
		}
	}

	header = (struct mctp_protocol_control_header*) msg_buf;

	if ((header->msg_type != MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG) ||
		(header->integrity_check != 0) || (header->rsvd != 0) || (header->d_bit != 0)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name, line_number,
			cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
		return STATUS_INVALID_PACKET;
	}

	if ((header->command_code != command) || (header->instance_id != instance_id) ||
		(header->rq != request)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name, line_number,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE));
		return STATUS_CMD_RESPONSE;
	}

	*payload_len = msg_len - MCTP_PROTOCOL_MIN_MSG_LEN;

	memcpy (payload, &msg_buf[MCTP_PROTOCOL_MIN_MSG_LEN], *payload_len);

	return STATUS_SUCCESS;
}

/**
 * Send a MCTP control message to the PA-RoT Cerberus over MCTP and get response back
 * In case the routine fails to get response back, the above same process would be
 * repeated for multiple times.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command code for message to send
 * @param target_eid Target device EID
 * @param instance_id Instance ID to use
 * @param request Boolean indicating if message is a request
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param expected_payload_len Expected payload length.  Set to -1 to skip check.
 * @param payload Input buffer with payload to write to Cerberus
 * @param payload_len Length of payload buffer to write to Cerberus
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int mctp_protocol_send_ctrl_msg_get_rsp (struct cerberus_interface *intf, uint8_t command,
	uint8_t target_eid, uint8_t instance_id, bool request, bool crypto, size_t expected_payload_len,
	uint8_t *payload, size_t *payload_len)
{
	int i_retry = 0;
	uint8_t temp_buffer[MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD];
	uint8_t msg_buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	size_t msg_len, r_len;
	uint8_t mctp_fail_type = STATUS_SUCCESS;
	int status;

	status = cerberus_device_mutex_lock (intf, CERBERUS_MUTEX_TIMEOUT_MS);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		mctp_protocol_prepare_send_ctrl_msg (command, instance_id, true, payload, *payload_len,
			msg_buf, &msg_len);

		status = intf->mctp_intf_msg_transaction (intf, target_eid, msg_buf, msg_len, target_eid,
			crypto, msg_buf, &r_len, &mctp_fail_type);
		if (status == STATUS_SUCCESS) {
			status = mctp_protocol_process_read_ctrl_msg (intf, __func__, __LINE__,
				command, instance_id, request, msg_buf, r_len, expected_payload_len,
				temp_buffer, payload_len);

			// If proper response is received, no furthermore request is required to make.
			if (status == STATUS_SUCCESS) {
				memcpy (payload, temp_buffer, *payload_len);
				break;
			}
		}
		cerberus_common_sleep_ms (CERBERUS_CMD_RETRY_WAIT_TIME_MS);
	} while (i_retry++ < intf->params->num_mctp_retries);

	cerberus_device_mutex_unlock (intf);
	return status;
}
