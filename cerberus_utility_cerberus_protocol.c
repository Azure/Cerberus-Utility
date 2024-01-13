// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "cerberus_utility_common.h"
#include "cerberus_utility_mctp_interface.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_cerberus_protocol.h"
#include "cerberus_utility_status_codes.h"
#ifdef CERBERUS_ENABLE_CRYPTO
#include "cerberus_utility_crypto_interface.h"
#endif


/**
 * Strings for the Cerberus protocol error messages.
 */
const char *cerberus_protocol_error_messages_str[] = {
	[CERBERUS_PROTOCOL_NO_ERROR] = "Success: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_INVALID_REQ] = "Invalid Request: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_BUSY] = "Device busy: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_UNSPECIFIED] = "Vendor: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM] = "Invalid Checksum: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG] = "EOM before SOM: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_AUTHENTICATION] = "Authentication not established: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW] = "Message recieved out of sequence window: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN] = "Invalid message size: 0x%x",
	[CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW] = "MCTP message too large: 0x%x"
};


/**
 * Calculate maximum length of Cerberus protocol payload in a single MCTP message
 *
 * @param intf Cerberus interface to utilize
 *
 * @return Maximum length of Cerberus protocol payload in a single MCTP message
 */
size_t cerberus_protocol_get_max_payload_len_per_msg (struct cerberus_interface *intf)
{
	size_t trailer_len = CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	size_t max_payload_len;

	if (intf == NULL) {
		return 0;
	}

	if (intf->protocol_version >= 2) {
		max_payload_len = intf->mctp.write.max_payload_per_msg - CERBERUS_PROTOCOL_MIN_MSG_LEN;

		if (intf->session_encrypted) {
			max_payload_len -= trailer_len;
		}

		return max_payload_len;
	}
	else {
		return (intf->mctp.write.max_payload_per_msg - 1 - (CERBERUS_PROTOCOL_MIN_MSG_LEN - 1) *
			intf->mctp.write.max_pkts_per_msg);
	}
}

/**
 * Determine if a Cerberus status response message was received
 *
 * @param protocol_version Cerberus protocol version
 * @param msg_buf Input buffer containing response
 * @param msg_len Length of response
 * @param error_code Output for the error code in the status message
 * @param error_data Output for the detailed error information
 *
 * @return True if status response message received, false otherwise
 */
static bool cerberus_protocol_parse_status_message (uint16_t protocol_version, uint8_t *msg_buf,
	size_t msg_len, uint8_t *error_code, uint32_t *error_data)
{
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) msg_buf;
	uint16_t pci_vid = (protocol_version >= 2) ?
		CERBERUS_PROTOCOL_MSFT_PCI_VID : CERBERUS_PROTOCOL_MSFT_PCI_VID_OLD;

	if ((msg_len == (CERBERUS_PROTOCOL_MIN_MSG_LEN + 5)) &&
		(header->msg_type == MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) &&
		(header->pci_vendor_id == pci_vid) && (header->integrity_check == 0) &&
		(header->command == CERBERUS_PROTOCOL_ERROR)) {

		if (error_code) {
			*error_code = msg_buf[CERBERUS_PROTOCOL_MIN_MSG_LEN];
		}
		if (error_data) {
			*error_data = *((uint32_t*) (&msg_buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
		}
		return true;
	}

	return false;
}

/**
 * Determine if a Cerberus status response message was received
 *
 * @param protocol_version Cerberus protocol version
 * @param msg_buf Input buffer containing response
 * @param msg_len Length of response
 *
 * @return True if status response message received, false otherwise
 */
bool cerberus_protocol_is_status_message (uint16_t protocol_version, uint8_t *msg_buf,
	size_t msg_len)
{
	return cerberus_protocol_parse_status_message (protocol_version, msg_buf, msg_len, NULL, NULL);
}

/**
 * Determine if a Cerberus error message was received and extract the error code.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of function call
 * @param protocol_version Cerberus protocol version
 * @param msg_buf Input buffer containing response
 * @param msg_len Length of response
 * @param error_code Status code from the error response
 * @param error_data Output for the detailed error information
 *
 * @return True if error message received, false otherwise
 */
static bool cerberus_protocol_parse_error_message (struct cerberus_interface *intf,
	const char *func_name, int line_number, uint16_t protocol_version, uint8_t *msg_buf,
	size_t msg_len, uint8_t *error_code, uint32_t *error_data)
{
	uint8_t code;
	uint32_t err;

	if (cerberus_protocol_parse_status_message (protocol_version, msg_buf, msg_len, &code, &err) &&
		(code != CERBERUS_PROTOCOL_NO_ERROR)) {
		char errorstr[CERBERUS_MAX_MSG_LEN] = "";

		sprintf (errorstr, cerberus_protocol_error_messages_str[code], err);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name,
			line_number, cerberus_utility_get_errors_str (STATUS_MCTP_FAILURE), errorstr);

		if (error_code) {
			*error_code = code;
		}
		if (error_data) {
			*error_data = err;
		}

		return true;
	}

	return false;
}

/**
 * Determine if a Cerberus error message was received and print out error
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of function call
 * @param protocol_version Cerberus protocol version
 * @param msg_buf Input buffer containing response
 * @param msg_len Length of response
 *
 * @return True if error message received, false otherwise
 */
bool cerberus_protocol_is_error_message (struct cerberus_interface *intf, const char *func_name,
	int line_number, uint16_t protocol_version, uint8_t *msg_buf, size_t msg_len)
{
	return cerberus_protocol_parse_error_message (intf, func_name, line_number, protocol_version,
		msg_buf, msg_len, NULL, NULL);
}

/**
 * Prepare to send a Cerberus protocol message to Cerberus over MCTP.
 *
 * @param intf The Cerberus interface to utilize
 * @param command Command code for message to send
 * @param payload Input buffer with payload to write to Cerberus, NULL if no payload
 * @param payload_len Length of payload buffer to write to Cerberus, 0 if no payload
 * @param msg_len Length of mctp msg to write to Cerberus
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_prepare_send_msg (struct cerberus_interface *intf, uint8_t command,
	uint8_t *payload, size_t payload_len, size_t *msg_len)
{
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) intf->msg_buf;
	int status = STATUS_SUCCESS;
	size_t msg_offset;

	memset (header, 0, sizeof (struct cerberus_protocol_header));

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = (intf->protocol_version >= 2) ?
		CERBERUS_PROTOCOL_MSFT_PCI_VID : CERBERUS_PROTOCOL_MSFT_PCI_VID_OLD;
	header->command = command;

	if (intf->protocol_version >= 2) {
		msg_offset = CERBERUS_PROTOCOL_MIN_MSG_LEN;

		if ((payload != NULL) && (payload_len != 0)) {
			memcpy (intf->msg_buf + CERBERUS_PROTOCOL_MIN_MSG_LEN, payload, payload_len);

			if (intf->session_encrypted) {
#ifdef CERBERUS_ENABLE_CRYPTO
				size_t buffer_len = sizeof (intf->msg_buf) - CERBERUS_PROTOCOL_HEADER_SIZE_NO_ID;

				status = cerberus_crypto_interface_encrypt_payload (intf,
					&intf->msg_buf[CERBERUS_PROTOCOL_HEADER_SIZE_NO_ID], payload_len + 1, &buffer_len);
				if (status != STATUS_SUCCESS) {
					return status;
				}

				header->crypt = 1;
				msg_offset += buffer_len;
#else
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
					cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
				return STATUS_UNSUPPORTED_OPERATION;
#endif
			}
			else {
				msg_offset += payload_len;
			}
		}
	}
	else {
		size_t max_payload_per_packet = intf->mctp.write.max_packet_size -
			MCTP_PROTOCOL_MIN_PACKET_LEN_OLD - (CERBERUS_PROTOCOL_MIN_MSG_LEN - 1);
		size_t packet_payload_len;
		size_t payload_offset;

		msg_offset = sizeof (struct cerberus_protocol_header);
		packet_payload_len = MIN (max_payload_per_packet - 1, payload_len);
		memcpy (&intf->msg_buf[msg_offset], payload, packet_payload_len);
		payload_offset = packet_payload_len;
		msg_offset += packet_payload_len;
		payload_len -= packet_payload_len;

		while (payload_len > 0) {
			memcpy (&intf->msg_buf[msg_offset], (uint8_t*) header,
				sizeof (struct cerberus_protocol_header) - 1);
			msg_offset += (sizeof (struct cerberus_protocol_header) - 1);
			packet_payload_len = MIN (max_payload_per_packet, payload_len);
			memcpy (&intf->msg_buf[msg_offset], &payload[payload_offset], packet_payload_len);
			payload_offset += packet_payload_len;
			msg_offset += packet_payload_len;
			payload_len -= packet_payload_len;
		}
	}

	*msg_len = msg_offset;

	return status;
}

/**
 * Process a Cerberus protocol message
 *
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param intf Cerberus interface to use
 * @param msg_buf Input buffer containing message
 * @param msg_len Length of incoming message
 * @param command Command code expected for response
 * @param payload Output buffer with payload sent by Cerberus
 * @param payload_len Output buffer with payload length
 *
 * @return 0 if operation completed successfully or an error code.
 */
static int cerberus_protocol_process_variable_msg (const char *func_name, int line_number,
	struct cerberus_interface *intf, uint8_t *msg_buf, size_t msg_len, uint8_t command,
	uint8_t *payload, size_t *payload_len)
{
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) msg_buf;
	uint16_t pci_vid = (intf->protocol_version >= 2) ?
		CERBERUS_PROTOCOL_MSFT_PCI_VID : CERBERUS_PROTOCOL_MSFT_PCI_VID_OLD;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (msg_len < (CERBERUS_PROTOCOL_MIN_MSG_LEN) ||
	   (header->msg_type != MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) || (header->integrity_check != 0) ||
	   (header->pci_vendor_id != pci_vid)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name, line_number,
			cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
		return STATUS_INVALID_PACKET;
	}

	if (header->command != command) {
		sprintf (errorstr, cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), command,
			header->command);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name, line_number,
			errorstr);
		return STATUS_CMD_RESPONSE;
	}

	if (intf->protocol_version >= 2) {
		*payload_len = msg_len - CERBERUS_PROTOCOL_MIN_MSG_LEN;
		memcpy (payload, &msg_buf[CERBERUS_PROTOCOL_MIN_MSG_LEN], *payload_len);

		if (header->crypt) {
			if (intf->session_encrypted) {
#ifdef CERBERUS_ENABLE_CRYPTO
				*payload_len = msg_len - CERBERUS_PROTOCOL_HEADER_SIZE_NO_ID;
				memcpy (payload, &msg_buf[CERBERUS_PROTOCOL_HEADER_SIZE_NO_ID], *payload_len);
				int status = cerberus_crypto_interface_decrypt_payload (intf, payload, payload_len);
				if (status != STATUS_SUCCESS) {
					return status;
				}
#else
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
					cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
				return STATUS_UNSUPPORTED_OPERATION;
#endif
			}
			else {
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name,
					line_number, cerberus_utility_get_errors_str (STATUS_ENCRYPTION_OUT_OF_SESSION));
				return STATUS_ENCRYPTION_OUT_OF_SESSION;
			}
		}
	}
	else {
		size_t max_payload_per_packet = intf->mctp.read.max_packet_size -
			MCTP_PROTOCOL_MIN_PACKET_LEN_OLD - (CERBERUS_PROTOCOL_MIN_MSG_LEN - 1);
		size_t payload_per_packet;
		size_t msg_offset;

		msg_offset = sizeof (struct cerberus_protocol_header);
		msg_len -= sizeof (struct cerberus_protocol_header);
		payload_per_packet = MIN (max_payload_per_packet - 1, msg_len);
		memcpy (payload, &msg_buf[msg_offset], payload_per_packet);
		msg_offset += payload_per_packet;
		*payload_len = payload_per_packet;
		msg_len -= payload_per_packet;

		while (msg_len > 0) {
			header = (struct cerberus_protocol_header*) &msg_buf[msg_offset];

			if ((header->msg_type != MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) ||
				(header->integrity_check != 0) || (header->pci_vendor_id != pci_vid)) {
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name,
					line_number, cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
				return STATUS_INVALID_PACKET;
			}

			msg_offset += (sizeof (struct cerberus_protocol_header) - 1);
			msg_len -= (sizeof (struct cerberus_protocol_header) - 1);
			payload_per_packet = MIN (max_payload_per_packet, msg_len);
			memcpy (&payload[*payload_len], &msg_buf[msg_offset], payload_per_packet);
			msg_offset += payload_per_packet;
			*payload_len += payload_per_packet;
			msg_len -= payload_per_packet;
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Process a Cerberus protocol message
 *
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param intf Cerberus interface to utilize
 * @param msg_buf Input buffer containing message
 * @param msg_len Length of incoming message
 * @param command Command code expected for response
 * @param expected_payload_len Expected payload length
 * @param payload Output buffer with payload sent by Cerberus
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_protocol_process_msg (const char *func_name, int line_number,
	struct cerberus_interface* intf, uint8_t *msg_buf, size_t msg_len, uint8_t command,
	size_t expected_payload_len, uint8_t *payload)
{
	size_t payload_len;
	int status;

	status = cerberus_protocol_process_variable_msg (func_name, line_number, intf, msg_buf, msg_len,
		command, payload, &payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len != expected_payload_len) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), func_name, line_number,
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), expected_payload_len, payload_len);
		return STATUS_UNEXPECTED_RLEN;
	}

	return STATUS_SUCCESS;
}

/**
 * Process the Cerberus protocol message read from the Cerberus over MCTP.
 * If an error response is received, the error details will be returned.
 * In case the routine fails, No retry is implemented in it.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code expected for response
 * @param expected_payload_len Expected payload length
 * @param msg_buf mctp message buffer
 * @param msg_len mctp message data length
 * @param payload Output buffer with payload sent by Cerberus
 * @param error_code Output for the error code if a status response is received
 * @param error_data Output for the detailed error information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_protocol_process_read_msg (struct cerberus_interface *intf,
	const char *func_name, int line_number, const uint8_t command, size_t expected_payload_len,
	uint8_t *msg_buf, size_t msg_len, uint8_t *payload, uint8_t *error_code, uint32_t *error_data)
{
	if (cerberus_protocol_parse_error_message (intf, func_name, line_number, intf->protocol_version,
		msg_buf, msg_len, error_code, error_data)) {
		return STATUS_MCTP_FAILURE;
	}

	return cerberus_protocol_process_msg (func_name, line_number, intf, msg_buf, msg_len,
		command, expected_payload_len, payload);
}


/**
 * Process Cerberus protocol message read from Cerberus over MCTP.  If an error response is received, the
 * error details will be returned.
 * In case the routine fails, No retry is implemented in it.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code expected for response
 * @param msg_buf mctp message buffer
 * @param msg_len mctp message data length
 * @param payload Output buffer with payload sent by Cerberus
 * @param payload_len Output buffer with payload length
 * @param error_code Output for the error code if a status response is received
 * @param error_data Output for the detailed error information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_process_read_variable_msg (struct cerberus_interface *intf, const char *func_name,
	int line_number, uint8_t command, uint8_t *msg_buf, size_t msg_len, uint8_t *payload, size_t *payload_len,
	uint8_t *error_code, uint32_t *error_data)
{
	if (cerberus_protocol_parse_error_message (intf, func_name, line_number, intf->protocol_version,
		msg_buf, msg_len, error_code, error_data)) {
		return STATUS_MCTP_FAILURE;
	}

	return cerberus_protocol_process_variable_msg (func_name, line_number, intf, msg_buf,
		msg_len, command, payload, payload_len);
}

/**
 * Send a buffer to Cerberus over MCTP and check for an error message response
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code for message to send
 * @param target_eid Target device EID
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param payload Input buffer with payload to write to Cerberus, NULL if no payload
 * @param payload_len Length of payload buffer to write to Cerberus
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_send_no_rsp (struct cerberus_interface *intf, const char *func_name,
	int line_number, uint8_t command, uint8_t target_eid, bool crypto, uint8_t *payload,
	size_t payload_len)
{
	return cerberus_protocol_send_no_rsp_get_error (intf, func_name, line_number, command,
		target_eid, crypto, payload, payload_len, NULL, NULL);
}

/**
 * Send a buffer to Cerberus over MCTP and check for an error message response.
 * In case the routine fails to get response back, the above same process would be
 * repeated for multiple times.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code for message to send
 * @param target_eid Target device EID
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param payload Input buffer with payload to write to Cerberus, NULL if no payload
 * @param payload_len Length of payload buffer to write to Cerberus
 * @param error_code Output for the error code in the status response
 * @param error_data Output for the detailed error information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_send_no_rsp_get_error (struct cerberus_interface *intf, const char *func_name,
	int line_number, uint8_t command, uint8_t target_eid, bool crypto, uint8_t *payload,
	size_t payload_len, uint8_t *error_code, uint32_t *error_data)
{
	size_t r_len;
	size_t msg_len;
	int i_retry = 0;
	uint8_t temp_buffer[MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD];
	uint8_t mctp_fail_type = STATUS_SUCCESS;

	int status;

	status = cerberus_device_mutex_lock (intf, CERBERUS_MUTEX_TIMEOUT_MS);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		status = cerberus_protocol_prepare_send_msg (intf, command, payload, payload_len,
			&msg_len);
		if (status != STATUS_SUCCESS) {
			goto done;
		}

		status = intf->mctp_intf_msg_transaction (intf, target_eid, intf->msg_buf, msg_len,
			target_eid, crypto, temp_buffer, &r_len, &mctp_fail_type);
		if (status == STATUS_SUCCESS) {
			if (cerberus_protocol_parse_error_message (intf, func_name, line_number,
				intf->protocol_version, temp_buffer, r_len, error_code, error_data)) {
				status = STATUS_MCTP_FAILURE;
				goto done;
			}
			break;
		}
		cerberus_common_sleep_ms (CERBERUS_CMD_RETRY_WAIT_TIME_MS);
	} while (i_retry++ < intf->params->num_mctp_retries);

done:
	cerberus_device_mutex_unlock (intf);

	return status;
}

/**
 * Send a buffer to Cerberus over MCTP and check for an error message response
 * In case the routine fails to get response back, the above same process would be
 * repeated for multiple times.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code for message to send
 * @param target_eid Target device EID
 * @param expected_payload_len Expected response payload length
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param payload Buffer with payload to write to Cerberus, then to be filled with response payload
 * @param payload_len Length of payload to write to Cerberus
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_send_and_read_rsp (struct cerberus_interface *intf,
	const char *func_name, int line_number, uint8_t command, uint8_t target_eid,
	size_t expected_payload_len, bool crypto, uint8_t *payload, size_t payload_len)
{
	return cerberus_protocol_send_and_read_rsp_get_error (intf, func_name, line_number, command,
		target_eid, expected_payload_len, crypto, payload, payload_len, NULL, NULL);
}

/**
 * Send a buffer to  Cerberus over MCTP and check for an error message response.  If a generic
 * status response is received, the error information will be extracted.
 * In case the routine fails to get response back, the above same process would be
 * repeated for multiple times.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code for message to send
 * @param target_eid Target device EID
 * @param expected_payload_len Expected response payload length
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param payload Buffer with payload to write to Cerberus, then to be filled with response payload
 * @param payload_len Length of payload to write to Cerberus
 * @param error_code Output for the error code if a status response is received
 * @param error_data Output for the detailed error information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_send_and_read_rsp_get_error (struct cerberus_interface *intf,
	const char *func_name, int line_number, uint8_t command, uint8_t target_eid,
	size_t expected_payload_len, bool crypto, uint8_t *payload, size_t payload_len,
	uint8_t *error_code, uint32_t *error_data)
{
	uint8_t temp_buffer[MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD];
	int i_retry = 0;
	size_t msg_len;
	size_t r_len;
	uint8_t mctp_fail_type = STATUS_SUCCESS;
	int status;

	status = cerberus_device_mutex_lock (intf, CERBERUS_MUTEX_TIMEOUT_MS);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		status = cerberus_protocol_prepare_send_msg (intf, command, payload,
			payload_len, &msg_len);
		if (status != STATUS_SUCCESS) {
			goto done;
		}

		status = intf->mctp_intf_msg_transaction (intf, target_eid, intf->msg_buf, msg_len,
			target_eid, crypto, intf->msg_buf, &r_len, &mctp_fail_type);
		if (status != STATUS_SUCCESS) {
			status = mctp_fail_type;
		}
		else {
			status = cerberus_protocol_process_read_msg (intf, func_name, line_number, command,
				expected_payload_len, intf->msg_buf, r_len, temp_buffer, error_code, error_data);
			if (status == STATUS_SUCCESS) {
				memcpy (payload, temp_buffer, expected_payload_len);
			}
			break;
		}

		cerberus_common_sleep_ms (CERBERUS_CMD_RETRY_WAIT_TIME_MS);
	} while (i_retry++ < intf->params->num_mctp_retries);


done:
	cerberus_device_mutex_unlock (intf);

	return status;
}

/**
 * Send a buffer to Cerberus over MCTP and check for an error message response
 * In case the routine fails to get response back, the above same process would be
 * repeated for multiple times.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code for message to send
 * @param target_eid Target device EID
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param payload Buffer with payload to write to Cerberus, then to be filled with response payload
 * @param payload_len Input length of payload to write to Cerberus.  Output with received payload
 * length
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_send_and_read_variable_rsp (struct cerberus_interface *intf,
	const char *func_name, int line_number, uint8_t command, uint8_t target_eid, bool crypto,
	uint8_t *payload, size_t *payload_len)
{
	return cerberus_protocol_send_and_read_variable_rsp_get_error (intf, func_name, line_number,
		command, target_eid, crypto, payload, payload_len, NULL, NULL);
}

/**
 * Send a buffer to Cerberus over MCTP and check for an error message response.  If a generic status
 * response is received, the error information will be extracted.
 * In case the routine fails to get response back, the above same process would be
 * repeated for multiple times.
 *
 * @param intf The Cerberus interface to utilize
 * @param func_name String with the caller's function name
 * @param line_number Line number of caller function
 * @param command Command code for message to send
 * @param target_eid Target device EID
 * @param crypto Flag indicating if the response is subject to the cryptographic timeout
 * @param payload Buffer with payload to write to Cerberus, then to be filled with response payload
 * @param payload_len Input length of payload to write to Cerberus.  Output with received payload
 * length
 * @param error_code Output for the error code if a status response is received
 * @param error_data Output for the detailed error information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_protocol_send_and_read_variable_rsp_get_error (struct cerberus_interface *intf,
	const char *func_name, int line_number, uint8_t command, uint8_t target_eid, bool crypto,
	uint8_t *payload, size_t *payload_len, uint8_t *error_code, uint32_t *error_data)
{
	uint8_t temp_buffer[MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD];
	size_t temp_buffer_len;
	int i_retry = 0;
	size_t msg_len;
	size_t r_len;
	uint8_t mctp_fail_type = STATUS_SUCCESS;
	int status;

	status = cerberus_device_mutex_lock (intf, CERBERUS_MUTEX_TIMEOUT_MS);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		status = cerberus_protocol_prepare_send_msg (intf, command, payload, *payload_len,
			&msg_len);
		if (status != STATUS_SUCCESS) {
			goto done;
		}

		status = intf->mctp_intf_msg_transaction (intf, target_eid, intf->msg_buf, msg_len,
			target_eid, crypto, intf->msg_buf, &r_len, &mctp_fail_type);
		if (status != STATUS_SUCCESS) {
			status = mctp_fail_type;
		}
		else {
			status = cerberus_protocol_process_read_variable_msg (intf, func_name, line_number, command,
				intf->msg_buf, r_len, temp_buffer, &temp_buffer_len, error_code, error_data);
			if (status == STATUS_SUCCESS) {
				memcpy (payload, temp_buffer, temp_buffer_len);
				*payload_len = temp_buffer_len;
			}
			break;
		}

		cerberus_common_sleep_ms (CERBERUS_CMD_RETRY_WAIT_TIME_MS);
	} while (i_retry++ < intf->params->num_mctp_retries);

done:
	cerberus_device_mutex_unlock (intf);

	return status;
}
