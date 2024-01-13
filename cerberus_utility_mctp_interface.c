// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "cerberus_utility_common.h"
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_api.h"
#include "cerberus_utility_mctp_interface.h"


/**
 * Compute CRC8 value for provided buffer
 *
 * @param smbus_addr SMBUS address to prepend to buffer before computation
 * @param data Input buffer to compute checksum of
 * @param len Length of input buffer
 *
 * @return computed CRC value
 */
static uint8_t mctp_interface_crc8 (uint8_t smbus_addr, const uint8_t *data, size_t len)
{
	uint16_t i;
	uint8_t crc = 0;
	int j;

	crc ^= smbus_addr;

	for (j = 0; j < 8; ++j) {
		if ((crc & 0x80) != 0) {
			crc = (uint8_t) ((crc << 1) ^ 0x07);
		}
		else {
			crc <<= 1;
		}
	}

	for (i = 0; i < len; ++i) {
		crc ^= data[i];

		for (j = 0; j < 8; ++j) {
			if ((crc & 0x80) != 0) {
				crc = (uint8_t) ((crc << 1) ^ 0x07);
			}
			else {
				crc <<= 1;
			}
		}
	}

	return crc;
}

/**
 * Compute CRC8 checksum on provided buffer and compare with received checksum
 *
 * @param device_addr Device SMBUS address
 * @param rcv_crc Received checksum
 * @param data Input buffer to compute checksum of
 * @param len Length of input buffer
 * @param mctp_debug Debug flag to print MCTP communication messages
 *
 * @return Boolean indicating whether both computed and received checksums match
 */
static bool mctp_interface_verify_crc8 (uint8_t device_addr, const uint8_t rcv_crc,
	const uint8_t *data, size_t len, uint8_t mctp_debug)
{
	uint8_t val = mctp_interface_crc8 ((device_addr << 1), data, len);

	if (mctp_debug) {
		if (val != rcv_crc) {
			printf ("crc: %x vs %x\n", rcv_crc, val);
		}
	}

	return (val == rcv_crc);
}

/**
 * Construct packet with MCTP header
 *
 * @param intf Cerberus interface to utilize
 * @param payload Packet payload
 * @param payload_len Packet payload length
 * @param source_addr SMBUS address of source device
 * @param target_eid EID of target device
 * @param msg_tag MCTP message tag to utilize
 * @param packet_seq MCTP packet sequence to utilize
 * @param som Boolean indicating whether this packet is the start of an MCTP message
 * @param eom Boolean indicating whether this packet is the end of an MCTP message
 * @param packet Output buffer to hold constructed packet
 * @param dest_addr SMBUS destination address
 * @param protocol_version Cerberus protocol version
 * @param msg_type Buffer for message type. If SOM will be populated with message type, else
 * 	incoming value will be used
 * @param eid MCTP EID to utilize
 * @param packet_len Buffer to hold length of packet generated
 * @param force_crc Force CRC usage
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
static int mctp_interface_construct_mctp_packet (struct cerberus_interface *intf, uint8_t *payload,
	size_t payload_len, uint8_t source_addr, uint8_t target_eid, uint8_t msg_tag,
	uint8_t packet_seq, bool som,bool eom, uint8_t *packet, uint8_t dest_addr,
	uint16_t protocol_version, uint8_t* msg_type, uint8_t eid, size_t *packet_len, bool force_crc)
{
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) packet;
	size_t msg_offset = sizeof (struct mctp_protocol_transport_header);
	bool crc;

	memset (packet, 0, sizeof (struct mctp_protocol_transport_header));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = (uint8_t) (msg_offset - 2 + payload_len);
	header->source_addr = (source_addr << 1) | 0x01;
	header->header_version = MCTP_PROTOCOL_SUPPORTED_HDR_VERSION;
	header->destination_eid = target_eid;
	header->source_eid = eid;
	header->msg_tag = msg_tag;
	header->tag_owner = (protocol_version == 0) ? MCTP_PROTOCOL_TO_REQUEST_OLD :
		MCTP_PROTOCOL_TO_REQUEST;
	header->packet_seq = packet_seq;
	header->eom = eom;
	header->som = som;

	memcpy (packet + msg_offset, payload, payload_len);

	if (som) {
		*msg_type = payload[0];
	}

	if (force_crc ||
		((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF)) {
		crc = true;
	}
	else if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG) {
		crc = false;
	}
	else {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
		return STATUS_INVALID_PACKET;
	}

	if (crc) {
		packet[msg_offset + payload_len] = mctp_interface_crc8 ((dest_addr << 1), packet,
			msg_offset + payload_len);
	}

	*packet_len = msg_offset + payload_len + crc;

	return STATUS_SUCCESS;
}

/**
 * Process incoming MCTP packet and validate MCTP header
 *
 * @param intf Cerberus interface to utilize
 * @param buf Input buffer with incoming packet
 * @param buf_len Length of input buffer
 * @param payload Pointer to start of payload in input buffer
 * @param payload_len Output buffer to be filled with length of payload in packet
 * @param packet_len Output buffer to be filled with length of packet
 * @param source_eid Expected source EID
 * @param msg_tag Expected MCTP message tag
 * @param packet_seq Expected MCTP packet sequence
 * @param som Expected MCTP start of message
 * @param eom Output buffer to be filled with MCTP end of message field
 * @param device_addr Address this packet was sent to
 * @param protocol_version Cerberus protocol version
 * @param msg_type Buffer for message type. If SOM will be populated with message type, else
 * 	incoming value will be used
 * @param eid MCTP EID to utilize
 * @param mctp_debug Flag to print MCTP debug messages
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
static int mctp_interface_process_packet (struct cerberus_interface *intf, uint8_t *buf,
	size_t buf_len, uint8_t **payload, size_t *payload_len, size_t *packet_len, uint8_t source_eid,
	uint8_t msg_tag, uint8_t packet_seq, bool som, bool *eom, uint8_t device_addr,
	uint16_t protocol_version, uint8_t *msg_type, uint8_t eid, uint8_t mctp_debug)
{
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	bool crc;

	*eom = false;
	*packet_len = 0;
	*payload_len = 0;

	if (buf_len < MCTP_PROTOCOL_PACKET_OVERHEAD) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if ((header->cmd_code != SMBUS_CMD_CODE_MCTP) ||
		(header->header_version != MCTP_PROTOCOL_SUPPORTED_HDR_VERSION) ||
		(header->destination_eid != eid) ||	(header->source_eid != source_eid) ||
		(header->msg_tag != msg_tag) ||	(header->packet_seq != packet_seq) ||
		(header->som != som)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
		return STATUS_INVALID_PACKET;
	}

	if (protocol_version == 0) {
		if (header->tag_owner != MCTP_PROTOCOL_TO_RESPONSE_OLD) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
			return STATUS_INVALID_PACKET;
		}
	}
	else {
		if (header->tag_owner != MCTP_PROTOCOL_TO_RESPONSE) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
			return STATUS_INVALID_PACKET;
		}
	}

	*eom = header->eom;
	*payload = buf + sizeof (struct mctp_protocol_transport_header);

	if (header->som) {
		*msg_type = (*payload)[0];
	}

	if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG) {
		crc = false;
	}
	else if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) {
		crc = true;
	}
	else {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PACKET));
		return STATUS_INVALID_PACKET;
	}

	*packet_len = header->byte_count + 2 + crc;
	*payload_len = *packet_len - (sizeof (struct mctp_protocol_transport_header) + crc);

	if (header->byte_count > (buf_len - (2 + crc))) {
		return STATUS_PARTIAL_PACKET;
	}

	if (crc && !mctp_interface_verify_crc8 (device_addr, buf[*packet_len - 1], buf,
		*packet_len - 1, mctp_debug)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_CRC_FAILURE));
		return STATUS_CRC_FAILURE;
	}

	return STATUS_SUCCESS;
}

/**
 * Send out buffer contents over MCTP to target EID
 *
 * @param intf Cerberus interface to utilize
 * @param target_eid Target EID to write out payload to
 * @param w_buf Input buffer containing payload to be sent out
 * @param w_len Length of buffer to be transmitted
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
static int mctp_interface_write (struct cerberus_interface *intf, uint8_t target_eid, uint8_t *w_buf,
	size_t w_len)
{
	uint8_t packet_seq = 0;
	uint8_t msg_type;
	size_t payload_len;
	size_t packet_len;
	bool som = true;
	bool eom;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;

	}

	if ((w_buf == NULL) || (w_len == 0) || (target_eid >= NUM_MCTP_PROTOCOL_EIDS)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (w_len > intf->mctp.write.max_payload_per_msg) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_PAYLOAD_TOO_LARGE));
		return STATUS_PAYLOAD_TOO_LARGE;
	}

	intf->msg_tag = (intf->msg_tag + 1) % 8;

	if (intf->params->debug_level & CERBERUS_DEBUG_MCTP) {
		printf ("Write %zu bytes.\n", w_len);
	}

	while (w_len > 0) {
		if (w_len <= intf->mctp.write.max_payload) {
			eom = true;
			payload_len = w_len;
		}
		else {
			eom = false;
			payload_len = intf->mctp.write.max_payload;
		}

		status = mctp_interface_construct_mctp_packet (intf, w_buf, payload_len, intf->i2c_addr,
			target_eid, intf->msg_tag, packet_seq, som, eom, intf->mctp_buf,
			intf->params->device_address, intf->protocol_version, &msg_type,
			intf->params->utility_eid, &packet_len, cerberus_utility_get_bridge_request (intf));
		if (status != STATUS_SUCCESS) {
			return status;
		}

		status = intf->write (intf, intf->mctp_buf, packet_len, eom);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		packet_seq = (packet_seq + 1) % 4;
		som = false;
		w_len -= payload_len;
		w_buf += payload_len;
	}

	return STATUS_SUCCESS;
}

/**
 * Read in MCTP packets received from indicated EID
 *
 * @param intf Cerberus interface to utilize
 * @param source_eid Source EID to read in packets from
 * @param r_buf Output buffer containing packets read back
 * @param r_len Length of output buffer
 * @param crypto Flag indicating the command uses cryptographic timeouts
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
static int mctp_interface_read (struct cerberus_interface *intf, uint8_t source_eid, uint8_t *r_buf,
	size_t *r_len, bool crypto)
{
	unsigned long start_time = cerberus_common_get_cpu_time_ms ();
	uint8_t *payload;
	uint8_t packet_seq = 0;
	uint8_t msg_tag;
	size_t payload_len = 0;
	size_t packet_len = 0;
	size_t i_proc;
	size_t i_read;
	size_t i_buf;
	int resp_timeout;
	int status;
	bool response_started = false;
	bool eom = false;
	bool som = true;

	if ((intf == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	if((r_buf == NULL) || (r_len == NULL) || (source_eid >= NUM_MCTP_PROTOCOL_EIDS)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*r_len = 0;
	resp_timeout = (crypto) ? intf->mctp.crypto_start_timeout : intf->mctp.response_start_timeout;

	while (!eom) {
		if (cerberus_common_timeout_expired (start_time, intf->mctp.cmd_timeout) ||
			(!response_started && cerberus_common_timeout_expired (start_time, resp_timeout))) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_MCTP_TIMEOUT));
			return STATUS_MCTP_TIMEOUT;
		}

		i_proc = 0;
		i_read = 0;

		while (i_read < MCTP_PROTOCOL_MAX_MESSAGE_LEN) {
			i_buf = MCTP_PROTOCOL_MAX_MESSAGE_LEN - i_read;
			cerberus_common_sleep_ms (MCTP_PROTOCOL_PACKET_READ_DELAY_MS);

			status = intf->read (intf, &intf->mctp_buf[i_read], &i_buf);
			if ((status == STATUS_NO_DATA) || (i_buf == 0)) {
				break;
			}
			else if (status == STATUS_COMPLETE_PACKET) {
				i_read += i_buf;
				break;
			}
			else if (status != STATUS_SUCCESS) {
				return status;
			}

			i_read += i_buf;
		}

		if (intf->params->debug_level & CERBERUS_DEBUG_MCTP) {
			printf ("BMC read back %zi bytes.\n", i_read);
		}

		if (i_read == 0) {
			continue;
		}

		response_started = true;

		while (intf->mctp_buf[i_proc] != SMBUS_CMD_CODE_MCTP) {
			++i_proc;
		}

		if (intf->params->debug_level & CERBERUS_DEBUG_MCTP) {
			printf ("Moved forward to %zi.\n", i_proc);
		}

		while ((i_proc < i_read) && !eom) {
			status = mctp_interface_process_packet (intf, &intf->mctp_buf[i_proc], i_read - i_proc,
				&payload, &payload_len, &packet_len, source_eid, intf->msg_tag, packet_seq, som,
				&eom, intf->i2c_addr, intf->protocol_version, &msg_tag, intf->params->utility_eid,
				(intf->params->debug_level & CERBERUS_DEBUG_MCTP));
			if (status != STATUS_SUCCESS) {
				++i_proc;
			}
			else {
				if (intf->params->debug_level & CERBERUS_DEBUG_MCTP) {
					printf ("Found packet at %zi bytes, %i eom.\n", i_proc, eom);
				}

				memcpy (r_buf + *r_len, payload, payload_len);
				*r_len = (*r_len + payload_len);
				i_proc += packet_len;
				packet_seq = (packet_seq + 1) % 4;
				som = false;
			}
		}
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_MCTP) {
		printf ("Read back %zi bytes.\n", *r_len);
	}

	return STATUS_SUCCESS;
}

/**
 * Send out buffer contents over MCTP and read the MCTP from indicated EID
 *
 * @param intf Cerberus interface to utilize
 * @param target_eid Target EID to write out payload to
 * @param w_buf Input buffer containing payload to be sent out
 * @param w_len Length of buffer to be transmitted
 * @param source_eid Source EID to read in packets from
 * @param crypto Flag indicating the command uses cryptographic timeouts
 * @param r_buf Output buffer containing packets read back
 * @param r_len Length of output buffer
 * @param fail_type Idenfication of failure type
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
int mctp_interface_msg_transaction (struct cerberus_interface *intf, uint8_t target_eid,
	uint8_t *w_buf, size_t w_len, uint8_t source_eid, bool crypto, uint8_t *r_buf, size_t *r_len,
	uint8_t *fail_type)
{
	int status;

	status = mctp_interface_write (intf, target_eid, w_buf, w_len);
	if (status != STATUS_SUCCESS) {
		*fail_type = STATUS_MCTP_WRITE_FAILURE;
		return status;
	}

	status = mctp_interface_read (intf, source_eid, r_buf, r_len, crypto);
	if (status != STATUS_SUCCESS) {
		*fail_type = STATUS_MCTP_READ_FAILURE;
	}

	return status;
}
