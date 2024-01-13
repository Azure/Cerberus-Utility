// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_MCTP_PROTOCOL
#define CERBERUS_UTILITY_MCTP_PROTOCOL

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


#define MCTP_PROTOCOL_MIN_MSG_LEN						sizeof (struct mctp_protocol_control_header)
#define MCTP_PROTOCOL_VID_FORMAT_PCI					0


#pragma pack(push, 1)
/**
 * MCTP control message header
 */
struct mctp_protocol_control_header
{
	uint8_t msg_type:7;									/**< MCTP message type */
	uint8_t integrity_check:1;							/**< MCTP message integrity check, always 0*/
	uint8_t instance_id:5;								/**< Instance ID */
	uint8_t rsvd:1;										/**< Reserved */
	uint8_t d_bit:1;									/**< D-bit */
	uint8_t rq:1;										/**< Request bit */
	uint8_t command_code;								/**< Command code */
};

/**
 * MCTP control get routing table entries message response format
 */
struct mctp_protocol_control_get_routing_table_entries_response {
	uint8_t completion_code;							/**< Completion code */
	uint8_t next_entry_handle;							/**< Next entry handle */
	uint8_t num_entries;								/**< Number of entries in response */
};

/**
 * MCTP control routing table entry format
 */
struct mctp_protocol_control_routing_table_entry {
	uint8_t eid_range_size;								/**< Size of EID range */
	uint8_t starting_eid;								/**< Starting EID */
	uint8_t port_number:5;								/**< Port number */
	uint8_t eid_assignment_type:1;						/**< Dynamic/Static entry */
	uint8_t entry_type:2;								/**< Entry type*/
	uint8_t binding_type_id;							/**< Physical transport binding type ID */
	uint8_t media_type_id;								/**< Physical media type ID */
	uint8_t address_size;								/**< Physical address size */
	uint8_t address;									/**< Physical address */
};
#pragma pack(pop)


struct cerberus_interface;

int mctp_protocol_process_msg (const char *func_name, int line_number, uint8_t *msg_buf,
	size_t msg_len, uint8_t command, uint8_t instance_id, bool request, size_t expected_payload_len,
	uint8_t *payload, char *err_buf, size_t err_buf_len);

int mctp_protocol_send_ctrl_msg_get_rsp (struct cerberus_interface *intf, uint8_t command,
	uint8_t target_eid, uint8_t instance_id, bool request, bool crypto, size_t expected_payload_len,
	uint8_t *payload, size_t *payload_len);


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_MCTP_PROTOCOL
