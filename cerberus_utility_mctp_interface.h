// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_MCTP_INTERFACE_
#define CERBERUS_UTILITY_MCTP_INTERFACE_

#include <stdint.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif


#define	SMBUS_CMD_CODE_MCTP								0x0F

#define	MCTP_PROTOCOL_PACKET_OVERHEAD					(sizeof (struct mctp_protocol_transport_header) + 1)
#define	MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD				64
#define	MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT				247
#define	MCTP_PROTOCOL_MAX_PACKET_LEN					(MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT + MCTP_PROTOCOL_PACKET_OVERHEAD)
#define	MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD				4096
#define	MCTP_PROTOCOL_MAX_MESSAGE_OVERHEAD				((MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD / MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD) * MCTP_PROTOCOL_PACKET_OVERHEAD)
#define	MCTP_PROTOCOL_MAX_MESSAGE_LEN					(MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD + MCTP_PROTOCOL_MAX_MESSAGE_OVERHEAD)
#define	MCTP_PROTOCOL_MIN_PACKET_LEN_OLD				MCTP_PROTOCOL_PACKET_OVERHEAD
#define	MCTP_PROTOCOL_MAX_MESSAGE_LEN_OLD				4224

#define	MCTP_PROTOCOL_MSG_TYPE_SHIFT					0
#define	MCTP_PROTOCOL_MSG_TYPE_SET_MASK					(127U << MCTP_PROTOCOL_MSG_TYPE_SHIFT)

#define	MCTP_PROTOCOL_SUPPORTED_HDR_VERSION				0x01
#define	MCTP_PROTOCOL_TO_REQUEST						0x01
#define	MCTP_PROTOCOL_TO_RESPONSE						0x00
#define	MCTP_PROTOCOL_TO_REQUEST_OLD					0x00
#define	MCTP_PROTOCOL_TO_RESPONSE_OLD					0x01

#define	MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG				0x00
#define	MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF				0x7E

#define	MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS			100
#define	MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS				1000

#define	MCTP_PROTOCOL_PACKET_READ_DELAY_MS				30
#define	MCTP_PROTOCOL_RSP_START_TIMEOUT_VAL_MS			500
#define	MCTP_PROTOCOL_CRYPTO_START_TIMEOUT_VAL_MS		1500
#define	MCTP_PROTOCOL_CMD_TIMEOUT_VAL_MS				30000

#define MCTP_BMC_LINK_TIMEOUT_MS						100
#define MCTP_BMC_RSP_TIMEOUT_MS							3000

#define MCTP_PROTOCOL_CMD_DEFAULT_RETRY_TIMES			3


/**
 * MCTP EIDs
 */
enum {
	MCTP_PROTOCOL_IB_EXT_MGMT = 0x08,					/**< In-band external management EID */
	MCTP_PROTOCOL_OOB_EXT_MGMT = 0x09,					/**< Out-of-band external management EID */
	MCTP_PROTOCOL_BMC_EID = 0x0A,						/**< BMC EID */
	MCTP_PROTOCOL_PA_ROT_CTRL_EID = 0x0B,				/**< Cerberus control EID */
	NUM_MCTP_PROTOCOL_EIDS = 0xFF						/**< Number of MCTP EIDs */
};

/**
 * MCTP control commands
 */
enum {
	MCTP_PROTOCOL_SET_EID = 0x01,							/**< Set Endpoint ID */
	MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT = 0x06,			/**< Get vendor defined message support */
	MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES = 0x0A,	/**< Get Routing Table Entries */
};

/**
 * MCTP completion codes
 */
enum
{
	MCTP_PROTOCOL_SUCCESS,								/**< Success */
	MCTP_PROTOCOL_ERROR,								/**< Generic error */
	MCTP_PROTOCOL_ERROR_INVALID_DATA,					/**< Invalid data or parameter value */
	MCTP_PROTOCOL_ERROR_INVALID_LEN,					/**< Invalid message length */
	MCTP_PROTOCOL_ERROR_NOT_READY,						/**< Receiver not ready */
	MCTP_PROTOCOL_ERROR_UNSUPPORTED_CMD,				/**< Command unspecified or unsupported */
	MCTP_PROTOCOL_CMD_SPECIFIC = 0x80,					/**< Command specific completion code */
};

#pragma pack(push, 1)
/**
 * MCTP portion of packet header
 */
struct mctp_protocol_transport_header
{
	uint8_t cmd_code;									/**< SMBUS command code */
	uint8_t byte_count;									/**< SMBUS packet byte count */
	uint8_t source_addr;								/**< SMBUS source address */
	uint8_t header_version:4;							/**< MCTP header version */
	uint8_t rsvd:4;										/**< Reserved, zero */
	uint8_t destination_eid;							/**< MCTP destination EID */
	uint8_t source_eid;									/**< MCTP source EID */
	uint8_t msg_tag:3;									/**< MCTP message tag */
	uint8_t tag_owner:1;								/**< MCTP tag owner */
	uint8_t packet_seq:2;								/**< MCTP packet sequence */
	uint8_t eom:1;										/**< MCTP end of message */
	uint8_t som:1;										/**< MCTP start of message */
};
#pragma pack(pop)


struct cerberus_interface;


int mctp_interface_msg_transaction (struct cerberus_interface *intf, uint8_t target_eid, uint8_t *w_buf,
	size_t w_len, uint8_t source_eid, bool crypto, uint8_t *r_buf, size_t *r_len, uint8_t *fail_type);


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_MCTP_INTERFACE_
