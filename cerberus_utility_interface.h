// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_INTERFACE_H_
#define CERBERUS_UTILITY_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include "cerberus_utility_mctp_interface.h"
#include "cerberus_utility_api.h"
#include "cerberus_utility_interface_parameters.h"
#include "cerberus_utility_platform_interface.h"


#ifdef __cplusplus
extern "C" {
#endif


#define CERBERUS_SLAVE_ADDR						0x41
#define BMC_SLAVE_ADDR							0x10

#define CERBERUS_FW_VERSION_MAX_LEN				255
#define CERBERUS_FILENAME_MAX_LEN				255
#define CERBERUS_SHA256_HASH_LEN				32
#define CERBERUS_VERSION_MAX_LEN				32
#define CERBERUS_CHALLENGE_NONCE_LEN			32
#define CERBERUS_PCR_LEN						CERBERUS_SHA256_HASH_LEN


struct cerberus_crypto_interface;

/**
 * Parameters for packetizing messages.
 */
struct cerberus_mctp_message {
	size_t max_packet_size;								/**< Maximum number of bytes in a single packet. */
	size_t max_payload;									/**< Maximum payload in a single packet. */
	size_t max_payload_per_msg;							/**< Maximum total payload in a single message. */
	int max_pkts_per_msg;								/**< Maximum number of packets in a single message. */
};

/**
 * Parameters for the MCTP layer.
 */
struct cerberus_mctp {
	struct cerberus_mctp_message read;					/**< Parameters for reading messages. */
	struct cerberus_mctp_message write;					/**< Parameters for writing messages. */
	int response_start_timeout;							/**< Timeout to wait for the start of a response, in milliseconds. */
	int crypto_start_timeout;							/**< Timeout to wait for crypto responses, in milliseconds. */
	int cmd_timeout;									/**< Timeout for the overall command, in milliseconds. */
};

/**
 * Configurable parameters for all Cebrerus utility interfaces.
 */
struct cerberus_interface_param {
	uint8_t utility_eid;								/**< MCTP EID for utility to utilize */
	uint8_t device_eid;									/**< The EID of the target Cerberus device */
	uint8_t device_address;								/**< Cerberus slave SMBUS address */
	bool multi_master;									/**< Boolean for if current transaction using multi-master I2C */
	int num_mctp_retries;								/**< Number of times to retry failed transactions at an MCTP request message level */
	bool suppress_err_msg;								/**< Boolean for if error messages are to be printed */
	int command_timeout;								/**< Timeout for the overall command, in milliseconds */
	uint32_t print_level;								/**< Flag to enable diffrent print levels */
	uint32_t debug_level;								/**< Flag to enable different debug levels */
	int channel;										/**< I2C channel for Cerberus*/
	char cmd_err_msg[CERBERUS_MAX_ERR_MSG_LEN];			/**< Cerberus command success/error message */
	uint8_t aardvrk_port_num;							/**< Aardvark communication port to initialize */
	uint8_t utility_address;							/**< Utility slave SMBUS address */
};

/**
 * Interface for communicating with Cerberus.
 */
struct cerberus_interface {
	struct cerberus_mctp mctp;							/**< MCTP context */
	struct cerberus_device_caps local;					/**< Local device capabilities */
	size_t max_write_pkt;								/**< Maximum packet length that can be transmitted */
	struct cerberus_device_caps remote;					/**< Remote device capabilities */
	struct cerberus_interface_param *params;			/**< Cerberus interface parameters */
	int32_t handle;										/**< Linux bus file handle */
	uint16_t protocol_version;							/**< Cerberus protocol version */
	uint8_t i2c_addr;									/**< SMBUS address used */
	uint8_t msg_tag;									/**< Message tag of current transaction */
	bool session_encrypted;								/**< Channel encryption established */
	bool bridge_request;								/**< Flag indicating request is meant for MCTP bridge */
	char cmd_err_msg[512];								/**< Cerberus command success/error message */
	uint8_t cmd_buf[MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD];	/**< Buffer for Cerberus protocol commands */
	uint8_t msg_buf[MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD];	/**< Buffer for Tx/Rx MCTP messages */
	uint8_t mctp_buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];	/**< Buffor for packetized MCTP messages */
	void *mutex_handle;									/**< Handle to a mutex around communication to a Cerberus device */
	struct cerberus_crypto_interface *crypto;			/**< Crypto interface for session encryption */
	struct cerberus_platform_interface platform;		/**< Platform specific implementation interface */

	/**
	 * Perform a block write
	 *
	 * @param intf Cerberus interface instance to utilize
	 * @param w_buf Input buffer with data to be transmitted
	 * @param w_len Length of output data
	 * @param last_write Boolean indicating whether last write in transaction
	 *
	 * @return Completion status, 0 if success or an error code
	 */
	int (*write) (struct cerberus_interface *intf, uint8_t *w_buf, size_t w_len, bool last_write);

	/**
	 * Perform a block read
	 *
	 * @param intf Cerberus interface instance to utilize
	 * @param r_buf Output buffer to be filled with read data
	 * @param r_len Input maximum number of bytes to read.  Output number of bytes read.
	 *
	 * @return Completion status, 0 if success or an error code
	 */
	int (*read) (struct cerberus_interface *intf, uint8_t *r_buf, size_t *r_len);

	/**
	 * Set ME recovery mode
	 *
	 * @param intf Cerberus interface instance to utilize
	 * @param setting 0 if putting ME out of recovery, 1 if putting ME in recovery mode
	 *
	 * @return Completion status, 0 if success or an error code
	 */
	int (*set_me_recovery) (struct cerberus_interface *intf, uint8_t setting);

	/**
	 * Detect if Cerberus device is present or not
	 *
	 * @param intf Cerberus interface instance to utilize
	 *
	 * @return STATUS_SUCCESS if device is detected, STATUS_NO_DEVICE if device is not detected, or
	 *  an error code
	 */
	int (*detect_device) (struct cerberus_interface *intf);

	/**
	 * Send out buffer contents over MCTP and read the MCTP response from indicated EID
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
	int (*mctp_intf_msg_transaction) (struct cerberus_interface *intf, uint8_t target_eid,
		uint8_t *w_buf, size_t w_len, uint8_t source_eid, bool crypto, uint8_t *r_buf,
		size_t *r_len, uint8_t *fail_type);
};


int cerberus_utility_init (struct cerberus_interface *intf);
void cerberus_utility_release (struct cerberus_interface *intf);
int cerberus_interface_type_init (uint32_t intf_type, struct cerberus_interface *intf,
	struct cerberus_interface_param *params);
void cerberus_interface_type_deinit (struct cerberus_interface *intf);


int cerberus_utility_set_bridge_request (struct cerberus_interface *intf);
int cerberus_utility_clear_bridge_request (struct cerberus_interface *intf);
bool cerberus_utility_get_bridge_request (struct cerberus_interface *intf);


#ifdef __cplusplus
}
#endif

#endif /* CERBERUS_UTILITY_INTERFACE_H_ */
