// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "cerberus_utility_common.h"
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_mctp_params.h"
#include "cerberus_utility_cerberus_protocol.h"


/**
 * Initialize the MCTP parameters for communication to any Cerberus device.  The local device
 * capabilities will also be initialized.
 *
 * @param intf The Cerberus interface to configure.
 * @param max_read_pkt The maximum amount of data that can be read by the local device.
 * @param max_write_pkt The maximum amount of data that can be written by the local device.
 *
 * @return STATUS_SUCCESS if the parameters were initialized successfully or an error code.
 */
int mctp_interface_init_parameters (struct cerberus_interface *intf, size_t max_read_pkt,
	size_t max_write_pkt)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((max_read_pkt < (MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD + MCTP_PROTOCOL_PACKET_OVERHEAD)) ||
		(max_write_pkt < (MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD + MCTP_PROTOCOL_PACKET_OVERHEAD))) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_BAD_MCTP_PARAMETERS));
		return STATUS_BAD_MCTP_PARAMETERS;
	}

	intf->mctp.read.max_payload = MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD;
	intf->mctp.read.max_packet_size = intf->mctp.read.max_payload + MCTP_PROTOCOL_PACKET_OVERHEAD;
	intf->mctp.read.max_payload_per_msg = MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD;
	intf->mctp.read.max_pkts_per_msg = 1;

	intf->mctp.write.max_payload = MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD;
	intf->mctp.write.max_packet_size = intf->mctp.write.max_payload + MCTP_PROTOCOL_PACKET_OVERHEAD;
	intf->mctp.write.max_payload_per_msg = MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD;
	intf->mctp.write.max_pkts_per_msg = 1;

	intf->mctp.response_start_timeout = MCTP_PROTOCOL_RSP_START_TIMEOUT_VAL_MS;
	intf->mctp.crypto_start_timeout = MCTP_PROTOCOL_CRYPTO_START_TIMEOUT_VAL_MS;
	intf->mctp.cmd_timeout = MCTP_PROTOCOL_CMD_TIMEOUT_VAL_MS;

	intf->local.max_packet_payload = (uint16_t) max_read_pkt - MCTP_PROTOCOL_PACKET_OVERHEAD;
	intf->max_write_pkt = max_write_pkt;
	intf->local.max_message_body = MCTP_PROTOCOL_MAX_MESSAGE_PAYLOAD;
	intf->local.max_message_timeout = MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS;
	intf->local.max_crypto_timeout = MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS;

#ifdef CERBERUS_ENABLE_CRYPTO
	intf->local.device_info |= CERBERUS_DEVICE_AUTH | CERBERUS_DEVICE_EXTERNAL;
	intf->local.pk_key_strength = CERBERUS_PKEY_RSA | CERBERUS_PKEY_ECDSA | CERBERUS_PKEY_ECC_160 |
		CERBERUS_PKEY_ECC_256 | CERBERUS_PKEY_RSA_2048 | CERBERUS_PKEY_RSA_3072 |
		CERBERUS_PKEY_RSA_4096;
	intf->local.enc_key_strength = CERBERUS_ENCRYPT_AES_256;
#endif

	return STATUS_SUCCESS;
}

/**
 * Configure the MCTP parameters for the Cerberus interface to a device.  The local and remote
 * device capabilities will be examined to determine the appropriate parameters.
 *
 * @param intf The Cerberus interface to configure.
 */
void mctp_interface_set_parameters (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return;
	}

	if (intf->protocol_version >= 3) {
		intf->mctp.read.max_payload =
			MIN (intf->local.max_packet_payload, intf->remote.max_packet_payload);
		intf->mctp.read.max_packet_size =
			intf->mctp.read.max_payload + MCTP_PROTOCOL_PACKET_OVERHEAD;
		intf->mctp.read.max_payload_per_msg =
			MIN (intf->local.max_message_body, intf->remote.max_message_body);
		intf->mctp.read.max_pkts_per_msg =
			(int) ceil (intf->mctp.read.max_payload_per_msg / (1.0 * intf->mctp.read.max_payload));

		intf->mctp.write.max_payload = MIN (intf->max_write_pkt - MCTP_PROTOCOL_PACKET_OVERHEAD,
			intf->remote.max_packet_payload);
		intf->mctp.write.max_packet_size =
			intf->mctp.write.max_payload + MCTP_PROTOCOL_PACKET_OVERHEAD;
		intf->mctp.write.max_payload_per_msg =
			MIN (intf->local.max_message_body, intf->remote.max_message_body);
		intf->mctp.write.max_pkts_per_msg = (int) ceil (
			intf->mctp.write.max_payload_per_msg / (1.0 * intf->mctp.write.max_payload));

		intf->mctp.response_start_timeout = MCTP_BMC_LINK_TIMEOUT_MS +
			MAX (intf->remote.max_message_timeout, MCTP_BMC_RSP_TIMEOUT_MS) * 3;
		intf->mctp.crypto_start_timeout = MCTP_BMC_LINK_TIMEOUT_MS +
			MAX (intf->remote.max_crypto_timeout, MCTP_BMC_RSP_TIMEOUT_MS) * 3;
		intf->mctp.cmd_timeout = MCTP_PROTOCOL_CMD_TIMEOUT_VAL_MS;
	}
	else {
		intf->mctp.read.max_packet_size =
			intf->local.max_packet_payload + MCTP_PROTOCOL_PACKET_OVERHEAD;
		intf->mctp.read.max_payload = intf->local.max_packet_payload;
		intf->mctp.read.max_pkts_per_msg = (int) ceil (
			MCTP_PROTOCOL_MAX_MESSAGE_LEN_OLD / (1.0 * intf->mctp.read.max_packet_size));
		intf->mctp.read.max_payload_per_msg = MCTP_PROTOCOL_MAX_MESSAGE_LEN_OLD -
			(MCTP_PROTOCOL_PACKET_OVERHEAD * intf->mctp.read.max_pkts_per_msg);

		intf->mctp.write.max_packet_size = intf->max_write_pkt;
		intf->mctp.write.max_payload = intf->max_write_pkt - MCTP_PROTOCOL_PACKET_OVERHEAD;
		intf->mctp.write.max_pkts_per_msg =
			(int) ceil (MCTP_PROTOCOL_MAX_MESSAGE_LEN_OLD / (1.0 * intf->max_write_pkt));
		intf->mctp.write.max_payload_per_msg = MCTP_PROTOCOL_MAX_MESSAGE_LEN_OLD -
			(MCTP_PROTOCOL_PACKET_OVERHEAD * intf->mctp.write.max_pkts_per_msg);

		intf->mctp.response_start_timeout = MCTP_PROTOCOL_RSP_START_TIMEOUT_VAL_MS;
		intf->mctp.crypto_start_timeout = MCTP_PROTOCOL_CRYPTO_START_TIMEOUT_VAL_MS;
		intf->mctp.cmd_timeout = MCTP_PROTOCOL_CMD_TIMEOUT_VAL_MS;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_MCTP) {
		printf ("Read: pkt=%zd, payload=%zd, pkt/msg=%d, msg=%zd\n",
			intf->mctp.read.max_packet_size, intf->mctp.read.max_payload,
			intf->mctp.read.max_pkts_per_msg, intf->mctp.read.max_payload_per_msg);
		printf ("Write: pkt=%zd, payload=%zd, pkt/msg=%d, msg=%zd\n",
			intf->mctp.write.max_packet_size, intf->mctp.write.max_payload,
			intf->mctp.write.max_pkts_per_msg, intf->mctp.write.max_payload_per_msg);
	}
}
