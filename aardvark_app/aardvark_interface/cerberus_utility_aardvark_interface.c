// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_mctp_interface.h"
#include "cerberus_utility_mctp_params.h"
#include "cerberus_utility_aardvark_interface.h"
#include "cerberus_utility_api.h"
#include "aardvark_com.h"
#include "unused.h"


#define CERBERUS_MCTP_WR_MAX_PAYLOAD	240


static int comm_write (struct cerberus_interface *intf, uint8_t *w_buf, size_t w_len,
	bool last_write)
{
	UNUSED (last_write);

	int status;

	if (intf->params->debug_level & CERBERUS_DEBUG_COMM) {
		size_t i;
		printf ("Cerberus Write (%zi): ", w_len);

		for (i = 0; i < w_len; ++i) {
			printf ("0x%02x ", w_buf[i]);
		}

		printf ("\n");
	}

	status = aardvark_com_write (intf, intf->params->device_address, w_buf, w_len);
	return status;
}

static int comm_read (struct cerberus_interface *intf, uint8_t *r_buf, size_t *r_len)
{
	int status;

	if ((intf == NULL) || (r_buf == NULL) || (r_len == NULL) || (*r_len == 0)) {
		return STATUS_INVALID_INPUT;
	}

	if (*r_len > intf->mctp.read.max_packet_size) {
		*r_len = intf->mctp.read.max_packet_size;
	}

	status = aardvark_com_read (intf, intf->params->device_address, intf->params->multi_master,
		r_buf, r_len);

	if (intf->params->debug_level & CERBERUS_DEBUG_COMM) {
		if (((status == STATUS_SUCCESS) || (status == STATUS_COMPLETE_PACKET)) && (*r_len > 0)) {
			size_t i;
			printf ("Cerberus Read (%zi): ", *r_len);

			for (i = 0; i < *r_len; ++i) {
				printf ("0x%02x ", r_buf[i]);
			}

			printf ("\n");
		}
	}

	return status;
}

static int win_set_me_recovery (struct cerberus_interface *intf, uint8_t setting)
{
	UNUSED (intf);
	UNUSED (setting);
	return STATUS_SUCCESS;
}

static int win_detect_device (struct cerberus_interface *intf)
{
	UNUSED (intf);
	return STATUS_SUCCESS;
}

/**
 * Initialize Aardvark Cerberus interface instance.
 *
 * @param intf Cerberus interface instance to initialize.
 * @param params Cerberus parameters interface instance to utilize.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cerberus_utility_aardvark_init (struct cerberus_interface *intf,
	struct cerberus_interface_param *params)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = mctp_interface_init_parameters (intf, MCTP_PROTOCOL_MAX_PACKET_LEN,
		CERBERUS_MCTP_WR_MAX_PAYLOAD);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = aardvark_com_init (intf, params->aardvrk_port_num);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	srand ((unsigned int) time (NULL));

	intf->params = params;
	intf->protocol_version = 2;
	intf->msg_tag = rand () % 8;
	intf->write = comm_write;
	intf->read = comm_read;
	intf->set_me_recovery = win_set_me_recovery;
	intf->detect_device = win_detect_device;
	intf->i2c_addr = params->utility_address;
	intf->mctp_intf_msg_transaction = mctp_interface_msg_transaction;

	status = cerberus_platform_interface_init (intf);

	return status;
}

/**
 * Release Cerberus utility Aardvark interface instance
 *
 * @param intf Cerberus interface instance to deinitialize
 */
void cerberus_utility_aardvark_deinit (struct cerberus_interface *intf)
{
	if (intf != NULL) {
		aardvark_com_close ();
		cerberus_utility_release (intf);
	}
}
