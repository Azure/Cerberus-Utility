// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "aardvark_com.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_status_codes.h"


#define BITRATE_KHz				100
#define BUS_TIMEOUT_MS			150
#define MAX_AARDVARK_PORTS		16


static Aardvark handle;

/**
 * Initializes and open an aardvark port
 *
 * @param intf Cerberus Interface to utilize
 * @param port_num port to open
 *
 * @return 0 if operation completed successfully or error code
 */
int aardvark_com_init (struct cerberus_interface *intf, uint8_t port_num)
{
	int status = STATUS_SUCCESS;
	int bitrate;
	int bus_timeout;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	handle = aa_open (port_num);
	if (handle <= 0) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PORT));
		status = STATUS_INVALID_PORT;
		goto end;
	}

	/* Ensure that the I2C subsystem is enabled */
	aa_configure (handle, AA_CONFIG_SPI_I2C);

	/* Enable the I2C bus pullup resistors (2.2k resistors).
	   This command is only effective on v2.0 hardware or greater.
	   The pullup resistors on the v1.02 hardware are enabled by default */
	aa_i2c_pullup (handle, AA_I2C_PULLUP_BOTH);

	/* Set the bitrate */
	bitrate = aa_i2c_bitrate (handle, BITRATE_KHz);
	printf ("Bitrate set to %d kHz\n", bitrate);

	/* Set the bus lock timeout */
	bus_timeout = aa_i2c_bus_timeout (handle, BUS_TIMEOUT_MS);
	printf ("Bus lock timeout set to %d ms\n", bus_timeout);

	/* Enable slave mode. Needed for Multi-master transfer.
	   Slave mode will remain enabled after a master transaction */
	status = aa_i2c_slave_enable (handle, BMC_SLAVE_ADDR, 0, 0);
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_I2C_ENABLE_SLAVE_MODE_FAILURE));
	}

end:
	return status;
}

/**
 * Close the aardvark port
 *
 * @return 0 if operation completed successfully or error code
 */
int aardvark_com_close ()
{
	return aa_close (handle);
}

/**
 * Write the provided buffer to the i2c port
 *
 * @param intf Cerberus interface to utilize
 * @param device_addr i2c address of the device
 * @param buffer packet to write
 * @param len length of the packet
 *
 * @return 0 if operation completed successfully or error code
 */
int aardvark_com_write (struct cerberus_interface *intf, uint8_t device_addr, uint8_t *buffer,
	size_t len)
{
	int status = STATUS_SUCCESS;
	u16 bytes;
	char err_msg [CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((buffer == NULL) || (len < 1)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (handle <= 0) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PORT));
		return STATUS_INVALID_PORT;
	}

	status = aa_i2c_write_ext (handle, device_addr, AA_I2C_NO_FLAGS, (u16) len, buffer, &bytes);
	if ((status != AA_I2C_STATUS_OK) || (bytes != len)) {
		snprintf (err_msg, sizeof (err_msg), "bytes: %d write_error: %s\n", bytes,
			aa_status_string (bytes));
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_COMMUNICATION_FAILURE), err_msg);
		status = STATUS_COMMUNICATION_FAILURE;
	}

	aa_sleep_ms (10);

	return status;
}

/**
 * Read data from the i2c port
 *
 * @param intf Cerberus interface to utilize
 * @param device_addr i2c address of the device
 * @param multi_master Flag indicating if reading from a multi master device
 * @param r_buf The buffer to store incoming data
 * @param r_len Maximum length of the buffer, updated with bytes read
 *
 * @return 0 if operation completed successfully or error code
 */
int aardvark_com_read (struct cerberus_interface *intf, uint8_t device_addr, bool multi_master,
	uint8_t *r_buf, size_t *r_len)
{
	u16 bytes_read = 0;
	int status = STATUS_SUCCESS;
	u08 addr;
	char err_msg [CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((r_buf == NULL) || (*r_len < 1)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (handle <= 0) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_PORT));
		return STATUS_INVALID_PORT;
	}

	if (multi_master) {
		status = aa_async_poll (handle, 500);
		if (status & AA_ASYNC_I2C_READ) {
			status = aa_i2c_slave_read_ext (handle, &addr, (u16) *r_len, r_buf, &bytes_read);
		}
		else if (status == AA_ASYNC_NO_DATA) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_NO_DATA));
			status = STATUS_NO_DATA;
			goto ret;
		}
	}
	else {
		status = aa_i2c_read_ext (handle, device_addr, AA_I2C_NO_FLAGS, (u16) *r_len, r_buf,
			&bytes_read);
		if (status == AA_I2C_STATUS_OK) {
			status = STATUS_COMPLETE_PACKET;
			goto ret;
		}
	}

	if (status != AA_I2C_STATUS_OK) {
		snprintf (err_msg, sizeof (err_msg), "i2c_read error: %s\n", aa_status_string (status));
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_COMMUNICATION_FAILURE), err_msg);
		return STATUS_COMMUNICATION_FAILURE;
	}

ret:
	*r_len = bytes_read;

	return status;
}


/**
 * Detect and print available Aardvark devices
 *
 * @return 0 if operation completed successfully or error code
 */
int aardvark_detect_devices ()
{
	u16 ports[MAX_AARDVARK_PORTS];
	u32 unique_ids[MAX_AARDVARK_PORTS];
	int nelem = MAX_AARDVARK_PORTS;
	int i;

	// Find all the attached devices
	int count = aa_find_devices_ext(nelem, ports, nelem, unique_ids);

	// Print the information on each device
	if (count > nelem)  count = nelem;
	for (i = 0; i < count; ++i) {
		// Determine if the device is in-use
		const char *status = "(avail) ";
		if (ports[i] & AA_PORT_NOT_FREE) {
			ports[i] &= ~AA_PORT_NOT_FREE;
			status = "(in-use)";
		}

		// Display device port number, in-use status, and serial number
		printf("\tport=%-3d %s (%04d-%06d)\n", ports[i], status, unique_ids[i] / 1000000,
			unique_ids[i] % 1000000);
	}

	return 0;
}