// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_api.h"
#include "cerberus_utility_cli.h"
#include "cerberus_utility_interface_parameters.h"


//! @brief Usage text.
const char options_usage[] =
"\t-p <number>               Connect to target over I2C. Specify port number\n\
                                    e.g. -p 0 or -p 1\n\
\t-e <number>               EID of the target Cerberus device.\n\
                                    Range: (0-0xfe)\n\
\t-r <retry_val>            Define number of MCTP retries\n\
\t-a <device_addr>          I2C address of the Aardvark\n\
\t-s <slave_addr>           I2C slave address of the device\n\
\t--slave                   I2C device is a slave instead of multi-master\n\
\t--debug <debug_val>       Turn on debug prints\n\
                                    0x1 - I2C debug prints\n\
                                    0x2 - MCTP debug prints\n\
                                    0x4 - Command debug prints\n\
\t--time                    Display time it takes to execute commands in milliseconds\n\
\t--secure                  Issue command through an encrypted channel with Cerberus\n";

/**
 * Print Cerberus utility help message
 */
static void print_cerberus_usage (void)
{
	int i_cmd;

	printf ("Cerberus Utility Usage:\n");
	printf (options_usage);
	printf ("\n");
	printf ("\n");
	printf ("\t%s\n", cerberus_cli_command_list[CERBERUS_CLI_CMD_HELP].command_str);

	for (i_cmd = CERBERUS_CLI_CMD_FW_VERSION; i_cmd < NUM_CERBERUS_CLI_CMD; ++i_cmd) {
		if (i_cmd == CERBERUS_CLI_CMD_PRINT_MCTP_ROUTING_TABLE) {
			printf ("\nMCTP Control Commands:\n");
		}

		printf ("\t-p 0 -s %x -e %x --debug <val> %s\n",
			CERBERUS_SLAVE_ADDR, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
			cerberus_cli_command_list[i_cmd].command_str);
	}
}

/**
 * Initialize interface parameters instance for Aardvark interface.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param port_num Port number of the connected Aardvark device.
 * @param slave_addr I2C device address value to set.
 * @param target_eid device EID value to set.
 * @param multi_master Flag to enable or disable I2C multi-master mode.
 * @param debug Debug level value to set.
 * @param print_flag Print level value to set.
 * @param num_mctp_retries Max MCTP retries value to set.
 *
 * @return Initialization status, 0 if success or an error code.
 */
static int cerberus_utility_aardvark_init_params (struct cerberus_interface_param *intf_param,
	int port_num, uint8_t host_addr, uint8_t slave_addr, int8_t target_eid, bool multi_master, int debug,
	int print_flag, int num_mctp_retries)
{
	int status;

	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_interface_param_set_aardvark_port_number (intf_param, port_num);
	if (status != STATUS_SUCCESS) {
		return status;
	}
	
	status = cerberus_interface_param_set_utility_address (intf_param, host_addr);
	if (status != STATUS_SUCCESS) {
		return status;
	}
	
	status = cerberus_interface_param_set_device_address (intf_param, slave_addr);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_interface_param_set_device_eid (intf_param, target_eid);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_interface_param_set_multi_master (intf_param, multi_master);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_interface_param_set_debug_level (intf_param, debug);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_interface_param_set_print_level (intf_param, print_flag);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_interface_param_set_mctp_retries (intf_param, num_mctp_retries);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_interface_param_set_utility_eid (intf_param, MCTP_PROTOCOL_OOB_EXT_MGMT);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	return STATUS_SUCCESS;
}

/**
 * Cerberus utility entry point
 *
 * @param argc Number of command line arguments
 * @param argv Command line arguments
 *
 * @return 0 if operation completed successfully or error code
 */
int main (int argc, char **argv)
{
	struct cerberus_interface *intf = NULL;
	struct cerberus_interface_param *intf_param = NULL;
	char **arg_buf = argv;
	int debug = 0;
	int port_num = 0;
	bool multi_master = true;
	bool secure = false;
	uint8_t host_addr = BMC_SLAVE_ADDR;
	uint8_t slave_addr = CERBERUS_SLAVE_ADDR;
	int print_flag = CERBERUS_PRINT_FLAG_ERROR | CERBERUS_PRINT_FLAG_INFO;
	int n_arg = argc;
	int num_mctp_retries = -1;
	int status;
	int i_arg;
	uint8_t target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	char err_buf[CERBERUS_MAX_ERR_MSG_LEN];

	memset (err_buf, 0, sizeof (err_buf));

	--n_arg;
	++arg_buf;

	if (n_arg < 1) {
		print_cerberus_usage ();
		return STATUS_INVALID_INPUT;
	}

	for (i_arg = 0; i_arg < argc; ++i_arg) {
		if (strncmp (argv[i_arg], "-p", 2) == 0) {
			port_num = (uint8_t) strtol (argv[++i_arg], NULL, 10);
			n_arg -= 2;
			arg_buf += 2;
		}
		else if (strncmp (argv[i_arg], "-a", 2) == 0) {
			host_addr = (uint8_t) strtol (argv[++i_arg], NULL, 16);
			n_arg -= 2;
			arg_buf += 2;
		}
		else if (strncmp (argv[i_arg], "-s", 2) == 0) {
			slave_addr = (uint8_t) strtol (argv[++i_arg], NULL, 16);
			n_arg -= 2;
			arg_buf += 2;
		}
		else if (strncmp (argv[i_arg], "-r", 2) == 0) {
			num_mctp_retries = strtol (argv[++i_arg], NULL, 10);
			if (num_mctp_retries < 0) {
				printf ("Invalid input: %d\n", num_mctp_retries);
				status = STATUS_INVALID_INPUT;
				return status;
			}
			n_arg -= 2;
			arg_buf += 2;
		}
		else if (strncmp (argv[i_arg], "-e", 2) == 0) {
			target_eid = (uint8_t) strtol (argv[++i_arg], NULL, 16);
			n_arg -= 2;
			arg_buf += 2;
		}
		else if (strncmp (argv[i_arg], "--slave", 7) == 0) {
			multi_master = false;
			--n_arg;
			++arg_buf;
		}
		else if (strncmp (argv[i_arg], "--debug", 7) == 0) {
			debug = strtol (argv[++i_arg], NULL, 16);
			n_arg -= 2;
			arg_buf += 2;
		}
		else if (strncmp (argv[i_arg], "--secure", 8) == 0) {
			secure = true;
			--n_arg;
			++arg_buf;
		}
		else if (strncmp (argv[i_arg], "--time", 6) == 0) {
			print_flag |= CERBERUS_PRINT_FLAG_TIME;
			--n_arg;
			++arg_buf;
		}
		else if (strncmp (argv[i_arg], "-", 1) == 0) {
			printf ("Invalid input: unrecognized argument %s\n", argv[i_arg]);
			status = STATUS_INVALID_INPUT;
			print_cerberus_usage ();
			return status;
		}
	}

	if (cerberus_utility_cli_is_command (*arg_buf, CERBERUS_CLI_CMD_HELP)) {
		cerberus_utility_cli_show_header ();
		print_cerberus_usage ();
		return STATUS_SUCCESS;
	}

	intf_param = cerberus_interface_param_init (err_buf, CERBERUS_MAX_ERR_MSG_LEN);
	if (intf_param == NULL) {
		status = STATUS_NO_MEM;
		goto err_status_param;
	}

	status = cerberus_utility_aardvark_init_params (intf_param, port_num, host_addr,
		slave_addr, target_eid, multi_master, debug, print_flag, num_mctp_retries);
	if (status != STATUS_SUCCESS) {
		goto err_status_param;
	}

	intf = cerberus_interface_init (CERBERUS_INTF_AARDVARK, intf_param, err_buf,
		CERBERUS_MAX_ERR_MSG_LEN);
	if (intf == NULL) {
		status = STATUS_NO_MEM;
		printf ("%s\n\n", err_buf);
		goto exit;
	}

	cerberus_utility_cli_show_header ();

	status = cerberus_utility_cli_ext (intf, n_arg, arg_buf, secure);
	cerberus_utility_cli_show_result (status);

	if (status == STATUS_UNKNOWN_REQUEST) {
		print_cerberus_usage ();
	}

exit:
	cerberus_interface_deinit (intf);
	cerberus_interface_param_deinit (intf_param);

	return status;

err_status_param:
	if (intf_param == NULL) {
		printf ("%s\n\n", err_buf);
	}
	else {
		printf ("%s\n\n", cerberus_interface_param_get_last_error (intf_param));
		cerberus_interface_param_deinit (intf_param);
	}

	return status;
}
