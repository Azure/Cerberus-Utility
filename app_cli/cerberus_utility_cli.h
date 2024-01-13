// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_CLI_H_
#define CERBERUS_UTILITY_CLI_H_

#include "cerberus_utility_interface.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * List of CLI commands
 */
enum {
	CERBERUS_CLI_CMD_HELP,
	CERBERUS_CLI_CMD_VERSION,
	CERBERUS_CLI_CMD_FW_VERSION,
	CERBERUS_CLI_CMD_FW_UPDATE,
	CERBERUS_CLI_CMD_PFM_ID,
	CERBERUS_CLI_CMD_PFM_VERSIONS,
	CERBERUS_CLI_CMD_PFM_UPDATE,
	CERBERUS_CLI_CMD_PFM_REBOOT_ACTION,
	CERBERUS_CLI_CMD_PFM_CHK_VERSION,
	CERBERUS_CLI_CMD_PFM_ACTIVATE,
	CERBERUS_CLI_CMD_CHECK_BYPASS,
	CERBERUS_CLI_CMD_PORT_STATE,
	CERBERUS_CLI_CMD_DEBUG_LOG_READ,
	CERBERUS_CLI_CMD_DEBUG_LOG_CLEAR,
	CERBERUS_CLI_CMD_TCG_LOG_READ,
	CERBERUS_CLI_CMD_TCG_LOG_CLEAR,
	CERBERUS_CLI_CMD_TCG_LOG_EXPORT,
	CERBERUS_CLI_CMD_EXPORT_CSR,
	CERBERUS_CLI_CMD_IMPORT_SIGNED_CERT,
	CERBERUS_CLI_CMD_GET_CERT_STATE,
	CERBERUS_CLI_CMD_INTRUSION_STATE,
	CERBERUS_CLI_CMD_INTRUSION_RESET,
	CERBERUS_CLI_CMD_REVERT_BYPASS,
	CERBERUS_CLI_CMD_RESET_DEFAULT,
	CERBERUS_CLI_CMD_CLEAR_PLATFORM_CONFIG,
	CERBERUS_CLI_CMD_CLEAR_COMPONENT_MANIFESTS,
	CERBERUS_CLI_CMD_PCD_ID,
	CERBERUS_CLI_CMD_PCD_UPDATE,
	CERBERUS_CLI_CMD_PCD_COMPONENTS,
	CERBERUS_CLI_CMD_CFM_ID,
	CERBERUS_CLI_CMD_CFM_UPDATE,
	CERBERUS_CLI_CMD_CFM_ACTIVATE,
	CERBERUS_CLI_CMD_CFM_COMPONENTS,
	CERBERUS_CLI_CMD_HOST_STATE,
	CERBERUS_CLI_CMD_RECOVERY_IMAGE_UPDATE,
	CERBERUS_CLI_CMD_RECOVERY_IMAGE_VERSION,
	CERBERUS_CLI_CMD_DEVICE_INFO,
	CERBERUS_CLI_CMD_DEVICE_ID,
	CERBERUS_CLI_CMD_DEVICE_CAPABILITIES,
	CERBERUS_CLI_CMD_RESET_COUNTER,
	CERBERUS_CLI_CMD_GET_CERT_CHAIN,
	CERBERUS_CLI_CMD_GET_CERT,
	CERBERUS_CLI_CMD_GET_DIGESTS,
	CERBERUS_CLI_CMD_GET_SVN,
	CERBERUS_CLI_CMD_DETECT_DEVICE,
	CERBERUS_CLI_CMD_CHALLENGE,
	CERBERUS_CLI_CMD_TEST_ERROR,
	CERBERUS_CLI_CMD_UNSEAL,
	CERBERUS_CLI_CMD_COMPONENTS_STATUS,
	CERBERUS_CLI_CMD_DIAG_HEAP,
	CERBERUS_CLI_CMD_PRINT_MCTP_ROUTING_TABLE,
	NUM_CERBERUS_CLI_CMD
};


/**
 * Container for CLI commands
 */
struct cerberus_cli_command {
	const char *command_str;							/**< String for command name */
	size_t command_len;									/**< Length of command name string */
	int args;											/**< Number of required arguments */
};

extern struct cerberus_cli_command cerberus_cli_command_list[NUM_CERBERUS_CLI_CMD];


bool cerberus_utility_cli_is_command (const char *check, int command_id);
void cerberus_utility_cli_show_header (void);
void cerberus_utility_cli_show_result (int status);
int cerberus_utility_cli_ext (struct cerberus_interface *intf, int argc, char **argv,
	bool secure);
int cerberus_utility_cli_connect_device (struct cerberus_interface *intf);
int cerberus_utility_cli_setup_secure_channel (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len, bool *secure_channel_created);

// DEPRECATED: Use cerberus_utility_cli_ext() instead.
int cerberus_utility_cli (struct cerberus_interface *intf, int argc, char **argv);


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_CLI_H_
