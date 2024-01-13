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
#include "cerberus_utility_debug_commands.h"



/**
 * Supported Cerberus utility command strings
 */
struct cerberus_cli_command cerberus_cli_command_list[NUM_CERBERUS_CLI_CMD] = {
	[CERBERUS_CLI_CMD_HELP] = {
		.command_str = "help",
		.command_len = 4,
		.args = 0
	},
	[CERBERUS_CLI_CMD_VERSION] = {
		.command_str = "version",
		.command_len = 7,
		.args = 0
	},
	[CERBERUS_CLI_CMD_FW_VERSION] = {
		.command_str = "fwversion <0:cerberus, 1:riot>",
		.command_len = 9,
		.args = 0
	},
	[CERBERUS_CLI_CMD_FW_UPDATE] = {
		.command_str = "fwupdate <filename>",
		.command_len = 8,
		.args = 1
	},
	[CERBERUS_CLI_CMD_PFM_ID] = {
		.command_str = "pfmid <pfm_port> <pfm_region> <0:version ID, 1:platform ID>",
		.command_len = 5,
		.args = 2
	},
	[CERBERUS_CLI_CMD_PFM_VERSIONS] = {
		.command_str = "pfmversions <pfm port> <pfm region> [fw type]",
		.command_len = 11,
		.args = 2
	},
	[CERBERUS_CLI_CMD_PFM_UPDATE] = {
		.command_str = "pfmupdate <pfm port> <filename> <0:activate after reboot, 1:activate immediately>",
		.command_len = 9,
		.args = 3
	},
	[CERBERUS_CLI_CMD_PFM_REBOOT_ACTION] = {
		.command_str = "pfmrebootaction <pfm port>",
		.command_len = 15,
		.args = 1
	},
	[CERBERUS_CLI_CMD_PFM_CHK_VERSION] = {
		.command_str = "pfmcheckversion <pfm port> <pfm region> <version string> [fw type]",
		.command_len = 15,
		.args = 3
	},
	[CERBERUS_CLI_CMD_PFM_ACTIVATE] = {
		.command_str = "pfmactivate <pfm port> <0:activate after reboot, 1:activate immediately>",
		.command_len = 11,
		.args = 2
	},
	[CERBERUS_CLI_CMD_CHECK_BYPASS] = {
		.command_str = "checkbypass <pfm port>",
		.command_len = 11,
		.args = 1
	},
	[CERBERUS_CLI_CMD_PORT_STATE] = {
		.command_str = "portstate <pfm port>",
		.command_len = 9,
		.args = 1
	},
	[CERBERUS_CLI_CMD_DEBUG_LOG_READ] = {
		.command_str = "debuglogread",
		.command_len = 12,
		.args = 0
	},
	[CERBERUS_CLI_CMD_DEBUG_LOG_CLEAR] = {
		.command_str = "debuglogclear",
		.command_len = 13,
		.args = 0
	},
	[CERBERUS_CLI_CMD_TCG_LOG_READ] = {
		.command_str = "tcglogread",
		.command_len = 10,
		.args = 0
	},
	[CERBERUS_CLI_CMD_TCG_LOG_CLEAR] = {
		.command_str = "tcglogclear",
		.command_len = 11,
		.args = 0
	},
	[CERBERUS_CLI_CMD_TCG_LOG_EXPORT] = {
		.command_str = "tcglogexport <filename> <0: autodetect, 1:generate in utility, 2: generate in FW>",
		.command_len = 12,
		.args = 1
	},
	[CERBERUS_CLI_CMD_EXPORT_CSR] = {
		.command_str = "exportcsr <filename>",
		.command_len = 9,
		.args = 1
	},
	[CERBERUS_CLI_CMD_IMPORT_SIGNED_CERT] = {
		.command_str = "importsignedcert <0:device_id, 1:root, 2:intermediate> <certificate>",
		.command_len = 16,
		.args = 2
	},
	[CERBERUS_CLI_CMD_GET_CERT_STATE] = {
		.command_str = "getcertstate",
		.command_len = 12,
		.args = 0
	},
	[CERBERUS_CLI_CMD_INTRUSION_STATE] = {
		.command_str = "intrusionstate",
		.command_len = 14,
		.args = 0
	},
	[CERBERUS_CLI_CMD_INTRUSION_RESET] = {
		.command_str = "intrusionreset <filename> <0:save token, 1:load token>",
		.command_len = 14,
		.args = 0
	},
	[CERBERUS_CLI_CMD_REVERT_BYPASS] = {
		.command_str = "revertbypass <filename> <0:save token, 1:load token>",
		.command_len = 12,
		.args = 0
	},
	[CERBERUS_CLI_CMD_RESET_DEFAULT] = {
		.command_str = "factorydefault <filename> <0:save token, 1: load token>",
		.command_len = 14,
		.args = 0
	},
	[CERBERUS_CLI_CMD_CLEAR_PLATFORM_CONFIG] = {
		.command_str = "clearpcd <filename> <0:save token, 1: load token>",
		.command_len = 8,
		.args = 0
	},
	[CERBERUS_CLI_CMD_CLEAR_COMPONENT_MANIFESTS] = {
		.command_str = "clearcfm <filename> <0:save token, 1: load token>",
		.command_len = 8,
		.args = 0
	},
	[CERBERUS_CLI_CMD_PCD_ID] = {
		.command_str = "pcdid <0:version ID, 1:platform ID>",
		.command_len = 5,
		.args = 0
	},
	[CERBERUS_CLI_CMD_PCD_UPDATE] = {
		.command_str = "pcdupdate <filename>",
		.command_len = 9,
		.args = 1
	},
	[CERBERUS_CLI_CMD_PCD_COMPONENTS] = {
		.command_str = "pcdcomponents",
		.command_len = 13,
		.args = 0
	},
	[CERBERUS_CLI_CMD_CFM_ID] = {
		.command_str = "cfmid <cfm_region> <0:version ID, 1:platform ID>",
		.command_len = 5,
		.args = 1
	},
	[CERBERUS_CLI_CMD_CFM_UPDATE] = {
		.command_str = "cfmupdate <filename> <0:activate after reboot, 1:activate immediately>",
		.command_len = 9,
		.args = 2
	},
	[CERBERUS_CLI_CMD_CFM_ACTIVATE] = {
		.command_str = "cfmactivate <0:activate after reboot, 1:activate immediately>",
		.command_len = 11,
		.args = 1
	},
	[CERBERUS_CLI_CMD_CFM_COMPONENTS] = {
		.command_str = "cfmcomponents <cfm_region>",
		.command_len = 13,
		.args = 1
	},
	[CERBERUS_CLI_CMD_HOST_STATE] = {
		.command_str = "hoststate <port_id>",
		.command_len = 9,
		.args = 1
	},
	[CERBERUS_CLI_CMD_RECOVERY_IMAGE_UPDATE] = {
		.command_str = "recimgupdate <port_id> <filename>",
		.command_len = 12,
		.args = 2
	},
	[CERBERUS_CLI_CMD_RECOVERY_IMAGE_VERSION] = {
		.command_str = "recimgversion <port_id>",
		.command_len = 13,
		.args = 1
	},
	[CERBERUS_CLI_CMD_DEVICE_INFO] = {
		.command_str = "deviceinfo",
		.command_len = 10,
		.args = 0,
	},
	[CERBERUS_CLI_CMD_DEVICE_ID] = {
		.command_str = "deviceid",
		.command_len = 8,
		.args = 0
	},
	[CERBERUS_CLI_CMD_DEVICE_CAPABILITIES] = {
		.command_str = "devicecaps",
		.command_len = 10,
		.args = 0
	},
	[CERBERUS_CLI_CMD_RESET_COUNTER] = {
		.command_str = "getresetcounter <0:cerberus, 1:component> <port_id>",
		.command_len = 15,
		.args = 0
	},
	[CERBERUS_CLI_CMD_GET_CERT_CHAIN] = {
		.command_str = "getcertchain <slot> [basename]",
		.command_len = 12,
		.args = 1
	},
	[CERBERUS_CLI_CMD_GET_CERT] = {
		.command_str = "getcert <slot> <cert> <filename>",
		.command_len = 7,
		.args = 3
	},
	[CERBERUS_CLI_CMD_GET_DIGESTS] = {
		.command_str = "getdigests [slot]",
		.command_len = 10,
		.args = 0
	},
	[CERBERUS_CLI_CMD_GET_SVN] = {
		.command_str = "getsvn",
		.command_len = 6,
		.args = 0
	},
	[CERBERUS_CLI_CMD_DETECT_DEVICE] = {
		.command_str = "detectdevice",
		.command_len = 12,
		.args = 0
	},
	[CERBERUS_CLI_CMD_CHALLENGE] = {
		.command_str = "challenge",
		.command_len = 9,
		.args = 0
	},
	[CERBERUS_CLI_CMD_TEST_ERROR] = {
		.command_str = "testerror",
		.command_len = 9,
		.args = 0
	},
	[CERBERUS_CLI_CMD_UNSEAL] = {
		.command_str = "unseal <0: RSA, 1: ECDH> <params> <seed> <cipher> <sealing> <hmac>",
		.command_len = 6,
		.args = 6
	},
	[CERBERUS_CLI_CMD_COMPONENTS_STATUS] = {
		.command_str = "compstate",
		.command_len = 9,
		.args = 0,
	},
	[CERBERUS_CLI_CMD_DIAG_HEAP] = {
		.command_str = "diagheap",
		.command_len = 8,
		.args = 0,
	},
	[CERBERUS_CLI_CMD_PRINT_MCTP_ROUTING_TABLE] = {
		.command_str = "mctproutingtable",
		.command_len = 16,
		.args = 0
	},
};

/**
 * List of CLI debug commands
 */
enum {
	CERBERUS_CLI_DEBUG_CMD_LOG_FILL = NUM_CERBERUS_CLI_CMD,
	CERBERUS_CLI_DEBUG_CMD_START_ATTESTATION,
	CERBERUS_CLI_DEBUG_CMD_ATTESTATION_STATUS,
	CERBERUS_CLI_DEBUG_CMD_END
};

#define	NUM_CERBERUS_CLI_DEBUG_CMD		(CERBERUS_CLI_DEBUG_CMD_END - NUM_CERBERUS_CLI_CMD)

/**
 * Supported Cerberus utility command strings
 */
static struct cerberus_cli_command cerberus_cli_debug_command_list[] = {
	[CERBERUS_CLI_DEBUG_CMD_LOG_FILL] = {
		.command_str = "dbglogfill",
		.command_len = 10,
		.args = 0
	},
	[CERBERUS_CLI_DEBUG_CMD_START_ATTESTATION] = {
		.command_str = "dbgstartattestation",
		.command_len = 19,
		.args = 1
	},
	[CERBERUS_CLI_DEBUG_CMD_ATTESTATION_STATUS] = {
		.command_str = "dbgattestationstatus",
		.command_len = 20,
		.args = 1
	},
};


/**
 * Determine if the provided argument matches a specified command.
 *
 * @param check The argument to check.
 * @param command_id ID of the command to compare to.
 *
 * @return true if the argument matches the expected command or false if not.
 */
bool cerberus_utility_cli_is_command (const char *check, int command_id)
{
	struct cerberus_cli_command *cmd = &cerberus_cli_command_list[command_id];

	if (check == NULL) {
		return false;
	}

	if (strlen (check) == cmd->command_len) {
		if (strncmp (check, cmd->command_str, cmd->command_len) == 0) {
			return true;
		}
	}

	return false;
}

/**
 * Determine if the provided argument matches a specified command.
 *
 * @param check The argument to check.
 * @param command_id ID of the command to compare to.
 *
 * @return true if the argument matches the expected command or false if not.
 */
static bool cerberus_utility_cli_is_debug_command (const char *check, int command_id)
{
	struct cerberus_cli_command *cmd = &cerberus_cli_debug_command_list[command_id];

	if (strlen (check) == cmd->command_len) {
		if (strncmp (check, cmd->command_str, cmd->command_len) == 0) {
			return true;
		}
	}

	return false;
}

/**
 * Determine the command to execute.
 *
 * @param argc Number of arguments.
 * @param argv The argument list.
 * @param used Output for the number of arguments consumed identifying the command.
 *
 * @return The command ID or -1 if the command is unknown or malformed.
 */
static int cerberus_utility_cli_find_command (int argc, char **argv, int *used)
{
	int i;
	int j;

	for (i = 0; i < argc; i++) {
		for (j = 0; j < NUM_CERBERUS_CLI_CMD; j++) {
			if (cerberus_utility_cli_is_command (argv[i], j)) {
				*used = i + 1;
				if ((argc - *used) < cerberus_cli_command_list[j].args) {
					return -1;
				}

				return j;
			}
		}

		for (j = NUM_CERBERUS_CLI_CMD; j < CERBERUS_CLI_DEBUG_CMD_END; j++) {
			if (cerberus_utility_cli_is_debug_command (argv[i], j)) {
				*used = i + 1;
				if ((argc - *used) < cerberus_cli_debug_command_list[j].args) {
					return -1;
				}

				return j;
			}
		}
	}

	return -1;
}

/**
 * Execute the unseal flow.
 *
 * @param intf The Cerberus interface to utilize.
 * @param type The type of unsealing the execute.
 * @param params Seed parameter to pass.
 * @param seed_path Path to the file that contains the seed.
 * @param cipher_path Path to the file that contains the ciphertext.
 * @param sealing_path Path to the file that contains the sealing value.
 * @param hmac_path Path to the file that contains the payload HMAC.
 *
 * @return Result of the unsealing operation.
 */
static int execute_unsealing (struct cerberus_interface *intf, int type, int params,
	const char *seed_path, const char *cipher_path, const char *sealing_path, const char *hmac_path)
{
	/* TODO: Get device certs and generate this data randomly to enable unseal testing. */
	uint8_t *seed = NULL;
	size_t seed_len;
	uint8_t *ciphertext = NULL;
	size_t cipher_len;
	uint8_t *sealing = NULL;
	size_t sealing_len;
	uint8_t *hmac = NULL;
	size_t hmac_len;
	uint8_t key[CERBERUS_PROTOCOL_UNSEAL_MAX_KEY_LENGTH];
	uint16_t key_length = sizeof (key);
	int status;
	int i;

	status = cerberus_read_file (intf, seed_path, &seed, &seed_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}
	status = cerberus_read_file (intf, cipher_path, &ciphertext, &cipher_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}
	status = cerberus_read_file (intf, sealing_path, &sealing, &sealing_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}
	status = cerberus_read_file (intf, hmac_path, &hmac, &hmac_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

	if (hmac_len != 32) {
		strcpy (intf->cmd_err_msg, "HMAC length is not valid");
		status = STATUS_INVALID_INPUT;
		goto exit;
	}

	if (sealing_len != (5 * 64)) {
		strcpy (intf->cmd_err_msg, "Sealing length is not valid");
		status = STATUS_INVALID_INPUT;
		goto exit;
	}

	if (!type) {
		status = cerberus_message_unseal_rsa (intf, seed, (uint16_t) seed_len,
			(enum cerberus_unseal_seed_padding) params, ciphertext, (uint16_t) cipher_len, hmac,
			(const uint8_t (*)[64]) sealing, key, &key_length);
	}
	else {
		status = cerberus_message_unseal_ecc (intf, seed, (uint16_t) seed_len,
			(enum cerberus_unseal_seed_processing) params, ciphertext, (uint16_t) cipher_len, hmac,
			(const uint8_t (*)[64]) sealing, key, &key_length);
	}

	if (status == STATUS_SUCCESS) {
		printf ("Encryption key length: %i\n", key_length);

		for (i = 0; i < key_length; ++i) {
			printf ("%02X ", key[i]);
		}

		printf ("\n");
	}

exit:
	cerberus_free (seed);
	cerberus_free (ciphertext);
	cerberus_free (sealing);
	cerberus_free (hmac);
	if (status != STATUS_SUCCESS) {
		printf ("%s\n", cerberus_get_last_error (intf));
	}
	return status;
}

/**
 * Print the utility version header to the console.
 */
void cerberus_utility_cli_show_header ()
{
	printf ("--------------------------------------------------------------------------------\n");
	printf ("-------------------- Cerberus Utility Version: %s -------------------------\n",
		cerberus_get_utility_version ());
	printf ("--------------------------------------------------------------------------------\n\n");
}

/**
 * Print the command result to the console.
 *
 * @param status Command completion status.
 */
void cerberus_utility_cli_show_result (int status)
{
	if (status == STATUS_SUCCESS) {
		printf ("\nCerberus command completed successfully.\n");
	}
	else if (status != STATUS_UNKNOWN_REQUEST) {
		printf ("\nCerberus command failed.\n");
	}
}

/**
 * Execute request utility command
 *
 * @param intf Cerberus interface to utilize
 * @param argc Number of command line arguments
 * @param argv Command line arguments
 * @param command Utility command to execute
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
static int cerberus_utility_cli_execute_command (struct cerberus_interface *intf, int argc,
	char **argv, int command)
{
	int status = STATUS_SUCCESS;

	switch (command) {
		case CERBERUS_CLI_CMD_FW_VERSION: {
			uint8_t area_index;
			uint8_t fw_version[CERBERUS_FW_VERSION_MAX_LEN];

			if (argc > 0) {
				area_index = (uint8_t) strtol (argv[0], NULL, 10);
			}
			else {
				area_index = 0;
			}

			status = cerberus_get_fwversion (intf, area_index, fw_version, sizeof (fw_version));
			if (status == STATUS_SUCCESS) {
				switch (area_index) {
					case 0:
						printf ("Cerberus Version: %s\n", fw_version);
						break;

					case 1:
						printf ("RIoT Core Version: %s\n", fw_version);
						break;

					default:
						printf ("Version: %s\n", fw_version);
						break;
				}

			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_FW_UPDATE:
			status = cerberus_fwupdate (intf, argv[0]);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;

		case CERBERUS_CLI_CMD_PFM_REBOOT_ACTION: {
			char *action_string;
			uint32_t reboot_action;
			uint8_t pfm_port = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_get_pfm_reboot_action (intf, pfm_port, &reboot_action, &action_string);
			if (status == STATUS_SUCCESS) {
				printf ("PFM Next Reboot Action: %s\n", action_string);
				cerberus_free (action_string);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PFM_UPDATE: {
			uint8_t port;
			uint8_t activate_setting;

			port = (uint8_t) strtol (argv[0], NULL, 10);
			activate_setting = (uint8_t) strtol (argv[2], NULL, 10);

			status = cerberus_pfm_update (intf, argv[1], port, activate_setting);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;
		}

		case CERBERUS_CLI_CMD_PFM_ID: {
			uint8_t port;
			uint8_t pfm_region;
			uint32_t manifest_id;
			char *manifest_platform_id = NULL;
			uint8_t id = 0;

			port = (uint8_t) strtol (argv[0], NULL, 10);
			pfm_region = (uint8_t) strtol (argv[1], NULL, 10);

			if (argc > 2) {
				id = (uint8_t) strtol (argv[2], NULL, 10);
			}

			if (id == 0) {
				status = cerberus_get_pfm_id (intf, port, pfm_region, &manifest_id);
			}
			else if (id == 1) {
				status = cerberus_get_pfm_platform_id (intf, port, pfm_region, &manifest_platform_id);
			}
			else {
				printf ("Invalid Input\n");
				status = STATUS_INVALID_INPUT;
			}

			if (status == STATUS_SUCCESS) {
				if (id == 0) {
					printf ("Cerberus PFM ID: 0x%x\n", manifest_id);
				}
				else {
					printf ("Cerberus PFM platform ID: %s\n", manifest_platform_id);
					cerberus_free (manifest_platform_id);
				}
			}
			else {
				if (status == STATUS_INVALID_MANIFEST) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PFM_VERSIONS: {
			uint8_t port;
			uint8_t pfm_region;

			port = (uint8_t) strtol (argv[0], NULL, 10);
			pfm_region = (uint8_t) strtol (argv[1], NULL, 10);

			status = cerberus_print_pfm_supported_fw_for_type (intf, port, pfm_region,
				(argc > 2) ? argv[2] : NULL);
			if (status != STATUS_SUCCESS) {
				if (status == STATUS_INVALID_MANIFEST) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PFM_CHK_VERSION: {
			uint8_t port;
			uint8_t pfm_region;
			char fw_version[CERBERUS_FW_VERSION_MAX_LEN];

			port = (uint8_t) strtol (argv[0], NULL, 10);
			pfm_region = (uint8_t) strtol (argv[1], NULL, 10);
			strncpy (fw_version, argv[2], CERBERUS_FW_VERSION_MAX_LEN);
			fw_version[CERBERUS_FW_VERSION_MAX_LEN - 1] = '\0';

			status = cerberus_check_fw_pfm_support_for_type (intf, port, pfm_region,
				(argc > 3) ? argv[3] : NULL, fw_version);
			if (status == STATUS_SUCCESS) {
				printf ("%s supported on PFM port %i, region %i\n", fw_version, port,
					pfm_region);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PFM_ACTIVATE: {
			uint8_t port;
			uint8_t activate_setting;

			port = (uint8_t) strtol (argv[0], NULL, 10);
			activate_setting = (uint8_t) strtol (argv[1], NULL, 10);

			status = cerberus_pfm_activate (intf, port, activate_setting);
			if (status != STATUS_SUCCESS) {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_CHECK_BYPASS: {
			bool bypass;
			uint8_t pfm_port = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_check_bypass_mode (intf, pfm_port, &bypass);
			if (status == STATUS_SUCCESS) {
				printf ("Port %i in %s mode\n", pfm_port, (bypass ? "bypass" : "active"));
				if (bypass) {
					status = STATUS_INVALID_MANIFEST;
				}
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PORT_STATE: {
			uint8_t state;
			uint8_t pfm_port = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_get_port_state (intf, pfm_port, &state);
			if (status == STATUS_SUCCESS) {
				printf ("Port %i is in ", pfm_port);

				switch (state) {
					case CERBERUS_PORT_STATE_ACTIVE:
						printf ("active mode\n");
						break;

					case CERBERUS_PORT_STATE_BYPASS:
						printf ("bypass mode\n");
						break;

					case CERBERUS_PORT_STATE_RECOVERY:
						printf ("recovery mode\n");
						break;

					default:
						printf ("an unknown mode\n");
						break;
				}
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_DEBUG_LOG_CLEAR:
			status = cerberus_debug_log_clear (intf);
			if (status == STATUS_SUCCESS) {
				printf ("Debug log cleared successfully\n");
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_DEBUG_LOG_READ: {
			char *debug_buffer;
			size_t debug_len;

			status = cerberus_debug_log_read (intf, &debug_buffer, &debug_len);
			if (status == STATUS_SUCCESS) {
				printf ("%s\n", debug_buffer);
				cerberus_free (debug_buffer);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_TCG_LOG_CLEAR:
			status = cerberus_attestation_log_clear (intf);
			if (status == STATUS_SUCCESS) {
				printf ("TCG log cleared successfully\n");
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_TCG_LOG_READ:
			status = cerberus_print_tcg_log (intf);
			if (status != STATUS_SUCCESS) {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_TCG_LOG_EXPORT: {
			int mode;

			if (argc > 1) {
				mode = (int) strtol (argv[1], NULL, 10);
			}
			else {
				mode = 0;
			}

			switch (mode) {
				case 1:
					status = cerberus_export_tcg_log_through_utility_file (intf, argv[0]);
					break;

				case 2:
					status = cerberus_export_tcg_log_through_fw_file (intf, argv[0]);
					break;

				default:
					status = cerberus_export_tcg_log_file (intf, argv[0]);
					break;

			}

			if (status == STATUS_SUCCESS) {
				printf ("Exported TCG event log to: %s", argv[0]);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PCD_UPDATE:
			status = cerberus_pcd_update (intf, argv[0]);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;

		case CERBERUS_CLI_CMD_PCD_ID: {
			uint32_t manifest_id;
			char *manifest_platform_id = NULL;
			uint8_t id = 0;

			if (argc > 0) {
				id = (uint8_t) strtol (argv[0], NULL, 10);
			}

			if (id == 0) {
				status = cerberus_get_pcd_id (intf, &manifest_id);
			}
			else if (id == 1) {
				status = cerberus_get_pcd_platform_id (intf, &manifest_platform_id);
			}
			else {
				printf ("Invalid Input\n");
				status = STATUS_INVALID_INPUT;
			}

			if (status == STATUS_SUCCESS) {
				if (id == 0) {
					printf ("Cerberus PCD ID: 0x%x\n", manifest_id);
				}
				else {
					printf ("Cerberus PCD platform ID: %s\n", manifest_platform_id);
					cerberus_free (manifest_platform_id);
				}

			}
			else {
				if (status == STATUS_INVALID_MANIFEST) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_CFM_UPDATE: {
			uint8_t activate = (uint8_t) strtol (argv[1], NULL, 10);

			status = cerberus_cfm_update (intf, argv[0], activate);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;
		}

		case CERBERUS_CLI_CMD_PCD_COMPONENTS: {
			status = cerberus_print_pcd_supported_components (intf);
			if (status != STATUS_SUCCESS) {
				if (status == STATUS_INVALID_MANIFEST) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_CFM_ID: {
			char *manifest_platform_id = NULL;
			uint32_t manifest_id;
			uint8_t cfm_region;
			uint8_t id = 0;

			cfm_region = (uint8_t) strtol (argv[0], NULL, 10);

			if (argc > 1) {
				id = (uint8_t) strtol (argv[1], NULL, 10);
			}

			if (id == 0) {
				status = cerberus_get_cfm_id (intf, cfm_region, &manifest_id);
			}
			else if (id == 1) {
				status = cerberus_get_cfm_platform_id (intf, cfm_region, &manifest_platform_id);
			}
			else {
				printf ("Invalid Input\n");
				status = STATUS_INVALID_INPUT;
			}

			if (status == STATUS_SUCCESS) {
				if (id == 0) {
					printf ("Cerberus CFM ID: 0x%x\n", manifest_id);
				}
				else {
					printf ("Cerberus CFM platform ID: %s\n", manifest_platform_id);
					cerberus_free (manifest_platform_id);
				}
			}
			else {
				if (status == STATUS_INVALID_MANIFEST) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_CFM_ACTIVATE: {
			uint8_t activate = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_cfm_activate (intf, activate);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;
		}

		case CERBERUS_CLI_CMD_CFM_COMPONENTS: {
			uint8_t cfm_region;

			cfm_region = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_print_cfm_supported_components (intf, cfm_region);
			if (status != STATUS_SUCCESS) {
				if (status == STATUS_INVALID_MANIFEST) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_EXPORT_CSR:
			status = cerberus_get_devid_csr (intf, argv[0]);
			if (status != STATUS_SUCCESS) {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_IMPORT_SIGNED_CERT: {
			uint8_t cert_num = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_send_signed_ca_certificate (intf, cert_num, argv[1]);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;
		}

		case CERBERUS_CLI_CMD_GET_CERT_STATE: {
			uint32_t update_status;

			status = cerberus_get_riot_cert_state (intf, &update_status, NULL);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;
		}

		case CERBERUS_CLI_CMD_INTRUSION_STATE: {
			uint8_t state;

			status = cerberus_get_intrusion_state (intf, &state);
			if (status == STATUS_SUCCESS) {
				switch (state) {
					case CERBERUS_INTRUSION_STATE_INTRUDED:
						printf ("Chassis intrusion detected\n");
						break;

					case CERBERUS_INTRUSION_STATE_NOT_INTRUDED:
						printf ("No chassis intrusion detected\n");
						break;

					default:
						printf ("Intrusion state has not been determined\n");
						break;
				}
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_INTRUSION_RESET: {
			if (argc > 0) {
				if (argc > 1) {
					bool load_token = (bool) strtol (argv[1], NULL, 10);

					status = cerberus_reset_intrusion_configuration (intf, argv[0], load_token);
					printf ("%s\n", cerberus_get_last_error (intf));
				}
				else {
					status = STATUS_UNKNOWN_REQUEST;
				}
			}
			else {
				status = cerberus_reset_intrusion_configuration (intf, NULL, false);
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_REVERT_BYPASS:
			if (argc > 0) {
				if (argc > 1) {
					bool load_token = (bool) strtol (argv[1], NULL, 10);

					status = cerberus_reset_bypass_configuration (intf,	argv[0], load_token);
					printf ("%s\n", cerberus_get_last_error (intf));
				}
				else {
					status = STATUS_UNKNOWN_REQUEST;
				}
			}
			else {
				status = cerberus_reset_bypass_configuration (intf, NULL, false);
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_RESET_DEFAULT:
			if (argc > 0) {
				if (argc > 1) {
					bool load_token = (bool) strtol (argv[1], NULL, 10);

					status = cerberus_reset_default_configuration (intf, argv[0], load_token);
					printf ("%s\n", cerberus_get_last_error (intf));
				}
				else {
					status = STATUS_UNKNOWN_REQUEST;
				}
			}
			else {
				status = cerberus_reset_default_configuration (intf, NULL, false);
				printf ("%s\n", cerberus_get_last_error (intf));

			}

			break;

		case CERBERUS_CLI_CMD_CLEAR_PLATFORM_CONFIG:
			if (argc > 0) {
				if (argc > 1) {
					bool load_token = (bool) strtol (argv[1], NULL, 10);

					status = cerberus_reset_platform_configuration (intf, argv[0], load_token);
					printf ("%s\n", cerberus_get_last_error (intf));
				}
				else {
					status = STATUS_UNKNOWN_REQUEST;
				}
			}
			else {
				status = cerberus_reset_platform_configuration (intf, NULL, false);
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_CLEAR_COMPONENT_MANIFESTS:
			if (argc > 0) {
				if (argc > 1) {
					bool load_token = (bool) strtol (argv[1], NULL, 10);

					status = cerberus_reset_component_configuration (intf, argv[0], load_token);
					printf ("%s\n", cerberus_get_last_error (intf));
				}
				else {
					status = STATUS_UNKNOWN_REQUEST;
				}
			}
			else {
				status = cerberus_reset_component_configuration (intf, NULL, false);
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_HOST_STATE: {
			uint8_t host_state;
			const char *state_str;
			uint8_t pfm_port = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_get_host_state (intf, pfm_port, &host_state);
			if (status == STATUS_SUCCESS) {
				state_str = cerberus_get_host_state_str (intf, host_state);
				if (state_str != NULL) {
					printf ("Host %i State: %s\n", pfm_port, state_str);
				}
				else {
					printf ("Host %i State: %x\n", pfm_port, host_state);
				}
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_RECOVERY_IMAGE_UPDATE: {
			uint8_t pfm_port = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_recovery_image_update (intf, pfm_port, argv[1]);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;
		}

		case CERBERUS_CLI_CMD_RECOVERY_IMAGE_VERSION: {
			uint8_t fw_version[CERBERUS_FW_VERSION_MAX_LEN];
			uint8_t pfm_port = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_get_recovery_image_version (intf, pfm_port, fw_version,
				sizeof (fw_version));
			if (status == STATUS_SUCCESS) {
				printf ("Recovery Image Version: %s\n", fw_version);
			}
			else {
				if (status == STATUS_INVALID_RECOVERY_IMAGE) {
					status = STATUS_SUCCESS;
				}
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_DEVICE_INFO: {
			uint8_t device_info[CERBERUS_FW_VERSION_MAX_LEN];
			size_t length = CERBERUS_FW_VERSION_MAX_LEN;
			size_t i;

			status = cerberus_get_device_info (intf, device_info, &length);
			if (status == STATUS_SUCCESS) {
				printf ("Chip UUID: ");
				for (i = 0; i < length; i++) {
					printf ("%02x", device_info[i]);
				}
				printf ("\n");
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_DEVICE_ID: {
			struct cerberus_device_id ids;

			status = cerberus_get_device_id (intf, &ids);
			if (status == STATUS_SUCCESS) {
				printf ("Vendor ID: 0x%02x\n", ids.vendor_id);
				printf ("Device ID: 0x%02x\n", ids.device_id);
				printf ("Subsystem Vendor ID: 0x%02x\n", ids.subsystem_vid);
				printf ("Subsystem ID: 0x%02x\n", ids.subsystem_id);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_DEVICE_CAPABILITIES: {
			struct cerberus_device_caps capabilities;

			status = cerberus_get_device_capabilities (intf, &capabilities);
			if (status == STATUS_SUCCESS) {
				printf ("Max Message Body: %d\n", capabilities.max_message_body);
				printf ("Max Packet Payload: %d\n", capabilities.max_packet_payload);
				printf ("Request Timeout: %d\n", capabilities.max_message_timeout);
				printf ("Crypto Timeout: %d\n", capabilities.max_crypto_timeout);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_RESET_COUNTER: {
			uint8_t area_index = 0;
			uint8_t pfm_port = 0;
			uint16_t reset_count;

			if (argc > 0) {
				area_index = (uint8_t) strtol (argv[0], NULL, 10);
			}

			if ((area_index == 1) && (argc < 2)) {
				status = STATUS_UNKNOWN_REQUEST;
			}
			else {
				if (argc > 1) {
					pfm_port = (uint8_t) strtol (argv[1], NULL, 10);
				}

				status = cerberus_get_reset_counter (intf, area_index, pfm_port, &reset_count);
				if (status == STATUS_SUCCESS) {
					printf ("Reset counter: %i\n", reset_count);
				}
				else {
					printf ("%s\n", cerberus_get_last_error (intf));
				}
			}

			break;
		}

		case CERBERUS_CLI_CMD_GET_CERT_CHAIN: {
			int i_cert;
			struct cerberus_cert_chain chain;
			uint8_t slot_num = (uint8_t) strtol (argv[0], NULL, 10);
			char *basename = "cert";

			if (argc > 1) {
				basename = argv[1];
			}

			status = cerberus_get_cert_chain (intf, slot_num, &chain);
			if (status == STATUS_SUCCESS) {
				printf ("Number of certificates in chain: %i\n\n", chain.num_cert);

				for (i_cert = 0; i_cert < chain.num_cert; ++i_cert) {
					char file[CERBERUS_FILENAME_MAX_LEN];

					snprintf (file, sizeof (file), "%s_%d.der", basename, i_cert);
					file[CERBERUS_FILENAME_MAX_LEN - 1] = '\0';

					printf ("Size of cert (%i): %zi\n", i_cert, chain.cert[i_cert].cert_len);
					status = cerberus_write_file (intf, file, chain.cert[i_cert].cert,
						chain.cert[i_cert].cert_len);
					if (status != STATUS_SUCCESS) {
						printf ("Failed to write cert %i\n", i_cert);
						printf ("%s\n", cerberus_get_last_error (intf));
						continue;
					}
				}

				cerberus_free_cert_chain (&chain);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_GET_CERT: {
			struct cerberus_cert cert;
			uint8_t slot_num = (uint8_t) strtol (argv[0], NULL, 10);
			uint8_t cert_num = (uint8_t) strtol (argv[1], NULL, 10);

			status = cerberus_get_cert (intf, slot_num, cert_num, &cert);
			if (status == STATUS_SUCCESS) {
				status = cerberus_write_file (intf, argv[2], cert.cert, cert.cert_len);
				cerberus_free_cert (&cert);

				if (status != STATUS_SUCCESS) {
					printf ("%s\n", cerberus_get_last_error (intf));
				}
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_GET_DIGESTS: {
			struct cerberus_digests digests;
			uint8_t slot_num = 0;
			uint32_t i;

			if (argc > 0) {
				slot_num = (uint8_t) strtol (argv[0], NULL, 10);
			}

			status = cerberus_get_digests (intf, slot_num, &digests);
			if (status == STATUS_SUCCESS) {
				printf ("Number of certificates in chain: %zi\n\n", digests.num_digest);

				for (i = 0; i < digests.num_digest; i++) {
					uint8_t *digest = digests.digest + (i * digests.digest_len);
					uint32_t j;

					printf ("Digest (%i): ", i);
					for (j = 0; j < digests.digest_len; j++) {
						printf ("%02x", digest[j]);
					}
					printf ("\n");
				}

				cerberus_free_digests (&digests);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_GET_SVN: {
			struct cerberus_svns svns;

			// Get the SVNs.
			status = cerberus_get_svn_number (intf, &svns);
			if (status == STATUS_SUCCESS) {
				uint32_t i;

				printf ("Number of SVNs: %zi\n\n", svns.num_svn);

				for (i = 0; i < svns.num_svn; i++) {
					uint32_t j;

					printf ("SVN (%i): ", i);
					for (j = 0; j < svns.list[i].svn_length; j++) {
						printf ("%02x", svns.list[i].svn_data[j]);
					}
					printf ("\n");
				}

				cerberus_free_svns (&svns);
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_DETECT_DEVICE:
			status = cerberus_detect_device (intf);
			if (status == STATUS_NO_DEVICE) {
				printf ("Cerberus is not supported on this platform.\n");
			}
			else if (status == STATUS_SUCCESS) {
				printf ("Cerberus is supported on this platform.\n");
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		case CERBERUS_CLI_CMD_UNSEAL: {
			int type = (uint8_t) strtol (argv[0], NULL, 10);
			int params = (uint8_t) strtol (argv[1], NULL, 10);

			status = execute_unsealing (intf, type, params, argv[2], argv[3], argv[4], argv[5]);

			break;
		}

		case CERBERUS_CLI_CMD_CHALLENGE: {
			uint8_t pmr0_buf[CERBERUS_PCR_LEN];
			size_t i;

			status = cerberus_attestation_challenge (intf, NULL, 0, pmr0_buf, CERBERUS_PCR_LEN);
			if (status == STATUS_SUCCESS) {
				printf ("Attestation completed successfully.\nPMR0: ");
				for (i = 0; i < CERBERUS_PCR_LEN; i++) {
					printf ("%X ", pmr0_buf[i]);
				}
				printf ("\n");
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_TEST_ERROR: {
			status = cerberus_test_error_msg (intf);
			if (status == STATUS_SUCCESS) {
				printf ("Test completed successfully.\n");
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_COMPONENTS_STATUS: {
			status = cerberus_print_component_status (intf);
			if (status != STATUS_SUCCESS) {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_DIAG_HEAP: {
			struct cerberus_heap heap;

			status = cerberus_current_heap_usage (intf, &heap);
			if (status == STATUS_SUCCESS) {
				printf ("Heap Usage:\n");
				if (heap.total > 0) {
					printf ("\tTotal: %d\n", heap.total);
				}
				if (heap.free > 0) {
					printf ("\tFree: %d\n", heap.free);
				}
				if (heap.min_free > 0) {
					printf ("\tMinimum Free: %d\n", heap.min_free);
				}
				if (heap.free_blocks > 0) {
					printf ("\tFree Blocks: %d\n", heap.free_blocks);
				}
				if (heap.max_block > 0) {
					printf ("\tMax Block Size: %d\n", heap.max_block);
				}
				if (heap.min_block > 0) {
					printf ("\tMin Block Size: %d\n", heap.min_block);
				}
			}
			else {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;
		}

		case CERBERUS_CLI_CMD_PRINT_MCTP_ROUTING_TABLE:
			status = cerberus_print_mctp_routing_table (intf);
			if (status != STATUS_SUCCESS) {
				printf ("%s\n", cerberus_get_last_error (intf));
			}

			break;

		/* Test/debug commands. */
		case CERBERUS_CLI_DEBUG_CMD_LOG_FILL:
			status = cerberus_debug_fill_log (intf);
			printf ("%s\n", cerberus_get_last_error (intf));

			break;

		case CERBERUS_CLI_DEBUG_CMD_START_ATTESTATION: {
			uint8_t device_num = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_debug_start_attestation (intf, device_num);

			break;
		}

		case CERBERUS_CLI_DEBUG_CMD_ATTESTATION_STATUS: {
			uint8_t attestation_status;
			uint8_t device_num = (uint8_t) strtol (argv[0], NULL, 10);

			status = cerberus_debug_get_attestation_status (intf, device_num, &attestation_status);
			if (status == STATUS_SUCCESS) {
				if (attestation_status == 0) {
					printf ("Cerberus Device %i Not Authenticated\n", device_num);
				}
				else if (attestation_status == 1) {
					printf ("Cerberus Device %i Authenticated\n", device_num);
				}
			}

			break;
		}

	}

	return status;
}

/**
 * Connect to a remote Cerberus device.
 *
 * @param intf Cerberus interface to utilize.
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code.
*/
int cerberus_utility_cli_connect_device (struct cerberus_interface *intf)
{
	int status;
	unsigned long connect_start_time_ms;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) ) {
		printf ("[%s:%i] Invalid input.\r\n", __func__, __LINE__);
		return STATUS_INVALID_INPUT;
	}

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		connect_start_time_ms = cerberus_get_cpu_time_ms ();
	}

	status = cerberus_remote_device_connect (intf);
	if (status != STATUS_SUCCESS) {
		printf ("Failed to connect to Cerberus device: %s\n\n", cerberus_get_last_error (intf));
		return status;
	}

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		printf ("Remote device connect executed in %li milliseconds.\n\n",
			cerberus_get_cpu_time_ms () - connect_start_time_ms);
	}

	return status;
}

/**
 * Set up an encrypted channel to the remote cerberus device. Remote device connect
 * should be called before setting up encrypted channel.
 *
 * @param intf Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 * @param secure_channel_created Output True if encrypted channel is established.
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code.
*/
int cerberus_utility_cli_setup_secure_channel (struct cerberus_interface *intf,
	uint8_t *root_ca, size_t root_ca_len, bool *secure_channel_created)
{

	int status;
	unsigned long encrypt_start_time_ms;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (secure_channel_created == NULL)) {
		printf ("[%s:%i] Invalid input.\r\n", __func__, __LINE__);
		return STATUS_INVALID_INPUT;
	}

	*secure_channel_created = false;

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		encrypt_start_time_ms = cerberus_get_cpu_time_ms ();
	}

	status = cerberus_setup_encrypted_channel (intf, root_ca, root_ca_len);
	if (status != STATUS_SUCCESS) {
		printf ("Failed to setup secure session: %s\n", cerberus_get_last_error (intf));
		return status;
	}

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		printf ("Channel encryption setup executed in %li milliseconds.\n\n",
			cerberus_get_cpu_time_ms () - encrypt_start_time_ms);
	}

	*secure_channel_created = true;

	printf ("Secure session established with Cerberus device.\n\n");

	return status;
}

/**
 * Process command line input and perform supported actions using optional encrypted channel to
 * device
 *
 * @param intf Cerberus interface to utilize
 * @param argc Number of command line arguments
 * @param argv Command line arguments
 * @param secure Flag used to indicate whether a secure channel is requested
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
int cerberus_utility_cli_ext (struct cerberus_interface *intf, int argc, char **argv,
	bool secure)
{
	unsigned long total_start_time_ms;
	unsigned long cmd_start_time_ms;
	bool skip_cerberus_protocol_setup = false;
	bool channel_created = false;
	int command;
	int used_args = 0;
	int status;
	int status_bridge_request;

	if ((intf == NULL) || (intf->params == NULL) || (argv == NULL)) {
		printf ("[%s:%i] Invalid input.\r\n", __func__, __LINE__);
		return STATUS_INVALID_INPUT;
	}

	if (argc < 1) {
		return STATUS_UNKNOWN_REQUEST;
	}

	command = cerberus_utility_cli_find_command (argc, argv, &used_args);
	if ((command == -1) || (command == CERBERUS_CLI_CMD_HELP)) {
		return STATUS_UNKNOWN_REQUEST;
	}

	if (command == CERBERUS_CLI_CMD_VERSION) {
		return STATUS_SUCCESS;
	}

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		total_start_time_ms = cerberus_get_cpu_time_ms ();
	}

	if ((command == CERBERUS_CLI_CMD_PRINT_MCTP_ROUTING_TABLE) ||
		(command == CERBERUS_CLI_CMD_DETECT_DEVICE)) {
		skip_cerberus_protocol_setup = true;
	}

	if (!skip_cerberus_protocol_setup) {
		status = cerberus_utility_cli_connect_device (intf);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		if (secure) {
			status = cerberus_utility_cli_setup_secure_channel (intf, NULL, 0, &channel_created);
			if (status != STATUS_SUCCESS) {
				goto exit;
			}
		}
	}

	argc -= used_args;
	argv += used_args;

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		cmd_start_time_ms = cerberus_get_cpu_time_ms ();
	}

	status = cerberus_utility_cli_execute_command (intf, argc, argv, command);

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		printf ("\nCommand executed in %li milliseconds.\n",
			cerberus_get_cpu_time_ms () - cmd_start_time_ms);
	}

	if (channel_created) {
		cerberus_close_encrypted_channel (intf);
	}

	if (intf->params->print_level & CERBERUS_PRINT_FLAG_TIME) {
		printf ("Total execution took %li milliseconds.\n",
			cerberus_get_cpu_time_ms () - total_start_time_ms);
	}

exit:
	status_bridge_request = cerberus_utility_clear_bridge_request (intf);
	if (status == STATUS_SUCCESS) {
		status = status_bridge_request;
	}

	return status;
}

/**
 * Process command line input and perform supported actions.
 *
 * DEPRECATED: Use cerberus_utility_cli_ext() instead.
 *
 * @param intf Cerberus interface to utilize
 * @param argc Number of command line arguments
 * @param argv Command line arguments
 *
 * @return STATUS_SUCCESS if operation completed successfully or error code
 */
int cerberus_utility_cli (struct cerberus_interface *intf, int argc, char **argv)
{
	return cerberus_utility_cli_ext (intf, argc, argv, false);
}
