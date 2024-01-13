// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "cerberus_utility_common.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_commands_internal.h"
#include "cerberus_utility_cerberus_protocol.h"
#include "cerberus_utility_status_codes.h"


extern const char *spi_filter_messages_str[];
extern const char *manifest_cmd_statuses_str[];


/**
 * Retrieve and optionally print Cerberus manifest update status
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest Type of manifest to get update status for
 * @param update_status Output buffer for the update status
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_get_manifest_update_status (struct cerberus_interface *intf,
	struct cerberus_manifest_request *manifest, struct cerberus_fw_update_status *update_status)
{
	char manifest_string[8];
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";
	uint32_t manifest_update_status;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((manifest == NULL) || (update_status == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	switch (manifest->manifest_type) {
		case CERBERUS_MANIFEST_PFM:
			intf->cmd_buf[0] = CERBERUS_PFM_UPDATE_STATUS;
			intf->cmd_buf[1] = manifest->port;
			strcpy (manifest_string, "PFM");
			break;

		case CERBERUS_MANIFEST_CFM:
			intf->cmd_buf[0] = CERBERUS_CFM_UPDATE_STATUS;
			strcpy (manifest_string, "CFM");
			break;

		case CERBERUS_MANIFEST_PCD:
			intf->cmd_buf[0] = CERBERUS_PCD_UPDATE_STATUS;
			strcpy (manifest_string, "PCD");
			break;

		default:
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
			return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_UPDATE_STATUS, intf->params->device_eid, sizeof (uint32_t), false,
		intf->cmd_buf, sizeof (uint8_t) + sizeof (manifest->port));
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (&manifest_update_status, intf->cmd_buf, sizeof (uint32_t));

	update_status->status_code = manifest_update_status & 0xFF;
	update_status->status_code_module = manifest_update_status >> 8;

	if (update_status->status_code < NUM_MANIFEST_CMD_STATUS) {
		snprintf (errorstr, sizeof (errorstr),
			manifest_cmd_statuses_str[update_status->status_code],
			update_status->status_code_module);
		snprintf (update_status->status_str, sizeof (update_status->status_str), "%s", errorstr);
	}
	else {
		snprintf (update_status->status_str, sizeof (update_status->status_str), "0x%x",
			manifest_update_status);
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("%s update status: %i\n", manifest_string, manifest_update_status);
	}

	return STATUS_SUCCESS;
}

/**
 * Complete a Cerberus PFM update.
 *
 * @param intf The Cerberus interface to utilize
 * @param pfm_port The struct containing port and activate setting.  Set activate_setting 0 to
 * 	activate PFM after host reboot, 1 to activate immediately
 * @param suppress_msg Flag indicating if PFM messages need to be suppressed
 * @param update_status Output buffer to be filled with update status
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_validate_host_update (struct cerberus_interface *intf,
	struct cerberus_pfm_activate *pfm, bool suppress_msg,
	struct cerberus_fw_update_status *update_status)
{
	struct cerberus_manifest_request manifest;
	uint32_t flash_error_status_code = 0;
	uint32_t status_code;
	unsigned long start_time;
	bool flash_error = false;
	bool started_activating = false;
	int status;

	intf->cmd_buf[0] = pfm->port;
	intf->cmd_buf[1] = pfm->activate_setting;

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE, intf->params->device_eid, false, intf->cmd_buf, 2);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	manifest.port = pfm->port;
	manifest.manifest_type = CERBERUS_MANIFEST_PFM;
	while (1) {
		status = cerberus_get_manifest_update_status (intf, &manifest, update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		status_code = update_status->status_code_module;

		switch (update_status->status_code) {
			case MANIFEST_CMD_STATUS_SUCCESS:
				if (!suppress_msg) {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"PFM update completed successfully\n");
				}
				return STATUS_SUCCESS;

			case MANIFEST_CMD_STATUS_STARTING:
			case MANIFEST_CMD_STATUS_VALIDATION:
				if (!pfm->activate_setting &&
					cerberus_common_timeout_expired (start_time,
						CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
						cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						__func__, __LINE__,
						cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			case MANIFEST_CMD_STATUS_ACTIVATING:
				if (!started_activating && !suppress_msg) {
					cerberus_print_info ("Starting runtime activation of PFM.\n");
					started_activating = true;
				}

				flash_error = false;
				cerberus_common_sleep_ms (50);
				continue;

			case MANIFEST_CMD_STATUS_ACTIVATION_PENDING:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"PFM update completed successfully, activation requires host reboot.\n");
				return STATUS_SUCCESS;

			case MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR:
				if (!flash_error || (status_code != flash_error_status_code)) {
					flash_error = true;
					flash_error_status_code = status_code;

					if (!suppress_msg) {
						cerberus_print_info (
							"%s. Attempting to correct error, please do not exit utility as that will keep ME in recovery mode.\n",
							update_status->status_str);
					}
					else {
						cerberus_print_info ("%s\n", update_status->status_str);
					}
					cerberus_common_sleep_ms (50);
				}

				start_time = cerberus_common_get_cpu_time_ms ();
				continue;

			default:
				if (!suppress_msg || (status_code != 0x1d09)) {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"PFM update failed: %s", update_status->status_str);
					return STATUS_UPDATE_FAILURE;
				}
				else {
					snprintf (update_status->status_str, sizeof (update_status->status_str),
						"No PFM available. No update verification could be performed.");
					return STATUS_SUCCESS;
				}
		}
	}

	return status;
}

/**
 * Parse the SPI filter configuration log entry and generate the message.
 *
 * @param port The port identifier.
 * @param config The bit field indicating the filter configuration.
 * @param message Output buffer for the formatted message.
 * @param max_message Size of the message buffer.
 */
void cerberus_format_filter_config_entry (uint32_t port, uint32_t config, char *message,
	size_t max_message)
{
	const char *bypass = "disabled";
	const char *addr = "";
	const char *mode = "";

	switch (config & (3U << 12)) {
		case (1U << 12):
			bypass = "full CS0";
			break;

		case (1U << 13):
			bypass = "full CS1";
			break;

		default:
			if (config & (1U << 14)) {
				bypass = "R/W";
			}
			break;
	}

	switch (config & ((1U << 10) | (1U << 15))) {
		case 0:
			addr = "3-byte";
			break;

		case (1U << 10):
			addr = "4-byte";
			break;

		case (1U << 15):
			addr = "fixed 3-byte";
			break;

		case ((1U << 10) | (1U << 15)):
			addr = "fixed 4-byte";
			break;
	}

	switch (config & (7U << 18)) {
		case 0:
			mode = "dual";
			break;

		case (1U << 18):
		case (2U << 18):
			mode = "bypass";
			break;

		case (3U << 18):
			mode = "single CS0";
			break;

		case (4U << 18):
			mode = "single CS1";
			break;
	}

	snprintf (message, max_message, spi_filter_messages_str[SPI_FILTER_LOGGING_FILTER_CONFIG], port,
		(config & 0xff), (config & (1U << 8)) ? "enabled" : "disabled", !!(config & (1U << 9)),
		addr, (config & (1U << 16)) ? "4-byte" : "3-byte", !!(config & (1U << 17)),
		!!(config & (1U << 11)), bypass, mode, (config & (1U << 21)) ? "full" : "R/W only");
}
