// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_api.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_interface_parameters.h"
#include "cerberus_utility_interface.h"


/**
 * Initialize cerberus interface parameter structure with default values.
 *
 * @param intf_param Reference to Ceberus interface parameter structure to initialize.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
int cerberus_interface_param_init_default (struct cerberus_interface_param * intf_param)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->device_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	intf_param->device_address = CERBERUS_SLAVE_ADDR;
	intf_param->multi_master = true;
	intf_param->num_mctp_retries = MCTP_PROTOCOL_CMD_DEFAULT_RETRY_TIMES;
	intf_param->print_level = CERBERUS_PRINT_FLAG_OFF;
	intf_param->debug_level = CERBERUS_DEBUG_OFF;

	return STATUS_SUCCESS;
}

/**
 * Set utility EID for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param eid Utility EID value to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_utility_eid (
	struct cerberus_interface_param *intf_param, uint8_t eid)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->utility_eid = eid;
	return STATUS_SUCCESS;
}

/**
 * Get utility EID from Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param eid Output for utility EID value.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_utility_eid (
	struct cerberus_interface_param *intf_param, uint8_t *eid)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (eid == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*eid = intf_param->utility_eid;
	return STATUS_SUCCESS;
}

/**
 * Set device EID for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param dev_eid device EID value to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_device_eid (
	struct cerberus_interface_param *intf_param, uint8_t dev_eid)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->device_eid = dev_eid;
	return STATUS_SUCCESS;
}

/**
 * Get device EID from Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param dev_eid Output for device EID value.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_device_eid (
	struct cerberus_interface_param *intf_param, uint8_t *dev_eid)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (dev_eid == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*dev_eid = intf_param->device_eid;
	return STATUS_SUCCESS;
}

/**
 * Set I2C utility address for Cerberus interface parameters instance.  This parameter is ONLY
 * applicable for CERBERUS_INTF_AARDVARK interface.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param dev_addr I2C address value to set for the utility.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_utility_address (
	struct cerberus_interface_param *intf_param, uint8_t dev_addr)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->utility_address = dev_addr;
	return STATUS_SUCCESS;
}

/**
 * Get I2C utility address from Cerberus interface parameters instance.  This parameter is ONLY
 * applicable for CERBERUS_INTF_AARDVARK interface.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param dev_addr Output for I2C utility address value.  It will hold a valid I2C utility address
 *  if Cerberus interface type is CERBERUS_INTF_AARDVARK, otherwise 0.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_utility_address (
	struct cerberus_interface_param *intf_param, uint8_t *dev_addr)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (dev_addr == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*dev_addr = intf_param->utility_address;
	return STATUS_SUCCESS;
}

/**
 * Set I2C device address for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param dev_addr I2C device address value to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_device_address (
	struct cerberus_interface_param *intf_param, uint8_t dev_addr)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->device_address = dev_addr;
	return STATUS_SUCCESS;
}

/**
 * Get I2C device address from Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param dev_addr Output for I2C device address value.  It will hold a valid I2C device address.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_device_address (
	struct cerberus_interface_param *intf_param, uint8_t *dev_addr)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (dev_addr == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*dev_addr = intf_param->device_address;
	return STATUS_SUCCESS;
}

/**
 * Set I2C multi-master mode for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param enable Flag to enable or disable I2C multi-master mode.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_multi_master (
	struct cerberus_interface_param *intf_param, bool enable)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->multi_master = enable;
	return STATUS_SUCCESS;
}

/**
 * Get I2C multi-master mode from Cerberus interface parameters instance.
 *
 * @param intf_param Ceberus interface parameters instance to utilize.
 * @param enable Output flag indicating I2C multi-master mode.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_multi_master (
	struct cerberus_interface_param *intf_param, bool *enable)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (enable == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*enable = intf_param->multi_master;
	return STATUS_SUCCESS;
}

/**
 * Set max MCTP retries for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param num_retries Max MCTP retries value to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_mctp_retries (
	struct cerberus_interface_param *intf_param, int num_retries)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->num_mctp_retries = num_retries;
	return STATUS_SUCCESS;
}

/**
 * Get max MCTP reties value from Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param num_retries Output for max MCTP retries.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_mctp_retries (
	struct cerberus_interface_param *intf_param, int *num_retries)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (num_retries == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*num_retries = intf_param->num_mctp_retries;
	return STATUS_SUCCESS;
}

/**
 * Set command timeout for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters to initialize.
 * @param timeout Command timeout value in milli seconds to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_command_timeout (
	struct cerberus_interface_param *intf_param, int timeout)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->command_timeout = timeout;
	return STATUS_SUCCESS;
}

/**
 * Get command timeout value from Cerberus interface parameters instance
 *
 * @param intf_param Cerberus interface parameters to utilize.
 * @param enable Output for command timeout value in milli seconds.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_command_timeout (
	struct cerberus_interface_param *intf_param, int *timeout)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (timeout == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*timeout = intf_param->command_timeout;
	return STATUS_SUCCESS;
}

/**
 * Set Aardvark port number for Cerberus interface parameters instance.  This parameter is ONLY
 * applicable for CERBERUS_INTF_AARDVARK interface.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param port_num Port number of the connected Aardvark device.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_aardvark_port_number (
	struct cerberus_interface_param *intf_param, int port_num)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->aardvrk_port_num = port_num;
	return STATUS_SUCCESS;
}

/**
 * Get Aardvark port number from Cerberus interface parameters instance.  This parameter is ONLY
 * applicable for CERBERUS_INTF_AARDVARK interface.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param port_num Output for Aardvark port number.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_aardvark_port_number (
	struct cerberus_interface_param *intf_param, int *port_num)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (port_num == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*port_num = intf_param->aardvrk_port_num;
	return STATUS_SUCCESS;
}

/**
 * Set I2C channel value of interface parameters.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param channel I2C channel type value to set.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_channel (
	struct cerberus_interface_param *intf_param, int channel)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->channel = channel;
	return STATUS_SUCCESS;
}

/**
 * Get I2C channel value of interface parameters.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param channel Output for I2C channel type value.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_channel (
	struct cerberus_interface_param *intf_param, int *channel)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (channel == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*channel = intf_param->channel;
	return STATUS_SUCCESS;
}

/**
 * Set print level for Cerberus interface parameters instance.  This parameter allows user to set
 * different print levels.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param print_level Print level value to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_print_level (
	struct cerberus_interface_param *intf_param, uint32_t print_level)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->print_level |= print_level;
	return STATUS_SUCCESS;
}

/**
 * Get print level for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param print_level Output for print level value.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_print_level (
	struct cerberus_interface_param *intf_param, uint32_t *print_level)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (print_level == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*print_level = intf_param->print_level;
	return STATUS_SUCCESS;
}

/**
 * Set debug level for Cerberus interface parameters instance.  This parameter allows user to set
 * different debug levels.
 *
 * @param intf_param Cerberus interface parameters instance to initialize.
 * @param debug_level Debug level value to set.
 *
 * @return STATUS_SUCCESS if set operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_set_debug_level (
	struct cerberus_interface_param *intf_param, uint32_t debug_level)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	intf_param->debug_level |= debug_level;
	return STATUS_SUCCESS;
}

/**
 * Get debug level for Cerberus interface parameters instance.
 *
 * @param intf_param Cerberus interface parameters instance to utilize.
 * @param debug_level Output for debug level value.
 *
 * @return STATUS_SUCCESS if get operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_interface_param_get_debug_level (
	struct cerberus_interface_param *intf_param, uint32_t *debug_level)
{
	if (intf_param == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (debug_level == NULL) {
		cerberus_print_error (intf_param->cmd_err_msg, sizeof (intf_param->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*debug_level = intf_param->debug_level;
	return STATUS_SUCCESS;
}

/**
 * Get Cerberus last error message
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return NULL terminated last error message.
 */
LIB_EXPORT const char* cerberus_interface_param_get_last_error (
	struct cerberus_interface_param *intf_param)
{
	if (intf_param == NULL) {
		return cerberus_utility_get_errors_str (STATUS_INVALID_INPUT);
	}

	return intf_param->cmd_err_msg;
}
