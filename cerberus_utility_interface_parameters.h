// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_INTERFACE_PARAMETERS_H_
#define CERBERUS_UTILITY_INTERFACE_PARAMETERS_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "cerberus_utility_api.h"


#ifdef __cplusplus
extern "C" {
#endif


LIB_EXPORT struct cerberus_interface_param* cerberus_interface_param_init (char *err_buf,
	size_t err_buf_size);
LIB_EXPORT void cerberus_interface_param_deinit (struct cerberus_interface_param *intf_param);
int cerberus_interface_param_init_default (struct cerberus_interface_param * intf_param);

LIB_EXPORT int cerberus_interface_param_set_utility_eid (
	struct cerberus_interface_param *intf_param, uint8_t eid);
LIB_EXPORT int cerberus_interface_param_get_utility_eid (
	struct cerberus_interface_param *intf_param, uint8_t *eid);

LIB_EXPORT int cerberus_interface_param_set_device_eid (
	struct cerberus_interface_param *intf_param, uint8_t dev_eid);
LIB_EXPORT int cerberus_interface_param_get_device_eid (
	struct cerberus_interface_param *intf_param, uint8_t *dev_eid);

LIB_EXPORT int cerberus_interface_param_set_utility_address (
	struct cerberus_interface_param *intf_param, uint8_t dev_addr);
LIB_EXPORT int cerberus_interface_param_get_utility_address (
	struct cerberus_interface_param *intf_param, uint8_t *dev_addr);

LIB_EXPORT int cerberus_interface_param_set_device_address (
	struct cerberus_interface_param *intf_param, uint8_t dev_addr);
LIB_EXPORT int cerberus_interface_param_get_device_address (
	struct cerberus_interface_param *intf_param, uint8_t *dev_addr);

LIB_EXPORT int cerberus_interface_param_set_multi_master (
	struct cerberus_interface_param *intf_param, bool enable);
LIB_EXPORT int cerberus_interface_param_get_multi_master (
	struct cerberus_interface_param *intf_param, bool *enable);

LIB_EXPORT int cerberus_interface_param_set_mctp_retries (
	struct cerberus_interface_param *intf_param, int num_retries);
LIB_EXPORT int cerberus_interface_param_get_mctp_retries (
	struct cerberus_interface_param *intf_param, int *num_retries);

LIB_EXPORT int cerberus_interface_param_set_command_timeout (
	struct cerberus_interface_param *intf_param, int timeout);
LIB_EXPORT int cerberus_interface_param_get_command_timeout (
	struct cerberus_interface_param *intf_param, int *timeout);

LIB_EXPORT int cerberus_interface_param_set_aardvark_port_number (
	struct cerberus_interface_param *intf_param, int port_num);
LIB_EXPORT int cerberus_interface_param_get_aardvark_port_number (
	struct cerberus_interface_param *intf_param, int *port_num);

LIB_EXPORT int cerberus_interface_param_set_channel (
	struct cerberus_interface_param *intf_param, int channel);
LIB_EXPORT int cerberus_interface_param_get_channel (
	struct cerberus_interface_param *intf_param, int *channel);

LIB_EXPORT int cerberus_interface_param_set_print_level (
	struct cerberus_interface_param *intf_param, uint32_t print_level);
LIB_EXPORT int cerberus_interface_param_get_print_level (
	struct cerberus_interface_param *intf_param, uint32_t *print_level);

LIB_EXPORT int cerberus_interface_param_set_debug_level (
	struct cerberus_interface_param *intf_param, uint32_t debug_level);
LIB_EXPORT int cerberus_interface_param_get_debug_level (
	struct cerberus_interface_param *intf_param, uint32_t *debug_level);

LIB_EXPORT const char* cerberus_interface_param_get_last_error (
	struct cerberus_interface_param *intf_param);


#ifdef __cplusplus
}
#endif

#endif /* CERBERUS_UTILITY_INTERFACE_PARAMETERS_H_ */
