// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_MCTP_PARAMS_H_
#define CERBERUS_UTILITY_MCTP_PARAMS_H_

#include <stdint.h>
#include <stddef.h>
#include "cerberus_utility_interface.h"


#ifdef __cplusplus
extern "C" {
#endif


int mctp_interface_init_parameters (struct cerberus_interface *intf, size_t max_read_pkt,
	size_t max_write_pkt);
void mctp_interface_set_parameters (struct cerberus_interface *intf);


#ifdef __cplusplus
}
#endif

#endif /* CERBERUS_UTILITY_MCTP_PARAMS_H_ */
