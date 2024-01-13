// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AARDVARK_COM_H_
#define AARDVARK_COM_H_

#include <stdint.h>
#include <stdbool.h>
#include "aardvark.h"
#include "cerberus_utility_interface.h"


int aardvark_detect_devices ();

int aardvark_com_init (struct cerberus_interface *intf, uint8_t port_num);

int aardvark_com_write (struct cerberus_interface *intf, uint8_t device_addr, uint8_t *buffer,
	size_t len);

int aardvark_com_read (struct cerberus_interface *intf, uint8_t device_addr, bool multi_master,
	uint8_t *r_buf, size_t *r_len);

int aardvark_com_close ();


#endif // AARDVARK_COM_H_
