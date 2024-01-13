// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_COMMON_H_
#define CERBERUS_UTILITY_COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include "cerberus_utility_interface.h"


#ifdef __cplusplus
extern "C" {
#endif


#define MIN(a,b) 						(((a) < (b)) ? (a) : (b))
#define MAX(a,b) 						(((a) > (b)) ? (a) : (b))
#define CEIL(x) 			 			(((x - (int) (x)) > 0) ? (int) (x + 1) : (int) (x))
#define	SWAP_BYTES_UINT32(x) 			(((x >> 24) & 0xff) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | ((x << 24) & 0xff000000))
#define	SWAP_BYTES_UINT16(x) 			(((x >> 8) & 0xff) | ((x << 8) & 0xff00))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) 					(sizeof (x) / sizeof (x[0]))
#endif

#define CERBERUS_MUTEX_NAME					"/Cerberus_Mutex"
#define CERBERUS_LINUX_MUTEX_NAME			"/Cerberus_Linux_Mutex"
#define CERBERUS_MUTEX_TIMEOUT_MS			60000
#define CERBERUS_CMD_RETRY_WAIT_TIME_MS		100


void cerberus_common_sleep_ms (unsigned long time_ms);
unsigned long cerberus_common_get_cpu_time_ms ();
bool cerberus_common_timeout_expired (unsigned long start_time_ms, unsigned long timeout_period_ms);
uint32_t cerberus_common_htonl (uint32_t host_long);

void cerberus_print_set_level (uint32_t level);
void cerberus_print_info (const char* fmt, ...);
void cerberus_print_error (char *buffer, size_t buf_len, const char* function_name, int line_number,
	const char* fmt, ...);

int cerberus_utility_mutex_create (struct cerberus_interface *intf);
int cerberus_device_mutex_lock (struct cerberus_interface *intf, uint32_t wait_time_ms);
void cerberus_device_mutex_unlock (struct cerberus_interface *intf);
void cerberus_device_mutex_destroy (struct cerberus_interface *intf);
int cerberus_common_increment_byte_array (uint8_t *buf, size_t length, bool allow_rollover);


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_COMMON_H_
