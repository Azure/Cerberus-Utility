// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#ifdef __unix__
#include <fcntl.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif
#include "cerberus_utility_status_codes.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_common.h"
#include "unused.h"


static uint32_t cerberus_print_flag = 0;

#ifndef CERBERUS_UTILITY_NO_MUTEX
#ifdef __unix__

/**
 * Container of information for a shared memory mutex.
 */
struct cerberus_device_shared_mutex {
	int shm;							/**< Handle to a shared memory object. */
	pthread_mutex_t *mutex;				/**< Handle to the pthread mutex. */
};


/**
 * Initialize a shared mutex.  This function temporarily overrides the caller's umask so mutex can
 * be created or updated (if already created) so other callers not in the same group can access it.
 *
 * @param mutex_handle Output handle to a mutex around communication to a Cerberus device. This will be
 * NULL on error.
 * @param syscall_pthr_err Pointer pointing to the location where either system call error or
 * pthread function call failure is saved.
 *
 * @return 0 if the mutex was successfully initialized or an error code
 */
static int cerberus_device_shared_mutex_init (struct cerberus_device_shared_mutex **mutex_handle,
	int *syscall_pthr_err)
{
	pthread_mutexattr_t mutex_attrib;
	int shm;
	pthread_mutex_t *mutex;
	int err_no = STATUS_SUCCESS;
	mode_t curr_umask;

	*syscall_pthr_err = 0;

	//Set the umask to 000 and store the current umask
	curr_umask = umask (0);

	// Attempt to create and open shm if it does not exist yet.
	shm = shm_open (CERBERUS_LINUX_MUTEX_NAME, O_CREAT | O_EXCL | O_RDWR, (S_IRWXU | S_IRWXG | S_IRWXO));

	// shm already exists. Some process might be using it.
	if (shm < 0) {

		// Open shm, instead of creating it.
		shm = shm_open (CERBERUS_LINUX_MUTEX_NAME, O_RDWR, (S_IRWXU | S_IRWXG | S_IRWXO));

		// Failed to open the existing shm for Rd/Wr
		if (shm < 0) {
			*syscall_pthr_err = errno;
			err_no = STATUS_MUTEX_SHM_OPEN_FAILURE;
			goto clean_umask;
		}

		/*
		 * 1) If mutex was created with the old version of cerberus_utlity,
		 * the permissions may be incorrect.  Update the permissions so everyone can access it.
		 * 2) Ensure calls to fchmod() are non-fatal so that different
		 * users than the file owner can open/access it.
		 */
		fchmod (shm, (S_IRWXU | S_IRWXG | S_IRWXO));

		// Memory map shm with mutex.
		mutex = (pthread_mutex_t*) mmap (NULL, sizeof (pthread_mutex_t), PROT_READ | PROT_WRITE,
			MAP_SHARED, shm, 0);
		if (mutex == MAP_FAILED) {
			*syscall_pthr_err = errno;
			err_no = STATUS_MUTEX_MAP_SHM_FAILURE;
			goto clean_shm;
		}
	}
	// shm is just created. Initialize it.
	else {
		if (ftruncate (shm, sizeof (pthread_mutex_t)) != 0) {
			*syscall_pthr_err = errno;
			err_no = STATUS_MUTEX_TRUNCATE_SHM_FAILURE;
			goto clean_shm;
		}

		// Memory map shm with mutex.
		mutex = (pthread_mutex_t*) mmap (NULL, sizeof (pthread_mutex_t),
			PROT_READ | PROT_WRITE, MAP_SHARED, shm, 0);
		if (mutex == MAP_FAILED) {
			*syscall_pthr_err = errno;
			err_no = STATUS_MUTEX_MAP_SHM_FAILURE;
			goto clean_shm;
		}

		*syscall_pthr_err = pthread_mutexattr_init (&mutex_attrib);
		if (*syscall_pthr_err != 0) {
			err_no = STATUS_MUTEX_INIT_ATTR_FAILURE;
			goto clean_mutex;
		}

		*syscall_pthr_err = pthread_mutexattr_setpshared (&mutex_attrib, PTHREAD_PROCESS_SHARED);
		if (*syscall_pthr_err != 0) {
			err_no = STATUS_MUTEX_SET_SHARED_ATTR_FAILURE;
			goto clean_mutex;
		}

		*syscall_pthr_err = pthread_mutexattr_settype (&mutex_attrib, PTHREAD_MUTEX_NORMAL);
		if (*syscall_pthr_err != 0) {
			err_no = STATUS_MUTEX_SET_ATTR_TYPE_FAILURE;
			goto clean_mutex;
		}

		*syscall_pthr_err = pthread_mutexattr_setrobust (&mutex_attrib, PTHREAD_MUTEX_ROBUST);
		if (*syscall_pthr_err != 0) {
			err_no = STATUS_MUTEX_SET_ROBUS_ATTR_FAILURE;
			goto clean_mutex;
		}

		*syscall_pthr_err = pthread_mutex_init (mutex, &mutex_attrib);
		if (*syscall_pthr_err != 0) {
			err_no = STATUS_MUTEX_INIT_FAILURE;
			goto clean_mutex;
		}
	}

	*mutex_handle = malloc (sizeof (struct cerberus_device_shared_mutex));
	if (*mutex_handle == NULL) {
		err_no = STATUS_MUTEX_ALLOCATE_MEMORY_FAILURE;
		goto clean_mutex;
	}

	(*mutex_handle)->mutex = mutex;
	(*mutex_handle)->shm = shm;

	// Restore the process's umask
	umask (curr_umask);
	return STATUS_SUCCESS;

clean_mutex:
	munmap (mutex, sizeof (pthread_mutex_t));
clean_shm:
	close (shm);
	*mutex_handle = NULL;
clean_umask:
	umask (curr_umask);
	return err_no;
}

/**
 * Check for and wait on the shared mutex for the configured timeout
 *
 * @param handle Handle to a mutex around communication to a Cerberus device
 * @param msecs Timeout period in milliseconds
 * @param pthread_err Pointer pointing to the location where pthread function call failure is saved.
 *
 * @return 0 if the mutex was successfully locked or an error code
 */
static int cerberus_device_shared_mutex_timeout (struct cerberus_device_shared_mutex *handle,
	uint32_t msecs, int *pthread_err)
{
	struct timespec maxtime;

	clock_gettime (CLOCK_REALTIME , &maxtime);
	maxtime.tv_sec += msecs / 1000;
	maxtime.tv_nsec += (msecs % 1000) * 1000000ULL;
	if (maxtime.tv_nsec > 999999999L) {
		maxtime.tv_sec++;
		maxtime.tv_nsec -= 1000000000ULL;
	}

	*pthread_err = pthread_mutex_timedlock (handle->mutex, &maxtime);
	if (*pthread_err != 0) {
		if (*pthread_err == EOWNERDEAD) {
			pthread_mutex_consistent (handle->mutex);
		}
		else if (*pthread_err == ETIMEDOUT) {
			return STATUS_MUTEX_WAIT_TIMEOUT_FAILURE;
		}
		else {
			return STATUS_MUTEX_FAILURE;
		}
	}

	return 0;
}
#endif
#endif

/**
 * Get current CPU time in milliseconds
 *
 * @return CPU time in milliseconds
 */
unsigned long cerberus_common_get_cpu_time_ms ()
{
#ifdef __unix__
	struct timespec curr_time;

	clock_gettime (CLOCK_MONOTONIC, &curr_time);

	return (1000.0 * curr_time.tv_sec + curr_time.tv_nsec / 1000000.0);
#elif _WIN32
	return (unsigned long)((clock () * 1000.0) / CLOCKS_PER_SEC);
#else
#error Platform unsupported
#endif
}

/**
 * Check if timeout has expired
 *
 * @param start_time_ms Start time in milliseconds
 * @param timeout_period_ms Timeout period in milliseconds
 *
 * @return True if timeout has expired, False otherwise
 */
bool cerberus_common_timeout_expired (unsigned long start_time_ms, unsigned long timeout_period_ms)
{
	return ((cerberus_common_get_cpu_time_ms () - start_time_ms) >= timeout_period_ms);
}

/**
 * Sleep for a given period of time in milliseconds
 *
 * @param time_ms sleep time in milliseconds
 */
void cerberus_common_sleep_ms (unsigned long time_ms)
{
#ifdef __unix__
	usleep (time_ms * 1000);
#endif
#ifdef _WIN32
	Sleep (time_ms);
#endif
}

/**
 * Convert the unsigned 32-bit integer host_long from host byte order to network byte order.
 * Assumes host byte order is different from network byte order.
 *
 * @param host_long The unsigned 32-bit integer to convert.
 */
uint32_t cerberus_common_htonl (uint32_t host_long)
{
#ifdef __unix__
	return htonl (host_long);
#elif _WIN32
	return SWAP_BYTES_UINT32 (host_long);
#else
#error Platform unsupported
#endif
}

/**
 * Set Cerberus print flag
 *
 * @param level value indicating what different print flags to enable.
 */
void cerberus_print_set_level (uint32_t level)
{
	cerberus_print_flag = level;
}

/**
 * Print Cerberus info message
 *
 * @param fmt Message format
 * @param ... Additional arguments
 */
void cerberus_print_info (const char* fmt, ...) {
	va_list args;

	if (cerberus_print_flag & CERBERUS_PRINT_FLAG_INFO) {
		va_start (args, fmt);
		vprintf (fmt, args);
		va_end (args);
	}
}

/**
 * Copy or Print Cerberus error message
 *
 * @param buffer Output Buffer to be filled with error message.  NULL value will
 * 	print the error message.
 * @param buf_len Length of the output buffer.  Buffer length 0 will print the error message.
 * @param function_name String of function where error happened
 * @param line_number Line number where error happened
 * @param fmt Message format
 * @param ... Additional arguments
 */
void cerberus_print_error (char *buffer, size_t buf_len, const char* function_name, int line_number,
	const char* fmt, ...)
{
	va_list args;
	size_t len;

	if ((buffer != NULL) && (buf_len > 0)) {
		len = snprintf (buffer, buf_len, "[%s:%i] ", function_name, line_number);
		va_start (args, fmt);
		vsnprintf (&buffer[len], (buf_len - len), fmt, args);
		va_end (args);
	}
	else if (cerberus_print_flag & CERBERUS_PRINT_FLAG_ERROR) {
		printf ("[%s:%i] ", function_name, line_number);
		va_start (args, fmt);
		vprintf (fmt, args);
		va_end (args);
		printf ("\n");
	}
}

/**
 * Create an interprocess lock
 *
 * @param intf Cerberus interface to utilize.
 *
 * @return Completion status.
 */
int cerberus_utility_mutex_create (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

#ifndef CERBERUS_UTILITY_NO_MUTEX
#ifdef _WIN32
	LPVOID message = NULL;
	if (intf->mutex_handle == NULL) {
		// Attempt to create named mutex. If already exists, function returns existing handle
		intf->mutex_handle = (void*) CreateMutexA (NULL, 0, CERBERUS_MUTEX_NAME);
		if (intf->mutex_handle == NULL) {
			FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError (),
				MAKELANGID (LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR) &message, 0, NULL);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MUTEX_CREATE_FAILURE), message, GetLastError ());
			LocalFree(message);
			return STATUS_MUTEX_CREATE_FAILURE;
		}
	}
#elif __unix__
	if (intf->mutex_handle == NULL) {
		int err_no;
		int syscall_pthr_err;

		err_no = cerberus_device_shared_mutex_init (
			(struct cerberus_device_shared_mutex**) &intf->mutex_handle, &syscall_pthr_err);
		if (err_no != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (err_no), strerror (syscall_pthr_err), syscall_pthr_err);
			return err_no;
		}
	}
#else
#error Platform unsupported
#endif
#endif

	return STATUS_SUCCESS;
}

/**
 * Attempt to acquire interprocess lock around a Cerberus device
 *
 * @param intf Cerberus interface to utilize.
 * @param wait_time_ms Wait timeout value in milliseconds.
 *
 * @return Completion status.
 */
int cerberus_device_mutex_lock (struct cerberus_interface *intf, uint32_t wait_time_ms)
{
#ifndef CERBERUS_UTILITY_NO_MUTEX
	if ((intf == NULL) || (intf->mutex_handle == NULL)) {
		return STATUS_INVALID_INPUT;
	}

#ifdef _WIN32
{
	DWORD status;
	int err_no;
	LPVOID message = NULL;

	status = WaitForSingleObject ((HANDLE) intf->mutex_handle, wait_time_ms);
	if (status == WAIT_TIMEOUT) {
		err_no = STATUS_MUTEX_WAIT_TIMEOUT_FAILURE;
		goto err_status;
	}

	if (status == WAIT_FAILED) {
		err_no = STATUS_MUTEX_FAILURE;
		goto err_status;
	}

	return STATUS_SUCCESS;

err_status:
	FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError (),
		MAKELANGID (LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR) &message, 0, NULL);
	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		cerberus_utility_get_errors_str (err_no), message, GetLastError ());
	LocalFree(message);
	return err_no;
}
#elif __unix__
	int err_no;
	int pthread_err;

	err_no = cerberus_device_shared_mutex_timeout (
		(struct cerberus_device_shared_mutex*) intf->mutex_handle, wait_time_ms, &pthread_err);
	if (err_no != 0) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (err_no), strerror (pthread_err), pthread_err);
		return err_no;
	}
	return STATUS_SUCCESS;
#else
#error Platform unsupported
#endif
#else
	UNUSED (intf);
	UNUSED (wait_time_ms);
	return STATUS_SUCCESS;
#endif
}

/**
 * Release an interprocess lock around a Cerberus device
 *
 * @param intf Cerberus interface to utilize.
 */
void cerberus_device_mutex_unlock (struct cerberus_interface *intf)
{
#ifndef CERBERUS_UTILITY_NO_MUTEX
	if ((intf == NULL) || (intf->mutex_handle == NULL)) {
		return;
	}

#ifdef _WIN32
	ReleaseMutex ((HANDLE) intf->mutex_handle);
#elif __unix__
	if (pthread_mutex_unlock (
		((struct cerberus_device_shared_mutex*) intf->mutex_handle)->mutex) != 0) {
		return;
	}
#else
#error Platform unsupported
#endif
#else
	UNUSED (intf);
#endif
}

/**
 * Release an interprocess lock around a Cerberus device
 *
 * @param intf Cerberus interface to utilize.
 */
void cerberus_device_mutex_destroy (struct cerberus_interface *intf)
{
#ifndef CERBERUS_UTILITY_NO_MUTEX
	if ((intf == NULL) || (intf->mutex_handle == NULL)) {
		return;
	}

#ifdef _WIN32
	CloseHandle ((HANDLE) intf->mutex_handle);
#elif __unix__
{
	struct cerberus_device_shared_mutex *shm_mutex =
		(struct cerberus_device_shared_mutex*) intf->mutex_handle;
	munmap (shm_mutex->mutex, sizeof (pthread_mutex_t));
	close (shm_mutex->shm);
	free (shm_mutex);
}
#else
#error Platform unsupported
#endif
	intf->mutex_handle = NULL;
#else
	UNUSED (intf);
#endif

}

/**
 * Increments byte array of arbitary length len by 1
 *
 * @param buf input array to be incremented
 * @param length length of the array
 * @param allow_rollover lets to roll over when upper boundary is reached
 *
 * @return 0 if the input array is incremented successfully, error otherwise
 */
int cerberus_common_increment_byte_array (uint8_t *buf, size_t length, bool allow_rollover)
{
	size_t index = 0;

	if ((length == 0) || (buf == NULL)) {
		return STATUS_INVALID_INPUT;
	}

	while ((index < (length - 1)) && (buf[index] == 0xff)) {
		buf[index++] = 0;
	}

	if ((index == (length - 1)) && (buf[index] == 0xff)) {
		if (allow_rollover) {
			buf[index] = 0;
		}
		else {
			memset (buf, 0xff, length);
			return STATUS_BOUNDARY_REACHED;
		}
	}
	else {
		buf[index]++;
	}

	return 0;
}
