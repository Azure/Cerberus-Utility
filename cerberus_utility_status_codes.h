// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_STATUS_CODES_H_
#define CERBERUS_UTILITY_STATUS_CODES_H_


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Cerberus utility completion codes
 */
enum {
	STATUS_SUCCESS,											/**< Successful operation. */
	STATUS_CRC_FAILURE,										/**< Incoming packet had invalid CRC */
	STATUS_INVALID_PACKET,									/**< Incoming packet had invalid data */
	STATUS_INVALID_MANIFEST,								/**< Manifest invalid */
	STATUS_COMMUNICATION_FAILURE,							/**< Failure while communicating with Cerberus */
	STATUS_UPDATE_FAILURE,									/**< Failure while performing update */
	STATUS_NO_MEM,											/**< Failed to allocate memory from heap */
	STATUS_INVALID_UPDATE_FILE,								/**< Update file provided invalid */
	STATUS_UNKNOWN_REQUEST,									/**< User request unknown */
	STATUS_INVALID_INPUT,									/**< Invalid input */
	STATUS_PAYLOAD_TOO_LARGE,								/**< Payload too large for MCTP */
	STATUS_MCTP_TIMEOUT,									/**< Timeout while waiting for MCTP response */
	STATUS_PARTIAL_PACKET,									/**< Partial MCTP packet received */
	STATUS_NO_DATA,											/**< No data received */
	STATUS_UNKNOWN,											/**< Status could not be determined */
	STATUS_UNEXPECTED_RLEN,									/**< Unexpected response length */
	STATUS_CMD_RESPONSE,									/**< Unexpected command response */
	STATUS_EMPTY_FILE,										/**< Provided file empty */
	STATUS_READ_FILE_FAILED,								/**< Failed to read provided file*/
	STATUS_OPEN_FILE_FAILED,								/**< Failed to open provided file */
	STATUS_OPERATION_TIMEOUT,								/**< Timeout while performing operation */
	STATUS_STRING_NOT_TERMINATED,							/**< String value is not null terminated. */
	STATUS_BUF_TOO_SMALL,									/**< Value larger than container. */
	STATUS_NOT_STRING,										/**< Value is not a printable string. */
	STATUS_ATTESTATION_FAILURE,								/**< Attestation operation failed. */
	STATUS_MCTP_FAILURE,									/**< MCTP layer error received */
	STATUS_RESERVED_26,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_27,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_28,										/**< Reserved for platform specific completion status */
	STATUS_FW_NOT_SUPPORTED_BY_MANIFEST,					/**< FW version provided not provided by active manifest */
	STATUS_CERBERUS_CMD_UNSUPPORTED,						/**< Command sent not supported by Cerberus */
	STATUS_RESERVED_31,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_32,										/**< Reserved for platform specific completion status */
	STATUS_UNSUPPORTED_FORMAT,								/**< Log stored in an unsupported format. */
	STATUS_RESERVED_34,										/**< Reserved for platform specific completion status */
	STATUS_COMPLETE_PACKET,									/**< Received a complete packet */
	STATUS_RESERVED_36,										/**< Reserved for platform specific completion status */
	STATUS_OUTPUT_FILE_REQUIRED,							/**< No output file provided for received data */
	STATUS_WRITE_FILE_FAILED,								/**< Failed to write to provided file */
	STATUS_CERBERUS_CMD_NOT_AUTHORIZED,						/**< Command is not authorized for execution. */
	STATUS_RESERVED_40,										/**< Reserved for platform specific completion status */
	STATUS_UNEXPECTED_VALUE,								/**< Unexpected value */
	STATUS_INVALID_RECOVERY_IMAGE,							/**< Recovery image invalid */
	STATUS_INVALID_PORT,									/**< Invalid communication port specified */
	STATUS_RESERVED_44,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_45,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_46,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_47,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_48,										/**< Reserved for platform specific completion status */
	STATUS_RESERVED_49,										/**< Reserved for platform specific completion status */
	STATUS_PROTOCOL_INCOMPATIBLE,							/**< An incompatible version of the protocol is being used */
	STATUS_BAD_MCTP_PARAMETERS,								/**< MCTP parameters are not valid */
	STATUS_NO_CERTIFICATE,									/**< No certificate is available for the parameters */
	STATUS_NO_DEVICE,										/**< No device is available */
	STATUS_MSFT_VID_SET_UNSUPPORTED,						/**< Device does not support Microsoft VID command set */
	STATUS_NO_KEY,											/**< Key not selected before crypto operation */
	STATUS_INVALID_KEY,										/**< Key invalid for requested crypto operation */
	STATUS_SIG_VERIFY_FAIL,									/**< Signature verification failed */
	STATUS_UNSUPPORTED_OPERATION,							/**< Requested operation unsupported */
	STATUS_KEY_LENGTH_UNSUPPORTED,							/**< Key length is not supported */
	STATUS_ENCRYPTION_OUT_OF_SESSION,						/**< Encrypted packet received out of session */
	STATUS_CERT_NOT_SELF_SIGNED,							/**< Certificate not self signed */
	STATUS_CERT_SELF_SIGNED,								/**< Certificate self signed */
	STATUS_CERT_NOT_CA,										/**< Certificate not for a CA */
	STATUS_CERT_INVALID_SIGNATURE,							/**< Invalid signature */
	STATUS_CERT_INVALID_CERT,								/**< Invalid certificate */
	STATUS_CERT_SIG_TYPE_UNSUPPORTED,						/**< Unsupported signature type */
	STATUS_OPERATION_UNSUPPORTED_BY_DEVICE,					/**< Requested command not supported by device */
	STATUS_SESSION_ESTABLISHMENT_FAILED,					/**< Failed to establish a secure session */
	STATUS_LOG_CONTENTS_INCONSISTENT,						/**< Log contains inconsistent information */
	STATUS_LOG_LEN_INVALID,									/**< Log not large enough for contents */
	STATUS_MUTEX_FAILURE,									/**< Failure during a mutex operation */
	STATUS_CRYPTO_FAILURE,									/**< Failure during a crypto library operation */
	STATUS_MCTP_READ_FAILURE,								/**< Failed to read MCTP response */
	STATUS_CERT_PROVISIONING_LOCKED,						/**< Certificate provisioning locked */
	STATUS_RESERVED_75,										/**< Reserved for platform specific completion status */
	STATUS_I2C_ENABLE_SLAVE_MODE_FAILURE,					/**< Failed to enable I2C slave mode */
	STATUS_MUTEX_SHM_OPEN_FAILURE,							/**< Failed to open share memory for mutex */
	STATUS_MUTEX_MAP_SHM_FAILURE,							/**< Failed to map share memory for mutex */
	STATUS_MUTEX_TRUNCATE_SHM_FAILURE,						/**< Failed to truncate share memory for mutex */
	STATUS_MUTEX_INIT_ATTR_FAILURE,							/**< Failed to initialize mutex attributes */
	STATUS_MUTEX_SET_SHARED_ATTR_FAILURE,					/**< Failed to set mutex process-shared attribute */
	STATUS_MUTEX_SET_ATTR_TYPE_FAILURE,						/**< Failed to set attribute type for mutex */
	STATUS_MUTEX_SET_ROBUS_ATTR_FAILURE,					/**< Failed to set robustness attribute for mutex */
	STATUS_MUTEX_INIT_FAILURE,								/**< Failed to initialize mutex */
	STATUS_MUTEX_ALLOCATE_MEMORY_FAILURE,					/**< Failed to allocate memory for mutex */
	STATUS_MUTEX_CREATE_FAILURE,							/**< Failed to create mutex */
	STATUS_MUTEX_WAIT_TIMEOUT_FAILURE,						/**< Wait mutex timeout */
	STATUS_REBOOT_AFTER_UPDATE_FAILURE,						/**< Failed to reboot after FW/PCD update */
	STATUS_MCTP_WRITE_FAILURE,								/**< Failed to write MCTP data */
	STATUS_MCTP_CTRL_REQ_FAIL,								/**< MCTP control request failed */
	STATUS_MBEDTLS_FAILURE,									/**< Failed to execute mbedtls operation */
	STATUS_BOUNDARY_REACHED,								/**< Boundary reached and can't Increment/Decrement */
	STATUS_MUTEX_SET_SHARED_PERMISSION_FAILURE,				/**< Failed to set shared mutex permissions for existing mutex. */
	STATUS_RESERVED_94,										/**< Reserved for platform specific completion status */
	STATUS_UNSUPPORTED_DIGEST_LEN,							/**< Unsupported digest length */
	STATUS_PLATFORM_SPECIFIC_ERROR,							/**< Start of platform specific error codes */
};

const char *cerberus_utility_get_errors_str (int status_code);


#ifdef __cplusplus
}
#endif

#endif // CERBERUS_UTILITY_STATUS_CODES_H_
