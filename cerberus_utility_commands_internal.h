// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_COMMANDS_INTERNAL_H_
#define CERBERUS_UTILITY_COMMANDS_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>
#include "cerberus_utility_api.h"

#ifdef __cplusplus
extern "C" {
#endif


#define CERBERUS_MAX_LOG_SIZE						 (68 * 1024)
#define CERBERUS_MAX_MANIFEST_LEN					 (64 * 1024)
#define CERBERUS_MAX_SEAL_LEN						 64

#define CERBERUS_CMD_TIMEOUT_VAL_S					 300
#define CERBERUS_MAX_SEND_RETRIES					 10
#define CERBERUS_MAX_UPDATE_RETRIES					 3

#define CERBERUS_BIOS_PORT_NUM						 1

#define CERBERUS_TCG_NUM_ALG						 1
#define CERBERUS_TCG_VENDOR_INFO_SIZE				 0
#define CERBERUS_TCG_SHA256_ALG_ID					 0x0B
#define CERBERUS_TCG_SERVER_PLATFORM_CLASS			 0x01
#define CERBERUS_TCG_UINT_SIZE_32					 0x01
#define CERBERUS_TCG_EFI_NO_ACTION_EVENT_TYPE		 0x03
#define CERBERUS_TCG_EFI_ACTION_EVENT_TYPE			 0x05
#define CERBERUS_TCG_LOG_SIGNATURE 					 "Spec ID Event03"

#define	MSFT_SUBSYSTEM_DEVICE_ID_CERBERUS			 0x0001

#define CERBERUS_MAX_GET_FW_VERSION_RETRIES			 20
#define CERBERUS_CMD_WAIT_TIME_AFTER_FWUPDATE_MS	 20000

/**
 * Identifier for the type of update status.
 */
enum {
	CERBERUS_FW_UPDATE_STATUS = 0,							/**< Cerberus FW update. */
	CERBERUS_PFM_UPDATE_STATUS,								/**< PFM update. */
	CERBERUS_CFM_UPDATE_STATUS,								/**< CFM update. */
	CERBERUS_PCD_UPDATE_STATUS,								/**< PCD update. */
	CERBERUS_HOST_FW_NEXT_RESET,							/**< Host FW reset verification. */
	CERBERUS_RECOVERY_UPDATE_STATUS,						/**< Recovery image update. */
	CERBERUS_CONFIG_RESET_STATUS,							/**< Configuration reset. */
	NUM_CERBERUS_UPDATE_TYPES								/**< Number of update types. */
};

/**
 * Status codes for FW update operations
 */
enum {
	UPDATE_STATUS_SUCCESS = 0,								/**< Successful update. */
	UPDATE_STATUS_STARTING,									/**< The update process is starting. */
	UPDATE_STATUS_START_FAILURE,							/**< Failed to start the update process. */
	UPDATE_STATUS_VERIFYING_IMAGE,							/**< Verifying the staging image. */
	UPDATE_STATUS_INCOMPLETE_IMAGE,							/**< Failed to receive the entire update image. */
	UPDATE_STATUS_VERIFY_FAILURE,							/**< A failure while verifying the staging flash. */
	UPDATE_STATUS_INVALID_IMAGE,							/**< The staging image is not valid. */
	UPDATE_STATUS_BACKUP_ACTIVE,							/**< Backing up the current image. */
	UPDATE_STATUS_BACKUP_FAILED,							/**< The current image failed to be backed up. */
	UPDATE_STATUS_SAVING_STATE,								/**< The current application state is being saved. */
	UPDATE_STATUS_STATE_SAVE_FAIL,							/**< The application state was not saved. */
	UPDATE_STATUS_UPDATING_IMAGE,							/**< The active image is being updated from the staging flash. */
	UPDATE_STATUS_UPDATE_FAILED,							/**< Failed to update the active image. */
	UPDATE_STATUS_CHECK_REVOCATION,							/**< Check the new certificate for revocation of older ones. */
	UPDATE_STATUS_REVOKE_CHK_FAIL,							/**< Error while checking for certificate revocation. */
	UPDATE_STATUS_CHECK_RECOVERY,							/**< Check the recovery image to see if update is required. */
	UPDATE_STATUS_RECOVERY_CHK_FAIL,						/**< Error while checking for recovery updates. */
	UPDATE_STATUS_BACKUP_RECOVERY,							/**< The recovery image is being backed up. */
	UPDATE_STATUS_BACKUP_REC_FAIL,							/**< The recovery image failed to be backed up. */
	UPDATE_STATUS_UPDATE_RECOVERY,							/**< The recovery image is being updated from the staging flash. */
	UPDATE_STATUS_UPDATE_REC_FAIL,							/**< Failed to update the recovery image. */
	UPDATE_STATUS_REVOKE_CERT,								/**< The certificate revocation list is being updated. */
	UPDATE_STATUS_REVOKE_FAILED,							/**< The revocation list failed updating. */
	UPDATE_STATUS_NONE_STARTED,								/**< No update has been attempted since the last reboot. */
	UPDATE_STATUS_STAGING_PREP_FAIL,						/**< Failed to prepare staging area for update. */
	UPDATE_STATUS_STAGING_PREP,								/**< Preparing staging area for update. */
	UPDATE_STATUS_STAGING_WRITE_FAIL,						/**< Failed to program staging area with update packet. */
	UPDATE_STATUS_STAGING_WRITE,							/**< Programming staging area with update packet. */
	UPDATE_STATUS_REQUEST_BLOCKED,							/**< A request has been made before the previous one finished. */
	UPDATE_STATUS_TASK_NOT_RUNNING,							/**< The task servicing update request is not running. */
	UPDATE_STATUS_UNKNOWN,									/**< The update status cannot be determined. */
	UPDATE_STATUS_SYSTEM_PREREQ_FAIL,						/**< The system state does not allow for firmware updates. */
	NUM_UPDATE_STATUS										/**< Number of FW update command statuses. */
};

/**
 * Status codes for recovery image update operations
 */
enum {
	RECOVERY_IMAGE_CMD_STATUS_SUCCESS = 0,					/**< Successful operation. */
	RECOVERY_IMAGE_CMD_STATUS_STARTING,						/**< The recovery image operation is starting. */
	RECOVERY_IMAGE_CMD_STATUS_REQUEST_BLOCKED,				/**< A request has been made before the previous one finished. */
	RECOVERY_IMAGE_CMD_STATUS_PREPARE,						/**< The recovery image is being prepared for updating. */
	RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL,					/**< There was an error preparing the recovery image for updating. */
	RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA,					/**< New recovery image data is being stored. */
	RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL,					/**< There was an error storing the recovery image data. */
	RECOVERY_IMAGE_CMD_STATUS_ACTIVATING,					/**< Activation is being attempted for a new recovery image. */
	RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL,				/**< There was an error activating the new recovery image. */
	RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR,				/**< An unspecified, internal error occurred. */
	RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED,					/**< No recovery image operation has been started. */
	RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING,				/**< The task servicing recovery image operations is not running. */
	RECOVERY_IMAGE_CMD_STATUS_UNKNOWN,						/**< The recovery image status could not be determined. */
	RECOVERY_IMAGE_CMD_NUM_STATUS,							/**< Number of recovery image command statuses. */
};

/**
 * Status codes for manifest operations
 */
enum {
	MANIFEST_CMD_STATUS_SUCCESS = 0,						/**< Successful operation. */
	MANIFEST_CMD_STATUS_STARTING,							/**< The manifest operation is starting. */
	MANIFEST_CMD_STATUS_REQUEST_BLOCKED,					/**< A request has been made before the previous one finished. */
	MANIFEST_CMD_STATUS_PREPARE,							/**< The manifest is being prepared for updating. */
	MANIFEST_CMD_STATUS_PREPARE_FAIL,						/**< There was an error preparing the manifest for updating. */
	MANIFEST_CMD_STATUS_STORE_DATA,							/**< New manifest data is being stored. */
	MANIFEST_CMD_STATUS_STORE_FAIL,							/**< There was an error storing manifest data. */
	MANIFEST_CMD_STATUS_VALIDATION,							/**< The new manifest is being validated. */
	MANIFEST_CMD_STATUS_VALIDATE_FAIL,						/**< There was an error validating the new manifest. */
	MANIFEST_CMD_STATUS_INTERNAL_ERROR,						/**< An unspecified, internal error occurred. */
	MANIFEST_CMD_STATUS_NONE_STARTED,						/**< No manifest operation has been started. */
	MANIFEST_CMD_STATUS_TASK_NOT_RUNNING,					/**< The task servicing manifest operations is not running. */
	MANIFEST_CMD_STATUS_UNKNOWN,							/**< The manifest status could not be determined. */
	MANIFEST_CMD_STATUS_ACTIVATING,							/**< Activation is being attempted for a new manifest. */
	MANIFEST_CMD_STATUS_ACTIVATION_FAIL,					/**< There was an error activating the new manifest. */
	MANIFEST_CMD_STATUS_ACTIVATION_PENDING,					/**< Validation was successful, but activation requires a host reboot. */
	MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR,				/**< An error occurred during activation that prevents host access to flash. */
	NUM_MANIFEST_CMD_STATUS									/**< Number of manifest command statuses */
};

/**
 * Verification actions that can be taken on reset of the host processor.
 */
enum {
	REBOOT_ACTION_NONE = 0,									/**< No action is pending on host reset. */
	REBOOT_ACTION_VERIFY_PFM,								/**< A pending PFM will be verified. */
	REBOOT_ACTION_VERIFY_UPDATE,							/**< A host FW update will be verified. */
	REBOOT_ACTION_VERIFY_PFM_AND_UPDATE,					/**< A pending PFM and host FW update will be verified. */
	REBOOT_ACTION_ACTIVATE_UPDATE,							/**< A prevalidated host FW update will be made active. */
	REBOOT_ACTION_ACTIVATE_PFM_AND_UPDATE,					/**< A prevalidated pending PFM and host FW update will both be made active. */
	REBOOT_ACTION_VERIFY_BYPASS_FLASH,						/**< A PFM will be used to verify flash, which is being accessed in bypass mode. */
	NUM_REBOOT_ACTION										/**< Number of reboot actions */
};

/**
 * Status codes for attestation operations
 */
enum {
	ATTESTATION_CMD_STATUS_SUCCESS = 0,						/**< Successful operation. */
	ATTESTATION_CMD_STATUS_RUNNING,							/**< An attestation operation is in progress. */
	ATTESTATION_CMD_STATUS_FAILURE,							/**< Attestation operation failed. */
	ATTESTATION_CMD_STATUS_REQUEST_BLOCKED,					/**< A request has been made before the previous one finished. */
	ATTESTATION_CMD_STATUS_NONE_STARTED,					/**< No attestation operation has been started. */
	ATTESTATION_CMD_STATUS_TASK_NOT_RUNNING,				/**< The task servicing attestation operations is not running. */
	ATTESTATION_CMD_STATUS_UNKNOWN,							/**< The attestation status could not be determined. */
	ATTESTATION_CMD_STATUS_INTERNAL_ERROR,					/**< An unspecified, internal error occurred. */
	NUM_ATTESTATION_CMD_STATUS								/**< Number of attestation command statuses */
};

/**
 * Status codes for configuration reset operations.
 */
enum {
	CONFIG_RESET_STATUS_SUCCESS = 0,						/**< Successful operation. */
	CONFIG_RESET_STATUS_STARTING,							/**< A configuration reset operation has started. */
	CONFIG_RESET_STATUS_REQUEST_BLOCKED,					/**< A request has been made before the previous one finished. */
	CONFIG_RESET_STATUS_RESTORE_BYPASS,						/**< Configuration is being reset to restore bypass mode. */
	CONFIG_RESET_STATUS_BYPASS_FAILED,						/**< Failed to restore bypass mode. */
	CONFIG_RESET_STATUS_RESTORE_DEFAULTS,					/**< All configuration and state are being erased. */
	CONFIG_RESET_STATUS_DEFAULTS_FAILED,					/**< Failed to restore default configuration. */
	CONFIG_RESET_STATUS_NONE_STARTED,						/**< No configuration reset operation has been started. */
	CONFIG_RESET_STATUS_TASK_NOT_RUNNING,					/**< The task servicing reset operations is not running. */
	CONFIG_RESET_STATUS_INTERNAL_ERROR,						/**< An unspecified, internal error occurred. */
	CONFIG_RESET_STATUS_UNKNOWN,							/**< The configuration reset status could not be determined. */
	CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG,				/**< Platform configuration is being cleared. */
	CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED,				/**< Failed to clear platform configuration. */
	CONFIG_RESET_STATUS_RESET_INTRUSION,					/**< Intrusion state is being reset. */
	CONFIG_RESET_STATUS_INTRUSION_FAILED,					/**< Failed to reset intrusion state. */
	CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS,			/**< Component manifests are being cleared. */
	CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED, 		/**< Failed to clear component manifests. */
	NUM_CONFIG_RESET_STATUS									/**< Number of reset configuration statuses. */
};

/**
 * States that will be reported for the stored RIoT certificates.
 */
enum  {
	RIOT_CERT_STATE_CHAIN_VALID = 0,						/**< A valid certificate chain has been authenticated. */
	RIOT_CERT_STATE_CHAIN_INVALID,							/**< An incomplete or invalid certificate chain is stored. */
	RIOT_CERT_STATE_VALIDATING,								/**< The stored certificates are being authenticated. */
	NUM_RIOT_CERT_STATES									/**< Number of RIoT certificate states. */
};

/**
 * Cerberus logging severities
 */
enum {
	LOGGING_SEVERITY_ERROR = 0,
	LOGGING_SEVERITY_WARNING,
	LOGGING_SEVERITY_INFO,
	NUM_LOGGING_SEVERITY
};

/**
 * Cerberus logging components
 */
enum {
	LOGGING_COMPONENT_INIT = 0,								/**< Log entry for initialization */
	LOGGING_COMPONENT_CMD_INTERFACE,						/**< Log entry for command interface */
	LOGGING_COMPONENT_CRYPTO,								/**< Log entry for crypto */
	LOGGING_COMPONENT_HOST_FW,								/**< Log entry for host firmware management */
	LOGGING_COMPONENT_CERBERUS_FW,							/**< Log entry for Cerberus firmware images */
	LOGGING_COMPONENT_STATE_MGR,							/**< Log entry for state management */
	LOGGING_COMPONENT_MANIFEST,								/**< Log entry for manifests */
	LOGGING_COMPONENT_SPI_FILTER,							/**< Log entry for the SPI filter */
	LOGGING_COMPONENT_I2C,									/**< Log entry for I2C failures */
	LOGGING_COMPONENT_BOOT,									/**< Log entry for the bootloader */
	LOGGING_COMPONENT_FLASH,								/**< Log entry for flash. */
	LOGGING_COMPONENT_SPI,									/**< Log entry for SPI failures. */
	LOGGING_COMPONENT_RECOVERY,								/**< Log entry for recovery images */
	LOGGING_COMPONENT_MCTP,									/**< Log entry for MCTP stack */
	LOGGING_COMPONENT_TPM,									/**< Log entry for TPM */
	LOGGING_COMPONENT_RIOT,									/**< Log entry for RIoT */
	LOGGING_COMPONENT_SYSTEM,								/**< Log entry for system management. */
	LOGGING_COMPONENT_INTRUSION,							/**< Log entry for chassis intrusion. */
	LOGGING_COMPONENT_ATTESTATION,							/**< Log entry for attestation operations. */
	LOGGING_COMPONENT_SPDM,									/**< Log entry for SPDM stack. */
	LOGGING_COMPONENT_CRASH_DUMP,							/**< Log entry for exception or crash diagnostics. */
	LOGGING_COMPONENT_DEVICE_SPECIFIC = 0xf0				/**< Base component ID for device specific messages */
};

/**
 * Cerberus crypto log messages - MAKE SURE IN SYNC WITH core\logging\debug_log.h!!
 */
enum {
	CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_INIT_EC,					/**< mbedTLS failure during AES GCM init */
	CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_CRYPT_EC,				/**< mbedTLS failure during AES GCM buffer encryt/decrypt */
	CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_AUTH_DECRYPT_EC,			/**< mbedTLS failure during AES GCM buffer authenticated decryption */
	CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC,						/**< mbedTLS failure during public key context init */
	CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_EC, 					/**< mbedTLS failure during private key parsing */
	CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_PUB_EC, 				/**< mbedTLS failure during public key parsing */
	CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_KEY_DER_EC, 			/**< mbedTLS failure during private key export to DER structure */
	CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_PUBKEY_DER_EC, 			/**< mbedTLS failure during public key export to DER structure */
	CRYPTO_LOG_MSG_MBEDTLS_PK_SIGN_EC, 						/**< mbedTLS failure during signing */
	CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC,					/**< mbedTLS failure during signature verification */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_COPY_EC,				/**< mbedTLS failure during ECP group copy */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_COPY_EC,						/**< mbedTLS failure during ECP copy */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_CHECK_PUB_PRV_EC, 			/**< mbedTLS failure during ECP keypair check */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_LOAD_EC,				/**< mbedTLS failure during ECP group load */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_MUL_EC,						/**< mbedTLS failure during ECP multiplication */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_GEN_KEY_EC, 					/**< mbedTLS failure during ECP key pair generation */
	CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC,					/**< mbedTLS failure during MPI import from binary */
	CRYPTO_LOG_MSG_MBEDTLS_MPI_WRITE_BIN_EC,				/**< mbedTLS failure during MPI export from binary */
	CRYPTO_LOG_MSG_MBEDTLS_ECDH_COMPUTE_SHARED_SECRET_EC,	/**< mbedTLS failure during ECDH shared secret computation */
	CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC,				/**< mbedTLS failure during CTR DRBG initial seeding */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_WRITE_OID_EC,				/**< mbedTLS failure during ASN1 OID write */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_CLOSE_EC,					/**< mbedTLS failure during ASN1 object close */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_GET_TAG_EC,					/**< mbedTLS failure during ASN1 tag get */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_GET_INT_EC,					/**< mbedTLS failure during ASN1 int get */
	CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC,				/**< mbedTLS failure during X509 key load */
	CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_SET_SUBJECT_EC,			/**< mbedTLS failure during X509 CSR subject name set */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_KEY_USAGE_EC,			/**< mbedTLS failure during X509 key usage addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_EXT_KEY_USAGE_EC,		/**< mbedTLS failure during X509 extended key usage addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_BASIC_CONSTRAINTS_EC,	/**< mbedTLS failure during X509 basic constraints addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_RIOT_EC,				/**< mbedTLS failure during X509 RIOT addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_DER_WRITE_EC,			/**< mbedTLS failure during X509 CSR DER write */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_SUBJECT_EC,				/**< mbedTLS failure during CRT subject set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_ISSUER_EC,				/**< mbedTLS failure during CRT issuer set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_VALIDITY_EC,				/**< mbedTLS failure during CRT validity set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_AUTHORITY_EC,			/**< mbedTLS failure during CRT authority set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_WRITE_DER_EC,				/**< mbedTLS failure during CRT export as DER */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_PARSE_DER_EC,				/**< mbedTLS failure during CRT parse as DER */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_CERT_AUTHENTICATE_EC,		/**< mbedTLS failure during certificate authentication */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_GEN_KEY_EC,					/**< mbedTLS failure during RSA key generation */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_PKCS1_VERIFY_EC,				/**< mbedTLS failure during RSA PKCS1 verification */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_LOAD_EC,				/**< mbedTLS failure during RSA public key load */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC,				/**< mbedTLS failure during RSA public key check */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_OAEP_DECRYPT_EC,				/**< mbedTLS failure during RSA OAEP decryption */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_TCBINFO_EC,				/**< mbedTLS failure during X509 TCB Info addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_UEID_EC,				/**< mbedTLS failure during X509 UEID addition */
};

/**
 * Cerberus command handler log messages.
 */
enum {
	CMD_LOGGING_PROCESS_FAIL,								/**< Error while processing a received command. */
	CMD_LOGGING_PACKET_OVERFLOW,							/**< A received message exceeded the maximum length. */
	CMD_LOGGING_PROTOCOL_ERROR,								/**< Error while processing input in MCTP protocol layer. */
	CMD_LOGGING_SEND_PACKET_FAIL,							/**< Error sending a packet over a command channel. */
	CMD_LOGGING_RECEIVE_PACKET_FAIL,						/**< Error receiving a packet over a command channel. */
	CMD_LOGGING_SOC_RESET_TRIGGERED,						/**< SoC reset has been triggered. */
	CMD_LOGGING_SOC_NMI_TRIGGERED,							/**< SoC NMI has been triggered. */
	CMD_LOGGING_ERROR_MESSAGE,								/**< Error message received. */
	CMD_LOGGING_UNSEAL_FAIL,								/**< An unseal operation failed. */
	CMD_LOGGING_RESTORE_BYPASS_FAIL,						/**< Failed to revert device to bypass mode. */
	CMD_LOGGING_BYPASS_RESTORED,							/**< Device has been reverted to bypass mode. */
	CMD_LOGGING_RESTORE_DEFAULTS_FAIL,						/**< Failed to revert device to the default state. */
	CMD_LOGGING_DEFAULTS_RESTORED,							/**< Device has been wiped of all configuration. */
	CMD_LOGGING_NOTIFICATION_ERROR,							/**< Unknown background task action specified. */
	CMD_LOGGING_DEBUG_LOG_CLEAR_FAIL,						/**< Failed to clear debug log. */
	CMD_LOGGING_COMMAND_TIMEOUT,							/**< Command response was not sent due to processing timeout. */
	CMD_LOGGING_DEBUG_LOG_CLEARED,							/**< The debug log has been cleared. */
	CMD_LOGGING_NO_CERT,									/**< No certificate was avaialble for a request. */
	CMD_LOGGING_CHANNEL_PACKET_ERROR,						/**< There was a receive error on a command channel. */
	CMD_LOGGING_NO_BACKGROUND_HANDELR,						/**< No background task handler provided for an event. */
	CMD_LOGGING_AUX_KEY,									/**< Done generating auxiliary attestation key. */
	CMD_LOGGING_GENERATE_AUX_KEY,							/**< Generating auxiliary attestation key. */
	CMD_LOGGING_CLEAR_PLATFORM_CONFIG,						/**< Device platform configuration has been cleared. */
	CMD_LOGGING_CLEAR_PLATFORM_FAIL,						/**< Failed to clear platform configuration. */
	CMD_LOGGING_RESET_INTRUSION,							/**< Intrusion state has been reset. */
	CMD_LOGGING_RESET_INTRUSION_FAIL,						/**< Failed to reset intrusion state. */
	CMD_LOGGING_CHANNEL,									/**< Command channel identifier. */
	CMD_LOGGING_CLEAR_CFM,									/**< Component manifest has been cleared. */
	CMD_LOGGING_CLEAR_CFM_FAIL,								/**< Failed to clear component manifest. */
	CMD_LOGGING_PERSIST_EID_FAIL,							/**< Failed to perist EID on flash. */
};

/**
 * Cerberus host firmware management log messages.
 */
enum {
	HOST_LOGGING_PENDING_FAILED_FW_UPDATE,					/**< The pending PFM failed to enable a firmware update. */
	HOST_LOGGING_PENDING_FAILED_CURRENT,					/**< The pending PFM failed to enable the current firmware. */
	HOST_LOGGING_ACTIVE_FAILED_FW_UPDATE,					/**< The active PFM failed to enable a firmware update. */
	HOST_LOGGING_ROLLBACK_FAILED,							/**< A rollback attempt failed. */
	HOST_LOGGING_RECOVERY_IRQ,								/**< Failure to control BMC recovery IRQ generation. */
	HOST_LOGGING_SOFT_RESET,								/**< Error during soft reset processing. */
	HOST_LOGGING_PENDING_VERIFY_FW_UPDATE,					/**< Verifying a firmware update with the pending PFM. */
	HOST_LOGGING_PENDING_VERIFY_CURRENT,					/**< Verifying the current firmware with the pending PFM. */
	HOST_LOGGING_ACTIVE_VERIFY_FW_UPDATE,					/**< Verifying a firmware update with the active PFM. */
	HOST_LOGGING_ACTIVE_VERIFY_CURRENT,						/**< Verifying the current firmware with the active PFM. */
	HOST_LOGGING_ACTIVE_FAILED_CURRENT,						/**< The active PFM failed to enable the current firmware. */
	HOST_LOGGING_PENDING_ACTIVATE_FW_UPDATE,				/**< Activating a firmware update with the pending PFM. */
	HOST_LOGGING_ACTIVE_ACTIVATE_FW_UPDATE,					/**< Activating a firmware update with the active PFM. */
	HOST_LOGGING_ROLLBACK_STARTED,							/**< Host flash rollback has been triggered. */
	HOST_LOGGING_ROLLBACK_COMPLETED,						/**< Host flash rollback completed successfully. */
	HOST_LOGGING_PENDING_ROLLBACK_FAILED,					/**< A rollback attempt using the pending PFM failed. */
	HOST_LOGGING_PREPARE_UPDATE,							/**< Prepare host flash for a firmware update. */
	HOST_LOGGING_WRITE_UPDATE_FAILED,						/**< Failed to write firmware update data to host flash. */
	HOST_LOGGING_NOTIFICATION_ERROR,						/**< Unknown task action specified. */
	HOST_LOGGING_ENTER_RESET,								/**< Detected host reset. */
	HOST_LOGGING_EXIT_RESET,								/**< Detected host out of reset. */
	HOST_LOGGING_HOST_DOWN,									/**< Host down interrupt received. */
	HOST_LOGGING_HOST_UP,									/**< Host up interrupt received. */
	HOST_LOGGING_RECOVERY_STARTED,							/**< Host recovery has been triggered. */
	HOST_LOGGING_RECOVERY_COMPLETED,						/**< Host recovery completed successfully. */
	HOST_LOGGING_RECOVERY_FAILED,							/**< Host recovery attempt failed. */
	HOST_LOGGING_HOST_FLASH_ACCESS_ERROR,					/**< Error giving the host SPI access. */
	HOST_LOGGING_HOST_FLASH_ACCESS_RETRIES,					/**< The number of attempts needed to give the host SPI access. */
	HOST_LOGGING_POWER_ON_RESET,							/**< Error during power-on reset processing. */
	HOST_LOGGING_BYPASS_MODE,								/**< Error configuring for unsecure boot. */
	HOST_LOGGING_ROT_FLASH_ACCESS_ERROR,					/**< Error setting RoT SPI access. */
	HOST_LOGGING_ROT_FLASH_ACCESS_RETRIES,					/**< The number of attempts needed to set RoT SPI access. */
	HOST_LOGGING_FILTER_FLASH_TYPE_ERROR,					/**< Error configuring the SPI filter for the flash devices. */
	HOST_LOGGING_FILTER_FLASH_TYPE_RETRIES,					/**< The number of attempts needed to configure the filter. */
	HOST_LOGGING_SWAP_FLASH_ERROR,							/**< Error swapping the flash devices. */
	HOST_LOGGING_SWAP_FLASH_RETRIES,						/**< The number of attempts needed to swap flash devices. */
	HOST_LOGGING_FILTER_RW_REGIONS_ERROR,					/**< Error configuring the SPI filter read/write regions. */
	HOST_LOGGING_FILTER_RW_REGIONS_RETRIES,					/**< The number of attempts needed to configure the filter regions. */
	HOST_LOGGING_INIT_PROTECTION_ERROR,						/**< Error initializing protection for host flash. */
	HOST_LOGGING_INIT_PROTECTION_RETRIES,					/**< The number of attempts needed to initialize flash protection. */
	HOST_LOGGING_CONFIG_FLASH_ERROR,						/**< Error configuring the flash roles. */
	HOST_LOGGING_CONFIG_FLASH_RETRIES,						/**< The number of attempts needed to configure the device roles. */
	HOST_LOGGING_BYPASS_MODE_ERROR,							/**< Error configuring the filter for bypass mode. */
	HOST_LOGGING_BYPASS_MODE_RETRIES,						/**< The number of attempts needed to configure the filter. */
	HOST_LOGGING_CLEAR_RW_REGIONS_ERROR,					/**< Error clearing the SPI filter read/write regions. */
	HOST_LOGGING_CLEAR_RW_REGIONS_RETRIES,					/**< The number of attempts needed to clear the filter regions. */
	HOST_LOGGING_PCR_UPDATE_ERROR,							/**< Error while updating a PCR entry. */
	HOST_LOGGING_BACKUP_FIRMWARE_STARTED,					/**< Start backup of active host firmware. */
	HOST_LOGGING_BACKUP_FIRMWARE_COMPLETED,					/**< Host active firmware backup has completed. */
	HOST_LOGGING_BMC_RECOVERY_DETECTED,						/**< Detected BMC recovery attempt. */
	HOST_LOGGING_RESET_COUNTER_UPDATE_FAILED,				/**< Reset counter update failed. */
	HOST_LOGGING_RW_RESTORE_START,							/**< Start condition for restoring active R/W regions. */
	HOST_LOGGING_RW_RESTORE_FINISH,							/**< End condition for active image R/W regions. */
	HOST_LOGGING_CHECK_PENDING_FAILED,						/**< Failed an empty check for a pending PFM. */
	HOST_LOGGING_CLEAR_PFMS,								/**< Clearing all PFMs to enable bypass mode. */
	HOST_LOGGING_RESET_RELEASE_FAILED,						/**< Failed to release the host reset after POR. */
	HOST_LOGGING_FLASH_RESET,								/**< Host flash was reset. */
	HOST_LOGGING_FORCE_RESET,								/**< Force reset issued to host. */
	HOST_LOGGING_HOST_BOOTING_TIME,							/**< Time taken in ms for host to boot. */
	HOST_LOGGING_RECOVERY_RETRIES							/**< Number of recovery attempts. */
};

/**
 * Cerberus firmware image log messages.
 */
enum {
	FIRMWARE_LOGGING_RECOVERY_IMAGE,						/**< The state of the recovery image. */
	FIRMWARE_LOGGING_UPDATE_FAIL,							/**< Error updating the firmware image. */
	FIRMWARE_LOGGING_UPDATE_START,							/**< Start processing a received firmware image. */
	FIRMWARE_LOGGING_UPDATE_COMPLETE,						/**< Firmware update completed successfully. */
	FIRMWARE_LOGGING_ERASE_FAIL,							/**< Failed to erase firmware staging region. */
	FIRMWARE_LOGGING_WRITE_FAIL,							/**< Failed to write firmware image data. */
	FIRMWARE_LOGGING_RECOVERY_RESTORE_FAIL,					/**< Failed to restore a bad recovery image. */
	FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,					/**< Done restoring a bad active image. */
	FIRMWARE_LOGGING_ACTIVE_RESTORE_START,					/**< Start to restore a bad active image. */
	FIRMWARE_LOGGING_RECOVERY_RESTORE_START,				/**< Start to restore a bad recovery image. */
	FIRMWARE_LOGGING_RECOVERY_UPDATE,						/**< Start to update the recovery image. */
	FIRMWARE_LOGGING_REVOCATION_UPDATE,						/**< Device anti-rollback state is being updated. */
	FIRMWARE_LOGGING_REVOCATION_FAIL,						/**< Error during revocation checks. */
};

/**
 * Cerberus state management log messages.
 */
enum {
	STATE_LOGGING_PERSIST_FAIL,								/**< Failed to persist non-volatile state. */
	STATE_LOGGING_ERASE_FAIL,								/**< Failed to erase unused state region. */
};

/**
 * Cerberus manifest log messages.
 */
enum {
	MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,				/**< Failed to record manifest measurement in PCR store. */
	MANIFEST_LOGGING_GET_MEASUREMENT_FAIL,					/**< Failed to get a manifest measurement. */
	MANIFEST_LOGGING_PFM_VERIFIED_EVENT_FAIL,				/**< Failed PFM verification notification. */
	MANIFEST_LOGGING_PFM_ACTIVATED_EVENT_FAIL,				/**< Failed PFM activation notification. */
	MANIFEST_LOGGING_CFM_VERIFIED_EVENT_FAIL,				/**< Failed CFM verification notification. */
	MANIFEST_LOGGING_CFM_ACTIVATED_EVENT_FAIL,				/**< Failed CFM activation notification. */
	MANIFEST_LOGGING_PENDING_RESET_FAIL,					/**< Failed to set reset for a pending PFM. */
	MANIFEST_LOGGING_PFM_RECORD_INVALID,					/**< Invalid call to force PFM measurements. */
	MANIFEST_LOGGING_CFM_RECORD_INVALID,					/**< Invalid call to force CFM measurements. */
	MANIFEST_LOGGING_KEY_REVOCATION_FAIL,					/**< Failure while running manifest key revocation. */
	MANIFEST_LOGGING_ERASE_FAIL,							/**< Failed to erase pending manifest region. */
	MANIFEST_LOGGING_WRITE_FAIL,							/**< Failed to write manifest data. */
	MANIFEST_LOGGING_VERIFY_FAIL,							/**< Failed to verify new manifest. */
	MANIFEST_LOGGING_NOTIFICATION_ERROR,					/**< Unknown task action specified. */
	MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR,				/**< Critical failure during activation. */
	MANIFEST_LOGGING_ACTIVATION_FAIL,						/**< Failed to activate manifest. */
	MANIFEST_LOGGING_PCD_VERIFIED_EVENT_FAIL,				/**< Failed PCD verification notification. */
	MANIFEST_LOGGING_PCD_ACTIVATED_EVENT_FAIL,				/**< Failed PCD activation notification. */
	MANIFEST_LOGGING_PCD_RECORD_INVALID,					/**< Invalid call to force PCD measurements. */
	MANIFEST_LOGGING_EMPTY_PFM,								/**< An empty PFM caused manifests to be cleared. */
	MANIFEST_LOGGING_GET_ID_FAIL,							/**< Failed to get manifest ID for measurement. */
	MANIFEST_LOGGING_GET_PLATFORM_ID_FAIL,					/**< Failed to get manifest platform ID for measurement. */
	MANIFEST_LOGGING_EMPTY_PCD,								/**< An empty PCD caused manifests to be cleared. */
	MANIFEST_LOGGING_EMPTY_CFM,								/**< An empty CFM caused manifests to be cleared. */
	MANIFEST_LOGGING_PFM_CLEAR_ACTIVE_EVENT_FAIL,			/**< Failed clear active PFM notification. */
	MANIFEST_LOGGING_CFM_CLEAR_ACTIVE_EVENT_FAIL,			/**< Failed clear active CFM notification. */
	MANIFEST_LOGGING_PCD_CLEAR_ACTIVE_EVENT_FAIL,			/**< Failed clear active PCD notification. */
	MANIFEST_LOGGING_PCD_UPDATE,							/**< Received a PCD update. */
	MANIFEST_LOGGING_CFM_ACTIVATION,						/**< Received a CFM activate request. */
	MANIFEST_LOGGING_PFM_ACTIVATION_REQUEST_FAIL, 			/**< PFM activation request notification failure. */
	MANIFEST_LOGGING_CFM_ACTIVATION_REQUEST_FAIL, 			/**< CFM activation request notification failure. */
	MANIFEST_LOGGING_PCD_ACTIVATION_REQUEST_FAIL, 			/**< PCD activation request notification failure. */
	MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,				/**< There is no valid manifest key available in the keystore. */
	MANIFEST_LOGGING_MANIFEST_KEY_REVOKED,					/**< The manifest key in the keystore has revoked the default key. */
};

/**
 * Cerberus SPI filter log messages.
 */
enum {
	SPI_FILTER_LOGGING_BLOCKED_COMMAND,						/**< A SPI command was blocked by the filter. */
	SPI_FILTER_LOGGING_READ_BLOCKED_FAIL,					/**< Failed to read a blocked SPI command code. */
	SPI_FILTER_LOGGING_IRQ_STATUS,							/**< The cause of SPI filter interrupts. */
	SPI_FILTER_LOGGING_FILTER_CONFIG,						/**< SPI filter configuration. */
	SPI_FILTER_LOGGING_ADDRESS_MODE,						/**< The address mode of the filter has changed. */
	SPI_FILTER_LOGGING_FILTER_REGION,						/**< A R/W address region for the filter. */
	SPI_FILTER_LOGGING_DEVICE_SIZE,							/**< The device size configuration. */
};

/**
 * Cerberus I2C log messages.
 */
enum {
	I2C_LOGGING_MASTER_WRITE_FAIL,							/**< Error while writing to I2C bus as master. */
	I2C_LOGGING_SLAVE_BUS_LOCKUP,							/**< I2C slave recovered from a bus lockup. */
};

/**
 * Cerberus flash log messages.
 */
enum {
	FLASH_LOGGING_INCOMPLETE_WRITE,							/**< A write was only partially completed. */
	FLASH_LOGGING_ECC_ERROR,								/**< An ECC error was detected on flash. */
	FLASH_LOGGING_ECC_REFRESH,								/**< Flash data refresh due to ECC error. */
};

/**
 * Logging messages for MCTP stack operations.
 */
enum {
	MCTP_LOGGING_PROTOCOL_ERROR,							/**< Error while processing input in MCTP protocol layer. */
	MCTP_LOGGING_ERR_MSG,									/**< Cerberus protocol error message received. */
	MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL,						/**< Failure while processing MCTP control request message. */
	MCTP_LOGGING_PKT_DROPPED,								/**< MCTP packet dropped. */
	MCTP_LOGGING_CHANNEL,									/**< MCTP command channel identifier. */
	MCTP_LOGGING_SET_EID_FAIL,								/**< Failed when processing a Set EID request. */
	MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN,					/**< Received a MCTP control message with invalid length. */
	MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL,					/**< Received a MCTP control message with a failed completion code. */
	MCTP_LOGGING_MCTP_CONTROL_RSP_FAIL,						/**< Failure while processing MCTP control response message. */
	MCTP_LOGGING_GET_EID_FAIL,								/**< Failed when processing a Get EID request. */
	MCTP_LOGGING_RSP_TIMEOUT,								/**< Timed out while waiting for MCTP response. */
};

/**
 * Logging messages for a recovery image.
 */
enum {
	RECOVERY_LOGGING_RECORD_MEASUREMENT_FAIL,				/**< Failed to record a recovery image measurement in PCR store. */
	RECOVERY_LOGGING_GET_MEASUREMENT_FAIL,					/**< Failed to get a recovery image measurement. */
	RECOVERY_LOGGING_ACTIVATED_EVENT_FAIL,					/**< Failed recovery image activation notification. */
	RECOVERY_LOGGING_RECORD_INVALID,						/**< Invalid call to force recovery image measurements. */
	RECOVERY_LOGGING_WRITE_FAIL,							/**< Failed to write recovery image data. */
	RECOVERY_LOGGING_VERIFY_FAIL,							/**< Failed to verify the new recovery image. */
	RECOVERY_LOGGING_NOTIFICATION_ERROR,					/**< Unknown task action specified. */
	RECOVERY_LOGGING_ACTIVATION_FLASH_ERROR,				/**< Critical failure during activation. */
	RECOVERY_LOGGING_ACTIVATION_FAIL,						/**< Failed to activate the recovery image. */
	RECOVERY_LOGGING_ERASE_FAIL,							/**< Failed to erase recovery image region. */
	RECOVERY_LOGGING_INVALIDATE_MEASUREMENT_FAIL,			/**< Failed to invalidate a measurement in PCR store. */
	RECOVERY_LOGGING_OCP_READ_ERROR,						/**< Error processing an OCP read request. */
	RECOVERY_LOGGING_OCP_WRITE_ERROR,						/**< Error processing an OCP write request. */
	RECOVERY_LOGGING_OCP_PEC_ERROR,							/**< PEC error on a received request. */
	RECOVERY_LOGGING_OCP_WRITE_INCOMPLETE,					/**< An incomplete block write command was received. */
	RECOVERY_LOGGING_OCP_WRITE_OVERFLOW,					/**< More data than is allowed was sent. */
};

/**
 * Logging messages for TPM.
 */
enum {
	TPM_LOGGING_CLEAR_FAILED,								/**< TPM clear failed. */
	TPM_LOGGING_CLEAR_TPM,									/**< TPM storage has been cleared. */
	TPM_LOGGING_INVALID_HEADER,								/**< TPM storage header was not valid. */
	TPM_LOGGING_READ_HEADER_FAILED,							/**< Failed to read the TPM header. */
	TPM_LOGGING_SOFT_RESET_ERROR,							/**< Error during reset processing. */
	TPM_LOGGING_NO_HEADER,									/**< TPM header not available. */
	TPM_LOGGING_NO_SEGMENT_DATA,							/**< TPM storage segment had no data. */
	TPM_LOGGING_ERASE_FAILED,								/**< TPM erase failed. */
};

/**
 * Logging messages for RIoT operations.
 */
enum {
	RIOT_LOGGING_DEVID_AUTH_STATUS,							/**< Authentication status for a signed Device ID. */
};

/**
 * Logging messages for system management.
 */
enum {
	SYSTEM_LOGGING_RESET_NOT_EXECUTED,						/**< Failed to schedule a device reset. */
	SYSTEM_LOGGING_RESET_FAIL,								/**< Failed to reset the device. */
	SYSTEM_LOGGING_PERIODIC_FAILED,							/**< A periodic task failed to execute a handler. */
	SYSTEM_LOGGING_POLICY_CHECK_FAIL,						/**< Failed to query the device security policy. */
	SYSTEM_LOGGING_GET_POLICY_FAIL,							/**< Failed to query for the active security policy. */
	SYSTEM_LOGGING_UNDETERMINED_UNLOCK,						/**< An error prevented detection or application of any possible unlock policy. */
	SYSTEM_LOGGING_DEVICE_UNLOCKED,							/**< An unlock policy has been applied to the device. */
	SYSTEM_LOGGING_LOCK_STATE_FAIL,							/**< An error occurred attempting to make the lock state consistent. */
	SYSTEM_LOGGING_TOKEN_INVALIDATE_FAIL,					/**< Failed to invalidate a consumed unlock token. */
};

/**
 * Identifiers for security policy parameters.
 */
enum {
	SYSTEM_LOGGING_POLICY_FW_SIGNING,						/**< Security policy check for firmware signing. */
	SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK,					/**< Security policy check for anti-rollback. */
};

/**
 * Identifiers for types of unlock policies that can be applied.
 */
enum {
	SYSTEM_LOGGING_UNLOCK_PERSISTENT,						/**< Identifier for a persistent unlock policy. */
	SYSTEM_LOGGING_UNLOCK_ONE_TIME,							/**< Identifier for a one-time unlock policy. */
};

/**
 * Logging messages for chassis intrusion management.
 */
enum {
	INTRUSION_LOGGING_INTRUSION_DETECTED,					/**< Chassis intrusion detected. */
	INTRUSION_LOGGING_HANDLE_FAILED,						/**< Intrusion handling failed. */
	INTRUSION_LOGGING_CHECK_FAILED,							/**< Intrusion state check failed. */
	INTRUSION_LOGGING_INTRUSION_NOTIFICATION,				/**< Processed an intrusion notification. */
	INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION,			/**< Processed a no intrusion notification. */
	INTRUSION_LOGGING_ERROR_NOTIFICATION,					/**< Processed a intrusion error notification. */
	INTRUSION_LOGGING_STORE_DATA_FAIL,						/**< Received a store data failure response. */
	INTRUSION_LOGGING_CHALLENGE_DATA_FAIL,					/**< Received a challenge data failure response. */
	INTRUSION_LOGGING_CHALLENGE_DATA_INVALID_HASH_LEN,		/**< Received a challenge data response with an incorrect hash len. */
};

/**
 * Logging messages for attestation operations.
 */
enum {
	ATTESTATION_LOGGING_DEVICE_NOT_INTEROPERABLE,					/**< Target device does not support interoperable protocol specification version. */
	ATTESTATION_LOGGING_GET_CERT_NOT_SUPPORTED,						/**< Target device does not support get certificate command. */
	ATTESTATION_LOGGING_MEASUREMENT_CAP_NOT_SUPPORTED,				/**< Target device does not support measurement response capabilities. */
	ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY,							/**< Requested slot number not occupied by certificate chain on target device. */
	ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP,					/**< Requested slot number not utilized by target device in response. */
	ATTESTATION_LOGGING_CERT_CHAIN_DIGEST_MISMATCH,					/**< Certificate chain digest provided by target device in response different than cached. */
	ATTESTATION_LOGGING_TARGET_REQ_UNSUPPORTED_MUTUAL_AUTH,			/**< Target device requested unsupported mutual authentication. */
	ATTESTATION_LOGGING_UNEXPECTED_HASH_LEN_IN_RSP,					/**< Expected hash length not utilized by target device in attestation response. */
	ATTESTATION_LOGGING_UNEXPECTED_HASH_ALGO_IN_RSP,				/**< Expected hash algorithm not utilized by target device in attestation response. */
	ATTESTATION_LOGGING_UNEXPECTED_MEAS_HASH_ALGO_IN_RSP,			/**< Expected measurement hash algorithm not utilized by target device in attestation response. */
	ATTESTATION_LOGGING_CERBERUS_PROTOCOL_VER_UNSUPPORTED,			/**< Attestation target device protocol version not interoperable with device. */
	ATTESTATION_LOGGING_ALIAS_KEY_TYPE_UNSUPPORTED,					/**< Attestation target device sent an alias certificate with an unsupported key type. */
	ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH,		/**< Target sent a certificate chain which has a different digest than that sent by target. */
	ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED,				/**< Received response unexpected. */
	ATTESTATION_LOGGING_MEASUREMENT_SPEC_UNSUPPORTED,				/**< Target device uses unsupported measurement spec. */
	ATTESTATION_LOGGING_BASE_ASYM_KEY_SIG_ALG_UNSUPPORTED,			/**< Target device uses unsupported asymmetric key signature algorithm. */
	ATTESTATION_LOGGING_HASHING_ALGORITHM_UNSUPPORTED,				/**< Target device uses unsupported hashing algorithm. */
	ATTESTATION_LOGGING_HASHING_MEAS_ALGORITHM_UNSUPPORTED,			/**< Target device uses unsupported measurement hashing algorithm. */
	ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN,							/**< Received response has unexpected length. */
	ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS,			/**< Received measurements response has unexpected number of measurement blocks. */
	ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,					/**< Device failed during attestation flow. */
	ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_DIGEST,		/**< Received measurements response has digest of measurement block when raw requested. */
	ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE,					/**< Received measurements response too large. */
	ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW,			/**< Received measurements response has raw measurement block when digest requested. */
	ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED,						/**< Device failed to send SPDM device ID block. */
	ATTESTATION_LOGGING_ILLEGAL_RSP_NOT_READY,						/**< Received response not ready response for a command that does not permit it. */
	ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP,					/**< Response not ready for unexpected command received. */
	ATTESTATION_LOGGING_BRIDGE_RESET_TRIGGERED_ROUTING_TABLE_SYNC,	/**< MCTP bridge has triggered a MCTP routing table sync. */
	ATTESTATION_LOGGING_BRIDGE_FAILED_TO_DETECT_MCTP_BRIDGE_RESET,	/**< MCTP bridge reset detection failed. */
	ATTESTATION_LOGGING_ROUTING_TABLE_REFRESH_REQUEST_FAILED,		/**< Failed to request an MCTP routing table refresh. */
	ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID,			/**< CFM version set selector entry invalid. */
	ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED,				/**< Failed to determine device version set using CFM version set selector entry. */
	ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY,					/**< Device discovery failed during attestation flow. */
	ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR,				/**< Failed to find next device for discovery. */
	ATTESTATION_LOGGING_NEXT_DEVICE_ATTESTATION_ERROR,				/**< Failed to find next device for attestation. */
	ATTESTATION_LOGGING_PCR_UPDATE_ERROR,							/**< Error while updating a PCR entry. */
	ATTESTATION_LOGGING_GET_ATTESTATION_STATUS_ERROR,				/**< Failed to get attestation status. */
	ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR,				/**< Failed to get MCTP routing table. */
};

/**
 * Logging messages for SPDM stack.
 */
enum {
	SPDM_LOGGING_ERR_MSG,									/**< Failed while processing SPDM request. */
};

/**
 * Error messages that can be logged for crash or exception diagnostics.
 */
enum {
	CRASH_DUMP_LOGGING_EXCEPTION = 0,						/**< An exception occurred that triggered a reboot. */
	CRASH_DUMP_LOGGING_EXCEPTION_DETAIL,					/**< Details for a device exception. */
};

/**
 * Identifiers indicating the type of information getting logged for an exception.
 */
enum {
	CRASH_DUMP_LOGGING_ARM_R0 = 0x00,						/**< The R0 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R1 = 0x01,						/**< The R1 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R2 = 0x02,						/**< The R2 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R3 = 0x03,						/**< The R3 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R12 = 0x04,						/**< The R12 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_LR = 0x05,						/**< The link register value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_PC = 0x06,						/**< The program counter from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_XPSR = 0x07,						/**< The xPSR value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_HFSR = 0x08,						/**< The HFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_MMFSR = 0x09,					/**< The MMFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_MMFAR = 0x0a,					/**< The MMFAR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_BFSR = 0x0b,						/**< The BFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_BFAR = 0x0c,						/**< The BFAR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_UFSR = 0x0d,						/**< The UFSR value for the exception. */
};

/**
 * Identifier for the type of key exchange.
 */
enum cerberus_key_exchange_types {
	CERBERUS_PROTOCOL_SESSION_KEY = 0,						/**< Exchange session encryption key */
	CERBERUS_PROTOCOL_PAIRED_KEY_HMAC,						/**< Exchange an HMAC paired key */
	CERBERUS_PROTOCOL_DELETE_SESSION_KEY,					/**< Delete session key */
};

/**
 * Identifier for the type of HMAC used in a key exchange.
 */
enum {
	CERBERUS_PROTOCOL_HMAC_SHA256 = 0,						/**< HMAC using SHA256 */
	CERBERUS_PROTOCOL_HMAC_SHA384,							/**< HMAC using SHA384 */
	CERBERUS_PROTOCOL_HMAC_SHA512,							/**< HMAC using SHA512 */
};

/**
 * Identifier for the type of system log.
 */
enum cerberus_log_type {
	CERBERUS_DEBUG_LOG = 1,									/**< Debug log type. */
	CERBERUS_ATTESTATION_LOG,								/**< Attestation log type. */
	CERBERUS_TAMPER_LOG,									/**< Tamper log type. */
	CERBERUS_TCG_LOG,										/**< TCG log type. */
	NUM_CERBERUS_LOG_TYPES									/**< Number of log types. */
};

/**
 * Identifier for the pfm activate setting.
 */
enum pfm_activate_setting_type {
	PFM_ACTIVATE_AFTER_REBOOT = 0,							/**< Activate pfm after reboot. */
	PFM_ACTIVATE_IMMEDIATELY,								/**< Activate pfm immediately. */
	NUM_PFM_ACTIVATE_SETTINGS								/**< Number of pfm activate settings. */
};

/**
 * Manifest types
 */
enum {
	CERBERUS_MANIFEST_PFM,			 						/**< PFM manifest. */
	CERBERUS_MANIFEST_CFM,									/**< CFM manifest. */
	CERBERUS_MANIFEST_PCD,									/**< PCD manifest. */
	NUM_CERBERUS_MANIFEST_TYPES			 					/**< Number of manifest types. */
};

#pragma pack(push, 1)
/**
 * TCG event digests list.
 */
struct tcg_digests {
	uint32_t num_digests; 									/**< Number of digests */
	struct tcg_digest *digests; 							/**< List of digests */
};

/**
 * TCG event digest.
 */
struct tcg_digest {
	uint16_t digest_algorithm_id; 							/**< ID of hashing algorithm */
	uint8_t *digest; 										/**< Digest */
};

/**
 * TCG event log algorithm descriptor.
 */
struct tcg_algorithm {
	uint16_t digest_algorithm_id;							/**< Algorithm ID */
	uint16_t digest_size;									/**< Algorithm digest size */
};

/**
 * TCG event entry.
 */
struct tcg_event2 {
	uint32_t pcr_bank;										/**< PCR bank */
	uint32_t event_type;									/**< Type of event */
	uint32_t digest_count;									/**< Number of digests */
	uint16_t digest_algorithm_id;							/**< ID of hashing algorithm */
	uint8_t digest[32];										/**< Digest extended to PCR */
	uint32_t event_size;									/**< Event size */
};

/**
 * TCG event entry - old format.
 */
struct tcg_event {
	uint32_t pcr_bank;										/**< PCR bank */
	uint32_t event_type;									/**< Type of event */
	uint8_t pcr[20];										/**< PCR value */
	uint32_t event_size;									/**< Event size */
	//uint8_t event[0];										/**< Event */
};

/**
 * TCG event log header.
 */
struct tcg_log_header {
	uint8_t signature[16];									/**< The null terminated ASCII string "Spec ID Event03" */
	uint32_t platform_class;								/**< Platform class as defined in TCG spec */
	uint8_t spec_version_minor;								/**< Spec minor version number */
	uint8_t spec_version_major;								/**< Spec major version number */
	uint8_t spec_errata;									/**< Spec errata supported */
	uint8_t uintn_size;										/**< Size of uint fields */
	uint32_t num_algorithms;								/**< Number of hashing algorithms used in log */
	struct tcg_algorithm digest_sizes[CERBERUS_TCG_NUM_ALG];/**< Hashing algorithms descriptors */
	uint8_t vendor_info_size;								/**< Size of vendorInfo */
	//uint8_t vendor_info[CERBERUS_TCG_VENDOR_INFO_SIZE];	/**< Vendor-specific extra information */
};

/**
 * TCG log entry header for 0xCA entries.
 */
struct logging_tcg_entry_ca {
	uint8_t log_magic;										/**< Entry starting magic sequence */
	uint32_t entry_id;										/**< Entry ID */
};

/**
 * TCG log entry header for 0xCB entries.
 */
struct logging_tcg_entry_cb {
	uint8_t log_magic;										/**< Entry starting magic sequence */
	uint16_t length;										/**< Length of the entry. */
	uint32_t entry_id;										/**< Entry ID */
};

/**
 * TCG log entry header for 0xCC entries.
 */
struct logging_tcg_entry_cc {
	uint8_t log_magic;										/**< Start of entry marker. */
	uint16_t length;										/**< Length of the entry. */
	uint32_t entry_id;										/**< Unique entry identifier. */
	uint8_t data_offset;									/**< Offset within the entry where the log entry data starts. */
};

/**
 * Debug log entry format.
 */
struct logging_debug_entry_base {
	uint8_t severity;										/**< Severity */
	uint8_t component;										/**< Component */
	uint8_t msg_index;										/**< Message index */
	uint32_t arg1;											/**< Optional argument 1 */
	uint32_t arg2;											/**< Optional argument 2 */
	uint64_t time;											/**< Elapsed time in milliseconds since boot. */
};

/**
 * Debug log entry header for 0xCA entries.
 */
struct logging_debug_entry_ca {
	uint8_t log_magic;										/**< Entry starting magic sequence */
	uint32_t entry_id;										/**< Entry ID */
};

/**
 * Debug log entry header for 0xCB entries.
 */
struct logging_debug_entry_cb {
	uint8_t log_magic;										/**< Entry starting magic sequence */
	uint16_t length;										/**< Length of the entry. */
	uint32_t entry_id;										/**< Entry ID */
	uint16_t format;										/**< Entry format identifier. */
};

/**
 * Debug log entry header for 0xCC entries.
 */
struct logging_debug_entry_cc {
	uint8_t log_magic;										/**< Start of entry marker. */
	uint16_t length;										/**< Length of the entry. */
	uint32_t entry_id;										/**< Unique entry identifier. */
	uint8_t data_offset;									/**< Offset within the entry where the log entry data starts. */
};

/**
 * Cerberus PFM activate
 */
struct cerberus_pfm_activate {
	uint8_t port;											/**< Port to activate PFM */
	uint8_t activate_setting;								/**< Active immediately or on reboot */
};

/**
 * Cerberus FW update status
 */
struct cerberus_fw_update_status {
	uint32_t status_code;									/**< FW update status code */
	uint32_t status_code_module;							/**< Module generating status code */
	uint32_t remaining_len;									/**< Remaining length */
	char status_str[CERBERUS_MAX_MSG_LEN];					/**< Update status string */
};

/**
 * Cerberus manifest type request
 */
struct cerberus_manifest_request {
	uint8_t port;											/**< manifest port */
	uint8_t manifest_type;									/**< Manifest type */
};

#pragma pack(pop)

int cerberus_validate_host_update (struct cerberus_interface *intf,
	struct cerberus_pfm_activate *pfm, bool suppress_msg,
	struct cerberus_fw_update_status *update_status);
void cerberus_format_filter_config_entry (uint32_t port, uint32_t config, char *message,
	size_t max_message);
int cerberus_get_manifest_update_status (struct cerberus_interface *intf,
	struct cerberus_manifest_request *manifest, struct cerberus_fw_update_status *update_status);


#ifdef __cplusplus
}
#endif

#endif /* CERBERUS_UTILITY_COMMANDS_INTERNAL_H_ */
