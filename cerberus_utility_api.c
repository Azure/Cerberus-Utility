// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include "cerberus_utility_api.h"
#include "cerberus_utility_cerberus_protocol.h"
#include "cerberus_utility_commands_internal.h"
#include "cerberus_utility_common.h"
#include "cerberus_utility_component_map.h"
#include "cerberus_utility_interface.h"
#include "cerberus_utility_interface_parameters.h"
#include "cerberus_utility_mctp_interface.h"
#include "cerberus_utility_mctp_params.h"
#include "cerberus_utility_mctp_protocol.h"
#include "cerberus_utility_status_codes.h"
#include "crypto/mbedtls/include/mbedtls/asn1.h"
#include "crypto/mbedtls/include/mbedtls/x509.h"
#include "crypto/mbedtls/include/mbedtls/x509_crt.h"
#include "crypto/x509.h"
#include "version.h"
#include "unused.h"
#ifdef CERBERUS_ENABLE_CRYPTO
#include "cerberus_utility_crypto_interface.h"
#endif


#define CERBERUS_LAST_UNSUPPORTED_VERSION		1
#define TIMEOUT_VAL_S_PER_MB 					50		/** Update command completion timeout in seconds per MB */

/** Macro to calculate the timeout in seconds for the update command completion.  It takes update
 * size in bytes as input */
#define CERBERUS_UPDATE_CMD_TIMEOUT_VAL_S(update_size_bytes) \
	((update_size_bytes / (1024 * 1024)) ? \
	(((update_size_bytes / (1024 * 1024)) + 1) * TIMEOUT_VAL_S_PER_MB) : \
	TIMEOUT_VAL_S_PER_MB)

const char *cerberus_util_version = UTILITY_VERSION_STRING;
uint8_t version_buf[CERBERUS_VERSION_MAX_LEN];

/**
 * Strings for the different logging components.
 */
const char *logging_component_str[] = {
	[LOGGING_COMPONENT_INIT] = "Init",
	[LOGGING_COMPONENT_CMD_INTERFACE] = "Cmd Intf",
	[LOGGING_COMPONENT_CRYPTO] = "Crypto",
	[LOGGING_COMPONENT_HOST_FW] = "Host",
	[LOGGING_COMPONENT_CERBERUS_FW] = "FW",
	[LOGGING_COMPONENT_STATE_MGR] = "State",
	[LOGGING_COMPONENT_MANIFEST] = "Manifest",
	[LOGGING_COMPONENT_SPI_FILTER] = "Filter",
	[LOGGING_COMPONENT_I2C] = "I2C",
	[LOGGING_COMPONENT_BOOT] = "Boot",
	[LOGGING_COMPONENT_FLASH] = "Flash",
	[LOGGING_COMPONENT_SPI] = "SPI",
	[LOGGING_COMPONENT_RECOVERY] = "Rec Img",
	[LOGGING_COMPONENT_MCTP] = "MCTP",
	[LOGGING_COMPONENT_TPM] = "TPM",
	[LOGGING_COMPONENT_RIOT] = "RIoT",
	[LOGGING_COMPONENT_SYSTEM] = "System",
	[LOGGING_COMPONENT_INTRUSION] = "Intrusion",
	[LOGGING_COMPONENT_ATTESTATION] = "Attestation",
	[LOGGING_COMPONENT_SPDM] = "SPDM",
};

/**
 * Strings for the crypto logging messages.
 */
const char *crypto_logging_messages_str[] = {
	[CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_INIT_EC] = "mbedTLS - AES GCM initialization error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_CRYPT_EC] =
		"mbedTLS - AES GCM buffer encryption/decryption error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_AUTH_DECRYPT_EC] =
		"mbedTLS - AES GCM buffer authenticated decryption error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC] = "mbedTLS - Public key context init error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_EC] = "mbedTLS - Private key parsing error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_PUB_EC] = "mbedTLS - Public key parsing error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_KEY_DER_EC] =
		"mbedTLS - Private key DER export error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_PUBKEY_DER_EC] =
		"mbedTLS - Public key DER export error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_SIGN_EC] = "mbedTLS - Signing error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC] = "mbedTLS - Signature verification error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_COPY_EC] = "mbedTLS - ECP group copy error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECP_COPY_EC] = "mbedTLS - ECP copy error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECP_CHECK_PUB_PRV_EC] = "mbedTLS - ECP keypair check error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_LOAD_EC] = "mbedTLS - ECP group load error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECP_MUL_EC] = "mbedTLS - ECP multiplication error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECP_GEN_KEY_EC] = "mbedTLS - ECP key pair generation error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC] = "mbedTLS - MPI import from binary error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_MPI_WRITE_BIN_EC] = "mbedTLS - MPI export to binary error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ECDH_COMPUTE_SHARED_SECRET_EC] =
		"mbedTLS - ECDH shared secret computation error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC] =
		"mbedTLS - CTR DRBG initial seeding error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ASN1_WRITE_OID_EC] = "mbedTLS - ASN1 OID write error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ASN1_CLOSE_EC] = "mbedTLS - ASN1 object close error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ASN1_GET_TAG_EC] = "mbedTLS - ASN1 get tag error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_ASN1_GET_INT_EC] = "mbedTLS - ASN1 get int error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC] = "mbedTLS - X509 failure during key load: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_SET_SUBJECT_EC] =
		"mbedTLS - X509 CSR subject set error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_KEY_USAGE_EC] =
		"mbedTLS - X509 key usage addition error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_EXT_KEY_USAGE_EC] =
		"mbedTLS - X509 extended key usage addition error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_BASIC_CONSTRAINTS_EC] =
		"mbedTLS - X509 basic constraints addition error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_RIOT_EC] = "mbedTLS - X509 RIOT addition error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_DER_WRITE_EC] =
		"mbedTLS - X509 CSR write to DER error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_SUBJECT_EC] = "mbedTLS - X509 CRT subject set error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_ISSUER_EC] = "mbedTLS - X509 CRT issuer set error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_VALIDITY_EC] =
		"mbedTLS - X509 CRT validity set error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_AUTHORITY_EC] =
		"mbedTLS - X509 CRT authority set error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_WRITE_DER_EC] = "mbedTLS - X509 CRT write to DER error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_PARSE_DER_EC] = "mbedTLS - X509 CRT parse as DER error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_CRT_CERT_AUTHENTICATE_EC] =
		"mbedTLS - X509 CRT certificate authentication error code: 0x%x, %x",
	[CRYPTO_LOG_MSG_MBEDTLS_RSA_GEN_KEY_EC] = "mbedTLS - RSA key generation error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_RSA_PKCS1_VERIFY_EC] =
		"mbedTLS - RSA PKCS1 verification error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_LOAD_EC] = "mbedTLS - RSA public key load error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC] =
		"mbedTLS - RSA public key check error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_RSA_OAEP_DECRYPT_EC] = "mbedTLS - RSA OAEP decryption error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_TCBINFO_EC] =
		"mbedTLS - X509 TCB Info addition error code: 0x%x",
	[CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_UEID_EC] = "mbedTLS - X509 UEID addition error code: 0x%x",
};

/**
 * Strings for the cmd interface logging messages.
 */
const char *cmd_logging_messages_str[] = {
	[CMD_LOGGING_PROCESS_FAIL] = "Command processing error code: 0x%x, channel %i",
	[CMD_LOGGING_PACKET_OVERFLOW] = "Command packet overflow on channel %i",
	[CMD_LOGGING_PROTOCOL_ERROR] =
		"Command processing error, Tag: 0x%x from [0x%x] to [0x%x], %s",
	[CMD_LOGGING_SEND_PACKET_FAIL] = "Error sending a packet on channel %i, code 0x%x",
	[CMD_LOGGING_RECEIVE_PACKET_FAIL] = "Error receiving a packet on channel %i, code 0x%x",
	[CMD_LOGGING_SOC_RESET_TRIGGERED] = "SoC reset command received on channel %i, id %d",
	[CMD_LOGGING_SOC_NMI_TRIGGERED] = "SoC NMI command received on channel %i",
	[CMD_LOGGING_ERROR_MESSAGE] =
		"Received MCTP error message, Tag: 0x%x from [0x%x] to [0x%x], [0x%x]: 0x%x",
	[CMD_LOGGING_UNSEAL_FAIL] = "An unseal operation failed, code 0x%x",
	[CMD_LOGGING_RESTORE_BYPASS_FAIL] = "Failed to revert device to bypass mode, code 0x%x",
	[CMD_LOGGING_BYPASS_RESTORED] = "Device has been reverted to bypass mode",
	[CMD_LOGGING_RESTORE_DEFAULTS_FAIL] = "Failed to revert device to the default state, code 0x%x",
	[CMD_LOGGING_DEFAULTS_RESTORED] = "Device has been wiped of all configuration",
	[CMD_LOGGING_NOTIFICATION_ERROR] = "Unknown background task notification: 0x%x",
	[CMD_LOGGING_DEBUG_LOG_CLEAR_FAIL] = "Failed to clear debug log: 0x%x",
	[CMD_LOGGING_COMMAND_TIMEOUT] =
		"Command response on channel %i was not sent due to processing timeout: %ims",
	[CMD_LOGGING_DEBUG_LOG_CLEARED] = "The debug log has been cleared",
	[CMD_LOGGING_NO_CERT] = "Certificate in slot=%i, num=%i is not available, code 0x%x",
	[CMD_LOGGING_CHANNEL_PACKET_ERROR] = "Channel %i detected an error while receiving a packet",
	[CMD_LOGGING_NO_BACKGROUND_HANDELR] = "No background task handler provided for an event: 0x%x",
	[CMD_LOGGING_AUX_KEY] = "Done generating auxiliary attestation key, code 0x%x",
	[CMD_LOGGING_GENERATE_AUX_KEY] = "Generating auxiliary attestation key",
	[CMD_LOGGING_CLEAR_PLATFORM_CONFIG] = "Device platform configuration has been cleared",
	[CMD_LOGGING_CLEAR_PLATFORM_FAIL] = "Failed to clear platform configuration, code 0x%x",
	[CMD_LOGGING_RESET_INTRUSION] =	"Intrusion state has been reset",
	[CMD_LOGGING_RESET_INTRUSION_FAIL] = "Failed to reset intrusion state, code 0x%x",
	[CMD_LOGGING_CHANNEL] = "Received response on channel %i",
	[CMD_LOGGING_CLEAR_CFM] = "Component manifests have been cleared",
	[CMD_LOGGING_CLEAR_CFM_FAIL] = "Failed to clear component manifests, code 0x%x",
	[CMD_LOGGING_PERSIST_EID_FAIL] = "Failed to persist eid on flash, eid %i, code 0x%x",
};

/**
 * Strings for the host management logging messages.
 */
const char *host_logging_messages_str[] = {
	[HOST_LOGGING_PENDING_FAILED_FW_UPDATE] =
		"Pending PFM failed configuration of host FW update for port %i, code 0x%x",
	[HOST_LOGGING_PENDING_FAILED_CURRENT] =
		"Pending PFM failed configuration of current FW for port %i, code 0x%x",
	[HOST_LOGGING_ACTIVE_FAILED_FW_UPDATE] =
		"Active PFM failed configuration of host FW update for port %i, code 0x%x",
	[HOST_LOGGING_ROLLBACK_FAILED] = "Host FW rollback attempt failed, code 0x%x, port %i",
	[HOST_LOGGING_RECOVERY_IRQ] = "Failed to configure recovery IRQs: enable=%i, code 0x%x",
	[HOST_LOGGING_SOFT_RESET] = "Host %i soft reset processing error, code 0x%x",
	[HOST_LOGGING_PENDING_VERIFY_FW_UPDATE] =
		"Pending PFM verification of a host FW update for port %i, code 0x%x",
	[HOST_LOGGING_PENDING_VERIFY_CURRENT] =
		"Pending PFM verification of the current FW for port %i, code 0x%x",
	[HOST_LOGGING_ACTIVE_VERIFY_FW_UPDATE] =
		"Active PFM verification of a host FW update for port %i, code 0x%x",
	[HOST_LOGGING_ACTIVE_VERIFY_CURRENT] =
		"Active PFM verification of the current FW for port %i, code 0x%x",
	[HOST_LOGGING_ACTIVE_FAILED_CURRENT] =
		"Active PFM failed configuration of current FW for port %i, code 0x%x",
	[HOST_LOGGING_PENDING_ACTIVATE_FW_UPDATE] =
		"Pending PFM activation of a validated host FW update for port %i, code 0x%x",
	[HOST_LOGGING_ACTIVE_ACTIVATE_FW_UPDATE] =
		"Active PFM activation of a validated host FW update for port %i, code 0x%x",
	[HOST_LOGGING_ROLLBACK_STARTED] = "Host flash rollback has been triggered for port %i",
	[HOST_LOGGING_ROLLBACK_COMPLETED] = "Host flash rollback completed successfully for port %i",
	[HOST_LOGGING_PENDING_ROLLBACK_FAILED] =
		"Host FW rollback attempt failed using the pending PFM, code 0x%x, port %i",
	[HOST_LOGGING_PREPARE_UPDATE] = "Port %i firmware prepare update, code 0x%x",
	[HOST_LOGGING_WRITE_UPDATE_FAILED] = "Port %i firmware update write failure, code 0x%x",
	[HOST_LOGGING_NOTIFICATION_ERROR] = "Port %i firmware bad task notification: 0x%x",
	[HOST_LOGGING_ENTER_RESET] = "Detected host reset on port %i",
	[HOST_LOGGING_EXIT_RESET] = "Detected host out of reset on port %i",
	[HOST_LOGGING_HOST_DOWN] = "Detected host down on port %i, code 0x%x",
	[HOST_LOGGING_HOST_UP] = "Detected host up on port %i, code 0x%x",
	[HOST_LOGGING_RECOVERY_STARTED] = "Recovery has been triggered for port %i",
	[HOST_LOGGING_RECOVERY_COMPLETED] = "Recovery image applied successfully for port %i",
	[HOST_LOGGING_RECOVERY_FAILED] = "Recovery attempt failed, code 0x%x, port %i",
	[HOST_LOGGING_HOST_FLASH_ACCESS_ERROR] = "Port %i failed to give host SPI access, code 0x%x",
	[HOST_LOGGING_HOST_FLASH_ACCESS_RETRIES] = "Port %i needed %i retries to give host SPI access",
	[HOST_LOGGING_POWER_ON_RESET] = "Host %i power-on reset processing error, code 0x%x",
	[HOST_LOGGING_BYPASS_MODE] = "Configuring host %i to boot unsecurely, code 0x%x",
	[HOST_LOGGING_ROT_FLASH_ACCESS_ERROR] = "Port %i failed to take host SPI access, code 0x%x",
	[HOST_LOGGING_ROT_FLASH_ACCESS_RETRIES] = "Port %i needed %i retries to take host SPI access",
	[HOST_LOGGING_FILTER_FLASH_TYPE_ERROR] =
		"Port %i failed filter configuration for the flash devices, code 0x%x",
	[HOST_LOGGING_FILTER_FLASH_TYPE_RETRIES] =
		"Port %i needed %i retries for flash device filter configuration",
	[HOST_LOGGING_SWAP_FLASH_ERROR] = "Port %i failed to swap host flash devices, code 0x%x",
	[HOST_LOGGING_SWAP_FLASH_RETRIES] = "Port %i needed %i retries to swap host flash devices",
	[HOST_LOGGING_FILTER_RW_REGIONS_ERROR] =
		"Port %i failed to configure filter R/W regions, code 0x%x",
	[HOST_LOGGING_FILTER_RW_REGIONS_RETRIES] =
		"Port %i needed %i retries to configure filter R/W regions",
	[HOST_LOGGING_INIT_PROTECTION_ERROR] =
		"Port %i failed to initialize host flash protection, code 0x%x",
	[HOST_LOGGING_INIT_PROTECTION_RETRIES] =
		"Port %i needed %i retries to initialize host flash protection",
	[HOST_LOGGING_CONFIG_FLASH_ERROR] =
		"Port %i failed to configure the filter with the RO device, code 0x%x",
	[HOST_LOGGING_CONFIG_FLASH_RETRIES] =
		"Port %i needed %i retries to configure the RO flash device",
	[HOST_LOGGING_BYPASS_MODE_ERROR] =
		"Port %i failed to configure the filter for bypass mode, code 0x%x",
	[HOST_LOGGING_BYPASS_MODE_RETRIES] = "Port %i needed %i retries to configure bypass mode",
	[HOST_LOGGING_CLEAR_RW_REGIONS_ERROR] =
		"Port %i failed to clear all filter R/W regions, code 0x%x",
	[HOST_LOGGING_CLEAR_RW_REGIONS_RETRIES] =
		"Port %i needed %i retries to clear filter R/W regions",
	[HOST_LOGGING_PCR_UPDATE_ERROR] = "Failed to update host FW PCR 0x%x, code 0x%x",
	[HOST_LOGGING_BACKUP_FIRMWARE_STARTED] = "Port %i has started backup of active host firmware",
	[HOST_LOGGING_BACKUP_FIRMWARE_COMPLETED] =
		"Port %i active host firmware backup has completed, code 0x%x",
	[HOST_LOGGING_BMC_RECOVERY_DETECTED] = "Port %i detected BMC recovery indication, count %i",
	[HOST_LOGGING_RESET_COUNTER_UPDATE_FAILED] =
		"Port %i failed to to update reset counter, code 0x%x",
	[HOST_LOGGING_RW_RESTORE_START] =
		"Port %i start restore of active image R/W regions, code 0x%x",
	[HOST_LOGGING_RW_RESTORE_FINISH] =
		"Port %i completed restore of active image R/W regions, code 0x%x",
	[HOST_LOGGING_CHECK_PENDING_FAILED] = "Port %i failed to check pending PFM contents, code 0x%x",
	[HOST_LOGGING_CLEAR_PFMS] = "Port %i entering bypass mode via PFM",
	[HOST_LOGGING_RESET_RELEASE_FAILED] = "Failed to release the reset after POR for port %i",
	[HOST_LOGGING_FLASH_RESET] = "Host flash was reset on port %i, code 0x%x",
	[HOST_LOGGING_FORCE_RESET] = "Forced reset issued to host on port %i",
	[HOST_LOGGING_HOST_BOOTING_TIME] = "Host on port %i boot time: %ims",
	[HOST_LOGGING_RECOVERY_RETRIES] = "Port %i needed %i host recovery retries",
};

/**
 * Strings for the FW image management logging messages.
 */
const char *fw_image_logging_messages_str[] = {
	[FIRMWARE_LOGGING_RECOVERY_IMAGE] = "Recovery image state: recovery_bad=%i, code 0x%x",
	[FIRMWARE_LOGGING_UPDATE_FAIL] = "Firmware update failure 0x%x, code 0x%x",
	[FIRMWARE_LOGGING_UPDATE_START] = "Start processing a received firmware image",
	[FIRMWARE_LOGGING_UPDATE_COMPLETE] = "Firmware update completed successfully",
	[FIRMWARE_LOGGING_ERASE_FAIL] = "Firmware update erase failure 0x%x, code 0x%x",
	[FIRMWARE_LOGGING_WRITE_FAIL] = "Firmware update write failure 0x%x, code 0x%x",
	[FIRMWARE_LOGGING_RECOVERY_RESTORE_FAIL] = "Failed to restore the recovery image, code 0x%x",
	[FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE] = "Done restoring the active image, code 0x%x",
	[FIRMWARE_LOGGING_ACTIVE_RESTORE_START] = "Start to restore a bad active image",
	[FIRMWARE_LOGGING_RECOVERY_RESTORE_START] = "Start to restore a bad recovery image",
	[FIRMWARE_LOGGING_RECOVERY_UPDATE] = "Updating the recovery image",
	[FIRMWARE_LOGGING_REVOCATION_UPDATE] = "Updating hardware backed anti-rollback",
	[FIRMWARE_LOGGING_REVOCATION_FAIL] = "Firmware revocation failure 0x%x, code 0x%x",
};

/**
 * Strings for the state management logging messages.
 */
const char *state_logging_messages_str[] = {
	[STATE_LOGGING_PERSIST_FAIL] = "Failed to save state ID %i, code 0x%x",
	[STATE_LOGGING_ERASE_FAIL] = "Failed to erase unused state storage at 0x%x, code 0x%x",
};

/**
 * Strings for the manifest logging messages.
 */
const char *manifest_messages_str[] = {
	[MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL] = "Failed to record measurement 0x%x, code 0x%x",
	[MANIFEST_LOGGING_GET_MEASUREMENT_FAIL] = "Failed to get measurement 0x%x, code 0x%x",
	[MANIFEST_LOGGING_PFM_VERIFIED_EVENT_FAIL] = "Failed PFM verification notification, code 0x%x",
	[MANIFEST_LOGGING_PFM_ACTIVATED_EVENT_FAIL] = "Failed PFM activation notification, code 0x%x",
	[MANIFEST_LOGGING_CFM_VERIFIED_EVENT_FAIL] = "Failed CFM verification notification, code 0x%x",
	[MANIFEST_LOGGING_CFM_ACTIVATED_EVENT_FAIL] = "Failed CFM activation notification, code 0x%x",
	[MANIFEST_LOGGING_PENDING_RESET_FAIL] = "Failed to set reset for a pending PFM, code 0x%x",
	[MANIFEST_LOGGING_PFM_RECORD_INVALID] = "Invalid call to force PFM measurements, code 0x%x",
	[MANIFEST_LOGGING_CFM_RECORD_INVALID] = "Invalid call to force CFM measurements, code 0x%x",
	[MANIFEST_LOGGING_KEY_REVOCATION_FAIL] =
		"Failure while running manifest key revocation: key %i, code 0x%x",
	[MANIFEST_LOGGING_ERASE_FAIL] = "Port %i manifest update erase failure, code 0x%x",
	[MANIFEST_LOGGING_WRITE_FAIL] = "Port %i manifest update write failure, code 0x%x",
	[MANIFEST_LOGGING_VERIFY_FAIL] = "Port %i manifest update verification failure, code 0x%x",
	[MANIFEST_LOGGING_NOTIFICATION_ERROR] = "Port %i manifest bad task notification: 0x%x",
	[MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR] =
		"Activation failure for port %i preventing host access to flash, code 0x%x",
	[MANIFEST_LOGGING_ACTIVATION_FAIL] = "Failed to activate manifest for port %i, code 0x%x",
	[MANIFEST_LOGGING_PCD_VERIFIED_EVENT_FAIL] = "Failed PCD verification notification, code 0x%x",
	[MANIFEST_LOGGING_PCD_ACTIVATED_EVENT_FAIL] = "Failed PCD activation notification, code 0x%x",
	[MANIFEST_LOGGING_PCD_RECORD_INVALID] = "Invalid call to force PCD measurements, code 0x%x",
	[MANIFEST_LOGGING_EMPTY_PFM] = "Port %i revert to bypass mode via PFM, code 0x%x",
	[MANIFEST_LOGGING_GET_ID_FAIL] = "Failed to get manifest ID for measurement 0x%x, code 0x%x",
	[MANIFEST_LOGGING_GET_PLATFORM_ID_FAIL] =
		"Failed to get manifest Platform ID for measurement 0x%x, code 0x%x",
	[MANIFEST_LOGGING_EMPTY_PCD] = "An empty PCD caused the active PCD to be cleared",
	[MANIFEST_LOGGING_EMPTY_CFM] = "An empty CFM caused the active CFM to be cleared",
	[MANIFEST_LOGGING_PFM_CLEAR_ACTIVE_EVENT_FAIL] =
		"Failed clear active PFM notification, code 0x%x",
	[MANIFEST_LOGGING_CFM_CLEAR_ACTIVE_EVENT_FAIL] =
		"Failed clear active CFM notification, code 0x%x",
	[MANIFEST_LOGGING_PCD_CLEAR_ACTIVE_EVENT_FAIL] =
		"Failed clear active PCD notification, code 0x%x",
	[MANIFEST_LOGGING_PCD_UPDATE] = "Apply a received PCD update",
	[MANIFEST_LOGGING_CFM_ACTIVATION] = "Received a CFM activate request",
	[MANIFEST_LOGGING_PFM_ACTIVATION_REQUEST_FAIL] = "PFM activation request notification failure, code 0x%x",
	[MANIFEST_LOGGING_CFM_ACTIVATION_REQUEST_FAIL] = "CFM activation request notification failure, code 0x%x",
	[MANIFEST_LOGGING_PCD_ACTIVATION_REQUEST_FAIL] = "PCD activation request notification failure, code 0x%x",
	[MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY] = "Manifest key %i has no valid key available in the keystore, code 0x%x",
	[MANIFEST_LOGGING_MANIFEST_KEY_REVOKED] = "Default manifest key %i has been revoked by a keystore key with ID 0x%x",
};

/**
 * Strings for the SPI filter logging messages.
 */
const char *spi_filter_messages_str[] = {
	[SPI_FILTER_LOGGING_BLOCKED_COMMAND] =
		"A SPI command was blocked by filter port %d: opcode=0x%x",
	[SPI_FILTER_LOGGING_READ_BLOCKED_FAIL] =
		"Failed to read a blocked SPI command code for port %d, code 0x%x",
	[SPI_FILTER_LOGGING_IRQ_STATUS] = "SPI filter %i generated an interrupt: 0x%x",
	[SPI_FILTER_LOGGING_FILTER_CONFIG] =
		"SPI filter %i configuration, mfg_id=%i, %s, ro_cs=%i, addr_mode=%s, addr_rst=%s, addr_we=%i, dirty=%i, bypass=%s, flash_mode=%s, single_wr=%s",
	[SPI_FILTER_LOGGING_ADDRESS_MODE] = "SPI filter %i address mode changed: %s",
	[SPI_FILTER_LOGGING_FILTER_REGION] = "SPI filter %i R/W Region %i: 0x%08x-0x%08x",
	[SPI_FILTER_LOGGING_DEVICE_SIZE] = "SPI filter %i device size: 0x%08x",
};

/**
 * Strings for the I2C logging messages.
 */
const char *i2c_messages_str[] = {
	[I2C_LOGGING_MASTER_WRITE_FAIL] = "Error while performing I2C operation: 0x%x",
	[I2C_LOGGING_SLAVE_BUS_LOCKUP] = "I2C slave detected bus lock-up on channel %i: status=0x%x",
};

/**
 * Strings for the flash logging messages.
 */
const char *flash_messages_str[] = {
	[FLASH_LOGGING_INCOMPLETE_WRITE] = "A partial flash write failed at address 0x%x, code 0x%x",
	[FLASH_LOGGING_ECC_ERROR] = "Flash ECC errors: correctable=0x%x, uncorrectable=0x%x",
	[FLASH_LOGGING_ECC_REFRESH] = "Refresh flash data at address 0x%x due to ECC errors, code 0x%x",
};

/**
 * Logging messages for MCTP stack operations.
 */
const char *mctp_messages_str[] = {
	[MCTP_LOGGING_PROTOCOL_ERROR] =
		"Error while processing input in MCTP protocol layer, Tag: 0x%x from [0x%x] to [0x%x], %s",
	[MCTP_LOGGING_ERR_MSG] =
		"Received Cerberus protocol error message, Tag: 0x%x from [0x%x] to [0x%x], [0x%x]: 0x%x",
	[MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL] =
		"Failure while processing MCTP control request message: 0x%x on channel %i",
	[MCTP_LOGGING_PKT_DROPPED] =
		"MCTP packet dropped, length %i: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
	[MCTP_LOGGING_CHANNEL] = "MCTP channel %i",
	[MCTP_LOGGING_SET_EID_FAIL] = "Failed when processing a Set EID request: 0x%x on channel %i",
	[MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN] =
		"Received a MCTP control message with invalid length %i from device 0x%x for command %i",
	[MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL] =
		"Received a MCTP control message with a failed completion code: 0x%x from device 0x%x for command %i",
	[MCTP_LOGGING_MCTP_CONTROL_RSP_FAIL] =
		"Failure while processing MCTP control response message: 0x%x on channel %i",
	[MCTP_LOGGING_GET_EID_FAIL] = "Failed when processing a Get EID request: 0x%x on channel %i",
	[MCTP_LOGGING_RSP_TIMEOUT] =
		"Timed out while waiting for MCTP response from device (0x%x), message tag %i, timeout duration %i",
};

/**
 * Logging messages for a recovery image.
 */
const char *recovery_img_messages_str[] = {
	[RECOVERY_LOGGING_RECORD_MEASUREMENT_FAIL] =
		"Failed to record host recovery image measurement %i in PCR store: 0x%x",
	[RECOVERY_LOGGING_GET_MEASUREMENT_FAIL] =
		"Failed to get host recovery image measurement %i: 0x%x",
	[RECOVERY_LOGGING_ACTIVATED_EVENT_FAIL] =
		"Failed host recovery image activation notification: 0x%x",
	[RECOVERY_LOGGING_RECORD_INVALID] =
		"Invalid call to force host recovery image measurements: 0x%x",
	[RECOVERY_LOGGING_WRITE_FAIL] = "Port %i host recovery update write failure: 0x%x",
	[RECOVERY_LOGGING_VERIFY_FAIL] =
		"Port %i host recovery update verification failure: 0x%x",
	[RECOVERY_LOGGING_NOTIFICATION_ERROR] =
		"Port %i host recovery bad task notification: 0x%x",
	[RECOVERY_LOGGING_ACTIVATION_FLASH_ERROR] =
		"Activation failure for port %i preventing host access to flash: 0x%x",
	[RECOVERY_LOGGING_ACTIVATION_FAIL] =
		"Failed to activate host recovery image for port %i: 0x%x",
	[RECOVERY_LOGGING_ERASE_FAIL] = "Port %i host recovery image update erase failure: 0x%x",
	[RECOVERY_LOGGING_INVALIDATE_MEASUREMENT_FAIL] =
		"Failed to invalidate a measurement %i in PCR store: 0x%x",
	[RECOVERY_LOGGING_OCP_READ_ERROR] = "Error processing an OCP recovery read request: 0x%x",
	[RECOVERY_LOGGING_OCP_WRITE_ERROR] = "Error processing an OCP recovery write request: 0x%x",
	[RECOVERY_LOGGING_OCP_PEC_ERROR] =
		"PEC error on a received OCP recovery request: calc=0x%x, data=0x%x",
	[RECOVERY_LOGGING_OCP_WRITE_INCOMPLETE] =
		"An incomplete block write OCP recovery command was received: rx bytes=%d, byte count=%d",
	[RECOVERY_LOGGING_OCP_WRITE_OVERFLOW] =
		"An OCP recovery write request received more data than is allowed",
};

/**
 * Strings for the TPM logging messages.
 */
const char *tpm_logging_messages_str[] = {
	[TPM_LOGGING_CLEAR_FAILED] = "TPM clear failed: 0x%x",
	[TPM_LOGGING_CLEAR_TPM] = "TPM storage has been cleared",
	[TPM_LOGGING_INVALID_HEADER] = "TPM storage header was not valid",
	[TPM_LOGGING_READ_HEADER_FAILED] = "Failed to read the TPM storage header: 0x%x",
	[TPM_LOGGING_SOFT_RESET_ERROR] = "TPM storage soft reset error: 0x%x",
	[TPM_LOGGING_NO_HEADER] = "TPM header not available: 0x%x",
	[TPM_LOGGING_NO_SEGMENT_DATA] = "TPM storage segment %i had no data: 0x%x",
	[TPM_LOGGING_ERASE_FAILED] = "TPM storage segment %i failed to be erased: 0x%x",
};

/**
 * Logging messages for RIoT.
 */
const char *riot_messages_str[] = {
	[RIOT_LOGGING_DEVID_AUTH_STATUS] = "Authenticate signed Device ID cert chain: 0x%x",
};

/**
 * Logging messages for system management.
 */
const char *system_messages_str[] = {
	[SYSTEM_LOGGING_RESET_NOT_EXECUTED] = "Failed to schedule a device reset, code 0x%x",
	[SYSTEM_LOGGING_RESET_FAIL] = "Failed to reset the device, code 0x%x",
	[SYSTEM_LOGGING_PERIODIC_FAILED] = "Task %i failed to execute a periodic handler, code 0x%x",
	[SYSTEM_LOGGING_POLICY_CHECK_FAIL] =
		"Failed to query the device security policy for %s, code 0x%x",
	[SYSTEM_LOGGING_GET_POLICY_FAIL] = "Failed get the active security policy, code 0x%x",
	[SYSTEM_LOGGING_UNDETERMINED_UNLOCK] = "Failed to load or apply an unlock policy, code 0x%x",
	[SYSTEM_LOGGING_DEVICE_UNLOCKED] = "A %s unlock policy has been applied to the device",
	[SYSTEM_LOGGING_LOCK_STATE_FAIL] =
		"An error occurred attempting to update the device lock state, code 0x%x",
	[SYSTEM_LOGGING_TOKEN_INVALIDATE_FAIL] =
		"Failed to invalidate a consumed unlock token, code 0x%x",
};

/**
 * Strings for the security policy checks in logging messages.
 */
const char *system_policy_str[] = {
	[SYSTEM_LOGGING_POLICY_FW_SIGNING] = "firmware signing",
	[SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK] = "anti-rollback",
};

/**
 * Strings for the unlock policy types in logging messages.
 */
const char *system_unlock_type_str[] = {
	[SYSTEM_LOGGING_UNLOCK_PERSISTENT] = "persistent",
	[SYSTEM_LOGGING_UNLOCK_ONE_TIME] = "one-time",
};

/**
 * Logging messages for chassis intrusion management.
 */
const char *intrusion_messages_str[] = {
	[INTRUSION_LOGGING_INTRUSION_DETECTED] = "Chassis intrusion detected",
	[INTRUSION_LOGGING_HANDLE_FAILED] = "Failed to handle a detected intrusion event, code 0x%x",
	[INTRUSION_LOGGING_CHECK_FAILED] = "Chassis intrusion state check failed, code 0x%x",
	[INTRUSION_LOGGING_INTRUSION_NOTIFICATION] = "Processed an intrusion notification, code 0x%x",
	[INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION] =
		"Processed a no intrusion notification, code 0x%x",
	[INTRUSION_LOGGING_ERROR_NOTIFICATION] =
		"Processed an intrusion error notification, code 0x%x",
	[INTRUSION_LOGGING_STORE_DATA_FAIL] =
		"Failed to store intrusion data for EID %i, code 0x%x",
	[INTRUSION_LOGGING_CHALLENGE_DATA_FAIL] =
		"Failed to challenge intrusion data for EID %i, code 0x%x",
	[INTRUSION_LOGGING_CHALLENGE_DATA_INVALID_HASH_LEN] =
		"Invalid intrusion data hash length %i from EID %i",
};

/**
 * Logging messages for attestation operations.
 */
const char *attestation_messages_str[] = {
	[ATTESTATION_LOGGING_DEVICE_NOT_INTEROPERABLE] = "Target device (0x%x) does not support interoperable protocol specification version.",
	[ATTESTATION_LOGGING_GET_CERT_NOT_SUPPORTED] = "Target device (0x%x) does not support get certificate command: %i",
	[ATTESTATION_LOGGING_MEASUREMENT_CAP_NOT_SUPPORTED] = "Target device (0x%x) does not support measurement response capabilities: %i",
	[ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY] = "Requested slot number not occupied by certificate chain on target device (0x%x): slot number %i, slot mask %i",
	[ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP] = "Requested slot number not utilized by target device (0x%x) in response: %i vs %i",
	[ATTESTATION_LOGGING_CERT_CHAIN_DIGEST_MISMATCH] = "Certificate chain digest provided by target device (0x%x) in response different than cached, slot number %i",
	[ATTESTATION_LOGGING_TARGET_REQ_UNSUPPORTED_MUTUAL_AUTH] = "Target device (0x%x) requested unsupported mutual authentication.",
	[ATTESTATION_LOGGING_UNEXPECTED_HASH_LEN_IN_RSP] = "Expected hash length not utilized by target device (0x%x) in attestation response: %i vs %i",
	[ATTESTATION_LOGGING_UNEXPECTED_HASH_ALGO_IN_RSP] = "Expected hash algorithm not utilized by target device (0x%x) in attestation response: %i",
	[ATTESTATION_LOGGING_UNEXPECTED_MEAS_HASH_ALGO_IN_RSP] = "Expected measurement hash algorithm not utilized by target device (0x%x) in attestation response: %i",
	[ATTESTATION_LOGGING_CERBERUS_PROTOCOL_VER_UNSUPPORTED] = "Attestation target device (0x%x) protocol version not interoperable with device: device max %i, device min %i, supported %i",
	[ATTESTATION_LOGGING_ALIAS_KEY_TYPE_UNSUPPORTED] = "Attestation target device (0x%x) sent an alias certificate with unsupported key type %i",
	[ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH] = "Target (0x%x) certificate chain digest comparison with digest sent by target failed, slot number %i: %x",
	[ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED] = "Received response from device (0x%x) unexpected: Received protocol %i command %i, Expected protocol %i command %i ",
	[ATTESTATION_LOGGING_MEASUREMENT_SPEC_UNSUPPORTED] = "Target device (0x%x) uses unsupported measurement spec %i",
	[ATTESTATION_LOGGING_BASE_ASYM_KEY_SIG_ALG_UNSUPPORTED] = "Target device (0x%x) uses unsupported asymmetric key signature algorithm %i",
	[ATTESTATION_LOGGING_HASHING_ALGORITHM_UNSUPPORTED] = "Target device (0x%x) uses unsupported hashing algorithm %i",
	[ATTESTATION_LOGGING_HASHING_MEAS_ALGORITHM_UNSUPPORTED] = "Target device (0x%x) uses unsupported measurement hashing algorithm %i",
	[ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN] = "Received response from device (0x%x) has unexpected length for command %i: %i vs %i",
	[ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS] = "Received measurements response from device (0x%x) has unexpected number of measurement blocks: %i vs %i",
	[ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION] = "Device (0x%x) failed during attestation flow: protocol %i command %i, code %x",
	[ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_DIGEST] = "Device (0x%x) measurements response has digest of measurement block when raw requested: block %i",
	[ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE] = "Device (0x%x) measurements response too large: block %i size %i",
	[ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW] = "Device (0x%x) in response to measurement operation %i sent block %i in raw form when digest requested",
	[ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED] = "Device (0x%x) using SPDM protocol minor version %i failed to send SPDM device ID block: 0x%x",
	[ATTESTATION_LOGGING_ILLEGAL_RSP_NOT_READY] = "Received response not ready response from device (0x%x) for command 0x%x that does not permit it.",
	[ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP] = "Response not ready from device (0x%x) for unexpected command received: 0x%x vs 0x%x",
	[ATTESTATION_LOGGING_BRIDGE_RESET_TRIGGERED_ROUTING_TABLE_SYNC] = "MCTP bridge has triggered a MCTP routing table sync",
	[ATTESTATION_LOGGING_BRIDGE_FAILED_TO_DETECT_MCTP_BRIDGE_RESET] = "MCTP bridge reset detection failed, code %x",
	[ATTESTATION_LOGGING_ROUTING_TABLE_REFRESH_REQUEST_FAILED] = "Failed to request an MCTP routing table refresh, code %x",
	[ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID] = "CFM version set selector for device (0x%x) PMR %i Measurement %i entry %i invalid",
	[ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED] = "Failed to determine device version set for device (0x%x) using CFM version set selector entry PMR %i Measurement %i, code %x",
	[ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY] = "Device discovery failed during attestation flow: command %i, code %x",
	[ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR] = "Failed to find next device for discovery, code %x",
	[ATTESTATION_LOGGING_NEXT_DEVICE_ATTESTATION_ERROR] = "Failed to find next device for attestation, code %x",
	[ATTESTATION_LOGGING_PCR_UPDATE_ERROR] = "Failed to update attestation PCR 0x%x, code 0x%x",
	[ATTESTATION_LOGGING_GET_ATTESTATION_STATUS_ERROR] = "Failed to get attestation status, code %x",
	[ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR] = "Failed to get MCTP routing table, code %x",
};

/**
 * Logging messages for SPDM stack.
 */
const char *spdm_messages_str[] = {
	[SPDM_LOGGING_ERR_MSG] =
		"Failed while processing SPDM request (0x%x) from (0x%x). SPDM error code 0x%x, data 0x%x, code 0x%x ",
};

/**
 * Strings for crash or exception diagnostics.
 */
const char *crash_dump_messages_str[] = {
	[CRASH_DUMP_LOGGING_EXCEPTION] = "An exception occurred: type 0x%x, stack 0x%x",
	[CRASH_DUMP_LOGGING_EXCEPTION_DETAIL] = "", /* Defined in crash_dump_details_str. */
};

/**
 * Strings for detailed information getting logged for an exception.
 */
const char *crash_dump_details_str[] = {
	[CRASH_DUMP_LOGGING_ARM_R0] = "R0: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_R1] = "R1: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_R2] = "R2: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_R3] = "R3: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_R12] = "R12: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_LR] = "LR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_PC] = "PC: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_XPSR] = "xPSR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_HFSR] = "HFSR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_MMFSR] = "MMFSR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_MMFAR] = "MMFAR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_BFSR] = "BFSR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_BFAR] = "BFAR: 0x%x",
	[CRASH_DUMP_LOGGING_ARM_UFSR] = "UFSR: 0x%x",
};

/**
 * Strings for the FW update statuses.
 */
const char *update_statuses_str[] = {
	[UPDATE_STATUS_SUCCESS] = "Successful update.",
	[UPDATE_STATUS_STARTING] = "The update process is starting.",
	[UPDATE_STATUS_START_FAILURE] = "Failed to start the update process, code 0x%x",
	[UPDATE_STATUS_VERIFYING_IMAGE] = "Verifying the staging image.",
	[UPDATE_STATUS_INCOMPLETE_IMAGE] = "Failed to receive the entire update image, code 0x%x",
	[UPDATE_STATUS_VERIFY_FAILURE] = "Failed while verifying the staging image, code 0x%x",
	[UPDATE_STATUS_INVALID_IMAGE] = "Staging image is not valid, code 0x%x",
	[UPDATE_STATUS_BACKUP_ACTIVE] = "Backing up the current image.",
	[UPDATE_STATUS_BACKUP_FAILED] = "Failed while backing up current image, code 0x%x",
	[UPDATE_STATUS_SAVING_STATE] = "Current application state is being saved.",
	[UPDATE_STATUS_STATE_SAVE_FAIL] = "Application state was not saved, code 0x%x",
	[UPDATE_STATUS_UPDATING_IMAGE] = "Active image is being updated from the staging flash.",
	[UPDATE_STATUS_UPDATE_FAILED] = "Failed to update active image, code 0x%x",
	[UPDATE_STATUS_CHECK_REVOCATION] = "Checking new certificate for revocation of older ones.",
	[UPDATE_STATUS_REVOKE_CHK_FAIL] = "Failed while checking for certificate revocation, code 0x%x",
	[UPDATE_STATUS_CHECK_RECOVERY] = "Checking recovery image to see if update is required.",
	[UPDATE_STATUS_RECOVERY_CHK_FAIL] = "Error while checking for recovery updates, code 0x%x",
	[UPDATE_STATUS_BACKUP_RECOVERY] = "Recovery image is being backed up.",
	[UPDATE_STATUS_BACKUP_REC_FAIL] = "Failed while backing up recovery image, code 0x%x",
	[UPDATE_STATUS_UPDATE_RECOVERY] = "Updating recovery image from staging flash.",
	[UPDATE_STATUS_UPDATE_REC_FAIL] = "Failed to update recovery image, code 0x%x",
	[UPDATE_STATUS_REVOKE_CERT] = "Certificate revocation list is being updated.",
	[UPDATE_STATUS_REVOKE_FAILED] = "Failed while updating certificate revocation list, code 0x%x",
	[UPDATE_STATUS_NONE_STARTED] = "No update attempted since last reboot.",
	[UPDATE_STATUS_STAGING_PREP_FAIL] = "Failed to prepare staging area for update, code 0x%x",
	[UPDATE_STATUS_STAGING_PREP] = "Preparing staging area for update.",
	[UPDATE_STATUS_STAGING_WRITE_FAIL] =
		"Failed to program staging area with update packet, code 0x%x",
	[UPDATE_STATUS_STAGING_WRITE] = "Programming staging area with update packet.",
	[UPDATE_STATUS_REQUEST_BLOCKED] = "A request was made before the previous one was completed.",
	[UPDATE_STATUS_TASK_NOT_RUNNING] = "The task servicing update requests is not running.",
	[UPDATE_STATUS_UNKNOWN] = "Update status cannot be determined.",
	[UPDATE_STATUS_SYSTEM_PREREQ_FAIL] = "The system state does not allow for firmware updates."
};

/**
 * Strings for the host recovery image update statuses.
 */
const char *recovery_image_cmd_statuses_str[] = {
	[RECOVERY_IMAGE_CMD_STATUS_SUCCESS] = "Successful operation.",
	[RECOVERY_IMAGE_CMD_STATUS_STARTING] = "The recovery image operation is starting",
	[RECOVERY_IMAGE_CMD_STATUS_REQUEST_BLOCKED] =
		"A request has been made before the previous one finished",
	[RECOVERY_IMAGE_CMD_STATUS_PREPARE] = "The recovery image is being prepared for updating",
	[RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL] =
		"There was an error preparing the recovery image for updating",
	[RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA] = "New recovery image data is being stored",
	[RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL] = "There was an error storing the recovery image data",
	[RECOVERY_IMAGE_CMD_STATUS_ACTIVATING] =
		"Activation is being attempted for a new recovery image",
	[RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL] =
		"There was an error activating the new recovery image, code 0x%x",
	[RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR] = "An unspecified, internal error occurred",
	[RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED] = "No recovery image operation has been started",
	[RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING] =
		"The task servicing recovery image operations is not running",
	[RECOVERY_IMAGE_CMD_STATUS_UNKNOWN] = "The recovery image status could not be determined",
};

/**
 * Strings for the manifest update statuses.
 */
const char *manifest_cmd_statuses_str[] = {
	[MANIFEST_CMD_STATUS_SUCCESS] = "Successful operation.",
	[MANIFEST_CMD_STATUS_STARTING] = "The manifest operation is starting.",
	[MANIFEST_CMD_STATUS_REQUEST_BLOCKED] =
		"A request has been made before the previous one finished.",
	[MANIFEST_CMD_STATUS_PREPARE] = "The manifest is being prepared for updating.",
	[MANIFEST_CMD_STATUS_PREPARE_FAIL] =
		"There was an error preparing the manifest for updating, code 0x%x",
	[MANIFEST_CMD_STATUS_STORE_DATA] = "New manifest data is being stored.",
	[MANIFEST_CMD_STATUS_STORE_FAIL] = "There was an error storing manifest data, code 0x%x",
	[MANIFEST_CMD_STATUS_VALIDATION] = "The new manifest is being validated.",
	[MANIFEST_CMD_STATUS_VALIDATE_FAIL] =
		"There was an error validating the new manifest, code 0x%x",
	[MANIFEST_CMD_STATUS_INTERNAL_ERROR] = "An unspecified internal error occurred, code 0x%x",
	[MANIFEST_CMD_STATUS_NONE_STARTED] = "No manifest operation has been started.",
	[MANIFEST_CMD_STATUS_TASK_NOT_RUNNING] =
		"The task servicing manifest operations is not running.",
	[MANIFEST_CMD_STATUS_UNKNOWN] =	"The manifest status could not be determined.",
	[MANIFEST_CMD_STATUS_ACTIVATING] = "Activation is being attempted for a new manifest.",
	[MANIFEST_CMD_STATUS_ACTIVATION_FAIL] =
		"There was an error activating the new manifest, code 0x%x",
	[MANIFEST_CMD_STATUS_ACTIVATION_PENDING] =
		"Validation was successful, but activation requires a host reboot.",
	[MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR] =
		"An error occurred during activation that prevents host access to flash, code 0x%x"
};

/**
 * Strings for the reboot actions.
 */
const char *reboot_actions_str[] = {
	[REBOOT_ACTION_NONE] = "No action is pending on host reset.",
	[REBOOT_ACTION_VERIFY_PFM] = "A pending PFM will be verified.",
	[REBOOT_ACTION_VERIFY_UPDATE] = "A host FW update will be verified.",
	[REBOOT_ACTION_VERIFY_PFM_AND_UPDATE] = "A pending PFM and host FW update will be verified.",
	[REBOOT_ACTION_ACTIVATE_UPDATE] = "A prevalidated host FW update will be made active.",
	[REBOOT_ACTION_ACTIVATE_PFM_AND_UPDATE] =
		"A prevalidated pending PFM and host FW update will both be made active.",
	[REBOOT_ACTION_VERIFY_BYPASS_FLASH] =
		"A pending PFM will be used to verify flash, which currently has no active PFM."
};

/**
 * Strings for the attestation operation statuses.
 */
const char *attestation_cmd_statuses_str[] = {
	[ATTESTATION_CMD_STATUS_SUCCESS] = "Successful operation.",
	[ATTESTATION_CMD_STATUS_RUNNING] = "An attestation operation is in progress.",
	[ATTESTATION_CMD_STATUS_FAILURE] = "Attestation operation failed, code 0x%x",
	[ATTESTATION_CMD_STATUS_REQUEST_BLOCKED] =
		"A request has been made before the previous one finished.",
	[ATTESTATION_CMD_STATUS_NONE_STARTED] = "No attestation operation has been started.",
	[ATTESTATION_CMD_STATUS_TASK_NOT_RUNNING] =
		"The task servicing attestation operations is not running.",
	[ATTESTATION_CMD_STATUS_UNKNOWN] = "The attestation status could not be determined.",
	[ATTESTATION_CMD_STATUS_INTERNAL_ERROR] = "An unspecified, internal error occurred.",
};

/**
 * Strings for the configuration reset update statuses.
 */
const char *config_reset_cmd_statuses_str[] = {
	[CONFIG_RESET_STATUS_SUCCESS] = "Successful operation.",
	[CONFIG_RESET_STATUS_STARTING] = "A configuration reset operation has started.",
	[CONFIG_RESET_STATUS_REQUEST_BLOCKED] =
		"A request has been made before the previous one finished.",
	[CONFIG_RESET_STATUS_RESTORE_BYPASS] = "Configuration is being reset to restore bypass mode.",
	[CONFIG_RESET_STATUS_BYPASS_FAILED] = "Failed to restore bypass mode, code 0x%x",
	[CONFIG_RESET_STATUS_RESTORE_DEFAULTS] = "All configuration and state are being erased.",
	[CONFIG_RESET_STATUS_DEFAULTS_FAILED] = "Failed to restore default configuration, code 0x%x",
	[CONFIG_RESET_STATUS_NONE_STARTED] = "No configuration reset operation has been started.",
	[CONFIG_RESET_STATUS_TASK_NOT_RUNNING] = "The task servicing reset operations is not running.",
	[CONFIG_RESET_STATUS_INTERNAL_ERROR] = "An unspecified, internal error occurred, code 0x%x",
	[CONFIG_RESET_STATUS_UNKNOWN] = "The configuration reset status could not be determined.",
	[CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG] = "Platform configuration is being cleared.",
	[CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED] = "Failed to clear platform configuration.",
	[CONFIG_RESET_STATUS_RESET_INTRUSION] = "Intrusion state is being reset.",
	[CONFIG_RESET_STATUS_INTRUSION_FAILED] = "Failed to reset intrusion state, code 0x%x",
	[CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS] = "Component manifests are being cleared.",
	[CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED] = "Failed to clear component manifests.",
};

/**
 * Strings for the signed certificate states.
 */
const char *riot_cert_state_str[] = {
	[RIOT_CERT_STATE_CHAIN_VALID] = "Device contains a signed certificate chain.",
	[RIOT_CERT_STATE_CHAIN_INVALID] =
		"Device certificate chain is incomplete or invalid, code 0x%x.",
	[RIOT_CERT_STATE_VALIDATING] = "Validating the device certificate chain.",
};

/**
 * Strings for the host state.
 */
const char *host_processor_state_str[] = {
	[HOST_PROCESSOR_OUT_OF_RESET] = "The host processor is running.",
	[HOST_PROCESSOR_HELD_IN_RESET] = "The host is being held in reset by Cerberus.",
	[HOST_PROCESSOR_NOT_HELD_IN_RESET] =
		"The host is not being held in reset, but is not yet running."
};

/**
 * Strings for the different logging severities.
 */
const char *logging_severities[] = {
	[LOGGING_SEVERITY_ERROR] = "Error",
	[LOGGING_SEVERITY_WARNING] = "Warning",
	[LOGGING_SEVERITY_INFO] = "Info"
};

extern const char* cerberus_protocol_error_messages_str[];


#pragma pack(push, 1)
/**
 * Details for a single component type supported by a PCD.
 */
struct cerberus_pcd_supported_components {
	uint32_t component_id;									/**< Component ID. */
	uint8_t component_count;								/**< Component Count. */
};
#pragma pack(pop)

/**
 * Retrieve Cerberus utility version
 *
 * @return pointer to the NULL terminated version string.
 */
LIB_EXPORT const char* cerberus_get_utility_version ()
{
	return UTILITY_VERSION_STRING;
}

/**
 * Function to release dynamically allocated buffer
*/
LIB_EXPORT void cerberus_free (void *buffer)
{
	if (buffer != NULL) {
		free (buffer);
	}
}

/**
 * Establish an unencrypted connection to a remote device.  This must be called before making any
 * other calls to send commands to a device.
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if the remote device is available for communication or an error code.
 */
LIB_EXPORT int cerberus_remote_device_connect (struct cerberus_interface *intf)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_find_protocol_version (intf);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->protocol_version >= 3) {
		status = cerberus_get_device_capabilities (intf, &intf->remote);
		if (status != STATUS_SUCCESS) {
			return status;
		}
	}
	else {
		intf->remote.max_message_timeout = intf->local.max_message_timeout;
		intf->remote.max_crypto_timeout = intf->local.max_crypto_timeout;
		intf->remote.max_message_body = intf->local.max_message_body;
		intf->remote.max_packet_payload = intf->local.max_packet_payload;
	}

	mctp_interface_set_parameters (intf);
	return STATUS_SUCCESS;
}

/**
 * Command to indicate if a platform is expected to have Cerberus.
 *
 * @param intf The Cerberus interface to utilize.
 *
 * @return STATUS_SUCCESS if device is detected, STATUS_NO_DEVICE if device is not detected, or an
 *  error code.
 */
LIB_EXPORT int cerberus_detect_device (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	return intf->detect_device (intf);
}

/**
 * Get Cerberus protocol version from device.
 * Make a protocol version request.  If the request does not succeed,
 * make a FW version request instead, to figure out protocol version.
 * In case it fails as well, repeat the above process multiple times.
 *
 * @param intf The Cerberus interface to utilize.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_find_protocol_version (struct cerberus_interface *intf)
{
	uint8_t payload[MCTP_PROTOCOL_MIN_SUPPORTED_PAYLOAD];
	unsigned long start_time;
	uint16_t pci_vid;
	uint8_t i_vid = 0;
	size_t payload_len;
	int backup_retry_times;
	uint16_t version = CERBERUS_LAST_UNSUPPORTED_VERSION;
	int status = STATUS_SUCCESS;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	backup_retry_times = intf->params->num_mctp_retries;
	start_time = cerberus_common_get_cpu_time_ms ();

	// Set MCTP retry setup times to MAX.
	intf->params->num_mctp_retries = MAX (MCTP_PROTOCOL_CMD_DEFAULT_RETRY_TIMES,
		backup_retry_times);
	while (1) {
		payload[0] = i_vid;

		// Make protocol version # request and get response.
		payload_len = 1;
		status = mctp_protocol_send_ctrl_msg_get_rsp (intf, MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT,
			intf->params->device_eid, 0, false, false, 7, payload, &payload_len);

		/* At this point, if we still see STATUS_MCTP_TIMEOUT or STATUS_COMMUNICATION_FAILURE
		 * error, it could be caused by the wrong protocol version #. When the protocol
		 * is old version, such as 0, or 1, we won't get any proper response from
		 * MCTP. Let's try to set protocol version # 1 or 0, and then make FW version
		 * request instead. If the request can get succeeded, the protocol version #
		 * we set is correct. */
		if ((status == STATUS_MCTP_TIMEOUT) || (status == STATUS_COMMUNICATION_FAILURE)) {
			intf->params->utility_eid = MCTP_PROTOCOL_BMC_EID;
			while (1) {
				intf->protocol_version = version;
				status = cerberus_get_fwversion (intf, 0, NULL, 0);

				/* The FW version request returns success. It means the protocol version number
				 * currently set is correct. */
				if (status == STATUS_SUCCESS) {
					cerberus_print_info ("Switching to Cerberus protocol v%d.\n\n",
						intf->protocol_version);
					goto done;
				}

				// We already try all protocol version # we should try.
				if (version == 0) {
					break;
				}

				// We'll continue to look at the next one.
				version--;
			}
		}

		if (status != STATUS_SUCCESS) {
			goto done;
		}

		if (payload[0] != MCTP_PROTOCOL_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), MCTP_PROTOCOL_SUCCESS,
				payload[0]);
			status = STATUS_CMD_RESPONSE;
			goto done;
		}

		if (payload[2] == MCTP_PROTOCOL_VID_FORMAT_PCI) {
			pci_vid = SWAP_BYTES_UINT16 (*((uint16_t*) &payload[3]));

			if (pci_vid == CERBERUS_PROTOCOL_MSFT_PCI_VID) {
				break;
			}
		}

		if (payload[1] == 0xFF) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MSFT_VID_SET_UNSUPPORTED));
			status = STATUS_MSFT_VID_SET_UNSUPPORTED;
			goto done;
		}

		if (payload[1] != (i_vid + 1)) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), i_vid + 1, payload[1]);
			status = STATUS_CMD_RESPONSE;
			goto done;
		}

		i_vid = payload[1];

		if (cerberus_common_timeout_expired (start_time, 10 * 1000)) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
			status = STATUS_OPERATION_TIMEOUT;
			goto done;
		}
	}

	intf->protocol_version = SWAP_BYTES_UINT16 (*((uint16_t*) &payload[3 + sizeof (uint16_t)]));

	if (intf->protocol_version < 4) {
		intf->params->utility_eid = MCTP_PROTOCOL_BMC_EID;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Using Cerberus protocol v%d.\n\n", intf->protocol_version);
	}

done:
	// Resume MCTP retry setup times.
	intf->params->num_mctp_retries = backup_retry_times;
	return status;
}

/**
 * Discover the transmission capabilities of a remote device.
 *
 * @param intf The cerberus interface to utilize.
 * @param capabilities Output for the device's capabilities.
 *
 * @return STATUS_SUCCESS if the capabilities were retrieved successfully or an error code.
 */
LIB_EXPORT int cerberus_get_device_capabilities (struct cerberus_interface *intf,
	struct cerberus_device_caps *capabilities)
{
	struct cerberus_protocol_device_capabilities *request =
		(struct cerberus_protocol_device_capabilities*) intf->cmd_buf;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (capabilities == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	request->max_message = intf->local.max_message_body;
	request->max_packet = intf->local.max_packet_payload;
	request->features = 0;
	request->device_info = intf->local.device_info;
	request->pk_key_strength = intf->local.pk_key_strength;
	request->enc_key_strength = intf->local.enc_key_strength;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, intf->params->device_eid, sizeof (*request),
		false, intf->cmd_buf, sizeof (*request) - 2);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	capabilities->max_message_body = request->max_message;
	capabilities->max_packet_payload = request->max_packet;
	capabilities->max_message_timeout = request->message_timeout * 10;
	capabilities->max_crypto_timeout = request->crypto_timeout * 100;
	capabilities->device_info = request->device_info;
	capabilities->pk_key_strength = request->pk_key_strength;
	capabilities->enc_key_strength = request->enc_key_strength;

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Remote Capabilities:\n");
		cerberus_print_info ("\tMax message: %d\n", request->max_message);
		cerberus_print_info ("\tMax packet: %d\n", request->max_packet);
		cerberus_print_info ("\tDevice: 0x%x\n", request->device_info);
		cerberus_print_info ("\tFeatures: 0x%x\n", request->features);
		cerberus_print_info ("\tPK strength: 0x%x\n", request->pk_key_strength);
		cerberus_print_info ("\tEncrypt strength: 0x%x\n", request->enc_key_strength);
		cerberus_print_info ("\tMessage timeout: %d\n", request->message_timeout);
		cerberus_print_info ("\tCrypto timeout: %d\n", request->crypto_timeout);
		cerberus_print_info ("\n");
	}

	return STATUS_SUCCESS;
}

/**
 * Read data from a file.
 *
 * @param intf The cerberus inteface to utilize
 * @param name Path to the file.
 * @param buffer Output for the file data.  This will by dynamically allocated and must be freed.
 * @param length Output for the length of the data.
 *
 * @return STATUS_SUCCESS if the file was read successfully or an error code.
 */
LIB_EXPORT int cerberus_read_file (struct cerberus_interface *intf, const char *name,
	uint8_t **buffer, size_t *length)
{
	FILE *file = NULL;
	size_t bytes;
	int status;

	file = fopen (name, "rb");

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (buffer == NULL) || (length == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT), name);
		return STATUS_INVALID_INPUT;
	}

	if (file == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_UPDATE_FILE), name);
		return STATUS_INVALID_UPDATE_FILE;
	}

	if (fseek (file, 0L, SEEK_END) == STATUS_SUCCESS) {
		if ((int) (bytes = ftell (file)) == -1) {
			status = STATUS_OPEN_FILE_FAILED;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (status), name);
			goto end_clean;
		}
	}
	else {
		status = STATUS_INVALID_UPDATE_FILE;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), name);
		goto end_clean;
	}

	*buffer = malloc (bytes + 1);

	if (*buffer == NULL) {
		status = STATUS_NO_MEM;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
		goto end_clean;
	}

	if (fseek (file, 0L, SEEK_SET) == -1) {
		status = STATUS_INVALID_UPDATE_FILE;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), name);
		goto end_clean;
	}

	fread (*buffer, 1, bytes, file);
	if (ferror (file) != 0) {
		status = STATUS_READ_FILE_FAILED;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), name);
		goto end_clean;
	}

	*length = bytes;
	status = STATUS_SUCCESS;

end_clean:
	fclose (file);

	if (status != STATUS_SUCCESS) {
		free (*buffer);
		*buffer = NULL;
	}

	return status;
}

/**
 * Write data to a file.
 *
 * @param intf The cerberus interface to utilize
 * @param filename Path to the file.
 * @param buffer Input buffer containing data to write to the file.
 * @param length The length of the data to write.
 *
 * @return STATUS_SUCCESS if the data was written successfully to the file or an error code.
 */
LIB_EXPORT int cerberus_write_file (struct cerberus_interface *intf, const char *filename,
	const uint8_t *buffer, size_t length)
{
	FILE *file = NULL;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL) || (buffer == NULL) || (length == 0)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	file = fopen (filename, "wb");
	if (file == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_OPEN_FILE_FAILED), filename);
		return STATUS_OPEN_FILE_FAILED;
	}

	fwrite (buffer, sizeof (uint8_t), length, file);
	if (ferror (file) != 0) {
		status = STATUS_WRITE_FILE_FAILED;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), filename);
		goto end_clean;
	}

	status = STATUS_SUCCESS;

end_clean:
	fclose (file);
	return status;
}

/**
 * Retrieve Cerberus FW version
 *
 * @param intf The Cerberus interface to utilize
 * @param area The firmware area index
 * @param buffer Ouput buffer to be filled with a NULL terminated fw version string
 * @param buf_len length of the output buffer
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_fwversion (struct cerberus_interface *intf, uint8_t area,
	uint8_t *buffer, size_t buf_len)
{
	size_t version_len;
	size_t i;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = area;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_FW_VERSION, intf->params->device_eid, CERBERUS_VERSION_MAX_LEN, false,
		intf->cmd_buf, 1);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	version_len = strnlen ((const char*) intf->cmd_buf, CERBERUS_VERSION_MAX_LEN);
	if (version_len == CERBERUS_VERSION_MAX_LEN) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_STRING_NOT_TERMINATED));
		return STATUS_STRING_NOT_TERMINATED;
	}

	for (i = 0; i < version_len; ++i) {
		if (!isprint (intf->cmd_buf[i])) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_NOT_STRING), intf->cmd_buf[i]);
			return STATUS_NOT_STRING;
		}
	}

	if (buffer != NULL) {
		if (buf_len <= version_len) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
			return STATUS_BUF_TOO_SMALL;
		}

		memcpy (buffer, intf->cmd_buf, (version_len + 1));
	}

	return STATUS_SUCCESS;
}

/**
 * Check whether Cerberus rebooted successfully by reading the FW version after update.
 *
 * @param intf The Cerberus interface to utilize
 * @param update_type NULL terminated string indicating type of update
 *
 * @return STATUS_SUCCESS if Cerberus reboots successfully or an error code.
 */

static int cerberus_check_reboot_status_after_update (struct cerberus_interface *intf,
	const char *update_type)
{
	uint8_t cmd_fwver_retries = CERBERUS_MAX_GET_FW_VERSION_RETRIES;
	uint8_t fw_version[CERBERUS_FW_VERSION_MAX_LEN];
	int status;

	while (cmd_fwver_retries) {
		status = cerberus_get_fwversion (intf, 0, fw_version, sizeof (fw_version));
		if (status == STATUS_SUCCESS) {
			if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
				cerberus_print_info ("\nCerberus rebooted successfully\n");
			}
			snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
	 			"%s update completed successfully\n", update_type);
			return status;
		}
		if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
			cerberus_print_info (".");
		}
		--cmd_fwver_retries;
		cerberus_common_sleep_ms (1000);
	}

	status = STATUS_REBOOT_AFTER_UPDATE_FAILURE;
	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		cerberus_utility_get_errors_str (status), update_type);
	return status;
}

/**
 * Wait for the cerberus to reboot after firmware/PCD update
 *
 * @param intf The Cerberus interface to utilize
 * @param update_type Type of update.  This can be Firmware or PCD
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_wait_for_reboot_to_complete_after_update (struct cerberus_interface *intf,
	const char *update_type)
{
	if (update_type == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("\nWaiting for Cerberus to reboot");
	}

	cerberus_common_sleep_ms (CERBERUS_CMD_WAIT_TIME_AFTER_FWUPDATE_MS);
	return cerberus_check_reboot_status_after_update (intf, update_type);
}

/**
 * Retrieve extended Cerberus FW update status
 *
 * @param intf The Cerberus interface to utilize
 * @param update Output struct to be populated with the update information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_get_ext_fw_update_status (struct cerberus_interface *intf,
	struct cerberus_fw_update_status *update)
{
	uint32_t update_status;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (update == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = CERBERUS_FW_UPDATE_STATUS;

	status = cerberus_protocol_send_and_read_rsp (intf,  __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS, intf->params->device_eid, 2 * sizeof (uint32_t),
		false, intf->cmd_buf, 2);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (&update_status, intf->cmd_buf, sizeof (update_status));
	memcpy (&update->remaining_len, (intf->cmd_buf + sizeof (update->status_code)),
		sizeof (update->remaining_len));

	update->status_code_module = update_status >> 8;
	update->status_code = update_status & 0xFF;
	if (update->status_code < NUM_UPDATE_STATUS) {
		snprintf (update->status_str, sizeof (update->status_str),
			update_statuses_str[update->status_code], update->status_code_module);
	}
	else {
		snprintf (update->status_str, sizeof (update->status_str), "Cerberus Update Status: 0x%x",
			update_status);
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("FW Update Status: %i\n", update_status);
		cerberus_print_info ("FW Remaining Length: %i\n", update->remaining_len);
	}

	return STATUS_SUCCESS;
}

/**
 * Initiate a FW update on Cerberus
 *
 * @param intf The Cerberus interface to utilize
 * @param size Size of FW update file that will be sent out to Cerberus
 * @param update_status Output struct to be populated with status info.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_fwupdate_init (struct cerberus_interface *intf, uint32_t size,
	struct cerberus_fw_update_status *update_status)
{
	unsigned long start_time;
	int status;

	if (update_status == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_INIT_FW_UPDATE, intf->params->device_eid, false, (uint8_t*) &size,
		sizeof (size));
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	while (1) {
		status = cerberus_get_ext_fw_update_status (intf, update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (update_status->status_code) {
			case UPDATE_STATUS_SUCCESS:
				return STATUS_SUCCESS;

			case UPDATE_STATUS_STARTING:
			case UPDATE_STATUS_STAGING_PREP:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Firmware update failed: 0x%x", update_status->status_code);
				return STATUS_UPDATE_FAILURE;
		}
	}
}

/**
 * Complete Cerberus FW update
 *
 * @param intf The Cerberus interface to utilize
 * @param update_status Output struct to be populated with status info.
 * @param cmd_timeout_val_s Timeout value in seconds for the command completion.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_fwupdate_complete (struct cerberus_interface *intf,
	struct cerberus_fw_update_status *update_status, uint32_t cmd_timeout_val_s)
{
	uint8_t msg_retries;
	unsigned long start_time;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (update_status == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE, intf->params->device_eid, false, NULL, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	cerberus_print_info ("\nDone sending update image, verifying and completing update\n");

	start_time = cerberus_common_get_cpu_time_ms ();

	while (1) {
		for (msg_retries = 0; msg_retries < CERBERUS_MAX_SEND_RETRIES; ++msg_retries) {
			status = cerberus_get_ext_fw_update_status (intf, update_status);
			if (status == STATUS_SUCCESS) {
				break;
			}

			cerberus_print_info ("Retrying....\n");
		}

		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (update_status->status_code) {
			case UPDATE_STATUS_SUCCESS:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Firmware update completed successfully\n");
				return STATUS_SUCCESS;

			case UPDATE_STATUS_STARTING:
			case UPDATE_STATUS_VERIFYING_IMAGE:
			case UPDATE_STATUS_BACKUP_ACTIVE:
			case UPDATE_STATUS_SAVING_STATE:
			case UPDATE_STATUS_UPDATING_IMAGE:
			case UPDATE_STATUS_CHECK_REVOCATION:
			case UPDATE_STATUS_CHECK_RECOVERY:
			case UPDATE_STATUS_BACKUP_RECOVERY:
			case UPDATE_STATUS_UPDATE_RECOVERY:
			case UPDATE_STATUS_REVOKE_CERT:
				if (cerberus_common_timeout_expired (start_time, cmd_timeout_val_s * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Firmware update failed: %s", update_status->status_str);
				return STATUS_UPDATE_FAILURE;
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Send Cerberus a FW update file
 *
 * @param intf The Cerberus interface to utilize
 * @param name The update filename
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_fwupdate (struct cerberus_interface *intf, const char *name)
{
	struct cerberus_fw_update_status update_status;
	unsigned long start_time;
	size_t update_size;
	size_t max_per_msg;
	size_t index = 0;
	uint32_t length = 0;
	uint8_t *buffer = NULL;
	uint8_t update_retries = 0;
	uint8_t msg_retries;
	uint32_t cmd_timeout_val_s;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (name == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_read_file (intf, name, &buffer, &update_size);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (update_size == 0) {
		status = STATUS_INVALID_UPDATE_FILE;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), name);
		goto end_clean;
	}

	/* command timeout is calculated dynamically based on the size of the image. */
	cmd_timeout_val_s = (uint32_t) CERBERUS_UPDATE_CMD_TIMEOUT_VAL_S (update_size);
	if (cmd_timeout_val_s < CERBERUS_CMD_TIMEOUT_VAL_S) {
		cmd_timeout_val_s = CERBERUS_CMD_TIMEOUT_VAL_S;
	}

	update_status.remaining_len = (uint32_t) update_size;
	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);

	while (update_status.remaining_len != 0) {
		index = 0;

		status = cerberus_fwupdate_init (intf, (uint32_t) update_size, &update_status);
		if (status != STATUS_SUCCESS) {
			goto end_clean;
		}

		cerberus_print_info ("Done update preparation, sending update bytes\n");

		while (update_size > 0) {
			length = (uint32_t) MIN (max_per_msg, update_size);

			memcpy (intf->cmd_buf, &buffer[index], length);

			for (msg_retries = 0; msg_retries < CERBERUS_MAX_SEND_RETRIES; ++msg_retries) {
				status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
					CERBERUS_PROTOCOL_FW_UPDATE, intf->params->device_eid, false, intf->cmd_buf,
					length);
				if (status == STATUS_SUCCESS) {
					break;
				}

				cerberus_print_info ("Retrying....\n");
			}

			if (status != STATUS_SUCCESS) {
				goto end_clean;
			}

			update_status.status_code = UPDATE_STATUS_UNKNOWN;
			start_time = cerberus_common_get_cpu_time_ms ();

			while (update_status.status_code != UPDATE_STATUS_SUCCESS) {
				status = cerberus_get_ext_fw_update_status (intf, &update_status);
				if (status != STATUS_SUCCESS) {
					cerberus_print_info ("\n");
					goto end_clean;
				}

				switch (update_status.status_code) {
					case UPDATE_STATUS_SUCCESS:
					case UPDATE_STATUS_STARTING:
					case UPDATE_STATUS_STAGING_WRITE:
						if (cerberus_common_timeout_expired (start_time,
							CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
							cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
								__func__, __LINE__,
								cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
							status = STATUS_OPERATION_TIMEOUT;
							goto end_clean;
						}

						cerberus_print_info (".");
						fflush (stdout);
						cerberus_common_sleep_ms (50);
						continue;

					default:
						snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
							"Firmware update failed: %s", update_status.status_str);
						status = STATUS_UPDATE_FAILURE;
						goto end_clean;
				}
			}

			if (update_status.remaining_len == (update_size - length)) {
				index += length;
				update_size -= length;
			}
			else if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
				cerberus_print_info ("\nWrite operation failed, retrying: %i vs %i\n",
					update_status.remaining_len, (update_size - length));
			}

			if ((int32_t) update_status.remaining_len < 0) {
				cerberus_print_info  (
					"\nFirmware update failed: Utility and device out of sync while transferring update file\n");
				++update_retries;

				if (update_retries > CERBERUS_MAX_UPDATE_RETRIES) {
					status = STATUS_UPDATE_FAILURE;
					goto end_clean;
				}
			}
		}
	}

end_clean:
	if (buffer) {
		free (buffer);
	}

	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_fwupdate_complete (intf, &update_status, cmd_timeout_val_s);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	return cerberus_wait_for_reboot_to_complete_after_update (intf, "Firmware");
}

/**
 * Retrieve Cerberus PFM actions that can be taken on reset of the host processor.
 *
 * @param intf The Cerberus interface to utilize
 * @param pfm_port The port number to query
 * @param reboot_action Output pointer to hold Reboot action value
 * @param action_str Output buffer that will be filled with reboot action string.  Buffer is
 *  dynamically allocated MUST BE FREED BY CALLER using cerberus_free()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pfm_reboot_action (struct cerberus_interface *intf,
	uint8_t pfm_port, uint32_t *reboot_action, char **action_str)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (reboot_action == NULL) || (action_str == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*action_str = malloc (CERBERUS_MAX_MSG_LEN);
	if (*action_str == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	intf->cmd_buf[0] = CERBERUS_HOST_FW_NEXT_RESET;
	intf->cmd_buf[1] = pfm_port;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_UPDATE_STATUS, intf->params->device_eid, sizeof (uint32_t), false,
		intf->cmd_buf, 2 * sizeof (uint8_t));
	if (status != STATUS_SUCCESS) {
		cerberus_free (*action_str);
		return status;
	}

	memcpy (reboot_action, intf->cmd_buf, sizeof (uint32_t));

	if ((*reboot_action) < NUM_REBOOT_ACTION) {
		snprintf (*action_str, CERBERUS_MAX_MSG_LEN, "%s", reboot_actions_str[*reboot_action]);
	}
	else {
		snprintf (*action_str, CERBERUS_MAX_MSG_LEN, "0x%x", *reboot_action);
	}

	return STATUS_SUCCESS;
}

/**
 * Start a Cerberus PFM update
 *
 * @param intf The Cerberus interface to utilize
 * @param pfm_port The port number requiring PFM update
 * @param size Size of PFM file
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_pfmupdate_init (struct cerberus_interface *intf, uint8_t pfm_port,
	uint32_t size)
{
	struct cerberus_manifest_request manifest = {pfm_port, CERBERUS_MANIFEST_PFM};
	struct cerberus_fw_update_status update_status;
	unsigned long start_time;
	int status;

	intf->cmd_buf[0] = pfm_port;
	memcpy (&intf->cmd_buf[1], &size, sizeof (uint32_t));

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_INIT_PFM_UPDATE, intf->params->device_eid, false, intf->cmd_buf, 5);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	while (1) {
		status = cerberus_get_manifest_update_status (intf, &manifest, &update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (update_status.status_code) {
			case MANIFEST_CMD_STATUS_STARTING:
			case MANIFEST_CMD_STATUS_PREPARE:
			case MANIFEST_CMD_STATUS_NONE_STARTED:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				cerberus_print_info ("Done PFM update preparation.\n");

				if (update_status.status_code == MANIFEST_CMD_STATUS_SUCCESS) {
					return STATUS_SUCCESS;
				}
				else {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"PFM Update Status: %s", update_status.status_str);
					return STATUS_UPDATE_FAILURE;
				}
		}
	}
}

/**
 * Activate PFM
 *
 * @param intf The Cerberus interface to utilize.
 * @param port Host port number to activate PFM.
 * @param activate_setting Set activate_setting 0 to activate PFM after host reboot,
 *  1 to activate immediately.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_pfm_activate (struct cerberus_interface *intf, uint8_t port,
	uint8_t activate_setting)
{
	int status;
	int recovery_status;
	struct cerberus_pfm_activate pfm;
	struct cerberus_fw_update_status update_status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (activate_setting > 1)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params->multi_master) && (intf->params->device_address == CERBERUS_SLAVE_ADDR)) {
		if (activate_setting && (port == CERBERUS_BIOS_PORT_NUM)) {
			status = intf->set_me_recovery (intf, 1);
			if (status != STATUS_SUCCESS) {
				return status;
			}
		}
	}

	pfm.port = port;
	pfm.activate_setting = activate_setting;
	status = cerberus_validate_host_update (intf, &pfm, false, &update_status);

	if ((intf->params->multi_master) && (intf->params->device_address == CERBERUS_SLAVE_ADDR)) {
		if (activate_setting && (port == CERBERUS_BIOS_PORT_NUM)) {
			recovery_status = intf->set_me_recovery (intf, 0);
			if ((status == STATUS_SUCCESS) && (recovery_status != STATUS_SUCCESS)) {
				status = recovery_status;
			}
		}
	}

	return status;
}

/**
 * Update Cerberus PFM on specified host port.
 *
 * @param intf The Cerberus interface to utilize
 * @param filename Filename containing PFM file to send out
 * @param port Host port number to update PFM
 * @param activate_setting PFM activate setting.  Set activate_setting 0 to activate PFM after host
 *  reboot, 1 to activate immediately
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_pfm_update (struct cerberus_interface *intf, const char *filename,
	uint8_t port, uint8_t activate_setting)
{
	uint8_t *buffer = NULL;
	size_t length = 0;
	size_t index = 0;
	size_t max_per_msg;
	size_t size;
	struct cerberus_fw_update_status update_status;
	struct cerberus_manifest_request manifest;
	unsigned long start_time;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL) || (activate_setting > 1)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_read_file (intf, filename, &buffer, &size);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (size == 0) {
		status = STATUS_INVALID_UPDATE_FILE;
		snprintf (errorstr, sizeof (errorstr), cerberus_utility_get_errors_str (status), filename);
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			errorstr);
		goto end_clean;
	}

	status = cerberus_pfmupdate_init (intf, port, (uint32_t) size);
	if (status != STATUS_SUCCESS) {
		goto end_clean;
	}

	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);
	while (size > 0) {
		length = MIN (max_per_msg - 1, size);

		intf->cmd_buf[0] = port;
		memcpy (&intf->cmd_buf[1], &buffer[index], length);

		status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
			CERBERUS_PROTOCOL_PFM_UPDATE, intf->params->device_eid, false, intf->cmd_buf,
			length + 1);
		if (status != STATUS_SUCCESS) {
			goto end_clean;
		}

		index += length;
		size -= length;
		update_status.status_code = UPDATE_STATUS_UNKNOWN;

		start_time = cerberus_common_get_cpu_time_ms ();

		manifest.manifest_type = CERBERUS_MANIFEST_PFM;
		manifest.port = port;
		while (update_status.status_code != UPDATE_STATUS_SUCCESS) {
			status = cerberus_get_manifest_update_status (intf, &manifest, &update_status);
			if (status != STATUS_SUCCESS) {
				goto end_clean;
			}

			switch(update_status.status_code) {
				case MANIFEST_CMD_STATUS_SUCCESS:
				case MANIFEST_CMD_STATUS_STARTING:
				case MANIFEST_CMD_STATUS_STORE_DATA:
					if (cerberus_common_timeout_expired (start_time,
						CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
						cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
							__func__, __LINE__,
							cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
						status = STATUS_OPERATION_TIMEOUT;
						goto end_clean;
					}

					cerberus_common_sleep_ms (50);
					continue;

				default:
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"PFM update failed: %s", update_status.status_str);
					status = STATUS_UPDATE_FAILURE;
					goto end_clean;
			}
		}
	}

	cerberus_print_info ("Done sending PFM file.\n");

end_clean:
	if (buffer) {
		free (buffer);
	}

	if (status != STATUS_SUCCESS) {
		return status;
	}
	else {
		return cerberus_pfm_activate (intf, port, activate_setting);
	}
}

/**
 * Get ID for PFM in provided port and region
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port number
 * @param pfm_region PFM storage region
 * @param pfm_id Output buffer for PFM ID
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pfm_id (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region, uint32_t *pfm_id)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (pfm_id == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = port;
	intf->cmd_buf[1] = pfm_region;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_PFM_ID, intf->params->device_eid, 1 + sizeof (uint32_t), false,
		intf->cmd_buf, 2);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			"No valid PFM found for port %i, region %i", port, pfm_region);
		return STATUS_INVALID_MANIFEST;
	}

	memcpy (pfm_id, &intf->cmd_buf[1], sizeof (uint32_t));

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("PFM ID: 0x%x\n", *pfm_id);
	}

	return STATUS_SUCCESS;
}

/**
 * Get platform ID for PFM in provided port and region
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port
 * @param pfm_region PFM storage region
 * @param pfm_platform_id Output buffer filled with NULL terminated PFM platform ID.  MUST BE
 *  FREED BY CALLER using cerberus_free()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pfm_platform_id (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region, char **pfm_platform_id)
{
	int status;
	size_t payload_len;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (pfm_platform_id == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = port;
	intf->cmd_buf[1] = pfm_region;
	intf->cmd_buf[2] = 1;

	payload_len = 3;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_PFM_ID, intf->params->device_eid, false, intf->cmd_buf, &payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			"No valid PFM found for port %i, region %i", port, pfm_region);
		return STATUS_INVALID_MANIFEST;
	}

	*pfm_platform_id = strdup ((char*) &intf->cmd_buf[1]);
	if (*pfm_platform_id == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("PFM Platform ID: %s\n", *pfm_platform_id);
	}

	return STATUS_SUCCESS;
}

/**
 * Get FW versions supported by PFM in provided port and region
 *
 * @param intf The Cerberus interface to utilize.
 * @param port PFM port to query supported FW versions.
 * @param pfm_region PFM storage region.
 * @param supported_fw_versions Output buffer that will be filled with the supported FW versions
 *  string.  MUST BE FREED BY CALLER using cerberus_free()
 * @param total_len Output indicating total length of the buffer.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pfm_supported_fw (struct cerberus_interface *intf, uint8_t port,
	uint8_t pfm_region, uint8_t **supported_fw_versions, size_t *total_len)
{
	return cerberus_get_pfm_supported_fw_for_type (intf, port, pfm_region, NULL,
		supported_fw_versions,	total_len);
}

/**
 * Print out FW versions supported by PFM in provided port and region
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port to query supported fw versions
 * @param pfm_region PFM storage region
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_pfm_supported_fw (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region)
{
	return cerberus_print_pfm_supported_fw_for_type (intf, port, pfm_region, NULL);
}

/**
 * Check PFM in provided port and region for FW version support.  If there are multiple firmware
 * components supported by the PFM, this may return a false positive if the version numbers between
 * components are not unique.
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port to query for FW version support
 * @param pfm_region PFM storage region
 * @param fw_version String containing FW version to check
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_check_fw_pfm_support (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region, const char *fw_version)
{
	return cerberus_check_fw_pfm_support_for_type (intf, port, pfm_region, NULL, fw_version);
}

/**
 * Get FW versions supported by PFM in provided port and region.  Optionally, versions for a
 * specific firmware component are retrieved.
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port to query supported fw versions
 * @param pfm_region PFM storage region
 * @param fw_type Optional identifier for the FW component to query.  Set to null to get all
 *  components and versions.
 * @param supported_fw_versions Output buffer to fill up with supported FW versions strings.
 *  Buffer is dynamically allocated MUST BE FREED BY CALLER using cerberus_free()
 * @param total_len Output length indicating total buffer length for supported_fw_versions
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pfm_supported_fw_for_type (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region, const char *fw_type, uint8_t **supported_fw_versions,
	size_t *total_len)
{
	uint32_t initial_pfm_id;
	uint32_t pfm_id;
	uint32_t offset = 0;
	uint32_t version_len;
	uint32_t max_buf_len = CERBERUS_MAX_MANIFEST_LEN;
	uint8_t *realloc_ptr;
	size_t payload_len;
	int status = STATUS_SUCCESS;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (supported_fw_versions == NULL) || (total_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	*supported_fw_versions = (uint8_t*) malloc (CERBERUS_MAX_MANIFEST_LEN);
	if (*supported_fw_versions == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	if (fw_type && (strlen (fw_type) > 255)) {
		status = STATUS_INVALID_INPUT;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		goto exit;
	}

	status = cerberus_get_pfm_id (intf, port, pfm_region, &initial_pfm_id);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

	*total_len = 0;

	while (1) {
		intf->cmd_buf[0] = port;
		intf->cmd_buf[1] = pfm_region;
		memcpy (&intf->cmd_buf[2], &offset, sizeof (offset));

		payload_len = 2 + sizeof (offset);

		if (fw_type) {
			intf->cmd_buf[6] = (uint8_t) strlen (fw_type) + 1;
			strcpy ((char*) &intf->cmd_buf[7], fw_type);

			payload_len += 1 + intf->cmd_buf[6];
		}

		status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
			CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, intf->params->device_eid, false, intf->cmd_buf,
			&payload_len);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		if (payload_len < 1) {
			status = STATUS_UNEXPECTED_RLEN;
			snprintf (errorstr, sizeof (errorstr), cerberus_utility_get_errors_str (status),
				payload_len, 1);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				errorstr);
			goto exit;
		}

		if (intf->cmd_buf[0] == 0) {
			if (offset > 0) {
				break;
			}

			snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
				"No valid PFM found for port %i, region %i", port, pfm_region);
			status = STATUS_INVALID_MANIFEST;
			goto exit;
		}

		memcpy (&pfm_id, &intf->cmd_buf[1], sizeof (pfm_id));

		if (pfm_id != initial_pfm_id) {
			status = STATUS_INVALID_MANIFEST;
			snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
				"PFM changed while retrieving supported versions. Try again.");
			goto exit;
		}

		version_len = (uint32_t) (payload_len - (1 + sizeof (pfm_id)));
		if (version_len == 0) {
			break;
		}

		if ((offset + version_len) > max_buf_len) {
			max_buf_len += CERBERUS_MAX_MANIFEST_LEN;

			realloc_ptr = (uint8_t*) realloc (*supported_fw_versions, max_buf_len);
			if (realloc_ptr == NULL) {
				status = STATUS_NO_MEM;
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (status));
				goto exit;
			}

			*supported_fw_versions = realloc_ptr;
		}

		memcpy ((*supported_fw_versions + offset), &intf->cmd_buf[1 + sizeof (pfm_id)],
			payload_len - (1 + sizeof (pfm_id)));

		offset += version_len;
		*total_len = offset;
	}

exit:
	if (status != STATUS_SUCCESS) {
		cerberus_free (*supported_fw_versions);
	}
	return status;
}

/**
 * Print out FW versions supported by PFM in provided port and region.  Optionally, versions for a
 * specific firmware component are retrieved.
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port to query supported fw versions
 * @param pfm_region PFM storage region
 * @param fw_type Optional identifier for the FW component to query.  Set to null to get all
 *  components and versions.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_pfm_supported_fw_for_type (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region, const char *fw_type)
{
	uint8_t *supported_fw_versions;
	size_t total_len = CERBERUS_MAX_MANIFEST_LEN;
	size_t i_string = 0;
	size_t i_index = 0;
	int status = STATUS_SUCCESS;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_pfm_supported_fw_for_type (intf, port, pfm_region, fw_type,
		&supported_fw_versions,	&total_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	i_index = 0;

	if (!fw_type) {
		cerberus_print_info ("Supported FW Versions:\n");
	}
	else {
		cerberus_print_info ("Supported FW Versions for %s:\n", fw_type);
	}

	while (i_index < total_len) {
		for (; supported_fw_versions[i_index] != '\0'; ++i_index) {}

		cerberus_print_info ("%s\n", &supported_fw_versions[i_string]);

		++i_index;
		i_string = i_index;
	}

	cerberus_free (supported_fw_versions);

	return status;
}

/**
 * Check PFM in provided port and region for FW version support.  If versions for a specific
 * firmware component are not checked, there could be false positives if the different firmware
 * components don't have unique version identfiers.
 *
 * @param intf The Cerberus interface to utilize
 * @param port PFM port to query for FW version support
 * @param pfm_region PFM storage region
 * @param fw_type Optional identifier for the FW component to query.  Set to null to check against
 *  all components and versions.
 * @param fw_version String containing FW version to check
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_check_fw_pfm_support_for_type (struct cerberus_interface *intf,
	uint8_t port, uint8_t pfm_region, const char *fw_type, const char *fw_version)
{
	uint8_t *supported_fw_versions;
	size_t total_len = CERBERUS_MAX_MANIFEST_LEN;
	size_t i_string = 0;
	size_t i_index = 0;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (fw_version == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_pfm_supported_fw_for_type (intf, port, pfm_region,
		fw_type, &supported_fw_versions, &total_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	i_index = 0;

	while (i_index < total_len) {
		for (; supported_fw_versions[i_index] != '\0'; ++i_index) {}

		if (!strcmp (fw_version, (const char*) &supported_fw_versions[i_string])) {
			return STATUS_SUCCESS;
		}

		++i_index;
		i_string = i_index;
	}

	snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
		"%s not supported on PFM port %i, region %i", fw_version, port, pfm_region);

	cerberus_free (supported_fw_versions);

	return STATUS_FW_NOT_SUPPORTED_BY_MANIFEST;
}

/**
 * Check if provided port has an active PFM
 *
 * @param intf The Cerberus interface to utilize
 * @param pfm_port The port number to query
 * @param bypass Output flag indicating if port has an active PFM
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_check_bypass_mode (struct cerberus_interface *intf, uint8_t pfm_port, bool *bypass)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (bypass == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = pfm_port;
	intf->cmd_buf[1] = 0;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_PFM_ID, intf->params->device_eid, 1 + sizeof (uint32_t), false,
		intf->cmd_buf, 2);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	*bypass = (intf->cmd_buf[0] == 0) ? true : false;

	return STATUS_SUCCESS;
}

/**
 * Check the current operational mode of the port.  The port may be in active mode, bypass mode,
 * recovery mode, or an unknown mode.
 *
 * @param intf The Cerberus interface to utilize
 * @param pfm_port The port number to query
 * @param state Output for the port state
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_port_state (struct cerberus_interface *intf, uint8_t pfm_port,
	uint8_t *state)
{
	uint8_t digest[CERBERUS_SHA256_HASH_LEN];
	const uint8_t *exp_digest;
	int status;
	size_t digest_len = 0;
	uint8_t i_state;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (state == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (!intf->platform.port_state.get_digest_len || !intf->platform.port_state.get_digest ||
		!intf->platform.port_state.get_expected_digest) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
		return STATUS_UNSUPPORTED_OPERATION;
	}

	status = intf->platform.port_state.get_digest_len (intf, pfm_port, &digest_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (digest_len != CERBERUS_SHA256_HASH_LEN) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_DIGEST_LEN),
			digest_len);
		return STATUS_UNSUPPORTED_DIGEST_LEN;
	}

	status = intf->platform.port_state.get_digest (intf, pfm_port, digest);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	for (i_state = CERBERUS_PORT_STATE_ACTIVE; i_state <= CERBERUS_PORT_STATE_RECOVERY;
		++i_state) {
		status = intf->platform.port_state.get_expected_digest (intf, pfm_port,
			i_state, &exp_digest);
		if ((status == STATUS_SUCCESS) && (exp_digest != NULL) &&
			(memcmp (digest, exp_digest, digest_len) == 0)) {
			*state = i_state;
			return status;
		}
	}

	*state	= CERBERUS_PORT_STATE_UNKNOWN;

	return status;
}

/**
 * Check the current chassis intrusion state. The chassis may be in an intruded state,
 * non-intruded state, or unknown state.
 *
 * @param intf The Cerberus interface to utilize.
 * @param state Output for the intrusion state.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_intrusion_state (struct cerberus_interface *intf,
	uint8_t *state)
{
	uint8_t digest[CERBERUS_SHA256_HASH_LEN];
	const uint8_t *exp_digest;
	int status;
	size_t digest_len = 0;
	uint8_t i_state;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (state == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (!intf->platform.intrusion_state.get_digest_len ||
		!intf->platform.intrusion_state.get_digest ||
		!intf->platform.intrusion_state.get_expected_digest) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
		return STATUS_UNSUPPORTED_OPERATION;
	}

	status = intf->platform.intrusion_state.get_digest_len (intf, &digest_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (digest_len != CERBERUS_SHA256_HASH_LEN) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_DIGEST_LEN),
			digest_len);
		return STATUS_UNSUPPORTED_DIGEST_LEN;
	}

	status = intf->platform.intrusion_state.get_digest (intf, digest);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	for (i_state = CERBERUS_INTRUSION_STATE_INTRUDED;
		i_state <= CERBERUS_INTRUSION_STATE_NOT_INTRUDED; ++i_state) {
		status = intf->platform.intrusion_state.get_expected_digest (intf, i_state,
			&exp_digest);
		if ((status == STATUS_SUCCESS) && (exp_digest != NULL) &&
			(memcmp (digest, exp_digest, digest_len) == 0)) {
			*state = i_state;
			return status;
		}
	}

	*state	= CERBERUS_INTRUSION_STATE_UNKNOWN;

	return status;
}

/**
 * Function to release dynamically allocated container holding component names
 */
LIB_EXPORT void cerberus_free_comp_list (struct cerberus_components *components)
{
	size_t i_entry;

	if (components != NULL) {
		for (i_entry = 0; i_entry < components->num_components; ++i_entry) {
			free (components->component_str[i_entry]);
		}

		free (components->component_str);
	}
}

/**
 * Find component name in componenent map.
 *
 * @param component_id Component ID.
 * @param component_index Output of component Index.
 *
 * @return true on success, else returns false.
 */
static bool find_component_in_component_map (uint32_t component_id, size_t *component_index)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE (component_map); i++) {
		if (component_id == component_map[i].component_id) {
			*component_index = i;
			return true;
		}
	}

	return false;
}

/**
 * Generate strings array with names of components supported by manifest.
 *
 * @param intf The Cerberus interface to utilize.
 * @param is_cfm The flag to identify CFM or PCD.
 * @param supported_component_ids Buffer with supported component ids.
 * @param components Output container that will be filled with the supported component names.
 * 	Container is dynamically allocated MUST BE FREED BY CALLER using cerberus_free_comp_list().
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_get_supported_components_strings (struct cerberus_interface *intf,
	bool is_cfm, uint8_t *supported_component_ids, struct cerberus_components *components)
{
	char comp_str[32];
	size_t i_index;
	size_t j_index;
	size_t k_index = 0;
	size_t i_component;
	size_t num_total_components = 0;
	struct cerberus_pcd_supported_components *supported_component =
		(struct cerberus_pcd_supported_components*) supported_component_ids;
	bool component_found;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (components == NULL) || (supported_component_ids == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (is_cfm == true) {
		num_total_components = components->num_components;
	}
	else {
		for (i_index = 0; i_index < components->num_components; ++i_index) {
			num_total_components += supported_component[i_index].component_count;
		}
	}

	components->component_str = (char**) malloc (sizeof (char*) * num_total_components);
	if (components->component_str == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	// Map component IDs to name using the component_map if component_id is found
	for (i_index = 0; i_index < components->num_components; ++i_index) {
		if (is_cfm == true) {
			component_found = find_component_in_component_map (((uint32_t*) (supported_component_ids))[i_index],
				&i_component);

			if (component_found == true)
			{
				snprintf (comp_str, sizeof (comp_str),
					"%s", component_map[i_component].component_str);
			}
			else {
				snprintf (comp_str, sizeof (comp_str),
					"Component %i", ((uint32_t*) (supported_component_ids))[i_index]);
			}

			components->component_str[i_index] = strdup (comp_str);
			if (components->component_str[i_index] == NULL) {
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
					cerberus_utility_get_errors_str (STATUS_NO_MEM));
				cerberus_free_comp_list (components);
				return STATUS_NO_MEM;
			}
		}
		else {
			component_found = find_component_in_component_map (supported_component[i_index].component_id,
					&i_component);

			for (j_index = 0; j_index < supported_component[i_index].component_count; ++j_index) {
				if (component_found == true) {
					snprintf (comp_str, sizeof (comp_str),
						"%s-%zu", component_map[i_component].component_str, j_index);
				}
				else {
					snprintf (comp_str, sizeof (comp_str),
						"Component %i-%zu", supported_component[i_index].component_id, j_index);
				}

				components->component_str[k_index] = strdup (comp_str);
				if (components->component_str[k_index] == NULL) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
						cerberus_utility_get_errors_str (STATUS_NO_MEM));
					cerberus_free_comp_list (components);
					return STATUS_NO_MEM;
				}
				k_index++;
			}
		}
	}

	components->num_components = num_total_components;

	return STATUS_SUCCESS;
}

/**
 * Get components supported by manifest.
 *
 * @param intf The Cerberus interface to utilize.
 * @param is_cfm The flag to identify CFM or PCD.
 * @param cfm_region The region to query.
 * @param components Output container that will be filled with the supported component names.
 * 	Container is dynamically allocated MUST BE FREED BY CALLER using cerberus_free_comp_list().
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_get_supported_components (struct cerberus_interface *intf,
	bool is_cfm, uint8_t cfm_region, struct cerberus_components *components)
{
	uint32_t offset = 0;
	uint32_t initial_manifest_id;
	uint32_t manifest_id;
	uint32_t max_buf_len = CERBERUS_MAX_MANIFEST_LEN;
	uint32_t manifest_id_len;
	size_t i_index = 0;
	size_t payload_len;
	size_t max_per_msg;
	int status = STATUS_SUCCESS;
	uint8_t *supported_component_ids;
	uint8_t *realloc_ptr;
	struct cerberus_pcd_supported_components *supported_components;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (components == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	supported_component_ids = (uint8_t*) malloc (CERBERUS_MAX_MANIFEST_LEN);
	if (supported_component_ids == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	if (is_cfm == true) {
		status = cerberus_get_cfm_id (intf, cfm_region, &initial_manifest_id);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}
	}
	else {
		status = cerberus_get_pcd_id (intf, &initial_manifest_id);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}
	}

	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);

	while (1) {
		if (is_cfm == true) {
			intf->cmd_buf[0] = cfm_region;
			memcpy (&intf->cmd_buf[1], &offset, sizeof (offset));
			payload_len = 1 + sizeof (offset);
		}
		else {
			memcpy (&intf->cmd_buf[0], &offset, sizeof (offset));
			payload_len = sizeof (offset);
		}

		status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
			(is_cfm == true) ? CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS :
				CERBERUS_PROTOCOL_GET_PCD_SUPPORTED_COMPONENT_IDS,
			intf->params->device_eid, false, intf->cmd_buf, &payload_len);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		if (payload_len < 1) {
			status = STATUS_UNEXPECTED_RLEN;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status), payload_len, 1);
			goto exit;
		}

		if (intf->cmd_buf[0] == 0) {
			if (is_cfm == true) {
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"No valid CFM found for region %i", cfm_region);
			}
			else {
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"No valid PCD found");
			}
			status = STATUS_INVALID_MANIFEST;
			goto exit;
		}

		memcpy (&manifest_id, &intf->cmd_buf[1], sizeof (manifest_id));

		if (manifest_id != initial_manifest_id) {
			status = STATUS_INVALID_MANIFEST;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				"%s changed while retrieving supported versions. Try again.\n",
				(is_cfm == true) ? "CFM" : "PCD");
			goto exit;
		}

		manifest_id_len = (uint32_t) (payload_len - (1 + sizeof (manifest_id)));

		if ((offset + manifest_id_len) > max_buf_len) {
			max_buf_len += CERBERUS_MAX_MANIFEST_LEN;

			realloc_ptr = (uint8_t*) realloc (supported_component_ids, max_buf_len);
			if (realloc_ptr == NULL) {
				status = STATUS_NO_MEM;
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (status));
				goto exit;
			}

			supported_component_ids = realloc_ptr;
		}

		memcpy (supported_component_ids + offset, &intf->cmd_buf[1 + sizeof (manifest_id)],
			(payload_len - (1 + sizeof (manifest_id))));

		offset += manifest_id_len;

		if (payload_len != max_per_msg) {
			break;
		}
	}

	if (is_cfm == true) {
		components->num_components = offset / sizeof (uint32_t);
	}
	else {
		components->num_components = offset / sizeof (struct cerberus_pcd_supported_components);
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Supported component IDs:\n");

		if (is_cfm == true) {
			for (i_index = 0; i_index < components->num_components; ++i_index) {
				cerberus_print_info ("%i\n", ((uint32_t*) (supported_component_ids))[i_index]);
			}
		}
		else {
			supported_components =
				(struct cerberus_pcd_supported_components*) supported_component_ids;

			for (i_index = 0; i_index < components->num_components; ++i_index) {
				cerberus_print_info ("%i %i\n", supported_components[i_index].component_id,
					supported_components[i_index].component_count);
			}
		}
	}

exit:
	if (status == STATUS_SUCCESS) {
		status = cerberus_get_supported_components_strings (intf, is_cfm,
			supported_component_ids, components);
	}

	cerberus_free (supported_component_ids);

	return status;
}

/**
 * Print out component IDs supported by manifest in provided region.
 *
 * @param intf The Cerberus interface to utilize
 * @param is_cfm The flag to identify CFM or PCD.
 * @param cfm_region CFM storage region
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_print_supported_components (struct cerberus_interface *intf,
	bool is_cfm, uint8_t cfm_region)
{
	struct cerberus_components components;
	size_t i_index = 0;
	int status = STATUS_SUCCESS;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_supported_components (intf, is_cfm, cfm_region, &components);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	cerberus_print_info ("Supported Components:\n");

	for (i_index = 0; i_index < components.num_components; ++i_index) {
		cerberus_print_info ("%s\n", components.component_str[i_index]);
	}

	cerberus_free_comp_list (&components);

	return status;
}

/**
 * Get components supported by CFM.
 *
 * @param intf The Cerberus interface to utilize.
 * @param cfm_region The region to query.
 * @param components Output container that will be filled with the supported component names.
 * 	Container is dynamically allocated MUST BE FREED BY CALLER using cerberus_free_comp_list().
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_cfm_supported_components (struct cerberus_interface *intf,
	uint8_t cfm_region, struct cerberus_components *components)
{
	return cerberus_get_supported_components (intf, true, cfm_region, components);
}

/**
 * Print out component IDs supported by CFM in provided region.
 *
 * @param intf The Cerberus interface to utilize
 * @param cfm_region CFM storage region
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_cfm_supported_components (struct cerberus_interface *intf,
	uint8_t cfm_region)
{
	return cerberus_print_supported_components (intf, true, cfm_region);
}

/**
 * Get components supported by PCD.
 *
 * @param intf The Cerberus interface to utilize.
 * @param components Output container that will be filled with the supported component names.
 * 	Container is dynamically allocated MUST BE FREED BY CALLER using cerberus_free_comp_list().
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pcd_supported_components (struct cerberus_interface *intf,
	struct cerberus_components *components)
{
	return cerberus_get_supported_components (intf, false, 0, components);
}

/**
 * Print out component IDs supported by PCD.
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_pcd_supported_components (struct cerberus_interface *intf)
{
	return cerberus_print_supported_components (intf, false, 0);
}

/**
 * Send a debug log clear request to Cerberus
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_debug_log_clear (struct cerberus_interface *intf)
{
	enum cerberus_log_type log_type;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	log_type = CERBERUS_DEBUG_LOG;

	return cerberus_protocol_send_no_rsp (intf, __func__, __LINE__, CERBERUS_PROTOCOL_CLEAR_LOG,
		intf->params->device_eid, false, (uint8_t*) &log_type, sizeof (uint8_t));
}

/**
 * Send a attestation log clear request to Cerberus
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_attestation_log_clear (struct cerberus_interface *intf)
{
	enum cerberus_log_type log_type;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	log_type = CERBERUS_ATTESTATION_LOG;

	return cerberus_protocol_send_no_rsp (intf, __func__, __LINE__, CERBERUS_PROTOCOL_CLEAR_LOG,
		intf->params->device_eid, false, (uint8_t*) &log_type, sizeof (uint8_t));
}

/**
 * Retrieve information on all Cerberus logs
 *
 * @param intf The Cerberus interface to utilize
 * @param log Output buffer to be filled with debug, attestation and tamper log info
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_log_info (struct cerberus_interface *intf,
	struct cerberus_log_info *log)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (log == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_LOG_INFO, intf->params->device_eid, sizeof (uint32_t) * 3, false,
		intf->cmd_buf, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (&log->debug_log, intf->cmd_buf, sizeof (uint32_t));

	memcpy (&log->attestation_log, &intf->cmd_buf[sizeof (uint32_t)], sizeof (uint32_t));

	memcpy (&log->tamper_log, &intf->cmd_buf[2 * sizeof (uint32_t)], sizeof (uint32_t));

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Debug Log Length: %i\n", log->debug_log);
		cerberus_print_info ("Attestation Log Length: %i\n", log->attestation_log);
		cerberus_print_info ("Tamper Log Length: %i\n", log->tamper_log);
	}

	return STATUS_SUCCESS;
}

/**
 * Retrieve log contents from Cerberus
 *
 * @param intf The Cerberus interface to utilize
 * @param log_type Log to read back
 * @param log Output buffer for log contents, CONTENTS MUST BE FREED BY CALLER using
 * 	cerberus_free()
 * @param log_len Length of output buffer
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_log_read (struct cerberus_interface *intf, uint8_t log_type, uint8_t **log,
	size_t *log_len)
{
	struct cerberus_log_info log_info = {0};
	uint8_t *log_buf = NULL;
	uint32_t offset = 0;
	size_t total_len = 0;
	size_t payload_len;
	size_t max_per_msg;
	int status;

	if ((log == NULL) || (log_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (log_type != CERBERUS_TCG_LOG) {
		status = cerberus_get_log_info (intf, &log_info);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (log_type) {
			case CERBERUS_DEBUG_LOG:
				if (log_info.debug_log == 0) {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "Debug log empty!");
					return STATUS_NO_DATA;
				}
				break;

			case CERBERUS_ATTESTATION_LOG:
				if (log_info.attestation_log == 0) {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"TCG attestation log empty!");
					return STATUS_NO_DATA;
				}
				break;

			case CERBERUS_TAMPER_LOG:
				if (log_info.tamper_log == 0) {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "Tamper log empty!");
					return STATUS_NO_DATA;
				}
				break;

			default:
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
				return STATUS_INVALID_INPUT;
		}
	}

	log_buf = malloc (CERBERUS_MAX_LOG_SIZE);
	if (log_buf == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);

	cerberus_print_info ("Retrieving log bytes\n");

	while (1) {
		intf->cmd_buf[0] = log_type;
		memcpy (&intf->cmd_buf[1], &offset, sizeof (offset));

		payload_len = 1 + sizeof (offset);

		status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
			CERBERUS_PROTOCOL_READ_LOG, intf->params->device_eid, false, intf->cmd_buf,
			&payload_len);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}
		total_len += payload_len;

		if (total_len > CERBERUS_MAX_LOG_SIZE) {
			status = STATUS_BUF_TOO_SMALL;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status));
			goto exit;
		}

		memcpy (&log_buf[offset], intf->cmd_buf, payload_len);

		offset = (uint32_t) total_len;

		cerberus_print_info (".");
		fflush (stdout);

		if ((payload_len) < max_per_msg) {
			break;
		}
	}

	*log = log_buf;
	*log_len = total_len;

	cerberus_print_info ("\n");
	return status;

exit:
	free (log_buf);

	cerberus_print_info ("\n");
	return status;
}

/**
 * Reallocate memory and copy current message into buffer
 *
 * @param intf The Cerberus interface to utilize
 * @param buffer Buffer to update with the message
 * @param buf_size Current max length of the buffer
 * @param index Index to start copying into the buffer
 * @param msg Message to copy
 * @param msg_len Length of the message.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int realloc_and_copy_msg_log (struct cerberus_interface *intf, char **buffer,
	size_t *buf_size, size_t *index, uint8_t *msg, size_t msg_len)
{
	char *realloc_ptr =  NULL;
	size_t curr_index;
	size_t max_buf_len;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((buffer == NULL) || (msg == NULL) || (buf_size == NULL) || (index == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	curr_index = *index;
	max_buf_len = *buf_size;

	if ((curr_index + msg_len) > max_buf_len) {
		max_buf_len += CERBERUS_MAX_LOG_SIZE;
		realloc_ptr = realloc (*buffer, sizeof (char) * max_buf_len);
		if (realloc_ptr == NULL) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_NO_MEM));
			return STATUS_NO_MEM;
		}

		*buffer = realloc_ptr;
		*buf_size = max_buf_len;
	}

	memcpy ((*buffer + curr_index), msg, msg_len);
	*index = curr_index + msg_len;

	return STATUS_SUCCESS;
}

/**
 * Retrieve the debug log contents from Cerberus and fill the output buffer with raw log data.
 *
 * @param intf The Cerberus interface to utilize.
 * @param list Output list containing debug log entries in logging_debug_entry format.  List is dynamically
 *  allocated MUST BE FREED BY CALLER using cerberus_free_log_entries().
 *
 * @return STATUS_SUCCESS if the operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_debug_log_read_entries (struct cerberus_interface *intf,
	struct logging_debug_list **list)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (list == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	/* TODO: Create a list of debug log entries.  call cerberus_log_read (intf, CERBERUS_DEBUG_LOG,
	 * &entries, &log_len) and create entries in the struct logging_debug_entry format and add to the
	 * list */

	*list = NULL;

	return STATUS_SUCCESS;
}

/**
 * Free all debug log entries in the provided list.
 *
 * @param list List of debug log entries to be freed.
 *
 */
LIB_EXPORT void cerberus_free_log_entries (struct logging_debug_list *list)
{
	UNUSED (list);
	/* TODO: Free the log entries */
}

/**
 * Retrieve the debug log contents from Cerberus.  The log entries will be decoded into
 * human-readable strings.
 *
 * @param intf The Cerberus interface to utilize.
 * @param debug_log Output buffer that will be filled with the formatted debug log.  MUST BE FREED
 *  BY CALLER using cerberus_free().
 * @param debug_len Output for the total length of the output buffer.
 *
 * @return STATUS_SUCCESS if the operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_debug_log_read (struct cerberus_interface *intf, char **debug_log,
	size_t *debug_len)
{
	uint8_t *entries = NULL;
	char log_msg[CERBERUS_MAX_MSG_LEN];
	uint8_t log_msg_len = 0;
	char *log_buffer = NULL;
	size_t log_index = 0;
	size_t log_max_size = CERBERUS_MAX_MSG_LEN;
	char message[CERBERUS_MAX_MSG_LEN];
	char sub_msg[CERBERUS_MAX_MSG_LEN];
	size_t log_len = 0;
	int status;
	uint8_t *pos;
	struct platform_debug_log_interface *platform_debug_log_intf;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (debug_log == NULL) || (debug_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	platform_debug_log_intf = &intf->platform.debuglog;

	status = cerberus_log_read (intf, CERBERUS_DEBUG_LOG, &entries, &log_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (log_len == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "Debug log empty!");
		status = STATUS_NO_DATA;
		goto exit;
	}

	log_buffer = malloc (sizeof (char) * CERBERUS_MAX_LOG_SIZE);
	if (log_buffer == NULL) {
		status = STATUS_NO_MEM;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		goto exit;
	}

	log_index += snprintf (log_buffer, log_max_size,
		"\n\n\n%-10s| %-16s| %-10s| %-10s| %-10s\n", "Entry", "Elapsed Time", "Severity",
		"Component", "Message");
	log_index += snprintf (&log_buffer[log_index], log_max_size,
		"----------------------------------------------------------------------------------------------------------------\n");

	pos = entries;
	while (log_len > 0) {
		struct logging_debug_entry_base *entry;
		uint8_t entry_type;
		uint32_t entry_id;
		uint16_t entry_length;
		uint16_t entry_size = 0;
		/* Commented out due to compiler warning.  Leaving as a reference for the future. */
		//uint16_t entry_format = 0;
		uint16_t milliseconds = 0;
		uint8_t seconds = 0;
		uint8_t minutes = 0;
		uint32_t hours = 0;

		const char **message_str = NULL;
		const char *sev = NULL;
		const char *component_name = NULL;

		entry_type = *pos;
		if ((entry_type & 0xF0) != 0xC0) {
			log_msg_len = snprintf (log_msg, sizeof (log_msg),
				"%-10u| %5u:%02u:%02u.%03u | %-10s| %-10s| Corrupt entry type: 0x%02X\n", 0, 0, 0,
				0, 0, "", "", entry_type);
			status = realloc_and_copy_msg_log (intf, &log_buffer, &log_max_size, &log_index,
				(uint8_t*) log_msg, log_msg_len);
			if (status == STATUS_SUCCESS) {
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_FORMAT), entry_type);
				status = STATUS_UNSUPPORTED_FORMAT;
			}
			goto exit;
		}

		switch (entry_type) {
			case 0xCA: {
				struct logging_debug_entry_ca *header = (struct logging_debug_entry_ca*) pos;
				entry_id = header->entry_id;
				entry_length = sizeof (struct logging_debug_entry_ca) +
					sizeof (struct logging_debug_entry_base);
				entry =
					(struct logging_debug_entry_base*) (pos + sizeof (struct logging_debug_entry_ca));
				break;
			}

			case 0xCB: {
				struct logging_debug_entry_cb *header = (struct logging_debug_entry_cb*) pos;
				entry_id = header->entry_id;
				entry_length = header->length;
				entry_size = header->length - sizeof (struct logging_debug_entry_cb);
				/* Commented out due to compiler warning.  Leaving as a reference for the future. */
				//entry_format = header->format;
				entry =
					(struct logging_debug_entry_base*) (pos + sizeof (struct logging_debug_entry_cb));
				break;
			}

			default: {
				struct logging_debug_entry_cc *header = (struct logging_debug_entry_cc*) pos;
				entry_id = header->entry_id;
				entry_length = header->length;
				entry_size = header->length - header->data_offset;
				/* Commented out due to compiler warning.  Leaving as a reference for the future. */
				//entry_format = *((uint16_t*) (pos + header->data_offset));
				entry =
					(struct logging_debug_entry_base*) (pos + header->data_offset + sizeof (uint16_t));
				break;
			}
		}

		// Time stamp field has been added into the debug log entry. Therefore, size of the old
		// version debug log entry would be smaller than size of the current version log entry.
		// For old version debug log entry, its time stamp will be displayed as 0:0:0.0.
		if (entry_size >= sizeof (struct logging_debug_entry_base)) {
			hours = (uint32_t) (entry->time / 3600000);
			entry->time -= hours * 3600000;
			minutes = (uint8_t) (entry->time / 60000);
			entry->time -= minutes * 60000;
			seconds = (uint8_t) (entry->time / 1000);
			entry->time -= seconds * 1000;
			milliseconds = (uint16_t) entry->time;
		}

		if (entry->severity < NUM_LOGGING_SEVERITY) {
			sev = logging_severities[entry->severity];
		}

		switch (entry->component) {
			case LOGGING_COMPONENT_CMD_INTERFACE:
				if (entry->msg_index < ARRAY_SIZE (cmd_logging_messages_str)) {
					message_str = cmd_logging_messages_str;
				}
				break;

			case LOGGING_COMPONENT_CRYPTO:
				if (entry->msg_index < ARRAY_SIZE (crypto_logging_messages_str)) {
					message_str = crypto_logging_messages_str;
				}
				break;

			case LOGGING_COMPONENT_HOST_FW:
				if (entry->msg_index < ARRAY_SIZE (host_logging_messages_str)) {
					message_str = host_logging_messages_str;
				}
				break;

			case LOGGING_COMPONENT_CERBERUS_FW:
				if (entry->msg_index < ARRAY_SIZE (fw_image_logging_messages_str)) {
					message_str = fw_image_logging_messages_str;
				}
				break;

			case LOGGING_COMPONENT_STATE_MGR:
				if (entry->msg_index < ARRAY_SIZE (state_logging_messages_str)) {
					message_str = state_logging_messages_str;
				}
				break;

			case LOGGING_COMPONENT_MANIFEST:
				if (entry->msg_index < ARRAY_SIZE (manifest_messages_str)) {
					message_str = manifest_messages_str;
				}
				break;

			case LOGGING_COMPONENT_SPI_FILTER:
				if (entry->msg_index < ARRAY_SIZE (spi_filter_messages_str)) {
					message_str = spi_filter_messages_str;
				}
				break;

			case LOGGING_COMPONENT_I2C:
				if (entry->msg_index < ARRAY_SIZE (i2c_messages_str)) {
					message_str = i2c_messages_str;
				}
				break;

			case LOGGING_COMPONENT_RECOVERY:
				if (entry->msg_index < ARRAY_SIZE (recovery_img_messages_str)) {
					message_str = recovery_img_messages_str;
				}
				break;

			case LOGGING_COMPONENT_FLASH:
				if (entry->msg_index < ARRAY_SIZE (flash_messages_str)) {
					message_str = flash_messages_str;
				}
				break;

			case LOGGING_COMPONENT_MCTP:
				if (entry->msg_index < ARRAY_SIZE (mctp_messages_str)) {
					message_str = mctp_messages_str;
				}
				break;

			case LOGGING_COMPONENT_TPM:
				if (entry->msg_index < ARRAY_SIZE (tpm_logging_messages_str)) {
					message_str = tpm_logging_messages_str;
				}
				break;

			case LOGGING_COMPONENT_RIOT:
				if (entry->msg_index < ARRAY_SIZE (riot_messages_str)) {
					message_str = riot_messages_str;
				}
				break;

			case LOGGING_COMPONENT_SYSTEM:
				if (entry->msg_index < ARRAY_SIZE (system_messages_str)) {
					message_str = system_messages_str;
				}
				break;

			case LOGGING_COMPONENT_INTRUSION:
				if (entry->msg_index < ARRAY_SIZE (intrusion_messages_str)) {
					message_str = intrusion_messages_str;
				}
				break;

			case LOGGING_COMPONENT_ATTESTATION:
				if (entry->msg_index < ARRAY_SIZE (attestation_messages_str)) {
					message_str = attestation_messages_str;
				}
				break;

			case LOGGING_COMPONENT_SPDM:
				if (entry->msg_index < ARRAY_SIZE (spdm_messages_str)) {
					message_str = spdm_messages_str;
				}
				break;

			case LOGGING_COMPONENT_CRASH_DUMP:
				if (entry->msg_index < ARRAY_SIZE (crash_dump_messages_str)) {
					message_str = crash_dump_messages_str;
				}
				break;

			case LOGGING_COMPONENT_INIT:
			case LOGGING_COMPONENT_BOOT:
			default:
				if (platform_debug_log_intf->get_component_messages_str) {
					platform_debug_log_intf->get_component_messages_str (intf, entry, &message_str);
				}

				break;
		}

		if (message_str != NULL) {
			bool done = false;

			if (message_str == cmd_logging_messages_str) {
				switch (entry->msg_index) {
					case CMD_LOGGING_PROTOCOL_ERROR:
						snprintf (sub_msg, sizeof (sub_msg),
							cerberus_protocol_error_messages_str[(entry->arg1 >> 24 & 0xFF)],
								entry->arg2);

						snprintf (message, sizeof (message),
							cmd_logging_messages_str[CMD_LOGGING_PROTOCOL_ERROR],
							(entry->arg1 & 0xFF), (entry->arg1 >> 16 & 0xFF),
							(entry->arg1 >> 8 & 0xFF), sub_msg);
						done = true;
						break;

					case CMD_LOGGING_ERROR_MESSAGE:
						snprintf (message, sizeof (message),
							cmd_logging_messages_str[CMD_LOGGING_ERROR_MESSAGE],
							(entry->arg1 & 0xFF), (entry->arg1 >> 16 & 0xFF),
							(entry->arg1 >> 8 & 0xFF), (entry->arg1 >> 24 & 0xFF), entry->arg2);
						done = true;
						break;

					case CMD_LOGGING_NO_CERT:
						snprintf (message, sizeof (message),
							cmd_logging_messages_str[CMD_LOGGING_NO_CERT],
							((entry->arg1 >> 8) & 0xFF), entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;
				}
			}
			else if (message_str == spi_filter_messages_str) {
				switch (entry->msg_index) {
					case SPI_FILTER_LOGGING_FILTER_CONFIG:
						cerberus_format_filter_config_entry (entry->arg1, entry->arg2, message,
							sizeof (message));
						done = true;
						break;

					case SPI_FILTER_LOGGING_ADDRESS_MODE:
						if (entry->arg2 > 1) {
							snprintf (sub_msg, sizeof (sub_msg), "error 0x%x", entry->arg2);
						}
						else {
							snprintf (sub_msg, sizeof (sub_msg), "%s",
								(entry->arg2 == 0) ? "3-byte" : "4-byte");
						}

						snprintf (message, sizeof (message),
							spi_filter_messages_str[SPI_FILTER_LOGGING_ADDRESS_MODE], entry->arg1,
							sub_msg);
						done = true;
						break;

					case SPI_FILTER_LOGGING_FILTER_REGION:
						snprintf (message, sizeof (message),
							spi_filter_messages_str[SPI_FILTER_LOGGING_FILTER_REGION],
							(entry->arg1 >> 24) & 0xff, (entry->arg2 >> 24) & 0xff,
							entry->arg1 << 8, entry->arg2 << 8);
						done = true;
						break;
				}
			}
			else if (message_str == mctp_messages_str) {
				switch (entry->msg_index) {
					case MCTP_LOGGING_PROTOCOL_ERROR:
						snprintf (sub_msg, sizeof (sub_msg),
							cerberus_protocol_error_messages_str[(entry->arg1 >> 24 & 0xFF)],
								entry->arg2);

						snprintf (message, sizeof (message),
							mctp_messages_str[MCTP_LOGGING_PROTOCOL_ERROR],
							(entry->arg1 & 0xFF), (entry->arg1 >> 16 & 0xFF),
							(entry->arg1 >> 8 & 0xFF), sub_msg);
						done = true;
						break;

					case MCTP_LOGGING_ERR_MSG:
						snprintf (message, sizeof (message),
							mctp_messages_str[MCTP_LOGGING_ERR_MSG], (entry->arg1 & 0xFF),
							(entry->arg1 >> 16 & 0xFF), (entry->arg1 >> 8 & 0xFF),
							(entry->arg1 >> 24 & 0xFF), entry->arg2);
						done = true;
						break;

					case MCTP_LOGGING_PKT_DROPPED:
						snprintf (message, sizeof (message),
							mctp_messages_str[MCTP_LOGGING_PKT_DROPPED], (entry->arg2 >> 24),
							(entry->arg1 & 0xFF), (entry->arg1 >> 8 & 0xFF),
							(entry->arg1 >> 16 & 0xFF), (entry->arg1 >> 24 & 0xFF),
							(entry->arg2 & 0xFF), (entry->arg2 >> 8 & 0xFF),
							(entry->arg2 >> 16 & 0xFF));
						done = true;
						break;

					case MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN:
						snprintf (message, sizeof (message),
							mctp_messages_str[MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL:
						snprintf (message, sizeof (message),
							mctp_messages_str[MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case MCTP_LOGGING_RSP_TIMEOUT:
						snprintf (message, sizeof (message),
							mctp_messages_str[MCTP_LOGGING_RSP_TIMEOUT],
							(entry->arg1) >> 8, entry->arg1 & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

				}
			}
			else if (message_str == attestation_messages_str) {
				switch (entry->msg_index) {
					case ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_HASH_LEN_IN_RSP:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_HASH_LEN_IN_RSP],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_CERBERUS_PROTOCOL_VER_UNSUPPORTED:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_CERBERUS_PROTOCOL_VER_UNSUPPORTED],
							entry->arg1, (entry->arg2 >> 16) & 0xFF, (entry->arg2 >> 8) & 0xFF,
							entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH],
							(entry->arg1 >> 8) & 0xFF, entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED],
							entry->arg1, (entry->arg2 >> 24) & 0xFF, (entry->arg2 >> 16) & 0xFF,
							(entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN],
							(entry->arg1 >> 8) & 0xFF, entry->arg1 & 0xFF,
							(entry->arg2 >> 16) & 0xFFFF, entry->arg2 & 0xFFFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION],
							(entry->arg1 >> 16) & 0xFF, (entry->arg1 >> 8) & 0xFF,
							entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE],
							(entry->arg1 >> 8) & 0xFF, entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW],
							entry->arg1, (entry->arg2 >> 8) & 0xFF, entry->arg2 & 0xFF);
						done = true;
						break;

					case ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED],
							(entry->arg1 >> 8) & 0xFF, entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP],
							(entry->arg1 >> 8) & 0xFF, entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID:
						snprintf (message, sizeof (message),
							attestation_messages_str[
								ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID],
							(entry->arg1 >> 16) & 0xFF, (entry->arg1 >> 8) & 0xFF,
							entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED:
						snprintf (message, sizeof (message),
							attestation_messages_str[
								ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED],
							(entry->arg1 >> 16) & 0xFF, (entry->arg1 >> 8) & 0xFF,
							entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY],
							entry->arg1, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR],
							entry->arg1, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_NEXT_DEVICE_ATTESTATION_ERROR:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_NEXT_DEVICE_ATTESTATION_ERROR],
							entry->arg1, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_PCR_UPDATE_ERROR:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_PCR_UPDATE_ERROR],
							entry->arg1, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_GET_ATTESTATION_STATUS_ERROR:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_GET_ATTESTATION_STATUS_ERROR],
							entry->arg1, entry->arg2);
						done = true;
						break;

					case ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR:
						snprintf (message, sizeof (message),
							attestation_messages_str[ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR],
							entry->arg1, entry->arg2);
						done = true;
						break;
				}
			}
			else if (message_str == spdm_messages_str) {
				switch (entry->msg_index) {
					case SPDM_LOGGING_ERR_MSG:
						snprintf (message, sizeof (message),
							spdm_messages_str[SPDM_LOGGING_ERR_MSG], (entry->arg1 >> 24) & 0xFF,
							(entry->arg1 >> 16) & 0xFF, (entry->arg1 >> 8) & 0xFF,
							entry->arg1 & 0xFF, entry->arg2);
						done = true;
						break;
				}
			}
			else if (platform_debug_log_intf->post_process_component_message) {
				platform_debug_log_intf->post_process_component_message (intf, message_str, message,
					sizeof (message), entry, &done);
			}
			else if (message_str == system_messages_str) {
				switch (entry->msg_index) {
					case SYSTEM_LOGGING_POLICY_CHECK_FAIL: {
						const char *policy;
						char value[4];

						if (entry->arg1 < ARRAY_SIZE (system_policy_str)) {
							policy = system_policy_str[entry->arg1];
						}
						else {
							snprintf (value, sizeof (value), "%i", entry->arg1);
							policy = value;
						}

						snprintf (message, sizeof (message),
							system_messages_str[SYSTEM_LOGGING_POLICY_CHECK_FAIL], policy,
							entry->arg2);

						done = true;
						break;
					}

					case SYSTEM_LOGGING_DEVICE_UNLOCKED: {
						const char *type = "unknown";

						if (entry->arg1 < ARRAY_SIZE (system_unlock_type_str)) {
							type = system_unlock_type_str[entry->arg1];
						}

						snprintf (message, sizeof (message),
							system_messages_str[SYSTEM_LOGGING_DEVICE_UNLOCKED], type);

						done = true;
						break;
					}
				}
			}
			else if (message_str == crash_dump_messages_str) {
				switch (entry->msg_index) {
					case CRASH_DUMP_LOGGING_EXCEPTION_DETAIL:
						if (entry->arg1 < ARRAY_SIZE (crash_dump_details_str)) {
							snprintf (message, sizeof (message),
								crash_dump_details_str[entry->arg1], entry->arg2);
						}
						else {
							snprintf (message, sizeof (message),
								"Exception info ID=0x%x, value=0x%x", entry->arg1, entry->arg2);
						}

						done = true;
						break;
				}
			}

			if (!done) {
				snprintf (message, sizeof (message), message_str[entry->msg_index], entry->arg1,
					entry->arg2);
			}
		}
		else {
			snprintf (message, sizeof (message), "Message ID=%u, arg1=0x%x, arg2=0x%x",
				entry->msg_index, entry->arg1, entry->arg2);
		}

		if (entry->component < ARRAY_SIZE (logging_component_str)) {
			component_name = logging_component_str[entry->component];
		}
		else if (platform_debug_log_intf->get_component_name) {
			platform_debug_log_intf->get_component_name (intf, entry->component, &component_name);
		}

		if (component_name != NULL) {
			if (sev) {
				log_msg_len = snprintf (log_msg, sizeof (log_msg),
					"%-10u| %5u:%02u:%02u.%03u | %-10s| %-10s| %s\n", entry_id, hours, minutes,
					seconds, milliseconds, sev, component_name, message);
			}
			else {
				log_msg_len = snprintf (log_msg, sizeof (log_msg),
					"%-10u| %5u:%02u:%02u.%03u | %-10u| %-10s| %s\n", entry_id, hours, minutes,
					seconds, milliseconds, entry->severity, component_name,
					message);
			}

		}
		else {
			if (sev) {
				log_msg_len = snprintf (log_msg, sizeof (log_msg),
					"%-10u| %5u:%02u:%02u.%03u | %-10s| %-10u| %s\n", entry_id, hours, minutes,
					seconds, milliseconds, sev, entry->component, message);
			}
			else {
				log_msg_len = snprintf (log_msg, sizeof (log_msg),
					"%-10u| %5u:%02u:%02u.%03u | %-10u| %-10u| %s\n", entry_id, hours, minutes,
					seconds, milliseconds, entry->severity, entry->component, message);
			}
		}

		status = realloc_and_copy_msg_log (intf, &log_buffer, &log_max_size, &log_index,
			(uint8_t*) log_msg, log_msg_len);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		pos += entry_length;
		log_len -= entry_length;
	}

	log_buffer[log_index++] = '\0';

	*debug_log = log_buffer;
	*debug_len = log_index;

exit:
	if ((status != STATUS_SUCCESS) && (log_buffer)) {
		free (log_buffer);
	}

	cerberus_free (entries);

	return status;
}

/**
 * Retrieve the debug log contents from Cerberus into a file.  The log entries will be decoded into
 * human-readable strings.
 *
 * @param intf The Cerberus interface to utilize.
 * @param filename File name to save debug log to
 *
 * @return STATUS_SUCCESS if the operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_debug_log_file (struct cerberus_interface *intf,
	const char *filename)
{
	char *debug_log = NULL;
	size_t debug_log_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_debug_log_read (intf, &debug_log, &debug_log_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_write_file (intf, filename, (uint8_t*) debug_log, debug_log_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

exit:
	cerberus_free (debug_log);
	return status;
}

/**
 * Retrieve the debug log contents from Cerberus.  Only the specified range of entries will be
 * returned.  The log entries will be decoded into human-readable strings.
 *
 * @param intf The Cerberus interface to utilize.
 * @param start The index that will be the first entry returned.  A negative index indicates a count
 *  back from the last entry.  If a positive start index is greater than the total number of entries,
 *  nothing will be returned.  If a negative start index is greater than the total number of entries,
 *  entries will be read starting from the first entry.
 * @param end The index for the first entry that is out of the defined range.  The last entry
 *  returned will be the one prior to this index.  A negative value will return all entries to the
 *  end.  An end that is less than or equal to the start will return nothing.
 * @param debug_log Output buffer that will be filled with the formatted debug log.  MUST BE FREED
 *  BY CALLER using cerberus_free().
 * @param debug_len Output for the total length of the output buffer.
 *
 * @return STATUS_SUCCESS if the operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_debug_log_read_range (struct cerberus_interface *intf, int start, int end,
	char **debug_log, size_t *debug_len)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (debug_log == NULL) || (debug_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if ((start >= 0) && (end >= 0) && (start <= end)) {
		*debug_log = NULL;
		*debug_len = 0;

		return STATUS_SUCCESS;
	}

	/* TODO: Move debug log parsing here and apply the range.  cerberus_debug_log_read should be
	 * updated to just call cerberus_debug_log_read_range (intf, 0, -1, debug_log, debug_len). */
	*debug_log = NULL;
	*debug_len = 0;

	return STATUS_SUCCESS;
}

/**
 * Retrieve the debug log contents from Cerberus.  Only write the specified range of entries to a
 * file. The log entries will be decoded into human-readable strings.
 *
 * @param intf The Cerberus interface to utilize.
 * @param start The index that will be the first entry returned.  A negative index indicates a count
 *  back from the last entry.  If a positive start index is greater than the total number of entries,
 *  nothing will be returned.  If a negative start index is greater than the total number of entries,
 *  entries will be read starting from the first entry.
 * @param end The index for the first entry that is out of the defined range.  The last entry
 *  returned will be the one prior to this index.  A negative value will return all entries to the
 *  end.  An end that is less than or equal to the start will return nothing.
 * @param filename File name to save debug log to
 *
 * @return STATUS_SUCCESS if the operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_debug_log_range_file (struct cerberus_interface *intf, int start,
	int end, const char *filename)
{
	char *debug_log = NULL;
	size_t debug_log_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_debug_log_read_range (intf, start, end, &debug_log, &debug_log_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_write_file (intf, filename, (uint8_t*) debug_log, debug_log_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

exit:
	cerberus_free (debug_log);
	return status;
}

/**
 * Retrieve Cerberus attestation log contents from Cerberus.  This log will contain all entries
 * used in computing PCR values, but is not TCG-formatted.
 *
 * @param intf The Cerberus interface to utilize
 * @param entries Output buffer to be filled with TCG log entries, MUST BE FREED BY CALLER using
 * 	cerberus_free()
 * @param num_entries Number of entries read back in output buffer
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_attestation_log_read (struct cerberus_interface *intf,
	struct logging_tcg_entry **entries, size_t *num_entries)
{
	uint8_t *next;
	uint8_t *pos;
	uint8_t *log;
	size_t log_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (entries == NULL) || (num_entries == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_log_read (intf, CERBERUS_ATTESTATION_LOG, &log, &log_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	pos = log;
	next = log;
	*num_entries = 0;
	while (log_len > 0) {
		uint8_t *entry;
		uint8_t entry_type;
		uint16_t entry_length;
		uint32_t entry_id;

		entry_type = *pos;
		if ((entry_type & 0xF0) != 0xC0) {
			free (log);

			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_FORMAT), entry_type);
			return STATUS_UNSUPPORTED_FORMAT;
		}

		switch (entry_type) {
			case 0xCA: {
				struct logging_tcg_entry_ca *header = (struct logging_tcg_entry_ca*) pos;
				entry_length = sizeof (struct logging_tcg_entry_ca) +
					sizeof (struct logging_tcg_entry) - sizeof (uint32_t);
				entry_id = header->entry_id;
				entry = pos + sizeof (struct logging_tcg_entry_ca);
				break;
			}

			case 0xCB: {
				struct logging_tcg_entry_cb *header = (struct logging_tcg_entry_cb*) pos;
				entry_length = header->length;
				entry_id = header->entry_id;
				entry = pos + sizeof (struct logging_tcg_entry_cb);
				break;
			}

			default: {
				struct logging_tcg_entry_cc *header = (struct logging_tcg_entry_cc*) pos;
				entry_length = header->length;
				entry_id = header->entry_id;
				entry = pos + header->data_offset;
				break;
			}
		}

		*((uint32_t*) next) = entry_id;
		next += sizeof (uint32_t);
		memmove (next, entry, sizeof (struct logging_tcg_entry) - sizeof (uint32_t));

		next += (sizeof (struct logging_tcg_entry) - sizeof (uint32_t));
		(*num_entries)++;
		pos += entry_length;
		log_len -= entry_length;
	}

	*entries = (struct logging_tcg_entry*) log;
	return status;
}

/**
 * Retrieve and print out TCG log contents from Cerberus
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_tcg_log (struct cerberus_interface *intf)
{
	struct logging_tcg_entry *entries = NULL;
	size_t entry_count = 0;
	uint16_t i_entry;
	uint8_t i_buf = 0;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_attestation_log_read (intf, &entries, &entry_count);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (entry_count == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "TCG log empty!\n");
		status = STATUS_NO_DATA;
		goto exit;
	}

	cerberus_print_info ("\n\n\n%-10s| %-10s| %-20s| %-65s| %-65s\n", "Entry", "PCR Number",
		"TCG Event Type", "Digest", "Measurement");
	cerberus_print_info (
		"---------------------------------------------------------------------------------------");
	cerberus_print_info (
		"------------------------------------------------------------------------------------------\n");

	for (i_entry = 0; i_entry < entry_count; i_entry++) {
		cerberus_print_info ("%-10i| %-10i| 0x%-18X| ", entries[i_entry].entry_id,
			(uint8_t) (entries[i_entry].measurement_type >> 8), entries[i_entry].event_type);

		for (i_buf = 0; i_buf < CERBERUS_SHA256_HASH_LEN; ++i_buf) {
			cerberus_print_info ("%02X", entries[i_entry].digest[i_buf]);
		}

		cerberus_print_info (" | ");

		for (i_buf = 0; i_buf < CERBERUS_SHA256_HASH_LEN; ++i_buf) {
			cerberus_print_info ("%02X", entries[i_entry].measurement[i_buf]);
		}

		cerberus_print_info ("\n");
	}

	cerberus_print_info ("\n");

exit:
	cerberus_free ((uint8_t*) entries);

	return status;
}

/**
 * Retrieve the aggregate measurement for a PCR bank from Cerberus
 *
 * @param intf The Cerberus interface to utilize
 * @param pcr_num The PCR bank to retrieve aggregate measurement
 * @param measurement Output buffer to store final measurement value from PCR bank, MUST BE FREED
 *  BY CALLER using cerberus_free()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pcr_measurement (struct cerberus_interface *intf, uint8_t pcr_num,
	uint8_t **measurement)
{
	struct logging_tcg_entry *entries = NULL;
	int entry_count = 0;
	int i_entry;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (measurement == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_attestation_log_read (intf, &entries, (size_t*) &entry_count);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (entry_count == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "TCG log empty!\n");
		status = STATUS_NO_DATA;
		goto release_entries;
	}

	*measurement = malloc (CERBERUS_SHA256_HASH_LEN);
	if (*measurement == NULL) {
		status = STATUS_NO_MEM;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		goto release_entries;
	}

	for (i_entry = entry_count - 1; i_entry >= 0; i_entry--) {
		if ((uint8_t) (entries[i_entry].measurement_type >> 8) == pcr_num) {
			memcpy (*measurement, entries[i_entry].measurement, CERBERUS_SHA256_HASH_LEN);
			goto release_entries;
		}
		else if ((uint8_t) (entries[i_entry].measurement_type >> 8) < pcr_num) {
			status = STATUS_INVALID_INPUT;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
			goto release_all;
		}
	}

release_all:
	cerberus_free (*measurement);

release_entries:
	cerberus_free ((uint8_t*) entries);
	return status;
}

/**
 * Retrieve and export TCG event log generated by utility to a buffer
 *
 * @param intf The Cerberus interface to utilize.
 * @param tcg_log Output buffer that will be filled with the formatted tcg log.  MUST BE FREED
 *  BY CALLER using cerberus_free().
 * @param log_len Output for the total length of the output buffer.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_tcg_log_through_utility_memory (struct cerberus_interface *intf,
	char **tcg_log, size_t *log_len)
{
	struct logging_tcg_entry *entries = NULL;
	struct tcg_event old_event = {0};
	struct tcg_event2 event = {0};
	struct tcg_log_header header;
	struct cerberus_device_id ids;
	size_t entry_count = 0;
	size_t payload_len;
  	size_t event_size_pos;
	uint32_t event_size;
	uint16_t i_entry;
	char *log_buffer = NULL;
	size_t log_index = 0;
	size_t log_max_size = 0;
	int status;
	struct platform_tcg_log_interface *platform_tcg_log_intf;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (tcg_log == NULL) || (log_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	platform_tcg_log_intf = &(intf->platform.tcglog);

	status = cerberus_get_device_id (intf, &ids);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_attestation_log_read (intf, &entries, &entry_count);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (entry_count == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "TCG log empty!");
		status = STATUS_NO_DATA;
		goto exit;
	}

	old_event.event_type = CERBERUS_TCG_EFI_NO_ACTION_EVENT_TYPE;
	old_event.event_size = sizeof (struct tcg_log_header);

	memset (&header, 0, sizeof (header));
	memcpy (header.signature, CERBERUS_TCG_LOG_SIGNATURE, sizeof (header.signature));

	header.platform_class = CERBERUS_TCG_SERVER_PLATFORM_CLASS;
	header.spec_version_minor = 0;
	header.spec_version_major = 2;
	header.spec_errata = 0;
	header.uintn_size = CERBERUS_TCG_UINT_SIZE_32;
	header.num_algorithms = CERBERUS_TCG_NUM_ALG;
	header.digest_sizes[0].digest_algorithm_id = CERBERUS_TCG_SHA256_ALG_ID;
	header.digest_sizes[0].digest_size = CERBERUS_SHA256_HASH_LEN;
	header.vendor_info_size = CERBERUS_TCG_VENDOR_INFO_SIZE;

	log_buffer = malloc (sizeof (char) * CERBERUS_MAX_LOG_SIZE);
	if (log_buffer == NULL) {
		status = STATUS_NO_MEM;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		goto exit;
	}

	log_max_size = CERBERUS_MAX_LOG_SIZE;

	memcpy (log_buffer, &old_event, sizeof (old_event));
	log_index += sizeof (old_event);

	memcpy (&log_buffer[log_index], &header, sizeof (header));
	log_index += sizeof (header);

	for (i_entry = 0; i_entry < entry_count; ++i_entry) {
		event.pcr_bank = (uint8_t) (entries[i_entry].measurement_type >> 8);
		event.event_type = entries[i_entry].event_type;
		event.digest_count = 1;
		event.digest_algorithm_id = CERBERUS_TCG_SHA256_ALG_ID;
		event.event_size = 0;

		event_size = 0;

		if (platform_tcg_log_intf->post_process_event_entry) {
			platform_tcg_log_intf->post_process_event_entry (intf, ids, &event);
		}

		memcpy (event.digest, entries[i_entry].digest, sizeof (event.digest));
		status = realloc_and_copy_msg_log (intf, &log_buffer, &log_max_size, &log_index,
			(uint8_t*) &event, sizeof (event));
		if (status != STATUS_SUCCESS) {
			goto exit;
		}
		event_size_pos = log_index - sizeof (event.event_size);

		do {
			uint8_t *payload_buf = NULL;
			payload_len = 6;

			intf->cmd_buf[0] = event.pcr_bank;
			intf->cmd_buf[1] = (uint8_t) entries[i_entry].measurement_type;

			memcpy (&intf->cmd_buf[2], &event_size, sizeof (uint32_t));

			status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
				CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, intf->params->device_eid, true,
				intf->cmd_buf, &payload_len);
			if (status != STATUS_SUCCESS) {
				goto exit;
			}

			if (payload_len == 0) {
				if (platform_tcg_log_intf->post_process_event_data) {
					platform_tcg_log_intf->post_process_event_data (intf, event, &payload_buf,
						&payload_len);
				}
			} else {
				payload_buf = intf->cmd_buf;
			}

			if (payload_buf != NULL) {
				status = realloc_and_copy_msg_log (intf, &log_buffer, &log_max_size, &log_index,
					payload_buf, payload_len);
				if (status != STATUS_SUCCESS) {
					goto exit;
				}
			}

			event_size += (uint32_t) payload_len;
		} while (payload_len == intf->mctp.read.max_payload_per_msg);

		memcpy (&log_buffer[event_size_pos], &event_size, sizeof (event_size));
	}

	*tcg_log = log_buffer;
	*log_len = log_index;

exit:
	if (status != STATUS_SUCCESS) {
		cerberus_free (log_buffer);
	}
	cerberus_free ((uint8_t*) entries);

	return status;
}

/**
 * Retrieve and export TCG event log generated by utility to file
 *
 * @param intf The Cerberus interface to utilize
 * @param filename File name to save TCG event log to
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_tcg_log_through_utility_file (struct cerberus_interface *intf,
	const char *filename)
{
	char *tcg_buffer = NULL;
	size_t tcg_buffer_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_export_tcg_log_through_utility_memory (intf, &tcg_buffer, &tcg_buffer_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_write_file (intf, filename, (uint8_t*) tcg_buffer, tcg_buffer_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

exit:
	cerberus_free (tcg_buffer);
	return status;
}

/**
 * Verify TCG event log entries are consistent
 *
 * @param intf The Cerberus interface to utilize.
 * @param tcg_log TCG formatted log.  Will be freed if contents invalid.
 * @param log_len TCG log length.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_verify_tcg_log (struct cerberus_interface *intf, char *tcg_log, size_t log_len)
{
	UNUSED (intf);

#ifdef CERBERUS_ENABLE_CRYPTO
	struct hash_engine_mbedtls hash;
	struct tcg_event2 *event;
	uint8_t digest[CERBERUS_SHA256_HASH_LEN];
	uint8_t *event_data;
	size_t offset = sizeof (struct tcg_event) + sizeof (struct tcg_log_header);
	int status;

	status = hash_mbedtls_init (&hash);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	while (offset < log_len) {
		if (((int) (log_len - (offset + sizeof (struct tcg_event2)))) < 0) {
			status = STATUS_LOG_LEN_INVALID;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_LOG_LEN_INVALID));
			goto release_log;
		}

		event = (struct tcg_event2*) &(tcg_log)[offset];
		event_data = (uint8_t*) event + sizeof (struct tcg_event2);

		if (((int) (log_len - (offset + sizeof (struct tcg_event2) + event->event_size))) < 0) {
			status = STATUS_LOG_LEN_INVALID;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_LOG_LEN_INVALID));
			goto release_log;
		}

		status = hash.base.calculate_sha256 (&hash.base, event_data, event->event_size,
			digest, sizeof (digest));
		if (status != STATUS_SUCCESS) {
			goto release_log;
		}

		if (memcmp (event->digest, digest, sizeof (digest)) != 0) {
			status = STATUS_LOG_CONTENTS_INCONSISTENT;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_LOG_CONTENTS_INCONSISTENT));
			goto release_log;
		}

		offset += (sizeof (struct tcg_event2) + event->event_size);
	}

	goto release_hash;

release_log:
	cerberus_free (tcg_log);

release_hash:
	hash_mbedtls_release (&hash);

	return status;
#else
	UNUSED (tcg_log);
	UNUSED (log_len);
	return STATUS_SUCCESS;
#endif
}

/**
 * Retrieve and export TCG event log generated by FW to a buffer
 *
 * @param intf The Cerberus interface to utilize.
 * @param tcg_log Output buffer that will be filled with the formatted tcg log.  MUST BE FREED
 *  BY CALLER using cerberus_free().
 * @param log_len Output for the total length of the output buffer.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_tcg_log_through_fw_memory (struct cerberus_interface *intf,
	char **tcg_log, size_t *log_len)
{
	int num_retries = 1;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (tcg_log == NULL) || (log_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	while (num_retries > 0) {
		status = cerberus_log_read (intf, CERBERUS_TCG_LOG, (uint8_t**) tcg_log, log_len);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		status = cerberus_verify_tcg_log (intf, *tcg_log, *log_len);
		if (status == STATUS_SUCCESS) {
			return status;
		}

		--num_retries;
	}

	return status;
}

/**
 * Retrieve and export TCG event log generated by FW to file
 *
 * @param intf The Cerberus interface to utilize
 * @param filename File name to save TCG event log to
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_tcg_log_through_fw_file (struct cerberus_interface *intf,
	const char *filename)
{
	char *tcg_buffer = NULL;
	size_t tcg_buffer_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_export_tcg_log_through_fw_memory (intf, &tcg_buffer, &tcg_buffer_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_write_file (intf, filename, (uint8_t*) tcg_buffer, tcg_buffer_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

exit:
	cerberus_free (tcg_buffer);
	return status;
}

/**
 * Retrieve and export TCG event log to a buffer
 *
 * @param intf The Cerberus interface to utilize.
 * @param tcg_log Output buffer that will be filled with the formatted tcg log.  MUST BE FREED
 *  BY CALLER using cerberus_free().
 * @param log_len Output for the total length of the output buffer.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_tcg_log_memory (struct cerberus_interface *intf, char **tcg_log,
	size_t *log_len)
{
	int status;

	status = cerberus_export_tcg_log_through_fw_memory (intf, tcg_log, log_len);
	if (status == STATUS_MCTP_FAILURE) {
		status = cerberus_export_tcg_log_through_utility_memory (intf, tcg_log, log_len);
	}

	return status;
}

/**
 * Retrieve and export TCG event log to file. The function will first attempt to get TCG log
 * generated by FW, and if it fails, will resort to TCG log generated by utility.
 *
 * @param intf The Cerberus interface to utilize
 * @param filename File name to save TCG event log to
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_export_tcg_log_file (struct cerberus_interface *intf, const char *filename)
{
	char *tcg_buffer = NULL;
	size_t tcg_buffer_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_export_tcg_log_memory (intf, &tcg_buffer, &tcg_buffer_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_write_file (intf, filename, (uint8_t*) tcg_buffer, tcg_buffer_len);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

exit:
	cerberus_free (tcg_buffer);
	return status;
}

/**
 * Get the digests for each certificate in a specified chain using protocol version 4 or higher
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The slot identifier for the requested certificate chain
 * @param digests Output for the certificate digests.  MUST BE FREED BY CALLER USING
 *  cerberus_free_digests().
 * @param key_exchange_algo Key exchange algorithm to set
 *
 * @return STATUS_SUCCESS if the digests were retrieved successfully or an error code.
 */
LIB_EXPORT int cerberus_get_digests_with_key_exchange (struct cerberus_interface *intf,
	uint8_t slot_num, struct cerberus_digests *digests,
	enum cerberus_key_exchange_algorithms key_exchange_algo)
{
	size_t payload_len;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (digests == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (intf->protocol_version < 4) {
		key_exchange_algo = CERBERUS_ECDHE_KEY_EXCHANGE;
	}

	intf->cmd_buf[0] = slot_num;
	intf->cmd_buf[1] = key_exchange_algo;

	payload_len = 2;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_DIGEST, intf->params->device_eid, false, intf->cmd_buf, &payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len < 2) {
		status = STATUS_UNEXPECTED_RLEN;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), payload_len, 2);
		return status;
	}

	if (payload_len < ((size_t) (2 + (intf->cmd_buf[1] * 32)))) {
		status = STATUS_UNEXPECTED_RLEN;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), payload_len, 2 + (intf->cmd_buf[1] * 32));
		return status;
	}

	if (intf->cmd_buf[1] != 0) {
		digests->digest = calloc (intf->cmd_buf[1], 32);
		if (digests->digest == NULL) {
			status = STATUS_NO_MEM;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (status));
			return status;
		}

		digests->num_digest = intf->cmd_buf[1];
		digests->digest_len = 32;
		memcpy (digests->digest, &intf->cmd_buf[2], 32 * digests->num_digest);
	}
	else {
		status = STATUS_NO_CERTIFICATE;
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "%s",
			cerberus_utility_get_errors_str (status));
	}

	return status;
}

/**
 * Get the digests for each certificate in a specified chain.
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The slot identifier for the requested certificate chain
 * @param digests Output for the certificate digests.  MUST BE FREED BY CALLER USING
 *  cerberus_free_digests().
 *
 * @return STATUS_SUCCESS if the digests were retrieved successfully or an error code.
 */
LIB_EXPORT int cerberus_get_digests (struct cerberus_interface *intf, uint8_t slot_num,
	struct cerberus_digests *digests)
{
	return cerberus_get_digests_with_key_exchange (intf, slot_num, digests,
		CERBERUS_KEYS_EXCHANGE_NONE);
}

/**
 * Free retrieved certificate digests.
 *
 * @param digests The digests container to free.
 */
LIB_EXPORT void cerberus_free_digests (struct cerberus_digests *digests)
{
	if (digests) {
		free (digests->digest);
	}
}

/**
 * Initialize list of SVNs.
 *
 * @param svns Pointer to a buffer that holds the SVN list.
 *
 * @return STATUS_SUCCESS if the SVN list was initialized successfully.
 */
static int cerberus_init_svn_list (struct cerberus_svns *svns)
{
	int status = STATUS_SUCCESS;

	svns->list = calloc (2, sizeof (struct cerberus_svn));
	if (svns->list == NULL) {
		status = STATUS_NO_MEM;
		goto exit;
	}

exit:
	return status;
}

/**
 * Free retrieved SVNs.
 *
 * @param svns The svn list container to free.
 */
LIB_EXPORT void cerberus_free_svns (struct cerberus_svns *svns)
{
	if (svns) {
		if (svns->list) {
			uint8_t i = 0;
			while (i != svns->num_svn) {
				free (svns->list[i].svn_data);
				i++;
			}
			free (svns->list);
		}
		svns->num_svn = 0;
	}
}

/**
 * Helper function to extract the required SVN number from a given certificate.
 *
 * @param intf Cerberus utility interface to utilize
 * @param cert The cerberus certificate pointer.
 * @param svn Pointer to the buffer that stores the SVN.
 *
 * @return STATUS_SUCCESS if the SVN was extracted successfully.
 */
static int cerberus_get_svn_from_dice_tcbinfo (struct cerberus_interface *intf,
	struct cerberus_cert *cert, struct cerberus_svn *svn)
{
	uint8_t *pos;
	uint8_t *end;
	uint8_t *ext_end;
	size_t length;
	mbedtls_x509_crt certificate;
	int status;

	mbedtls_x509_crt_init (&certificate);

	status = mbedtls_x509_crt_parse_der_nocopy (&certificate, (unsigned char*) cert->cert,
		(size_t) cert->cert_len);
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
		status = STATUS_MBEDTLS_FAILURE;
		goto exit;
	}

	pos = certificate.v3_ext.p;
	end = pos + certificate.v3_ext.len;

	status = mbedtls_asn1_get_tag (&pos, end, &length,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
		status = STATUS_MBEDTLS_FAILURE;
		goto exit;
	}

	while (pos < end) {
		status = mbedtls_asn1_get_tag (&pos, end, &length,
			(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
			status = STATUS_MBEDTLS_FAILURE;
			goto exit;
		}

		ext_end = pos + length;

		status = mbedtls_asn1_get_tag (&pos, end, &length, MBEDTLS_ASN1_OID);
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
			status = STATUS_MBEDTLS_FAILURE;
			goto exit;
		}

		if ((length != MBEDTLS_OID_SIZE (X509_TCG_DICE_TCBINFO_OID_RAW)) ||
			(memcmp (X509_TCG_DICE_TCBINFO_OID_RAW, pos, length) != 0)) {
			pos = ext_end;
			continue;
		}

		pos += length;
		mbedtls_asn1_get_bool (&pos, ext_end, &status);

		status = mbedtls_asn1_get_tag (&pos, end, &length, MBEDTLS_ASN1_OCTET_STRING);
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
			status = STATUS_MBEDTLS_FAILURE;
			goto exit;
		}

		status = mbedtls_asn1_get_tag (&pos, end, &length,
			(MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED));
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
			status = STATUS_MBEDTLS_FAILURE;
			goto exit;
		}

		status = mbedtls_asn1_get_tag (&pos, end, &length, (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2));
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
			status = STATUS_MBEDTLS_FAILURE;
			goto exit;
		}

		pos += length;

		status = mbedtls_asn1_get_tag (&pos, end, &length, (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 3));
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MBEDTLS_FAILURE), status);
			status = STATUS_MBEDTLS_FAILURE;
			goto exit;
		}

		// Update the SVN data in the list.
		svn->svn_length = length;
		svn->svn_data = calloc (1, length);
		if (svn->svn_data == NULL) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_NO_MEM));
			status = STATUS_NO_MEM;
			goto exit;
		}
		memcpy (svn->svn_data, (uint8_t*) pos, length);

		goto exit;
	}

	// Ideally, we shouldn't reach here.
	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		"Unexpected Value received.");
	status = STATUS_UNEXPECTED_VALUE;

exit:
	mbedtls_x509_crt_free (&certificate);
	return status;
}

/**
 * Retrieve the hardware/software security version number (SVN).
 *
 * @param intf The Cerberus interface to utilize.
 * @param svns Pointer to output list of SVNs, MUST BE FREED BY CALLER USING
 * cerberus_free_svns().
 *
 * @return STATUS_SUCCESS if the SVNs were retrieved successfully or an error code.
 */
LIB_EXPORT int cerberus_get_svn_number (struct cerberus_interface *intf, struct cerberus_svns *svns)
{
	struct cerberus_cert_chain chain;
	struct cerberus_cert cert;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (svns == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	memset (svns, 0, sizeof (struct cerberus_svns));

	status = cerberus_get_cert_chain (intf, 0, &chain);
	if (status != STATUS_SUCCESS) {
		goto exit;
	}

	status = cerberus_init_svn_list (svns);
	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
			__LINE__, "Failed to initialize list of SVNs");
		goto exit_free_certchain;
	}

	// Get the L0 SVN.
	status = cerberus_get_cert (intf, 0, (chain.num_cert - 2), &cert);
	if (status != STATUS_SUCCESS) {
		goto exit_free_svn;
	}

	status = cerberus_get_svn_from_dice_tcbinfo (intf, &cert, &(svns->list[svns->num_svn++]));
	if (status != STATUS_SUCCESS) {
		goto exit_free_cert;
	}

	cerberus_free_cert (&cert);

	// Get the L1 SVN.
	status = cerberus_get_cert (intf, 0, (chain.num_cert - 1), &cert);
	if (status != STATUS_SUCCESS) {
		goto exit_free_svn;
	}

	status = cerberus_get_svn_from_dice_tcbinfo (intf, &cert, &(svns->list[svns->num_svn++]));

exit_free_cert:
	cerberus_free_cert (&cert);
exit_free_svn:
	if (status != STATUS_SUCCESS) {
		cerberus_free_svns (svns);
	}
exit_free_certchain:
	cerberus_free_cert_chain (&chain);

exit:
	return status;
}

/**
 * Retrieve a single certificate and report the error code if it fails.
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The slot for the requested certificate
 * @param cert_num Certificate identifier to retrieve
 * @param cert Output container for the certificate.  MUST BE FREED BY CALLER USING
 *  cerberus_free_cert()
 * @param cert_error Output for the response error code.
 *
 * @return STATUS_SUCCESS if the certificate was retrieved successfully or an error code.
 */
static int cerberus_get_cert_with_error (struct cerberus_interface *intf, uint8_t slot_num,
	uint8_t cert_num, struct cerberus_cert *cert, uint32_t *cert_error)
{
	uint16_t offset = 0;
	size_t payload_len;
	uint8_t *cert_data;
	int status;

	cert->cert = NULL;
	cert->cert_len = 0;

	do {
		if (cert->cert_len > 4096) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				"Received certificate exceeds maximum length.");
			status = STATUS_BUF_TOO_SMALL;
			goto exit;
		}

		intf->cmd_buf[0] = slot_num;
		intf->cmd_buf[1] = cert_num;
		*((uint16_t*) &intf->cmd_buf[2]) = offset;
		*((uint16_t*) &intf->cmd_buf[4]) = 0;

		payload_len = 6;

		status = cerberus_protocol_send_and_read_variable_rsp_get_error (intf, __func__, __LINE__,
			CERBERUS_PROTOCOL_GET_CERTIFICATE, intf->params->device_eid, false, intf->cmd_buf,
			&payload_len, NULL, cert_error);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		if (payload_len < 2) {
			status = STATUS_UNEXPECTED_RLEN;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status), payload_len, 2);
			goto exit;
		}

		if (intf->cmd_buf[0] != slot_num) {
			status = STATUS_CMD_RESPONSE;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status), slot_num, intf->cmd_buf[0]);
			goto exit;
		}

		if (intf->cmd_buf[1] != cert_num) {
			status = STATUS_CMD_RESPONSE;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status), cert_num, intf->cmd_buf[1]);
			goto exit;
		}

		if (payload_len > 2) {
			cert_data = realloc (cert->cert, cert->cert_len + (payload_len - 2));
			if (cert_data == NULL) {
				status = STATUS_NO_MEM;
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (status));
				goto exit;
			}

			cert->cert = cert_data;
			memcpy (&cert->cert[offset], &intf->cmd_buf[2], payload_len - 2);
			cert->cert_len += payload_len - 2;
			offset += (uint16_t) payload_len - 2;
		}
	} while (payload_len == intf->mctp.read.max_payload_per_msg);

	return 0;

exit:
	cerberus_free_cert (cert);
	return status;
}

/**
 * Retrive a single certificate from Cerberus
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The slot for the requested certificate
 * @param cert_num Certificate identifier to retrieve
 * @param cert Output container for the certificate.  MUST BE FREED BY CALLER USING
 *  cerberus_free_cert()
 *
 * @return STATUS_SUCCESS if the certificate was retrieved successfully or an error code.
 */
LIB_EXPORT int cerberus_get_cert (struct cerberus_interface *intf, uint8_t slot_num,
	uint8_t cert_num, struct cerberus_cert *cert)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (cert == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_cert_with_error (intf, slot_num, cert_num, cert, NULL);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (cert->cert_len == 0) {
		status = STATUS_NO_CERTIFICATE;
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "%s",
			cerberus_utility_get_errors_str (status));
	}

	return status;
}

/**
 * Retrieve a complete certificate chain from Cerberus using protocol v2.
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The certificate slot to query
 * @param chain Output container for the certificate chain.  MUST BE FREED BY CALLER USING
 *  cerberus_free_cert_chain()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_get_cert_chain_v2 (struct cerberus_interface *intf, uint8_t slot_num,
	struct cerberus_cert_chain *chain)
{
	uint8_t i_cert;
	int status = STATUS_SUCCESS;
	uint32_t cert_error;

	chain->cert = calloc (3, sizeof (struct cerberus_cert));
	if (chain->cert == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	chain->num_cert = 0;

	for (i_cert = 0; i_cert < 3; ++i_cert) {
		status = cerberus_get_cert_with_error (intf, slot_num, i_cert,
			&chain->cert[chain->num_cert], &cert_error);
		if ((status == STATUS_MCTP_FAILURE) && (cert_error == 0x7f002c0c) && (i_cert == 0)) {
			/* We won't always get an intermediate CA. */
			continue;
		}
		else if (status != STATUS_SUCCESS) {
			goto exit;
		}

		chain->num_cert++;
	}

	return status;

exit:
	cerberus_free_cert_chain (chain);
	return status;
}

/**
 * Retrieve a complete certificate chain from Cerberus using protocol v4 or greater
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The certificate slot to query
 * @param chain Output container for the certificate chain.  MUST BE FREED BY CALLER USING
 *  cerberus_free_cert_chain()
 * @param key_exchange_algo Key exchange algorithm to set.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_cert_chain_with_key_exchange (struct cerberus_interface *intf,
	uint8_t slot_num, struct cerberus_cert_chain *chain,
	enum cerberus_key_exchange_algorithms key_exchange_algo)
{
	int status = STATUS_SUCCESS;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (chain == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (intf->protocol_version < 3) {
		return cerberus_get_cert_chain_v2 (intf, slot_num, chain);
	}
	else {
		struct cerberus_digests digests;
		int i;

		status = cerberus_get_digests_with_key_exchange (intf, slot_num, &digests,
			key_exchange_algo);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		chain->num_cert = (uint8_t) digests.num_digest;
		cerberus_free_digests (&digests);

		chain->cert = calloc (chain->num_cert, sizeof (struct cerberus_cert));
		if (chain->cert == NULL) {
			status = STATUS_NO_MEM;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (status));
			return status;
		}

		for (i = 0; i < chain->num_cert; i++) {
			status = cerberus_get_cert (intf, slot_num, i, &chain->cert[i]);
			if (status != STATUS_SUCCESS) {
				goto exit;
			}
		}
	}

	return 0;

exit:
	cerberus_free_cert_chain (chain);
	return status;
}

/**
 * Retrieve a complete certificate chain from Cerberus
 *
 * @param intf The Cerberus interface to utilize
 * @param slot_num The certificate slot to query
 * @param chain Output container for the certificate chain.  MUST BE FREED BY CALLER USING
 *  cerberus_free_cert_chain()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_cert_chain (struct cerberus_interface *intf, uint8_t slot_num,
	struct cerberus_cert_chain *chain)
{
	return cerberus_get_cert_chain_with_key_exchange (intf, slot_num, chain,
		CERBERUS_KEYS_EXCHANGE_NONE);
}

/**
 * Free a single certificate
 *
 * @param cert Certificate to free.
 */
LIB_EXPORT void cerberus_free_cert (struct cerberus_cert *cert)
{
	if (cert != NULL) {
		free (cert->cert);
		cert->cert = NULL;
		cert->cert_len = 0;
	}
}

/**
 * Free complete certificate chain
 *
 * @param chain Certificate chain to release
 */
LIB_EXPORT void cerberus_free_cert_chain (struct cerberus_cert_chain *chain)
{
	int i;

	if (chain != NULL) {
		if (chain->cert != NULL) {
			for (i = 0; i < chain->num_cert; i++) {
				cerberus_free_cert (&chain->cert[i]);
			}

			free (chain->cert);
			chain->cert = NULL;
			chain->num_cert = 0;
		}
	}
}

/**
 * Retrieve attestation unsealing result
 *
 * @param intf The Cerberus interface to utilize
 * @param attestation_status Output buffer for the attestation status
 * @param encryption_key Output buffer for the encrypted key
 * @param encryption_key_len Size of the encryption key buffer, output the size of the key
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_get_unsealing_result (struct cerberus_interface *intf,
	uint32_t *attestation_status, uint8_t *encryption_key, uint16_t *encryption_key_len)
{
	size_t payload_len = 0;
	uint16_t key_len;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT, intf->params->device_eid, false, intf->cmd_buf,
		&payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len < sizeof (uint32_t)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len, sizeof (uint32_t));
		return STATUS_UNEXPECTED_RLEN;
	}

	*attestation_status = *((uint32_t*) intf->cmd_buf);

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Unsealing Status: %i\n", *attestation_status);
	}

	if (*attestation_status == ATTESTATION_CMD_STATUS_SUCCESS) {
		key_len = *((uint16_t*) &intf->cmd_buf[sizeof (uint32_t)]);

		if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
			cerberus_print_info ("Unsealing key length: %i\n", key_len);
		}

		if (payload_len != (sizeof (uint32_t) + sizeof (uint16_t) + key_len)) {
			status = STATUS_UNEXPECTED_RLEN;
			sprintf (errorstr, cerberus_utility_get_errors_str (status), payload_len,
				sizeof (uint32_t) + sizeof (uint16_t) + key_len);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				errorstr);
			return status;
		}

		if (key_len > *encryption_key_len) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
			return STATUS_BUF_TOO_SMALL;
		}

		memcpy (encryption_key, &intf->cmd_buf[sizeof (uint32_t) + sizeof (uint16_t)], key_len);
		*encryption_key_len = key_len;
	}

	return STATUS_SUCCESS;
}

/**
 * Unseal an encryption key using the device measurements.
 *
 * @param intf The Cerberus interface to utilize
 * @param seed The request seed for key derivation
 * @param seed_len The length of the request seed
 * @param seed_type The type of seed being used
 * @param seed_params Additional parameters for the seed
 * @param cipher The encrypted attestation data
 * @param cipher_length Length of the encrypted data
 * @param hmac The HMAC-SHA256 for the attestation request
 * @param sealing List of PMRs to unseal against
 * @param encryption_key Output buffer for the unsealed encryption key that will decrypt the
 *  attestation data
 * @param encryption_key_len Size of the encryption key buffer, updated with the length of the
 *  encryption key
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_message_unseal (struct cerberus_interface *intf, const uint8_t *seed,
	uint16_t seed_len, uint8_t seed_type, uint8_t seed_params, const uint8_t *cipher,
	uint16_t cipher_len, const uint8_t *hmac, const uint8_t sealing[5][64], uint8_t *encryption_key,
	uint16_t *encryption_key_len)
{
	uint32_t attestation_status = ATTESTATION_CMD_STATUS_UNKNOWN;
	size_t offset;
	unsigned long start_time;
	uint16_t hmac_len = 32;	// Only SHA256 HMAC is supported.
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (seed == NULL) || (seed_len == 0) ||
		(cipher == NULL) || (cipher_len == 0) || (hmac == NULL) || (sealing == NULL) ||
		(encryption_key == NULL) || (encryption_key_len == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	if (*encryption_key_len < CERBERUS_PROTOCOL_UNSEAL_MAX_KEY_LENGTH) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
		return STATUS_BUF_TOO_SMALL;
	}

	/* Ensure the total command fits in a single message. */
	if ((seed_len + cipher_len + hmac_len + (sizeof (*sealing) * 5) + 8) >
		cerberus_protocol_get_max_payload_len_per_msg (intf)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_PAYLOAD_TOO_LARGE));
		return STATUS_PAYLOAD_TOO_LARGE;
	}

	if (intf->protocol_version < 3) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_PROTOCOL_INCOMPATIBLE), intf->protocol_version);
		return STATUS_PROTOCOL_INCOMPATIBLE;
	}

	intf->cmd_buf[0] = seed_type;
	intf->cmd_buf[1] = seed_params;
	offset = 2;

	*((uint16_t*) &intf->cmd_buf[offset]) = seed_len;
	memcpy (&intf->cmd_buf[offset + 2], seed, seed_len);
	offset += 2 + seed_len;

	*((uint16_t*) &intf->cmd_buf[offset]) = cipher_len;
	memcpy (&intf->cmd_buf[offset + 2], cipher, cipher_len);
	offset += 2 + cipher_len;

	*((uint16_t*) &intf->cmd_buf[offset]) = hmac_len;
	memcpy (&intf->cmd_buf[offset + 2], hmac, hmac_len);
	offset += 2 + hmac_len;

	memcpy (&intf->cmd_buf[offset], sealing, sizeof (*sealing) * 5);
	offset += sizeof (*sealing) * 5;

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_UNSEAL_MESSAGE, intf->params->device_eid, false, intf->cmd_buf, offset);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	cerberus_print_info ("Started message unsealing on Cerberus.\n");

	start_time = cerberus_common_get_cpu_time_ms ();

	while (attestation_status != ATTESTATION_CMD_STATUS_SUCCESS) {
		status = cerberus_get_unsealing_result (intf, &attestation_status, encryption_key,
			encryption_key_len);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		switch (attestation_status & 0xFF) {
			case ATTESTATION_CMD_STATUS_SUCCESS:
				break;

			case ATTESTATION_CMD_STATUS_RUNNING:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_print_info (".");
				fflush (stdout);
				cerberus_common_sleep_ms (50);
				break;

			case ATTESTATION_CMD_STATUS_FAILURE:
				snprintf (errorstr, sizeof (errorstr),
					attestation_cmd_statuses_str[ATTESTATION_CMD_STATUS_FAILURE],
					attestation_status >> 8);
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, "Unseal operation failed: %s", errorstr);


				status = STATUS_ATTESTATION_FAILURE;
				goto exit;

			default:
				if (attestation_status < NUM_ATTESTATION_CMD_STATUS) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, "Unseal operation failed: %s",
						attestation_cmd_statuses_str[attestation_status]);
				}
				else {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, "Unseal operation failed: 0x%x",
						attestation_status);
				}

				status = STATUS_ATTESTATION_FAILURE;
				goto exit;
		}
	}

exit:
	cerberus_print_info ("\n");
	return status;
}

/**
 * Unseal an encryption key using an RSA attestation key.
 *
 * @param intf The Cerberus interface to utilize
 * @param seed The request seed encrypted with the attestation public key
 * @param seed_len The length of the request seed
 * @param seed_padding The padding scheme used to encrypt the seed
 * @param cipher The encrypted attestation data
 * @param cipher_len Length of the encrypted data
 * @param hmac The HMAC-SHA256 for the attestation request
 * @param sealing List of PMRs to unseal against
 * @param encryption_key Output buffer for the unsealed encryption key that will decrypt the
 *  attestation data
 * @param encryption_key_len Size of the encryption key buffer, updated with the length of the
 *  encryption key
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_message_unseal_rsa (struct cerberus_interface *intf, const uint8_t *seed,
	uint16_t seed_len, enum cerberus_unseal_seed_padding seed_padding, const uint8_t *cipher,
	uint16_t cipher_len, const uint8_t *hmac, const uint8_t sealing[5][64], uint8_t *encryption_key,
	uint16_t *encryption_key_len)
{
	return cerberus_message_unseal (intf, seed, seed_len, 0, seed_padding, cipher, cipher_len, hmac,
		sealing, encryption_key, encryption_key_len);
}

/**
 * Unseal an encryption key using an ECC attestation key.
 *
 * @param intf The Cerberus interface to utilize
 * @param seed The request seed encrypted with the attestation public key
 * @param seed_len The length of the request seed
 * @param seed_processing Processing that is required on the ECDH output to generate the seed.
 * @param cipher The encrypted attestation data
 * @param cipher_len Length of the encrypted data
 * @param hmac The HMAC-SHA256 for the attestation request
 * @param sealing A 64-byte sealing value for the attestation data
 * @param encryption_key Output buffer for the unsealed encryption key that will decrypt the
 * 	attestation data, MUST BE FREED BY CALLER using cerberus_free_encryption_key
 * @param encryption_key_len Output for the length of the encryption key.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_message_unseal_ecc (struct cerberus_interface *intf, const uint8_t *seed,
	uint16_t seed_len, enum cerberus_unseal_seed_processing seed_processing, const uint8_t *cipher,
	uint16_t cipher_len, const uint8_t *hmac, const uint8_t sealing[5][64], uint8_t *encryption_key,
	uint16_t *encryption_key_len)
{
	return cerberus_message_unseal (intf, seed, seed_len, 1, seed_processing, cipher, cipher_len,
		hmac, sealing, encryption_key, encryption_key_len);
}

/**
 * Retrieve and print out Cerberus device ID CSR
 *
 * @param intf The Cerberus interface to utilize
 * @param filename The file to export CSR
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_devid_csr (struct cerberus_interface *intf, const char *filename)
{
	FILE *file = NULL;
	uint8_t index = 0;
	size_t payload_len = sizeof (index);
	size_t i_payload;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = index;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_EXPORT_CSR, intf->params->device_eid, true, intf->cmd_buf, &payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len < 1) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_UNEXPECTED_RLEN), payload_len, 1);
		return STATUS_UNEXPECTED_RLEN;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Cerberus Device ID CSR:\n");

		for (i_payload = 0; i_payload <= payload_len; ++i_payload) {
			cerberus_print_info ("%02x", intf->cmd_buf[i_payload]);
		}
		cerberus_print_info ("\n");
	}

	file = fopen (filename, "wb");
	if (file == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_OPEN_FILE_FAILED), filename);
		return STATUS_OPEN_FILE_FAILED;
	}

	fwrite (intf->cmd_buf, 1, payload_len, file);
	fclose (file);

	return STATUS_SUCCESS;
}

/**
 * Retrieve the state of the state of stored RIoT certificates.
 *
 * @param intf The Cerberus interface to utilize
 * @param cert_state Output buffer for the certificate state
 * @param error_data Optional output for details in case of an error.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_riot_cert_state (struct cerberus_interface *intf, uint32_t *cert_state,
	uint32_t *error_data)
{
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (cert_state == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_and_read_rsp_get_error (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE, intf->params->device_eid, sizeof (uint32_t), false,
		intf->cmd_buf, 0, NULL, error_data);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (cert_state, intf->cmd_buf, sizeof (uint32_t));

	if ((*cert_state & 0xFF) < NUM_RIOT_CERT_STATES) {
		snprintf (errorstr, sizeof (errorstr), riot_cert_state_str[*cert_state & 0xFF],
			*cert_state >> 8);
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "Device Certificate State: %s",
			errorstr);
	}
	else {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "Device Certificate State: 0x%x",
			*cert_state);
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Device Certificate State: %i\n", *cert_state);
	}

	return STATUS_SUCCESS;
}

/**
 * Send a signed CA certificate
 *
 * @param intf The Cerberus interface to utilize
 * @param cert_num The certificate id to import
 * @param name The file to import signed certificate from
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_send_signed_ca_certificate (struct cerberus_interface *intf,
	uint8_t cert_num, const char *name)
{
	uint8_t *buffer = NULL;
	size_t length = 0;
	size_t index = 0;
	size_t max_per_msg;
	size_t size;
	uint8_t error_code;
	uint32_t error_data;
	unsigned long start_time;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (name == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_read_file (intf, name, &buffer, &size);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (size == 0) {
		status = STATUS_INVALID_UPDATE_FILE;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), name);
		goto exit;
	}

	intf->cmd_buf[0] = cert_num;
	memcpy (&intf->cmd_buf[1], &size, sizeof (uint16_t));

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("certificate size: %zd\r\n", size);
	}

	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);

	length = MIN (max_per_msg - (1 + sizeof (uint16_t)), size);
	memcpy (&intf->cmd_buf[1 + sizeof (uint16_t)], &buffer[index], length);

	status = cerberus_protocol_send_no_rsp_get_error (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT, intf->params->device_eid, true, intf->cmd_buf,
		length + 3, &error_code, &error_data);
	if ((status != STATUS_SUCCESS) && (status != STATUS_MCTP_FAILURE)) {
		goto exit;
	}

	if (status == STATUS_MCTP_FAILURE) {
		if (error_data == 0x7f002902) {
			status = STATUS_CERT_PROVISIONING_LOCKED;
			snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
				"Certificate provisioning locked");
		}
		goto exit;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	do {
		if (cerberus_common_timeout_expired (start_time, CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
			status = STATUS_OPERATION_TIMEOUT;
		}
		else {
			status = cerberus_get_riot_cert_state (intf, &error_data, &error_data);
			if ((status == STATUS_MCTP_FAILURE) && (error_data == 0x7f001506)) {
				/* Status command is unsupported by the firmware, so just return success. */
				status = STATUS_SUCCESS;
				error_data = 0xff;
			}
		}
	} while ((status == STATUS_SUCCESS) && ((error_data & 0xFF) == RIOT_CERT_STATE_VALIDATING));

	if (status == STATUS_SUCCESS) {
		cerberus_print_info ("Done sending signed CA certificate.\n");

		if (error_data != 0xff) {
			if ((error_data & 0xFF) < NUM_RIOT_CERT_STATES) {
				snprintf (errorstr, sizeof (errorstr), riot_cert_state_str[error_data & 0xFF],
					error_data >> 8);
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Device Certificate State: %s", errorstr);
			}
			else {
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Device Certificate State: 0x%x", error_data);
			}
		}
	}

exit:
	if (buffer) {
		free (buffer);
	}

	return status;
}

/**
 * Start a Cerberus manifest update
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest_type Type of manifest to update
 * @param size Size of manifest file
 * @param update_status Output buffer to be filled in with update status info
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_manifest_update_init (struct cerberus_interface *intf, uint8_t manifest_type,
	uint32_t size, struct cerberus_fw_update_status *update_status)
{
	unsigned long start_time;
	uint8_t command_id;
	char manifest_string[10] = "Manifest";
	struct cerberus_manifest_request manifest;
	int status;

	switch (manifest_type) {
		case CERBERUS_MANIFEST_CFM:
			command_id = CERBERUS_PROTOCOL_INIT_CFM_UPDATE;
			strcpy (manifest_string, "CFM");
			break;

		case CERBERUS_MANIFEST_PCD:
			command_id = CERBERUS_PROTOCOL_INIT_PCD_UPDATE;
			strcpy (manifest_string, "PCD");
			break;

		default:
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
			return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__, command_id,
		intf->params->device_eid, false, (uint8_t*) &size, sizeof (uint32_t));
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	manifest.port = 0;
	manifest.manifest_type = manifest_type;
	while (1) {
		status = cerberus_get_manifest_update_status (intf, &manifest, update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (update_status->status_code) {
			case MANIFEST_CMD_STATUS_STARTING:
			case MANIFEST_CMD_STATUS_PREPARE:
			case MANIFEST_CMD_STATUS_NONE_STARTED:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				if (update_status->status_code == MANIFEST_CMD_STATUS_SUCCESS) {
					return STATUS_SUCCESS;
				}

				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "%s",
					update_status->status_str);
				return STATUS_UPDATE_FAILURE;
		}
	}
}

/**
 * Complete a Cerberus manifest update
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest_type Type of manifest being updated
 * @param update_status Output buffer to be filled with update status
 * @param activate_setting 1 to activate immediately, 0 to activate after Cerberus reboot
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_manifest_update_complete (struct cerberus_interface *intf,
	uint8_t manifest_type, struct cerberus_fw_update_status *update_status,
	uint8_t activate_setting)
{
	unsigned long start_time;
	uint8_t command_id;
	size_t payload_len;
	char manifest_string[10] = "Manifest";
	struct cerberus_manifest_request manifest;
	int status;

	switch (manifest_type) {
		case CERBERUS_MANIFEST_CFM:
			command_id = CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE;
			payload_len = 1;
			strcpy (manifest_string, "CFM");
			break;

		case CERBERUS_MANIFEST_PCD:
			command_id = CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE;
			payload_len = 0;
			strcpy (manifest_string, "PCD");
			break;

		default:
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
			return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__, command_id,
		intf->params->device_eid, false, &activate_setting, payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	manifest.port = 0;
	manifest.manifest_type = manifest_type;
	while (1) {
		status = cerberus_get_manifest_update_status (intf, &manifest, update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

	switch (update_status->status_code) {
			case MANIFEST_CMD_STATUS_SUCCESS:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
		 			"%s update completed successfully\n", manifest_string);
				return STATUS_SUCCESS;

			case MANIFEST_CMD_STATUS_STARTING:
			case MANIFEST_CMD_STATUS_VALIDATION:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "%s update failed: %s",
					manifest_string, update_status->status_str);
				return STATUS_UPDATE_FAILURE;
		}
	}
}

/**
 * Send Cerberus a manifest update
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest_type Type of manifest to send out
 * @param filename Filename containing manifest file to send out
 * @param activate_setting 1 to activate immediately, 0 to activate after Cerberus reboot
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_manifest_update (struct cerberus_interface *intf, uint8_t manifest_type,
	const char *filename, uint8_t activate_setting)
{
	unsigned long start_time;
	size_t length = 0;
	size_t index = 0;
	size_t max_per_msg;
	size_t size;
	struct cerberus_fw_update_status update_status;
	uint8_t *buffer = NULL;
	uint8_t command_id;
	char manifest_string[10] = "Manifest";
	struct cerberus_manifest_request manifest;
	int status;

	if (filename == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_read_file (intf, filename, &buffer, &size);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (size == 0) {
		status = STATUS_INVALID_UPDATE_FILE;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), filename);
		goto end_clean;
	}

	switch (manifest_type) {
		case CERBERUS_MANIFEST_CFM:
			command_id = CERBERUS_PROTOCOL_CFM_UPDATE;
			strcpy (manifest_string, "CFM");
			break;

		case CERBERUS_MANIFEST_PCD:
			command_id = CERBERUS_PROTOCOL_PCD_UPDATE;
			strcpy (manifest_string, "PCD");
			break;

		default:
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
			return STATUS_INVALID_INPUT;
	}

	status = cerberus_manifest_update_init (intf, manifest_type, (uint32_t) size, &update_status);
	if (status != STATUS_SUCCESS) {
		goto end_clean;
	}

	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);

	while (size > 0) {
		length = MIN (size, max_per_msg);

		memcpy (intf->cmd_buf, &buffer[index], length);

		status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__, command_id,
			intf->params->device_eid, false, intf->cmd_buf, length);
		if (status != STATUS_SUCCESS) {
			goto end_clean;
		}

		index += length;
		size -= length;
		update_status.status_code = UPDATE_STATUS_UNKNOWN;

		start_time = cerberus_common_get_cpu_time_ms ();

		manifest.port = 0;
		manifest.manifest_type = manifest_type;
		while (update_status.status_code != UPDATE_STATUS_SUCCESS) {
			status = cerberus_get_manifest_update_status (intf, &manifest, &update_status);
			if (status != STATUS_SUCCESS) {
				goto end_clean;
			}

			switch(update_status.status_code) {
				case MANIFEST_CMD_STATUS_SUCCESS:
				case MANIFEST_CMD_STATUS_STARTING:
				case MANIFEST_CMD_STATUS_STORE_DATA:
					if (cerberus_common_timeout_expired (start_time,
						CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
						cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
							__func__, __LINE__,
							cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
						status = STATUS_OPERATION_TIMEOUT;
						goto end_clean;
					}

					cerberus_common_sleep_ms (50);
					continue;

				default:
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),"%s update failed: %s",
						manifest_string, update_status.status_str);
					status = STATUS_UPDATE_FAILURE;
					break;
			}
		}
	}

end_clean:
	if (buffer) {
		free (buffer);
	}

	if (status != STATUS_SUCCESS) {
		return status;
	}
	else {
		status =  cerberus_manifest_update_complete (intf, manifest_type, &update_status,
			activate_setting);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		if (manifest_type == CERBERUS_MANIFEST_PCD) {
			status  = cerberus_wait_for_reboot_to_complete_after_update (intf, "PCD");
		}
	}

	return status;
}

/**
 * Send Cerberus a CFM update
 *
 * @param intf The Cerberus interface to utilize
 * @param activate_setting 1 to activate immediately, 0 to activate after Cerberus reboot
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_cfm_activate (struct cerberus_interface *intf, uint8_t activate_setting)
{
	struct cerberus_fw_update_status fw_update_status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (activate_setting > 1)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	return cerberus_manifest_update_complete (intf, CERBERUS_MANIFEST_CFM, &fw_update_status,
		activate_setting);
}

/**
 * Send Cerberus a CFM update
 *
 * @param intf The Cerberus interface to utilize
 * @param filename Filename containing CFM file to send out
 * @param activate_setting 1 to activate immediately, 0 to activate after Cerberus reboot
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_cfm_update (struct cerberus_interface *intf, const char *filename,
	uint8_t activate_setting)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	return cerberus_manifest_update (intf, CERBERUS_MANIFEST_CFM, filename, activate_setting);
}

/**
 * Send Cerberus a PCD update
 *
 * @param intf The Cerberus interface to utilize
 * @param filename Filename containing manifest file to send out
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 * */
LIB_EXPORT int cerberus_pcd_update (struct cerberus_interface *intf, const char *filename)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (filename == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	return cerberus_manifest_update (intf, CERBERUS_MANIFEST_PCD, filename, 0);
}

/**
 * Get ID for CFM in provided region
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest_region The region to query
 * @param manifest_id Output buffer for manifest ID
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_cfm_id (struct cerberus_interface *intf, uint8_t manifest_region,
	uint32_t *manifest_id)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (manifest_id == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = manifest_region;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_CFM_ID, intf->params->device_eid, 1 + sizeof (uint32_t), false,
		intf->cmd_buf, sizeof (manifest_region));
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "No valid CFM found for region %i",
			manifest_region);
		return STATUS_INVALID_MANIFEST;
	}

	memcpy (manifest_id, &intf->cmd_buf[1], sizeof (uint32_t));

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("CFM ID: 0x%x\n", *manifest_id);
	}

	return STATUS_SUCCESS;
}

/**
 * Get platform ID for CFM in provided region
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest_region The region to query
 * @param cfm_platform_id Output buffer filled with NULL terminated CFM platform ID.  MUST BE
 *  FREED BY CALLER using cerberus_free()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_cfm_platform_id (struct cerberus_interface *intf,
	uint8_t manifest_region, char **cfm_platform_id)
{
	int status;
	size_t payload_len;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (cfm_platform_id == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = manifest_region;
	intf->cmd_buf[1] = 1;

	payload_len = 2;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_CFM_ID, intf->params->device_eid, false, intf->cmd_buf, &payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			"No valid CFM found for region %i", manifest_region);
		return STATUS_INVALID_MANIFEST;
	}

	*cfm_platform_id = strdup ((char*) &intf->cmd_buf[1]);
	if (*cfm_platform_id == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("CFM Platform ID: %s\n", *cfm_platform_id);
	}

	return STATUS_SUCCESS;
}

/**
 * Get ID for PCD in provided region
 *
 * @param intf The Cerberus interface to utilize
 * @param manifest_id Output buffer for manifest ID
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pcd_id (struct cerberus_interface *intf, uint32_t *manifest_id)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (manifest_id == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_PCD_ID, intf->params->device_eid, 1 + sizeof (uint32_t), false,
		intf->cmd_buf, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "No valid PCD found\n");
		return STATUS_INVALID_MANIFEST;
	}

	memcpy (manifest_id, &intf->cmd_buf[1], sizeof (uint32_t));

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("PCD ID: 0x%x\n", *manifest_id);
	}

	return STATUS_SUCCESS;
}

/**
 * Get platform ID for PCD
 *
 * @param intf The Cerberus interface to utilize
 * @param pcd_platform_id Output buffer filled with NULL terminated PCD platform ID.  MUST BE
 *  FREED BY CALLER using cerberus_free()
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_pcd_platform_id (struct cerberus_interface *intf,
	char **pcd_platform_id)
{
	int status;
	size_t payload_len;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (pcd_platform_id == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = 1;

	payload_len = 1;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_PCD_ID, intf->params->device_eid, false, intf->cmd_buf, &payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "No valid PCD found\n");
		return STATUS_INVALID_MANIFEST;
	}

	*pcd_platform_id = strdup ((char*) &intf->cmd_buf[1]);
	if (*pcd_platform_id == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_NO_MEM));
		return STATUS_NO_MEM;
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("PCD Platform ID: %s\n", *pcd_platform_id);
	}

	return STATUS_SUCCESS;
}

/**
 * Retrieve and optionally print the configuration reset status.
 *
 * @param intf The Cerberus interface to utilize
 * @param update_status Output buffer for the update status
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_get_config_reset_status (struct cerberus_interface *intf,
	uint32_t *update_status)
{
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (update_status == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = CERBERUS_CONFIG_RESET_STATUS;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_UPDATE_STATUS, intf->params->device_eid, sizeof (uint32_t), false,
		intf->cmd_buf, 2 * sizeof (uint8_t));
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (update_status, intf->cmd_buf, sizeof (uint32_t));

	if ((*update_status & 0xFF) < NUM_CONFIG_RESET_STATUS) {
		snprintf (errorstr, sizeof (errorstr),
			config_reset_cmd_statuses_str[*update_status & 0xFF], *update_status >> 8);
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			"Configuration Reset Update Status: %s", errorstr);
	}
	else {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			"Configuration Reset Update Status: 0x%x", *update_status);
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Configuration Reset Update Status: %i\n", *update_status);
	}

	return STATUS_SUCCESS;
}

/**
 * Wait for Cerberus to complete configuration reset operation
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_wait_reset_config (struct cerberus_interface *intf)
{
	uint32_t update_status;
	unsigned long start_time;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	cerberus_print_info ("Sent reset configuration request, waiting for completion.\n");

	start_time = cerberus_common_get_cpu_time_ms ();

	while (1) {
		status = cerberus_get_config_reset_status (intf, &update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (update_status) {
			case CONFIG_RESET_STATUS_SUCCESS:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Configuration reset completed successfully\n");
				return STATUS_SUCCESS;

			case CONFIG_RESET_STATUS_STARTING:
			case CONFIG_RESET_STATUS_RESTORE_BYPASS:
			case CONFIG_RESET_STATUS_RESTORE_DEFAULTS:
			case CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG:
			case CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS:
			case CONFIG_RESET_STATUS_RESET_INTRUSION:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				if ((update_status & 0xFF) < NUM_UPDATE_STATUS) {
					snprintf (errorstr, sizeof (errorstr),
						config_reset_cmd_statuses_str[update_status & 0xFF], update_status >> 8);
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"Configuration reset failed: %s", errorstr);
				}
				else {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"Configuration reset failed: 0x%x", update_status);
				}
				return STATUS_UPDATE_FAILURE;
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Clear configured state in the device.
 *
 * @param intf The Cerberus interface to utilize
 * @param type The type of reset configuration to execute.
 * @param token_file File to read token from or write generated token to
 * @param load_file Flag to read or write token
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
static int cerberus_reset_device_configuration (struct cerberus_interface *intf,
	enum cerberus_reset_config_type type, char *token_file, bool load_file)
{
	FILE* file;
	uint8_t *buffer = NULL;
	uint8_t *payload;
	size_t token_length = 0;
	size_t r_len = 0;
	size_t msg_len = 0;
	bool mctp_success;
	int i_retry = 0;
	uint8_t mctp_fail_type = STATUS_SUCCESS;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = type;

	if (load_file) {
		status = cerberus_read_file (intf, token_file, &buffer, &token_length);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		if (token_length > (cerberus_protocol_get_max_payload_len_per_msg (intf) - 1)) {
			free (buffer);
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_PAYLOAD_TOO_LARGE));
			return STATUS_PAYLOAD_TOO_LARGE;
		}

		memcpy (&intf->cmd_buf[1], buffer, token_length);
		free (buffer);
	}

	status = cerberus_device_mutex_lock (intf, CERBERUS_MUTEX_TIMEOUT_MS);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		status = cerberus_protocol_prepare_send_msg (intf, CERBERUS_PROTOCOL_RESET_CONFIG,
			intf->cmd_buf, 1 + token_length, &msg_len);
		if (status != STATUS_SUCCESS) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status));
			cerberus_device_mutex_unlock (intf);
			return status;
		}

		status = intf->mctp_intf_msg_transaction (intf, intf->params->device_eid, intf->msg_buf,
			msg_len, intf->params->device_eid, true, intf->msg_buf, &r_len, &mctp_fail_type);
		if (status == STATUS_SUCCESS) {
			break;
		}

		cerberus_common_sleep_ms (CERBERUS_CMD_RETRY_WAIT_TIME_MS);
	} while (i_retry++ < intf->params->num_mctp_retries);

	cerberus_device_mutex_unlock (intf);

	if (status != STATUS_SUCCESS) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status));
		return status;
	}

	payload = &intf->msg_buf[CERBERUS_PROTOCOL_MIN_MSG_LEN];

	if (cerberus_protocol_is_status_message (intf->protocol_version, intf->msg_buf, r_len)) {
		if (*payload != CERBERUS_PROTOCOL_NO_ERROR) {
			if (*((uint32_t*) &payload[1]) == 0x7f004603) {
				status = STATUS_CERBERUS_CMD_NOT_AUTHORIZED;
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (status));
			}
			else {
				status = STATUS_MCTP_FAILURE;
				snprintf (errorstr, sizeof (errorstr),
					cerberus_protocol_error_messages_str[*payload], *((uint32_t*) &payload[1]));
				cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
					__LINE__, cerberus_utility_get_errors_str (status), errorstr);
			}

			return status;
		}
		else {
			mctp_success = true;
		}
	}
	else {
		mctp_success = false;
	}

	if (load_file && !mctp_success) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), CERBERUS_PROTOCOL_ERROR,
			*(payload - 1));
		return STATUS_CMD_RESPONSE;
	}

	if (mctp_success) {
		status = cerberus_wait_reset_config (intf);
	}
	else {
		if (*(payload - 1) != CERBERUS_PROTOCOL_RESET_CONFIG) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), CERBERUS_PROTOCOL_RESET_CONFIG,
				*(payload - 1));
			return STATUS_CMD_RESPONSE;
		}

		if (token_file == NULL) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_OUTPUT_FILE_REQUIRED));
			return STATUS_OUTPUT_FILE_REQUIRED;
		}

		file = fopen (token_file, "wb");
		if (file == NULL) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_OPEN_FILE_FAILED), token_file);
			return STATUS_OPEN_FILE_FAILED;
		}

		fwrite (&intf->msg_buf[CERBERUS_PROTOCOL_MIN_MSG_LEN], 1,
			r_len - CERBERUS_PROTOCOL_MIN_MSG_LEN, file);
		if (ferror (file) != 0) {
			status = STATUS_WRITE_FILE_FAILED;
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (status), token_file);
		}

		fclose (file);
	}

	return status;
}

/**
 * Reset device configuration state to default.
 *
 * @param intf The Cerberus interface to utilize
 * @param token_file File to read token from or write generated token to
 * @param load_file Flag to read or write token
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_reset_default_configuration (struct cerberus_interface *intf,
	char *token_file, bool load_file)
{
	return cerberus_reset_device_configuration (intf, CERBERUS_RESET_CONFIG_DEFAULTS,
		token_file, load_file);
}

/**
 * Reset bypass configuration state.
 *
 * @param intf The Cerberus interface to utilize
 * @param token_file File to read token from or write generated token to
 * @param load_file Flag to read or write token
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_reset_bypass_configuration (struct cerberus_interface *intf,
	char *token_file, bool load_file)
{
	return cerberus_reset_device_configuration (intf, CERBERUS_RESET_CONFIG_BYPASS,
		token_file, load_file);
}

/**
 * Reset platform configuration state.
 *
 * @param intf The Cerberus interface to utilize
 * @param token_file File to read token from or write generated token to
 * @param load_file Flag to read or write token
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_reset_platform_configuration (struct cerberus_interface *intf,
	char *token_file, bool load_file)
{
	return cerberus_reset_device_configuration (intf, CERBERUS_RESET_CONFIG_PLATFORM,
		token_file, load_file);
}

/**
 * Reset intrusion configuration state.
 *
 * @param intf The Cerberus interface to utilize
 * @param token_file File to read token from or write generated token to
 * @param load_file Flag to read or write token
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_reset_intrusion_configuration (struct cerberus_interface *intf,
	char *token_file, bool load_file)
{
	return cerberus_reset_device_configuration (intf, CERBERUS_RESET_CONFIG_INTRUSION,
		token_file, load_file);
}

/**
 * Reset device component configuration.
 *
 * @param intf The Cerberus interface to utilize
 * @param token_file File to read token from or write generated token to
 * @param load_file Flag to read or write token
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_reset_component_configuration (struct cerberus_interface *intf,
	char *token_file, bool load_file)
{
	return cerberus_reset_device_configuration (intf, CERBERUS_RESET_CONFIG_CFM,
		token_file, load_file);
}

/**
 *  Get the host reset state string.
 *
 * @param intf The Cerberus interface to utilize
 * @param host_state Reset state of host
 *
 * @return Returns host state string or NULL on error.
 */
LIB_EXPORT const char* cerberus_get_host_state_str (struct cerberus_interface *intf,
	uint8_t host_state)
{
	if (intf == NULL) {
		return NULL;
	}

	if ((intf->params == NULL) || (host_state >= NUM_HOST_PROCESSOR_STATES)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return NULL;
	}
	else {
		return host_processor_state_str[host_state];
	}
}

/**
 *  Get the host reset state.
 *
 * @param intf The Cerberus interface to utilize
 * @param port The port number to query
 * @param host_state Output the state of the host to be filled
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_host_state (struct cerberus_interface *intf, uint8_t port,
	uint8_t *host_state)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (host_state == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = port;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_HOST_STATE, intf->params->device_eid, sizeof (uint8_t), false,
		intf->cmd_buf, 1);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	*host_state = intf->cmd_buf[0];

	return status;
}

/**
 * Retrieve the extended Cerberus host recovery image update status
 *
 * @param intf The Cerberus interface to utilize
 * @param recovery_port The port number to update the recovery image
 * @param update_status Output buffer for the update status
 *
 * @return 0 if operation completed successfully or an error code.
 */
static int cerberus_get_ext_recovery_image_update_status (struct cerberus_interface *intf,
	uint8_t recovery_port, struct cerberus_fw_update_status *update_status)
{
	size_t payload_len = 2;
	uint32_t recovery_update_status;
	int status;
	char errorstr[CERBERUS_MAX_MSG_LEN] = "";

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (update_status == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = CERBERUS_RECOVERY_UPDATE_STATUS;
	intf->cmd_buf[1] = recovery_port;

	status = cerberus_protocol_send_and_read_rsp (intf,  __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS, intf->params->device_eid, 2 * sizeof (uint32_t),
		false, intf->cmd_buf, payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (&recovery_update_status, intf->cmd_buf, sizeof (uint32_t));
	memcpy (&update_status->remaining_len, intf->cmd_buf + sizeof (uint32_t), sizeof (uint32_t));

	update_status->status_code = recovery_update_status & 0xFF;
	update_status->status_code_module = recovery_update_status >> 8;

	if (update_status->status_code < RECOVERY_IMAGE_CMD_NUM_STATUS) {
		snprintf (errorstr, sizeof (errorstr),
			recovery_image_cmd_statuses_str[update_status->status_code],
			update_status->status_code_module);
		snprintf (update_status->status_str, sizeof (update_status->status_str), "%s", errorstr);
	}
	else {
		snprintf (update_status->status_str, sizeof (update_status->status_str), "0x%x\n",
			recovery_update_status);
	}

	if (intf->params->debug_level & CERBERUS_DEBUG_CMD) {
		cerberus_print_info ("Recovery Image Update Status: %i\n", recovery_update_status);
		cerberus_print_info ("Remaining Length: %i\n", update_status->remaining_len);
	}

	return STATUS_SUCCESS;
}

/**
 * Initiate a host recovery image update on Cerberus
 *
 * @param intf The Cerberus interface to utilize
 * @param recovery_port The port number to update
 * @param size Size of recovery image update file that will be sent out to Cerberus
 * @param update_status Output buffer to be filled with update status
 *
 * @return 0 if operation completed successfully or an error code.
 */
static int cerberus_recovery_image_init (struct cerberus_interface *intf,
	uint8_t recovery_port, uint32_t size, struct cerberus_fw_update_status *update_status)
{
	unsigned long start_time;
	int status;

	intf->cmd_buf[0] = recovery_port;
	memcpy (&intf->cmd_buf[1], &size, sizeof (uint32_t));

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE, intf->params->device_eid, false, intf->cmd_buf,
		5);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	while (1) {
		status = cerberus_get_ext_recovery_image_update_status (intf, recovery_port, update_status);
		if (status != STATUS_SUCCESS) {
			return status;
		}

		switch (update_status->status_code) {
			case RECOVERY_IMAGE_CMD_STATUS_STARTING:
			case RECOVERY_IMAGE_CMD_STATUS_PREPARE:
			case RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					return STATUS_OPERATION_TIMEOUT;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				if (update_status->status_code == RECOVERY_IMAGE_CMD_STATUS_SUCCESS) {
					return STATUS_SUCCESS;
				}
				else {
					snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
						"Recovery Image Update Status: %s", update_status->status_str);
					return STATUS_UPDATE_FAILURE;
				}
		}
	}
}

/**
 * Activate a host recovery image update
 *
 * @param intf The Cerberus interface to utilize
 * @param recovery_port The port number being updated
 * @param update_status Output buffer to be filled with update status
 *
 * @return 0 if operation completed successfully or an error code.
 */
static int cerberus_recovery_image_activate (struct cerberus_interface *intf,
	uint8_t recovery_port, struct cerberus_fw_update_status *update_status)
{
	uint8_t msg_retries;
	unsigned long start_time;
	int status;

	intf->cmd_buf[0] = recovery_port;

	status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE, intf->params->device_eid, false,	intf->cmd_buf,
		1);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	start_time = cerberus_common_get_cpu_time_ms ();

	while (1) {
		for (msg_retries = 0; msg_retries < CERBERUS_MAX_SEND_RETRIES; ++msg_retries) {
			status = cerberus_get_ext_recovery_image_update_status (intf, recovery_port,
				update_status);
			if (status == STATUS_SUCCESS) {
				break;
			}

			printf ("Retrying....\n");
		}

		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		switch (update_status->status_code) {
			case RECOVERY_IMAGE_CMD_STATUS_SUCCESS:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Recovery image activation completed successfully\n");
				status = STATUS_SUCCESS;
				goto exit;

			case RECOVERY_IMAGE_CMD_STATUS_STARTING:
			case RECOVERY_IMAGE_CMD_STATUS_ACTIVATING:
				if (cerberus_common_timeout_expired (start_time,
					CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
						__LINE__, cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
					status = STATUS_OPERATION_TIMEOUT;
					goto exit;
				}

				cerberus_common_sleep_ms (50);
				continue;

			default:
				snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
					"Recovery image activation failed: %s", update_status->status_str);
				status = STATUS_UPDATE_FAILURE;
				goto exit;
		}
	}

exit:
	return status;
}

/**
 * Send Cerberus a host recovery image update file
 *
 * @param intf The Cerberus interface to utilize
 * @param recovery_port The port number to update
 * @param name The update filename
 *
 * @return 0 if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_recovery_image_update (struct cerberus_interface *intf,
	uint8_t recovery_port, const char *name)
{
	unsigned long start_time;
	size_t index = 0;
	struct cerberus_fw_update_status update_status;
	uint32_t length = 0;
	size_t update_size;
	uint8_t *buffer = NULL;
	uint8_t update_retries = 0;
	uint8_t msg_retries;
	size_t max_per_msg;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (name == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_read_file (intf, name, &buffer, (size_t*) &update_size);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (update_size == 0) {
		status = STATUS_INVALID_UPDATE_FILE;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), name);
		goto end_clean;
	}

	update_status.remaining_len = (int32_t) update_size;
	max_per_msg = cerberus_protocol_get_max_payload_len_per_msg (intf);

	while (update_status.remaining_len != 0) {
		index = 0;

		status = cerberus_recovery_image_init (intf, recovery_port, (uint32_t) update_size,
			&update_status);
		if (status != STATUS_SUCCESS) {
			goto end_clean;
		}

		cerberus_print_info ("Done recovery image update preparation, sending update bytes\n");

		while (update_size > 0) {
			length = (uint32_t) MIN (max_per_msg - 1, update_size);
			intf->cmd_buf[0] = recovery_port;
			memcpy (&intf->cmd_buf[1], &buffer[index], length);

			for (msg_retries = 0; msg_retries < CERBERUS_MAX_SEND_RETRIES; ++msg_retries) {
				status = cerberus_protocol_send_no_rsp (intf, __func__, __LINE__,
					CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE, intf->params->device_eid, false,
					intf->cmd_buf, length + 1);
				if (status == STATUS_SUCCESS) {
					break;
				}

				cerberus_print_info ("Retrying....\n");
			}

			if (status != STATUS_SUCCESS) {
				return status;
			}

			update_status.status_code = RECOVERY_IMAGE_CMD_STATUS_UNKNOWN;
			start_time = cerberus_common_get_cpu_time_ms ();

			while (update_status.status_code != RECOVERY_IMAGE_CMD_STATUS_SUCCESS) {
				status = cerberus_get_ext_recovery_image_update_status (intf, recovery_port,
					&update_status);

				if (status != STATUS_SUCCESS) {
					cerberus_print_info ("\n");
					goto end_clean;
				}

				switch (update_status.status_code) {
					case RECOVERY_IMAGE_CMD_STATUS_SUCCESS:
					case RECOVERY_IMAGE_CMD_STATUS_STARTING:
					case RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA:
						if (cerberus_common_timeout_expired (start_time,
							CERBERUS_CMD_TIMEOUT_VAL_S * 1000)) {
							status = STATUS_OPERATION_TIMEOUT;
							cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
								__func__, __LINE__,
								cerberus_utility_get_errors_str (STATUS_OPERATION_TIMEOUT));
							goto end_clean;
						}

						cerberus_print_info (".");
						fflush (stdout);
						cerberus_common_sleep_ms (50);
						continue;

					default:
						snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
							"Recovery image update failed: %s", update_status.status_str);
						status = STATUS_UPDATE_FAILURE;
						goto end_clean;
				}
			}

			if (update_status.remaining_len == (update_size - length)) {
				index += length;
				update_size -= length;
			}

			if ((int32_t) update_status.remaining_len < 0) {
				cerberus_print_info (
					"\nRecovery image update failed: Utility and device out of sync while transferring update file\n");
				++update_retries;

				if (update_retries > CERBERUS_MAX_UPDATE_RETRIES) {
					cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
						cerberus_utility_get_errors_str (STATUS_UPDATE_FAILURE));
					status = STATUS_UPDATE_FAILURE;
					goto end_clean;
				}
			}
		}
	}

end_clean:
	if (buffer) {
		free (buffer);
	}

	if (status != STATUS_SUCCESS) {
		return status;
	}

	cerberus_print_info ("\n");

	return cerberus_recovery_image_activate (intf, recovery_port, &update_status);
}

/**
 * Retrieve host recovery image version in provided port
 *
 * @param intf The Cerberus interface to utilize
 * @param recovery_port The port number to query
 * @param version Output buffer to be filled with NULL terminated version string
 * @param length Maximum length of the output buffer
 *
 * @return 0 if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_recovery_image_version (struct cerberus_interface *intf,
	uint8_t recovery_port, uint8_t *version, size_t length)
{
	size_t version_len;
	size_t i;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (version == NULL) || (length == 0)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = recovery_port;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, intf->params->device_eid,
		CERBERUS_VERSION_MAX_LEN, false, intf->cmd_buf, 1);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (intf->cmd_buf[0] == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
			cerberus_utility_get_errors_str (STATUS_INVALID_RECOVERY_IMAGE), recovery_port);
		return STATUS_INVALID_RECOVERY_IMAGE;
	}

	version_len = strnlen ((const char*) intf->cmd_buf, CERBERUS_VERSION_MAX_LEN);
	if (version_len == CERBERUS_VERSION_MAX_LEN) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_STRING_NOT_TERMINATED));
		return STATUS_STRING_NOT_TERMINATED;
	}

	for (i = 0; i < version_len; ++i) {
		if (!isprint (intf->cmd_buf[i])) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_NOT_STRING), intf->cmd_buf[i]);
			return STATUS_NOT_STRING;
		}
	}

	if (length <= version_len) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
		return STATUS_BUF_TOO_SMALL;
	}

	memcpy (version, intf->cmd_buf, (version_len + 1));

	return STATUS_SUCCESS;
}

/**
 * Retrieve Cerberus device information in raw ASCII format
 *
 * @param intf The Cerberus interface to utilize
 * @param buffer Output buffer to be filled with device info
 * @param length Maximum length of the output buffer.  To be updated with used up length
 * 	on output
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_device_info (struct cerberus_interface *intf, uint8_t *buffer,
	size_t *length)
{
	size_t payload_len = 1;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (buffer == NULL) || (length == NULL) || (*length == 0)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = 0;

	status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_DEVICE_INFO, intf->params->device_eid, false, intf->cmd_buf,
		&payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (payload_len < 1) {
		status = STATUS_UNEXPECTED_RLEN;
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (status), payload_len, 1);
		return status;
	}

	if (*length < payload_len) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_BUF_TOO_SMALL));
		return STATUS_BUF_TOO_SMALL;
	}

	memcpy (buffer, intf->cmd_buf, payload_len);
	*length = payload_len;

	return STATUS_SUCCESS;
}

/**
 * Retrieve Cerberus device IDs
 *
 * @param intf The Cerberus interface to utilize
 * @param ids Container for device IDs
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_device_id (struct cerberus_interface *intf,
	struct cerberus_device_id *ids)
{
	size_t payload_len = 0;
	int status;
	uint16_t *data;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (ids == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_GET_DEVICE_ID, intf->params->device_eid, 4 * sizeof (uint16_t), false,
		intf->cmd_buf, payload_len);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	data = (uint16_t*) intf->cmd_buf;
	ids->vendor_id = data[0];
	ids->device_id = data[1];
	ids->subsystem_vid = data[2];
	ids->subsystem_id = data[3];

	return STATUS_SUCCESS;
}

/**
 * Retrieve the specified reset counter
 *
 * @param intf The Cerberus interface to utilize
 * @param type The reset counter type
 * @param port The port number to query
 * @param counter Output for the reset counter
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_reset_counter (struct cerberus_interface *intf, uint8_t type,
	uint8_t port, uint16_t *counter)
{
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (counter == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	intf->cmd_buf[0] = type;
	intf->cmd_buf[1] = port;

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_RESET_COUNTER, intf->params->device_eid, sizeof (uint16_t), false,
		intf->cmd_buf, 2);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy (counter, intf->cmd_buf, sizeof (uint16_t));

	return STATUS_SUCCESS;
}

/**
 * Setup an encrypted channel with Cerberus
 *
 * @param intf The Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_setup_encrypted_channel (struct cerberus_interface *intf, uint8_t *root_ca,
	size_t root_ca_len)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

#ifdef CERBERUS_ENABLE_CRYPTO
	return cerberus_crypto_interface_setup_encrypted_channel (intf, root_ca, root_ca_len);
#else
	UNUSED (root_ca);
	UNUSED (root_ca_len);
	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));

	return STATUS_UNSUPPORTED_OPERATION;
#endif
}

/**
 * Setup a paired session with device binding
 *
 * @param intf The Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_setup_device_binding (struct cerberus_interface *intf, uint8_t *root_ca,
	size_t root_ca_len)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

#ifdef CERBERUS_ENABLE_CRYPTO
	return cerberus_crypto_interface_setup_device_bindings (intf, root_ca, root_ca_len);
#else
	UNUSED (root_ca);
	UNUSED (root_ca_len);
	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));

	return STATUS_UNSUPPORTED_OPERATION;
#endif
}

/**
 * Close active encrypted channel.
 *
 * @param intf The Cerberus interface to utilize.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_close_encrypted_channel (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

#ifdef CERBERUS_ENABLE_CRYPTO
	return cerberus_crypto_interface_close_encrypted_channel (intf);
#else
	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));

	return STATUS_UNSUPPORTED_OPERATION;
#endif
}

/**
 * Perform the Cerberus attestation challenge flow on Cerberus device.
 *
 * @param intf The Cerberus interface to utilize.
 * @param root_ca Optional DER certificate for a root CA. Set to NULL if not utilized.
 * @param root_ca_len Root CA certificate length.
 * @param pmr0_buf Buffer to optionally retrieve the device's PMR0 value. Set to NULL if not needed.
 * @param pmr0_buf_len Optional argument indicating length of the buffer, set it to 0 if not needed.
 *
 * @return Completion status, 0 if success or an error code.
 */
LIB_EXPORT int cerberus_attestation_challenge (struct cerberus_interface *intf, uint8_t *root_ca,
	size_t root_ca_len, uint8_t *pmr0_buf, size_t pmr0_buf_len)
{
	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

#ifdef CERBERUS_ENABLE_CRYPTO
	return cerberus_crypto_interface_attestation_challenge (intf, root_ca, root_ca_len, pmr0_buf,
		pmr0_buf_len);
#else
	UNUSED (root_ca);
	UNUSED (root_ca_len);
	UNUSED (pmr0_buf);
	UNUSED (pmr0_buf_len);

	cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
		cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));

	return STATUS_UNSUPPORTED_OPERATION;
#endif
}

/**
 * Free component attestation status.
 *
 * @param results The status container to free.
 */
LIB_EXPORT void cerberus_free_components_status (struct cerberus_component_statuses *results)
{
	size_t i_status;

	if (results && results->statuses) {
		for (i_status = 0; i_status < results->num_status; ++i_status) {
			cerberus_free (results->statuses[i_status].status_str);
		}

		cerberus_free (results->statuses);
	}
}

/**
 * Get Cerberus PCR bank and measurement index for requested event type.
 *
 * @param intf The Cerberus interface to utilize.
 * @param event_type Event type requested.
 * @param pcr_bank Container to fill with PCR bank if found.
 * @param measurement_index Container to fill with measurement index if found.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int cerberus_get_pcr_bank_by_event_type (struct cerberus_interface *intf,
	uint32_t event_type, uint8_t *pcr_bank, uint8_t *measurement_index)
{
	struct logging_tcg_entry *entries = NULL;
	size_t entry_count = 0;
	uint16_t i_entry;
	int status;

	status = cerberus_attestation_log_read (intf, &entries, &entry_count);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (entry_count == 0) {
		snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), "No attestation log entries found");
		status = STATUS_NO_DATA;
		goto exit;
	}

	for (i_entry = 0; i_entry < entry_count; ++i_entry) {
		if (entries[i_entry].event_type == event_type) {
			*pcr_bank = (uint8_t) (entries[i_entry].measurement_type >> 8);
			*measurement_index = (uint8_t) entries[i_entry].measurement_type;
			goto exit;
		}
	}

	snprintf (intf->cmd_err_msg, sizeof (intf->cmd_err_msg),
		"No entry found in the attestation log for event type: 0x%x", event_type);
	status = STATUS_OPERATION_UNSUPPORTED_BY_DEVICE;

exit:
	cerberus_free ((uint8_t*) entries);

	return status;
}

/**
 * Get the component attestation status of all AC-RoT components.
 *
 * @param intf The Cerberus interface to utilize.
 * @param results Container to hold attestation results.  Buffer is dynamically allocated MUST BE
 * FREED BY CALLER using cerberus_free_cfm_results()
 *
 * @return Completion status, 0 if success or an error code.
 */
LIB_EXPORT int cerberus_get_components_status (struct cerberus_interface *intf,
	struct cerberus_component_statuses *results)
{
	size_t status_offset = sizeof (uint32_t) + 1;
	size_t event_offset = 0;
	size_t payload_len;
	size_t num_comps;
	size_t i_comp;
	uint32_t manifest_id;
	uint8_t measurement_index;
	uint8_t pcr_bank;
	char comp_str[32];
	int status;
	uint32_t event_type;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (results == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	results->statuses = NULL;
	results->num_status = 0;

	// If Cerberus has no active PCD, then return empty components list
	status = cerberus_get_pcd_id (intf, &manifest_id);
	if (status != STATUS_SUCCESS) {
		if (status == STATUS_INVALID_MANIFEST) {
			return STATUS_SUCCESS;
		}
		return status;
	}

	if (!intf->platform.comp_state.get_cfm_init_status_event_type) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_UNSUPPORTED_OPERATION));
		return STATUS_UNSUPPORTED_OPERATION;
	}

	// Get platform specific cfm init status event type value from the attestation log
	status = intf->platform.comp_state.get_cfm_init_status_event_type (intf, &event_type);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = cerberus_get_pcr_bank_by_event_type (intf, event_type, &pcr_bank, &measurement_index);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	do {
		payload_len = 6;

		intf->cmd_buf[0] = pcr_bank;
		intf->cmd_buf[1] = measurement_index;

		memcpy (&intf->cmd_buf[2], &event_offset, sizeof (uint32_t));

		status = cerberus_protocol_send_and_read_variable_rsp (intf, __func__, __LINE__,
			CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, intf->params->device_eid, true, intf->cmd_buf,
			&payload_len);
		if (status != STATUS_SUCCESS) {
			goto fail;
		}

		event_offset += payload_len;

		if (results->num_status != 0) {
			status_offset = 0;
		}

		num_comps = event_offset - status_offset;

		results->statuses = realloc (results->statuses,
			sizeof (struct cerberus_component_status) * (results->num_status + num_comps));
		if (results->statuses == NULL) {
			status = STATUS_NO_MEM;
			goto fail;
		}

		for (i_comp = 0; i_comp < num_comps; ++i_comp) {
			results->statuses[results->num_status].status = intf->cmd_buf[status_offset + i_comp];

			switch (results->statuses[results->num_status].status) {
				case CERBERUS_COMP_AUTHENTICATED:
					results->statuses[results->num_status].status_str = strdup ("Authenticated");
					break;

				case CERBERUS_COMP_UNIDENTIFIED:
					results->statuses[results->num_status].status_str = strdup ("Unidentified");
					break;

				case CERBERUS_COMP_NEVER_ATTESTED:
					results->statuses[results->num_status].status_str = strdup ("Never Attested");
					break;

				case CERBERUS_COMP_READY_FOR_ATTESTATION:
					results->statuses[results->num_status].status_str =
						strdup ("Ready for Attestation");
					break;

				case CERBERUS_COMP_ATTESTATION_FAILED:
					results->statuses[results->num_status].status_str =
						strdup ("Attestation Failed");
					break;

				default:
					snprintf (comp_str, sizeof (comp_str), "%i",
						results->statuses[results->num_status].status);
					results->statuses[results->num_status].status_str = strdup (comp_str);
					break;
			}

			++results->num_status;
		}
	} while (payload_len == intf->mctp.read.max_payload_per_msg);

	return STATUS_SUCCESS;

fail:
	cerberus_free_components_status (results);

	return status;
}


/**
 * Print out component attestation status along with component IDs supported by PCD.
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_component_status (struct cerberus_interface *intf)
{
	struct cerberus_components components;
	struct cerberus_component_statuses results;
	size_t i_index = 0;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_components_status (intf, &results);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	if (results.num_status != 0) {
		status = cerberus_get_supported_components (intf, false, 0, &components);
		if (status != STATUS_SUCCESS) {
			if (status != STATUS_INVALID_MANIFEST) {
				goto exit_status;
			}
		}

		if (results.num_status != components.num_components) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), results.num_status,
				components.num_components);
			status = STATUS_CMD_RESPONSE;
			goto exit_comp_list;
		}
	}

	printf ("Number of components: %zi\n\n", results.num_status);

	for (i_index = 0; i_index < components.num_components; ++i_index) {
		printf ("%s: %s\n", components.component_str[i_index],
			results.statuses[i_index].status_str);
	}

exit_comp_list:
	if (results.num_status != 0) {
		cerberus_free_comp_list (&components);
	}
exit_status:
	cerberus_free_components_status (&results);

	return status;
}

/**
 * Test Cerberus device error messaging
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_test_error_msg (struct cerberus_interface *intf)
{
	uint32_t error_data;
	uint8_t error_code;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_no_rsp_get_error (intf, __func__, __LINE__, 0xFF,
		intf->params->device_eid, false, NULL, 0, &error_code, &error_data);
	if (status != STATUS_MCTP_FAILURE) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			"Test failed, valid Cerberus error message not received");
		return STATUS_UNEXPECTED_VALUE;
	}

	if (error_code != 0x04) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_CMD_RESPONSE), error_code, 0x04);
		return STATUS_CMD_RESPONSE;
	}

	return STATUS_SUCCESS;
}

/**
 * Get the current heap usage for the device.
 *
 * @param intf The Cerberus interface to utilize
 * @param heap Output for the heap usage information
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_current_heap_usage (struct cerberus_interface *intf,
	struct cerberus_heap *heap)
{
	int status;
	uint32_t *in;
	int *out;
	uint32_t i;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (heap == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_protocol_send_and_read_rsp (intf, __func__, __LINE__,
		CERBERUS_PROTOCOL_DIAG_HEAP_USAGE, intf->params->device_eid, sizeof (uint32_t) * 6, false,
		intf->cmd_buf, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	in = (uint32_t*) intf->cmd_buf;
	out = (int*) heap;
	for (i = 0; i < (sizeof (*heap) / sizeof (int)); i++, in++, out++) {
		if (*in == 0xffffffff) {
			*out = -1;
		}
		else {
			*out = (int) *in;
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Get Cerberus last error message
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return NULL terminated last error message.
 */
LIB_EXPORT const char* cerberus_get_last_error (struct cerberus_interface *intf)
{
	if (intf == NULL) {
		return cerberus_utility_get_errors_str (STATUS_INVALID_INPUT);
	}

	return intf->cmd_err_msg;
}

/**
 * Get MCTP routing table from MCTP bridge.
 *
 * @param intf The Cerberus interface to utilize
 * @param routing_table Output routing table to be filled in
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_get_mctp_routing_table (struct cerberus_interface *intf,
	struct cerberus_routing_table *routing_table)
{
	struct mctp_protocol_control_get_routing_table_entries_response *routing_table_rsp;
	struct mctp_protocol_control_routing_table_entry *entry;
	uint8_t entry_handle = 0;
	uint8_t i_entry;
	size_t payload_len;
	int status;
	int status_bridge_request;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if ((intf->params == NULL) || (routing_table == NULL)) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_utility_set_bridge_request (intf);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	routing_table->entries = NULL;
	routing_table->num_entries = 0;

	while (entry_handle != 0xFF) {
		payload_len = sizeof (entry_handle);

		status = mctp_protocol_send_ctrl_msg_get_rsp (intf,
			MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES, MCTP_PROTOCOL_BMC_EID, 0, false, false,
			-1, intf->cmd_buf, &payload_len);
		if (status != STATUS_SUCCESS) {
			goto exit;
		}

		routing_table_rsp =
			(struct mctp_protocol_control_get_routing_table_entries_response*) intf->cmd_buf;
		entry = (struct mctp_protocol_control_routing_table_entry*) (routing_table_rsp + 1);

		if (routing_table_rsp->completion_code != 0) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
				cerberus_utility_get_errors_str (STATUS_MCTP_CTRL_REQ_FAIL),
				routing_table_rsp->completion_code);
			status = STATUS_MCTP_CTRL_REQ_FAIL;
			goto exit;
		}

		routing_table->entries = realloc (routing_table->entries,
			sizeof (struct cerberus_routing_table_entry) *
				(routing_table->num_entries + routing_table_rsp->num_entries));
		if (routing_table->entries == NULL) {
			cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__,
				__LINE__, cerberus_utility_get_errors_str (STATUS_NO_MEM));
			status = STATUS_NO_MEM;
			goto exit;
		}

		for (i_entry = 0; i_entry < routing_table_rsp->num_entries; ++i_entry) {
			routing_table->entries[routing_table->num_entries].entry_type =
				entry[i_entry].entry_type;
			routing_table->entries[routing_table->num_entries].starting_eid =
				entry[i_entry].starting_eid;
			routing_table->entries[routing_table->num_entries].eid_range_size =
				entry[i_entry].eid_range_size;
			routing_table->entries[routing_table->num_entries].address =
				entry[i_entry].address;
			++routing_table->num_entries;
		}

		entry_handle = routing_table_rsp->next_entry_handle;
	}

exit:
	status_bridge_request = cerberus_utility_clear_bridge_request (intf);
	if (status == STATUS_SUCCESS) {
		status = status_bridge_request;
	}

	return status;
}

/**
 * Get and print MCTP routing table from MCTP bridge.
 *
 * @param intf The Cerberus interface to utilize
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
LIB_EXPORT int cerberus_print_mctp_routing_table (struct cerberus_interface *intf)
{
	struct cerberus_routing_table routing_table;
	uint8_t i_entry;
	int status;

	if (intf == NULL) {
		return STATUS_INVALID_INPUT;
	}

	if (intf->params == NULL) {
		cerberus_print_error (intf->cmd_err_msg, sizeof (intf->cmd_err_msg), __func__, __LINE__,
			cerberus_utility_get_errors_str (STATUS_INVALID_INPUT));
		return STATUS_INVALID_INPUT;
	}

	status = cerberus_get_mctp_routing_table (intf, &routing_table);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	cerberus_print_info ("\n%-6s| %-5s| %-5s| %-10s| %-9s|\n", "Entry", "Type", "EID",
		"EID Range", "Address");
	cerberus_print_info ("--------------------------------------------\n");

	for (i_entry = 0; i_entry < routing_table.num_entries; ++i_entry) {
		cerberus_print_info ("%-6i| %-5i| 0x%-3X| %-10i| 0x%-7X|\n", i_entry,
			routing_table.entries[i_entry].entry_type, routing_table.entries[i_entry].starting_eid,
			routing_table.entries[i_entry].eid_range_size, routing_table.entries[i_entry].address);
	}

	return STATUS_SUCCESS;
}


/**
 * Get current CPU time in milliseconds.
 *
 * @return CPU time in milliseconds.
 */
LIB_EXPORT unsigned long cerberus_get_cpu_time_ms ()
{
	return cerberus_common_get_cpu_time_ms ();
}

/**
 * Sleep for given time in milliseconds.
 *
 * @param time_ms sleep time in milliseconds.
 */
LIB_EXPORT void cerberus_sleep_ms (unsigned long time_ms)
{
	cerberus_common_sleep_ms (time_ms);
}
