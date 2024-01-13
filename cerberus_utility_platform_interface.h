// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_UTILITY_PLATFORM_INTERFACE_
#define CERBERUS_UTILITY_PLATFORM_INTERFACE_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * TCG event entry.
 */
struct tcg_event2;

/**
 * Debug log entry format.
 */
struct logging_debug_entry_base;

/**
 * Interface for platform specific debug log processing
 */
struct platform_debug_log_interface {
	/**
	 * Gets debug log component name string.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param component Debug component ID.
	 * @param component_name Component name string.
	 *
	 * @return STATUS_SUCCESS if operation completed successfully or an error code.
	 */
	int (*get_component_name) (struct cerberus_interface *intf, uint8_t component,
		const char **component_name);

	/**
	 * Gets reference to the debug log component message strings.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param entry debug log entry.
	 * @param message_str Output the reference to the list of message strings related to the component.
	 *
	 * @return STATUS_SUCCESS if operation completed successfully or an error code.
	 */
	int (*get_component_messages_str) (struct cerberus_interface *intf,
		struct logging_debug_entry_base *entry, const char ***message_str);

	/**
	 * Post process component debug log message based on the debug log entry.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param message_str Reference to the list of message strings related to the component.
	 * @param message Output the post processed debug message.
	 * @param message_size Size of the debug message buffer.
	 * @param entry debug log entry.
	 * @param done Output true if the message buffer is filled with the post processed message, false otherwise.
	 *
	 * @return STATUS_SUCCESS if operation completed successfully or an error code.
	 */
	int (*post_process_component_message) (struct cerberus_interface *intf,
		const char **message_str, char *message, int message_size,
		struct logging_debug_entry_base *entry, bool *done);
};

/**
 * Interface for platform specific TCG log processing.
 */
struct platform_tcg_log_interface {
	/**
	 * Post process a TCG log event entry.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param ids Cerberus Device IDs.
	 * @param event reference to TCG log event entry.
	 *
	 * @return STATUS_SUCCESS if operation completed successfully or an error code.
	 */
	int (*post_process_event_entry) (struct cerberus_interface *intf, struct cerberus_device_id ids,
		struct tcg_event2 *event);

	/**
	 * Post process the TCG event data.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param event TCG log event entry.
	 * @param event_data_buf event data buffer.
	 * @param event_data_size event data size.
	 *
	 * @return STATUS_SUCCESS if operation completed successfully or an error code.
	 */
	int (*post_process_event_data) (struct cerberus_interface *intf, struct tcg_event2 event,
		uint8_t **event_data_buf, size_t *event_data_size);
};

/**
 * Interface for platform specific intrusion_state processing.
 */
struct platform_intrusion_state_interface {
	/**
	 * Get platform specific digest size for the intrusion_state event type
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param digest_len Output the length of the digest.
	 *
	 * @return STATUS_SUCCESS if the digest length was successfully retrieved or an error code.
	 */
	int (*get_digest_len) (struct cerberus_interface *intf, size_t *digest_len);

	/**
	 * Gets the digest for the intrusion state event type from the TCG log.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param digest Output the digest for the intrusion state event type.
	 *
	 * @return STATUS_SUCCESS if the digest was successfully retrieved or an error code.
	 */
	int (*get_digest) (struct cerberus_interface *intf, uint8_t *digest);

	/**
	 * Gets the expected digest for a given intrusion state.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param state Intrusion state to get the expected digest for.
	 * @param exp_digest Output the expected digest for the intrusion state.
	 *
	 * @return STATUS_SUCCESS if the expected digest was successfully retrieved or an error code.
	 */
	int (*get_expected_digest) (struct cerberus_interface *intf,
		enum cerberus_intrusion_state state, const uint8_t **exp_digest);
};

/**
 * Interface for platform specific port state processing.
 *
 */
struct platform_port_state_interface {
	/**
	 * Get platform specific digest length for the port_state event type
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param pfm_port Port to get the digest length for.
	 * @param digest_len Output the length of the digest.
	 *
	 * @return STATUS_SUCCESS if the digest length was successfully retrieved or an error code.
	 */
	int (*get_digest_len) (struct cerberus_interface *intf, uint8_t pfm_port, size_t *digest_len);

	/**
	 * Gets the digest for the port state event type of a given port from the TCG log.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param pfm_port Port to get the digest for.
	 * @param digest Output the digest for the port state event type.
	 *
	 * @return STATUS_SUCCESS if the digest was successfully retrieved or an error code.
	 */
	int (*get_digest) (struct cerberus_interface *intf, uint8_t pfm_port, uint8_t *digest);

	/**
	 * Gets the expected digest for a port state on a given port.
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param pfm_port Port to get the expected digest for.
	 * @param state Port state to get the expected digest for.
	 * @param exp_digest Output the expected digest for the port state.
	 *
	 * @return STATUS_SUCCESS if the expected digest was successfully retrieved or an error code.
	 */
	int (*get_expected_digest) (struct cerberus_interface *intf, uint8_t pfm_port,
		enum cerberus_port_state state, const uint8_t **exp_digest);
};

/**
 * Interface for platform specific component status flow processing.
 */
struct platform_comp_status_interface {
	/**
	 * Get platform specific value for cfm_init_status event type
	 *
	 * @param intf Cerberus interface instance to utilize.
	 * @param event_type Output the event type value.
	 *
	 * @return STATUS_SUCCESS if the event type was successfully retrieved or an error code.
	 */
	int (*get_cfm_init_status_event_type) (struct cerberus_interface *intf, uint32_t *event_type);
};

/**
 * Interface for platform specific command and command flow handling
 */
struct cerberus_platform_interface {
	struct platform_debug_log_interface			debuglog;			/**< Platform specific debug log processing interface */
	struct platform_tcg_log_interface			tcglog;				/**< Platform specific TCG log processing interface */
	struct platform_intrusion_state_interface	intrusion_state;	/**< Platform specific intrusion state processing interface */
	struct platform_port_state_interface		port_state;			/**< Platform specific port state processing interface */
	struct platform_comp_status_interface		comp_state;			/**< Platform specific component status processing interface */
};

/**
 * Initialize the platform specific command flow interface.
 * Registers various platform specific methods in the cerberus_platform_interface structure.
 *
 * @param intf Cerberus interface instance to utilize.
 *
 * @return STATUS_SUCCESS if operation completed successfully or an error code.
 */
int cerberus_platform_interface_init (struct cerberus_interface *intf);


#ifdef __cplusplus
}
#endif

#endif //CERBERUS_UTILITY_PLATFORM_INTERFACE_
