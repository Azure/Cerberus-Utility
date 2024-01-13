// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_H_
#define X509_H_

#include <stdint.h>
#include <stddef.h>
#include "hash.h"


/**
 * The maximum value that can be put into a path length constraint.
 */
#define	X509_CERT_MAX_PATHLEN		15

/*
 * The types of certificates that can be created.  This will dictate the different types of
 * extensions that are present.
 */
#define	X509_CERT_END_ENTITY		0	/* An end entity certificate. */
#define	X509_CERT_CA				1	/* A certificate that can be used to sign other certificates. */
#define	X509_CERT_CA_PATHLEN(x)		((x & X509_CERT_MAX_PATHLEN) + X509_CERT_CA)	/* A CA certificate with a specified path length constraint. */
#define	X509_CERT_CA_NO_PATHLEN		(X509_CERT_CA_PATHLEN (X509_CERT_MAX_PATHLEN) + 1)	/* A certificate with no path length constraint specified. */


/**
 * Helper macro to get the path length constraint from the type.
 */
#define	X509_CERT_PATHLEN(x)		(x - X509_CERT_CA)


/**
 * The OID for the legacy RIoT extension to X.509 certificates.
 */
#define	X509_RIOT_OID					"1.3.6.1.4.1.311.89.3.1"
#define	X509_RIOT_OID_RAW				"\x2b\x06\x01\x04\x01\x82\x37\x59\x03\x01"

/**
 * The OID for the TCB Info extension from TCG DICE.
 */
#define	X509_TCG_DICE_TCBINFO_OID		"2.23.133.5.4.1"
#define	X509_TCG_DICE_TCBINFO_OID_RAW	"\x67\x81\x05\x05\x04\x01"

/**
 * The OID for the UEID extension from TCG DICE.
 */
#define	X509_TCG_DICE_UEID_OID			"2.23.133.5.4.4"
#define	X509_TCG_DICE_UEID_OID_RAW		"\x67\x81\x05\x05\x04\x04"

/**
 * Information for the device UEID.
 */
struct x509_dice_ueid {
	const uint8_t *ueid;				/**< Raw data for the unique identifier. */
	size_t length;						/**< Length of the UEID data. */
};

/**
 * Information necessary to populate DICE X.509 extensions.
 */
struct x509_dice_tcbinfo {
	const char *version;				/**< Version identifier for the firmware. */
	uint32_t svn;						/**< Security state of the device. */
	const uint8_t *fw_id;				/**< The firmware ID hash. */
	enum hash_type fw_id_hash;			/**< The type of hash used to generate the firmware ID. */
	const struct x509_dice_ueid *ueid;	/**< Optional Device unique identifier.  If this is not
											null, a UEID extension will be added. */
};


/**
 * The possible types of public keys in a certificate.
 */
enum {
	X509_PUBLIC_KEY_ECC,		/**< An ECC public key. */
	X509_PUBLIC_KEY_RSA			/**< An RSA public key. */
};


/**
 * The maximum length for a certificate serial number.
 */
#define	X509_MAX_SERIAL_NUMBER	20


/**
 * The possible version numbers for X.509 certificates.
 */
enum {
	X509_VERSION_1 = 1,			/**< A version 1 certificate. */
	X509_VERSION_2 = 2,			/**< A version 2 certificate. */
	X509_VERSION_3 = 3,			/**< A version 3 certificate. */
};


/**
 * An X.509 certificate.  A certificate instance is only usable by the engine that initialized it.
 */
struct x509_certificate {
	void *context;		/**< The implementation context for the certificate. */
};

/**
 * A store for X.509 certificate authorities that can be used for certificate authentication.
 * Certificates contained in this store can either be a trusted root CA or an untrusted intermediate
 * CA that is rooted in a trusted CA in the store.  The CA certificate store is only usable by the
 * engine that initialized it.
 */
struct x509_ca_certs {
	void *context;		/**< The implementation context for an intermediate certificate store. */
};

/**
 * A platform-independent API for handling certificates.  X509 engine instances are not guaranteed
 * to be thread-safe across different API calls.
 */
struct x509_engine {
	/**
	 * Load an X.509 certificate encoded in DER format.
	 *
	 * @param engine The X.509 engine to use to load the certificate.
	 * @param cert The certificate instance to initialize.
	 * @param der The DER formatted certificate to load.
	 * @param length The length of the certificate data.
	 *
	 * @return 0 if the certificate was loaded successfully or an error code.
	 */
	int (*load_certificate) (struct x509_engine *engine, struct x509_certificate *cert,
		const uint8_t *der, size_t length);

	/**
	 * Release an X.509 certificate.
	 *
	 * @param engine The engine used to initialize the certificate.
	 * @param cert The certificate instance to release.
	 */
	void (*release_certificate) (struct x509_engine *engine, struct x509_certificate *cert);

	/**
	 * Get the version of a certificate.
	 *
	 * @param engine The X.509 engine that initialized the certificate.
	 * @param cert The certificate to query.
	 * @param cert_version Buffer to hold certificate version.
	 *
	 * @return 0 if the certificate version was retrieved successfully or an error code.
	 */
	int (*get_certificate_version) (struct x509_engine *engine, const struct x509_certificate *cert, 
		int *cert_version);

	/**
	 * Get the serial number of a certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to query.
	 * @param serial_num Output buffer for the certificate serial number.  This should be at least
	 * X509_MAX_SERIAL_NUMBER bytes to have enough space for any serial number.
	 * @param length The length of the serial number buffer.
	 * @param serial_num_len Buffer to hold serial number length.
	 *
	 * @return 0 if the serial number was retrieved successfully or an error code.
	 */
	int (*get_serial_number) (struct x509_engine *engine, const struct x509_certificate *cert,
		uint8_t *serial_num, size_t length, size_t *serial_num_len);

	/**
	 * Get the type of public key contained in the certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to query.
	 * @param key_type Buffer to contain key type.
	 *
	 * @return 0 if the key type was retrieved successfully or an error code.
	 */
	int (*get_public_key_type) (struct x509_engine *engine, const struct x509_certificate *cert,
		int *key_type);

	/**
	 * Get the bit length of the public key contained in the certificate.  This represents the key
	 * strength, not the length of the encoded public key data.  For example, a certificate for an
	 * RSA 2k key would report 2048.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to query.
	 * @param key_len Buffer to hold bit length of the public key.
	 *
	 * @return 0 if the key length was retrieved successfully or an error code.
	 */
	int (*get_public_key_length) (struct x509_engine *engine, const struct x509_certificate *cert,
		size_t *key_len);

	/**
	 * Extract the public key from a certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate that contains the desired public key.
	 * @param key Output buffer for the DER formatted public key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param key_length Output for the length of the public key buffer.
	 *
	 * @return 0 if the public key was successfully retrieved or an error code.
	 */
	int (*get_public_key) (struct x509_engine *engine, const struct x509_certificate *cert,
		uint8_t **key, size_t *key_length);

	/**
	 * Initialize an empty certificate store for CA certificates to use for X.509 path validation.
	 *
	 * @param engine The X.509 engine to use for creating the certificate store.
	 * @param store The CA certificate store to initialize.
	 *
	 * @return 0 if the certificate store was successfully initialized or an error code.
	 */
	int (*init_ca_cert_store) (struct x509_engine *engine, struct x509_ca_certs *store);

	/**
	 * Release a store for CA certificates.
	 *
	 * @param engine The X.509 engine that initialized the certificate store.
	 * @param store The CA certificate store to release.
	 */
	void (*release_ca_cert_store) (struct x509_engine *engine, struct x509_ca_certs *store);

	/**
	 * Add the certificate for a certificate authority that should be implicitly trusted when
	 * authenticating other certificates.  The root CA must be self-signed, and will be checked for
	 * validity prior to adding it as a trusted certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate store.
	 * @param store The certificate store to add the root CA to.
	 * @param der The DER formatted certificate for the root CA.
	 * @param length The length of the certificate data.
	 *
	 * @return 0 if the certificate was successfully added or an error code.
	 */
	int (*add_root_ca) (struct x509_engine *engine, struct x509_ca_certs *store, const uint8_t *der,
		size_t length);

	/**
	 * Add the certificate for a certificate authority that can be used in path validation.  The
	 * certificate must be for a CA that is not self signed.  No verification is done on the
	 * certificate until it is used for path validation.
	 *
	 * Intermediate certificates must be added in validation order, with certificates signed by
	 * a root CA added first.
	 *
	 * @param engine The X.509 engine used to initialize the certificate store.
	 * @param store The certificate store to add the CA to.
	 * @param der The DER formatted certificate for the intermediate CA.
	 * @param length The length of the certificate data.
	 *
	 * @return 0 if the certificate was successfully added to the store or an error code.
	 */
	int (*add_intermediate_ca) (struct x509_engine *engine, struct x509_ca_certs *store,
		const uint8_t *der, size_t length);

	/**
	 * Determine if a certificate is valid and comes from a trusted source.
	 *
	 * @param engine The X.509 engine used to initialize both the certificate and the certificate
	 * store.
	 * @param cert The certificate to authenticate.
	 * @param store The set of certificate authorities that can be used to authenticate the
	 * certificate.
	 *
	 * @return 0 if the certificate is trusted or an error code.
	 */
	int (*authenticate) (struct x509_engine *engine, const struct x509_certificate *cert,
		const struct x509_ca_certs *store);
};


#endif /* X509_H_ */
