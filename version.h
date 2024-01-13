// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef VERSION_H_
#define VERSION_H_


/* Version number components. */
#define	UTILITY_VERSION_MAJOR		0
#define	UTILITY_VERSION_MINOR		0
#define	UTILITY_VERSION_RELEASE		0
#define	UTILITY_VERSION_BUILD		0

/* Identifier for beta builds. */
#define	UTILITY_VERSION_IS_RELEASE	0
#if !UTILITY_VERSION_IS_RELEASE
#define	UTILITY_VERSION_TYPE		"-beta"
#else
#define	UTILITY_VERSION_TYPE		""
#endif


/* String macros to convert version number. */
#define	UTILITY_STRING(x)		#x
#define	UTILITY_TO_STRING(x)	UTILITY_STRING (x)


/**
 * The version number for the utility.
 */
#define	UTILITY_VERSION_NUM		((UTILITY_VERSION_MAJOR << 24) | (UTILITY_VERSION_MINOR << 16) | (UTILITY_VERSION_RELEASE << 8) | UTILITY_VERSION_BUILD)

/**
 * The version string for the utility.
 */
#define	UTILITY_VERSION_STRING	UTILITY_TO_STRING (UTILITY_VERSION_MAJOR) "." UTILITY_TO_STRING (UTILITY_VERSION_MINOR) "." UTILITY_TO_STRING (UTILITY_VERSION_RELEASE) "." UTILITY_TO_STRING (UTILITY_VERSION_BUILD) UTILITY_VERSION_TYPE


#endif /* VERSION_H_ */
