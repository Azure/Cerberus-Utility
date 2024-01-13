#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if [ -z $CORE_LIB_DIR ]; then
	CORE_LIB_DIR=core
fi

if [ -z "$VERSION_FILE" ]; then
	VERSION_FILE=version.h
fi

if [ -z "$VERSION_MK" ]; then
	VERSION_MK=version.mk
fi

if [ -f "$VERSION_MK" ]; then
	rm $VERSION_MK
fi

# version variables used for building versioned shared object library
major=`grep -m 1 UTILITY_VERSION_MAJOR $VERSION_FILE | awk '{print $3}' | tr -d '\r\n'`
minor=`grep -m 1 UTILITY_VERSION_MINOR $VERSION_FILE | awk '{print $3}' | tr -d '\r\n'`
release=`grep -m 1 UTILITY_VERSION_RELEASE $VERSION_FILE | awk '{print $3}' | tr -d '\r\n'`
build=`grep -m 1 UTILITY_VERSION_BUILD $VERSION_FILE | awk '{print $3}' | tr -d '\r\n'`

python3 << EOF
import re

ver_file = open ("$VERSION_MK", "w")
ver_file.writelines(["VERSION_MAJOR := $major", "\nVERSION_MINOR := $minor", "\nVERSION_BUILD := $release", "\nVERSION_RELEASE := $build"])
ver_file.close ()
EOF
