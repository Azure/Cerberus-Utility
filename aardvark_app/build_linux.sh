#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

OS="Linux"
MARCH="x86"
AARDVARK_LIBS_DIR=external-aardvark-libs
C_COMPILER=gcc
C_COMPILER_PREFIX=
EXTERNAL_LIBS=mbedtls
export CORE_LIB_DIR=..
pushd .

cd $CORE_LIB_DIR/

# Build mbedtls
chmod +x recipes/build_external_libs_linux_default.sh
recipes/build_external_libs_linux_default.sh $MARCH $EXTERNAL_LIBS $C_COMPILER $C_COMPILER_PREFIX

# Generate version.mk file
chmod +x recipes/build_version_mk.sh
recipes/build_version_mk.sh

popd

# Build utility
make -f Makefile_Linux.mak clean OS=$OS MARCH=$MARCH
make -f Makefile_Linux.mak OS=$OS MARCH=$MARCH -j$(nproc)

# Copy Aardvark library from external folder to the utility executable folder
if [ -d $AARDVARK_LIBS_DIR ]; then
	cp $AARDVARK_LIBS_DIR/*.so $OS/$MARCH/bin/
fi
