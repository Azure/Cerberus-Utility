#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# This script builds default external libraries necessary to build Cerberus Utility and
# for ARM64 builds this also installs the gcc compiler, if not already installed
# on the build machine.

C_COMPILER=$3
C_COMPILER_PREFIX=$4
ARCH=linux-x86_64
MARCH=$1
GCC_ARM_COMPILER_VERSION=10.2-2020.11

if [[ -d "build/external_libs/Linux" ]] && [[ $2 != "none" ]]; then
	rm -rf build/external_libs/Linux
fi


if [[ "$1" == "ARM64" ]] && [[ "$5" == "cc" ]]; then
	pushd .

	echo "building ARM GCC compiler"

	export PATH=$PATH:$(pwd)/gcc-arm-$GCC_ARM_COMPILER_VERSION-x86_64-aarch64-none-linux-gnu/bin
	aarch64-none-linux-gnu-gcc --version
	if [ $? -ne 0 ]; then
		wget https://developer.arm.com/-/media/Files/downloads/gnu-a/$GCC_ARM_COMPILER_VERSION/binrel/gcc-arm-$GCC_ARM_COMPILER_VERSION-x86_64-aarch64-none-linux-gnu.tar.xz
		tar -xvf gcc-arm-$GCC_ARM_COMPILER_VERSION-x86_64-aarch64-none-linux-gnu.tar.xz
		export PATH=$PATH:$(pwd)/gcc-arm-$GCC_ARM_COMPILER_VERSION-x86_64-aarch64-none-linux-gnu/bin
	fi
	C_COMPILER_PREFIX=aarch64-none-linux-gnu-
	C_COMPILER=aarch64-none-linux-gnu-gcc
	ARCH=linux-aarch64

	popd
fi

mkdir -p  build/external_libs/Linux/$MARCH

if [[ $2 == "mbedtls" || $2 == "all" ]]; then
	pushd .
	cd crypto/mbedtls
	if [ -d "build/Linux" ]
	then
		rm -rf build/Linux
	fi
	mkdir -p build/Linux
	cd build/Linux

	cmake -DCMAKE_C_COMPILER=$C_COMPILER -DCMAKE_POSITION_INDEPENDENT_CODE=true -DCMAKE_BUILD_TYPE=Release -DENABLE_PROGRAMS=Off -DENABLE_TESTING=Off -DUSE_STATIC_MBEDTLS_LIBRARY=On ../..
	make -j$(nproc)

	popd

	mkdir -p build/external_libs/Linux/$MARCH/mbedtls
	cp crypto/mbedtls/build/Linux/library/*.a build/external_libs/Linux/$MARCH/mbedtls/
fi
