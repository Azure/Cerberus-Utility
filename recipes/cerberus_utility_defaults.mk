# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.


OS ?= Linux
MARCH ?= AMD64

# common build artifact folders
BUILD_OUT_DIR ?= $(OS)/$(MARCH)/obj/
APP_OUT_DIR ?= $(OS)/$(MARCH)/bin/
LIB_OUT_DIR ?= $(OS)/$(MARCH)/lib/

# common sources
CORE_LIB_DIR ?= ..
CRYPTO_DIR := $(CORE_LIB_DIR)/crypto
APPCLI_DIR := $(CORE_LIB_DIR)/app_cli

LIB_SRCS += $(wildcard $(CORE_LIB_DIR)/*.c)
LIB_SRCS += $(wildcard $(CRYPTO_DIR)/*.c)

UTILITY_APP_SRCS += $(wildcard $(APPCLI_DIR)/*.c)

# common external libs
MBEDTLS_LIBS := mbedtls mbedcrypto mbedx509
MBEDTLS_STATIC_LIBS := $(addsuffix .a, $(addprefix lib, $(MBEDTLS_LIBS)))

# common external libs default build out and include paths.
MBEDTLS_LIB_DIR ?= $(CORE_LIB_DIR)/build/external_libs/$(OS)/$(MARCH)/mbedtls/
ifneq ("$(wildcard $(MBEDTLS_LIB_DIR)*.*)", "")
MBEDTLS_INC_DIR ?= $(CRYPTO_DIR)/mbedtls/include/
EXTERNAL_STATIC_LIBS += $(addprefix $(MBEDTLS_LIB_DIR), $(MBEDTLS_STATIC_LIBS))
endif

# common external lib dependencies
EXTERNAL_DEPLIB += $(MBEDTLS_LIBS)

# common standard lib dependencies
STANDARD_DEPLIB += m rt

# common include dirs
INC := $(CORE_LIB_DIR) $(MBEDTLS_INC_DIR) $(APPCLI_DIR)
INC_FLAGS += $(addprefix -I,$(sort $(INC)))

# common flags
override LDFLAGS += -L$(MBEDTLS_LIB_DIR) -L$(LIB_OUT_DIR)
override CFLAGS += -g -Wall -Wextra

# common vpath dirs
VPATH += $(CORE_LIB_DIR) $(CRYPTO_DIR) $(APPCLI_DIR)

# default app target names
UTILITY_APP_OUT ?= $(APP_OUT_DIR)cerberus_utility
UTILITY_APP_SO_OUT ?= $(APP_OUT_DIR)cerberus_utility_so

# Default static and shared lib target names
UTILITY_LIB_NAME ?= cerberus_utility
LIB_CERBERUS_UTILITY ?= libcerberus_utility

## default static lib
LIB_STATIC_NAME ?= $(addsuffix .a, $(addprefix lib, $(UTILITY_LIB_NAME)))
LIB_STATIC_TARGET ?= $(LIB_OUT_DIR)$(LIB_STATIC_NAME)
LIB_STATIC_TARGET_TMP ?= $(BUILD_OUT_DIR)libcerberus_utility_tmp.a

# Give version number for to the shared library target
include $(CORE_LIB_DIR)/version.mk
LIB_SO_NAME ?= $(addsuffix .so, $(addprefix lib, $(UTILITY_LIB_NAME)))
LIB_SO_MAJOR := $(LIB_SO_NAME).$(VERSION_MAJOR)
LIB_SO_MAJ_MIN := $(LIB_SO_NAME).$(VERSION_MAJOR).$(VERSION_MINOR)
LIB_SO_MAJ_MIN_BUILD := $(LIB_SO_NAME).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_BUILD)
LIB_SO_TARGET := $(LIB_OUT_DIR)$(LIB_SO_MAJ_MIN_BUILD)
