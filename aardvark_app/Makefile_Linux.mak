# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

ifeq ($(CORE_LIB_DIR), )
$(error CORE_LIB_DIR is not set)
endif

include $(CORE_LIB_DIR)/recipes/cerberus_utility_defaults.mk

SRC_DIR := .
AARDVARK_DIR := aardvark
AARDVARK_INTF_DIR := aardvark_interface

# App specific lib sources
LIB_SRCS += $(wildcard $(AARDVARK_DIR)/*.c)
LIB_SRCS += $(wildcard $(AARDVARK_INTF_DIR)/*.c)

# App sources
UTILITY_APP_SRCS += cerberus_utility_aardvark_app.c

# App specific includes
APP_INC := $(SRC_DIR) $(AARDVARK_DIR) $(AARDVARK_INTF_DIR)
INC_FLAGS += $(addprefix -I,$(sort $(APP_INC)))

# App specific external standard lib dependencies
STANDARD_DEPLIB += dl

# App specific flags
override CFLAGS += -DCERBERUS_ENABLE_CRYPTO -DCERBERUS_AARDVARK

# App specific source file search paths
VPATH +=  $(SRC_DIR) $(AARDVARK_DIR) $(AARDVARK_INTF_DIR)

include $(CORE_LIB_DIR)/recipes/cerberus_utility_compile.mk
