# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

!IFNDEF CORE_LIB_D
!MESSAGE CORE_LIB_D is not set
EXIT /B 1
!ENDIF

!IFDEF DEBUG
LIBC_RT=/NODEFAULTLIB:"msvcrtd.lib"
!ELSE
LIBC_RT=/NODEFAULTLIB:"msvcrt.lib"
!ENDIF
LIBS_W=comsuppw.lib wbemuuid.lib
LIBS_MBEDTLS=$(CORE_LIB_D)\build\external_libs\$(OS)\$(MARCH)\mbedtls\$(LIBS_MBEDTLS_DIR)\mbedcrypto.lib $(CORE_LIB_D)\build\external_libs\$(OS)\$(MARCH)\mbedtls\$(LIBS_MBEDTLS_DIR)\mbedx509.lib
LIBS_EX=advapi32.lib kernel32.lib wsock32.lib ws2_32.lib iphlpapi.lib $(LIBS_W) $(LIBC_RT) $(LIBS_MBEDTLS)

SRC_D=.
APPCLI_D=$(CORE_LIB_D)\app_cli
AARDVARK_D=$(SRC_D)\aardvark
AARDVARK_INTF_D=$(SRC_D)\aardvark_interface

CRYPTO_D=$(CORE_LIB_D)\crypto
MBEDTLS_D=$(CRYPTO_D)\mbedtls

TMP_D=$(OS)\$(MARCH)\tmp
BIN_D=$(OS)\$(MARCH)\bin

INC=/I$(CORE_LIB_D) /I$(SRC_D) /I$(APPCLI_D) /I$(AARDVARK_D) /I$(AARDVARK_INTF_D) /I$(MBEDTLS_D)/include

CERBERUS_PDB=cerberus_interface.pdb
CERBERUS_APP_PDB=cerberus_utility.pdb

!IFDEF DEBUG
TARGET_BIN_D=$(BIN_D)\debug
LIBS_MBEDTLS_DIR=msvc_static\Debug
!ELSE
TARGET_BIN_D=$(BIN_D)\release
LIBS_MBEDTLS_DIR=msvc_static\Release
!ENDIF

!IFDEF DEBUG
CFLAGS_DBG=/Zi
DBG_F=d
!ENDIF
CFLAGS_O=/W3 /O2 $(CFLAGS_DBG) /MT$(DBG_F) /nologo
CF_EX=/DWIN32 $(INC) /D_CONSOLE /D_CRT_SECURE_NO_DEPRECATE /D_CRT_NONSTDC_NO_DEPRECATE /DHAVE_STRING_H /DCERBERUS_AARDVARK
!IFDEF DISABLE_CRYPTO
CFLAGS_M=$(CFLAGS_O) $(CF_EX) /DSKIP_MD2 /DMETACOMMAND /Fd$(TARGET_BIN_D)\$(CERBERUS_PDB)
!ELSE
CFLAGS_M=$(CFLAGS_O) $(CF_EX) /DSKIP_MD2 /DMETACOMMAND /Fd$(TARGET_BIN_D)\$(CERBERUS_PDB) /DCERBERUS_ENABLE_CRYPTO
!ENDIF

!IFDEF DEBUG
LFLAGS_DBG=/DEBUG
!ENDIF
LFLAGS=/nologo /subsystem:console /machine:$(MARCH) /opt:ref /opt:icf $(LFLAGS_DBG)

CC=cl
LINK=link
MKDIR=-mkdir
MKLIB=lib
RM=del
CP=copy
RC=rc

CERBERUS_APP=cerberus_utility.exe

L_OBJ=$(TMP_D)\aardvark_com.obj \
	  $(TMP_D)\aardvark.obj \
      $(TMP_D)\cerberus_utility_interface_init.obj \
      $(TMP_D)\cerberus_utility_interface.obj \
	  $(TMP_D)\cerberus_utility_common.obj \
      $(TMP_D)\cerberus_utility_status_codes.obj \
      $(TMP_D)\cerberus_utility_status_str.obj \
	  $(TMP_D)\cerberus_utility_aardvark_interface.obj \
      $(TMP_D)\cerberus_utility_mctp_interface.obj \
	  $(TMP_D)\cerberus_utility_mctp_params.obj \
      $(TMP_D)\cerberus_utility_mctp_protocol.obj \
      $(TMP_D)\cerberus_utility_cerberus_protocol.obj \
      $(TMP_D)\cerberus_utility_api.obj \
      $(TMP_D)\cerberus_utility_commands_internal.obj \
      $(TMP_D)\cerberus_utility_supported_interfaces.obj \
      $(TMP_D)\cerberus_utility_interface_parameters.obj \
      $(TMP_D)\cerberus_utility_debug_commands.obj \
      $(TMP_D)\cerberus_utility_crypto_interface.obj \
      $(TMP_D)\cerberus_utility_platform_interface.obj

CRYPTO_OBJ=$(TMP_D)\aes_mbedtls.obj \
      $(TMP_D)\ecc_mbedtls.obj \
      $(TMP_D)\rsa_mbedtls.obj \
      $(TMP_D)\hash_mbedtls.obj \
      $(TMP_D)\x509_mbedtls.obj \
      $(TMP_D)\rng_mbedtls.obj \
      $(TMP_D)\kdf.obj \
      $(TMP_D)\hash.obj

E_OBJ=$(TMP_D)\cerberus_utility_aardvark_app.obj \
      $(TMP_D)\cerberus_utility_cli.obj

###################################################################
bin: banner $(TMP_D) $(BIN_D) $(TARGET_BIN_D) exe

banner:
	@echo Building Cerberus Utility

$(TMP_D):
	$(MKDIR) $(TMP_D)
	@echo created $(TMP_D)

$(BIN_D):
	$(MKDIR) $(BIN_D)
	@echo created $(BIN_D)

$(TARGET_BIN_D):
	$(MKDIR) $(TARGET_BIN_D)
	@echo created $(TARGET_BIN_D)

exe: $(TARGET_BIN_D)\$(CERBERUS_APP)

objclean:
	$(RM) $(TMP_D)\*.obj 2>NUL

distclean: objclean
	-$(RM) /Q $(TARGET_BIN_D)\* 2>NUL

$(TMP_D)\aardvark_com.obj:  $(AARDVARK_D)\aardvark_com.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\aardvark.obj:  $(AARDVARK_D)\aardvark.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_interface_init.obj: $(CORE_LIB_D)\cerberus_utility_interface_init.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_interface.obj: $(CORE_LIB_D)\cerberus_utility_interface.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_common.obj: $(CORE_LIB_D)\cerberus_utility_common.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_api.obj: $(CORE_LIB_D)\cerberus_utility_api.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_commands_internal.obj: $(CORE_LIB_D)\cerberus_utility_commands_internal.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_interface_parameters.obj: $(CORE_LIB_D)\cerberus_utility_interface_parameters.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_supported_interfaces.obj: $(CORE_LIB_D)\cerberus_utility_supported_interfaces.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_debug_commands.obj: $(CORE_LIB_D)\cerberus_utility_debug_commands.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_mctp_interface.obj: $(CORE_LIB_D)\cerberus_utility_mctp_interface.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_mctp_protocol.obj: $(CORE_LIB_D)\cerberus_utility_mctp_protocol.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_mctp_params.obj: $(CORE_LIB_D)\cerberus_utility_mctp_params.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_cerberus_protocol.obj: $(CORE_LIB_D)\cerberus_utility_cerberus_protocol.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_status_codes.obj: $(CORE_LIB_D)\cerberus_utility_status_codes.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_status_str.obj: $(CORE_LIB_D)\cerberus_utility_status_str.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_crypto_interface.obj: $(CORE_LIB_D)\cerberus_utility_crypto_interface.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_platform_interface.obj: $(CORE_LIB_D)\cerberus_utility_platform_interface.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_aardvark_interface.obj: $(AARDVARK_INTF_D)\cerberus_utility_aardvark_interface.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_aardvark_app.obj: $(SRC_D)\cerberus_utility_aardvark_app.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\cerberus_utility_cli.obj: $(APPCLI_D)\cerberus_utility_cli.c
    $(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\aes_mbedtls.obj: $(CRYPTO_D)\aes_mbedtls.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\ecc_mbedtls.obj: $(CRYPTO_D)\ecc_mbedtls.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\rsa_mbedtls.obj: $(CRYPTO_D)\rsa_mbedtls.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\hash_mbedtls.obj: $(CRYPTO_D)\hash_mbedtls.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\x509_mbedtls.obj: $(CRYPTO_D)\x509_mbedtls.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\rng_mbedtls.obj: $(CRYPTO_D)\rng_mbedtls.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\hash.obj: $(CRYPTO_D)\hash.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\kdf.obj: $(CRYPTO_D)\kdf.c
	$(CC) /c $(CFLAGS_M) /Fo$@ $**

$(TMP_D)\Resources.res: $(SRC_D)\Resources.rc
	$(RC) /fo $(TMP_D)\Resources.res $(SRC_D)\Resources.rc

$(TARGET_BIN_D)\$(CERBERUS_APP): $(L_OBJ) $(CRYPTO_OBJ) $(E_OBJ) $(TMP_D)\Resources.res
    $(LINK) $(LFLAGS) /PDB:$(TARGET_BIN_D)\$(CERBERUS_APP_PDB) /OUT:$(TARGET_BIN_D)\$(CERBERUS_APP) $** $(LIBS_EX)
