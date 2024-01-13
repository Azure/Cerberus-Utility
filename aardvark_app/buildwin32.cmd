REM Copyright (c) Microsoft Corporation. All rights reserved.
REM Licensed under the MIT license.


@echo off

set AARDVARK_APP_DIR=%cd%
set CORE_LIB_D=..
set AARDVARK_LIBS_D=external-aardvark-libs

set MARCH=x86
set OS=Windows
set UTMAKE=Makefile.mak

set build_bin=0
set build_bin_debug=0

if [%1]==[] (
  set build_bin=1
  set build_bin_debug=1
)

if [%1]==[bin] (
  set build_bin=1
)

if [%1]==[bin_debug] (
  set build_bin_debug=1
)

echo build_bin=%build_bin% build_bin_debug=%build_bin_debug%

REM Build mbedtls external library
cd %CORE_LIB_D%

setlocal
if %build_bin%==1 (
	echo building mbedtls_lib for Cerberus binary
	call recipes\build_external_libs_windows_default.cmd %MARCH% release mbedtls
)

if %build_bin_debug%==1 (
	echo building mbedtls_lib for Cerberus debug binary
	call recipes\build_external_libs_windows_default.cmd %MARCH% debug mbedtls
)
endlocal


setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"

if %build_bin%==1 (
  CALL :Build 0
  echo buildwin32 Cerberus Utility done
)

if %build_bin_debug%==1 (
  CALL :Build 1
  echo buildwin32 debug Cerberus Utility done
)
endlocal

cd %AARDVARK_APP_DIR%
EXIT /B %ERRORLEVEL%

:Build
REM Build Cerberus utility
cd %AARDVARK_APP_DIR%

if %~1==1 (
	set DEBUG=DEBUG=1
	set BIN_DIR=debug
) else (
	set BIN_DIR=release
)

nmake /nologo /S -f %UTMAKE% objclean MARCH=%MARCH% %DEBUG%
nmake /nologo /S -f %UTMAKE% bin MARCH=%MARCH% %DEBUG%

if exist %AARDVARK_LIBS_D%*.dll (
  xcopy /y %AARDVARK_LIBS_D%*.dll %AARDVARK_APP_DIR%\%OS%\%MARCH%\bin\%BIN_DIR%\
)
