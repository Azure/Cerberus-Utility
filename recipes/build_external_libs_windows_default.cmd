REM Copyright (c) Microsoft Corporation. All rights reserved.
REM Licensed under the MIT license.


@echo off


set MARCH=AMD64
set vcvars=vcvars64.bat
set build_mbedtls=0
set build_release=0
set build_debug=0

if [%~1]==[ARM64] (
	set MARCH=ARM64
	set vcvars=vcvarsx86_arm64.bat
) else if [%~1]==[x86] (
	set MARCH=x86
	set vcvars=vcvars32.bat
)

 if [%~2]==[] (
	set build_release=1
	set build_debug=1
)

if [%~2]==[release] (
	set build_release=1
)

if [%~2]==[debug] (
	set build_debug=1
)

if [%~3]==[] (
    set build_mbedtls=1
)

if [%~3]==[mbedtls] (
	set build_mbedtls=1
)

echo build_mbedtls=%build_mbedtls% build_release=%build_release% build_debug=%build_debug% 

set TOP_DIR=%cd%
set MBEDTLS_DIR=%TOP_DIR%\crypto\mbedtls

set MSVC_RUNTIME=msvc_static

if %build_mbedtls%==1 (
	setlocal
	call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\%vcvars%"

	if %build_release%==1 (
		REM BUILD mbedtls using multithreaded and static version of run-time library
		call :mbedtls_build 0, 0, MultiThreaded
	)

	if %build_debug%==1 (
		REM Build mbedtls using debug multithreaded and static debug version of run-time library
		call :mbedtls_build 1, 0, MultiThreadedDebug
	)

	endlocal

	setlocal
	call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\%vcvars%" -vcvars_ver=14.1

	if %build_release%==1 (
		REM BUILD mbedtls using multithreaded and dll specific version of run-time library
		call :mbedtls_build 0, 1, MultiThreadedDLL
	)

	if %build_debug%==1 (
		REM Build mbedtls using debug multithreaded and dll specific version of run-time library
		call :mbedtls_build 1, 1, MultiThreadedDebugDLL
	)

	endlocal

	if %errorlevel% NEQ 0 goto build_exit
)

goto build_exit

:mbedtls_build
REM setup flags
if %~1==1 (
	set MBEDTLS_DEBUG=Debug
) else (
	set MBEDTLS_DEBUG=Release
)

if %~2==1 (
	set MSVC_RUNTIME=msvc_dll
)

REM Create MbedTLS makefile
cd %MBEDTLS_DIR%

if not exist build\NUL mkdir build
cd build
if not exist %MARCH%\NUL mkdir %MARCH%
cd %MARCH%
if exist CMakeCache.txt del CMakeCache.txt
if exist library\NUL @RD /S /Q "library"
if %errorlevel% NEQ 0 goto build_exit

cmake -G"NMake Makefiles" -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_MSVC_RUNTIME_LIBRARY=%~3 -DCMAKE_BUILD_TYPE=%MBEDTLS_DEBUG% -DENABLE_PROGRAMS=Off -DENABLE_TESTING=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DUSE_STATIC_MBEDTLS_LIBRARY=On ..\..

REM Build MbedTLS static libraries
nmake /nologo /S

xcopy /y %MBEDTLS_DIR%\build\%MARCH%\library\*.lib %TOP_DIR%\build\external_libs\Windows\%MARCH%\mbedtls\%MSVC_RUNTIME%\%MBEDTLS_DEBUG%\

if %MBEDTLS_DEBUG%==Debug (
	copy %MBEDTLS_DIR%\build\%MARCH%\library\CMakeFiles\mbedcrypto.dir\mbedcrypto.pdb %TOP_DIR%\build\external_libs\Windows\%MARCH%\mbedtls\%MSVC_RUNTIME%\%MBEDTLS_DEBUG%\
	copy %MBEDTLS_DIR%\build\%MARCH%\library\CMakeFiles\mbedtls.dir\mbedtls.pdb %TOP_DIR%\build\external_libs\Windows\%MARCH%\mbedtls\%MSVC_RUNTIME%\%MBEDTLS_DEBUG%\
	copy %MBEDTLS_DIR%\build\%MARCH%\library\CMakeFiles\mbedx509.dir\mbedx509.pdb %TOP_DIR%\build\external_libs\Windows\%MARCH%\mbedtls\%MSVC_RUNTIME%\%MBEDTLS_DEBUG%\
)
if %errorlevel% NEQ 0 goto build_exit
exit /B 0

:build_exit
EXIT /B %ERRORLEVEL%
