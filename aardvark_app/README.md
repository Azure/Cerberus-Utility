# Introduction

This is the code to build Aardvark I2C Cerberus Utility for Windows and Linux.

Aardvark port of Cerberus Utility interfaces with Aardvark I2C/SPI Host
Adapter. Cerberus Utility makes use of APIs provided by Aardvark I2C/SPI
software to communicate with Cerberus over I2C bus.

More details about the Aardvark I2C/SPI host adapter can be found at

https://www.totalphase.com/products/aardvark-i2cspi/

# Building the Aardvark utility
To build Linux app, run `./build_linux.sh`

To build Windows app run `buildwin32.cmd`

# Usage
The aardvark variant of the utility needs shared object files `aardvark.dll/aardvark.so` (see [USB Driver](#usb-driver) for details) to communicate with Cerberus using Aardvark Host I2C/SPI adapter.

The utility will accept port number for adapter using `-p` and slave address using `-s` option.

If `--slave` option is used, the utility operates in master-slave mode instead of multi-master mode.

The aardvark variant of the utility supports the following command parameters:

```
        -p <number>               Connect to target over I2C. Specify port number
                                    e.g. -p 0 or -p 1
        -e <number>               EID of the target Cerberus device.
                                    Range: (0-0xfe)
        -r <retry_val>            Define number of MCTP retries
        -s <slave_addr>           I2C slave address of the device
        --slave                   I2C device is a slave instead of multi-master
        --debug <debug_val>       Turn on debug prints
                                    0x1 - I2C debug prints
                                    0x2 - MCTP debug prints
                                    0x4 - Command debug prints
        --time                    Display time it takes to execute commands in milliseconds
        --secure                  Issue command through an encrypted channel with Cerberus
```

# <a id="usb-driver"></a> USB Driver

For *Windows*, ensure the USB device drivers are installed before connecting
Aardvark I2C/SPI host adapter or running Cerberus Utility to communicate
with Cerberus device. Latest USB drivers for Windows can be downloaded from

https://www.totalphase.com/products/usb-drivers-windows/

For *Linux*, no specific kernel mode or user mode driver is required.

## Build dependencies
Cerberus Utility requires shared object file, aardvark.dll or aardvark.so
to call Aardvark APIs to communicate with Cerberus over I2C using USB host
interface.

**Note:** User is responsible to download these libraries to resolve the build dependencies.
The latest version of software API (aardvark.dll/aardvark.so) can be downloaded from
https://www.totalphase.com/products/aardvark-software-api/.

These libraries must be placed in the same folder as the aardvark utility executable.

On Windows, Cerberus Utility has been tested with Aardvark software API v5.30
On Linux, Cerberus Utility has been tested with Aardvark software API v5.50


