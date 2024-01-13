# Purpose
Cerberus Utility tool provides CLI access to communicate to Cerberus device.

# Cerberus Utility

The Cerberus Utility expects input in the following format:

```
cerberus_utility [setup_param] <command name> <command parameters>
```

## Setup Parameters

Common optional app setup parameters are defined below.

To find the setup parameters for a specific app, refer to its documentation or use [help](#help) command for guidance.

```
-s <slave_addr>         I2C slave address of the device.
-e <number>             Hex EID of the target Cerberus device.
                                Range: (0-0xfe)
-r <retry_val>          Define number of MTCP retries.
--secure                Issue command through an encrypted channel with Cerberus.
--time                  Display time it takes to execute commands in milliseconds.
--debug <debug_val>     Turn on debug prints.
                                0x1 - I2C debug prints
                                0x2 - MCTP debug prints
                                0x4 - Command debug prints
```

## Cerberus Utility Commands

The following is full list of Cerberus Utility commands.

### <a id="help"></a> **Help**

Display help output.

```
cerberus_utility help
```


### **Cerberus Firmware Version**

Get the firmware version of the specified Cerberus image.

```
cerberus_utility fwversion <area_id>
```
where `<area_id>` identifies the target firmware and can have one of the following values,
```
0: Cerberus Firmware (default)
1: RIoT Core Firmware
```


### **Cerberus Firmware Update**

Perform a Cerberus firmware update.

```
cerberus_utility fwupdate <path to fw binary>
```
Firmware image used must be a valid, signed update image.  Any other images will be rejected by the update handlers.


### **Cerberus PFM ID**

Retrieve the Cerberus PFM ID.

```
cerberus_utility pfmid <pfm_port> <pfm_region> <0:version ID, 1:platform ID>
```

`<pfm_port>` refers to the PFM used to verify a device connected to a SPI filter port. This will be platform specific (e.g. port 0 for BMC control, port 1 for BIOS control).

`<pfm_region>` refers to either active (0) or pending (1) PFM. A newly updated PFM will be stored in the pending region until Cerberus boots and validates the pending PFM, at which point it becomes the active PFM.


### **Cerberus PFM Versions List**

Retrieve the list of firmware versions Cerberus supports

```
cerberus_utility pfmversions <pfm_port> <pfm_region> [fw type]
```


### **Cerberus PFM Update**

Perform a Cerberus PFM update.

```
cerberus_utility pfmupdate <pfm_port> <path to PFM> <0:activate after reboot, 1:activate immediately>
```
PFMs used must be a valid, signed PFM.  Any other PFMs will be rejected by the update handlers.


### **Cerberus PFM Reboot Action**

Check Cerberus PFM actions that can be taken on reset of the host processor.

```
cerberus_utility pfmrebootaction <pfm_port>
```


### **Cerberus PFM Check Version Support**

Check if a PFM supports a specific FW version.

```
cerberus_utility pfmcheckversion <pfm_port> <pfm_region> <version string> [fw type]
```


### **Cerberus PFM Activate**

Run runtime verification for a staged PFM, and activate on success.

```
cerberus_utility pfmactivate <pfm_port> <0:activate after reboot, 1:activate immediately>
```


### **Cerberus Check Bypass**

Check for the presence of PFM for a port.

```
cerberus_utility checkbypass <pfm_port>
```
Command output indicating Port # in bypass mode will result in a failed command completion status indicating there are no PFMs on the port.  Command output indicating Port # in active mode indicates the presence of a PFM for the port but is not a clear indicator that the port is in active mode.  The presence of a PFM for the port may indicate that the port is in active mode or that the port booted in an insecure state.  The [portstate](#portstate) command is the best indicator of whether the port is in active or bypass mode.


### <a id="portstate"></a> **Cerberus Port State**

Check the mode of a port monitored by Cerberus.

```
cerberus_utility portstate <pfm_port>
```
A port in an unknown mode will result in a failed command completion status.


### **Cerberus Debug Log Read**

Retrieve Cerberus debug log entries.

```
cerberus_utility debuglogread
```


### **Cerberus Debug Log Clear**

Clear the Cerberus debug log.

```
cerberus_utility debuglogclear
```


### **Cerberus TCG Log Read**

Retrieve Cerberus TCG log entries.

```
cerberus_utility tcglogread
```


### **Cerberus TCG Log Clear**

Clear the Cerberus TCG log.

```
cerberus_utility tcglogclear
```


### **Cerberus TCG Log Export**

Export the Cerberus TCG log to a bin file.

```
cerberus_utility tcglogexport <filename> <mode>
```
It is possible to specify whether to export the TCG log compiled by the utility, the FW, or to attempt to grab the FW generated TCG log if available and fallback to the utility log otherwise.

The possible values for the `<mode>` parameter are:

```
0: autotdetect
1: generate in utility
2: generate in FW
```


### **Cerberus Export CSR**

Export the Cerberus Certificate Sign Request (CSR).

```
cerberus_utility exportcsr <filename>
```


### **Cerberus Import Signed Certificate**

Import signed device ID, intermediate CA or root CA certificate.

```
cerberus_utility importsignedcert <cert_id> <filename>
```
Where `<cert_id>` identifies the certificate that’s imported and can have one of the following values,
```
0: Device id Certificate
1: Root CA Certificate
2: Intermediate CA Certificate
```
After the certificate is sent to the device, an attempt will be made to validate the entire certificate chain.  Once the certificate chain has been successfully validated by the device, future calls to this command will fail.


### **Cerberus Get Signed Certificate State**

Determine if the device has a valid certificate chain for a signed device ID.

```
cerberus_utility getcertstate
```


### **Cerberus Intrusion State**

Check the intrusion state tracked by Cerberus.

```
cerberus_utility intrusionstate
```

### **Cerberus Reset Intrusion State**
The command sequence and requirements to reset the intrusion state from the intruded state to the non-intruded state is the same as [reverting to bypass mode](#revertbypass), just with a different operation.
```
cerberus_utility intrusionreset <filename> 0
```
Send the signed token to reset the intrusion state:
```
cerberus_utility intrusionreset <filename> 1
```

### <a id="revertbypass"></a> **Cerberus Revert to Bypass Mode**

Going from Active to Bypass mode is a two step process.

First, a token to unlock the operation needs to be generated by the device. This token can only be used once and only on the device that generated it.  To get the token and store it to a file:
```
cerberus_utility revertbypass <filename> 0
```
If the request for a token fails with an indication that the operation is not authorized, the device cannot be reverted to bypass mode.

If the operation is allowed and a token is received, the token must be signed with a Cerberus key. The signed token can be sent to the device to go back to bypass mode with:
```
cerberus_utility revertbypass <filename> 1
```


### **Cerberus Restore Factory Defaults**

The command sequence and requirements to clear out all configuration is the same as [reverting to bypass mode](#revertbypass), just with a different operation:

```
cerberus_utility factorydefault <filename> 0
```
Send the signed token to clear the configuration:
```
cerberus_utility factorydefault <filename> 1
```


### **Cerberus Clear PCD**

The command sequence and requirements to clear the device’s PCD is the same as [reverting to bypass mode](#revertbypass), just with a different operation:
```
cerberus_utility clearpcd <filename> 0
```
Send the signed token to clear the configuration:
```
cerberus_utility clearpcd <filename> 1
```


### **Cerberus Clear CFM**

The command sequence and requirements to clear the device’s CFM is the same as [reverting to bypass mode](#revertbypass), just with a different operation:
```
cerberus_utility clearcfm <filename> 0
```
Send the signed token to clear the configuration:
```
cerberus_utility clearcfm <filename> 1
```


### **Cerberus PCD ID**

Retrieve the Cerberus PCD ID.

```
cerberus_utility pcdid <0:version ID, 1:platform ID>
```


### **Cerberus PCD Update**

Perform a Cerberus PCD update.

```
cerberus_utility pcdupdate <filename>
```
PCDs used must be a valid, signed PCD. Any other PCDs will be rejected by the update handlers.


### **Cerberus CFM ID**

Retrieve the Cerberus CFM ID.

```
cerberus_utility cfmid <cfm_region> <0:version ID, 1:platform ID>
```


### **Cerberus CFM Update**

Perform a Cerberus CFM update.

```
cerberus_utility cfmupdate <filename> <0:activate after reboot, 1:activate immediately>
```
CFMs used must be a valid, signed CFM.  Any other CFMs will be rejected by the update handlers.


### **Cerberus CFM Activate**

Run runtime verification for a staged CFM, and activate on success.

```
cerberus_utility cfmactivate <0:activate after reboot, 1:activate immediately>
```


### **Cerberus CFM Components**

Get list of components supported by requested CFM.

```
cerberus_utility cfmcomponents <cfm_region>
```


### **Cerberus Get Host State**

Retrieve the reset state of the host processor being protected by Cerberus.

```
cerberus_utility hoststate <host_port>
```


### **Cerberus Host Recovery Image Update**

Perform a Cerberus host recovery image update.

```
cerberus_utility recimgupdate <recovery_port> <path to recovery image>
```
Recovery images used must be a valid, signed recovery image.  Any other images will be rejected by the update handlers.


### **Cerberus Host Recovery Image Version**

Retrieve the active Cerberus recovery image version.

```
cerberus_utility recimgversion <recovery_port>
```


### **Cerberus Device Information**

Get the unique identifier for the chip in raw ASCII format.

```
cerberus_utility deviceinfo
```


### **Cerberus Device ID**

Determine unique Cerberus ID.

```
cerberus_utility deviceid
```


### **Cerberus Device Capabilities**

Determine Cerberus device capabilities.

```
cerberus_utility devicecaps
```


### **Cerberus Get Reset Counter**

Get the Cerberus and Component reset counter since power-on.

```
cerberus_utility getresetcounter <type> <port>
```
where `<type>` identifies the target firmware and can have one of the following values,
```
0: Cerberus Firmware (default)
1: Component Firmware
```


### **Cerberus Get Certificate Chain**

Get a complete certificate chain from the device.

```
cerberus_utility getcertchain <slot> [basename]
```

where `<slot>` identifies the certificate chain to retrieve:
```
0: RIoT certificates
1: Attestation certificates
```
`[basename]` is an optional parameter to use for naming the output files. The files will be named **<basename>_<#>.der** with **<#>** indicating the certificate index in the chain. If no base file name is provided, **cert** is used as the default.


### **Cerberus Get Certificate**

Get a single certificate from the device.

```
cerberus_utility getcert <slot> <cert> <filename>
```

where `<slot>` identifies the certificate chain to query:
```
0: RIoT certificates
1: Attestation certificates
```

`<cert>` indicates the certificate index in the chain starting at the root CA and incremented sequentially for subsequent certificates. For example, typical values will be:
```
0: Root CA
1: Intermediate CA
2: Device ID
3: Alias / Attestation
```

`<filename>` is the file where the certificate data should be stored.  The certificate will be an **X.509 DER** encoded certificate.


### **Cerberus Get Certificate Digests**

Get certificate digests for a certificate chain from the device.
```
cerberus_utility getdigests [slot]
```

where `[slot]` identifies the certificate chain to retrieve:
```
0: RIoT certificates
1: Attestation certificates
```
If this is not specified, **slot 0** is retrieved.


### **Get SVN**

Retrieve the SVNs.
```
cerberus_utility getsvn
```


### **Cerberus Detect Device**

Determine if a platform is expected to have a Cerberus device.

```
cerberus_utility detectdevice
```


### **Cerberus Challenge**

Verify the Cerberus Challenge.

```
cerberus_utility challenge
```


### **Cerberus Test Error Message**

Test Cerberus error message interface.

```
cerberus_utility testerror
```


### **Unseal**

To test Cerberus unseal flows, ‘sealed’ data will need to be created.

Once the ‘sealed’ data is available, run:

```
cerberus_utility unseal <type> <param> <seed> <cipher> <sealing> <hmac>
```

where,
`<type>` identifies the type of unseal operation to perform:
```
0: RSA
1: ECDH
```

`<params>` indicates additional parameters necessary to processing the sealing seed:
```
    For RSA:
	    0:  PCKS#1 v1.5 padding
	    1:  OAEP padding with SHA-1
	    2:  OAEP padding with SHA-256

    For ECDH:
	    0:  Seed is the ECDH output
    	1:  Seed is the SHA-256 hash of the ECDH output

```

`<seed>` is the file for the seed data.

`<cipher>` is the ciphertext file that is sealed.

`<sealing>` is the file containing the PMR policy values the data is sealed to.

`<hmac>` is the file that contains the HMAC over the ciphertext and sealing files.


### **Cerberus Components Status**

Retrieve the Cerberus component attestation statuses.
```
cerberus_utility compstate
```


### **Device Diagnostics**

Some devices support additional commands to provide diagnostic information about device state.

*Heap Usage*

To query the device for current heap usage:

```
cerberus_utility diagheap
```


### **Cerberus Print MCTP Bridge Routing Table**

Fetch and print routing table from MCTP bridge using the MCTP control protocol.
```
cerberus_utility mctproutingtable
```
