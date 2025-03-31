# Cisco ISR
This pack includes Cortex XSIAM content.

## Configuration on Server Side
You need to configure your Cisco ISR device to forward Syslog messages.

Perform the following in order to configure log forwarding:
1. Enter Global Configuration Mode by either typing **configure terminal** or **conf t**.
2. Input the destination of where the logs should be sent by typing **logging \<Hostname OR IP Address\>**.

The instructions above set the logging with default configuration values.

More information can be found [here](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/command/iosxe/qualified-cli-command-reference-guide/m-logging-commands.pdf)

### Syslog Time Parsing Support
Support for syslog timestamp parsing is available with UTC timezone only. You will need to add the year and milliseconds to the product default datetime format.
* [Service timestamps command doc](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/R_through_setup.html#wp4972384860)
* [Clock Timezone command doc](https://www.cisco.com/c/en/us/td/docs/routers/xr12000/software/xr12k_r3-9/system_management/command/reference/yr39xr12k_chapter4.html#wp748744425)

1. Enter Global Configuration Mode by either typing **configure terminal** or **conf t**.
2. Configure your syslog timestamp formatting by typing the command;
```bash
service timestamps log datetime year msec
```
3. Optional, to configure the timezone format to UTC, type the command;
```bash
clock timezone UTC 0
```
4. Revert back to Privileged EXEC mode by typing **end**. 
5. Save your changes by either typing 
```bash
write memory
```
OR
```bash
copy running-config startup-config 
```
And wait for system confirmation.

Timestamp ingestion is currently supported for the following formats in UTC time zone;
* mmm dd HH:MM:SS.sss - E.g. Jan 01 10:00:00.123
* mmm  d YYYY HH:MM:SS.sss - E.g. Feb  3 2025 22:04:01.776
* mmm dd YYYY HH:MM:SS.sss - E.g. Mar 01 2021 10:00:00.123

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - isr
 