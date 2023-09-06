# Cisco ASR
This pack includes Cortex XSIAM content. 
<~XSIAM>
## Configuration on Server Side
You need to configure your Cisco ASR device to forward Syslog messages.

Syslog message logging to the console terminal is enabled by default.
Perform the following in order to configure log forwarding [Documentation](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/asr9k-r6-5/system-monitoring/configuration/guide/b-system-monitoring-cg-asr9000-65x/b-system-monitoring-cg-asr9000-65x_chapter_0101.html#con_1092736):
1. Open your Cisco ASR supported device terminal and type **enable** to enter Privileged EXEC mode.
2. Enter Global Configuration Mode by either typing **configure terminal** or **conf t**.
3. Input the destination of where the logs should be sent by typing **logging \<Hostname OR IP Address \>**.

## Syslog Time Parsing Support
Support for syslog timestamp parsing is available with UTC timezone (system default). You will need to add the year and milliseconds to the product default datetime format.
* [Clock Timezone command doc](https://www.cisco.com/c/en/us/td/docs/routers/xr12000/software/xr12k_r3-9/system_management/command/reference/yr39xr12k_chapter4.html#wp748744425)
* [Logging commands doc](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/system_monitoring/command/reference/b-sysmon-cr-asr9k/b-sysmon-cr-asr9k_chapter_0100.html#wp1414739610)
1. Open your Cisco ASR supported device terminal and type **enable** to enter Privileged EXEC mode.
2. Enter Global Configuration Mode by either typing **configure terminal** or **conf t**.
3. Configure your syslog timestamp formatting by typing the command;
```bash
service timestamps log datetime year msec
```
5. Optional, to configure the timezone format to UTC, type the command;
```bash
clock timezone UTC 0
```
7. Revert back to Privileged EXEC mode by typing **end**. 
8. Save your changes by either typing 
```bash
write memory
OR
copy running-config startup-config 
```
And wait for system confirmation.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - asr
</~XSIAM>
