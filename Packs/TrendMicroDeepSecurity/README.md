# Trend Micro Deep Security

This pack includes Cortex XSIAM content. 

## What does this pack do?
This pack enables you to:
- Configure policies and protect computers.
- Discover vulnerabilities and patch them.
- Perform routine maintenance tasks.

## Configuration on Trend Micro Deep Security management console

### Create API key for XSOAR
To use the Trend Deep Security APIs via XSOAR, you will need to create an API key in the Trend Deep Security console.

### Forward Syslog events to XSIAM
In order to send the Deep Security events to XSIAM,
Define a syslog configuration for forwarding events to a XSIAM broker VM in CEF format, 
and configure forwarding for the requested events - system events, security events, or both. 

#### Define a syslog configuration
On the Deep Security Manager Web Console, go to Policies --> Common Objects > Syslog Configuration. 
1. Set the Syslog port to 514 or your agent port.
2. Replace the "name" and "\<target-server IP address\>" in the CLI with the broker VM name and IP address.
Set the format to CEF.
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - Trend Micro
   - product as product - Deep Security