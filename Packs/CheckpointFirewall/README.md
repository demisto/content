# Check Point Firewall

This pack includes Cortex XSIAM content.
<~XSIAM>

## Configuration on Server Side

You need to configure Check Point to forward Syslog messages in CEF format.

Go to Checkpoint Log Export, and follow the instructions under **Basic Deployment** to set up the connection using the following guidelines:

1. If you use version R77.30 or R80.10, follow the instructions to install a Log Exporter.
2. Set the Syslog port to 514 or your agent port.
3. Replace the **name** and **\<target-server IP address\>** in the CLI with the broker VM name and IP address.
Set the format to CEF.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - Checkpoint
   - product as product - Firewall
</~XSIAM>
