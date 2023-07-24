# Corelight Zeek
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Corelight Sensor to forward Zeek Syslog messages.

1. Open the Corelight Sensor UI, and on the left menu bar click **Configuration**.
2. Open the **Export** tab and scroll down to **Export to Syslog**.
    * Under "Syslog Server"- Set your XSIAM IP and Port numbers.
    * Under **Syslog Format**- Pick the "Default" option.
    * Under **Syslog Facility**- Set your Syslog Facility, e.g., Local0.
    * Under **Syslog Severity**- Select the severity for the logs you will sent, e.g., Info.
3. Open the **Maintain** tab.
4. Under **Performance Monitoring**, enable the **Reporting to Syslog (UDP-Only)** option and set a time interval (e.g., 1min).
5. Under **Performance Monitoring**, enable the **Reporting Through Zeek Log Streams** option and set a time interval (e.g., 1min).

* Pay attention: Timestamp parsing support is under the a assumption that a UTC +0000 format is being used.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - corelight
   - product as product - zeek
