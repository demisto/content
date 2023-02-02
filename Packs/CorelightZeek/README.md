# Corelight Zeek
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Corelight Sensor to forward Zeek Syslog messages.

1. Open Corelight Sensor UI, at the left bar choose "Configuration".
2. Open the "Export" tab and scroll down to "Export to Syslog";
    * Under "Syslog Server"- Set you XSIAM IP and Port numbers.
    * Under "Syslog Format"- Pick the "Default" option.
    * Under "Syslog Facility"- Set your Syslog Facility, E.g. Local0.
    * Under "Syslog Severity"- Select the severity for the logs you will sent, E.g. Info.
3. << Dreaft >> Monitor - Configure default settings (avilable in diffrent tabs)
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option. << Update id Needed >>

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/configure-your-broker-vm). << Update if needed >>

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - corelight
   - product as product - zeek