# Cisco Email Security
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure CISCO ESA to forward Syslog messages in CEF format [Documentation](https://docs.ces.cisco.com/docs/single-log-line-sll#sll-log-example).

Open Cisco ESA UI, and follow these instructions:
1. Under **System Administration** go to **Log Subscriptions**.
2. Press on **Add Log Subscription**.
3. Select the log type as **Consolidated Event Logs**.
4. Select the fields that you want in the consolidated event log.
5. Select a log retrieval mechanism for the log subscription.
6. Submit and commit your configuration changes.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - esa