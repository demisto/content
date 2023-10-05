# Okta Access Gateway

This pack includes Cortex XSIAM content.

## Configuration on Server Side

#### Follow these steps for each of the three feeds: Audit, Access and Monitor

1. Navigate to your Access Gateway instance.
2. Select the **Logs and Backups** tab.
3. Select the **Log Forwarder** pane.
4. Select **+** > **Syslog remote**.
5. In the Add Forwarder: Syslog pane enter the following:
   - Name: The name of the forwarder.
   - Feed: AUDIT, ACCESS, or MONITOR
   - Protocol: Select either UDP or TCP. Ensure this protocol matches the log listener.
   - Host: Enter the DNS resolvable or IP address of the remote Syslog listener.
   - Port: Enter the port of the remote Syslog listener.
6. Click ***Validate Forwarder***. The Access Gateway then attempts to validate the remote logger connection information. If required, correct any input errors. On successful validation, the **Validate Forwarder** button changes to **Forwarder Validated**.
7. Click **Okay**. The log forwarder definition appears in the list of log forwarders.

* Pay attention: Timestamp support is available for the format **%Y-%m-%d{Key}%H:%M:%E3S%Ez**.

## Collect Events from Vendor

In order to use the collector, you can use the following option to collect events from the vendor:
 - [Broker VM](#broker-vm)

You will need to configure the vendor and product for this specific collector.
### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as vendor - Okta
   - product as product - OAG
