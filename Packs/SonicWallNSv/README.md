# SonicWall NSv
This pack includes Cortex XSIAM content. 

## Configuration on Server Side
You need to configure Sonicwall to forward logs in Syslog format and in UTC timezone.

### Configure Syslog forwarding
To configure the Sonicwall NSv to send Syslog to XSIAM server (Broker VM), use the steps described [here](https://www.sonicwall.com/support/knowledge-base/how-can-i-configure-a-syslog-server-on-a-sonicwall-firewall/170505984096810/).

### Configure Time zone
To configure Sonicwall to send logs in UTC formats please do the following:
1. Navigate to "Logs" -> "Syslog" -> "Syslog Settings"
2. Turn on "Display Syslog Timestamp in UTC"

Note: In order to parse the timestamp correctly, make sure that the timestamp is displayed in UTC.
The supported time format is yyyy-MM-dd hh:mm:ss (2021-12-08 10:00:00).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - sonicwall
   - product as product - ns