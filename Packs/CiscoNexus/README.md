# Cisco Nexus
This pack includes Cortex XSIAM content.


## Configuration on Server Side
To configure a remote logging server on a Cisco Nexus switch, follow these steps:
1. Access the Nexus switch's command-line interface (CLI) through a console connection or SSH.
2. Enter privileged EXEC mode by typing "enable" and providing the appropriate password.
3. Enter configuration mode by typing "configure terminal".
```bash
 > enable
 # configure terminal
```
4. Specify the logging server by entering the following command:
```bash
 # logging server <server-ip-address>
```
*Note:
The logs will receive the correct timestamp only when the timezone is set to UTC; otherwise, the logs will display the "insert time" as the timestamp.*

To send logs to a remote server with UTC timezone, follow the official Cisco [documentation](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/fundamentals/cisco-nexus-9000-series-nx-os-fundamentals-configuration-guide-release-105x/m-basic-device-management.html#task_1231769).

5. To confirm these settings, show the remote syslog server configuration:
```bash
 # show logging server
```

6. Save the configuration:
```bash
 # copy running-config startup-config
```

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
   - product as product - nexus