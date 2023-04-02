# Symantec Endpoint Protection
This pack includes Cortex XSIAM content. 
## Configuration on Server Side

1. Log in to Symantec Endpoint Protection Manager.
2. In the console, go to **Admin** > **Servers**.
3. Click the local site or remote site that you want to export log data from.
4. Click **Configure External Logging**.
5. Fill in all the needed information such as the Syslog Server's IP and the frequency for sending the logs. 

For more information, see the following: 
https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/Monitoring-Reporting-and-Enforcing-Compliance/viewing-logs-v7522439-d37e464/exporting-data-to-a-syslog-server-v8442743-d15e1107.html
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - symantec
   - product as product - ep
