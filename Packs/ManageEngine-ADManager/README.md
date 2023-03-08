# ManageEngine ADManager Plus
This pack includes Cortex XSIAM content. 
## Configuration on Server Side

Steps to enable Syslog Logging in ADManager Plus:
1. Log in to ADManager Plus.
2. Go to **Admin** > **Personlize** > **Integration**
3. Click the **Syslog Server** option.
4. Enter the details including Syslog Server Name, Port Number and Port Protocol. Also, choose the syslog standard and specify the data format needed for your XSIAM parser.
5. Click **Save**.

More information on a SIEM integration can be found [here](https://www.manageengine.com/products/ad-manager/admanager-kb/how-to-integrate-admanagerplus-with-splunk-and-syslog-servers.html).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - ManageEngine
   - product as product - ADManager
