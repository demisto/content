# ManageEngine ADAudit Plus
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure ManageEngine ADAudit Plus to forward Syslog messages in **CEF format**.

Steps to enable Syslog Logging in ADAuditPlus:
1. Navigate to **Admin** tab > **SIEM Integration**.
2. Select the **Enable** checkbox and the **Syslog** radio button.
3. Enter the Syslog server name. Ensure that the Syslog server is reachable from the ADAuditPlus server.
4. Enter the Syslog port number and protocol.
5. Select the Syslog standard and data format as CEF.
6. After saving this configuration, select the categories to forward. 

#### More information on SIEM integration can be found [here](https://www.manageengine.com/products/active-directory-audit/help/getting-started/siem-integration.html)

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - ManageEngine
   - product as product - ADAudit
