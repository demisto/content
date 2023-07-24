# ManageEngine ADManager Plus

This pack includes Cortex XSIAM content. 

<~XSIAM>
## Configuration on Server Side

Steps to enable Syslog Logging in ADManager Plus:
1. Log in to ADManager Plus.
2. Go to **Admin** > **Personlize** > **Integration**
3. Click the **Syslog Server** option.
4. Enter the details on the [*Syslog Settings*](https://www.manageengine.com/products/ad-manager/images/admanager-plus-being-integrated-with-syslog.png) form, including the **Syslog Server Name**, **Port Number** and **Port Protocol**.  In addition, select the [*RFC 5424*](https://datatracker.ietf.org/doc/html/rfc5424) **Syslog Standard** (recommended), and specify the requested data format for your Cortex XSIAM parser. 
5. Click **Save**.

*Please note*: Although Cortex XSIAM supports both [*RFC 5424*](https://datatracker.ietf.org/doc/html/rfc5424) and [*RFC 3164*](https://datatracker.ietf.org/doc/html/rfc3164) syslog standards, it is highly recommended you choose the more modern RFC 5424 standard over the obsolete RFC 3164. In contrast to the verbose timestamp format defined in RFC 5424, the RFC 3164 timestamp format lacks a timezone, which might cause time-difference issues for machines in different timezones. 

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

</~XSIAM>