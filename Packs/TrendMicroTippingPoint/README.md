# Trend Micro TippingPoint
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure the Security Management System (SMS) of Trend Micro TippingPoint to forward Syslog messages in CEF format.

### Log in to the TippingPoint system and follow the below steps:
1. On the **Admin Navigation** menu, select **Server Properties**.
2. Select the **Syslog** tab.
3. Under **Remote Syslog for Events**, click **New**.
4. Select the **Enable** checkbox.
5. Configure the following values:
   - Syslog Server - The IP address of the XSIAM Broker.
   - Port - Type 514 as the port address.
   - Log Type - Select ArcSight CEF Format v4.2.
   - Facility - Select Log Audit.
   - Severity - Select Severity in Event.
   - Delimiter - Select Space as the delimiter for the generated logs.
   - Include Timestamp in Header - Select Use original event timestamp.
   - Select the Include SMS Hostname in Header check box.
6. Click **OK**.

More information can be found [here](https://docs.trendmicro.com/en-us/tippingpoint/security-management-system.aspx)


## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.