# Bluecat Address Manager
This pack includes Cortex XSIAM content. 

## Configuration on Server Side
You need to configure Bluecat Address Manager to forward Syslog messages to XSIAM.

Please proceed with the following steps to configure syslog redirection on the BAM server:
1. Select the **Administration** tab.
2. Under **General**, click **Service Configuration**.
3. From the **Service Type** drop-down menu, select **Syslog**.
4. Under **General Settings**, set the following parameters: Under Syslog Server — enter the IPv4 address of the BrokerVM and click **Add**. 
5. Click **Update**.
   

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - bluecat
   - product as product - address_manager