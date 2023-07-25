# NGINX
This pack includes Cortex XSIAM content. 


## Configuration on Server Side


Note: In order to parse the timestamp correctly, make sure that the timestamp is set to UTC time zone.
The supported time formats are: 
- dd/MMM/yyyy:hh:mm:ss [+|-]nnnn (18/Jul/2021:10:00:00 +0000)
- yyyy/MM/dd hh:mm:ss (2020/01/19 10:00:00)


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - nginx
   - product as product - nginx
