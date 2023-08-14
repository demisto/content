# VMware ESXi
This pack includes Cortex XSIAM content.

* Pay attention: Timestamp parsing is available for UTC timezone in the following formats:
  * %Y-%m-%dT%H:%M:%SZ - UTC +00:00 format.  
  * %Y-%m-%dT%H:%M:%E3SZ - UTC +00:00 format with 3 digits of fractional precision.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as vendor<- VMware
   - product as product<- Esxi
