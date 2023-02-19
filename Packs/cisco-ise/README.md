# Cisco ISE 
This pack includes Cortex XSIAM content. 
## Configuration on Server Side

Complete the following to configure basic log syslog collection:
1. Go to **Administration** > **System** > **Logging** > **Remote Logging Targets**
2. Click **Add** and then fill the required details.
3. Click **Save**, and then verify the creation of the new target by going to the **Remote Logging Targets** page. 

**Note:**
To prevent log segmentation, set the Maximum Length of the log to **8096**.

More information on remote logging configuration can be found [here](https://www.cisco.com/c/en/us/td/docs/security/ise/2-7/admin_guide/b_ise_27_admin_guide/b_ISE_admin_27_maintain_monitor.html#ID58). 

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - ise