# Siemens SiPass

<~XSIAM>

This pack includes Cortex XSIAM content.

## Configuration on Server Side
%%UPDATE%% <Add vendor's specifications>

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **Siemens**.
   | `Product`     | Enter **SiPass**.
 
</~XSIAM>