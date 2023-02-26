# Microsoft DHCP

This pack includes Cortex XSIAM content.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options:
1. [XDRC (XDR Collector)](#xdrc-xdr-collector) option.
2. [Broker VM](#broker-vm) option.




### XDRC (XDR Collector)

To create or configure the Filebeat collector, use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with *microsoft_dhcp_raw*.

As cortex XSIAM provides YAML template for Windows Security Event Logs, you can use the following steps to create a collection profile:

   1. In Cortex XDR, select **Settings** → **Configurations** → **XDR Collectors** → **Profiles** → **+Add Profile** → **Windows**.
   2. Select **Winlogbeat**, then click **Next**.
   3. Configure the General Information parameters:
   - Profile Name — Specify a unique Profile Name to identify the profile. The name can contain only letters, numbers, or spaces, and must be no more than 30 characters. The name you choose will be visible from the list of profiles when you configure a policy.

   - Add description here — (Optional) To provide additional context for the purpose or business reason that explains why you are creating the profile, specify a profile description.

   4. Configure the settings for the profile selected in Step 2 - To add the "Windows Security" template, select it and click **Add**.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).


1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**. 
2. Right-click, and select **add app* → **Windows Event Collector**.