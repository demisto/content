# Microsoft DHCP

This pack includes Cortex XSIAM content.

## Configuration on Server Side

1. Start the DHCP administration tool (go to Start → Programs → Administrative Tools, and click **DHCP**).
2. Right-click the DHCP server, and select **Properties** from the context menu.
3. Select the **General** tab.
4. Select the **Enable DHCP audit logging** checkbox.
5. Click **OK**.

Note:
Time parsing is supported only when the below fields have the mentioned formats:
- date - MM/dd/yy (01/10/21)
- time - hh:mm:ss (10:00:00)
- timezone - +|-nn:nn (+03:00)

## Collect Events from Vendor

In order to use the collector, use the [XDRC (XDR Collector)](#xdrc-xdr-collector) option.


### XDRC (XDR Collector)

To create or configure the Filebeat collector, use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2) and [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Add-an-XDR-Collector-Profile-for-Windows).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with *microsoft_dhcp_raw*.

As cortex XSIAM provides YAML template for DHCP, you can use the following steps to create a collection profile:

   1. In XSIAM, select **Settings** → **Configurations** → **XDR Collectors** → **Profiles** → **+Add Profile** → **Windows**.
   2. Select **Filebeat** profile or **Winlogbeat** profile, then click Next.
   3. Configure the General Information parameters:
   - Profile Name — Specify a unique Profile Name to identify the profile. The name can contain only letters, numbers, or spaces, and must be no more than 30 characters. The name you choose will be visible from the list of profiles when you configure a policy.

   - Add description here—(Optional) To provide additional context for the purpose or business reason that explains why you are creating the profile, specify a profile description.

   4. Configure the settings for the profile selected in Step 2 - To add the "DHCP" template, select it and click **Add**.