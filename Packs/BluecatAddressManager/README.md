# Bluecat Address Manager
This pack includes Cortex XSIAM content. 

## Configuration on Server Side
You need to configure Bluecat Address Manager to forward Syslog messages to XSIAM in UTC format.

#### Please proceed with the following steps to configure syslog redirection on the BAM server:
1. Select the **Administration** tab.
2. Under **General**, click **Service Configuration**.
3. From the **Service Type** dropdown menu, select **Syslog**.
4. Under **General Settings** > **Syslog Server** enter the IPv4 address of the BrokerVM and click **Add**. 
5. Click **Update**.

#### To configure the BAM server to send logs in UTC format, complete the following steps:
1. Log in to the BlueCat Address Manager web interface using your administrator credentials.
2. Click the **Administration** tab located at the top of the page.
3. In the left-hand navigation pane, click **System** and then select **System Configuration**.
4. In the **System Configuration** page, you will see various configuration options. Look for the **Timezone** section.
5. Click the **Edit** button next to the **Timezone** field.
6. A pop-up window or a dropdown menu will appear, depending on the version of BlueCat Address Manager you are using.
  - If it's a pop-up window, select the desired timezone from the list provided and click **Save** or **Apply** to save the changes.
  -  If it's a dropdown menu, click the dropdown arrow and select the desired timezone from the list. Then click **Save** or **Apply** to save the changes.
Once you have saved the changes, the timezone in BlueCat Address Manager will be updated accordingly.

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