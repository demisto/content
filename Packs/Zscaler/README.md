<~XSIAM>
# Zscaler Internet access
This pack includes Cortex XSIAM content.


## config syslog CEF in Zscaler:

**Add an NSS Server:**

Link to the configuration in Zscaler website:
https://help.zscaler.com/zia/adding-nss-servers

1. Go to **Administration** > **Nanolog Streaming Service**.
2. From the **NSS Servers** tab, click **Add NSS Server**.
3. In the **Add NSS Server** window:
   * Name: Enter a name for the NSS server.
   * Type: The NSS for Web type is selected by default. To configure NSS for firewall logs, select **NSS for Firewall**.
     *Note*: If you have a subscription to Cloud Connector, the NSS for Firewall (NSS type) is displayed as NSS for Firewall, Cloud and Branch Connector.
   * Status: Enable or disable the status of the NSS server.
   * State: The health of the NSS server. This field is non-configurable.

4. Click **Save.** The NSS server gets added to your ZIA Admin Portal.
![Add NSS Server](https://raw.githubusercontent.com/demisto/content/9dc21658443d25d7eaf62106b24a2d3c7e9d367d/Packs/Zscaler/doc_files/add_nss_server.png)

**To download the SSL Certificate:**
1. Click the **Edit** icon corresponding to the NSS server.
2. In the **Edit NSS Server** window, under the **SSL Certificate** field, you can either download the SSL Certificate or generate a new certificate for that NSS server. You can upload this SSL certificate to the desired platform.
![Edit NSS Server](https://raw.githubusercontent.com/demisto/content/9dc21658443d25d7eaf62106b24a2d3c7e9d367d/Packs/Zscaler/doc_files/edit_nss_server.png)

**Add NSS Feeds:**

Click and follow the instructions in each of the following links.:

* Web Logs: https://help.zscaler.com/zia/adding-nss-feeds-web-logs
* SaaS Security Logs: https://help.zscaler.com/zia/adding-nss-feeds-saas-security-logs

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - zscaler
   - product as product - nssweblog

</~XSIAM>