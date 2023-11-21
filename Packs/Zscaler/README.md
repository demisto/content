<~XSIAM>
# Zscaler Internet access
This pack includes Cortex XSIAM content.


## Collect Events from Vendor

To configure the Zscaler Internet Access (ZIA) to send logs via the NSS feed output, refer to steps 1-3 in the following [XDR documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Zscaler-Internet-Access) which relates to both **Web logs** and **FW logs**.

#### More information on configuring NSS feed outputs:    
1. [Adding NSS Feeds for Firewall Logs](https://help.zscaler.com/zia/adding-nss-feeds-firewall-logs).
2. [Adding NSS Feeds for Web Logs](https://help.zscaler.com/zia/adding-nss-feeds-web-logs).
2. [NSS Feed Output Format: Firewall logs](https://help.zscaler.com/zia/nss-feed-output-format-firewall-logs).
4. [NSS Feed Output Format: Web Logs](https://help.zscaler.com/zia/nss-feed-output-format-web-logs).                                                                                                       


#### Notes:                        
- Make sure to specify the feed escape character as **=**.
- As mentioned in the documentation, make sure to add the feed output format for Web logs and/or FW logs.



### Configuring the Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. In the **General Settings** section, add the following details:
   * Port - specify the port of your log receiver host.
   * Protocol - choose TCP or UDP.
   * Format - specify to 'Auto-Detect'.
</~XSIAM>