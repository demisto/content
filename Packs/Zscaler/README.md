# Zscaler Internet Access

<~XSIAM>  
This pack includes Cortex XSIAM content. It supports ingestion and modeling both for ZIA logs which are streamed via *[VM-based NSS Feed](https://help.zscaler.com/zia/understanding-nanolog-streaming-service#vm-based-nss-deployment)*, and for ZIA logs which are streamed via *[Cloud NSS Feed](https://help.zscaler.com/zia/understanding-nanolog-streaming-service#cloud-nss)*. 

The sections below describe the necessary configurations required on Cortex XSIAM and Zscaler ZIA for each NSS feed type. 

## Configuration for Cloud NSS (HTTPS API Feed)

### Configure an HTTP Log Collector on XSIAM 

1. Navigate to **Settings** &rarr; **Configurations** &rarr; **Data Collection** &rarr; **Data Sources**.
2. Set a new instance for the *Custom - HTTP based Collector* data source as follows -
   
   | Parameter Name | Value                                                            |
   | :--------------| :--------------------------------------------------------------- | 
   | `Name`         | Specify a descriptive Name, for e.g., *Zscaler ZIA Cloud NSS*.   | 
   | `Compression`  | Select *gzip*.                                                   | 
   | `Log Format`   | Select *JSON*.                                                   | 
   | `Vendor`       | Enter *zscaler*.                                                 |
   | `Product`      | Enter *cloudnss*.                                                | 

3. Click **Save & Generate Token**.
   1. Click the **Copy** icon and record the copied generated token somewhere safe. You will need to provide this token when you configure the ZIA Cloud NSS feed on Zscaler. 
   2. Click **Done** when finished.
4. Hover over the new created HTTP Collector instance, and click the **Copy API URL**. You will need to provide this URL when you configure the ZIA Cloud NSS feed on Zscaler. 

### Configure a Cloud NSS Feed on Zscaler ZIA Admin Portal

You will need to [add a Cloud NSS Feed](https://help.zscaler.com/zia/adding-cloud-nss-feeds) on the Zscaler ZIA Admin Portal for each log type to subscribe to. 
- [Adding Cloud NSS Feeds for Web Logs](https://help.zscaler.com/zia/adding-cloud-nss-feeds-web-logs)
- [Adding Cloud NSS Feeds for DNS Logs](https://help.zscaler.com/zia/adding-cloud-nss-feeds-dns-logs)
- [Adding Cloud NSS Feeds for Admin Audit Logs](https://help.zscaler.com/zia/adding-cloud-nss-feeds-admin-audit-logs)
- [Adding Cloud NSS Feeds for Firewall Logs](https://help.zscaler.com/zia/adding-cloud-nss-feeds-for-firewall-logs)

#### Remarks 
For each Cloud NSS Feed you configure: 
  - Set the **`API URL`** to the URL of the Cortex XSIAM HTTP Collector Zscaler instance.
  - Set the **`Key 1`** HTTP header name to *Authorization*.
  - Set the **`Value 1`** Http Header value to the generated token of the Zscaler HTTP Collector instance. 
  - Select *JSON* for the **`Feed Output Type`**.
  - In order to assign the *_time* field on Cortex XSIAM with the event record's timestamp, the feed output format you configure must include either the timestamp as an epoch value if such exists (for e.g., *`%d{epochtime}`* on the [Web logs output format](https://help.zscaler.com/zia/nss-feed-output-format-web-logs#:~:text=Mon-,%25d%7Bepochtime%7D,-The%20epoch%20time)), or a formatted date/time string representation along it's corresponding time zone field (for e.g., *`%s{tz}`* on the [Admin Audit logs output format](https://help.zscaler.com/zia/nss-feed-output-format-admin-audit-logs#:~:text=55%3A48%202023-,%25s%7Btz%7D,-The%20time%20zone)). See the following links for the available output formats for each log type, and general guidelines for each the feeds formats: 
    - [General Guidelines for NSS Feeds and Feed Formats](https://help.zscaler.com/zia/general-guidelines-nss-feeds-and-feed-formats).
    - [NSS Feed Output Format: Web Logs](https://help.zscaler.com/zia/nss-feed-output-format-web-logs).
    - [NSS Feed Output Format: DNS Logs](https://help.zscaler.com/zia/nss-feed-output-format-dns-logs).
    - [NSS Feed Output Format: Admin Audit Logs](https://help.zscaler.com/zia/nss-feed-output-format-admin-audit-logs).
    - [NSS Feed Output Format: Firewall Logs](https://help.zscaler.com/zia/nss-feed-output-format-firewall-logs)

For additional details, see [About Cloud NSS Feeds](https://help.zscaler.com/zia/about-cloud-nss-feeds).


## Configurations for VM-Based NSS (Syslog Over TCP)

### Configure a VM-Based NSS Feed on Zscaler ZIA Admin Portal

To configure the Zscaler Internet Access (ZIA) to send logs via the NSS feed output, refer to steps 1-3 in the following [XDR documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Zscaler-Internet-Access) which relates to both **Web logs** and **FW logs**.

#### More information on configuring NSS feed outputs:    
1. [Adding NSS Feeds for Firewall Logs](https://help.zscaler.com/zia/adding-nss-feeds-firewall-logs).
2. [Adding NSS Feeds for Web Logs](https://help.zscaler.com/zia/adding-nss-feeds-web-logs).
2. [NSS Feed Output Format: Firewall logs](https://help.zscaler.com/zia/nss-feed-output-format-firewall-logs).
4. [NSS Feed Output Format: Web Logs](https://help.zscaler.com/zia/nss-feed-output-format-web-logs).                                                                                                       

##### Remarks                        
- Make sure to specify the feed escape character as *`=`*.
- As mentioned in the referenced documentation above, make sure to add the feed output format for Web logs and/or FW logs.

### Configure a Broker VM on Cortex XSIAM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select *TCP*.
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving streamed syslog events from Zscaler. This should be aligned with the port number defined on the Zscaler NSS feed.
   | `Format`      | Select *Auto-Detect*. 

</~XSIAM>