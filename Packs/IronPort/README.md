# Cisco ESA (Email Security Appliance)

# Integration:
The Cisco Email Security Appliance is an email security gateway product. It is designed to detect and block a wide variety of email-born threats, such as malware, spam and phishing attempts.

## What does this pack do?
- Retrieve spam quarantined messages.
- Release and delete messages from spam quarantine.
- Retrieve, add, append, edit or delete a list entry - blocklist and safelist of spam quarantine. 
- Retrieve tracking messages.
- Retrieve tracking messages enrichment summaries - AMP, DLP, URL.
- Reporting - get Cisco SMA's statistics reports.
- Fetch quarantine messages as incidents.

## Creating a Log Subscription in the Cisco ESA GUI

1. Choose System Administration > Log Subscriptions.
2. Click Add Log Subscription.
3. Select a log type and enter the log name (for the log directory) as well as the name for the log file itself.
4. Specify the maximum file size before AsyncOS rolls over the log file as well as a time interval between
rollovers.
5. Select the log level. The available options are Critical, Warning, Information, Debug, or Trace.
6. Configure the log retrieval method.
7. Submit and commit your changes.

[link to the website](https://www.cisco.com/c/en/us/td/docs/security/esa/esa11-1/user_guide/b_ESA_Admin_Guide_11_1/b_ESA_Admin_Guide_chapter_0100110.html#con_1134718)

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - esa
