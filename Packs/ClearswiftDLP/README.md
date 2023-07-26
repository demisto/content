# Clearswift DLP 
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Clearswift DLP to forward Syslog messages.

Open your Clearswift instance UI and follow these instructions:
1. From the Home page, click **System** > **Monitoring & Control** > **Logs & Alarms**.
2. Click the **Log Export** tab and select **Enable log export**.
3. Enter the IP Address (OR Hostname) and Port number of your Syslog server. The default port is 514.
4. Enter a Poll Interval (minutes). The recommended setting is once every 5 minutes. You can enter a value between 1 and 60 minutes.
5. Make a selection of the log types you want to export using the checkboxes adjacent to the list.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - clearswift
   - product as product - dlp