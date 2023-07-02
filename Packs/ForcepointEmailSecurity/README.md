# Forcepoint Email Security
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Forcepoint Email Security to forward Syslog messages in CEF format.

From the Forcepoint Security Manager, follow these instructions;
1. Navigate to the page **Settings** > **General** > **SIEM Integration**.
2. Select the checkbox **Enable SIEM integration for all email appliances**.
3. Configure the following SIEM settings;
   a. At **IP address or hostname**, enter the relevant IP address or hostname.
   b. At **Port**, enter the relevant Port number.
   c. From the **Transport protocol** section, enter the relevant protocol (**UDP**).
   d. From the **SIEM format** dropdown menu, enter the relevant format (**syslog/CEF**).
   e. Confirm configuration by clicking **Send Test Message**.
4. Click **OK** once you are done.

* Additional documentation Forcepoint Email Security Logs for SIEM is available [here](https://www.websense.com/content/support/library/email/v85/email_siem/siem_log_map.pdf)

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - forcepoint
   - product as product - email_security