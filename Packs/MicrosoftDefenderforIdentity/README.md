# Microsoft Defender for Identity
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Microsoft for Identity to forward Syslog messages in CEF format.

To configure, follow these instructions:
1. In [Microsoft 365 Defender](https://security.microsoft.com/), go to **Settings** > **Identities**.
2. Click **Syslog notifications**.
3. To enable syslog notification, set the **Syslog service** toggle to the **on** position.
4. Click **Configure service**. A pane will open where you can enter the details for the syslog service.
5. Enter the following details:
   * **Sensor** - From the drop-down list, choose the sensor that will send the alerts.
   * **Service endpoint and Port** - Enter the IP address or fully qualified domain name (FQDN) for the syslog server and specify the port number. You can configure only one Syslog endpoint.
   * **Transport** - Select the Transport protocol (TCP or UDP).
   * **Format** - Select the format (RFC 3164).
6. Click **Send test SIEM** notification and then verify the message is received in your Syslog infrastructure solution.
7. Click **Save**.
8. Once you've configured the **Syslog service**, you can choose which types of notifications (alerts or health issues) to send to your Syslog server.

* Additional documentation for syslog notifications is available [here](https://learn.microsoft.com/en-us/defender-for-identity/notifications#syslog-notifications).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - microsoft
   - product as product - azure_atp