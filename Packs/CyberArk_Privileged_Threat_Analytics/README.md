# CyberArk Privileged Threat Analytics

<~XSIAM>

This pack includes Cortex XSIAM content.

This pack contains a beta Modeling Rule, which lets you process CyberArk PTA log fields to XDM fields.
Since the Modeling Rule is considered as beta, it might not contain some of the fields that are available from the logs.
We appreciate your feedback on the quality and usability of the Modeling Rule to help us identify issues, fix them, and continually improve.

## Configuration on Server Side

You need to configure CyberArk Privileged Threat Analytics (PTA) to forward Syslog messages in CEF format.

Access your Cyberark PTA machine and follow these instructions [Product Documentation](https://docs.cyberark.com/PAS/Latest/en/Content/PTA/Outbound-Sending-%20PTA-syslog-Records-to-SIEM.htm):

1. On the PTA machine, open the default **systemparm.properties** file using the ***DEFAULTPARM*** command.
2. Copy the line containing the **syslog_outbound** property, and exit the file.
3. Open the local **systemparm.properties** file using the ***LOCALPARM*** command.
4. Press **i** to edit the file.
5. Paste the line you copied, uncomment the **syslog_outbound** property and edit the parameters. Use the following as a guide.
   * format - CEF.
   * protocol - UDP.
   * siem - Assign a name to your configuration.
   * host - Write the dedicated hostname or IP address.
   * port - Write the dedicated port number.
   * syslogType - RFC5424.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:

   | Parameter     | Value
   | :---          | :---
   | `Vendor`      | Enter **cyberark**.
   | `Product`     | Enter **pta**.

</~XSIAM>
