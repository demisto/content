# Fortimail
This pack includes Cortex XSIAM content. 

<~XSOAR>
Cortex XSOAR interfaces with Fortimail to increase email security.

# What does this pack do?

- Views, creates, updates, and deletes a Fortimail IP policy, Access control, and Recipient policy directly from Cortex XSOAR.
- Views, creates, updates, and deletes a Fortimail IP and Email groups directly from Cortex XSOAR.
- Views, creates, updates, and deletes a Fortimail IP and Email group members directly from Cortex XSOAR.
- Views all Fortimail profiles.
</~XSOAR>

<~XSIAM>
## Configuration on Server Side
You need to configure Fortimail to forward Syslog messages.
 
Open the Fortimail interface, and follow these instructions [Documentation](https://docs.fortinet.com/document/fortimail/7.4.2/administration-guide/332364/configuring-logging):
1. Go to **Log & Report** &rarr; **Log Setting** &rarr; **Remote**
2. Configure the following settings:
   | Setting            | Description   
   | :---               | :---        
   | `Status`           | Select to enable logging to this location.
   | `Name`             | Enter a unique name for this configuration.
   | `Server name/IP`   | Enter the IPv4, IPv6, or domain name (FQDN) address of the Syslog server or FortiAnalyzer that will store the logs.
   | `Server port`      | If the remote host is a FortiAnalyzer unit, type 514. If the remote host is a Syslog server, type the port number on which the Syslog server listens.
   | `Protocol`         | Select **Syslog**.
   | `Mode`             | Select **TCP**.
   | `Level`            | Select the severity level that a log message must equal or exceed in order to be recorded to this storage location.
   | `Facility`         | Select the facility identifier that the FortiMail unit will use to identify itself when sending log messages.
   | `CSV format`       | Enable if you want to send log messages in comma-separated value (CSV) format.
3. Click **Create**

* To verify logging connectivity, from the FortiMail unit, trigger a log message that matches the types and severity levels that you have chosen to store on the remote host. Then, on the remote host, confirm that it has received that log message.

**Pay Attention**:
Timestamp ingestion is only available in UTC timezone (00:00) for the **Date** (%Y-%m-%d) and **Time** (%k:%M:%S) fields.
In order to change Fortimail's system time zone use the commands-
```text
    config system time manual
    set daylight-saving-time {disable | enable}
    set zone <zone_int>
    end
``` 
For additional information, review Fortimail's System Time Manual [documentation](https://docs.fortinet.com/document/fortimail/7.4.1/cli-reference/302323/system-time-manual).

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
   | `Vendor`      | Enter **fortinet**.
   | `Product`     | Enter **fortimail**.
</~XSIAM>