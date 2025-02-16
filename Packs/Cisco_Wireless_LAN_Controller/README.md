# Cisco Wireless LAN Controller (WLC)
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 

## Message Logging Configuration
You need to configure Cisco WLC to forward Syslog messages.

* Product documentation for configuring message logging either from the GUI and CLI - [Link](https://www.cisco.com/c/en/us/td/docs/wireless/controller/8-5/config-guide/b_cg85/configuring_system_and_message_logging.html#sys-msg-logging).

Open your Cisco WLC GUI, and follow these instructions:
1. Go to Management &rarr; Logs &rarr; Config. The Syslog Configuration page appears.
2. In the **Syslog Server IP Address** field, enter the IPv4/IPv6 address of the server to which to send the syslog messages and click Add.
3. Optional, to set the severity level for filtering syslog messages to the syslog servers, choose one of the options under **Syslog Level**.
4. Optional, to set the facility for outgoing syslog messages to the syslog servers, choose one of the options under **Syslog Facility**.
5. Click **Apply**.
6. Optional, to set the severity level for logging messages to the controller buffer and console, choose one of the options from either the **Buffered Log Level** and **Console Log Level** dropdown lists.
7. Select the **File Info** checkbox if you want the message logs to include information about the source file. The default value is enabled.
8. Select the **Trace Info** checkbox if you want the message logs to include traceback information. The default is disabled.
9. Click **Apply**.
10. Click **Save Configuration**.


## Timestamp Ingestion

The following timestamp formats are currently supported for ingestion from Cisco WLC Syslog Messages in UTC time:
* MMM dd hh:mm:ss.nnn
* MMM dd hh:mm:ss.nnn TZ
* yyyy MMM dd hh:mm:ss.nnn
* yyyy MMM dd hh:mm:ss.nnn TZ
* MMM dd yyyy hh:mm:ss.nnn

In order to configure one of the above formats, follow these instructions:
1. Open your Cisco WLC CLI terminal, and type **enable** to enter Privileged EXEC mode.
2. Enter Global Configuration Mode by either typing **configure terminal** or **conf t**.
3. To configure the timezone in UTC format, type:
```bash
config time timezone enable 0 0
```
4. For adding a **year** and **milliseconds** to your syslog messages, type:
```bash
config service timestamps log datetime year msec
```
5. Revert back to Privileged EXEC mode by typing **end**. 
6. Save your changes by either typing 
```bash
write memory
OR
copy running-config startup-config 
```
And wait for system confirmation.


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
   | `Vendor`      | Enter **cisco**.
   | `Product`     | Enter **wlc**.
 
</~XSIAM>