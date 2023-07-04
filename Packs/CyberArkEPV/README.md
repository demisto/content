
# CyberArk Enterprise Password Vault (EPV)
This pack includes Cortex XSIAM content.


## Configuration on Server Side
Syslog messages can be sent to multiple syslog servers in two different ways.
- One message can be sent to multiple servers by configuring an XSLT file.
- Multiple messages can be sent to different servers and formatted differently for each server by configuring multiple XSLT files, formats, and code-message lists. The code-message lists must be matched. They must contain the same number of items in the same order.

Note: The .ini file contains these configuration values.
1. In \PrivateArk\Server\DBParm.sample.ini, copy the SYSLOG section.
- SyslogServerIP—The IP addresses of the Syslog servers where messages are sent. Specify multiple values with commas.
- SyslogServerProtocol—Specifies the Syslog protocol that is used to send audit logs. Specify TCP or UDP.
The default value is UDP.
- SyslogServerPort—The port used to connect to the Syslog server. The default value is 514.
- SyslogMessageCodeFilter—Defines which message codes are sent from the Vault to Trellix ESM through the Syslog protocol. You can specify message numbers or ranges of numbers, separated by commas. Specify multiple values with pipelines. By default, all message codes are sent for user and safe activities.
- SyslogTranslatorFile—Specifies the XSL file used to parse CyberArk audit records data into Syslog protocol. Specify multiple values with commas.
- DebugLevel—Determines the level of debug messages. Specify SYSLOG(2) to include Syslog xml messages in the trace file.
• UseLegacySyslogFormat—Controls the format of the syslog message, and defines whether it is sent in a newer syslog format (RFC 5424) or in a legacy format. The default value is No, which enables working with the newer syslog format. Specify multiple values with commas.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
 