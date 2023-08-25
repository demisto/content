# Apache Web Server
This pack includes Cortex XSIAM content. 

<~XSIAM>
## Configuration on Server Side
You need to configure Apache Web Server to forward Syslog messages.

Open your Apache Web Server instance, and follow these instructions [Documentation](https://docs.trellix.com/bundle/xdr_dscg/page/UUID-4540547f-28c4-0553-846e-544fbc02530f.html):
1. Log in to your Apache Web Server instance as a **root** user.
2. Edit the Apache configuration file **httpd.conf**.
   * Ensure to keep a backup copy of the file.
   * Edit one configuration file at a time. Save the file after each change and monitor its effect.
   * For further information on Apache Log Files - [Documentation](https://httpd.apache.org/docs/2.4/logs.html#page-header) 
3. Add the following information in the Apache configuration file to specify a custom path for the syslog events:
```bash 
   CustomLog "|/usr/bin/logger -t httpd -p <facility>.<priority>" combined 
```
   Where:
   * **facility** is a syslog facility, for example- local0.
   * **priority** is a syslog priority, for example- info OR notice.
4. Disable hostname lookup:
```bash 
   HostnameLookups off
``` 
5. Save the configuration file.
6. Edit the syslog configuration file:
```bash 
   /etc/syslog.conf
```    
7. Add the following information to your syslog configuration file:
```bash 
   <facility>.<priority> <TAB><TAB>@<host>:<port>
```
   Where:
   * **facility** - This value must match the value that you typed in the step 3.
   * **priority** - This value must match the value that you typed in step 3.
   * **TAB** - Indicates you must press the Tab key.
   * **host** - The syslog destination IP address.
   * **port** - The syslog destination Port.
8. Save the syslog configuration file.
9. Restart the syslog service:
```bash 
   /etc/init.d/syslog restart
```
10. Restart Apache to complete the syslog configuration.

* Pay attention: Timestamp Parsing is only available for the default **%t** format: \[%d/%b/%Y{Key}%H:%M:%S %z\]

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - apache
   - product as product - httpd

</~XSIAM>
