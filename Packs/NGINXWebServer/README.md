# NGINX
This pack includes Cortex XSIAM content.

## Configuration on Server Side
You need to configure your Nginx device to forward Syslog messages.

Perform the following in order to configure log forwarding:
1. Log in to the Nginx device CLI console.
2. Make sure that the Nginx device is configured to generate error and access logs. The default path to the logs is logs/ (the absolute path depends on the operating system and installation).
3. Add the below 2 lines to Nginx configuration file:  
```bash
error_log  syslog:server=<syslog server hostname/IP>:<port>,facility=local7,tag=nginx,severity=error;
access_log syslog:server=<syslog server hostname/IP>:<port>,facility=local7,tag=nginx,severity=info;
```
4. In order for the config changes to take effect you need to restart the nginx service.

**Pay Attention**: 
For timestamp ingestion, the default time zone for error logs is set to UTC (+0000), you can change the time zone according to your preference.
The supported timestamp formats from syslog messages: 
- dd/MMM/yyyy:hh:mm:ss [+|-]nnnn (18/Jul/2021:10:00:00 +0000)
- yyyy/MM/dd hh:mm:ss (2020/01/19 10:00:00)

More information can be found [here](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/)

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - nginx
   - product as product - nginx
