# Squid
This pack includes Cortex XSIAM content. 

Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator. It runs on most available operating systems, including Windows and is licensed under the GNU GPL.


## Configuration on Server Side
You need to configure Squid to forward Syslog messages to XSIAM.

In order to send logs via syslog please follow the below steps:
1. Open the squid.conf file and locate the command: ***access_log \<location of file\> squid***
2. Add the command ***access_log udp://\<Firewall Analyzer IP Address\>:514/1514 squid*** after the command you located in the previous step.
3. Restart the Squid service.

For more information, see the following: 
http://www.squid-cache.org/Doc/config/access_log/

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Set-up-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - squid
   - product as product - squid
