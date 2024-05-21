# Fortinet FortiManager
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 
## Configuration on Server Side

To configure Fortinet FortiManager to forward logs to Cortex XSIAM Broker VM via syslog follow the steps below.
1. Go to **System Settings** &rarr; **Advanced** &rarr; **Syslog Server**.
2. On the top pane, select the **Syslog Server** tab. A new Syslog server window will be open.
3. Choose a name for the new Syslog server.
4. Insert the IP address (or FQDN - Fully Qualified Domain Name) of the target listener.
5. Insert port number of the target listener. (Default port is 514).
For more information see [FortiManager documentation](https://docs2.fortinet.com/document/fortimanager/6.0.3/administration-guide/235746/syslog-server).
 
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
   | `Vendor`      | Enter **Fortinet**.
   | `Product`     | Enter **FortiManager**.
   | `Port`        | Enter port number for Cortex XSIAM Broker VM to listen to (default is 514)
   | `Protocol`    | Default is UDP
 

### XQL Queries
The following query returns all mapped XDM Fields
```
| datamodel dataset = fortinet_fortimanager_raw 
| fields fortinet_fortimanager_raw._raw_log,
    xdm.event.id,
    xdm.event.original_event_type,
    xdm.alert.severity,
    xdm.event.type,
    xdm.event.description,
    xdm.source.user.username,
    xdm.source.host.hostname,
    xdm.source.user.groups,
    xdm.event.operation_sub_type,
    xdm.session_context_id,
    xdm.auth.privilege_level,
    xdm.target.resource.type,
    xdm.source.ipv4,
    xdm.source.ipv6,
    xdm.event.log_level 
```

For further documentation please visit FortiManager documentation: 
* FortiManager [log types and subtypes](https://docs.fortinet.com/document/fortimanager/7.2.0/log-message-reference/238528/fortimanager-log-types-and-subtypes).

</~XSIAM>
