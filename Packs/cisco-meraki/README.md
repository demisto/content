# Cisco Meraki

<~XSIAM>
This pack includes Cortex XSIAM content.
  
## Configuration on Server Side
This section describes the configuration steps required on the Cisco Meraki dashboard to forward requested event logs to Cortex XSIAM Broker VM via syslog.
 
1. Log in to the Cisco Meraki dashboard. 
2. Navigate to the network which you want to configure syslog forwarding for.
3. Go to **Network-wide** &rarr; **Configure** &rarr; **General**.
4. Click the **Add a syslog server** link to define a new server entry for the Cortex XSIAM Broker VM syslog server, and fill in the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Server IP`   | The IP address of the target Cortex XSIAM Broker VM syslog server. 
   | `Port`        | The port number that the target Cortex XSIAM Broker VM syslog server is configured to listen on for receiving event logs from Cisco Meraki. 
   | `Roles`       | Select the requested event types that should be forwarded to Cortex XSIAM. 
5. Click **Save** to apply the changes.
 
For additional details, see [Cisco Meraki syslog server overview and configuration](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration#Configure_Dashboard).

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Right-click, and select **Syslog Collector** &rarr; **Configure**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select **UDP**.   
   | `Port`        | Should be aligned with the *port* defined in the Cisco Meraki Dashboard as described in the [Configuration on Server Side](#configuration-on-server-side) section above.   
   | `Format`      | Select **Auto-Detect**. 
   | `Vendor`      | Enter **Cisco**.
   | `Product`     | Enter **Meraki**.

</~XSIAM>	