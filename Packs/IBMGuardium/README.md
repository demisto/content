# IBM Guardium
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 
## Configuration on Server Side

To configure IBM Guardium to forward logs to Cortex XSIAM Broker VM via syslog follow the steps below.

### Creating a syslog destination for events

1. Log in to the CLI and define the IP address for Cortex XSIAM Broker VM.
2. Use SSH to log in to IBM as default user.  
Username: \<user name\>  
Password: \<password\> 
3. Type the following command to configure the syslog destination for: 

|  Event Type   | Command   
| :---          | :---        
| `informational events` | store remote add daemon.info \<IP address\>:\<port\> \<tcp\|udp\>
| `warning events` | store remote add daemon.warning \<IP address\>:\<port\> \<tcp\|udp\>
| `error events` | store remote add daemon.err \<IP address\>:\<port\> \<tcp\|udp\>
| `alert events` | store remote add daemon.alert \<IP address\>:\<port\> \<tcp\|udp\>
   

> **IP address** - IP address of the event collector  

> **port** - syslog port used to communicate to the event collector (default port in Guardium is 514 UDP)   

> **tcp\ udp** - protocol used to communicate with the event collector   


*For example:*  

``` bash
    store remote log add daemon.all <IP> udp

    store remote log add daemon.all example.com:1514 tcp
```  



[IBM Guardium - creating a syslog destination for events](https://www.ibm.com/docs/en/qsip/7.4?topic=guardium-creating-syslog-destination-events)

### Configure policies to generate syslog events

Policies in IBM Guardium are responsible for reacting to events and forwarding the event information to Cortex XSIAM Broker VM.

1. Click the **Tools tab**.
2. From the left navigation, select **Policy Builder**.
3. From the Policy Finder pane, select an existing policy and click **Edit Rules**.
4. Click **Edit this Rule individually**.
   The Access Rule Definition is displayed.
5. Click **Add Action**.
6. From the **Action** list, select one of the following alert types:
   **Alert Per Match** - A notification is provided for every policy violation.
   **Alert Daily** - A notification is provided the first time a policy violation occurs that day.
   **Alert Once Per Session** - A notification is provided per policy violation for unique session.
   **Alert Per Time Granularity** - A notification is provided per your selected time frame.
7. From the **Message Template** list, edit the message template or choose the default template (follow IBM Support link below for default template and CEF template).
8. From **Notification Type**, select **SYSLOG**.
9. Click **Add**, then click **Apply**.
10. Click **Save**.
11. Repeat this process for all rules within the policy that you want to forward to Cortex XSIAM Broker VM.


### Installing an IBM Guardium policy

1. Click the **Administration Console** tab.
2. From the left navigation, select **Configuration** &rarr; **Policy Installation**.
3. From the Policy Installer pane, select a policy that you created in the previous step.
4. From the drop-down list, select **Install and Override**.
   A confirmation is displayed to install the policy to all Inspection Engines.
5. Click **OK**.


[IBM Support - Shipping Guardium Syslog to Remote Server](https://www.ibm.com/support/pages/shipping-guardium-syslog-remote-server)

 
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
   | `Protocol`    | TCP or UDP according to the protocol defined in the IBM Guardium CLI.
   | `Port`        | Enter the port number defined in the IBM Guardium CLI or 514 if no specific port was defined.
   | `Vendor`      | Enter **IBM**.
   | `Product`     | Enter **Guardium**.


> [!NOTE]
This content refers to IBM Guardium version 10.0

</~XSIAM>