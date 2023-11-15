# Claroty Continuous Threat Detection (CTD)
<~XSOAR>

Effective network security starts with an accurate asset database. The integration between Claroty Continuous Threat Detection (CTD) and Palo Alto Networks Cortex XSOAR enables comprehensive IT-OT asset coverage through discovery & enrichment, vulnerability management, and automated threat alerts. Integrating these tools provides coverage through a single-pane-of-glass while eliminating the need for OT-specific monitoring expertise & dedicated tools.

Supporting the broadest list of OT protocols in the industry and multiple asset discovery methodologies, Claroty’s integration with Cortex XSOAR allows organizations to:
- Identify all OT assets and corresponding asset data to populate the CMDB
- Automate vulnerability management with context-rich playbooks for event resolution
- Threat detection engines identify and parse events to alert Cortex XSOAR for further ticketing and analysis

For more information:
- [Request a demo](https://security.claroty.com/request-a-demo/paloaltonetworks)
- [Read the joint solution brief](https://claroty.com/resources/integration-briefs/claroty-and-cortex-xsoar-integration-brief)
- [Visit Claroty.com](https://claroty.com/)

</~XSOAR>


<~XSIAM>

## Cortex XSIAM SIEM Content

This pack includes Cortex XSIAM SIEM content, which is supported directly by *Palo Alto Networks*. 

The SIEM content contains parsing and modeling rules for ingesting and mapping events and alerts that are sent from Claroty CTD to Cortex XSIAM. 

This section describes the configurations required on Claroty CTD for forwarding events and alerts to Cortex XSIAM and the configurations required on Cortex XSIAM for ingesting and mapping them. 
 
### Configuration on Claroty CTD
Follow these steps to configure Claroty CTD to forward Syslog messages to Cortex XSIAM.
 
1. Login to your account on the Claroty CTD web management console. 
2. Go to **Configuration** and navigate to **Log Settings** &rarr; **Syslog**.
3. Click **+ Add** to add a new syslog configuration. 
4. Clear the **Local** checkbox and fill in the following settings: 
   | Parameter          | Value   
   | :---               | :---        
   | `Message Contents` | Select the log type to forward to Cortex XSIAM.
   | `Message Format`   | Select **CEF**.
   | `Server`           | Enter the IP address of the target Cortex XSIAM Broker VM syslog server.
   | `Port`             | Enter the port number which the target Cortex XSIAM Broker VM syslog server would be listening on for receiving syslog messages from Claroty CTD.
   | `Protocol`         | Select the requested forwarding transport protocol (*UDP*, *TCP* or *TLS*). 
5. Click **Save**.
   
#### Remark
Since the syslog forwarding configuration is set for each log type individually, 
repeat the steps above for each log type (*Alerts*, *Events*, etc.) to monitor on Cortex XSIAM.


### Configuration on Cortex XSIAM
In order to use the collector for Claroty CTD, use the [Broker VM](#broker-vm) option.
 
#### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select the forwarding transport protocol in correspondence to the protocol defined on Claroty CTD (**UDP**, **TCP** or **Secure TCP** for **TLS**). 
   | `Format`        | Select **CEF**.
   | `Port`        | Enter the syslog service port number that this Cortex XSIAM Broker VM should listen on for receiving forwarded events from Claroty CTD.  
   | `Vendor`      | Enter **Claroty**. 
   | `Product`     | Enter **CTD**. 

</~XSIAM>
