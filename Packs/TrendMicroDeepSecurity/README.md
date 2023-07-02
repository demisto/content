# Trend Micro Deep Security

<~XSOAR>

## What does this pack do?
This pack enables you to:
- Configure policies and protect computers.
- Discover vulnerabilities and patch them.
- Perform routine maintenance tasks.

To use the Trend Deep Security APIs, you will need to create an API key in the Trend Deep Security console.

</~XSOAR>

<~XSIAM>

This pack includes Cortex XSIAM content. 

## Configuration on Server Side
Browse to the Trend Micro DSM (Deep Security Manager) Web Console, and perform the steps below. 

### Define a Syslog Configuration 
1. Navigate to _Policies_ &rarr; _Common Objects_ &rarr; _Syslog Configurations_.
2. Click _New_ &rarr; _New Configurations_.
3. Configure the following parameters on the _General_ tab:

   | Parameter                       | Description    
   | :---                            | :---                    
   | `Name`                          | Unique name that identifies the configuration.   
   | `Server Name`                   | Hostname or IP address of the XSIAM Broker VM Syslog Server.  
   | `Server Port`                   | The target syslog port of the XSIAM Broker VM Syslog Server.  
   | `Event Format`                  | Select **Common Event Format** (CEF).
   | `Transport`                     | Select the transport protocol.
   | `Include time zone in events`   | Whether to include the year and time zone in the event timestamp (Recommended).  
   | `Facility`                      | Type of process that events will be associated with. See [_Syslog Facilities and Levels_](https://success.trendmicro.com/dcx/s/solution/TP000086250?language=en_US).
   | `Agents should forward logs`    | Whether security events from the DSA (Deep Security Agents) should be sent to the target XSIAM VM Broker directly, or via the DSM. 

Please note: 
- Some logging functions are supported only for configurations which are defined to forward the DSA events indirectly via the DSM (and not directly to the syslog server).  
- Traffic should be enabled from the DSM (Deep Security Manager) tenant to the XSIAM Syslog Server for the requested port & protocol. If the (DSA) Deep Security Agents are configured to forward the events directly to the XSIAM server (and not via the DSM), then traffic should be enabled from the agent tenants as well. See [_Allow event forwarding network traffic_](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html#Network) for additional details. 

For full documentation, see [_Forward Deep Security events to a Syslog or SIEM server_](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html) on the Deep Security Help Center page.  

### Define Event Forwarding 
After defining a syslog configuration, you can define event forwarding for the system events and/or security events, using the syslog configuration defined in the previous section.  The system events are audit trail events and system alerts that are generated on the DSM, whereas the security events are alerts and notification events that are generated on the DSA from the various Deep Security protection modules. Define forwarding for the requested type of events: system events, security events, or both. 

#### Forward System Events
1. Navigate to _Administration_ &rarr; _System Settings_.
2. Click the _Event Forwarding_ tab. 
3. In the _SIEM_ section, in the _Forward System Events to a remote computer (via Syslog) using configuration_  option, select the relevant syslog configuration that was defined for forwarding the events to the XSIAM Broker VM. 
4. Click **Save**. 

For additional details, see [Forward system events](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html#Configur).

#### Forward Security Events
1. Navigate to _Policies_ and double-click the relevant policy which is applied to the monitored agents. 
2. Select _Settings_ on the left navigation pane, and open the _Event Forwarding_ tab. 
3. Under the _Event Forwarding Frequency (from the Agent/Appliance)_ section, select the requested forwarding frequency for the given policy under _Period between sending of events_. 
4. Under the _Event Forwarding Configuration (from the Agent/Appliance)_ section, for each protection module, select the relevant syslog configuartion for forwarding that module alerts to XSIAM. 
5. Click **Save**. 

For additional details ,see [Forward security events](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html#Configur2).


## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | The protocol that was defined in the syslog configuration on the Trend Micro Deep Security Manager Web Console.   
   | `Port`        | The port that was defined in the syslog configuration on the Trend Micro Deep Security Manager Web Console.   
   | `Format`      | Select **_CEF_**. 
   | `Vendor`      | Enter **_TrendMicro_**. 
   | `Product`     | Enter **_DeepSecurity_**. 

</~XSIAM>
