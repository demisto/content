# Arista Switch
<~XSIAM>
This pack includes Cortex XSIAM content. 

## Configuration on Server Side
This section describes the basic mandatory steps you should perform on Arista's switch in order to forward the audited event logs to XSIAM via Syslog. 
In addition, you may wish to customize the [logging level](https://arista.my.site.com/AristaCommunity/s/article/understanding-logging-levels) and [logging format](https://www.arista.com/en/um-eos/eos-switch-administration-commands#xx1268462) of the audited events as described below. 

### Configure Syslog forwarding
Arista's switch supports forwarding the audited events to a remote Syslog server. This is done via the ***logging host*** command. 

Follow these steps to configure forwarding of event logs from an Arista switch to an XSIAM Syslog Broker VM via UDP:
1. Connect to the switch CLI (Command Line Interface). 
2. Type **enable** (or **en**) to enter the _Privileged EXEC_ command mode, followed by the password if prompted. 
3. Type **configure** (or **config**) to enter the _Global Configuration_ command mode. 
4. Type **logging host** **_\<IP\>_** **_\<Port\>_** where _\<IP\>_ and _\<Port\>_ are the corresponding IP address and port of the [XSIAM Syslog Broker VM](#broker-vm). 
5. Type **write** (or **running-config startup-config**) to commit the updated configuration settings to the _start-up configuration_ file. 
6. Type **exit** to exit the _Global Configuration_ command mode and return back to the _Privileged EXEC_ command mode. 
7. Type **exit** again to terminate the session. 

Bellow is an example execution of the commands above: 
```bash
   switch> enable
   Password:
   switch# configure
   switch(config)# logging host 192.168.0.10 514
   switch(config)# write
   switch(config)# exit
   switch# exit
```

Remarks: 
- By default, the _**logging host**_ command described above configures the Syslog forwarding over UDP. If you wish to forward the event logs via a secure channel over TCP, refer to the documentation in the following links:
  - [Syslog with TLS Support](https://www.arista.com/en/um-eos/eos-control-plane-security#xx1117976). 
  - [Logging - Basic Syslog and Beyond](https://arista.my.site.com/AristaCommunity/s/article/logging-basic-syslog-and-beyond) (see the _Secure Syslog Transmission_ section).
- You may wish to customize the logging level to filter events from a certain level and/or facility. See [_Understanding Logging Levels_](https://arista.my.site.com/AristaCommunity/s/article/understanding-logging-levels) for additional details.
- By default, the timestamps in the generated event logs are specified in the traditional [RFC3164](https://www.ietf.org/rfc/rfc3164.txt) syslog format, which does not include a year and a timezone. It is recommended you override this default setting and configure the switch to forward the Syslog messages in [RFC5424](https://datatracker.ietf.org/doc/html/rfc5424) format, which specifies a high-resolution [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) timestamp which does include a year and a timezone. This configuration could be done from the _Global Configuration_ command mode via the _**logging format**_ command. See [Syslog Logging Format](https://www.arista.com/en/um-eos/eos-switch-administration-commands#xx1268462) for additional details. 
- The configuration described above was brief and basic. For the full documentation, be sure to see the latest Arista Configuration Guide for your switch version. In addition, you may find the following links useful: 
  - [EOS Logging Explained](https://arista.my.site.com/AristaCommunity/s/article/eos-logging-explained).
  - [Understanding Logging Levels](https://arista.my.site.com/AristaCommunity/s/article/understanding-logging-levels).
  - [Logging - Basic Syslog and Beyond](https://arista.my.site.com/AristaCommunity/s/article/logging-basic-syslog-and-beyond).
  - [System and Process Logging](https://arista.my.site.com/AristaCommunity/s/article/system-and-process-logging).
  - [Reacting to syslog-triggered events](https://arista.my.site.com/AristaCommunity/s/article/syslog-triggered-event-scripts).
  - [Syslog message generation on MAC table changes](https://arista.my.site.com/AristaCommunity/s/article/syslog-message-generation-on-mac-table-changes).
  - [Using AAA to log all commands from users on Arista EOS](https://arista.my.site.com/AristaCommunity/s/article/using-aaa-to-log-all-commands-from-users-on-arista-eos).

 ## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | The protocol that was defined in the [Syslog configuration on the Arista switch](#configure-syslog-forwarding) (**UDP** for the default or **Secure TCP** for the [Syslog with TLS Support](https://www.arista.com/en/um-eos/eos-control-plane-security#xx1117976) configuration.   
   | `Port`        | The Syslog service port that was defined in the [Syslog configuration on the Arista switch](#configure-syslog-forwarding).   
   | `Vendor`      | Enter **_Arista_**. 
   | `Product`     | Enter **_Switch_**. 
</~XSIAM>