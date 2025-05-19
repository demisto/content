# HPE Switch

<~XSIAM>
This pack includes Cortex XSIAM content.

## Configuration on HPE Switches

This section describes the basic mandatory steps you should perform on an HPE switch device in order to forward its audited logs to Cortex XSIAM via Syslog.

### Configure Syslog forwarding

HPE's switches support forwarding the audited messages to a remote Syslog server. This is done via the ***[logging](https://www.arubanetworks.com/techdocs/AOS-CX/10.14/HTML/diagnostics_8100-83xx-9300-10000/Content/Chp_RSyslog/RSyslog_cmds/log-10.htm)*** command.

Follow these steps to configure forwarding of event logs from an HPE switch to a Cortex XSIAM Syslog Broker VM over UDP:

1. Connect to the switch CLI (Command Line Interface).
2. Type **enable** to move from the *Operator Level* mode to  *Manager Level* mode, followed by the *Manager Level* password if prompted.
3. Type **config** to enter the *Global Configuration* command mode.
4. Type **logging**  ***\<IP\>*** **udp** ***\<PORT\>*** where *\<IP\>* and *\<PORT\>* are the corresponding IP address and port of the target [Cortex XSIAM Syslog Broker VM](#broker-vm).
5. Type **write memory** to commit the updated configuration settings to the *startup configuration* file.
6. Type **exit** to exit the *Global Configuration* command mode and return back to the *Manager Level* command mode.
7. Type **exit** again to terminate the *Manager Level* mode session.

#### Example

Bellow is an example execution of the commands above for forwarding messages over UDP to a syslog server with IP *`192.168.1.10`* on the default UDP port *`514`* :

```bash
   HP Switch> enable
   Password:
   HP Switch# configure
   HP Switch(config)# logging 192.168.1.10 udp 514
   switch(config)# write memory
   switch(config)# exit
   switch# exit
```

#### Remark

For additional examples and command options, such as setting the logging severity level, filtering logging only for certain event ID's and forwarding syslog messages over TCP or TLS, see HPE's [Remote Syslog logging command reference](https://www.arubanetworks.com/techdocs/AOS-CX/10.14/HTML/diagnostics_8100-83xx-9300-10000/Content/Chp_RSyslog/RSyslog_cmds/rem-sys-com.htm).

## Configuration on Cortex XSIAM

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Select the transport protocol configured on the HPE switch devices to forward messages to this Broker VM: ***UDP***, ***TCP***, or ***Secure TCP*** (TLS).
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving streamed syslog events from HPE switch devices.
   | `Format`      | Select *Auto-Detect*.
   | `Vendor`      | Enter ***HPE***.
   | `Product`     | Enter ***Switch***.

5. Click **Done**.

</~XSIAM>
