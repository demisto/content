# Brocade Switch

<~XSIAM>

This pack includes XSIAM content.

## Configuration on Server Side

This section describes the configuration that needs to be done on Brocade Fabric OS switch appliances in order to forward their event logs to Cortex XSIAM Broker VM via syslog.

### Syslog Forwarding Configuration

Brocade Fabric OS switches support forwarding the audited events to a remote syslog server. The syslog forwarding configuration is done via the [***syslogAdmin***](https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-commands/9-2-x/Fabric-OS-Commands/syslogAdmin.html) command.

For adding the Cortex XSIAM Broker VM as a syslog server, run the following command on the switch appliance CLI (Command Line Interface), replacing *\<IP\>* and *\<Port\>* with the actual corresponding IP address (or hostname) and port of the target [XSIAM Syslog Broker VM](#broker-vm):  

*syslogadmin --set -ip ***\<IP\>*** -port ***\<Port\>****

For example, the following command sets syslog forwarding over UDP (the default) to the Cortex XSIAM Broker VM which has IP address *10.1.2.3* on the default *514* syslog port:

```bash
   switch:admin> syslogadmin --set -ip 10.1.2.3 -port 514
```

For validating the configuration, run the following command to display all the configured syslog servers:

```bash
   switch:admin> syslogadmin --show -ip
```

For additional details and configuration options, such as setting the syslog facility level or using TLS for forwarding the logs via a secure channel over TCP, see the following links:  

- [Configuring Remote Syslog Servers](https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-administration/9-2-x/Perform-Advance-Configuration-Tasks-Admin1/v26748051/v26747989.html).
- [SyslogAdmin Command Reference](https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-commands/9-2-x/Fabric-OS-Commands/syslogAdmin.html).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the apps tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Select **UDP** for the default forwarding, or **Secure TCP** if the syslog forwarding on the Brocade switch appliance was defined with the **-secure** option (see [SyslogAdmin](https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-commands/9-2-x/Fabric-OS-Commands/syslogAdmin.html) command reference).  
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Brocade Fabric OS switch appliances. (This should be aligned with the *-port* operand used on the switch appliance when running the [SyslogAdmin](https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-commands/9-2-x/Fabric-OS-Commands/syslogAdmin.html) command as described in the [Syslog Forwarding Configuration](#syslog-forwarding-configuration) section).
   | `Vendor`      | Enter **Brocade**.
   | `Product`     | Enter **Switch**.

</~XSIAM>
