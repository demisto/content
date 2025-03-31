# Avaya Aura Communication Manager

<~XSIAM>
This pack includes Cortex XSIAM content.

## Configuration on Server Side

This section describes the configuration that needs to be done on Avaya Aura Communication Manager in order to forward its event logs to Cortex XSIAM Broker VM via syslog.

Follow the steps below:

1. Log in to Communication Manager System Management Interface.
2. On the **Administration** menu, click **Server (Maintenance)**.
3. In the left navigation pane, under **Security**, click **Server Log Files** and do the following:
   1. In `Enabled` select **Yes**.
   2. In `Protocol` click the transport protocol that would be used to transfer the syslog messages: **UDP**, **TCP** or **TLS**.
   3. In `Port` enter the syslog service port that the target Cortex XSIAM Broker VM is listening on for receiving forwarded events from Avaya Aura Communication Manager.
   4. In `Server IP/FQDN` type the IP address of the target [Cortex XSIAM Syslog Broker VM](#broker-vm).
4. Click **Submit**.  

See Avaya Aura [Configuring syslog server](https://documentation.avaya.com/bundle/AdministeringAvayaAuraCM_R8.1/page/Configuring_systelog_server.html) guide for additional details.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Select the protocol in correspondence to the protocol that was defined for syslog forwarding on Avaya Aura Communication Manager - **UDP**, **TCP** or **Secure TCP** if the syslog forwarding on the Communication Manager was defined with *TLS*.  
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Avaya Aura Communication Manager.
   | `Vendor`      | Enter **Avaya**.
   | `Product`     | Enter **Communicaton_Manager**.

</~XSIAM>
