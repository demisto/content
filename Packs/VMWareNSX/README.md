# VMware NSX
VMware NSX is a network virtualization platform that enables the creation and management of software-defined networks. It provides advanced security, automation, and micro-segmentation for modern data centers and cloud environments.

<~XSIAM>
This pack includes Cortex XSIAM content.

## What this pack contains?
- Modeling rules for VMWare NSX
- Syslog Integration
  
## Configuration on Server Side

This section describes the configuration required on the VMware NSX server to forward its event logs to Cortex XSIAM Broker VM via syslog.

1. From your browser, log in with admin privileges to an NSX Manager at ***`https://nsx-manager-ip-address`.***
2. Select, **System** -> **Fabric** -> **Profiles**.
3. Click the **Node Profiles** tab.
4. Click **All NSX Nodes** in the Name column.
5. In the **Syslog Servers** section, click **Add** to add a Syslog server.
    - Enter the **FQDN** or **IP address** of the Syslog server.
    - Specify a **port number**.
    - Select a **protocol**. - The available protocols are TCP, UDP, and LI (Log Insight).
    - Select a **log level**. The available levels are Emergency, Alert, Critical, Error, Warning, Notice, Information, and Debug.
    - Click **Add**.

6. Repeat step 5 to add more syslog servers, if required.

For additional details, see [Add Syslog Servers for NSX Nodes](https://techdocs.broadcom.com/us/en/vmware-cis/nsx/vmware-nsx/4-0/administration-guide/operations-and-management/log-messages-and-error-codes/add-syslog-servers-for-nsx-nodes.html)

**NOTE:**  This pack supports Syslog RFC 5424 format as shown in the following article [here](https://techdocs.broadcom.com/us/en/vmware-cis/nsx/vmware-nsx/4-0/administration-guide/operations-and-management/log-messages-and-error-codes/firewall-audit-log-messages.html).

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
   | `Protocol`    | Should be aligned with the selected *protocol* value in the NSX Server Management Interface syslog configuration, as described in the [Configuration on Server Side](#configuration-on-server-side) section above.
   | `Port`        | Should be aligned with the *port* defined in the NSX Server Management Interface syslog configuration as described in the [Configuration on Server Side](#configuration-on-server-side) section above.
   | `Format`      | Select **Auto-Detect**.
   | `Vendor`      | Enter **VMware**.
   | `Product`     | Enter **NSX**.

</~XSIAM> 