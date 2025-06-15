# VMware NSX
VMware NSX is a platform for creating and managing virtual networks. It provides advanced security, automation, and precise network control (micro segmentation) for modern data centers and cloud systems.

<~XSIAM>
This pack includes Cortex XSIAM content.

## What this pack contains
- Modeling rules for VMWare NSX
- Syslog integration
  
## Server side configuration

This section explains how to configure your VMware NSX server to forward its event logs to the Cortex XSIAM Broker VM using syslog.

1. From your browser, log in with admin privileges to an NSX Manager at ***`https://nsx-manager-ip-address`.***
2. Select, **System** -> **Fabric** -> **Profiles**.
3. Click the **Node Profiles** tab.
4. In the **Name** column, click **All NSX Nodes**.
5. In the **Syslog Servers** section, click **Add** to add a syslog server.
    - Enter the **FQDN** or **IP address** of the syslog server.
    - Specify a **port number**.
    - Select a **protocol**. - The available protocols are TCP, UDP, and LI (Log Insight).
    - Select a **log level**. The available levels are Emergency, Alert, Critical, Error, Warning, Notice, Information, and Debug.
    - Click **Add**.

6. Repeat step 5 to add more syslog servers, if required.

For more information, see [Add Syslog Servers for NSX Nodes](https://techdocs.broadcom.com/us/en/vmware-cis/nsx/vmware-nsx/4-0/administration-guide/operations-and-management/log-messages-and-error-codes/add-syslog-servers-for-nsx-nodes.html)

**NOTE:**  This pack supports Syslog RFC 5424 format as shown in the following article [here](https://techdocs.broadcom.com/us/en/vmware-cis/nsx/vmware-nsx/4-0/administration-guide/operations-and-management/log-messages-and-error-codes/firewall-audit-log-messages.html).

## Collect events from the vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

Configure the Broker VM as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Right-click, and select **Syslog Collector** &rarr; **Configure**.
3. When configuring the syslog collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Should be aligned with the port defined in the NSX Server Management Interface syslog configuration, as described in the [Server side configuration](#server-side-configuration) section above.
   | `Port`        | Should be aligned with the port defined in the NSX Server Management Interface syslog configuration, as described in the [Server side configuration](#server-side-configuration) section above.
   | `Format`      | Select **Auto-Detect**.
   | `Vendor`      | Enter **VMware**.
   | `Product`     | Enter **NSX**.

</~XSIAM> 