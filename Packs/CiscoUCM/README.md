
## Cicso UCM

Cisco Unified Communications Manager (UCM) is a unified voice and video call control platform, offering enterprise-grade IP telephony, session management, and voice/video call processing services.
This pack includes Cortex XSIAM content.

## What this pack contains

Syslog parsing rules for Cisco UCM
XDM modeling rules for authentication, device, CTI, and RTMT alerts

## Server side configuration

1. Log in to the Cisco Unified CM Administration interface.
2. Navigate to System Enterprise > Parameters.
3. Click `Remote Syslog Server Name` field, type the IP address your Broker VM and port.
4. Click the `Syslog Severity For Remote Syslog messages` list and select **Informational**.
5. Click **Save**.
6. Click **Apply Config**.

## Collect Events from Cisco UCM

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.

4. When configuring the Syslog Collector, set the following values **(not relevant for CEF and LEEF formats)**
    -----------------------------------------------------------------------------------------------------------------------------------------------------------

    | Parameter: :            | Value :                                                                                                                       |
    |-------------------------|-------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`              | Set the **Syslog Protocol** defined on Cisco UCM side (**TCP** or **UDP**)                                                    |
    | `Port`                  | Enter the **Syslog Port** that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Cisco UCM          |
    | `Vendor`                | Enter `cisco`                                                                                                                 |
    | `Product`               | Enter `ucm`                                                                                                                   |
