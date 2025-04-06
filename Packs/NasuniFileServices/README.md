## Nasuni File Services

This pack supports Syslog-based log ingestion from Nasuni File Services and includes parsing and modeling rules (XDM mapping) for Cortex XSIAM.

## Supported Event types

Volume audit logs.

## Configuration on Nasuni File Services Side

1. Log in to the Nasuni Management Console (NMC) with admin rights.
2.  Go to: `Volumes`.
3. For each relevant volume:
   - Ensure `File System Auditing` is enabled.
   - Set `Output Type` to **Syslog**.
4. Go to: `Filers > Syslog Export Settings`.
5. Select the Edge Appliance(s) and click `Edit Filers`.
6. In the `Servers` text box enter the IP or Hostname of your Broker VM in the following format - IP:port (example - 192.168.1.100:10514).
   If no port is specified it will default to UDP 514 (the system support log forwarding via UDP only).
7. Set the following settings:
   - `Send Auditing Messages`: **On**.
   - `Facility`: **local1** (recommended).
   - `Log Level`: **Info** or higher.
8. Click `Save Settings`.

## Log format

Nasuni audit logs are sent in **RFC 5424** syslog format with a JSON payload.

## Collect Events from Proofpoint Protection Server

In order to use the collector, use the [Broker VM](#broker-vm) option.

## Broker VM side

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values **(not relevant for CEF and LEEF formats)**:
    -----------------------------------------------------------------------------------------------------------------------------------------------------------
    | Parameter: :            | Value :                                                                                                                       |
    |-------------------------|-------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`              | Select **UDP**                                                                                                                |
    | `Port`                  | Enter the port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from NMC                           |
    | `Vendor`                | Enter `nasuni`                                                                                                                |
    | `Product`               | Enter `file_services`                                                                                                         |