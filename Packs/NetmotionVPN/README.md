## Netmotion VPN

This pack supports Syslog-based log ingestion from Netmotion VPN and includes parsing and modeling rules (XDM mapping) for Cortex XSIAM.

## Supported Event types

- RPC Rule
- Security Binding Rule
- Security Authenticating Rule
- IMP Rule

## Configure the Netmotion VPN Side

1. Log in to the **NetMotion Mobility console** as an administrator.
2. Navigate to **Configure > Server Settings**.
3. In the left pane, select one of the following options:

- For all servers, select Global Server Settings.
- For a specific server, select the specific server name.

4. Enable Syslog forwarding.
   a. Select Syslog – On / Off and check Turn syslog event logging on.
   b. Set Syslog – Server Host to your Broker VM’s IP/hostname.
   c. (Optional) Modify Syslog – Server Port (default is UDP 514).
5. Save the settings.

## Collect Events from Netmotion VPM

In order to use the collector, use the [Broker VM](#broker-vm) option.

## Configure the Broker VM side

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.

4. When configuring the Syslog Collector, set the following values **(not relevant for CEF and LEEF formats)**
    -----------------------------------------------------------------------------------------------------------------------------------------------------------

    | Parameter: :            | Value :                                                                                                                       |
    |-------------------------|-------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`              | Select **UDP** or **TCP**.                                                                                                    |
    | `Port`                  | Enter the port that Cortex XSIAM Broker VM should listen on for receiving forwarded events.                                   |
    | `Vendor`                | Enter `netmotion`.                                                                                                            |
    | `Product`               | Enter `vpn`.                                                                                                                  |
