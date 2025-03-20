
## Proofpoint Protection Server (PPS)

This pack provides a Cortex XSOAR integration for Proofpoint Protection Server.
Additionally, it supports Syslog-based log ingestion from Proofpoint Protection Server and includes parsing and modeling rules (XDM mapping) for Cortex XSIAM.

## Configuration on Proofpoint Server Side
1. Log in to the Proofpoint Protection Server interface.
2. Click `Logs and Reports`.
3. Click `Log Settings`.
4. Go to the **Remote Log Options** panel.
5. From `Syslog Protocol` Select **TCP** or **UDP**. 
5. In `Syslog Host`, type the IP address or Hostname of your Broker VM.
6. In `Syslog Port`, type 514 or any other preferred port.
7. Enable the `Syslog Filter Enable` by clicking **On**.
8. In the `Facility` list select the **local1** value.
9. In the `Level` list select the **Information** value.
10. Enable `Syslog MTA Enable` by clicking **On**.
11. In the `Facility` list select the **mail** value.
12. In the `Level` list select the **Information** value.
13. Click the `Save Changes`.

To review the Proofpoint Protection Server Syslog forwarding docs, click [here](https://proofpoint.my.site.com/community/s/login/?ec=302&startURL=%2Fcommunity%2Fs%2Farticle%2FRemote-Syslog-Forwarding).

## Collect Events from Proofpoint Protection Server
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values **(not relevant for CEF and LEEF formats)**:
    -----------------------------------------------------------------------------------------------------------------------------------------------------------
    | Parameter: :            | Value :                                                                                                                       |
    |-------------------------|-------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`              | Set the **Syslog Protocol** defined on Proofpoint PS side (**TCP** or **UDP**)                                                |
    | `Port`                  | Enter the **Syslog Port** that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Proofpoint PS      |
    | `Vendor`                | Enter `proofpoint`                                                                                                            |
    | `Product`               | Enter `ps`                                                                                                                    |