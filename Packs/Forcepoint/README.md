# Forcepoint NGFW
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Forcepoint NGFW to forward Syslog messages in CEF format.

Open Forcepoint NGFW interface, and follow these instructions;
1. Select **Home**.
2. Browse to **Others** > **Log Server**
3. Right-click the Log Server from which you want to forward log data, and select **Properties**.
4. Click the **Log Forwarding** tab.
5. To create a rule, click **Add**.
6. In the select **Target Host** cell, select the external host to which the log data is forwarded.
    6.1. Double-click the **Target Host** cell.
    6.2. Select a Host element.
    6.3. Click **Select**
7. To add a rule, click **Add**.
8. Configure the log forwarding rules.
9. Click **OK**.

* Additional documentation for log forwarding is available [here](https://help.stonesoft.com/onlinehelp/StoneGate/SMC/6.5.0/) at: **SMC configuration** > **Configuring the Log Server** > **Forwarding log data from Log Servers to external hosts** > **Add log forwarding rules to Log Servers**.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - forcepoint
   - product as product - firewall