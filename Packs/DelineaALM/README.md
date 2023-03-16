# Delinea Account Lifecycle Manager

(Formerly known as "Thycotic Account Lifecycle Manager")

This pack includes XSIAM content.

Delinea’s Account Lifecycle Manager makes service account governance seamless by automating the lifecycle of
service accounts, from workflow-based provisioning to account decommissioning.


## Configuration on Server Side

1. Navigate to **Integrations** > **SIEM** on the left-hand navigation menu.

2. Click the **Create SIEM Integration**.

3. Fill in the required values.

4. Click **Add**.

5. On the **Manage SIEM Integration** page click **edit**, change the output type to **CEF** and set the **Enabled* toggle to Yes.

6. When the integration is configured, click **Test SIEM Integration** in the upper right-hand corner. Clicking will immediately send ALM data to your chosen server.
 
 More information on SIEM integrations can be found [here](https://docs.thycotic.com/alm/current/configuration/other-int/integ-siem#siem_integration).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click and select **Syslog Collector** > **Configure**.
