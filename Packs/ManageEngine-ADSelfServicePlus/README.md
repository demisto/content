<~XSIAM>

# ManageEngine ADSelfService Plus

This pack includes Cortex XSIAM content.

## Configuration on Server Side

You need to configure ManageEngine ADSelfService Plus to forward Syslog messages to Cortex XSIAM.

Follow the below steps:

1. Log in to ADSelfService Plus as default Admin.
2. Navigate to **Admin** > **Product Settings** > **Integration Settings**.
3. Click the **Syslog Server** tile.
4. Enter the details including Syslog Server Name, Port Number and Port Protocol.
5. Select CEF for the Syslog Standard.
5. Click **Save**.

Note:
Make sure that the time zone of the logs are set to UTC.
Time parsing is based on "TIME" field (UTC epoch).

For additional information, refer to the official ManageEngine [documentation](https://www.manageengine.com/products/self-service-password/kb/siem-system-integration.html).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - Vendor as "Auto-Detect".
   - Product as "Auto-Detect".
   - Format as "Auto-Detect".

</~XSIAM>
