<~XSIAM>
# McAfee Database Security

## Configuration on Server Side
You need to configure McAfee Database Security to forward Syslog messages.

1. Login to the Database Security console.
2. Navigate to **System** > **Interfaces** > **Syslog**.
3. Click the **Use syslog** checkbox.
4. Configure the correct syslog host/port.
5. Select the transport protocol.
6. Set the syslog format to CEF (default).

Make sure to make the needed changes to the CEF format, as described [here](https://docs.trellix.com/bundle/database-security-4.8.x-product-guide/page/GUID-AB0748F3-CFA0-4688-9496-29DF34BA0428.html), in order that the mapping will work as expected.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
</~XSIAM>