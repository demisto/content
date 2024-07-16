# Barracuda Cloudgen Firewall
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Barracuda Cloudgen Firewall to forward Syslog messages.

1. Go to **CONFIGURATION** > **Full Configuration** > **Box** > **Infrastructure Services** > **Syslog Streaming**.
2.  Click **Lock**.
3. Set **Enable Syslog Streaming** to **yes**.
4. Click **Send Changes** and **Activate**.

* Pay attention: Timestamp parsing is only supported for UNIX timestamp (UTC). 

More details, see [here](https://campus.barracuda.com/product/cloudgenfirewall/doc/96026562/how-to-configure-syslog-streaming/)
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - barracuda
   - product as product - cgfw
