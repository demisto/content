# Ivanti Pulse Secure VTM
This pack includes Cortex XSIAM content. 
<~XSIAM>
## Configuration on Server Side
You need to configure the Virtual Traffic Manager (VTM) to forward Syslog messages.

Open the VTM UI; 

For forwarding Event logs:
1. Click the **System** tab and click **Alerting**.
2. In the **Alert Mappings** section, make sure Audit Events are kept in Syslog (action).
3. Click the **Global Settings** tab and click **Logging**.
4. Mark the **Whether to mirror the audit log to EventID** checkbox as **Yes**.
5. Under the **Apply Changes** section, click **Update**.

Setup for forwarding requests logging per Virtual Server (VS):
1. Click the **Services** tab, and under **Virtual Servers**, select a VS.
2. Click the **Request Logging** section for the relevant VS.
3. Under **Remote Request Logging**, make sure to preform the following; <br />
    3.1. Mark the checkbox for **syslog!enabled** as **Yes**. <br />
    3.2. In the **syslog!ipendpoint** section, fill the remote IP and Port of your syslog collector. <br />
    3.3. In the **syslog!msg_len_ limit** section, set the limit for a syslog message to **2048**. <br />
    3.4. In the **syslog!format** section, set the relevant syslog format.
    * For HTTPS, traffic inspection based VSs, select the **Simple connection log** format.
    * For HTTP, traffic inspection based VSs, select the **custom** format, input-
    ```bash
    %t|%T|%h|%m %U|%{Content-Type}o|%s|%u|%b|%{Cookie}i|%{Referer}i|%{User-Agent}i
    ``` 
4. In the **Apply Changes** section, click **Update**.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - ivanti
   - product as product - vtm
</~XSIAM>
