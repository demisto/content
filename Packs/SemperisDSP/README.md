# Semperis DSP
This pack includes Cortex XSIAM content. 
<~XSIAM>
## Configuration on Server Side
You need to configure Semperis DSP to forward Syslog messages.

Open your Semperis DSP UI and follow these instructions:
1. At the left panel, click **SETTINGS** > **SIEM Integration**.
2. Under the **Syslog Server** section, configure the following:
    * Make sure the syslog enablement checkbox is checked.
    * Under **Primary Syslog Server**, input the relevant syslog server IP address.
    * Under **Primary Port**, input the relevant syslog server port.
    * Make sure the protocol set for the primary communication is TCP (Without TLS).
3. Under the **Change Event Filtering** section, configure the following:
    * Make sure the **AD Changed Items** checkbox is enabled.
    * Make sure the **DNS** checkbox is enabled.
    * Make sure the **Send Operations Log to Syslog** checkbox is enabled.

  * Pay attention: Timestamp parsing is supported for the **OriginatingTime** OR **OperationTime** fields in UTC **%Y-%m-%dT%H:%M:%E3SZ** (+0000) format.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - semperis
   - product as product - dsp
</~XSIAM>