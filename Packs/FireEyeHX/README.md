<~XSIAM>
# FireEye HX
This pack includes Cortex XSIAM content.

## Configuration on Server Side
### Raw syslog audit messages
In order to configure FireEye HX to send syslog audit logs, refer to FireEye HX [Endpoint Security Server System Administration Guide](https://docs.trellix.com/bundle/hx_sag_5-3-0_pdf/resource/HX_SAG_5.3.0_pdf.pdf) (**Configuring a Syslog Server Using the CLI**).
Make sure to configure the syslog timestamp format to be RFC-3339 UTC.

### CEF format logs
In order to configure FireEye HX to send CEF logs, refer to FireEye HX [Endpoint Security Server System Administration Guide](https://docs.trellix.com/bundle/hx_sag_5-3-0_pdf/resource/HX_SAG_5.3.0_pdf.pdf).

For further assistant, contact the tech support of FireEye HX.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as fireeye
   - product as hx_audit
   - format as Auto-Detect
   - protocol as UDP
   
 </~XSIAM>