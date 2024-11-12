# Imperva WAF
This pack includes Cortex XSIAM content.

<~XSIAM>
## Configuration on Server Side
You need to configure Imperva WAF to forward Syslog messages in CEF format.

For the SIEM Log integration, see the following [documentation](https://docs.imperva.com/bundle/cloud-application-security/page/siem-log-configuration.htm).
## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Set-up-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - imperva_inc_
   - product as product - securesphere
</~XSIAM>