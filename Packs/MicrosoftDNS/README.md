# Microsoft DNS
This pack includes XSIAM content.

## Configuration on Server Side for Filebeat
1. Open the RUN window and enter: dnsmgmt.msc
2. Right-click the name of the DNS server in the left-hand panel and select **Properties**.
3. In the Debug logging tab, add a check in **Log packets for debugging**
4. Ensure the following are checked: **Outgoing**, **Incoming**, **Queries/Transfers**, **Updates**.
5. For long (detailed) logs, select **Details** and enter the log file path: ```c:\Windows\System32\dns\DNS.log```
   
   *Note: Detailed captures will heavily bloat the logs.*
 
## Filebeat Collection
For the Filebeat collector, use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)
Use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with *microsoft_dns_raw*.

When configuring the instance, you should use a yml file that configures the vendor and product, as shown in the below configuration for the Microsoft DNS product.

**Pay Attention**:
* There are two integrations available in this content pack.
* Timestamp log ingestion is supported in either of the following formats in UTC (00:00) time.
   - *%m/%d/%Y %I:%M:%S %p*
   - *%d/%m/%Y %H:%M:%S*

* ***As enrichment, forwarding DNS Audit logs is supported via Winlogbeat***

- Via Filebeat for DNS Debug logs.
- Via Winlogbeat for DNS Audit logs.

Follow these steps in order to configure the XDR Collector:
1. The implementation of the Collector for both of the methods requires to create a [Profile](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Add-an-XDR-Collector-Profile-for-Windows) for each integration.
   * For **XSIAM version 1.2** only, in the relevant profile under the *XDR Collectors Profiles*, copy and paste the information from the [Filebeat Configuration File](#filebeat-configuration-file) section.
2. Create a [Policy](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Apply-Profiles-to-Collection-Machine-Policies) and allocate the profiles you created to it.

#### Filebeat Configuration File

```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    -  c:\Windows\System32\dns\DNS.log
  processors:
    - add_fields:
        fields: 
          vendor: "microsoft"
          product: "dns"
```
**Note**: The above configuration uses the default location of the logs. 

### Winlogbeat Configuration File

```
winlogbeat.event_logs: 
  - name: Microsoft-Windows-DNSServer/Audit
    processors: 
      - add_fields: 
          fields: 
            vendor: microsoft
            product: dns
    id: dns-audit-logs
```

For **XSIAM version 1.3** and above, use the built-in YAML template provided within the XDR collector configuration.
