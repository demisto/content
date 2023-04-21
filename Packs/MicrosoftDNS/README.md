# Microsoft DNS

This pack includes XSIAM content.

## Configuration on Server Side

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
 
For **XSIAM version 1.2** only, copy and paste the below in the *Filebeat Configuration File* section (inside the relevant profile under the *XDR Collectors Profiles*).
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

For **XSIAM version 1.3** and above, please use the built-in YAML template provided within the XDR collector  configuration.
