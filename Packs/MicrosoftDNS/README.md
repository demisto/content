# Microsoft DNS

This pack includes XSIAM content 

## Configuration on Server Side

- Open the RUN window and enter: dnsmgmt.msc
- Click on the name of the DNS server in the left-hand panel and then right-click.
- Click on Properties and then on the Debug logging tab.
- Add a check in "Log packets for debugging"
- Ensure the following are checked: Outgoing, Incoming, Queries/Transfers, Updates.
- For long (detailed) logs, select Details. *Note: Detailed capture will heavily bloat the logs*
- Enter log file path: c:\Windows\System32\dns\DNS.log
## Filebeat Collection
In order to use the collector, you need to use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with msft_dns_raw

When configuring the instance, you should use a yml that configures the vendor and product, just as seen in the below configuration for the Microsoft DNS product.

Copy and paste the below YAML in the "Filebeat Configuration File" section (inside the relevant profile under the "XDR Collectors Profiles").

#### Filebeat Configuration file:

```
filebeat.inputs:
- type: filestream
  paths:
    - c:\Windows\System32\dns\DNS.log
processors:
  - add_fields:
      fields:
        vendor: msft
        product: dns
```

**Please note**: The above configuration uses the default location of the logs. 