This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

In either option, you will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with msft_dns_raw
When configuring an XDR collector profile, you should use a yml that will be used, among other things, to configure the vendor
and product. This example demonstrates how to set the configuration file:

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

**Please note**: The above configuration uses the default location of the logs. In case your linux saves the logs under a different location, you would need to change it in the yaml (under the `paths` field).
