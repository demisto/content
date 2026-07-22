This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, please use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]\_[product]\_raw with msft_ecm_raw
When configuring an XDR collector profile, you should use a yml that will be used, among other things, to configure the vendor and product. This example demonstrates how to set it, specifically for the Microsoft ECM product:

```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - "C:\\Program Files\\Microsoft Configuration Manager\\Logs\\*.log"
  processors:
    - add_fields:
        fields:
          vendor: msft
          product: ecm
```

**Please note**: The above configuration uses the default location of the logs. In case your Microsoft ECM server saves the logs under a different location, you would need to change it in the yaml (under the `paths` field).
