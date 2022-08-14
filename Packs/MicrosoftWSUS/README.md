This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:
 - [XDRC (XDR Collector)](#xdrc-xdr-collector) 

In either option, you will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]_[product]_raw with msft_wsus_raw.\
When configuring the instance, you should use a yml that configures the vendor and product, like this example for the Microsoft NPS product:

```
filebeat.inputs:
- type: filestream
  paths:
    - C:\Program Files\Update Services\LogFiles\Change.log
    - C:\Program Files\Update Services\LogFiles\SoftwareDistribution.log
processors:
- add_fields:
    fields:
        vendor: msft
        product: WSUS
```
