This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:
 - [Broker VM](#broker-vm)
 - [XDRC (XDR Collector)](#xdrc-xdr-collector) 

In either option, you will need to configure the vendor and product for this specific collector.

### Broker VM
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/configure-your-broker-vm).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
1. Right-click, and select **Syslog Collector** -> **Configure**.
1. When configuring the Syslog Collector, set:
   - vendor as redhat
   - product as linux

### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]_[product]_raw with redhat_linux-xdrc_raw.
When configuring the instance, you should use a yml that configures the vendor and product, like this example for the Microsoft NPS product:

```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - c:\windows\system32\logfiles\*.log
  processors:
    - add_fields:
        fields:
          vendor: msft
          product: nps
```










When configuring the Syslog Collector, set vendor as redhat, product as linux.

1. XDRC (XDR Collector) - You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]_[product]_raw with redhat_linux-xdrc_raw.\
When configuring the instance, you should use a yml that configures the vendor and product, like this example for the Microsoft NPS product:

```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - c:\windows\system32\logfiles\*.log
  processors:
    - add_fields:
        fields:
          vendor: msft
          product: nps
```

