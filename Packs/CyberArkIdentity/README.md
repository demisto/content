This content pack includes Cortex XSIAM content.

## Collect Events from Vendors

To use the collector, choose one of the following options to collect events from the vendor:
 - [Broker VM](#broker-vm)
 - [XDRC (XDR Collector)](#xdrc-xdr-collector) 

For either option, you need to configure the vendor and product for the specific collector.

### Broker VM
You will need to [configure your Broker VM](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/configure-your-broker-vm). \
You can also configure the specific vendor and product for this instance.
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as cyberark
   - product as identity

### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2). \
You can configure the vendor and product by replacing [vendor]_[product]_raw with cyberark_identity_raw
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

