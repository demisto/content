# Linux Events Collection
This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:

- [Linux Events Collection](#linux-events-collection)
  - [Collect Events from Vendor](#collect-events-from-vendor)
    - [Broker VM](#broker-vm)
    - [XDRC (XDR Collector)](#xdrc-xdr-collector)

In either option, you will need to configure the vendor and product for this specific collector.

### Broker VM

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**.
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as linux
   - product as linux

* Pay attention: Timestamp parsing is configured for **mmm dd HH:MM:SS** format in UTC timezone.
                 This can be done by running the following command on the relevant Linux server:
                 `sudo timedatectl set-timezone UTC`

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]\_[product]\_raw with linux_linux_raw
When configuring an XDR collector profile, you should use a yml that will be used, among other things, to configure the vendor and product. This example demonstrates how to set it, specifically for the Ubuntu Linux product:

```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/auth.log
    - /var/log/messages
    - /var/log/secure
  processors:
    - add_fields:
        fields:
          vendor: linux
          product: linux
```

**Please note**: The above configuration uses the default location of the logs. In case your linux saves the logs under a different location, you would need to change it in the yaml (under the `paths` field).
