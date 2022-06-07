This pack enables you to interact with Jamf Pro which is the product that allows you to manage Apple devices (Mac, iPhone, Apple TV, iPad). It can be used to control
  various configurations via different policies, install and uninstall applications, lock
  devices, perform smart groups searches, and more.

If your computer is lost or stolen, you can remotely lock the computer or erase its contents to ensure the security of sensitive information.

If an application on your Apple device has a security issue, you can check for this app on all your Apple devices and then decide what action to take.

This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:
 - [Broker VM](#broker-vm)
 - [XDRC (XDR Collector)](#xdrc-xdr-collector) 

In either option, you will need to configure the vendor and product for this specific collector.
### Broker VM
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/configure-your-broker-vm).
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as jamf
   - product as pro
### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).
You can configure the vendor and product by replacing vendor_product_raw with jamf_pro_raw.
When configuring the instance, you should use a yml that configures the vendor and product, like this example for the Microsoft NPS product:

```yml
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

## What does this pack do?
- Run remote commands on a computer or mobile device, such as erase, lock/lost_mode.
- Get various details about devices and users, such as names, IDs, services, applications, hardware, etc.
- Get a list of computers details based on applications.
