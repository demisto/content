# Microsoft WSUS

This pack includes XSIAM content 
## Configuration on Server Side
#### Validation that WSUS server role is enabled:
 - In "Server Manager", press "Manage" then "Add Roles and Features".
 - Navigate to "Server Roles" section in the left menu.
 - Scroll down and validate that "Windows Server Update Services" is selected.
 - Validate that also "WID Connectivity" and "WSUS Services" are selected and installed.

![Server Screenshot](https://i.postimg.cc/V6vjDDqH/WSUS.jpg)
## Collect Events from Vendor
In order to use the collector, you need to use the following option to collect events from the vendor:
- [XDRC (XDR Collector)](#xdrc-xdr-collector)
You will need to configure the vendor and product for this specific collector.
### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]_[product]raw with msft_wsus_raw. 

When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the Microsoft WSUS product.

## Filebeat Collection
In order to use the collector, you need to use the following option to collect events from the vendor:
- [XDRC (XDR Collector)](#xdrc-xdr-collector)
You will need to configure the vendor and product for this specific collector.
### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).
You can configure the vendor and product by replacing [vendor]_[product]_raw with msft_wsus_raw.
When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the Microsoft NPS product.

Copy and paste the below YAML in the "Filebeat Configuration File" section (inside the relevant profile under the "XDR Collectors Profiles").
#### Filebeat Configuration file:
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