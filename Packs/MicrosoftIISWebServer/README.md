# Microsoft IIS WEB SERVER

This pack includes XSIAM content.

## Configuration on the Server Side

1. Open the IIS Manager.
2. Click the site.
3. In the window on the right, click **Logging**.
4. Ensure the format is set to W3C.
## Collect Events from Vendor
In order to use the collector, you need to use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]_[product]raw with [vendor]_[product]_raw. 

When configuring the instance, you should use a YAML file that configures the vendor and product, as seen in the configuration below for the Microsoft IIS product.

Copy and paste the content of the following YAML file in the *Filebeat Configuration File* section (inside the relevant profile under the *XDR Collectors Profiles*).

#### Filebeat Configuration file:

```commandline
filebeat.modules:
- module: iis
  access:
    enabled: true
    var.paths: ["C:/inetpub/logs/LogFiles/*/*.log"]
  error:
    enabled: true
    var.paths: ["C:/Windows/System32/LogFiles/HTTPERR/*.log"]
```
