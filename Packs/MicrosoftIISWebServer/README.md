# Microsoft IIS WEB SERVER

This pack includes XSIAM content.

## Configuration on the Server Side

1. Click **Tools** > **Internet Information Services (IIS) Manager**.
   ![IIS Manager](https://github.com/demisto/content-docs/blob/master/docs/doc_imgs/integrations/iis-manager.png)
2. In the left pane, expand the **Sites** folder and click the designated site.
   ![Designated Site](https://github.com/demisto/content-docs/blob/master/docs/doc_imgs/integrations/iis-designated-site.png)
3. In the main window, click **Logging**.  
4. In the Log File section, ensure the format is set to **W3C**
   ![Format W3C](https://github.com/demisto/content-docs/blob/master/docs/doc_imgs/integrations/iis-w3c.png)
5. Cick **Select Fields**
6. Ensure all the fields are checked.
   ![Select Fields](https://github.com/demisto/content-docs/blob/master/docs/doc_imgs/integrations/iis-select-fields.png)
   
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
