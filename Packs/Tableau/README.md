# Tableau

This pack includes XSIAM content. 

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

In either option, you will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with tableau_log_raw
When configuring an XDR collector profile, you should use a yml that will be used, among other things, to configure the vendor
and product. This example demonstrates how to set the configuration file:

```
filebeat.inputs:
- type: filestream
  enabled: true
  id: tableau
  paths:
    - /tableau/server/data/data/tabsvc/logs/vizportal/*
    - /tableau/server/data/data/tabsvc/logs/apigateway/*
    - /tableau/server/data/data/tabsvc/logs/httpd/*
  processors:
    - add_fields:
        fields:
          vendor: tableau
          product: log
```

**Please note**: The above configuration uses the default location of the logs. In case your Linux saves the logs under a different location, you would need to change it in the yaml file (under the `paths` field).


### Parsing Rules Supported Timestamp Formats

The following are supported:
* yyyy-mm-dd hh:mm:ss.ms(3) -zzzz
* yyyy-mm-ddThh:mm:ss.ms(*) "-zzzz" (At the beginning of the code)
* yyyy-mm-ddThh:mm:ss.ms(3)Z (Available for the **ts** field in the raw log)
* yyyy-mm-ddThh:mm:ss.ms(*) (Available for the **ts** field in in the raw log) 