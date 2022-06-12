This pack includes XSIAM content.

## Collect Events from Vendor

### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]_[product]_raw with mysql_enterprise_raw.\
When configuring the instance, you should use a yml that configures the vendor and product, like this example:

```
filebeat.modules:
- module: mysqlenterprise
  audit:
    var.input: file
    var.paths: /home/user/mysqlauditlogs/audit.*.log
```
