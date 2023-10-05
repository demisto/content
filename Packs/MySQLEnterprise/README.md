This pack includes XSIAM content.

## Collect Events from Vendor

- [MySQL Enterprise Server Configuration](#mysql-enterprise-server-configuration)
- [XDRC (XDR Collector)](#xdrc-xdr-collector)

### MySQL Enterprise Server Configuration

1. Install the [audit log plugin](https://dev.mysql.com/doc/mysql-secure-deployment-guide/5.7/en/secure-deployment-audit.html)
2. After the audit log plugin installation verify the following two lines in the `my.cnf` file:
```
plugin-load = audit_log.so
audit_log_format=JSON
```

Note: In order to parse the timestamp correctly, make sure that the timestamp field is in the default time zone - UTC.
The supported time format is yyyy-MM-dd hh:mm:ss (2021-12-08 10:00:00).


### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).\
You can configure the vendor and product by replacing [vendor]_[product]_raw with mysql_enterprise_raw.\
When configuring the instance, you should use a yml that configures the vendor and product, like this example:

```
filebeat.inputs:
- type: filestream
  enabled: true
  json.keys_under_root: true
  json.add_error_key: true
  paths:
    - /var/lib/mysql/audit.log
  processors:
    - add_fields:
        fields:
          vendor: mysql
          product: enterprise
```
