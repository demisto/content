## IBM Security Verify Directory LDAP

IBM® Security Verify Directory is a trusted identity infrastructure with LDAP, proxy, and virtual directory server capabilities. It includes management tools and GUIs for easy administration. As part of the IBM Verify portfolio, it supports identity management and is the default directory for WebSphere® and AIX®.

<~XSIAM>

## What does this pack do?

- Modeling rules for audit events.
- Parsing rules for IBM Security Verify Directory.
- File collector configuration manual.

## Filebeat Collection

To use the collector, use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

Configure the vendor and product for this specific collector.

## XDRC (XDR Collector)

1. Refer to the official XDR Collector documentation [XDR Collectors](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/XDR-Collectors).  

2. Replace [vendor]\_[product]\_raw with ibm_ldap_raw in your configuration.

When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the IBM Security Verify Directory product.

When configuring the instance, use a YAML file that specifies the vendor and product, as shown in the Filebeat Configuration File example below.

#### Filebeat Configuration file

```commandline
- type: filestream
    enabled: true
    id: ldap
    paths: 
    - instance_home/idsslapd-instance_name/logs/audit.log
    processors: 
      - add_fields: 
          fields: 
            vendor: ibm
            product: ldap
```

This configuration collects data into a dataset named `ibm_ldap_raw`.  

For more information on audit log file locations, see [here](https://www.ibm.com/docs/en/svd/10.0.4?topic=tools-directory-server-log-configuration-file-locations)  

**Note**: The configuration uses the default location of the Message Tracking logs. If your Exchange server stores the logs in a different location, update the `paths` field in the YAML accordingly.  

</~XSIAM>
