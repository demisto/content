## IBM Security Verify Directory LDAP

IBM® Security Verify Directory is a trusted identity infrastructure with LDAP, proxy, and virtual directory server capabilities. It includes management tools and GUIs for easy administration. As part of the IBM Verify portfolio, it supports identity management and is the default directory for WebSphere® and AIX®.

<~XSIAM>

## What does this pack do?

- Modeling rules for audit events.
- Parsing rules for IBM Security Verify Directory.
- File collector configuration manual.

## Filebeat Collection

In order to use the collector, you need to use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

## XDRC (XDR Collector)

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/XDR-Collectors).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with ibm_ldap_raw

When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the IBM Security Verify Directory product.

Copy and paste the below YAML in the "Filebeat Configuration File" section (inside the relevant profile under the "XDR Collectors Profiles").

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

This configuration will collect the data into a dataset named `ibm_ldap_raw`.

For more information regarding audit log file location please review the following document [here](https://www.ibm.com/docs/en/svd/10.0.4?topic=tools-directory-server-log-configuration-file-locations)

**Please note**: The above configuration uses the default location of the Message Tracking logs. In case your Exchange server saves the Message Tracking logs under a different location, you would need to change it in the yaml (under the `paths` field).

</~XSIAM>