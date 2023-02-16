# Microsoft DHCP

This pack includes Cortex XSIAM content.

## Configuration on Server Side

1. Start the DHCP administration tool (go to Start, Programs, Administrative Tools, and click **DHCP**).
2. Right-click the DHCP server, and select **Properties** from the context menu.
3. Select the **General** tab.
4. Select the "Enable DHCP audit logging" check box.
5. Click OK.


## Collect Events from Vendor

In order to use the collector, use the [XDRC (XDR Collector)](#xdrc-xdr-collector) option.




### XDRC (XDR Collector)

To create or configure the Filebeat collector, use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with *microsoft_dhcp_raw*.

When configuring the instance, you should use a YML file that configures the vendor and product, as shown in the below configuration for the Microsoft DHCP product.

Copy and paste the following in the *Filebeat Configuration File* section (inside the relevant profile under the *XDR Collectors Profiles*).





#### Filebeat Configuration File

```
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - c:\Windows\System32\dhcp\DhcpSrvLog*.log
    processors:
      - drop_event.when.not.regexp.message: "^[0-9]+,.*"
      - dissect:
          tokenizer: "%{id},%{date},%{time},%{description},%{ipAddress},%{hostName},%{macAddress},%{userName},%{transactionID},%{qResult},%{probationTime},%{correlationID},%{dhcid},%{vendorClassHex},%{vendorClassASCII},%{userClassHex},%{userClassASCII},%{relayAgentInformation},%{dnsRegError}"
      - drop_fields:
          fields: [ "message" ]
      - add_fields:
          fields:
            vendor: "microsoft"
            product: "dhcp"
      - add_locale: ~
      - rename:
          fields:
            - from: "event.timezone"
              to: "dissect.timezone"
          ignore_missing: true
          fail_on_error: false
      - add_tags:
          tags: [windows_dhcp]
          target: "xdr_log_type"
```

**Note**: The above configuration uses the default location of the logs.