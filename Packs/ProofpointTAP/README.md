Use the Proofpoint Targeted Attack Protection (TAP) integration to protect against and provide additional visibility into phishing and other malicious email attacks.
Proofpoint TAP detects, analyzes and blocks advanced threats before they reach your inbox. This includes ransomware and other advanced email threats delivered through malicious attachments and URLs.

This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector to collect events from the vendor,  to collect events.You will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).
You can configure the vendor and product by replacing vendor_product_raw with proofpoint_tap_raw.
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
- Fetches events for all clicks and messages relating to known threats within a specified time period.
- Returns forensics evidence.
- Fetches events for clicks to malicious URLs in a specified time period. 
- Fetches events for messages in a specified time period.
- Fetches events for clicks to malicious URLs permitted and messages delivered containing a known attachment threat within a specified time period.
- Fetches a list of IDs of campaigns active in a specified time period.
- Fetches details for a given campaign.
- Fetches a list of the most attacked users in the organization.
- Fetches a list of the top clickers in the organization for a specified time period.
- Decodes URLs that have been rewritten by TAP to their original, target URL.

The playbook in this pack enriches information about the event forensics.
