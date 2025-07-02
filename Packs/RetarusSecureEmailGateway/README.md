<~XSIAM>

# Retarus Secure Email Gateway

Retarus Secure Email Gateway is a fully managed cloud service that provides comprehensive, multi-layered security and for organizations.

It filters all inbound and outbound traffic to defend against threats like malware, ransomware, and phishing using advanced sandboxing technology.

## This pack includes

Data normalization capabilities:

* Rules for modeling Retarus Secure Email Gateway logs that are ingested via the integration on Cortex XSIAM.
* The ingested logs can be queried in XQL Search using the *`retarus_secure_email_gateway_raw`* dataset.

## Supported log categories

| Category                         | Category Display Name            |
|:---------------------------------|:---------------------------------|
| AntiVirus MultiScan Inbound      | MultiScan                        |
| AntiVirus MultiScan Outbound     | MultiScan                        |
| Message Transfer Agent Inbound   | MTA                              |
| Message Transfer Agent Outbound  | MTA                              |
| CxO Fraud Detection              | CxO                              |
| Patient Zero Detection           | PZD                              |
| Sandboxing                       | Sandboxing                       |

### Supported Timestamp Formats

YYYY-MM-DD hh:mm:ss +hhmm (time zone based on UTC).

Example: "2018-10-16 14:58:43 +0200".

***

## Data Collection

### Retarus Secure Email Gateway side

Token ID is provided by Retarus for SIEM integration.

Note, due to the Retarus API limitation, only one instance can be configured for each token and channel.

Two instances with the same token and *different* channels are allowed.

Two instances with the same token and *same* channel may result in errors and/or missing events.

For more information [click here](https://docs.retarus.com/seg/api-manual-forensic-siem-integration#APIManual-ForensicSIEMIntegration-Authorization).

### Cortex XSIAM side

1. Go to Marketplace and install Retarus Secure Email Gateway.
2. Navigate to **Settings** -> **Data Collection** -> **Automation & Feed Integrations** -> **Add instance**.
3. Insert collector name.
4. Insert Server URL, default value is "events.retarus.com".
4. Insert Token ID.

</~XSIAM>
