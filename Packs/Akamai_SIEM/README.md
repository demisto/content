<~XSIAM>

## Overview

This pack enables using a Web Application Firewall (WAF), a security filter that protects against HTTP-based attacks by inspecting traffic before it reaches your application.
**Note:**
Use the native collector for log ingestion. The event collector will be deprecated in the next Cortex XSIAM version.

## This pack includes

Data normalization capabilities:

* Parsing and modeling rules normalize logs ingested via the Cortex XSIAM native collector.
* The *`akamai_waf_raw`* dataset enables querying ingested Akamai WAF SIEM logs in XQL Search.

***

## Data Collection

### Akamai WAF side

1. Go to `WEB & DATA CENTER SECURITY` > `Security Configuration` > choose your configuration > `Advanced settings` > Enable SIEM integration.
2. [Open Control panel](https://control.akamai.com/) and login with the admin account.
3. Open the `identity and access management` menu.
4. Create a user with `Manage SIEM` permissions or make sure the admin has permission to manage the SIEM.
5. Log in to the new account you just created.
6. Open the `identity and access management` menu.
7. Create a `new api client for me`.
8. Assign an API key to the relevant user group, and on the next page assign `Read/Write` access for `SIEM`.
9. Save the configuration and go to the API detail you just created.
10. Click `new credentials` and download or copy it.
11. Use the credentials to configure Akamai WAF in Cortex XSIAM.

For more information, see [here](https://techdocs.akamai.com/siem-integration/docs/akamai-siem-integration-for-splunk-and-cef-syslog).

### Cortex XSIAM side - native collector

To access the Akamai WAF SIEM on your Cortex XSIAM tenant:

1. In the navigation pane, click **Settings** and click **Data Sources**
2. At the top-right corner, click **Add Data Source**
3. Search for **Akamai WAF SIEM** and click **Connect**.

####

</~XSIAM>
