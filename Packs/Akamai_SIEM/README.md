<~XSIAM>
 
## Overview
A Web Application Firewall (WAF) is a security filter that protects against HTTP-based attacks by inspecting traffic before it reaches your application.
Note: The Event Collector is planned for deprecation in 2.8 version release. Customers are advised to switch to the Native Collector for continued support and enhanced capabilities.
 
## This pack includes:
 
Data normalization capabilities:
  * Rules for Parsing and Modeling logs that are ingested via the Native Collector on Cortex XSIAM.
  * The ingested Akamai WAF SIEM logs can be queried in XQL Search using the *`akamai_waf_raw`* dataset.
 
***
 
## Data Collection
 
### Akamai WAF side

1. Go to `WEB & DATA CENTER SECURITY` > `Security Configuration` > choose your configuration > `Advanced settings` > Enable SIEM integration.
2. [Open Control panel](https://control.akamai.com/) and login with admin account.
3. Open `identity and access management` menu.
4. Create a user with assigned roles `Manage SIEM` or make sure the admin has rights to manage SIEM.
5. Log in to the new account you created in the last step.
6. Open `identity and access management` menu.
7. Create `new api client for me`.
8. Assign an API key to the relevant user group, and on the next page assign `Read/Write` access for `SIEM`.
9. Save configuration and go to the API detail you created.
10. Press `new credentials` and download or copy it.
11. Now use the credentials to configure Akamai WAF in Cortex XSIAM.
 
For more information <[Link to the official docs](https://techdocs.akamai.com/siem-integration/docs/akamai-siem-integration-for-splunk-and-cef-syslog)>.
 
### Cortex XSIAM side - Native Collector
 
To access the Akamai WAF SIEM on your Cortex XSIAM tenant:

1. On the left panel, click **Settings** and click **Data Sources**
2. At the top-right corner, click **Add Data Source**
3. Search for **Akamai WAF SIEM** and click **Connect**.
 
 
#### 

</~XSIAM>