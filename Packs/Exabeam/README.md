<~XSIAM>

## Overview

Exabeam Threat Center is part of the Exabeam Security Management Platform, providing detection, User Event Behavioral Analytics (UEBA), and SOAR capabilities.
This pack enables the normalization of Exabeam Threat Center data ingested into Cortex XSIAM via API-based collection.
The normalized data can then be queried and used for investigation and analysis in Cortex XSIAM.

## This pack includes

Data normalization capabilities:  

* Rules for modeling Exabeam Threat Center logs that are ingested via the API into Cortex XSIAM.  
* The ingested Exabeam Threat Center logs can be queried in XQL Search using the *`<dataset_name>`* dataset.

## Data Collection

### Exabeam Threat Center side

There are 2 supported authentication methods:

* **API Token** - API token should be entered in the **API Token** parameter. In order to use the fetch incident functionality in this integration, the username must also be provided in the **Username** parameter.
* **Basic Authentication** - Providing username and password in the corresponding parameters in the configuration. This method also allows fetching incidents.

**NOTE**:  
Using an API Key in the **Password** parameter and `__token` in the Username parameter is deprecated. This method does not support incident fetching.

#### Generate a Cluster Authentication Token

1. Navigate to **Settings** > **Admin Operations** > **Cluster Authentication Token**.
2. In the **Cluster Authentication Token** menu, click the blue **`+`**.
3. In the **Setup Token** menu, fill in the **Token Name**, **Expiry Date**, and select the **Permission Level**(s).
4. Click **ADD TOKEN** to apply the configuration.

For more information, see the [Exabeam Administration Guide](https://docs.exabeam.com/en/advanced-analytics/i54/advanced-analytics-administration-guide/113254-configure-advanced-analytics.html#UUID-70a0411c-6ddc-fd2a-138d-fa83c7c59a40).

### Cortex XSIAM side - API

Configure the integration in Cortex XSIAM using the following parameters.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Username |  | False |
| Password |  | False |
| API Token | Cluster Authentication Token | False |
| Exabeam Incident Type | Incident type to filter in Exabeam. Possible values are: generic, abnormalAuth, accountManipulation, accountTampering, ueba, bruteForce, compromisedCredentials, cryptomining, dataAccessAbuse, dataExfiltration, dlp, departedEmployee, dataDestruction, evasion, lateralMovement, alertTriage, malware, phishing, privilegeAbuse, physicalSecurity, privilegeEscalation, privilegedActivity, ransomware, workforceProtection. | False |
| Priority | Incident priority to filter in Exabeam. Possible values are: low, medium, high, critical. | False |
| Status | Incident status to filter in Exabeam. Possible values are: closed, closedFalsePositive, inprogress, new, pending, resolved. | False |
| Fetch incidents |  | False |
| Max incidents per fetch |  | False |
| First fetch timestamp (**number**, **time unit**, e.g., 12 hours, 7 days) |  | False |
| Advanced: Minutes to look back when fetching | The number of minutes to look back for incidents created before the last run that did not match the initial query. Default is 1. | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

</~XSIAM>
