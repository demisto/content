<~XSIAM>

## Overview

iZOOlogic provides digital risk protection and threat management, including brand abuse, phishing, malware, social media, and executive threat monitoring.
This pack enables the normalization of iZOOlogic incident data ingested into Cortex XSIAM via API-based collection.
The normalized data can then be queried and used for investigation and analysis in Cortex XSIAM.

## This pack includes

Data normalization capabilities:

* Rules for modeling iZOOlogic incidents that are ingested via the API into Cortex XSIAM.
* The ingested iZOOlogic incidents can be queried in XQL Search using the *`izoologic_izoologic_raw`* dataset.

## Data Collection

### iZOOlogic side

1. Obtain an **API Key** and its corresponding **Secret Key** from iZOOlogic for the iZOOlabs Web API.
2. Note your iZOOlogic API **Server URL**.

For more information, see the iZOOlabs Web API documentation.

### Cortex XSIAM side - API

Configure the iZOOlogic integration in Cortex XSIAM using the following parameters.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The iZOOlogic API server URL. | True |
| API Key | The API key provided by iZOOlogic for authentication. | True |
| Secret Key | The secret key corresponding to the API key. | True |
| Fetch incidents | Whether to fetch incidents from iZOOlogic. | False |
| Fetch incident types | A comma-separated list of incident types to fetch from iZOOlogic. | True |
| Maximum incidents per fetch per type | The maximum number of incidents to fetch per type per fetch cycle. | True |
| Trust any certificate (not secure) | Whether to trust any certificate \(not secure\). | False |
| Use system proxy settings | Whether to use the system proxy settings. | False |

</~XSIAM>
