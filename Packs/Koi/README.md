# KOI

## Overview

KOI is an endpoint security platform that provides visibility and control over browser extensions, SaaS applications, and web-based threats.

## This pack includes
This pack includes an 

* Integration that fetches alerts and audit logs from KOI and ingests them into Cortex XSIAM for centralized security monitoring, correlation, and threat analysis.
* Integration commands for managing the KOI security posture: query and search the software/extension inventory, manage blocklist and allowlist entries, and control governance policies.
* Data normalization capabilities:
  * Rules for modeling KOI logs that are ingested via the API into Cortex XSIAM.
  * The ingested KOI logs can be queried in XQL Search using the *`koi_koi_raw`* dataset.

### Supported Event Types

* Audit logs
* Alerts

***

## Data Collection

### KOI side

#### Creating an API Key

1. **Ensure Appropriate Role**: To create an API key, you must have the `xt-Administrator` role.
2. **Navigate to the Settings Page**: Access the Settings page from the top navigation bar.
3. **Open the API Access Tab**: In the Settings page, select the **API Access** tab.
4. **Click "Create New API Key"**: Click the **Create new API key** button.
5. **Access Your API Key**: Within a few seconds, a new API key will appear in the table. Click the **Copy** button next to the key to copy it securely.


### Cortex XSIAM side - API

Configure the integration in Cortex XSIAM using the following parameters.

| **Parameter**                     | **Description**                                                                                                                                    | **Mandatory** |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| Name                              | Name of the integration instance.                                                                                                                  | True          |
| Server URL                        | The KOI API server URL.                                                                                                                            | Ture          |
| API Key                           | The API key for authenticating with the KOI API. See the help section for instructions on creating an API key.                                     | True          |
| Fetch events                      | Whether to fetch events.                                                                                                                           | False         |
| Fetch event types                 | Select which event types to fetch: Behavior Analytics alerts, Addressable Alerts, Detect And Protect Alerts. Default is Behavior Analytics alerts. | Conditional   |
| Audit log type filter             | Filter audit logs by type(s). If not specified, all audit log types will be fetched.                                                               | False         |
| Maximum number of events per type | Default is 5000 events to fetch for each type.                                                                                                     | False         |