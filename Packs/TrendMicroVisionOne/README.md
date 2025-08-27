# Trend Micro Vision One

## Overview

Trend Micro Vision One is a cybersecurity platform designed to provide centralized visibility, detection, and response across an organization's IT environment by unifying critical security capabilities, such as Attack Surface Risk Management (ASRM) and Extended Detection and Response (XDR), into a single, integrated architecture.

<~XSIAM>

## This Pack Includes

### Data Normalization and Querying Capabilities

* Data modeling rules to normalize Trend Micro Vision One logs that are ingested via _TrendMicroVisionOneEventCollector_ to Cortex XSIAM.
* Querying ingested logs in XQL Search using the _trend_micro_vision_one_raw_ dataset.

## Supported Log Categories

| Category                    | Category Display Name
| :---| :---
| [Workbench Alerts Logs](https://automation.trendmicro.com/xdr/api-v3/#tag/Workbench)                                  | Workbench
| [Search Result Logs](https://automation.trendmicro.com/xdr/api-v3/#tag/Search/paths/~1v3.0~1search~1detections/get)   | Search Detection
| [Observed Attack Technique Logs](https://automation.trendmicro.com/xdr/api-v3/#tag/Observed-Attack-Techniques)        | Observed Attack Techniques
| [Audit Logs](https://automation.trendmicro.com/xdr/api-v3/#tag/Audit-Logs)                                            | Audit

***

## Enable Data Collection

### Configure Trend Micro Vision One

Send an invitation to be added as an account, see Trend Micro Vision One documentation [here.](https://automation.trendmicro.com/xdr/api-v3/#tag/Accounts-(Foundation-Services-release)/paths/~1v3.0~1iam~1accounts/post)

1. Log in to your Trend Micro Vision One console.
2. Navigate to Administration → User Accounts.
3. Select the Roles tab and create a new custom role.
4. In the Permissions section, navigate to Platform Capabilities → XDR Threat Investigation and enable the following permissions:
    * Workbench, select View and Manage.
    * Observed Attack Techniques, select View, filter, and search.
    * Search, select View, filter and search.
    * Suspicious Object Management, select View, filter and search and Manage lists and configure settings.
5. Go to the Users tab and create a new user account. Assign the role you just created to this user.
6. Once the user is created, you need to generate an API authentication token for this account.  
Make sure to copy this token immediately and store it securely.  
You will need it for the XSIAM configuration, and you won't be able to view it again.

For configuration example from Sekoia, click [here.](https://docs.sekoia.io/integration/categories/endpoint/trend_micro_vision_one_oat/)

### Configure Cortex XSIAM

To fetch event from Trend Micro Vision One, please see integration requirements [here](https://xsoar.pan.dev/docs/reference/integrations/trend-micro-vision-one-event-collector).

1. Navigate to **Settings** → **Configuration** → **Data Collection** → **Automation & Feed Integrations**.
2. Search Trend Micro Vision One.
3. Click **Add Instance**.
4. Insert the **Server URL**.
5. Insert the **API Key** generated from Trend Micro Vision One.
6. Under _Collect_, select on **Fetch events**.

</~XSIAM>
