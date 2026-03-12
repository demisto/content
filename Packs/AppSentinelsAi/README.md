<~XSIAM>

## Overview

AppSentinel is an application security platform that provides audit logging for user activities, security events, and administrative operations. It tracks actions such as create, modify, and delete operations performed by users across the platform, enabling organizations to maintain a comprehensive audit trail for compliance and security monitoring.

This pack enables ingestion and normalization of AppSentinel Audit logs into Cortex XSIAM for security monitoring and analysis.

## This pack includes

Data normalization capabilities:

* Modeling Rule for AppSentinels Audit logs that are ingested via API into Cortex XSIAM.
* The ingested AppSentinels Audit logs can be queried in XQL Search using the *`appsentinels_appsentinels_raw`* dataset.

## Supported log categories

| Category                    | Category Display Name                 |
|:----------------------------|:--------------------------------------|
| security_events             | Security Events                       |
| users_events                | User Events                           |
| admin_events                | Admin Events                          |

### Supported endpoints

| Endpoint                    | Description                           |
|:----------------------------|:--------------------------------------|
| Audit                       | Audit logs                            |
| Events                      | Event logs                            |

***

## Data Collection

### AppSentinel side

Configure AppSentinel API access for audit log collection:

1. Log in to the AppSentinel management console.
2. Navigate to **Settings** → **API Access**.
3. Generate an API key and record the corresponding `x-user-key`.
4. Ensure the API key has permissions to access the Audit and Events endpoints.

### Authentication Method

AppSentinel uses API key authentication. The following headers must be included in API requests:

| Header         | Description                                      |
|:---------------|:-------------------------------------------------|
| `apikey`       | The API key generated from the AppSentinel console. |
| `x-user-key`   | The user key associated with the API key.         |

### Cortex XSIAM side

To configure the data collection in Cortex XSIAM:

1. Navigate to **Settings** → **Data Sources & Integrations** → **+ Add New**.
2. Search for **AppSentinels.ai**, hover over it and click **Add**.
3. When configuring the integration, set the following parameters:

    | Parameter      | Value                                                                                  |
    |:---------------|:---------------------------------------------------------------------------------------|
    | `API Key`      | Enter the API key generated in the AppSentinel console.                                |
    | `User key`     | Enter the user key associated with the API key.                                        |
    | `Organization` | Enter Organization name                                                                |

</~XSIAM>
