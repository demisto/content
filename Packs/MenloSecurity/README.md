<~XSIAM>

## Overview

The cloud-based Menlo Security Isolation Platform (MSIP) eliminates the possibility of malware reaching user devices via compromised or malicious web sites, email, or documents.
This pack enables the normalization of Menlo Security logs ingested into Cortex XSIAM via API-based collection.
The normalized data can then be queried and used for investigation and analysis in Cortex XSIAM.

## This pack includes

Data normalization capabilities:

* Rules for modeling Menlo Security Isolation Platform (MSIP) logs that are ingested via the API into Cortex XSIAM.
  * The ingested Menlo Security logs can be queried in XQL Search using the *`menlo_security_ip_raw`* dataset.

## Supported log categories

| Category    | Category Display Name      |
|:------------|:---------------------------|
| web         | Web access logs            |
| safemail    | Email URL rewriter logs    |
| audit       | Admin portal audit logs    |
| auth_flows  | Authentication flow logs   |
| smtp        | SMTP message logs          |
| attachment  | Email attachment logs      |
| bandwidth   | Bandwidth logs             |
| heat        | Threat intelligence alerts |
| firewall    | Firewall logs              |
| dlp         | Data loss prevention logs  |
| ms_client_logs | Menlo client logs       |

***

## Data Collection

### Cortex XSIAM side - API

To configure the Menlo Security integration in Cortex XSIAM:

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for **Menlo Security**.
3. Click **Add instance** to create and configure a new integration instance.

    | Parameter | Description | Required |
    | --- | --- | --- |
    | Server URL | The Menlo Security logging API base URL. Default: `https://logs.menlosecurity.com` | True |
    | Auth Token | The API authentication token with Log Export API permission. | True |
    | Token type | Select `Admin Token` (default) for tokens generated from the Admin UI (uses the v2 API). Select `Token` for legacy tokens (uses the v1 API). | True |
    | Log types | The log types to collect. Select one or more from: `web`, `safemail`, `audit`, `auth_flows`, `smtp`, `attachment`, `bandwidth`, `heat`, `firewall`, `dlp`, `ms_client_logs`. All log types are selected by default. Note: `heat` replaces the deprecated `isoc` log type. | True |
    | Fetch events | Enable event fetching. | False |
    | Maximum number of events per fetch per log type | The maximum number of events to fetch per log type per fetch cycle. | False |
    | Trust any certificate (not secure) | Disable SSL certificate verification. | False |
    | Use system proxy settings | Use the system proxy for API requests. | False |

4. Click **Test** to validate the connection.

> **Note:** For tenants with extremely large event volumes, configure a separate integration instance per log type. Splitting the load across instances allows each instance to fetch its log type independently and in parallel, improving overall throughput.

### Menlo Security side

1. Sign in to the Menlo Security Admin Portal.
2. Generate an API token with the **Log Export API** permission.
3. Provide the token in the **Auth Token** parameter when configuring the integration on the Cortex XSIAM side.

For more information, see the [Menlo Security documentation](https://csportal.menlosecurity.com/hc/en-us).

</~XSIAM>
