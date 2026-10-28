<~XSIAM>

## Overview

iManage Threat Manager is an AI-driven security solution for knowledge work platforms that uses machine learning and user behavior analytics to detect unusual user behavior, prevent data loss, and ensure compliance. It protects privileged information against internal and external threat actors through behavioral modeling, alerts, and automated responses.
This pack enables the normalization of iManage Threat Manager data ingested into Cortex XSIAM via API-based collection.
The normalized data can then be queried and used for investigation and analysis in Cortex XSIAM.

## This pack includes

Data normalization capabilities:

* Rules for modeling iManage Threat Manager logs that are ingested via the API into Cortex XSIAM.
* The ingested iManage Threat Manager logs can be queried in XQL Search using the *`imanage_threat_raw`* dataset.

## Supported Event Types

This pack normalizes the following iManage Threat Manager alert types:

* **Behavior Analytics alerts** - Anomaly alerts produced by user behavior analytics (e.g., anomalous activity across users or privileged accounts).
* **Addressable Alerts** - Alerts from the Detect and Protect module.
* **Detect And Protect Alerts** - Alerts that include the protective action taken on the user or account.

## Data Collection

### iManage Threat Manager side

The integration supports two authentication methods, depending on the alert types being fetched.

#### Application Token Authentication (for Behavior Analytics alerts)

To generate an application token and secret from the Threat Manager admin console:

1. In iManage Threat Manager, browse to **Configuration** > **System** > **Application Tokens for Utility Access**.
2. Select **New Token**. The New Token dialog opens.
3. In the **Token Name** field, enter a unique name for this application token.
4. Select the **Export Alert List** permission.
5. In **Token Expiry Time in minutes**, enter the number of minutes before this token becomes invalid.
   * By default, application tokens expire after 1400 minutes (1 day). The maximum value is 525600 (365 days).
6. Select **Generate Token**. The **New Token** dialog shows the generated application token and secret.

**Note:** The Integrations Manager role is required to generate an application token. If a user with the Integration Manager role is made inactive or the role is removed, all existing application tokens created by that user become inactive.

#### User Sign-in Authentication (for Addressable Alerts and Detect And Protect Alerts)

Use your iManage Threat Manager username and password. This provides a similar level of access to what the user would have in the admin console.

**Important:** These alert types cannot be accessed through application token authentication and require user credentials.

### Cortex XSIAM side - API

Configure the integration in Cortex XSIAM using the following parameters.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Should be in format https://&lt;your-instance&gt;.tm-cloudimanage.com | True |
| User Name | Username for user sign-in authentication. Required for Addressable Alerts and Detect And Protect Alerts. | Conditional |
| Password | Password for user sign-in authentication. Required for Addressable Alerts and Detect And Protect Alerts. | Conditional |
| Token | Application token for API token authentication. Required for Behavior Analytics alerts. | Conditional |
| Secret | Application secret for API token authentication. Required for Behavior Analytics alerts. | Conditional |
| Fetch events | Whether to fetch events. | False |
| Event types to fetch | Select which event types to fetch: Behavior Analytics alerts, Addressable Alerts, Detect And Protect Alerts. Default is Behavior Analytics alerts. | False |
| Maximum number of events per type | Default and maximum is 900 events to fetch for each type. | False |
| Trust any certificate (not secure) | Use SSL secure connection or not. | False |
| Use system proxy settings | Use proxy settings for connection or not. | False |

## Additional Information

* **Timezone:** All timestamps are in UTC.

</~XSIAM>
