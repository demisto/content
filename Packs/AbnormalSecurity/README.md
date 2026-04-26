## Overview

Abnormal Security provides comprehensive defense against the entire landscape of messaging threats, ranging from high-sophistication Vendor Email Compromise (VEC) and targeted spear-phishing to lower-priority graymail and unsolicited spam.

To mitigate these advanced risks, the platform utilizes Behavioral Data Science to establish an identity-based baseline of legitimate communication patterns. By analyzing these established norms, Abnormal can identify and neutralize anomalous deviations and novel attack vectors that bypass traditional, signature-based security infrastructures.

The integration of Abnormal Security with Cortex XSIAM empowers security teams to respond to email threats with speed and dramatically reduces mean time to respond (MTTR). Threat data is ingested via the Abnormal Security REST API, enabling continuous visibility into detected threats, remediation status, and attack metadata directly within XSIAM.

## This pack includes

- Modeling rules for Cortex XSIAM Abnormal Security email threat logs.
- Abnormal Security REST API into Cortex XSIAM.
- Retrieving email threat campaign data using Cortex XSOAR / XSIAM.
- Retrieving email anomaly cases using Cortex XSOAR / XSIAM.

<~XSIAM>

## Supported log categories

| Category | Category Display Name |
|:---------|:----------------------|
| Email Threats | Abnormal Security Email Threat Detections |

## Data Collection

### Abnormal Security side

#### Step 1: Generate an Authentication Token

1. Log in to the [Abnormal Security Portal](https://portal.abnormalsecurity.com/home/settings/integrations).
2. Navigate to **Settings** → **Integrations** and click on **Abnormal REST API**.
3. Click **Generate Token** to create your authentication token.
4. Copy and securely store the token — it grants access to sensitive threat data related to your organization.

> **Security Note:** Keep the token safe. Store it in a secure location such as an encrypted password vault. Do not share it unless absolutely necessary. If you believe the token has been compromised, contact your Abnormal Security Account Manager immediately.

For more information, refer to the [Abnormal Security REST API documentation](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3).

### Cortex XSIAM side

To configure Cortex XSIAM to collect data from the Abnormal Security REST API:

1. Navigate to **Settings** → **Automation & Feed Integration**.
2. Search for **Abnormal Security** and select **Add instance**.
3. Set the following parameters:

    | Parameter | Value |
    |:----------|:------|
    | `Name` | Abnormal Security Email Protection |
    | `Token` | Enter the authentication token generated in Step 1 above (`{your_api_token}`) |

4. Click **Test** to Verify the connection.
5. Click **Save & Exit** to save the configuration.

For more information on configuring data sources in Cortex XSIAM, see the [Cortex XSIAM Data Sources documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Data-Sources).

</~XSIAM>
