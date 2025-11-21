<~XSIAM>

## Overview

Lookout Mobile Endpoint Security is a comprehensive security solution that protects mobile devices from threats such as phishing, malware, network attacks, and device vulnerabilities. It leverages AI-driven threat intelligence to detect and prevent risks, ensuring secure access to corporate data while maintaining user privacy. The platform provides real-time risk assessments and integrates with enterprise security ecosystems to enhance overall mobile security posture.

This integration was integrated and tested with version v2 of Mobile Risk API.

## This Pack Includes

Data normalization capabilities:

* Modeling rule for mapping ingested Lookout Mobile Endpoint Security Threat, Audit, and Device logs.
* XQL search queries for the ingested Lookout Mobile Endpoint Security logs using the *`lookout_mobile_endpoint_security_raw`* dataset.

## Supported Log Categories

| Category | Category Display Name |
|:---------|:----------------------|
| Audit    | AUDIT                 |
| Threat   | THREAT                |
| Device   | DEVICE                |

***

## Data Collection

### Lookout Mobile Endpoint Security Side

Use the integration to automatically collect events from Lookout Mobile Endpoint Security (MES).

#### Creating an Application Key

You must create an application key specific to your Lookout Mobile Endpoint Security tenant to properly authenticate your application. You can do this from the [Lookout Mobile Endpoint Protection Console](https://api.lookout.com):

1. Log in to the Lookout Mobile Endpoint Security Protection console as an administrator.
2. In the left navigation bar, navigate to **System** > **Application Keys**.
*NOTE:* If you don’t see the **Application Keys** tab, contact Lookout Enterprise support to enable this feature on your tenant.
3. Click **GENERATE KEY**.
4. Enter a label name and click **Next**.
5. Copy the key from your clipboard into the configuration for your application.
    *IMPORTANT:* Immediately copy the generated key to your application since you cannot access the key again after completing this procedure.

### Cortex XSIAM Side

1. Navigate to **Settings** > **Configuration** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for **Lookout Mobile Endpoint Security** and click **Add Instance**.
3. Under **API Integration**, set the following values:

| **Parameter** | **Required** |
| --- | --- |
| Server URL | False |
| Application Key | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch interval in seconds | True |
| Event types to fetch | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

</~XSIAM>
