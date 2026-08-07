# Cisco ETD Connector

The Cisco ETD Connector enables Cortex XSIAM to ingest Cisco Email Threat Defense (ETD) logs for centralized monitoring, analytics, and threat investigation.

The integration retrieves Cisco ETD Message, Audit, and Connection logs and sends them to Cortex XSIAM for visualization, correlation, and alerting.

## Use Cases

- Email threat monitoring
- Security analytics
- SIEM correlation
- Email activity investigation
- Threat hunting and reporting

## Prerequisites

Before configuring the integration, ensure that the following requirements are met:

- Access to a Cisco Email Threat Defense (ETD) tenant
- Cisco ETD API credentials
- A Cortex XSIAM tenant with permissions to configure integrations

## Obtain Cisco ETD API Credentials

1. Sign in to the Cisco Email Threat Defense administration portal.
2. Navigate to the API access or application management section.
3. Create or locate an API application.
4. Record the following values:

- Client ID
- Client Secret
- API Key

These credentials are required when configuring the integration instance.

## Configure the Integration

1. Navigate to **Settings → Configurations → Integrations**.
2. Search for **Cisco ETD Connector**.
3. Click **Add Instance**.
4. Configure the following parameters:

- ETD API Base URL
- Client ID
- Client Secret
- API Key
- Event Type
- Max Fetch

5. Enable **Fetch Events**.
6. Click **Test** to verify connectivity.
7. Click **Save**.

After the integration is enabled, Cisco ETD logs are continuously collected and ingested into Cortex XSIAM for analysis and reporting.