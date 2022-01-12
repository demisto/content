#### Integration Author: Trend Micro
Support and maintenance for this integration are provided by the author. Please use the following contact details:
- **Email**: [integrations@trendmicro.com](mailto:integrations@trendmicro.com)
***
Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

## Obtaining Vision One API Credentials
Configuring the Trend Micro Vision One integration requires API credentials generated in Trend Micro Vision One. You can generate an API key to be used for the Cortex XSOAR integration by following these steps in Trend Micro Vision One.

1. Navigate to **Administration** > **Third-Party Integration**
2. Click on the **Trend Micro Vision One for Cortex XSOAR (XDR)** integration
3. Make note of both the **Endpoint URL** and the **Authentication token** as both will be used to configured the integration.

## Configure Vision One on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Vision One.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | Unique name for this Vision One instance | True |
| Fetch Incidents | Choose if the integration should sync incidents | True |
| Incident Type | Choose the "Trend Micro Vision One XDR Incident" type | True |
| API URL | Base URL for Vision One API | True |
| API Key | API token for authentication  | True |
| Incidents Fetch Interval (minutes) | How often do you want to check for new incidents | False |
| Sync On First Run (days) | How many days to go back during first sync | False |
| Max Incidents | Maximum Number of Workbenches to Retrieve | False |
4. Click **Test** to validate the URLs, token, and connection.

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/trend-micro-vision-one)