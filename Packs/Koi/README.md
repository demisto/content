# Koi

Koi is an endpoint security platform that provides visibility and control over browser extensions, SaaS applications, and web-based threats.

This pack includes the **Koi Event Collector** integration for Cortex XSIAM, which fetches alerts and audit logs from the Koi API.

<~XSIAM>

## Configuration

1. Navigate to **Settings** > **Data Sources & Integrations**.
2. Click **Add New** and search for **Koi Event Collector**.
3. Click **Add instance** and configure the required parameters.

| Parameter | Description | Required |
| --- | --- | --- |
| Server URL | The Koi API server URL. | True |
| API Key | The API key for authenticating with the Koi API. See the help section for instructions on creating an API key. | True |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |
| Fetch events | | False |
| Fetch event types | Select which event types to fetch from Koi. | True |
| Audit log type filter | Filter audit logs by type(s). If not specified, all audit log types will be fetched. | False |
| Maximum number of events per fetch | Maximum number of events to fetch per type per fetch cycle (default: 5000). | False |
| Events Fetch Interval | | False |

</~XSIAM>
