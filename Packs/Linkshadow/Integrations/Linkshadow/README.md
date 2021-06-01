Configure Linkshadow on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Linkshadow
3. Click **Add instance** to create and configure a new integration instance.

To configure the connection to your Linkshadow instance, you will provide:

API Token, API Username from Linkshadow  ( Generate tokens from following url : https://Linkshadow-device-IP/settings/#general-settings ) under the "Generate API Key for LinkShadow" section)


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Use API Token  | True |
| url | Server URL \(e.g. https://Linkshadow_IP/) | True |
| API Username | Use API Username | True |
| action | fetch_entity_anomalies | True |
| plugin_id | xsoar_integration_1604211382 | True |
| TimeFrame | Minutes | True |
| Incidents Fetch Interval | 01 Minutes | Default |

4. Click **Test** to validate the URLs, token, and connection.


