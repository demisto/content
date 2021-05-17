Linkshadow is a Next Generation Enterprise Security Analytics platform designed to manage threats in real-time with attacker behavior analytics, LinkShadow enhances organization's defenses against advanced cyber-attacks, zero-day malware and ransomware, while simultaneously gaining rapid insight into the effectiveness of their existing security investments. 

This integration was integrated and tested with version 4.5.8 of Linkshadow.
Enables LinkShadow to integrate with PaloAlto Cortex XSOAR Platform, It pushes Linkshadow Anomaly events to XSOAR to create a new Incident and trigger the relevant Playbook Actions.This pack includes configurations to combine the world-class threat detection of Linkshadow with the synchrony and automation abilities of XSOAR, allowing security teams to investigate and manage security events before they have time to escalate.

Gathers information about every anomaly detection made by the Linkshadow platform and populates it in XSOAR.

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
| **TimeFrame | 01 | True |
| **Incidents Fetch Interval | 01 Minutes | True |

4. Click **Test** to validate the URLs, token, and connection.

**Notes : The "TimeFrame" and "Incidents Fetch Interval" should be same as of now to avoid duplicate incidents.
