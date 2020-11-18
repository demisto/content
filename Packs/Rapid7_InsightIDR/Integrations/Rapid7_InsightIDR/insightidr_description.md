#Rapid7 InsightIDR: Cloud-based SIEM 
##Authentication
Before you start, make sure that you have an API key with Read/Write privileges.

This integration was integrated and tested with version xx of insightidr
## Configure insightidr on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for insightidr.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| region | Insight cloud server region \(i.e eu\) | True |
| apiKey | InsightIDR API key | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.