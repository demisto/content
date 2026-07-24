Fetches malicious Cisco Email Threat Defense (ETD) email logs and creates incidents in Cortex XSOAR.
This integration was integrated and tested with Cisco Email Threat Defense (ETD).

## Configure the Integration in Cortex XSOAR

1. Navigate to **Settings** → **Integrations** → **Servers & Services**.
2. Search for **Cisco Email Threat Defense (ETD)**.
3. Click **Add instance**.
4. Configure the following parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| ETD Base URL | Yes | Base URL of your Cisco Email Threat Defense (ETD) tenant. |
| API Key | Yes | API key used to authenticate API requests. |
| Client ID | Yes | OAuth client identifier. |
| Client Secret | Yes | OAuth client secret. |
| Use system proxy settings | No | Use the proxy configured on the Cortex XSOAR server. |
| Trust any certificate (not secure) | No | Disable SSL certificate validation. Enable only for testing or trusted environments. |
| First Fetch Time | No | Time from which incidents are fetched during the initial execution. Default is **3 days**. |
| Fetch incidents | Yes | Enables automatic fetching of ETD message events. |
| Incident Fetch Interval | Yes | Polling interval, in minutes, used to fetch new incidents. Default is **60**. |
| Incident Type | No | Incident type assigned to fetched incidents. |
| Max Fetch | No | Maximum number of incidents to fetch per polling cycle. Default is **100**. |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### etd-move-message

***
Reclassifies and remediates an ETD message.

#### Base Command

`etd-move-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The ETD message ID. | Required |
| verdict | The new verdict. | Required |
| folder | The new folder action. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ETD.Message.ID | String | The message ID. |
| ETD.Message.Verdict | String | The updated verdict. |
| ETD.Message.Folder | String | The updated folder. |
