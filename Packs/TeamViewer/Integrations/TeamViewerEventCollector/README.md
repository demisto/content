TeamViewer event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 15.40 of TeamViewer.
User access token scope: Event logging - Allow requesting all event logs.
A Tensor license is required.

## Configure TeamViewer Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for TeamViewer Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Script Token | The script token to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | First fetch time |  | False |
    | The maximum number of alerts per fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### teamviewer-get-events

***
Gets events from TeamViewer.

#### Base Command

`teamviewer-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 

#### Context Output

There is no context output for this command.
