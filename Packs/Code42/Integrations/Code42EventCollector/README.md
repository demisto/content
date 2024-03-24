Code42 Insider Risk software solutions provide the right balance of transparency, technology and training to detect and appropriately respond to data risk. Use the Code42EventCollector integration to fetch file events and audit logs.


## Configure Code42EventCollector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Code42EventCollector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://api.us.code42.com, see help section) | True |
    | API Client ID | True |
    | API Client Secret | True |
    | Maximum number of file events per fetch | True |
    | Maximum number of audit events per fetch | True |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### code42-get-events

***
Manual command to get events, used mainly for debugging

#### Base Command

`code42-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | from which time to get events. | Required | 
| end_date | until which time to get events. | Required | 
| limit | the maximum number of events to return. Default is 100. | Required | 
| event_type | the type of event to return. Possible values are: audit-logs, file-events. | Required | 

#### Context Output

There is no context output for this command.
