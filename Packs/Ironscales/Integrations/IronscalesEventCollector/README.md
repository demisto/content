Use this integration to fetch email security incidents from IRONSCALES as XSIAM events.

## Configure IRONSCALES Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IRONSCALES Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://appapi.ironscales.com) | True |
    | API Key | True |
    | Company ID | True |
    | Scopes (e.g. "company.all") | True |
    | Maximum number of events per fetch | False |
    | First fetch | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ironscales-get-events

***
Gets events from IronScale.

#### Base Command

`ironscales-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.
