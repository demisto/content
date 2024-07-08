This is the Cisco AMP event collector integration for Cortex XSIAM.
This integration was integrated and tested with version v1 of CiscoAMPEventCollector.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Cisco AMP Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco AMP Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                           | **Required** |
    |-----------------------------------------| --- |
    | Server URL (e.g., https://some_url.com) | True |
    | Client ID                               | True |
    | API Key                                 | True |
    | Max events number per fetch             | False |
    | Trust any certificate (not secure)      | False |
    | Use system proxy settings               | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-amp-get-events

***
Gets events from Cisco AMP.

#### Base Command

`cisco-amp-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| max_events_per_fetch | Maximum results to return. | Required | 
| from_date | From date to get events from. | Optional | 

#### Context Output

There is no context output for this command.
