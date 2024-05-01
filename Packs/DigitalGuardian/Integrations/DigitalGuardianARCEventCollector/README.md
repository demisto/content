This is the Digital Guardian ARC event collector integration for XSIAM.
This integration was integrated and tested with version 3.10.0 of DigitalGuardianARCEventCollector

## Known Limitations
The integration fetch interval should be set to a minimum of "1 hour". If set to less, a quota error might be received.

## Configure Digital Guardian ARC Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Digital Guardian ARC Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Auth Server URL (e.g. https://some_url.com) |  | True |
    | Gateway Base URL (e.g. https://some_url.com) |  | True |
    | Client ID |  | True |
    | Client Secret | Client Secret | True |
    | Export Profile |  | True |
    | First fetch time (Enter only number of days, integer) |  | False |
    | Number of events per fetch |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### digital-guardian-get-events

***
Gets events from Digital Guardian ARC product

#### Base Command

`digital-guardian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 
| days | Number of days to get data. Default is 7. | Optional | 

#### Context Output

There is no context output for this command.
