This is the Druva event collector integration for Cortex XSIAM.
This integration was integrated and tested with version xx of DruvaEventCollector.

## Configure Druva Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Druva Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Client ID | True |
    | Secret Key | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### druva-get-events

***
Gets events from Druva API in one batch (max 500), if tracker is given, events will be returned from here.

#### Base Command

`druva-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| tracker | A pointer to the last event we received. | Optional | 

#### Context Output

There is no context output for this command.
