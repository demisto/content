Abnormal Security Event Collector integration for XSIAM.
This integration was integrated and tested with version 01 of Abnormal Security Event Collector

## Configure Abnormal Security Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Abnormal Security Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Token | True |
    | First fetch time interval | False |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the token, and connection.
## Commands
You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### abnormal-security-event-collector-get-events
***
Manual command to fetch events and display them.


#### Base Command

`abnormal-security-event-collector-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 


#### Context Output

There is no context output for this command.