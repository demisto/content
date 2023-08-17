Palo Alto Networks Symantec Cloud Secure Web Gateway Event Collector integration for XSIAM.

## Configure Symantec Cloud Secure Web Gateway Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Cloud Secure Web Gateway Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | User name | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### symantec-get-events

***
Manual command to fetch events and display them.

#### Base Command

`symantec-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Occurrence time of the least recent event to include (inclusive). Default is 3 hours. | Optional | 
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.
