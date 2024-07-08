The API Key client_id and client_secret can be obtained by an owner from the Admin Console vault by navigating to Settings → Organization info screen and scrolling down to the API key section.
This integration was integrated and tested with version xx of Bitwarden Password Manager Event Collector.

## Configure Bitwarden Password Manager Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Bitwarden Password Manager Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://example.bitwarden.com) | True |
    | Client ID | True |
    | Client Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Maximum number of events per fetch | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bitwarden-get-events

***
Gets events from Bitwarden.

#### Base Command

`bitwarden-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start date from which to filter events. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
