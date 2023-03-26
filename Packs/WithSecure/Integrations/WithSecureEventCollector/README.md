WithSecure event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 1.0 of WithSecure Event Collector

## Configure WithSecure Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WithSecure Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Client ID | Client ID and Client Secret. | True |
    | Client Secret |  | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Maximum number of events per fetch, Max 1000 |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### with-secure-get-events

***
Manual command used to fetch events and display them.

#### Base Command

`with-secure-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_from | The date to start collecting the events from. | Optional | 
| limit | The maximum amount of events to return. | Optional | 

#### Context Output

There is no context output for this command.
