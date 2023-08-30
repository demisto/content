Collects alerts & threat activities from Armis resources.
This integration was integrated and tested with API V.1.8 of Armis API.

## Configure Armis Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Armis Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | URL of the Armis instance the event collector should connect to. | True |
    | API Secret Key | The authorization token used for authentication of the Armis API. | True |
    | Number of events to fetch per type | The maximum number of events to fetch per event type. | False |
    | Trust any certificate (not secure) | When selected, certificates are not checked. | False |
    | Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
    | Event types to fetch | Define which event types to fetch. | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from an Cortex XSIAM incident War Room ,as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### armis-get-events

***
Manual command to fetch and display events.

#### Base Command

`armis-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required |
| from_date | The date from which to fetch events. the format should be YYYY-MM-DD. If not specified, the current date will be used. | Optional |

#### Context Output

There is no context output for this command.
