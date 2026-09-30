Use the Akamai Event Viewer integration to collect Control Center portal-visible events (such as configuration changes, login attempts, alert activity, and log deliveries) stored in the Akamai Event Logger system.
This integration uses version 1 of the Akamai Event Viewer API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Akamai Event Viewer in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The customer-specific EdgeGrid API host, e.g., https://akaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net. The /event-viewer-api/v1 base path is appended by the integration. | True |
| Client token |  | True |
| Access token |  | True |
| Client secret |  | True |
| Account switch key | For customers who manage more than one account. Runs the operation from another account. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Event Type Names | A comma-separated list of event type names to fetch \(for example, "All Logins,Alert Activity"\). Use "all" to fetch all event types. Up to 10 event types can be selected. | False |
| The maximum number of events per fetch | The maximum is 500. When multiple event types are selected, the limit is shared between them. | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### akamai-event-viewer-get-events

***
Gets events from Akamai Event Viewer. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

#### Base Command

`akamai-event-viewer-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return. Maximum is 500. Default is 50. | Optional |
| start_time | The start time to fetch events from (e.g., "3 days ago", "2026-01-01T00:00:00Z"). Default is 1 minute ago. | Optional |
| end_time | The end time to fetch events until (e.g., "now", "2026-01-01T00:00:00Z"). Default is now. | Optional |
| should_push_events | If true, the command creates events; otherwise, it only displays them. Possible values are: true, false. Default is false. | Required |

#### Context Output

There is no context output for this command.
