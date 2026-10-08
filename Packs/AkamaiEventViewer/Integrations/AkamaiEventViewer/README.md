Use the Akamai Event Viewer integration to collect Control Center portal-visible events (such as configuration changes, login attempts, alert activity, and log deliveries) stored in the Akamai Event Logger system.
This integration uses version 1 of the Akamai Event Viewer API. For more information, see the [Akamai Event Viewer API documentation](https://techdocs.akamai.com/event-viewer/reference/api-get-started).

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Prerequisites

Create Akamai EdgeGrid API credentials:

1. In Akamai Control Center, go to **Identity & Access Management** > **API clients**.
2. Create an API client with access to the **Event Viewer** API.
3. Save the **host**, **client token**, **access token**, and **client secret**. Use them to configure the integration instance.

## Configure Akamai Event Viewer in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The customer-specific EdgeGrid API host, e.g., <https://akaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net>. The /event-viewer-api/v1 base path is appended by the integration. | True |
| Client token | The EdgeGrid client token of the Akamai API client. | True |
| Access token | The EdgeGrid access token of the Akamai API client. | True |
| Client secret | The EdgeGrid client secret of the Akamai API client. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Account switch key | The account switch key for customers who manage more than one account. Runs the operation from another account. | False |
| Fetch events |  | False |
| Event Type Names | The comma-separated list of event type names to fetch \(for example, "All Logins,Alert Activity"\). Use "all" to fetch all event types. Up to 10 event types can be selected. | False |
| The maximum number of events per fetch | The maximum number of events to fetch per fetch cycle. The maximum is 500. When multiple event types are selected, the limit is shared between them. | False |
| Events Fetch Interval | The interval, in minutes, between fetch cycles. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### akamai-event-viewer-get-events

***
Gets events from Akamai Event Viewer. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`akamai-event-viewer-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return. The maximum is 500. Default is 50. | Optional |
| event_type | The comma-separated list of event type names to retrieve (for example, "All Logins,Alert Activity"). Use "all" to retrieve all event types. If not specified, the Event Type Names instance parameter is used. | Optional |
| start_time | The start time to retrieve events from (for example, "3 days ago" or "2026-01-01T00:00:00Z"). Default is 1 minute ago. | Optional |
| end_time | The end time to retrieve events until (for example, "now" or "2026-01-01T00:00:00Z"). Default is now. | Optional |
| should_push_events | Whether to create events (true) or only display them (false). Possible values are: true, false. Default is false. | Required |

#### Context Output

There is no context output for this command.
