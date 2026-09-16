Collects the events log for authentication and Audit provided by Okta admin API

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Okta Log in Cortex

| **Parameter**                                                           | **Description**                                                                           | **Required** |
|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|--------------|
| Server URL                                                              | Okta URL (https://yourdomain.okta.com)                                                    | True         |
| Number of incidents to fetch per fetch                                  | The total number of incidents to retrieve in each fetch cycle                             | True         |
| proxy                                                                   | Use system proxy settings                                                                 | False        |
| API key                                                                 | The request API key                                                                       | True         |
| First fetch time interval                                               | The period (in days) to retrieve events from, if no time is saved in the system           | True         |
| Fetch events                                                            | Whether to fetch events from Okta                                                         | False        |
| Events Fetch Interval                                                   | The interval (in minutes) between fetch cycles                                            | False        |

## Commands

You can execute these commands in a playbook.

### okta-get-events

***
Manual command to fetch events and display them. Use for development and debugging only, as it may produce duplicate events or disrupt the fetch mechanism.

#### Base Command

`okta-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required |
| start_time | The start time from which to retrieve events. Supports relative time (for example, "5 minutes ago", "3 days ago") or ISO 8601 (for example, "2026-01-01T10:00:00Z"). Default is 5 minutes ago. | Optional |
| end_time | The end time until which to retrieve events. Supports relative time (for example, "1 hour ago") or ISO 8601 (for example, "2026-01-01T12:00:00Z"). Defaults to the present moment. | Optional |
| limit | The maximum number of events to retrieve. Defaults to the instance level limit. | Optional |
| from_date | Deprecated. Use the start_time argument instead. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Event.uuid | String | Unique identifier of the event. |
| Okta.Event.published | Date | Timestamp when the event was published. |
| Okta.Event.eventType | String | The type of the event. |
| Okta.Event.displayMessage | String | Human readable description of the event. |
| Okta.Event.severity | String | The severity of the event. |
