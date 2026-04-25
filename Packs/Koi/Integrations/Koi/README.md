## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### koi-get-events

***
Gets events from KOI. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and API request limitation exceeding.

#### Base Command

`koi-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | The type of events to retrieve. If not specified, uses the value configured in the integration parameters. Possible values are: Alerts, Audit. Default is Alerts,Audit. | Optional |
| limit | The maximum number of events to return per type. Default is 50. | Optional |
| start_time | Filter events created at or after this time. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | Filter events created at or before this time. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| should_push_events | If true, the command creates events in XSIAM; otherwise, it only displays them. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KOI.Event.id | String | The unique identifier of the event. |
| KOI.Event.source_log_type | String | The source log type of the event (Alerts or Audit). |
| KOI.Event._time | Date | The timestamp of the event in ISO 8601 format. |
| KOI.Event.created_at | Date | The creation time of the event (audit logs). |

#### Human Readable Output

>### KOI Events
>
>|id|source_log_type|_time|severity|status|
>|---|---|---|---|---|
>| alert-001 | Alerts | 2024-01-01T00:00:00Z | high | open |
>| audit-001 | Audit | 2024-01-01T00:00:00Z | | |
