Collects audit logs from Saviynt Enterprise Identity Cloud (EIC) using Analytics Runtime Control V2 (v5).

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Saviynt EIC Event Collector in Cortex

| Parameter | Description | Required |
| --- | --- | --- |
| Server URL | Base URL of the Saviynt EIC tenant the event collector should connect to. Example: `https://<tenant>.saviyntcloud.com`. | True |
| Username  |  | True |
| Password |  | True |
| Analytics Name | Name of the Analytics Runtime Control to query (for example `SIEMAuditLogs`). | True |
| Maximum number of events per fetch | Maximum number for events per fetch. Default is 50,000. |  |
| Events Fetch Interval | Time between fetch cycles. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from a Cortex XSIAM incident War Room, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### saviynt-eic-get-events

Manual command to fetch and optionally create events. This command is primarily intended for troubleshooting, as pushing events  may result in duplication and can impact API rate limits.

#### Base Command

`saviynt-eic-get-events`

#### Input

| Argument Name | Description | Required |
| --- | --- | --- |
| should_push_events | Set to true to create events in XSIAM; otherwise, the command only displays events. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of results to return (maximum 10,000 events). | Required |
| time_frame | Time frame in minutes to fetch events from. | Optional |
| offset | Offset for paging. | Optional |

#### Context Output

There is no context output for this command.
