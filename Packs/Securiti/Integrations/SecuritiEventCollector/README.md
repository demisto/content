## Securiti Event Collector

Use this integration to collect audit trail events from Securiti into Cortex XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

### Configuration

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| API Secret | True |
| Tenant Identifier | True |
| Fetch Events | False |
| The maximum number of events per fetch | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

### Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.

#### securiti-get-events

Gets audit trail events from Securiti. This command is intended for manual fetching and debugging.

##### Required Permissions

API Key with appropriate permissions in Securiti.

##### Base Command

`securiti-get-events`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Default is false. | Required |
| limit | Maximum number of results to return. Default is 50. | Optional |
| from_date | Date from which to get events (e.g., 2021-04-20T15:00:00Z or "3 days"). | Optional |

##### Context Output

There is no context output for this command.

##### Human Readable Output

A table of audit trail events with the following columns:

- id
- event_time
- activity_type
- object_type
- user_email
- message
- ip_address
