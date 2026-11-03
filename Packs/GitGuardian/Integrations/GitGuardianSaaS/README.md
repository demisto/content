Collect secret incidents and audit logs from the GitGuardian SaaS platform. GitGuardian is a developer-first solution that scans source-control activity in real time for leaked secrets (API tokens, database credentials, certificates).

This integration uses the GitGuardian v1.1 API. For GitGuardian Enterprise (`enterprise.gitguardian.com`), use the **GitGuardian Enterprise** integration.

## Configure GitGuardian SaaS in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | US region: `https://api.gitguardian.com`. EU region: `https://api.eu1.gitguardian.com`. A trailing `/v1` is optional. | False |
| API Key | Service Account token (recommended) or Personal Access Token with the `incidents:read` and `audit_logs:read` scopes. | True |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |
| Fetch events | | False |
| Event types | The event types to collect: Secret Incidents, Audit Logs. Default is both. | False |
| The maximum number of events per fetch per type |  Default is 1000. | False |

## Fetch Events

- The event types are collected concurrently. A failure in one event type does not stop the others.
- The first fetch collects events from the last hour.
- Each fetch collects events up to 1 minute before the current time, so events that the API indexes with a short delay are not missed.
- Events are filtered by the API `date` field (`date_after` / `date_before`). For secret incidents, `_ENTRY_STATUS` is `new` when `date` equals `triggered_at`, and `updated` otherwise. Audit logs are always `new`.
- If a saved pagination cursor is rejected by the API, the fetch restarts from the start of the current window. Some events may be collected again in this case.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gitguardian-saas-get-events

***
Retrieves GitGuardian SaaS secret incidents and audit logs. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`gitguardian-saas-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events. Otherwise, it only displays them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of events to return per event type. Default is 10. | Optional |
| start_date | The date from which to get events, in ISO-8601 format or as a relative time (e.g., "3 days ago", "2024-01-01T00:00:00Z"). Default is 1 hour ago. | Optional |
| event_types | A comma-separated list of event types to get. Default is the event types configured in the instance. Possible values are: Secret Incidents, Audit Logs. | Optional |

#### Context Output

There is no context output for this command.
