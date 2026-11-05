Demo event collector for Cortex XSIAM that generates synthetic AcmeDemo audit log events locally. No network calls are made, and any non-empty API key works.

Events are pushed to the `acmedemo_auditlogs_raw` dataset.

## Configure AcmeDemo AuditLogs Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The AcmeDemo server URL. Default is `https://api.acmedemo.example.com`. It is not contacted. | True |
| API Key | Any non-empty value. | True |
| First fetch time | How far back to generate events on the first fetch, for example `3 days`. Default is `3 days`. | False |
| Maximum number of events per fetch | Default is `1000`. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### acmedemo-get-events

***
Gets synthetic audit events from AcmeDemo. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command

`acmedemo-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of events to return. Default is 10. | Optional |
| start_time | The time from which to get events. Supports free text such as "3 days" or an ISO 8601 timestamp. Default is 3 days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AcmeDemo.Event.id | String | The event ID. |
| AcmeDemo.Event.created_time | Date | The event creation time. |
| AcmeDemo.Event.event_type | String | The event type. |
| AcmeDemo.Event.outcome | String | The event outcome. |
| AcmeDemo.Event.severity | String | The event severity. |
| AcmeDemo.Event.message | String | The event message. |
| AcmeDemo.Event.source_ip | String | The source IP address of the event. |
| AcmeDemo.Event.user_agent | String | The user agent of the event. |
| AcmeDemo.Event.user.id | String | The ID of the user who performed the action. |
| AcmeDemo.Event.user.name | String | The name of the user who performed the action. |
| AcmeDemo.Event.user.email | String | The email of the user who performed the action. |
| AcmeDemo.Event.target.type | String | The type of the target resource. |
| AcmeDemo.Event.target.name | String | The name of the target resource. |

#### Command example

```!acmedemo-get-events should_push_events=false limit=5```

#### Context Example

```json
{
    "AcmeDemo": {
        "Event": [
            {
                "id": "3b8f6c1e-2d4a-5f7b-9c0d-1e2f3a4b5c6d",
                "created_time": "2026-01-01T11:01:00Z",
                "event_type": "login",
                "outcome": "success",
                "severity": "low",
                "message": "User alice performed login on application acmedemo-console (success)",
                "source_ip": "198.51.100.23",
                "user_agent": "AcmeDemoCLI/2.3.1 (linux; amd64)",
                "user": {
                    "id": "u-1001",
                    "name": "alice",
                    "email": "alice@acmedemo.example.com"
                },
                "target": {
                    "type": "application",
                    "name": "acmedemo-console"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### AcmeDemo Audit Events
>|Id|Created Time|Event Type|Outcome|User|Source Ip|User Agent|Target|Severity|Message|
>|---|---|---|---|---|---|---|---|---|---|
>| 3b8f6c1e-2d4a-5f7b-9c0d-1e2f3a4b5c6d | 2026-01-01T11:01:00Z | login | success | id: u-1001<br>name: alice<br>email: alice@acmedemo.example.com | 198.51.100.23 | AcmeDemoCLI/2.3.1 (linux; amd64) | type: application<br>name: acmedemo-console | low | User alice performed login on application acmedemo-console (success) |
