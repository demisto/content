Collects security events from Proofpoint Tessian for Cortex XSIAM.

## Configure Tessian Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Proofpoint Tessian portal URL (e.g., https://\{subdomain\}.tessian-platform.com or https://\{subdomain\}.tessian-app.com). | True |
| API Token | API Token generated in the Proofpoint Portal under Integrations > Security Integrations > Proofpoint API. | True |
| Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | False |
| Trust any certificate (not secure) | When selected, certificates are not checked. | False |
| Fetch events | Whether to fetch events. | False |
| Maximum number of security events per fetch | Maximum number of security events to fetch per cycle. Each cycle makes up to 10 API calls of 100 events each (max 1000). | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tessian-get-events

***
This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and API request limitation exceeding.

#### Base Command

`tessian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return. Default is 100. Maximum is 1000. | Optional |
| created_after | Only include events created after this time. ISO 8601 format (e.g., 2024-01-01T00:00:00Z). | Optional |
| should_push_events | If true, the command creates events in XSIAM; otherwise, it only displays them. Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!tessian-get-events limit=10```

#### Human Readable Output

>### Tessian Security Events
>
>|Event ID|Type|Created At|Updated At|Entry Status|Portal Link|
>|---|---|---|---|---|---|
>| abc-123 | warning | 2024-01-01T00:00:00Z | 2024-01-01T00:00:00Z | new | https://example.tessian-platform.com/events/abc-123 |
