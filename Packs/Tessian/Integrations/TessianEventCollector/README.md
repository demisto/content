Collects security events from Proofpoint Tessian for Cortex XSIAM ingestion.
This integration was integrated and tested with version xx of TessianEventCollector.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Tessian Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Proofpoint Tessian portal URL \(for example, https://\[subdomain\].tessian-platform.com or https://\[subdomain\].tessian-app.com\). | True |
| API Token | The API Token generated in the Proofpoint Portal under Integrations &amp;gt; Security Integrations &amp;gt; Proofpoint API. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch events |  | False |
| Maximum number of security events per fetch | The maximum number of security events to fetch per cycle. Each cycle makes up to 10 API calls of 100 events each. | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tessian-get-events

***
Retrieves security events from Proofpoint Tessian. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`tessian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return. Maximum is 1000. | Optional |
| created_after | The time after which to include events. Accepts an ISO 8601 timestamp (for example, 2024-01-01T00:00:00Z) or a relative time (for example, 3 days). | Optional |
| should_push_events | Whether to create events in Cortex XSIAM. If true, the command creates events; otherwise, it only displays them. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.
