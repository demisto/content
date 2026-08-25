This is the GitGuardian event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 1.0.0 of GitGuardianEventCollector.

## Configure GitGuardian Event Collector in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | False |
| Deployment type | False |
| API key | True |
| Max number of events per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

The **Deployment type** parameter selects which GitGuardian API shape the collector uses:

- **Enterprise** (default): for self-hosted deployments. The API is served under `/api/v1` and incidents are fetched from `/api/v1/secrets`.
- **SaaS**: for the GitGuardian SaaS deployment (for example `https://api.gitguardian.com`). The API is served under `/v1` and incidents are fetched from `/v1/incidents/secrets`.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gitguardian-get-events

***
Gets events from GitGuardian.

#### Base Command

`gitguardian-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of results to return. | Required |
| from_date | Date from which to get events. | Optional |

#### Context Output

There is no context output for this command.
