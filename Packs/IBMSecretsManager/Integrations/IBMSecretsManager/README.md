IBM Secrets Manager is a centralized service to store, manage, and automate the lifecycle of secrets (API keys, passwords, TLS certificates, and arbitrary data), powered by HashiCorp Vault. This integration collects IBM Secrets Manager audit / Activity Tracker events (via IBM Cloud Logs) into Cortex.

## Configure IBM Secrets Manager in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cloud Logs Server URL | IBM Cloud Logs API base URL for audit collection, e.g. `https://{instance_guid}.api.{region}.logs.cloud.ibm.com`. | True |
| API Key | The IBM Cloud IAM API key. Exchanged for a short-lived Bearer token. | True |
| IAM URL | IAM token endpoint. Override only for non-default IAM environments. | False |
| Fetch events | Whether to fetch events. | False |
| The maximum number of events per fetch | The page size (maximum results per IBM Cloud Logs /v1/query call). Each fetch cycle performs up to 10 calls, so the effective maximum number of events per fetch is this value multiplied by 10 (e.g. 50000 x 10 = 500,000). | False |
| Trust any certificate (not secure) | Whether to trust any certificate. | False |
| Use system proxy settings | Whether to use system proxy settings. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ibm-secrets-manager-get-events

***
Manual command to fetch events from IBM Secrets Manager and display them. Used mainly for debugging.

#### Base Command

`ibm-secrets-manager-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the fetched events are sent to Cortex. If false, only displayed. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of events to return. Default is 50. | Optional |
| start_date | The start of the time window to query (inclusive). Accepts an absolute date (e.g. 2026-07-13T00:00:00Z) or a relative time (e.g. 3 days). Defaults to one hour before end_date. | Optional |
| end_date | The end of the time window to query (exclusive). Accepts an absolute date (e.g. 2026-07-13T00:00:00Z) or a relative time (e.g. 1 hour). Defaults to now. | Optional |

#### Context Output

There is no context output for this command.
