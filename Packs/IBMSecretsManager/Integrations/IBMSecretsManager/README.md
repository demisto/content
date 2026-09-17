IBM Secrets Manager is a centralized service to store, manage, and automate the lifecycle of secrets (API keys, passwords, TLS certificates, and arbitrary data), powered by HashiCorp Vault. This integration collects IBM Secrets Manager audit / Activity Tracker events (via IBM Cloud Logs) into Cortex XSIAM.

This integration was integrated and tested with the IBM Cloud Logs query API (v1).

## Configure IBM Secrets Manager in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cloud Logs Server URL | IBM Cloud Logs API base URL for audit collection, e.g. `https://{instance_guid}.api.{region}.logs.cloud.ibm.com`. | True |
| API Key | The IBM Cloud IAM API key. Exchanged for a short-lived Bearer token. | True |
| IAM URL | IAM token endpoint. Override only for non-default IAM environments. | False |
| Fetch events | Whether to fetch events. | False |
| The maximum number of events per fetch | The maximum number of events to fetch per cycle from IBM Cloud Logs. | False |
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
| should_push_events | If true, the fetched events are sent to Cortex XSIAM. If false, only displayed. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of events to return. Default is 50. | Optional |

#### Context Output

There is no context output for this command.
