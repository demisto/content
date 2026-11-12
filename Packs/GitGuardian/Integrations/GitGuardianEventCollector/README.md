This is the GitGuardian Enterprise event collector integration for Cortex XSIAM.
For the GitGuardian SaaS platform, use the **GitGuardian SaaS** integration.

## Configure GitGuardian Enterprise in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | False |
| API key | True |
| Max number of events per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

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
