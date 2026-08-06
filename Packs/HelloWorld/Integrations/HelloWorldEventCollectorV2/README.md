This is the Hello World event collector integration for Cortex XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure HelloWorld Event Collector V2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of the Hello World service. | False |
| Fetch alerts with status (ACTIVE, CLOSED) | The alert status to filter the fetched events by. | False |
| Max number of events per fetch | The maximum number of events to fetch per cycle. | False |
| Trust any certificate (not secure) | Whether to trust any certificate (not secure). | False |
| Use system proxy settings | Whether to use the system proxy settings. | False |

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### hello-world-get-events

***
Gets events from Hello World. This command is used for developing and debugging. It is not part of the automatic events fetch cycle.

#### Base Command

`hello-world-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Whether to create events. If "false", the command will only display them. Possible values are: true, false. Default is false. | Required |
| status | The alert status to filter the events by. Possible values are: ACTIVE, CLOSED. | Optional |
| limit | The maximum number of results to return. | Required |
| from_date | The date from which to get events. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!hello-world-get-events limit=1 should_push_events=false```
