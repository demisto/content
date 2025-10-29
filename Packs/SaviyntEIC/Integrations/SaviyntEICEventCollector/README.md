Collector for Saviynt Enterprise Identity Cloud (EIC) audit logs using Analytics Runtime Control V2.
This integration was tested with Saviynt EIC [API Reference for Amsterdam GA Release](https://documenter.getpostman.com/view/40843358/2sAYdctCto) (API v5).

## Configure Saviynt EIC Event Collector in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| Password | True |
| Analytics Name | True |
| Maximum number of events per fetch | False |
| Trust any certificate (not secure) | False |
| Events Fetch Interval | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### saviynt-eic-get-events

***
Gets events from Saviynt EIC.

#### Base Command

`saviynt-eic-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events, otherwise, it only displays them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum number of results to return (max 10000). | Required |
| time_frame | Time frame in minutes back from now to query. | Optional |
| offset | Offset for paging. | Optional |

#### Context Output

There is no context output for this command.
