Fetch Audit logs and APM events from Dynatrace Platform
This integration was integrated and tested with version xx of Dynatrace.

## Configure Dynatrace in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Access Token | False |
| Event types to fetch | True |
| The maximum number of audit logs events per fetch |  |
| The maximum number of APM events per fetch |  |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dynatrace-get-events

***
Manual command to fetch events and display them.

#### Base Command

`dynatrace-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| events_types_to_get | comma separated list of events types to get. Possible values are: Audit logs, APM. | Required | 
| audit_from | The start date for searching audit_logs events. The date can be provided in three formats- Timestamp in UTC milliseconds, Human-readable format in the following format- 2021-01-25T05:57:01.123+01:00 or relative timeframe using the format now-NU/A. For more information, please refer to https://docs.dynatrace.com/docs/discover-dynatrace/references/dynatrace-api/environment-api/events-v2/get-events for more information. | Optional | 
| apm_from | The start date for searching apm events. The date can be provided in three formats- Timestamp in UTC milliseconds, Human-readable format in the following format- 2021-01-25T05:57:01.123+01:00 or relative timeframe using the format now-NU/A. For more information, please refer to https://docs.dynatrace.com/docs/discover-dynatrace/references/dynatrace-api/environment-api/audit-logs/get-log for more information. | Optional | 
| audit_limit | Number of audit_logs events to fetch. Default is 1. | Optional | 
| apm_limit | Number of apm events to fetch. Default is 1. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

There is no context output for this command.
