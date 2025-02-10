Celonis Event Collector is an integration that supports fetching audit log events.
This integration was integrated and tested with version 4.0 of Celonis.

## Configure Celonis in Cortex


| **Parameter** | **Description**                                                                                                                    | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------| --- |
| Server URL | The endpoint URL is constructed using the team name and realm in the format: https://&lt;teamname&gt;.&lt;realm&gt;.celonis.cloud. | True |
| Server URL | The endpoint URL is constructed using the team name and realm in the format: https://&lt;teamname&gt;.&lt;realm&gt;.celonis.cloud. | True |
| Client ID | The Client ID to use for connection.                                                                                               | True |
| Client Secret | The Client Secret to use for connection.                                                                                           | True |
| Trust any certificate (not secure) |                                                                                                                                    | False |
| Use system proxy settings |                                                                                                                                    | False |
| Maximum number of events per fetch | Defines the maximum number of audits events per fetch cycle. Default value: 600.                                                   | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### celonis-get-events

***
Retrieves a list of audit logs events from the Celonis instance.

#### Base Command

`celonis-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of events to return. | Required | 
| start_date | The starting date from which events should be fetched. The date should be in the format "YYYY-MM-DDTHH:MM:SS.sssZ". Example: 2025-02-04T10:33:24.647Z. | Required | 
| end_date | The date up to which events should be fetched. The date should be in the format "YYYY-MM-DDTHH:MM:SS.sssZ". Example: 2025-02-04T10:33:24.647Z. | Required | 

#### Context Output

There is no context output for this command.


#### Command example
```!celonis-get-events should_push_events=false limit=10 end_date=2025-02-04T10:33:24.647Z start_date=2025-02-10T10:33:24.647Z```
