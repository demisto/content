This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Citrix Cloud Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Client Id |  | True |
| Client Secret |  | True |
| Customer ID |  | True |
| Max events per fetch | The maximum amount of events to retrieve. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### citrix-cloud-get-events

***
Returns system log events extracted from Citrix.

#### Base Command

`citrix-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| limit | The maximum number of logs to return. Default is 2000. | Optional | 
| start_date_time | Start DateTime for the records to be retrieved. | Optional | 
| end_date_time | End DateTime for the records to be retrieved. | Optional | 

#### Context Output

There is no context output for this command.