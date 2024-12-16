This is the GitGuardian event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 1.0.0 of GitGuardianEventCollector.

## Configure GitGuardian Event Collector in Cortex


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