This is the Cohesity Helios Event Collector integration for XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Cohesity Helios Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://helios.cohesity.com) |  | True |
| API Key | The API Key to use for connection | False |
| The maximum number of events per type. Default is 50000. | The collector pulls both Audit Logs and Alerts. This parameter sets the the maximum fetch number limit for each type. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cohesity-helios-get-events

***
Gets events from Cohesity Helios.

#### Base Command

`cohesity-helios-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it only displays them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 
| start_time | Specifies the start time of the alerts to be returned. | Required | 
| end_time | Specifies the end time of the alerts to be returned. Default is Now. | Required | 

#### Context Output

There is no context output for this command.