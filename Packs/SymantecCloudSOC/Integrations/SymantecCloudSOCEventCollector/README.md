Gets Events from Symantec CloudSOC.
This integration was integrated and tested with version 3.157 of Symantec CloudSOC.

## Configure Symantec Cloud SOC Event Collector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., <https://api.elastica.net/casb/>) | True |
| Key ID | True |
| Key Secret | True |
| First fetch time | False |
| Maximum number of incidents per fetch | False |



Symantec CloudSOC Event Collector collects the following event types:
* Investigate logs
* Detect incidents logs
  
### API Limitations
  You cannot retrieve investigate logs that are older than 180 days. Therefore, if setting a first fetch that is more than 180 days, for investigate logs it will be a maximum of 180 days.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### symantec-cloudsoc-get-events

***
Gets events from Symantec CloudSOC.

#### Base Command

`symantec-cloudsoc-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. Default is 1000. | Optional | 

#### Context Output

There is no context output for this command.