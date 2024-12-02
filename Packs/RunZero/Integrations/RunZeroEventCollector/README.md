This is the RunZero event collector integration for XSIAM.
This integration was integrated and tested with version 3.3.0 of RunZero Event Collector

## Configure RunZero Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://console.runzero.com/) |  | True |
| Fetch incidents |  | False |
| Maximum number of incidents per fetch |  | False |
| Client secret | The client secret to access the service REST API. | True |
| Client id | The client ID as defined in RunZero. | True |
| First fetch time |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### runzero-get-events
***
Gets events from RunZero.


#### Base Command

`runzero-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 
| start_time | Filter by start time. <br/>Examples:<br/>  "3 days ago"<br/>  "1 month"<br/>  "2019-10-10T12:22:00"<br/>  "2019-10-10". | Optional | 


#### Context Output

There is no context output for this command.