Palo Alto Networks Trend Micro Email Security Event Collector integration for XSIAM.

## Configure Trend Micro Email Security Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service URL |  | True |
| USER NAME |  | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Hide sensitive details from email |  | False |
| The maximum number of events per fetch. | The maximum number of events to fetch every time fetch is executed. | False |


**Note**: There are three types of events that the integration fetches, When the max fetch parameter is set to 1000 then 1000 logs will be retrieved from each type so that a total of 3000 logs can be retrieved.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### trend-micro-get-events

***
Manual command to fetch events and display them.

#### Base Command

`trend-micro-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_fetch | The maximum number of events to get. Default is 500. | Optional | 
| since | Occurrence time of the least recent event to include (inclusive). Default is 3 days. | Optional | 
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.