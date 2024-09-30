Deprecated. Use XSIAM/XDR Salesforce integration instead.

## Configure Salesforce Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Client ID |  | True |
| Client Secret |  | True |
| Username |  | True |
| Password |  | True |
| Query to get Hourly Event Log Files | For more information, visit the Query Hourly Event Log Files documentation https://developer.salesforce.com/docs/atlas.en-us.234.0.api_rest.meta/api_rest/event_log_file_hourly_query.htm | True |
| How many log files to fetch |  | True |
| First fetch time interval |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### salesforce-get-events

***
Manual command to fetch events.

#### Base Command

`salesforce-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| files_limit | The maximum number of log files to fetch. Default is 1. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 

#### Context Output

There is no context output for this command.