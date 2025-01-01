This is the Cisco ThousandEyes event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 1.0.0 of CiscoThousandEyes.

## Configure CiscoThousandEyes in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| User API Token | True |
| The maximum number of audit events per fetch. | False |
| The maximum number of alerts per fetch. | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Note:
>This API returns a list of activity log events **in the current account group**.
If user has permission View activity log for all users in account group the logs returned include events across all the account groups they belong to.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-thousandeyes-get-events

***
Gets events from Cisco ThousandEyes.

#### Base Command

`!cisco-thousandeyes-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional | 
| start_date | The start date from which to filter events. | Optional | 
| end_date | The end date to which to filter events. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
