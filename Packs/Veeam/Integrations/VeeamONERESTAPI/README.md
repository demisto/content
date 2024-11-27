Veeam ONE REST API allows you to query information about Veeam ONE entities and perform operations with these entities using HTTP requests and standard HTTP methods.
This integration was integrated and tested with version 12.2.0 of Veeam ONE.

## Configure Veeam ONE REST API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username |  | True |
| Password |  | True |
| Resource URL |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| First fetch time |  | False |
| Triggered Alarms Per Request | The maximum number of triggered alarms that can be fetched during command execution. | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### veeam-vone-get-triggered-alarms

***
Get All Triggered Alarms

#### Base Command

`veeam-vone-get-triggered-alarms`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Offset | Number of first resources in the output that are excluded. | Optional | 
| Limit | Number of first resources in the output that are returned. Default is 100. | Optional | 
| Filter | Conditions that a resource must meet to be included in the output. | Optional | 
| Sort | Order in which resources are returned. | Optional | 
| Select | Property that must be explicitly returned in a response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Veeam.VONE.TriggeredAlarmInfoPage.items.triggeredAlarmId | Number | ID assigned to a triggered alarm. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.name | String | Name of an alarm template. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.alarmTemplateId | Number | ID assigned to an alarm template. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.predefinedAlarmId | Number | ID assigned to an alarm. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.triggeredTime | String | Date and time when an alarm triggered. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.description | String | Message containing alarm details. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.comment | String | Comment on a triggered alarm. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.repeatCount | Number | Number of times an alarm was triggered. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.childAlarmsCount | Number | Number of alarm child objects. | 
| Veeam.VONE.TriggeredAlarmInfoPage.items.remediation.description | String |  | 
| Veeam.VONE.TriggeredAlarmInfoPage.totalCount | Number |  | 

### veeam-vone-resolve-triggered-alarms

***
Resolve Triggered Alarms

#### Base Command

`veeam-vone-resolve-triggered-alarms`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| triggeredAlarmIds | List of IDs assigned to triggered alarms that you want to resolve. | Required | 
| comment | Additional information. | Required | 
| resolveType | Type of alarm resolution. | Required | 

#### Context Output

There is no context output for this command.