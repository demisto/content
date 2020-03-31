## Overview
---

Allow integration with Zabbix api
This integration was integrated and tested with version xx of Zabbix
## Zabbix Playbook
---

## Use Cases
---

## Configure Zabbix on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Zabbix.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Url__
    * __Credentials__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. execute_command
### 1. execute_command
---
Execute command on Zabbix API
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`execute_command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | Method to call on Zabbix API | Required | 
| params | JSON with params to send with call | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| result | Unknown | result | 


##### Command Example
``` ```

##### Human Readable Output


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* "Unknown command"

