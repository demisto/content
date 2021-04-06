Alert and notify users using iLert
This integration was integrated and tested with version xx of iLert
## Configure iLert on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for iLert.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | The API key of the alert source (for triggering events only) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iLert-submit-event
***
Creates a new event/incident in iLert (In order to use this command  you have to enter the Integration Key in the integration settings)


#### Base Command

`iLert-submit-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integrationKey | The API key of the alert source. | Optional | 
| incidentKey | For ALERT events, the incident key can be used to deduplicate or group events. If an open incident with the key already exists, the event will be appended to the incident's event log. Otherwise a new incident will be created. For ACCEPT and RESOLVE events, the incident key is used to reference the open incident which is to be accepted or resolved by this event. | Optional | 
| eventType | Must be either ALERT, ACCEPT, or RESOLVE. Default is ALERT. | Optional | 
| summary | The event summary. Will be used as the incident summary if a new incident is created. | Optional | 
| details | The event details. Will be used as the incident details if a new incident is created. | Optional | 
| priority | Must be either HIGH or LOW. Will overwrite the evaluated priority of the alert source. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iLert.Event.incidentKey | string | Incident key | 
| iLert.Event.incidentUrl | unknown | Incident Url | 
| iLert.Event.responseCode | unknown | Response code | 


#### Command Example
``` ```

#### Human Readable Output



### iLert-acknowledge-event
***
Acknowledges an existing event in iLert


#### Base Command

`iLert-acknowledge-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IntegrationKey | The API key of the alert source. | Optional | 
| incidentKey | The incident key is used to reference the open incident which is to be accepted or resolved by this event. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iLert.Event.incidentKey | unknown | Incident key | 
| iLert.Event.incidentUrl | unknown | Incident Url | 
| iLert.Event.responseCode | unknown | Response code | 


#### Command Example
``` ```

#### Human Readable Output



### iLert-resolve-event
***
Resolves an existing event in iLert


#### Base Command

`iLert-resolve-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IntegrationKey | The API key of the alert source. | Optional | 
| incidentKey | The incident key is used to reference the open incident which is to be accepted or resolved by this event. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iLert.Event.incidentKey | unknown | Incident key | 
| iLert.Event.incidentUrl | unknown | Incident Url | 
| iLert.Event.responseCode | unknown | Response code | 


#### Command Example
``` ```

#### Human Readable Output


