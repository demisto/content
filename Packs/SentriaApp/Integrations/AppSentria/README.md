This is the Hello World integration for getting started.
## Configure App Sentria in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://api.xsoar-example.com) | True |
| Fetch incidents | False |
| Incident type | False |
| API Key | True |
| Incidents Fetch Interval | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### app-sentria-send-info

***

#### Base Command

`app-sentria-send-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Prioridad | No description provided. | Optional | 
| freshdeskticketstatus | No description provided. | Optional | 
| freshdeskticketagente | No description provided. | Optional | 
| freshdeskticketsubcategria | No description provided. | Optional | 
| freshdeskticketsoluciondelcaso | No description provided. | Optional | 
| id | No description provided. | Optional | 
| freshdeskticketusuarios | No description provided. | Optional | 
| freshdeskticketsistemas | No description provided. | Optional | 
| freshdeskticketpersistencia | No description provided. | Optional | 
| freshdeskticketobjetivos | No description provided. | Optional | 
| freshdeskticketttps | No description provided. | Optional | 
| freshdeskticketqueestamoshaciendo | No description provided. | Optional | 
| freshdeskticketquenecesitamoshacer | No description provided. | Optional | 
| freshdeskticketestadocierre | No description provided. | Optional | 
| freshdesktickettags | No description provided. | Optional | 
| Created | No description provided. | Optional | 
| analystassignmentsla1_totalDuration | No description provided. | Optional | 
| level2escalationsla2_totalDuration | No description provided. | Optional | 
| customerescalationsla3_totalDuration | No description provided. | Optional | 
| closingsla4_totalDuration | No description provided. | Optional | 
| name | No description provided. | Optional | 
| Product | No description provided. | Optional | 
| client | No description provided. | Optional | 
| case_url | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### app-sentria-send-message

***

#### Base Command

`app-sentria-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sentriaappactionclient | No description provided. | Optional | 
| sentriaappactionmsg | No description provided. | Optional | 
| sentriaappincidentid | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### app-sentria-send-msg-to-chat

***

#### Base Command

`app-sentria-send-msg-to-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sentriaappclient | No description provided. | Optional | 
| sentriaappmsg | No description provided. | Optional | 
| sentriaappincidentid | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### app-sentria-send-request-status

***

#### Base Command

`app-sentria-send-request-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | No description provided. | Optional | 
| sentriaappinternalcaseid | No description provided. | Optional | 
| data | No description provided. Default is {}. | Optional | 

#### Context Output

There is no context output for this command.
