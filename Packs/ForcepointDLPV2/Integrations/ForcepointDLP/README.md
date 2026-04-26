Forcepoint DLP 10.2 REST API Cortex XSOAR Entegrasyonu.
## Configure Forcepoint DLP in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (https://10.210.91.21:9443) | True |
| Username | True |
| Password | True |
| Trust any certificate | False |
| Use system proxy | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### forcepoint-dlp-get-incidents

***

#### Base Command

`forcepoint-dlp-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | No description provided. | Optional | 
| from_date | DD/MM/YYYY HH:mm:ss. | Optional | 
| to_date | DD/MM/YYYY HH:mm:ss. | Optional | 

#### Context Output

There is no context output for this command.
### forcepoint-dlp-get-policy-rules

***

#### Base Command

`forcepoint-dlp-get-policy-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Software Source Code. | Optional | 

#### Context Output

There is no context output for this command.
### forcepoint-dlp-list-policies

***

#### Base Command

`forcepoint-dlp-list-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | DLP, DISCOVERY. | Optional | 

#### Context Output

There is no context output for this command.
### forcepoint-dlp-update-incident

***

#### Base Command

`forcepoint-dlp-update-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | Forcepoint DLP ID. | Optional | 
| status | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
