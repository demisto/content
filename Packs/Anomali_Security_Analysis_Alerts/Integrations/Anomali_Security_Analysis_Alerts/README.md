Anomali SA Alerts
This integration was integrated and tested with version xx of Anomali_SA_Alerts.

## Configure Anomali_SA_Alerts in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| API Key | True |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatstream-search-job-create

***
create a new search job

#### Base Command

`threatstream-search-job-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | No description provided. | Optional | 
| source | No description provided. | Optional | 
| from | No description provided. | Optional | 
| to | No description provided. | Optional | 
| timezone | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### threatstream-search-job-status

***
query a search job status

#### Base Command

`threatstream-search-job-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### threatstream-search-job-results

***
get search job results

#### Base Command

`threatstream-search-job-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### threatstream-update-alert-status

***
update status of alert

#### Base Command

`threatstream-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | No description provided. | Optional | 
| uuid | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### threatstream-update-alert-comment

***
update comment of alert

#### Base Command

`threatstream-update-alert-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | No description provided. | Optional | 
| uuid | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
