Anomali SA Alerts
This integration was integrated and tested with version 1.0 of Anomali_SA_Alerts.

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
| query | The query string | Yes | 
| source | The source identifier | Optional | 
| from | From time | Optional | 
| to | To time | Optional | 
| timezone | Timezone | Optional | 

#### Context Output

### Search Job Created
|job_id|status|
|---|---|
| 7af7bc62c807446fa4bf7ad12dfbe64b | in progress |
### threatstream-search-job-status

***
query a search job status

#### Base Command

`threatstream-search-job-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id | Optional | 

#### Context Output

### Search Job Status
|job_id|status|
|---|---|
| 7af7bc62c807446fa4bf7ad12dfbe64b | DONE |
### threatstream-search-job-results

***
get search job results

#### Base Command

`threatstream-search-job-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id | Yes | 

#### Context Output

**Search Job Results**
| Field                        | Value                                 |
|------------------------------|---------------------------------------|
| avc_limit                    | 0.0                                   |
| avc_used_for_current_job     | 0.0                                   |
| avc_used_in_total            | 0.0                                   |
| count                        | 0                                     |
| has_next                     | false                                 |
| result_row_count             | 0                                     |
| result_update_id             | 0                                     |
| search_end_time              | 0                                     |
| search_start_time            | 0                                     |
| status                       | RUNNING                               |
| ui_info                      | explicitly_add_rawdata: false         |
| explicitly_remove_rawdata    | false                                 |


### threatstream-update-alert-status

***
update status of alert

#### Base Command

`threatstream-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | new status of the alert | Optional | 
| uuid | uuid of alert | Optional | 

#### Context Output

### Update Alert Status
|message|
|---|
| Table (alert) was successfully updated. |
### threatstream-update-alert-comment

***
update comment of alert

#### Base Command

`threatstream-update-alert-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | new comment of the alert | Yes | 
| uuid | uuid of alert | Yes | 

#### Context Output

### Update Alert Comment
|message|
|---|
| Table (alert) was successfully updated. |
