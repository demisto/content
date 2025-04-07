Anomali Security Analytics Alerts is an integrated cybersecurity solution that combines log aggregation, scalable data storage, and customizable dashboards to deliver rapid threat insights
This integration was integrated and tested with version 1.0 of Anomali Security Analytics Alerts.

## Configure Anomali Security Analytics Alerts in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| API Key | True |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### anomali-security-analytics-search-job-create

***
create a new search job

#### Base Command

`anomali-security-analytics-search-job-create`

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
### anomali-security-analytics-search-job-results

***
get search job results

#### Base Command

`anomali-security-analytics-search-job-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id | Yes | 

#### Context Output

**Search Job Results**

| id  | name            | owner              | status | severity | alert_time      | search_job_id                           |
|-----|-----------------|--------------------|--------|----------|-----------------|-----------------------------------------|
| 905 | AlertTriageDemo | test@anomali.com | new    | high     | 1741867250299   | 7af7bc62c807446fa4bf7ad12dfbe64b         |


### anomali-security-analytics-alert-update

***
update alert

#### Base Command

`anomali-security-analytics-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | new status of the alert | Optional | 
| comment | new comment of the alert | Optional | 
| uuid | uuid of alert | Yes | 

#### Context Output

### Update Alert Status
|message|
|---|
| Table (alert) was successfully updated. |