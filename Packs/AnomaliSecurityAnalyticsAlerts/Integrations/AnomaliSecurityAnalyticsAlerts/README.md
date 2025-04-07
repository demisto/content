The Anomali Security Analytics pack allows users to manage security alerts by interacting directly with the Anomali Security Analytics platform. It supports creating search jobs, monitoring their status, retrieving results, and updating alert statuses or comments, streamlining integration with Palo Alto XSOAR.
This integration was integrated and tested with version 1.0 of AnomaliSecurityAnalyticsAlerts.

## Configure Anomali Security Analytics Alerts in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### anomali-security-analytics-search-job-create

***
Create a new search job.

#### Base Command

`anomali-security-analytics-search-job-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search expression or keyword you're looking for in logs, e.g. alerts. | Required | 
| source | Filters results by the log source or origin system, e.g. third_party_xsoar_integration. | Optional | 
| from | Timerange - start time, e.g., 1 hour, 30 minutes. Default value is 1 day. Default is 1 day. | Optional | 
| to | Timerange - end time, e.g., 1 hour, 30 minutes. Default value is present. Default is 0 minutes. | Optional | 
| timezone | The desired timezone for the log source from the dropdown list. The default is Universal Link System Time Zone, which is the timezone where Universal Link is installed. Default value is UTC. Default is UTC. | Optional | 

### Search Job Created
|job_id|status|
|---|---|
| 7af7bc62c807446fa4bf7ad12dfbe64b | in progress |

### anomali-security-analytics-search-job-results

***
Get search job results.

#### Base Command

`anomali-security-analytics-search-job-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Unique identifier assigned to a background process or job. | Required | 
| offset | Offset of the search results. For example, if offset=10 and fetch_size=30, then this API will return results indexed 10 to 40. Default value is 0. | Optional | 
| fetch_size | Number of rows returned. Maximum rows is 1000. Default value is 25. Default is 25. | Optional | 

#### Context Output

**Search Job Results**

| id  | name            | owner              | status | severity | alert_time      | search_job_id                           |
|-----|-----------------|--------------------|--------|----------|-----------------|-----------------------------------------|
| 905 | AlertTriageDemo | test@anomali.com | new    | high     | 1741867250299   | 7af7bc62c807446fa4bf7ad12dfbe64b         |



### anomali-security-analytics-alert-update

***
Update alert's comment or status.

#### Base Command

`anomali-security-analytics-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Universally unique identifier assigned to uniquely identify objects such as Jobs, Alerts, Observables, Threat model entities. You can find it in search job results command. | Required | 
| comment | Field for adding analyst notes or remarks to Match events, IOC submissions and Alert triage decisions. Please provide either 'status' or 'comment' parameter. | Optional | 
| status | Current state of the observable in ThreatStream, e.g., active, inactive, falsepos. Please provide either 'status' or 'comment' parameter. | Optional | 

#### Context Output

### Update Alert Status
|message|
|---|
| Table (alert) was successfully updated. |
