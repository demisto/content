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
| source | Filters results by the log source or origin system, e.g. third_party_xsoar_integration. Default value is third_party. Default is third_party. | Optional | 
| from | Timerange - start time, e.g., 1 hour, 30 minutes. Default value is 1 day. Default is 1 day. | Optional | 
| to | Timerange - end time, e.g., 1 hour, 30 minutes. Default value is present. Default is 0 minutes. | Optional | 
| timezone | The desired timezone for the log source. Pass the official IANA name for the time zone you are interested in, e.g. Europe/London, America/New_York. Default value is UTC. Default is UTC. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliSecurityAnalytics.SearchJob.job_id | String | Job ID of the search job. | 

#### Human Readable Output

**Search Job Created**
|job_id|status|
|---|---|
| 7af7bc62c807446fa4bf7ad12dfbe64b | in progress |

### anomali-security-analytics-search-job-status

***
Get the status of one or more search jobs.

#### Base Command

`anomali-security-analytics-search-job-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Unique identifier assigned to a background process or job. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliSecurityAnalytics.SearchJobStatus.job_id | String | Job ID of the search job. | 
| AnomaliSecurityAnalytics.SearchJobStatus.status | String | Current status of the search job. e.g. RUNNING, DONE. | 
| AnomaliSecurityAnalytics.SearchJobStatus.progress | Number | Indicates the search progress. Numeric float value between 0 and 1. | 
| AnomaliSecurityAnalytics.SearchJobStatus.scanned | Number | Number of records scanned by the search query. | 
| AnomaliSecurityAnalytics.SearchJobStatus.total | Number | Total number of records matched by the search query. | 
| AnomaliSecurityAnalytics.SearchJobStatus.start_time | Number | Start timestamp of the time interval of the search query, in UNIX timestamp milliseconds. | 
| AnomaliSecurityAnalytics.SearchJobStatus.end_time | Number | End timestamp of the time interval of the search query, in UNIX timestamp milliseconds. | 
| AnomaliSecurityAnalytics.SearchJobStatus.bucket_length | Number | Width of each histogram bin depending on the search duration. | 
| AnomaliSecurityAnalytics.SearchJobStatus.num_of_bucket | Number | Number of buckets in which you receive all the search results. | 
| AnomaliSecurityAnalytics.SearchJobStatus.is_aggregated | Boolean | Whether the search results are aggregated. | 
| AnomaliSecurityAnalytics.SearchJobStatus.histogram_buckets | Array | Number of histogram buckets used to bucket the search result. | 

#### Human Readable Output
**Search Job Status**
|job_id|status|progress|scanned|total|start_time|end_time|
|---|---|---|---|---|---|---|
| 7af7bc62c807446fa4bf7ad12dfbe64b | in progress | 0.5 | 100 | 100 | 1741867250299 | 1741867250299 |

### anomali-security-analytics-search-job-results

***
Get search job results.

#### Base Command

`anomali-security-analytics-search-job-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Unique identifier assigned to a background process or job. | Required | 
| offset | Offset of records returned from the search result job. For example, if offset=10 and fetch_size=30, then this API will return results indexed 10 to 40. Default value is 0. | Optional | 
| fetch_size | Number of records returned from the search result job. Maximum rows is 1000. Default value is 25. Default is 25. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliSecurityAnalytics.SearchJobResults.job_id | String | Job ID of the search job. | 
| AnomaliSecurityAnalytics.SearchJobResults.status | String | Status of the search. | 
| AnomaliSecurityAnalytics.SearchJobResults.count | Number | Number of records returned. | 
| AnomaliSecurityAnalytics.SearchJobResults.has_next | Boolean | Indicates if more pages are available. | 
| AnomaliSecurityAnalytics.SearchJobResults.is_aggregated | Boolean | Indicates if the search is aggregated. | 
| AnomaliSecurityAnalytics.SearchJobResults.records | Array | List of records containing the fields included in the fields response attribute. | 
| AnomaliSecurityAnalytics.SearchJobResults.result_row_count | Number | Total number of records retrieved by the search. | 
| AnomaliSecurityAnalytics.SearchJobResults.search_end_time | Number | End timestamp of the search \(UNIX timestamp in milliseconds\). | 
| AnomaliSecurityAnalytics.SearchJobResults.search_start_time | Number | Start timestamp of the search \(UNIX timestamp in milliseconds\). | 
| AnomaliSecurityAnalytics.SearchJobResults.status | String | Status of the search job. | 
| AnomaliSecurityAnalytics.SearchJobResults.types | Array | Data types of the search record attributes. | 

#### Human Readable Output
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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnomaliSecurityAnalytics.UpdateAlert.message | String | Confirmation message returned after updating the alert status. | 

#### Human Readable Output
**Update Alert Status**
|message|
|---|
| Table (alert) was successfully updated. |
