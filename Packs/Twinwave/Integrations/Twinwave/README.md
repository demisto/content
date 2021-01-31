Stealth mode cybersecurity startup
Supported Cortex XSOAR versions: 6.0.0 and later.

## Configure Twinwave on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Twinwave.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | api-token | Twinwave API token | True |
    | first_fetch | Number of jobs to first fetch | False |
    | max_fetch |  | False |
    | source | Filter incidents by submission source. | False |
    | username | Filter UI incidents by username. Exact match only. \(Cannot use if source is all or api\) | False |
    | proxy | Use system proxy settings | False |
    | insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### twinwave-submit-url
***
Submit New URL for Scanning


#### Base Command

`twinwave-submit-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The target URL to visit and analyze. Unlike the UI, the API does not automatically un-defang the submitted URL. | Required | 
| engines | Array of strings (EngineName). List of engines to be used during the analysis. If you'd like to use the default Engines for your account, omit this field or specify the empty array []. . | Optional | 
| parameters | Optional list of parameters to customize behavior during analysis of the job. (E.g., passwords for archives.) {"archive_document_password": "", "decode_rewritten_urls": "true/false"}. | Optional | 
| priority | The job's priority relative to other jobs. Jobs with a lower priority value are processed before those with a higher value. (e.g., a priority=1 job will be processed before a priority=2 job.) Valid priority values are between 1 and 255. You may omit this field, in which case a default priority (10) is used. Default is 10. | Optional | 
| profile | An optional profile name that defines the analysis behavior to be used during the analysis for this job. Profiles names map to behaviors like identifying what collection of engines will be used. If no profile name is submitted the system will use the default profile. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.Submissions.JobID | Unknown | Job ID | 


### twinwave-submit-file
***
Submit File for Scanning


#### Base Command

`twinwave-submit-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry id of the File. | Required | 
| priority | The job's priority relative to other jobs. Jobs with a lower priority value are processed before those with a higher value. (e.g., a priority=1 job will be processed before a priority=2 job.) Valid priority values are between 1 and 255. You may omit this field, in which case a default priority (10) is used. Default is 10. | Optional | 
| profile | An optional profile name that defines the analysis behavior to be used during the analysis for this job. Profiles names map to behaviors like identifying what collection of engines will be used. If no profile name is submitted the system will use the default profile. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.Submissions.JobID | Unknown | Job ID | 


### twinwave-resubmit-job
***
Resubmit a Job


#### Base Command

`twinwave-resubmit-job`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.Submissions.JobID | Unknown | Job ID | 


### twinwave-get-job-summary
***
Get Job Summary


#### Base Command

`twinwave-get-job-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | the job ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.JobSummary | Unknown | Twinwave Job Summary | 
| Twinwave.JobSummary.ID | Unknown | Job ID | 
| Twinwave.JobSummary.Tasks.ID | Unknown | Task ID | 
| Twinwave.JobSummary.Tasks.JobID | Unknown | Job ID associated to the task | 


### twinwave-get-job-normalized-forensics
***
Get a Job's Normalized Forensics


#### Base Command

`twinwave-get-job-normalized-forensics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.JobNormalizedForensics | Unknown | Twinwave Job Normalized Forensics | 
| Twinwave.JobNormalizedForensics.JobID | Unknown | Job ID | 


### twinwave-get-task-normalized-forensics
***
Get a Task's Normalized Forensics


#### Base Command

`twinwave-get-task-normalized-forensics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Required | 
| task_id | The task ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.TaskNormalizedForensics | Unknown | Twinwave Task Normalized Forensics | 
| Twinwave.TaskNormalizedForensics.TaskID | Unknown | Task ID | 
| Twinwave.TaskNormalizedForensics.JobID | Unknown | Job ID | 


### twinwave-get-task-raw-forensics
***
Get a Task's Raw Forensics


#### Base Command

`twinwave-get-task-raw-forensics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Required | 
| task_id | The task ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.TaskRawForensics | Unknown | Twinwave Task Raw Forensics | 
| Twinwave.TaskRawForensics.JobID | Unknown | Job ID | 
| Twinwave.TaskRawForensics.TaskID | Unknown | Task ID | 


### twinwave-download-submitted-resource
***
Download the Submitted Resource. 

Download a password-protected Zip archive of the Resource. Use the password 'infected' to decrypt the archive.

All Resources discovered during the analysis are available for download via this endpoint. To get the list of SHA256s for the Job's Resources, see The Resources array from Get a Job Summary.


#### Base Command

`twinwave-download-submitted-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Required | 
| sha256 | The File sha256. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | Unknown | Name of the file | 
| File.EntryID | Unknown | Entry ID of the file | 


### twinwave-get-engines
***
List Available Engines


#### Base Command

`twinwave-get-engines`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.Engines | Unknown | Available Engines | 
| Twinwave.Engines.Name | Unknown | Name of the engine | 
| Twinwave.Engines.DefaultEnabled | Unknown | Default Enabled \(True/False\) | 
| Twinwave.Engines.SupportedTypes | Unknown | Supported Types | 


### twinwave-search-across-jobs-and-resources
***
Search Across Jobs and Resources


#### Base Command

`twinwave-search-across-jobs-and-resources`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| term | Specify the string to search for in the specified field. (E.g. .exe or example.com). | Optional | 
| field | Enum: "filename" "url" "tag" "sha256" "md5". | Optional | 
| type | Enum: "exact" "substring". | Optional | 
| count | Specify the maximum number of results to be returned. This has a hard limit of 100; specifying a number greater than that will result in a 400 Bad Request and the search will not be performed. | Optional | 
| shared_only | Specify true to only search across Jobs (and their Resources) which have been shared. | Optional | 
| submitted_by | Specify a username or part of a username (e.g. alice@example.com or alice) to only search across Jobs (and their Resources) submitted by the matching user. | Optional | 
| timeframe | Specify the maximum number of days back to search for results. Specify 0 for no limit. For example, setting this to 7 returns results within the last week. | Optional | 
| page | The page for which you want results. This defaults to 1 the first page. See HasNext in the response of your search to know whether or not there are more pages for your search criteria. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.JobsAndResources | Unknown | Jobs and Resources | 
| Twinwave.JobsAndResources.Jobs | Unknown | Job Details | 
| Twinwave.JobsAndResources.Jobs.ID | Unknown | Job ID | 


### twinwave-get-temp-artifact-url
***
Get a Temporary Artifact URL


#### Base Command

`twinwave-get-temp-artifact-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Throughout the analysis of a Resource, a variety of Artifacts may be generated. These include things like Screenshots, PCAPs, HAR files, etc. This API endpoint generates a temporary URL that can be used to download the contents of an artifact.<br/><br/>After making a call to this endpoint, the URL field will contain a link to a signed URL for the desired Artifact. This link has a limited lifetime, so upon receiving it, you should immediately make a GET request to retrieve the actual Artifact. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twinwave.TempArtifactURL.URL | Unknown | Temporary URL | 
