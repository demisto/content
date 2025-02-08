Submit a high volume of samples to run in a sandbox and view reports
This integration was integrated and tested with version 0 of Hatching Triage

## Configure Hatching Triage in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL | Private url is https://private.tria.ge/api/v0/ | True |
| API Key | The API Key to use for the connection. | True |
| Verify SSL |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### triage-query-samples
***
Get a list of all samples either private or public


#### Base Command

`triage-query-samples`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subset | Get samples from either private or public reports. Possible values are: owned, public. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.submissions.completed | Date | Date the sample analysis was completed | 
| Triage.submissions.filename | String | Name of the file submitted | 
| Triage.submissions.id | String | Unique identifier of the submission | 
| Triage.submissions.kind | String | Type of analysis | 
| Triage.submissions.private | Boolean | If the submissions is private or publically viewable | 
| Triage.submissions.status | String | Status of the submitted file | 
| Triage.submissions.submitted | Date | Date the sample was submitted | 
| Triage.submissions.tasks.id | String | Array of tasks that have been applied to the sample \(static, behavioral, etc\) | 
| Triage.submissions.tasks.status | String | Status of the task | 
| Triage.submissions.tasks.target | String | Sample the task is being run on | 
| Triage.submissions.url | String | URL that was submitted | 

### triage-submit-sample
***
Submits a file or url for analysis

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`triage-submit-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kind | Select if sample is a URL, file, or a file that should be fetched from a URL. Possible values are: url, file, fetch. | Required | 
| interactive | Choose if the sample should be interacted with in the GUI glovebox. Possible values are: false, true. Default is false. | Optional | 
| profiles | Select what profile to run the sample with. Requires the user to be registered with a company. | Optional | 
| data | Data to submit for analysis. For URLs give the URL. For files, give the entry-id of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.submissions.filename | String | Name of the submitted file | 
| Triage.submissions.id | String | Unique identifier of the submission | 
| Triage.submissions.kind | String | Type of sample to analyze | 
| Triage.submissions.private | Boolean | If the file is private or publicly viewable | 
| Triage.submissions.status | String | Status of the analysis of the submission | 
| Triage.submissions.submitted | Date | Date that the sample was submitted on | 

#### Command example
```!triage-submit-sample data="4@1" kind="file"```
#### Human Readable Output



### triage-get-sample
***
Pulls back basic information about the sample id given


#### Base Command

`triage-get-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.samples.completed | Date | Date the sample analysis was completed | 
| Triage.samples.filename | String | Name of the submitted sample | 
| Triage.samples.id | String | Unique identifier of the sample | 
| Triage.samples.kind | String | Type of sample submitted | 
| Triage.samples.private | Boolean | State of the visibility of the sample | 
| Triage.samples.status | String | Current status of the sample analysis | 
| Triage.samples.submitted | Date | Date the sample was submitted | 
| Triage.samples.tasks.id | String | Task name that was applied to the sample | 
| Triage.samples.tasks.status | String | Status of the task | 
| Triage.samples.tasks.target | String | Target of the task, e.g. filename for file submissions | 

### triage-get-sample-summary
***
Gets a summary report of the sample id provided


#### Base Command

`triage-get-sample-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.sample-summaries.completed | Date | Date the sample analysis was completed | 
| Triage.sample-summaries.created | Date | Date the analysis report was created | 
| Triage.sample-summaries.custom | String |  | 
| Triage.sample-summaries.owner | String |  | 
| Triage.sample-summaries.sample | String | Unique identifier of the sample | 
| Triage.sample-summaries.score | Number | Score of the sample on a scale of 0 to 10 | 
| Triage.sample-summaries.sha256 | String | SHA256 of the sample | 
| Triage.sample-summaries.status | String | Status of the analysis | 
| Triage.sample-summaries.target | String | Target for analysis | 
| Triage.sample-summaries.tasks | String | Tasks performed in the analysis | 

#### Command example
```!triage-get-sample-summary sample_id="220807-d5sxnaebbx"```
#### Human Readable Output



### triage-delete-sample
***
Deletes a sample from the sandbox


#### Base Command

`triage-delete-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 


#### Context Output

There is no context output for this command.
### triage-set-sample-profile
***
When a sample is in the static_analysis status, a profile should be selected in order to continue.


#### Base Command

`triage-set-sample-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 
| auto | Let Triage automatically select a profile, default is True. Possible values are: true, false. | Optional | 
| pick | If submitting an archive file, select which files to analyze. Multiple files can be specified with a comma seperator.Format is archive_file_name/sample_file.exe,archive_file_name/sample_file2.exe. | Optional | 
| profiles | Profile ID to use. | Optional | 


#### Context Output

There is no context output for this command.
### triage-get-static-report
***
Get the static analysis of a sample


#### Base Command

`triage-get-static-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.sample.reports.static.analysis.reported | Unknown | Date the sample was submitted | 
| DBotScore.Indicator | String | Triage analysis target | 
| DBotScore.Type | String | The indicator type - File or URL | 
| DBotScore.Vendor | String | The integration used to generate the indicator | 
| DBotScore.Score | Number | Analysis verdict as score from 1 to 10 | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| URL.Data | String | The URL | 

#### Command example
```!triage-get-static-report sample_id="220807-d5sxnaebbx"```
#### Human Readable Output



### triage-get-report-triage
***
Retrieves the generated Triage behavioral report for a single task


#### Base Command

`triage-get-report-triage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 
| task_id | Name of a behavioral task part of the sample analysis (e.g. behavioral1, behavioral2). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.sample.reports.triage | Unknown | Triage report of the submitted sample | 
| DBotScore.Indicator | String | Triage analysis target | 
| DBotScore.Type | String | The indicator type - File or URL | 
| DBotScore.Vendor | String | The integration used to generate the indicator | 
| DBotScore.Score | Number | Analysis verdict as score from 1 to 10 | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| URL.Data | String | The URL | 

#### Command example
```!triage-get-report-triage sample_id="220807-d5sxnaebbx" task_id="behavioral1"```
#### Human Readable Output



### triage-get-kernel-monitor
***
Retrieves the output of the kernel monitor


#### Base Command

`triage-get-kernel-monitor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 
| task_id | Name of a behavioral task part of the sample analysis (e.g. behavioral1, behavioral2). | Required | 


#### Context Output

There is no context output for this command.
### triage-get-pcap
***
Retrieves the PCAP of the analysis for further manual analysis


#### Base Command

`triage-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 
| task_id | Name of a behavioral task part of the sample analysis (e.g. behavioral1, behavioral2). | Required | 


#### Context Output

There is no context output for this command.
### triage-get-dumped-file
***
Retrieves files dumped by the sample. The names can be found under the "dumped" section from the triage report output


#### Base Command

`triage-get-dumped-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample's unique identifier, can be found using the query samples command. | Required | 
| task_id | Name of the task for the sample (e.g. behavioral1, static1, etc). | Required | 
| file_name | Name of the dumped file. | Required | 


#### Context Output

There is no context output for this command.
### triage-get-users
***
Return all users within the company as a paginated list. Returns a single user if a userID is provided


#### Base Command

`triage-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userID | Unique identifier of the user. Leave blank to query for all users. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.users.company_id | String | Company unique identifier | 
| Triage.users.created_at | Date | Date users account was created | 
| Triage.users.email | String | Users email | 
| Triage.users.email_confirmed_at | Date | Date user confirmed their email/account | 
| Triage.users.first_name | String | Users first name | 
| Triage.users.id | String | Users unique identifier | 
| Triage.users.last_name | String | Users last name | 
| Triage.users.permissions | String | Users permissions | 

### triage-create-user
***
Creates a new user and returns it. The user will become a member of the company the requesting user is a member of


#### Base Command

`triage-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Users username, usually their email. | Required | 
| firstName | Users first name. | Required | 
| lastName | Users last name. | Required | 
| password | Users password. | Required | 
| permissions | Users permissions. Possible values are: view_samples, submit_samples, delete_samples, edit_profiles, access_api, manage_machines, manage_company. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.users.company_id | String | Company unique identifier | 
| Triage.users.created_at | Date | Date users account was created | 
| Triage.users.email | String | Users email | 
| Triage.users.email_confirmed_at | Date | Date user confirmed their email/account | 
| Triage.users.first_name | String | Users first name | 
| Triage.users.id | String | Users unique identifier | 
| Triage.users.last_name | String | Users last name | 
| Triage.users.permissions | String | Users permissions | 

### triage-delete-user
***
Delete a user and all associated data, invalidating any sessions and removing their API keys. Any samples submitted by this user are kept


#### Base Command

`triage-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userID | Users unique identifier, can be found by querying for all users. | Required | 


#### Context Output

There is no context output for this command.
### triage-create-api-key
***
Creates a new key can be used to make API calls on behalf of the specified user. The user should have been granted the access_api permission beforehand


#### Base Command

`triage-create-api-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userID | Users unique identifier, can be found by querying for all users. | Required | 
| name | Name of the API key. Default is Created from XSOAR. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.apikey.key | String | API Key | 
| Triage.apikey.name | String | Name of the API Key | 

### triage-get-api-key
***
Lists all API keys that the user has.


#### Base Command

`triage-get-api-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userID | Users unique identifier, can be found by querying for all users. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.apikey.key | String | API Key | 
| Triage.apikey.name | String | Name of the API Key | 

### triage-delete-api-key
***
Delete the user's API key with the specified name


#### Base Command

`triage-delete-api-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userID | Users unique identifier, can be found by querying for all users. | Required | 
| name | Name of the API key to delete. | Required | 


#### Context Output

There is no context output for this command.
### triage-get-profiles
***
List all profiles that your company has


#### Base Command

`triage-get-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profileID | Unique identifier of the profile, can be found by querying for all profiles. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.profiles..id | String | Unique identifier of the profile | 
| Triage.profiles..name | String | Name of the profile | 
| Triage.profiles..network | String | Network configuration | 
| Triage.profiles..options.browser | String | Browser options | 
| Triage.profiles..tags | String | Applied tags | 
| Triage.profiles..timeout | Number | Max run time of the profile | 

### triage-create-profile
***
Create a new profile


#### Base Command

`triage-create-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the profile to create. | Required | 
| tags | Tags to apply to the profile. | Required | 
| timeout | Length of time the profile should run for. | Optional | 
| network | Network configuration the profile should use. Possible values are: drop, internet, proxy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.profiles.id | String | Profile unique identifier | 
| Triage.profiles.name | String | Profile name | 
| Triage.profiles.network | String | Profile network configuration | 
| Triage.profiles.options | Unknown | Profile options | 
| Triage.profiles.tags | String | Profile tags | 
| Triage.profiles.timeout | Number | Profile max run time | 

### triage-update-profile
***
Update an existing profile


#### Base Command

`triage-update-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profileID | Unique identifier of the profile to update. | Required | 
| name | Name of the profile. | Required | 
| tags | Tags to apply to the profile. | Required | 
| timeout | Length of time the profile should run for. | Optional | 


#### Context Output

There is no context output for this command.
### triage-query-search
***
Get a list of private and public samples matching the search query


#### Base Command

`triage-query-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query for Triage. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Triage.samples.completed | date | Date the sample analysis was completed | 
| Triage.samples.filename | string | Name of the file submitted | 
| Triage.samples.id | string | Unique identifier of the submission | 
| Triage.samples.kind | string | Type of analysis | 
| Triage.samples.private | boolean | If the submissions is private or publically viewable | 
| Triage.samples.status | string | Status of the submitted file | 
| Triage.samples.submitted | date | Date the sample was submitted | 
| Triage.samples.tasks.id | string | Array of tasks that have been applied to the sample \(static, behavioral, etc\) | 
| Triage.samples.tasks.status | string | Status of the task | 
| Triage.samples.tasks.target | string | Sample the task is being run on | 
| Triage.samples.url | string | URL that was submitted | 

#### Command example
```!triage-query-search query="tag:stealer AND tag:spyware"```
#### Human Readable Output



### triage-delete-profile
***
Update the profile with the specified ID or name. The stored profile is overwritten, so it is important that the submitted profile has all fields, with the exception of the ID


#### Base Command

`triage-delete-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profileID | Unique identifier of the profile to delete. | Required | 


#### Context Output

There is no context output for this command.