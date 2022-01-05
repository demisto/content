FortiSandbox integration is used to submit files to FortiSandbox for malware analysis and retrieving the report of the analysis. It can also provide file rating based on hashes for already scanned files.

## Configure FortiSandbox on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FortiSandbox.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | URL of the Fortisandbox server. | True |
    | Credentials |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) | By default SSL certification validation is enabled. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortisandbox-simple-file-rating-sha256
***
Get file rating of SHA-256 Checksum


#### Base Command

`fortisandbox-simple-file-rating-sha256`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| checksum | SHA-256 Checksum to check the rating. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-simple-file-rating-sha1
***
Get File Rating of SHA-1 checksum


#### Base Command

`fortisandbox-simple-file-rating-sha1`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| checksum | SHA-1 Checksum to check the rating. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-url-rating
***
Get URL Rating from FortiSandbox


#### Base Command

`fortisandbox-url-rating`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Comma separated URLs  to get url rating. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-get-file-verdict-detailed
***
Query file's verdict through its checksum (returns JSON)


#### Base Command

`fortisandbox-get-file-verdict-detailed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| checksum | Checksum value to query. | Required | 
| checksum_type | Type of checksum - sha1 or sha256. Possible values are: sha1, sha256. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-upload-file
***
Upload file (on-demand submit)


#### Base Command

`fortisandbox-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_entry_id | Entry ID of the file to upload. | Required | 
| archive_password | Password for archived/zipped files. | Optional | 
| vm_csv_list | VMs to scan the File on, comma seperated. (Ex.WIN7X86VM,WINXPVM). | Optional | 
| skip_steps | Do not use this parameter if no step to skip. 1 = Skip AV, 2= Skip Cloud, 4= Skip sandboxing, 8= Skip Static Scan. | Optional | 
| malpkg | Set the value as "1" to require to add the sample to malware package if it satisfy the malware critia. By default, the value is "0". Default is 0. | Optional | 
| sha256 | File SHA-256 used to get scan report. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSandbox.Upload.SubmissionId | string | Submission ID of file submission | 
| FortiSandbox.Upload.FileName | string | File Uploaded | 
| FortiSandbox.Upload.SHA256 | string | SHA256 of uploaded file used for getting report | 
| FortiSandbox.Upload.Status | string | Scan status | 


#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-query-job-verdict
***
Query File Scan verdict from FortiSandbox based on Job ID


#### Base Command

`fortisandbox-query-job-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Scan Job ID for file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-jobid-from-submission
***
Get Job IDs from an uploaded Submission using the submission ID


#### Base Command

`fortisandbox-jobid-from-submission`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_id | Submission ID of uploaded file to scan. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSandbox.Upload.Status | string | scan status | 
| FortiSandbox.Upload.JobIds | string | job ids for submission | 


#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-get-pdf-report
***
Get PDF Report of scanned item


#### Base Command

`fortisandbox-get-pdf-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_type | Select query method - job ID or sha256. Possible values are: jid, sha256. | Required | 
| query_value | Enter query value - job ID value or Sha256 hash of the file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fortisandbox-upload-urls
***
Upload CSV URLs


#### Base Command

`fortisandbox-upload-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | Comma seperated url values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


