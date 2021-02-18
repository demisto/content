Use the CrowdStrike Falcon X integration to submit files, file hashes, URLs, and FTPs for sandbox analysis, and to retrieve reports.

## Configure CrowdStrike Falcon X on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike Falcon X.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Client ID | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cs-fx-upload-file
***
Uploads a file for sandbox analysis.
Notice that the file identifier (SHA) can be changed as shown in the example below.

#### Base Command

`cs-fx-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | Name of the file to upload for sandbox analysis. | Required | 
| comment | A descriptive comment to identify the file for other users. | Optional | 
| is_confidential | Determines the visibility of this file in Falcon MalQuery. Can be "true" or "false". If "true", the file is confidential. | Optional | 
| file | Content of the uploaded sample in binary format. | Required | 
| submit_file | Whether to submit the given file to the sandbox. Can be "yes" or "no". Default is "no". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.sha256 | String | SHA256 hash of the uploaded file. | 
| csfalconx.resource.file_name | String | Name of the uploaded file.  | 


#### Command Example
```!cs-fx-upload-file file=895@07031695-ae27-49f6-8bb2-41943c7cb80c file_name=test.pdf comment="example" is_confidential="true" submit_file=no```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "file_name": "test.pdf",
            "sha256": "c5fdd1fb2c53cd00aba5b01270f91fd5598f315bef99938ddeb92c23667ec2c9"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|file_name|sha256|
>|---|---|
>| test.pdf | c5fdd1fb2c53cd00aba5b01270f91fd5598f315bef99938ddeb92c23667ec2c9 |


### cs-fx-submit-uploaded-file
***
Submits a sample SHA256 hash for sandbox analysis.
Notice that the file identifiers, SHA and ID are not the same.


#### Base Command

`cs-fx-submit-uploaded-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA256 ID of the sample, which is a SHA256 hash value. Find the sample ID from the response when uploading a malware sample or search with the cs-fx-upload-file command. | Required | 
| environment_id | Sandbox environment used for analysis. | Required | 
| action_script | Runtime script for sandbox analysis. | Optional | 
| command_line | Command line script passed to the submitted file at runtime. Max length: 2048 characters. | Optional | 
| document_password | Auto-filled for Adobe or Office files that prompt for a password. Max length: 32 characters. | Optional | 
| enable_tor | Whether the sandbox analysis routes network traffic via TOR. Can be "true" or "false". If true, sandbox analysis routes network traffic via TOR. | Optional | 
| submit_name | Name of the malware sample that’s used for file type detection. and analysis. | Optional | 
| system_date | Set a custom date for the sandbox environment in the format yyyy-MM-dd. | Optional | 
| system_time | Sets a custom time for the sandbox environment in the format HH:mm. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.uploaded_id  | String | Analysis ID received after uploading the file. | 
| csfalconx.resource.state | String | Analysis state. | 
| csfalconx.resource.created_timpestamp | String | Analysis start time. | 
| csfalconx.resource.sha256 | Unknown | SHA256 hash of the scanned file. | 
| csfalconx.resource.environment_id | Unknown | Environment ID of the analysis.  | 


#### Command Example
```!cs-fx-submit-uploaded-file sha256="a381a7b679119dee5b95c9c09993885e44ad2fd9cd52fa28bc116f8bdea71679" environment_id="160: Windows 10" action_script="default" command_line="command" document_password="password" enable_tor="false" submit_name="malware_test" system_date="2020-08-10" system_time="12:48"```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2020-07-03T06:36:17Z",
            "environment_id": 160,
            "sha256": "a381a7b679119dee5b95c9c09993885e44ad2fd9cd52fa28bc116f8bdea71679",
            "state": "created",
            "submitted_id": "1c9fe398b2294301aa3080ede8d77356_943236d30cc349538cab108d61c6986a"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|created_timestamp|environment_id|sha256|state|submitted_id|
>|---|---|---|---|---|
>| 2020-07-03T06:36:17Z | 160 | a381a7b679119dee5b95c9c09993885e44ad2fd9cd52fa28bc116f8bdea71679 | created | 1c9fe398b2294301aa3080ede8d77356_943236d30cc349538cab108d61c6986a |


### cs-fx-get-full-report
***
Gets a full version of a sandbox report.


#### Base Command

`cs-fx-get-full-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a submitted malware sample. Find a submission ID from the response when submitting a malware sample or search with the cs-fx-submit-uploaded-file command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.submitted_id | String | Analysis ID received after submitting the file. | 
| csfalconx.resource.verdict | String | Analysis verdict. | 
| csfalconx.resource.created_timpestamp | String | Analysis start time. | 
| csfalconx.resource.environment_id | String | Environment ID. | 
| csfalconx.resource.snadbox.environment_description | String | Environment description. | 
| csfalconx.resource.threat_score | Int | Score of the threat. | 
| csfalconx.resource.submit_url | String | URL submitted for analysis. | 
| csfalconx.resource.submission_type | String | Type of submitted artifact, for example file, URL, etc. | 
| csfalconx.resource.filetype | String | File type. | 
| csfalconx.resource.filesize | Int | File size. | 
| csfalconx.resource.sha256 | String | SHA256 hash of the submitted file. | 
| csfalconx.resource.ioc_report_strict_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_broad_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_strict_json_artifact_id | Int | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_broad_json_artifact_id | String | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_strict_stix_artifact_id | String | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_broad_stix_artifact_id | Int | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_strict_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 
| csfalconx.resource.ioc_report_broad_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 


#### Command Example
```!cs-fx-get-full-report ids="1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f"```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2020-03-16T17:04:48Z",
            "environment_description": "Windows 10 64 bit",
            "environment_id": 160,
            "id": "1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f",
            "ioc_report_broad_csv_artifact_id": "910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04",
            "ioc_report_broad_json_artifact_id": "b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8",
            "ioc_report_broad_maec_artifact_id": "16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945",
            "ioc_report_broad_stix_artifact_id": "90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1",
            "ioc_report_strict_csv_artifact_id": "910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04",
            "ioc_report_strict_json_artifact_id": "b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8",
            "ioc_report_strict_maec_artifact_id": "16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945",
            "ioc_report_strict_stix_artifact_id": "90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1",
            "sha256": "15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3",
            "submission_type": "page_url",
            "submit_url": "hxxps://www.google.com",
            "threat_score": 13,
            "verdict": "no specific threat"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|created_timestamp|environment_description|environment_id|id|ioc_report_broad_csv_artifact_id|ioc_report_broad_json_artifact_id|ioc_report_broad_maec_artifact_id|ioc_report_broad_stix_artifact_id|ioc_report_strict_csv_artifact_id|ioc_report_strict_json_artifact_id|ioc_report_strict_maec_artifact_id|ioc_report_strict_stix_artifact_id|sha256|submission_type|submit_url|threat_score|verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-03-16T17:04:48Z | Windows 10 64 bit | 160 | 1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f | 910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04 | b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8 | 16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945 | 90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1 | 910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04 | b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8 | 16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945 | 90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1 | 15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3 | page_url | hxxps://www.google.com | 13 | no specific threat |


### cs-fx-get-report-summary
***
Gets a short summary version of a sandbox report.


#### Base Command

`cs-fx-get-report-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a submitted malware sample. Find a submission ID from the response when submitting a malware sample or search with the cs-fx-submit-uploaded-file command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.id | String | Analysis ID. | 
| csfalconx.resource.verdict | String | Analysis verdict. | 
| csfalconx.resource.created_timpestamp | String | Analysis start time. | 
| csfalconx.resource.environment_id | String | Environment ID. | 
| csfalconx.resource.environment_description | String | Environment description. | 
| csfalconx.resource.threat_score | Int | Score of the threat. | 
| csfalconx.resource.submit_url | String | URL submitted for analysis. | 
| csfalconx.resource.submission_type | String | Type of submitted artifact. For example, file, URL, etc. | 
| csfalconx.resource.filetype | String | File type. | 
| csfalconx.resource.filesize | Int | File size. | 
| csfalconx.resource.sha256 | String | SHA256 hash of the submitted file. | 
| csfalconx.resource.ioc_report_strict_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_broad_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_strict_json_artifact_id | Int | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_broad_json_artifact_id | String | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_strict_stix_artifact_id | String | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_broad_stix_artifact_id | Int | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_strict_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 
| csfalconx.resource.ioc_report_broad_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 


#### Command Example
```!cs-fx-get-report-summary ids="1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f"```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2020-03-16T17:04:48Z",
            "environment_description": "Windows 10 64 bit",
            "environment_id": 160,
            "id": "1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f",
            "ioc_report_broad_csv_artifact_id": "910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04",
            "ioc_report_broad_json_artifact_id": "b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8",
            "ioc_report_broad_maec_artifact_id": "16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945",
            "ioc_report_broad_stix_artifact_id": "90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1",
            "ioc_report_strict_csv_artifact_id": "910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04",
            "ioc_report_strict_json_artifact_id": "b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8",
            "ioc_report_strict_maec_artifact_id": "16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945",
            "ioc_report_strict_stix_artifact_id": "90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1",
            "sha256": "15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3",
            "submission_type": "page_url",
            "submit_url": "hxxps://www.google.com",
            "threat_score": 13,
            "verdict": "no specific threat"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|created_timestamp|environment_description|environment_id|id|ioc_report_broad_csv_artifact_id|ioc_report_broad_json_artifact_id|ioc_report_broad_maec_artifact_id|ioc_report_broad_stix_artifact_id|ioc_report_strict_csv_artifact_id|ioc_report_strict_json_artifact_id|ioc_report_strict_maec_artifact_id|ioc_report_strict_stix_artifact_id|sha256|submission_type|submit_url|threat_score|verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-03-16T17:04:48Z | Windows 10 64 bit | 160 | 1c9fe398b2294301aa3080ede8d77356_8511c69fa47f4188bf59e3ab80f0f39f | 910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04 | b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8 | 16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945 | 90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1 | 910b844555678892b85afaa6761eb0619b43355a851797f2cd54aa814ad84e04 | b02b32f52a8fa67ad42d8b0e002d37622142b6b5f9c8174fa62df859422a8de8 | 16f7cb67df103b63badeed41a6d05d717c8aee898b811b1620e7d009dab18945 | 90c36e086e9459b8c08503409f58b1d8710b46867736fac292afff45b4ffb1f1 | 15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3 | page_url | hxxps://www.google.com | 13 | no specific threat |


### cs-fx-get-analysis-status
***
Checks the status of a sandbox analysis.


#### Base Command

`cs-fx-get-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a submitted malware sample. Find a submission ID from the response when submitting a malware sample or search with the cs-fx-submit-uploaded-file/url command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.id | String | Analysis ID. | 
| csfalconx.resource.verdict | String | Analysis verdict. | 
| csfalconx.resource.created_timpestamp | String | Analysis start time. | 
| csfalconx.resource.environment_id | String | Environment ID. | 
| csfalconx.resource.environment_description | String | Environment description. | 
| csfalconx.resource.threat_score | Int | Score of the threat. | 
| csfalconx.resource.submit_url | String | URL submitted for analysis. | 
| csfalconx.resource.submission_type | String | Type of submitted artifact. For example, file, URL, etc. | 
| csfalconx.resource.filetype | String | File type. | 
| csfalconx.resource.filesize | Int | File size. | 
| csfalconx.resource.sha256 | String | SHA256 hash of the submitted file. | 
| csfalconx.resource.ioc_report_strict_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_broad_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_strict_json_artifact_id | Int | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_broad_json_artifact_id | String | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_strict_stix_artifact_id | String | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_broad_stix_artifact_id | Int | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_strict_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 
| csfalconx.resource.ioc_report_broad_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 


#### Command Example
```!cs-fx-get-analysis-status ids="1c9fe398b2294301aa3080ede8d77356_8cfaaf951fff412090df3d27d4b4193d"```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2020-05-26T21:24:41Z",
            "environment_id": 160,
            "id": "1c9fe398b2294301aa3080ede8d77356_8cfaaf951fff412090df3d27d4b4193d",
            "sha256": "05cca3437abcb4057c157ed8b933b07fb198aa0fa0eb7f7c27e97029e9e0ad61",
            "state": "success"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|created_timestamp|environment_id|id|sha256|state|
>|---|---|---|---|---|
>| 2020-05-26T21:24:41Z | 160 | 1c9fe398b2294301aa3080ede8d77356_8cfaaf951fff412090df3d27d4b4193d | 05cca3437abcb4057c157ed8b933b07fb198aa0fa0eb7f7c27e97029e9e0ad61 | success |


### cs-fx-check-quota
***
Returns the total quota number and the in use quota number.


#### Base Command

`cs-fx-check-quota`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.quota.total | Number | Total quota number.  | 
| csfalconx.resource.quota.used | Number | Used quota number. | 
| csfalconx.resource.quota.in_progress | Number | Analysis in progress. | 


#### Command Example
```!cs-fx-check-quota```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "in_progress": 3,
            "total": 500,
            "used": 11
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|in_progress|total|used|
>|---|---|---|
>| 3 | 500 | 11 |


### cs-fx-find-reports
***
Finds sandbox reports by providing an FQL filter and paging details.


#### Base Command

`cs-fx-find-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Optional filter and sort criteria in the form of an FQL query. | Optional | 
| offset | The offset from which to start retrieving reports. | Optional | 
| limit | Maximum number of report IDs to return. Maximum is 5000. | Optional | 
| sort | Sort order. Can be "asc" or "desc". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.id | Number | Set of report IDs that match the search criteria.  | 


#### Command Example
```!cs-fx-find-reports offset=1 limit=5```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "resources": [
                "1c9fe398b2294301aa3080ede8d77356_b85ecb950a7946f781055165fb772d1d",
                "1c9fe398b2294301aa3080ede8d77356_d0b4bc43b10849bdb3a6b47ad21300e4",
                "1c9fe398b2294301aa3080ede8d77356_91863c129067479198bd150b512bb408",
                "1c9fe398b2294301aa3080ede8d77356_c94eaa632d5c4166a9b1266bce73d2f4",
                "1c9fe398b2294301aa3080ede8d77356_d0cd12feda95443d94c8bdc78d513d52"
            ]
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|resources|
>|---|
>| 1c9fe398b2294301aa3080ede8d77356_b85ecb950a7946f781055165fb772d1d,<br/>1c9fe398b2294301aa3080ede8d77356_d0b4bc43b10849bdb3a6b47ad21300e4,<br/>1c9fe398b2294301aa3080ede8d77356_91863c129067479198bd150b512bb408,<br/>1c9fe398b2294301aa3080ede8d77356_c94eaa632d5c4166a9b1266bce73d2f4,<br/>1c9fe398b2294301aa3080ede8d77356_d0cd12feda95443d94c8bdc78d513d52 |


### cs-fx-find-submission-id
***
Finds submission IDs for uploaded files by providing an FQL filter and paging details. Returns a set of submission IDs that match the search criteria.


#### Base Command

`cs-fx-find-submission-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Optional filter and sort criteria in the form of an FQL query. | Optional | 
| offset | The offset from which to start retrieving reports. | Optional | 
| limit | Maximum number of report IDs to return. Maximum is 5000. | Optional | 
| sort | Sort order. Can be "asc" or "desc". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.id | Number | Set of report IDs that match the search criteria.  | 


#### Command Example
```!cs-fx-find-submission-id offset=1 limit=5```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "resources": [
                "1c9fe398b2294301aa3080ede8d77356_943236d30cc349538cab108d61c6986a",
                "1c9fe398b2294301aa3080ede8d77356_853956d90743418b96dea59d190cdaf9",
                "1c9fe398b2294301aa3080ede8d77356_c97b23377e594218b5df76b512466582",
                "1c9fe398b2294301aa3080ede8d77356_b85ecb950a7946f781055165fb772d1d",
                "1c9fe398b2294301aa3080ede8d77356_d0b4bc43b10849bdb3a6b47ad21300e4"
            ]
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|resources|
>|---|
>| 1c9fe398b2294301aa3080ede8d77356_943236d30cc349538cab108d61c6986a,<br/>1c9fe398b2294301aa3080ede8d77356_853956d90743418b96dea59d190cdaf9,<br/>1c9fe398b2294301aa3080ede8d77356_c97b23377e594218b5df76b512466582,<br/>1c9fe398b2294301aa3080ede8d77356_b85ecb950a7946f781055165fb772d1d,<br/>1c9fe398b2294301aa3080ede8d77356_d0b4bc43b10849bdb3a6b47ad21300e4 |


### cs-fx-submit-url
***
Submits a URL or FTP for sandbox analysis.


#### Base Command

`cs-fx-submit-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A web page or file URL. It can be HTTP(S) or FTP.<br/>For example: `https://url.com or ftp://ftp.com` | Required | 
| environment_id | Sandbox environment used for analysis. | Required | 
| action_script | Runtime script for sandbox analysis. Values:<br/>default<br/>default_maxantievasion<br/>default_randomfiles<br/>default_randomtheme<br/>default_openie | Optional | 
| command_line | Command line script passed to the submitted file at runtime. Max length: 2048 characters | Optional | 
| document_password | Auto-filled for Adobe or Office files that prompt for a password. Max length: 32 characters. | Optional | 
| enable_tor | Whether the sandbox analysis routes network traffic via TOR. Can be "true" or "false". If true, sandbox analysis routes network traffic via TOR. Default is false. | Optional | 
| submit_name | Name of the malware sample that’s used for file type detection and analysis. | Optional | 
| system_date | Sets a custom date for the sandbox environment in the format yyyy-MM-dd. | Optional | 
| system_time | Sets a custom time for the sandbox environment in the format HH:mm. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.submitted_id | String | Analysis ID received after submitting the file. | 
| csfalconx.resource.state | String | Analysis state. | 
| csfalconx.resource.created_timpestamp | String | Analysis start time. | 
| csfalconx.resource.sha256 | Unknown | SHA256 hash of the scanned file. | 
| csfalconx.resource.environment_id | Unknown | Environment ID of the analysis. | 


#### Command Example
```!cs-fx-submit-url url="https://www.google.com" environment_id="160: Windows 10" action_script="default" document_password="password" enable_tor="false" submit_name="malware_test" system_date="2020-08-10" system_time="12:48"```

#### Context Example
```
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2020-07-03T06:36:19Z",
            "environment_id": 160,
            "state": "created",
            "submitted_id": "1c9fe398b2294301aa3080ede8d77356_472d590fdd4e49639e41f81928df2542"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|created_timestamp|environment_id|state|submitted_id|
>|---|---|---|---|
>| 2020-07-03T06:36:19Z | 160 | created | 1c9fe398b2294301aa3080ede8d77356_472d590fdd4e49639e41f81928df2542 |


### cs-fx-download-ioc
***
Downloads IOC packs, PCAP files, and other analysis artifacts.


#### Base Command

`cs-fx-download-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of an artifact, such as an IOC pack, PCAP file, or actor image. Find an artifact ID in a report or summary. | Required | 
| name | The name given to then downloaded file. | Optional | 
| accept_encoding | Format used to compress the downloaded file. Currently, you must provide the value of the GZIP file. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cs-fx-download-ioc id="cd1db2f53e8760792a48a2ec544a29e6f876643204598621783f71017f6b4266" name="test" accept_encoding="gzip"```

#### Context Example
```
{
    "csfalconx": {
        "resource": [
            [
                {
                    "ioc": "7.77.7.7",
                    "source": "runtime",
                    "type": "ip"
                },
                {
                    "ioc": "054e58bdec6972ff4b3167b34e77612f",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "05d6eeb048c90c766aece42e337dde4d",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "0f109e8d4aedbf943299263b152d4f00",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "15dd37df165655f35e8ce536d024167f",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "16e8057213bd80adc4baaf3a1ecc3f82",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "17fc5228ad1d52335c5fe981253ee545",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "195ef9caeb0f6216d9e8cfd4be942d36",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "1b4b2c7752a15752d30c0c0e6970988c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "1c3582f2c953e92f1be73969f49b209e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "1d5dc5cb90058cf92f1466d2fcfa4c97",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "21d10abfd2a3d671e5db3539c0cf431e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "222d020bd33c90170a8296adc1b7036a",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "2291c23b5ff917a1e40a64c5e5d71986",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "262810da4b496d7ce1486a413e4b12b1",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "264d51f1b2f3df04bb8bf07f7b1fb71c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "28082a61a32170d0479e2b1523962135",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "2d630301c6a51385326aab073ff4ec2e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "32b14e28f95191808d638688c9152843",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "3623a0e7cdcf3310ffb4c87c5b43ae02",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "36353ce86b46b877af6d90325ff03b95",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "3663019e0506c85d753c08c02660b34a",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "394f5551ee04fb916f132a6ba807de11",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "3b48ed2a0c41e2329e9c7ab86edd64b1",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "3bbbb863f37d818aba19a8451927c616",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "3e52939e94c51551361a10ad81197b60",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "46266ab248b89b3a40542e63bfc02603",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "46eebcbe18910b967267d592f76a2836",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "4fe51249cdc1c1ab03173fd0bed7db4f",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "5695647c9de015395b00344eb9d48a9d",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "576af4ad78a176e07b1af29bcf92aa1e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "59b1f27a96d13e54cd4867f0dddecd83",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "60767e9bd01835bd95792df61433ce4b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "656da8a3661b746eb9374659d15c4a2b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "67abaf7458772435ad67564b3fbf14a0",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "68b14871e4b235ac3788866621297a27",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "6d53703fddac024e2cf27fc4a7ac5df6",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "6f0cfccd7f00f7fd009b00ce6871272e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "6fddc5aede1751f10ce62923c042a793",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "704730bc2fbc8c69a929e21ef8aa7379",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "72c6a76c1eec3490f06e41bfa0d3f26b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "751b9ce3dc2dd9e3de156da983b2b3b4",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "77541eb350a5b881f81f3fcf6b9d3936",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "786551c4c8bcde890d0d4e0d70545529",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "7d3ed29c7c33ea81a14ab3563d3ce87c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "7f15e8271ee067b6074493d93813dad3",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "80b82d4d5e9d867ff1113e1879d92f68",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "8295247d3dae9745677ec2c1d6339011",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "83018fe200707cc3205b49b59ad1f760",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "83129da20ca16fae0bf1e24820eb1906",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "878a59d39c6172aab0997124ece4e8fe",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "8c39aaffa9b99019fc96e298296543d3",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "8db811264a0a6282eb134f60c7844c57",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "8e5034c077d52dafd449df9206cf5471",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "9234edf95ad1d3409a38b90d16713467",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "93ba37530689e5f858dfa8b31ae6c236",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "951c29a740e714857433557e9de737c8",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "95351915b3f4e2d7f5c2a8744c0ce4eb",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "99ba01e7652e90cc1740d6eaef4effdf",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "9b305ac55cbefb495190ba4c3c6f8e97",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "9e284a4ffaad5f5c3a3b5d9f3ab0b03d",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "9ec17d371530d8a4ee2c90fd393a1eb4",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "9ef29221c01ff06c6808b4c61108a824",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a040a3ada27bd0421afbe20ce933af4b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a5603a0780d44b6edfb18b7a68880b93",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a66cc76dfcb0f4ed5c51bd9c1b389a78",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a6763ae35acd41ec0f50bdfcc559d83b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a6836a433946a889741af4943e2ba623",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a82bba1dcff205558edc62b4509775f6",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a856d4a6170bbdc323372974ffca437e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a881defcf778f764141d5770e55132e4",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "a949ea32164cbfbeffaace03d289e34f",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "af84af2c2eaa9500b4a85e4237434b24",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b080dc93850347a50475fcd3df3a263a",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b3dfec2163622335b59b717d85a8b0d4",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b447d3f9668152426c12a2c497346553",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b4b02868b76e096f64bfc214f9611e8f",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b4e3cf26877344bbf70852ac3f7a5b94",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b5ff695b08c839155c5eb003d6e90cba",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "b8a434d31c6a7557e3a5723c39cc2ab3",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "c10d754c27174b47349306b4c3a3054f",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "ce72a3a3fe723345694654f97dad8bb6",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "d059dda2747521880e351cb19d66f25b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "d1db526687b9439169ee91614fdd8e0c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "d280e4b97c3981b9c85cda924a81ebac",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "d9129968f1e1cd135426368bbfaadb6b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "d9472401f9b7002921cb909fa421393c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "e03b08d438b560988883511e8d854a4b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "e85a6a9cf37b580a47073a9f41f7e36e",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "eb815e917831e2d9475e148457799855",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "f2f95afad83bd1a8b4facf8debd6cf4c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "f526b0de0664ec18965f46bcf39e6ab0",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "f8d1c5f572f3d8056d92e6a19f6a3186",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "fa0c8e71e7049ee4311b7c194ab9330b",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "fc47823102b667b6b7dc883155fbb574",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "fcab2d9f7bb7b3bee0fa8e47bcefdb95",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "fd3e826a891b2dba2acd7aea4e00599c",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "fdc1565e0b31d64d714aaf5234716bc2",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "fde52cb94e207ea2a2782dfa18d37ce3",
                    "source": "extracted",
                    "type": "md5"
                },
                {
                    "ioc": "0409018a0d4c8a5fca7a6872fc5f36c6c117eabf",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "09bfa1e0ed619838c09a8a2f9d0f305f51f35293",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "0a332783a3be35d35b4f8e6ed24c29b9b73fb2b2",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "0b2e71f7031c3ae1e426916a84592629e5285974",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "0bccfbe2680222ed00fc5b78472d68395f67c5d1",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "0cbd138a2ffada08365752c96dfb01e9c4706e72",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "0f142aec235f5b7055a51671fc8dd11c41761e89",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "0f9f02b33e97a37a0a83198d9277c7de30a2a133",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "12adc4a068cae4dd09372d30ba5b472b9a6f9187",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "135ad157d42af083da9c48f1b3a97e44043c46b0",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "194a177ff869dcc601a1c20e87e8a0743591964a",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "1acc8207029efcfc2abeeaf2d87732041ce43af0",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "1cbb4004815ad74e82bd38a25a842a5d8a11e2b6",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "1dac6ad3f332fbadde42f043aea0bfe38f8f7462",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "1df02e555b0eb8720a0e8f3a6236e96edbd46a44",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "20f8bbae09d11d0815e29b8c34d05fbf94025665",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "21bb1242cad0f4ed15f5428dd2888b0927bbbcbe",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "21ee83eb497f555d141c0a5da6cf0f4ed15b1bad",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "23d45a52d72f7d6ce5dd6870f6db2c6cbbf24a95",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "2494479325f5d95b0282c5804f29a1a2d3f279bc",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "258de626af33f204eb4f88a10035bffc185269cd",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "25e45a471f0ffb063302539f1c8199890b38b5bd",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "291fad57d3dde5490dbadddd8ea0a21b5b22b0e3",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "2b2003a078355d1b5c40a7173d902975adb82161",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "2e2a6d9ed39c0cd66e78016f32bcc4791f17a68e",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "2f947dd46ff651e9a0d7f459eb6d8e762f828f35",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "31ab45ed24d82fa29928e621a50916d40ebf90b9",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "344955ef0750adab73dcb1f990e034a1768dff33",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "355c210e196f7eee39bdca034313e20f7c8ffd6f",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "360dec6792e5cfe2bc7839a3663ede38d04c4f29",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "40696cc382192e83346030175c22d3ee8262ca40",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "440d2777660ebf84a0f51b0e9d4d70b38e7baa0c",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "47571575dfeaa7a547dd37bca16d09189e79b4ca",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "47de58c724df0b49b2b0d3d1e9641cca121d9f5f",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "51b28ec7ce79ea6d744d762d17df66e55d54c580",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "526a85d9e22f5e46631e96a22361424936ce1226",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "5906da6d0e07c4110e990ff9ff93004340ab8124",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "5b0f2ae72eed1584bc91176a04206f69ade904aa",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "5b8df645cff49aa1390d76af30571412987b004b",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "5e890811ecb79be566670c281bbab2886f49c496",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "5ef850a2715d725561f6e184d03e885ece113b01",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "5f1735bdbe22512ae84bdd52ed4f491ea48596a0",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "60f8972d53c3ba46246ddf344903cd50513d07b2",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "612e6f443d927330b9b8ac13cc4a2a6b959cee48",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "654f2250a2d0fd6cce1d7a0b132787c0a6067e41",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "65a3847912fc6f1196d1057d520997772cdd4990",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "6a7038d482c73815fc532391e8fa39566a421f5a",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "7207b8aae726d16516ee568eca1348c3c45d86cf",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "7477e03983e8ce3b617ad8010ecbdb0c6d110482",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "76ac49e1c29553124d8b42de15092381919acfed",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "7ad583aa228ab1cc01af4d69b8a1256d3ffbef23",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "808cbf203744a91fd5dd754fd8ace8b53c59d743",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8a82a108cb5533eb6fbb71464eddb6bb1568d6b9",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8b1fa15062d370e53a774e1890bd62bbb1c64195",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8b89e958739aba89e3e0651fca7e9c2a20e043c3",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8cb4b9c3fa0426fba933b589c41547c9c74b1a43",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8d02d2e21d0883aef74c58c4165b81eb2b91d687",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8d2dfab4359f85d26d2273a665f4756ea309583f",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "8e9df2292f5280f7aed98b310e11668485a18e86",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "91bf4d341678981c67a865040de73340fcd01a41",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "97839f6c09dc984c06707e0562e858bb479c6443",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "995c07769b3bf806c5bcd7d9211d56627dee888b",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "9b20e394a39ca22294fefc650f3d295c1380b3d5",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "9dff73112f7fc8397c3127e3b6a6efd0f5e23848",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "a5c10fc317416971fc5beb8ce2be03345f5128e2",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "a6419cdc5724dc9452de9ab1180f8d49bcc1aa3d",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "a78b33dc7086b59f9232dcf50d4e8590ccfd72ec",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "a8ee535fde7cb1bec7082c8df9566f0f97d6dd94",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "aaf20a6ec982df2a397bb975bf72cf5771128184",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "acee3127c9c3f2622a8bccc653cd740206cf66ff",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "af5b31dc8e381b2e2e07ead1efb37c6d39aa6569",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "b093757dbbc9e5e753a86addc10e8e5139ba7dcb",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "b36a63ad1c5758170ab356666916ac43db0b1e86",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "b3d4cf49fcf551f19bdd6af5df50cf43e0e85658",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "b3e15a4cc38d11187b9503989d9b1d17585f3bb7",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "b71226d430cfaca9adebaf2a584bec5ca3a72319",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "b718cc5a5ffcd038efd3f22a838712a410fb632b",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "ba9449290387275b0a80e03d534208a28614fa26",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "bd5d64d9ed4b3a4e9ce11c068f2c368be2c9a0f4",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "be3c08b7e5b5c2f7b8f6c28529725f5d73e0c764",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "bfe8dca1c5b9e9cffe0c683bf2e87bd6522bd9e9",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "c0431f82350b647faf7f38bb6dd5447faafaeced",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "c28b4a54808e597a70f119d08bc61cec1157984f",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "c59bee3260b514d321d6bdabcb6d6ed7b88edc6a",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "c986d550e8c663fb9bb4990c597ae6f553eacb86",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "d210cb1c1a3b8eb3d926f76170c1f7afea241bc8",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "d50acc1b397e06076d96984ed55f58f720190422",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "d7e37398dedae7d0b252131dd63351e24434017c",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "d9d08cbc21098199b9525df1c7a931aa7d4ed6b3",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "da90758c936d2b4b07be6d9ad189f54ceb7c14ba",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "db4f4f54bfa4cc299db4b7c585b5c92e2c8800f3",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "e1bd983e865184f74fcd72cc5c8fda0e5471f84b",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "eefb7c27460f2ff6a770f8f20d4be44809d894c2",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "f37aafac973dd7b5dee1f37642f26b3882d63751",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "f491be785a74d3d99feb3158d453c7a2f5020be5",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "f715c61244912f292946f63cb3cf0b376110aa5c",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "f89dd73d45cce148548e35ba18872a08397fb3bb",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "fd97f7d413d542c1f80c9532b9accd97bf930b6b",
                    "source": "extracted",
                    "type": "sha1"
                },
                {
                    "ioc": "005021b5f9b2672e7c6b846447c0cebeb8f9bd077428e2722948b51975f9660d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "016a28eb17ff195a7a18a69649bb99f58a2f03496b141a95f88f92e28988b0a6",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "099fef1c71250ca5bf9dff4bffdeb04bca1e1f3eb853d1a974bf3a8cd39383ef",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "0f407d7194e7955e312b177b16cc409ac89b4d0494c60ce75469fd4c474d4043",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "1074ce0c035e280ff10ce80780840465024b3a019305145c61a26c8315c39164",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "11fa26754c6ed1985e2b4049b06f112450f275b040574518acf51a37fcca3360",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "141156d92537f78e092999fd7f66b99d69813e414b89ca21f0f25e7a71c4a311",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "1566ab7d93d6b46d25d4d06e25bce78a44ac1e40826b90b0b92dce533c919fe4",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "17095cf302d370f7e2f66e4335ef56058ae36e588be67d5530e191f2e95c8dd5",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "178267f61af3e6e76052ea6b7ade224977c524f4a7e72df8a1422c0dd6dd14b6",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "19b1060bedc50b9362640395e3ace60622228edd29caa54228c5b3b4e2a6082d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "1a5612ca4453eeaef55e00a29b94cb55053db0febf5d767465fbf70348c473df",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "1e0ca5e091883e134828d8efda9866955212a455837bf6343e112afd2d5673d5",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "2016b27bbb381338db8a3205fe8391e0970bebe67470ab8fb09567563f625291",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "2572e5fe6786c52232c894641858abeef9c159200bf1f47acd5418e7e8b703e9",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "2a4cb70fd5a06adf1eee7e6d4cb89a4c8c92978cfa51bde8e3360b58fb62e49d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "2b52e902c2940fc007833114f30f1f54161f84da2f357b83d29b8c1134fb9a5d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "2d35cc1bb51d974de29e8fcc3b9afb5dfcb7e7a3027b9a009dbc289dd99c2748",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "3083d74bc9f52470c62df3c711249fa60df4164762e2575139684f9ba3c71240",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "31acb2b8cf32b6081522359e4b6fd035a3c5de87e5cae667dc44406b31125cfd",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "366de179cdd67383a1483796335457797b853481ca0e5408659a11ae5d5e7b8e",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "384b850d0e1698e1592609245e0caa3e9e1e5c03641f055b9115a86fd781a7da",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "3b63770b6f507105dcd72414e7bdaef44852cd76ad48647b493e84702e7eef3d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "40f873a43330c92904fa5763b509a2b651b4b29d0d2081bbb5ce10d2d12443be",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "4172d573062ad265f7d322d38883ccddff7b05e0820fb7ec3cf9801ebae64ed7",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "4432bbd1a390874f3f0a503d45cc48d346abc3a8c0213c289f4b615bf0ee84f3",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "46aade266c90ebc02d4c8018f537ed3043cd5486fea77d68955ea1613aa5458b",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "488c2c65b0b94be87b4c0036a098df25ee4f6cd2bf194b6f1a15441f2ee1db7d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "4a6b711a3a224a9451e043be2ec2475c2849243601f45729611acf55617bb5e6",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "51e2236f5764848a02fb5673420699a12b78ff19c78ca0509a18b24f6b7d2b50",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "55759ff83e70935bc16506acc584db6f7b1d4e7f3a4fba044ca90a8e3e5241e0",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "57a677b2cf2db05bd8a494ab4cbc9322cfde33b91220ed1080c1cf13f84fbf2e",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "600672e9164d0201ebb0349111994910105ad61386ca58c5d67556efa66f35c6",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "63a415feb02b52c34543ae9df5b069b1918d00e752bab94158a7380843d6cd06",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "6cb1b6e339a9117c2b25eba1515fe7ab9d616c262523dfdd12c76415d080f478",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "6e7b135be3e92d0709f0b7773202a7c3758233ecab4635700a464208cc9950c9",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "76ec85daea72b0c471fd559d3daa79ee9dc5e732015f6c698341ef9c94b84991",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "796daed8551007a9f7bf760a41de33dc92bfc32e6fb157f4e6af762ef2cce22b",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "7d73afa3dabaeec33cc7f5b2ff30f9489db7ed082234e42c78ae35aa52bb3a41",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "80c829f2db2ec88e55f34cf3473614d947ccc0ba39b2e267a8a93830470e5df0",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "844b02484b208c34b408fb61e4c8590970010997ed8ba2aee2009a33b01d7797",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "856bc7c058908168d12f859c3aa35a72a914be0c3b5dfdd9584fdbfaeb612bec",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "8909691ae3c674cc2bfcdd145c08eedca21c89b98403b38da958ab9ba1cefff6",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "8a0440855c7e08ecffde06a89f2182ea4cc3f493e75566170f040575a6a826e0",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "8d16cbada454edb42478219342651dd426815e703e446319a1ee690542eaef84",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "8e24a437490f1aa421b8ee7a95a0667041840b8cd10fd9a4d057ad73cd103864",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "8faa9b6971eda5eb1ddab5d94adb4ae59c8455459b50dcbe3420f2c8d30914b7",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "8fbd98643ff35c35a7034ce402dc8e519af1497c80a509c26d8b48215862d14f",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "90cdec4faf737adb2623fd668b3f8b023acae1aef55d1596cc1371c6ca6c753c",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "916f43a76ee027ed5cfae1932e5211ac5d2023773f1af6f8f1e1e836c81aceef",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "9b32c07c158eec7eb6a0bb8df3961633db49faef0f06d54fe94fa8d50d056331",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "a43cfc443e8b9bfd88d81a8b45360f1327889b9ba4d5db2e89c0558c2fdb6333",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "a79100b37dc27bb1198c8f56199e5f1ff686ca039cf6d76dd40a0acdd53f8cc7",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "a8156f1a6b38353aa444924406ad47736c6aaf90e534db826bc68260a5583725",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "a98058ead416c9036e7b91817b09f1df2ce6f2e5b1a690f620d4661019f531f1",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "a9a62a6c3536f17922b116d5b258c7c10ba687f4734fa91df02f13c72510d1b5",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "aa853c997b93d102ba4201102c4f42fd52c55e69d1c54f08783df9c600bc5884",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "aec564e08b5b0e6efaafcb5e32acdf4f2595cefbee8f3bb8fc529adc74dd82e2",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "b177f1717f348b2dbe913c81ae906f31b12ce240886548c335fcd931b09be3e3",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "b5e72042bc0ebb598affa5dc5adde62afa4af7d11a61c9682c10807bd8e665f3",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "b7139337e7a72822ac22eff838e3e955f713203298b4a6c9c00e7a1e19245154",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "b7b9555f4c2a4445f8d786bfad4c12bcf3c664a0f40d0576607cfa847d58eac2",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "b9865a550841bc99887b87502fcad20f1d0ceb3b84d88a1c70d6593101f6cd66",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "b9d5bcb6f63d7a3e20dd4ea343d9cefecd5770aa806c6471fa3da30d48888b26",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c001f8e6a175f024e553986cea4453e3f95396d8b5a1b19c3242344bcfc5e4f0",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c22d444aa5c44eeee70ec8e21f267faf8f5642507a331a304e026a798a7810ea",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c23e0d3598c4477caa7a75632c5b158ea73db3a02dfeccee695528a8efa4aeac",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c30ca342482170bcd279a029af1e6218a161b64c4bc2e725e63ded3bfd49983e",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c444e5a71483c95ae89468ff5ab420d15e71b33b05372bd3a1db6c435e996796",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c4eada327d83caebe0929b3aa638db533a2d30c4ef15a3dc4f445245dfd53797",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c70c2b47003a69646fc8347ed31504fdc4d6f0941ebae8761ef0cadce6c56e88",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c7ec4c42203f4931261ebf4e456a9bed0c389f9043ed8b6bfb97d7b9eb383319",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "c896ab2ab4f249ddd2e8be2bdb9e9956bcb5248c256e43e6474ef857f7f9141e",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "caf97c83f8926849e2f6eae191e2b9213550f410f6601c62f0aa7d3485ce79e5",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "cf62241aab4cc80a668ba9b676e0a55e870b945e38b710cdb3cd61c8ce6d7bd3",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "d18c35ae32ab207f8479c372e82aa6934f84aa640cc7bbffd285e5d40e17ad58",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "d5930d3ebabc0aa8e731fd6c249dc0cf54922505e0cf8b1629f895c47cb46f84",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "d62251a0f4874e2b56f27c1b44c399d29d57db85cded1b1bd758911eeb3f7e2e",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "d683ab7b817616669795b19aa794270e3b957caa3b271bdf665401203c20d6bc",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "d7b088b36bd43bd4325f7ab98cc6ef1f021559faf97d8d45d23424b0a8fe0e63",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "e2f2b23b31261c95e53c178183cebccfe55c9057d756fdef07af6124491e6413",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "e432f683769629d5c5712f4b34f26ddac599b4ba9c360f58eb0f8ca8a3eba6f9",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "e4c1015408bbb08ddd32da612e63ccdfe4e6ed8f6b3048ade7b9b21d520e7abc",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "e71ca8e2723e179767ace6aa690ba08a63e83c4b700bef411f56519310788136",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "e889837f9b3205d9b8f6c4341f3655258cf266fa3e9c33056b4fa52e02550237",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "eb5544fbad7bff6c43ff8b03ba7b122450c6577379fc6f6e5bc05a0b482ace74",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "f40bbbe902680c45c2192ec261e1e32a2a561b626bb588c60ef712aaf49bf5f9",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "f42b6e6d7dbf55534906d6d4102957d2ff38d7660ac1f75ff7572c410992b545",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "f53612ca03a286c2c94e07ab0c49ea7c7cb51cff2f6674b36fc0667f70b93c4d",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "f629edf2af597ab193ba750e68712024fb3560edb2445cf3162a48df0b2725c4",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "f8142377e4387420430e233be0ab491395c5d90b2b3dff9bdc608a836e09ed1b",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "f87046fbdd9a360b53561a02df2d6ebe87235c5c36c99eb03c1a81c0fa2f5cce",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "fa76c2a832dd0b351f1efd4a80ba8df2aaca9afa489a4de15182d81d12368a81",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "fb2556d2f1dc4deb27de7c59214134ea2839fd78580ce158943e94cf04819a61",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "fb3bd8af4332bd00f548a30e43e5e0180369afc581f0bdc04dba70e9296d5d3f",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "fc71e29adcf3f47d12ddcdbe3313f887c61f177d3c56346222f4b3d56324eec2",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "fd08e05c9ccc86940f430aed203fbd9366bc015c3d977baf18c306ce70cc2390",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "ff264234364940f1843d23207b67ba71554670d6372a0ce9b7dcd98915d16758",
                    "source": "extracted",
                    "type": "sha256"
                },
                {
                    "ioc": "55759ff83e70935bc16506acc584db6f7b1d4e7f3a4fba044ca90a8e3e5241e0",
                    "source": "input",
                    "type": "sha256"
                },
                {
                    "ioc": "178267f61af3e6e76052ea6b7ade224977c524f4a7e72df8a1422c0dd6dd14b6",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "2a4cb70fd5a06adf1eee7e6d4cb89a4c8c92978cfa51bde8e3360b58fb62e49d",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "4172d573062ad265f7d322d38883ccddff7b05e0820fb7ec3cf9801ebae64ed7",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "55759ff83e70935bc16506acc584db6f7b1d4e7f3a4fba044ca90a8e3e5241e0",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "b798e287d0d73c389f4ad8e0e55f88aa16d42757cd5ff9168bb855807ab66b6a",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "c4eada327d83caebe0929b3aa638db533a2d30c4ef15a3dc4f445245dfd53797",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "d7b088b36bd43bd4325f7ab98cc6ef1f021559faf97d8d45d23424b0a8fe0e63",
                    "source": "runtime",
                    "type": "sha256"
                },
                {
                    "ioc": "hxxp://32.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://allocator.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://apply.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://arena.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://backup.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://behaviors.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://blink.net",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://call.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://chrome.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://command.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://commands.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://common.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://crash.pb.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://dir.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://elf.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://event.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://experiment.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://gzip.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://handler.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://helper.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://impl.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://in.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://info.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://install.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://integration.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://io.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://item.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://list.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://lite.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://log.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://loop.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://main.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://memory.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://minidump.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://parameters.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://preferences.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://program.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://range.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://reader.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://recorder.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://report.pb.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://reports.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://seeker.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://server.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://settings.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://shortcut.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://snapshot.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://source.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://state.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://storage.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://stream.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://thread.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://tracker.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://trial.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://uninstall.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://util.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://version.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://versions.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://visitor.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://watcher.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://win.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://win32.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://worker.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://writable.cc",
                    "source": "runtime",
                    "type": "url"
                },
                {
                    "ioc": "hxxp://writer.cc",
                    "source": "runtime",
                    "type": "url"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon X response:
>|ioc|source|type|
>|---|---|---|
>| 7.77.7.7 | runtime | ip |
>| 054e58bdec6972ff4b3167b34e77612f | extracted | md5 |
>| 05d6eeb048c90c766aece42e337dde4d | extracted | md5 |
>| 0f109e8d4aedbf943299263b152d4f00 | extracted | md5 |
>| 15dd37df165655f35e8ce536d024167f | extracted | md5 |
>| 16e8057213bd80adc4baaf3a1ecc3f82 | extracted | md5 |
>| 17fc5228ad1d52335c5fe981253ee545 | extracted | md5 |
>| 195ef9caeb0f6216d9e8cfd4be942d36 | extracted | md5 |
>| 1b4b2c7752a15752d30c0c0e6970988c | extracted | md5 |
>| 1c3582f2c953e92f1be73969f49b209e | extracted | md5 |
>| 1d5dc5cb90058cf92f1466d2fcfa4c97 | extracted | md5 |
>| 21d10abfd2a3d671e5db3539c0cf431e | extracted | md5 |
>| 222d020bd33c90170a8296adc1b7036a | extracted | md5 |
>| 2291c23b5ff917a1e40a64c5e5d71986 | extracted | md5 |
>| 262810da4b496d7ce1486a413e4b12b1 | extracted | md5 |
>| 264d51f1b2f3df04bb8bf07f7b1fb71c | extracted | md5 |
>| 28082a61a32170d0479e2b1523962135 | extracted | md5 |
>| 2d630301c6a51385326aab073ff4ec2e | extracted | md5 |
>| 32b14e28f95191808d638688c9152843 | extracted | md5 |
>| 3623a0e7cdcf3310ffb4c87c5b43ae02 | extracted | md5 |
>| 36353ce86b46b877af6d90325ff03b95 | extracted | md5 |
>| 3663019e0506c85d753c08c02660b34a | extracted | md5 |
>| 394f5551ee04fb916f132a6ba807de11 | extracted | md5 |
>| 3b48ed2a0c41e2329e9c7ab86edd64b1 | extracted | md5 |
>| 3bbbb863f37d818aba19a8451927c616 | extracted | md5 |
>| 3e52939e94c51551361a10ad81197b60 | extracted | md5 |
>| 46266ab248b89b3a40542e63bfc02603 | extracted | md5 |
>| 46eebcbe18910b967267d592f76a2836 | extracted | md5 |
>| 4fe51249cdc1c1ab03173fd0bed7db4f | extracted | md5 |
>| 5695647c9de015395b00344eb9d48a9d | extracted | md5 |
>| 576af4ad78a176e07b1af29bcf92aa1e | extracted | md5 |
>| 59b1f27a96d13e54cd4867f0dddecd83 | extracted | md5 |
>| 60767e9bd01835bd95792df61433ce4b | extracted | md5 |
>| 656da8a3661b746eb9374659d15c4a2b | extracted | md5 |
>| 67abaf7458772435ad67564b3fbf14a0 | extracted | md5 |
>| 68b14871e4b235ac3788866621297a27 | extracted | md5 |
>| 6d53703fddac024e2cf27fc4a7ac5df6 | extracted | md5 |
>| 6f0cfccd7f00f7fd009b00ce6871272e | extracted | md5 |
>| 6fddc5aede1751f10ce62923c042a793 | extracted | md5 |
>| 704730bc2fbc8c69a929e21ef8aa7379 | extracted | md5 |
>| 72c6a76c1eec3490f06e41bfa0d3f26b | extracted | md5 |
>| 751b9ce3dc2dd9e3de156da983b2b3b4 | extracted | md5 |
>| 77541eb350a5b881f81f3fcf6b9d3936 | extracted | md5 |
>| 786551c4c8bcde890d0d4e0d70545529 | extracted | md5 |
>| 7d3ed29c7c33ea81a14ab3563d3ce87c | extracted | md5 |
>| 7f15e8271ee067b6074493d93813dad3 | extracted | md5 |
>| 80b82d4d5e9d867ff1113e1879d92f68 | extracted | md5 |
>| 8295247d3dae9745677ec2c1d6339011 | extracted | md5 |
>| 83018fe200707cc3205b49b59ad1f760 | extracted | md5 |
>| 83129da20ca16fae0bf1e24820eb1906 | extracted | md5 |
>| 878a59d39c6172aab0997124ece4e8fe | extracted | md5 |
>| 8c39aaffa9b99019fc96e298296543d3 | extracted | md5 |
>| 8db811264a0a6282eb134f60c7844c57 | extracted | md5 |
>| 8e5034c077d52dafd449df9206cf5471 | extracted | md5 |
>| 9234edf95ad1d3409a38b90d16713467 | extracted | md5 |
>| 93ba37530689e5f858dfa8b31ae6c236 | extracted | md5 |
>| 951c29a740e714857433557e9de737c8 | extracted | md5 |
>| 95351915b3f4e2d7f5c2a8744c0ce4eb | extracted | md5 |
>| 99ba01e7652e90cc1740d6eaef4effdf | extracted | md5 |
>| 9b305ac55cbefb495190ba4c3c6f8e97 | extracted | md5 |
>| 9e284a4ffaad5f5c3a3b5d9f3ab0b03d | extracted | md5 |
>| 9ec17d371530d8a4ee2c90fd393a1eb4 | extracted | md5 |
>| 9ef29221c01ff06c6808b4c61108a824 | extracted | md5 |
>| a040a3ada27bd0421afbe20ce933af4b | extracted | md5 |
>| a5603a0780d44b6edfb18b7a68880b93 | extracted | md5 |
>| a66cc76dfcb0f4ed5c51bd9c1b389a78 | extracted | md5 |
>| a6763ae35acd41ec0f50bdfcc559d83b | extracted | md5 |
>| a6836a433946a889741af4943e2ba623 | extracted | md5 |
>| a82bba1dcff205558edc62b4509775f6 | extracted | md5 |
>| a856d4a6170bbdc323372974ffca437e | extracted | md5 |
>| a881defcf778f764141d5770e55132e4 | extracted | md5 |
>| a949ea32164cbfbeffaace03d289e34f | extracted | md5 |
>| af84af2c2eaa9500b4a85e4237434b24 | extracted | md5 |
>| b080dc93850347a50475fcd3df3a263a | extracted | md5 |
>| b3dfec2163622335b59b717d85a8b0d4 | extracted | md5 |
>| b447d3f9668152426c12a2c497346553 | extracted | md5 |
>| b4b02868b76e096f64bfc214f9611e8f | extracted | md5 |
>| b4e3cf26877344bbf70852ac3f7a5b94 | extracted | md5 |
>| b5ff695b08c839155c5eb003d6e90cba | extracted | md5 |
>| b8a434d31c6a7557e3a5723c39cc2ab3 | extracted | md5 |
>| c10d754c27174b47349306b4c3a3054f | extracted | md5 |
>| ce72a3a3fe723345694654f97dad8bb6 | extracted | md5 |
>| d059dda2747521880e351cb19d66f25b | extracted | md5 |
>| d1db526687b9439169ee91614fdd8e0c | extracted | md5 |
>| d280e4b97c3981b9c85cda924a81ebac | extracted | md5 |
>| d9129968f1e1cd135426368bbfaadb6b | extracted | md5 |
>| d9472401f9b7002921cb909fa421393c | extracted | md5 |
>| e03b08d438b560988883511e8d854a4b | extracted | md5 |
>| e85a6a9cf37b580a47073a9f41f7e36e | extracted | md5 |
>| eb815e917831e2d9475e148457799855 | extracted | md5 |
>| f2f95afad83bd1a8b4facf8debd6cf4c | extracted | md5 |
>| f526b0de0664ec18965f46bcf39e6ab0 | extracted | md5 |
>| f8d1c5f572f3d8056d92e6a19f6a3186 | extracted | md5 |
>| fa0c8e71e7049ee4311b7c194ab9330b | extracted | md5 |
>| fc47823102b667b6b7dc883155fbb574 | extracted | md5 |
>| fcab2d9f7bb7b3bee0fa8e47bcefdb95 | extracted | md5 |
>| fd3e826a891b2dba2acd7aea4e00599c | extracted | md5 |
>| fdc1565e0b31d64d714aaf5234716bc2 | extracted | md5 |
>| fde52cb94e207ea2a2782dfa18d37ce3 | extracted | md5 |
>| 0409018a0d4c8a5fca7a6872fc5f36c6c117eabf | extracted | sha1 |
>| 09bfa1e0ed619838c09a8a2f9d0f305f51f35293 | extracted | sha1 |
>| 0a332783a3be35d35b4f8e6ed24c29b9b73fb2b2 | extracted | sha1 |
>| 0b2e71f7031c3ae1e426916a84592629e5285974 | extracted | sha1 |
>| 0bccfbe2680222ed00fc5b78472d68395f67c5d1 | extracted | sha1 |
>| 0cbd138a2ffada08365752c96dfb01e9c4706e72 | extracted | sha1 |
>| 0f142aec235f5b7055a51671fc8dd11c41761e89 | extracted | sha1 |
>| 0f9f02b33e97a37a0a83198d9277c7de30a2a133 | extracted | sha1 |
>| 12adc4a068cae4dd09372d30ba5b472b9a6f9187 | extracted | sha1 |
>| 135ad157d42af083da9c48f1b3a97e44043c46b0 | extracted | sha1 |
>| 194a177ff869dcc601a1c20e87e8a0743591964a | extracted | sha1 |
>| 1acc8207029efcfc2abeeaf2d87732041ce43af0 | extracted | sha1 |
>| 1cbb4004815ad74e82bd38a25a842a5d8a11e2b6 | extracted | sha1 |
>| 1dac6ad3f332fbadde42f043aea0bfe38f8f7462 | extracted | sha1 |
>| 1df02e555b0eb8720a0e8f3a6236e96edbd46a44 | extracted | sha1 |
>| 20f8bbae09d11d0815e29b8c34d05fbf94025665 | extracted | sha1 |
>| 21bb1242cad0f4ed15f5428dd2888b0927bbbcbe | extracted | sha1 |
>| 21ee83eb497f555d141c0a5da6cf0f4ed15b1bad | extracted | sha1 |
>| 23d45a52d72f7d6ce5dd6870f6db2c6cbbf24a95 | extracted | sha1 |
>| 2494479325f5d95b0282c5804f29a1a2d3f279bc | extracted | sha1 |
>| 258de626af33f204eb4f88a10035bffc185269cd | extracted | sha1 |
>| 25e45a471f0ffb063302539f1c8199890b38b5bd | extracted | sha1 |
>| 291fad57d3dde5490dbadddd8ea0a21b5b22b0e3 | extracted | sha1 |
>| 2b2003a078355d1b5c40a7173d902975adb82161 | extracted | sha1 |
>| 2e2a6d9ed39c0cd66e78016f32bcc4791f17a68e | extracted | sha1 |
>| 2f947dd46ff651e9a0d7f459eb6d8e762f828f35 | extracted | sha1 |
>| 31ab45ed24d82fa29928e621a50916d40ebf90b9 | extracted | sha1 |
>| 344955ef0750adab73dcb1f990e034a1768dff33 | extracted | sha1 |
>| 355c210e196f7eee39bdca034313e20f7c8ffd6f | extracted | sha1 |
>| 360dec6792e5cfe2bc7839a3663ede38d04c4f29 | extracted | sha1 |
>| 40696cc382192e83346030175c22d3ee8262ca40 | extracted | sha1 |
>| 440d2777660ebf84a0f51b0e9d4d70b38e7baa0c | extracted | sha1 |
>| 47571575dfeaa7a547dd37bca16d09189e79b4ca | extracted | sha1 |
>| 47de58c724df0b49b2b0d3d1e9641cca121d9f5f | extracted | sha1 |
>| 51b28ec7ce79ea6d744d762d17df66e55d54c580 | extracted | sha1 |
>| 526a85d9e22f5e46631e96a22361424936ce1226 | extracted | sha1 |
>| 5906da6d0e07c4110e990ff9ff93004340ab8124 | extracted | sha1 |
>| 5b0f2ae72eed1584bc91176a04206f69ade904aa | extracted | sha1 |
>| 5b8df645cff49aa1390d76af30571412987b004b | extracted | sha1 |
>| 5e890811ecb79be566670c281bbab2886f49c496 | extracted | sha1 |
>| 5ef850a2715d725561f6e184d03e885ece113b01 | extracted | sha1 |
>| 5f1735bdbe22512ae84bdd52ed4f491ea48596a0 | extracted | sha1 |
>| 60f8972d53c3ba46246ddf344903cd50513d07b2 | extracted | sha1 |
>| 612e6f443d927330b9b8ac13cc4a2a6b959cee48 | extracted | sha1 |
>| 654f2250a2d0fd6cce1d7a0b132787c0a6067e41 | extracted | sha1 |
>| 65a3847912fc6f1196d1057d520997772cdd4990 | extracted | sha1 |
>| 6a7038d482c73815fc532391e8fa39566a421f5a | extracted | sha1 |
>| 7207b8aae726d16516ee568eca1348c3c45d86cf | extracted | sha1 |
>| 7477e03983e8ce3b617ad8010ecbdb0c6d110482 | extracted | sha1 |
>| 76ac49e1c29553124d8b42de15092381919acfed | extracted | sha1 |
>| 7ad583aa228ab1cc01af4d69b8a1256d3ffbef23 | extracted | sha1 |
>| 808cbf203744a91fd5dd754fd8ace8b53c59d743 | extracted | sha1 |
>| 8a82a108cb5533eb6fbb71464eddb6bb1568d6b9 | extracted | sha1 |
>| 8b1fa15062d370e53a774e1890bd62bbb1c64195 | extracted | sha1 |
>| 8b89e958739aba89e3e0651fca7e9c2a20e043c3 | extracted | sha1 |
>| 8cb4b9c3fa0426fba933b589c41547c9c74b1a43 | extracted | sha1 |
>| 8d02d2e21d0883aef74c58c4165b81eb2b91d687 | extracted | sha1 |
>| 8d2dfab4359f85d26d2273a665f4756ea309583f | extracted | sha1 |
>| 8e9df2292f5280f7aed98b310e11668485a18e86 | extracted | sha1 |
>| 91bf4d341678981c67a865040de73340fcd01a41 | extracted | sha1 |
>| 97839f6c09dc984c06707e0562e858bb479c6443 | extracted | sha1 |
>| 995c07769b3bf806c5bcd7d9211d56627dee888b | extracted | sha1 |
>| 9b20e394a39ca22294fefc650f3d295c1380b3d5 | extracted | sha1 |
>| 9dff73112f7fc8397c3127e3b6a6efd0f5e23848 | extracted | sha1 |
>| a5c10fc317416971fc5beb8ce2be03345f5128e2 | extracted | sha1 |
>| a6419cdc5724dc9452de9ab1180f8d49bcc1aa3d | extracted | sha1 |
>| a78b33dc7086b59f9232dcf50d4e8590ccfd72ec | extracted | sha1 |
>| a8ee535fde7cb1bec7082c8df9566f0f97d6dd94 | extracted | sha1 |
>| aaf20a6ec982df2a397bb975bf72cf5771128184 | extracted | sha1 |
>| acee3127c9c3f2622a8bccc653cd740206cf66ff | extracted | sha1 |
>| af5b31dc8e381b2e2e07ead1efb37c6d39aa6569 | extracted | sha1 |
>| b093757dbbc9e5e753a86addc10e8e5139ba7dcb | extracted | sha1 |
>| b36a63ad1c5758170ab356666916ac43db0b1e86 | extracted | sha1 |
>| b3d4cf49fcf551f19bdd6af5df50cf43e0e85658 | extracted | sha1 |
>| b3e15a4cc38d11187b9503989d9b1d17585f3bb7 | extracted | sha1 |
>| b71226d430cfaca9adebaf2a584bec5ca3a72319 | extracted | sha1 |
>| b718cc5a5ffcd038efd3f22a838712a410fb632b | extracted | sha1 |
>| ba9449290387275b0a80e03d534208a28614fa26 | extracted | sha1 |
>| bd5d64d9ed4b3a4e9ce11c068f2c368be2c9a0f4 | extracted | sha1 |
>| be3c08b7e5b5c2f7b8f6c28529725f5d73e0c764 | extracted | sha1 |
>| bfe8dca1c5b9e9cffe0c683bf2e87bd6522bd9e9 | extracted | sha1 |
>| c0431f82350b647faf7f38bb6dd5447faafaeced | extracted | sha1 |
>| c28b4a54808e597a70f119d08bc61cec1157984f | extracted | sha1 |
>| c59bee3260b514d321d6bdabcb6d6ed7b88edc6a | extracted | sha1 |
>| c986d550e8c663fb9bb4990c597ae6f553eacb86 | extracted | sha1 |
>| d210cb1c1a3b8eb3d926f76170c1f7afea241bc8 | extracted | sha1 |
>| d50acc1b397e06076d96984ed55f58f720190422 | extracted | sha1 |
>| d7e37398dedae7d0b252131dd63351e24434017c | extracted | sha1 |
>| d9d08cbc21098199b9525df1c7a931aa7d4ed6b3 | extracted | sha1 |
>| da90758c936d2b4b07be6d9ad189f54ceb7c14ba | extracted | sha1 |
>| db4f4f54bfa4cc299db4b7c585b5c92e2c8800f3 | extracted | sha1 |
>| e1bd983e865184f74fcd72cc5c8fda0e5471f84b | extracted | sha1 |
>| eefb7c27460f2ff6a770f8f20d4be44809d894c2 | extracted | sha1 |
>| f37aafac973dd7b5dee1f37642f26b3882d63751 | extracted | sha1 |
>| f491be785a74d3d99feb3158d453c7a2f5020be5 | extracted | sha1 |
>| f715c61244912f292946f63cb3cf0b376110aa5c | extracted | sha1 |
>| f89dd73d45cce148548e35ba18872a08397fb3bb | extracted | sha1 |
>| fd97f7d413d542c1f80c9532b9accd97bf930b6b | extracted | sha1 |
>| 005021b5f9b2672e7c6b846447c0cebeb8f9bd077428e2722948b51975f9660d | extracted | sha256 |
>| 016a28eb17ff195a7a18a69649bb99f58a2f03496b141a95f88f92e28988b0a6 | extracted | sha256 |
>| 099fef1c71250ca5bf9dff4bffdeb04bca1e1f3eb853d1a974bf3a8cd39383ef | extracted | sha256 |
>| 0f407d7194e7955e312b177b16cc409ac89b4d0494c60ce75469fd4c474d4043 | extracted | sha256 |
>| 1074ce0c035e280ff10ce80780840465024b3a019305145c61a26c8315c39164 | extracted | sha256 |
>| 11fa26754c6ed1985e2b4049b06f112450f275b040574518acf51a37fcca3360 | extracted | sha256 |
>| 141156d92537f78e092999fd7f66b99d69813e414b89ca21f0f25e7a71c4a311 | extracted | sha256 |
>| 1566ab7d93d6b46d25d4d06e25bce78a44ac1e40826b90b0b92dce533c919fe4 | extracted | sha256 |
>| 17095cf302d370f7e2f66e4335ef56058ae36e588be67d5530e191f2e95c8dd5 | extracted | sha256 |
>| 178267f61af3e6e76052ea6b7ade224977c524f4a7e72df8a1422c0dd6dd14b6 | extracted | sha256 |
>| 19b1060bedc50b9362640395e3ace60622228edd29caa54228c5b3b4e2a6082d | extracted | sha256 |
>| 1a5612ca4453eeaef55e00a29b94cb55053db0febf5d767465fbf70348c473df | extracted | sha256 |
>| 1e0ca5e091883e134828d8efda9866955212a455837bf6343e112afd2d5673d5 | extracted | sha256 |
>| 2016b27bbb381338db8a3205fe8391e0970bebe67470ab8fb09567563f625291 | extracted | sha256 |
>| 2572e5fe6786c52232c894641858abeef9c159200bf1f47acd5418e7e8b703e9 | extracted | sha256 |
>| 2a4cb70fd5a06adf1eee7e6d4cb89a4c8c92978cfa51bde8e3360b58fb62e49d | extracted | sha256 |
>| 2b52e902c2940fc007833114f30f1f54161f84da2f357b83d29b8c1134fb9a5d | extracted | sha256 |
>| 2d35cc1bb51d974de29e8fcc3b9afb5dfcb7e7a3027b9a009dbc289dd99c2748 | extracted | sha256 |
>| 3083d74bc9f52470c62df3c711249fa60df4164762e2575139684f9ba3c71240 | extracted | sha256 |
>| 31acb2b8cf32b6081522359e4b6fd035a3c5de87e5cae667dc44406b31125cfd | extracted | sha256 |
>| 366de179cdd67383a1483796335457797b853481ca0e5408659a11ae5d5e7b8e | extracted | sha256 |
>| 384b850d0e1698e1592609245e0caa3e9e1e5c03641f055b9115a86fd781a7da | extracted | sha256 |
>| 3b63770b6f507105dcd72414e7bdaef44852cd76ad48647b493e84702e7eef3d | extracted | sha256 |
>| 40f873a43330c92904fa5763b509a2b651b4b29d0d2081bbb5ce10d2d12443be | extracted | sha256 |
>| 4172d573062ad265f7d322d38883ccddff7b05e0820fb7ec3cf9801ebae64ed7 | extracted | sha256 |
>| 4432bbd1a390874f3f0a503d45cc48d346abc3a8c0213c289f4b615bf0ee84f3 | extracted | sha256 |
>| 46aade266c90ebc02d4c8018f537ed3043cd5486fea77d68955ea1613aa5458b | extracted | sha256 |
>| 488c2c65b0b94be87b4c0036a098df25ee4f6cd2bf194b6f1a15441f2ee1db7d | extracted | sha256 |
>| 4a6b711a3a224a9451e043be2ec2475c2849243601f45729611acf55617bb5e6 | extracted | sha256 |
>| 51e2236f5764848a02fb5673420699a12b78ff19c78ca0509a18b24f6b7d2b50 | extracted | sha256 |
>| 55759ff83e70935bc16506acc584db6f7b1d4e7f3a4fba044ca90a8e3e5241e0 | extracted | sha256 |
>| 57a677b2cf2db05bd8a494ab4cbc9322cfde33b91220ed1080c1cf13f84fbf2e | extracted | sha256 |
>| 600672e9164d0201ebb0349111994910105ad61386ca58c5d67556efa66f35c6 | extracted | sha256 |
>| 63a415feb02b52c34543ae9df5b069b1918d00e752bab94158a7380843d6cd06 | extracted | sha256 |
>| 6cb1b6e339a9117c2b25eba1515fe7ab9d616c262523dfdd12c76415d080f478 | extracted | sha256 |
>| 6e7b135be3e92d0709f0b7773202a7c3758233ecab4635700a464208cc9950c9 | extracted | sha256 |
>| 76ec85daea72b0c471fd559d3daa79ee9dc5e732015f6c698341ef9c94b84991 | extracted | sha256 |
>| 796daed8551007a9f7bf760a41de33dc92bfc32e6fb157f4e6af762ef2cce22b | extracted | sha256 |
>| 7d73afa3dabaeec33cc7f5b2ff30f9489db7ed082234e42c78ae35aa52bb3a41 | extracted | sha256 |
>| 80c829f2db2ec88e55f34cf3473614d947ccc0ba39b2e267a8a93830470e5df0 | extracted | sha256 |
>| 844b02484b208c34b408fb61e4c8590970010997ed8ba2aee2009a33b01d7797 | extracted | sha256 |
>| 856bc7c058908168d12f859c3aa35a72a914be0c3b5dfdd9584fdbfaeb612bec | extracted | sha256 |
>| 8909691ae3c674cc2bfcdd145c08eedca21c89b98403b38da958ab9ba1cefff6 | extracted | sha256 |
>| 8a0440855c7e08ecffde06a89f2182ea4cc3f493e75566170f040575a6a826e0 | extracted | sha256 |
>| 8d16cbada454edb42478219342651dd426815e703e446319a1ee690542eaef84 | extracted | sha256 |
>| 8e24a437490f1aa421b8ee7a95a0667041840b8cd10fd9a4d057ad73cd103864 | extracted | sha256 |
>| 8faa9b6971eda5eb1ddab5d94adb4ae59c8455459b50dcbe3420f2c8d30914b7 | extracted | sha256 |
>| 8fbd98643ff35c35a7034ce402dc8e519af1497c80a509c26d8b48215862d14f | extracted | sha256 |
>| 90cdec4faf737adb2623fd668b3f8b023acae1aef55d1596cc1371c6ca6c753c | extracted | sha256 |
>| 916f43a76ee027ed5cfae1932e5211ac5d2023773f1af6f8f1e1e836c81aceef | extracted | sha256 |
>| 9b32c07c158eec7eb6a0bb8df3961633db49faef0f06d54fe94fa8d50d056331 | extracted | sha256 |
>| a43cfc443e8b9bfd88d81a8b45360f1327889b9ba4d5db2e89c0558c2fdb6333 | extracted | sha256 |
>| a79100b37dc27bb1198c8f56199e5f1ff686ca039cf6d76dd40a0acdd53f8cc7 | extracted | sha256 |
>| a8156f1a6b38353aa444924406ad47736c6aaf90e534db826bc68260a5583725 | extracted | sha256 |
>| a98058ead416c9036e7b91817b09f1df2ce6f2e5b1a690f620d4661019f531f1 | extracted | sha256 |
>| a9a62a6c3536f17922b116d5b258c7c10ba687f4734fa91df02f13c72510d1b5 | extracted | sha256 |
>| aa853c997b93d102ba4201102c4f42fd52c55e69d1c54f08783df9c600bc5884 | extracted | sha256 |
>| aec564e08b5b0e6efaafcb5e32acdf4f2595cefbee8f3bb8fc529adc74dd82e2 | extracted | sha256 |
>| b177f1717f348b2dbe913c81ae906f31b12ce240886548c335fcd931b09be3e3 | extracted | sha256 |
>| b5e72042bc0ebb598affa5dc5adde62afa4af7d11a61c9682c10807bd8e665f3 | extracted | sha256 |
>| b7139337e7a72822ac22eff838e3e955f713203298b4a6c9c00e7a1e19245154 | extracted | sha256 |
>| b7b9555f4c2a4445f8d786bfad4c12bcf3c664a0f40d0576607cfa847d58eac2 | extracted | sha256 |
>| b9865a550841bc99887b87502fcad20f1d0ceb3b84d88a1c70d6593101f6cd66 | extracted | sha256 |
>| b9d5bcb6f63d7a3e20dd4ea343d9cefecd5770aa806c6471fa3da30d48888b26 | extracted | sha256 |
>| c001f8e6a175f024e553986cea4453e3f95396d8b5a1b19c3242344bcfc5e4f0 | extracted | sha256 |
>| c22d444aa5c44eeee70ec8e21f267faf8f5642507a331a304e026a798a7810ea | extracted | sha256 |
>| c23e0d3598c4477caa7a75632c5b158ea73db3a02dfeccee695528a8efa4aeac | extracted | sha256 |
>| c30ca342482170bcd279a029af1e6218a161b64c4bc2e725e63ded3bfd49983e | extracted | sha256 |
>| c444e5a71483c95ae89468ff5ab420d15e71b33b05372bd3a1db6c435e996796 | extracted | sha256 |
>| c4eada327d83caebe0929b3aa638db533a2d30c4ef15a3dc4f445245dfd53797 | extracted | sha256 |
>| c70c2b47003a69646fc8347ed31504fdc4d6f0941ebae8761ef0cadce6c56e88 | extracted | sha256 |
>| c7ec4c42203f4931261ebf4e456a9bed0c389f9043ed8b6bfb97d7b9eb383319 | extracted | sha256 |
>| c896ab2ab4f249ddd2e8be2bdb9e9956bcb5248c256e43e6474ef857f7f9141e | extracted | sha256 |
>| caf97c83f8926849e2f6eae191e2b9213550f410f6601c62f0aa7d3485ce79e5 | extracted | sha256 |
>| cf62241aab4cc80a668ba9b676e0a55e870b945e38b710cdb3cd61c8ce6d7bd3 | extracted | sha256 |
>| d18c35ae32ab207f8479c372e82aa6934f84aa640cc7bbffd285e5d40e17ad58 | extracted | sha256 |
>| d5930d3ebabc0aa8e731fd6c249dc0cf54922505e0cf8b1629f895c47cb46f84 | extracted | sha256 |
>| d62251a0f4874e2b56f27c1b44c399d29d57db85cded1b1bd758911eeb3f7e2e | extracted | sha256 |
>| d683ab7b817616669795b19aa794270e3b957caa3b271bdf665401203c20d6bc | extracted | sha256 |
>| d7b088b36bd43bd4325f7ab98cc6ef1f021559faf97d8d45d23424b0a8fe0e63 | extracted | sha256 |
>| e2f2b23b31261c95e53c178183cebccfe55c9057d756fdef07af6124491e6413 | extracted | sha256 |
>| e432f683769629d5c5712f4b34f26ddac599b4ba9c360f58eb0f8ca8a3eba6f9 | extracted | sha256 |
>| e4c1015408bbb08ddd32da612e63ccdfe4e6ed8f6b3048ade7b9b21d520e7abc | extracted | sha256 |
>| e71ca8e2723e179767ace6aa690ba08a63e83c4b700bef411f56519310788136 | extracted | sha256 |
>| e889837f9b3205d9b8f6c4341f3655258cf266fa3e9c33056b4fa52e02550237 | extracted | sha256 |
>| eb5544fbad7bff6c43ff8b03ba7b122450c6577379fc6f6e5bc05a0b482ace74 | extracted | sha256 |
>| f40bbbe902680c45c2192ec261e1e32a2a561b626bb588c60ef712aaf49bf5f9 | extracted | sha256 |
>| f42b6e6d7dbf55534906d6d4102957d2ff38d7660ac1f75ff7572c410992b545 | extracted | sha256 |
>| f53612ca03a286c2c94e07ab0c49ea7c7cb51cff2f6674b36fc0667f70b93c4d | extracted | sha256 |
>| f629edf2af597ab193ba750e68712024fb3560edb2445cf3162a48df0b2725c4 | extracted | sha256 |
>| f8142377e4387420430e233be0ab491395c5d90b2b3dff9bdc608a836e09ed1b | extracted | sha256 |
>| f87046fbdd9a360b53561a02df2d6ebe87235c5c36c99eb03c1a81c0fa2f5cce | extracted | sha256 |
>| fa76c2a832dd0b351f1efd4a80ba8df2aaca9afa489a4de15182d81d12368a81 | extracted | sha256 |
>| fb2556d2f1dc4deb27de7c59214134ea2839fd78580ce158943e94cf04819a61 | extracted | sha256 |
>| fb3bd8af4332bd00f548a30e43e5e0180369afc581f0bdc04dba70e9296d5d3f | extracted | sha256 |
>| fc71e29adcf3f47d12ddcdbe3313f887c61f177d3c56346222f4b3d56324eec2 | extracted | sha256 |
>| fd08e05c9ccc86940f430aed203fbd9366bc015c3d977baf18c306ce70cc2390 | extracted | sha256 |
>| ff264234364940f1843d23207b67ba71554670d6372a0ce9b7dcd98915d16758 | extracted | sha256 |
>| 55759ff83e70935bc16506acc584db6f7b1d4e7f3a4fba044ca90a8e3e5241e0 | input | sha256 |
>| 178267f61af3e6e76052ea6b7ade224977c524f4a7e72df8a1422c0dd6dd14b6 | runtime | sha256 |
>| 2a4cb70fd5a06adf1eee7e6d4cb89a4c8c92978cfa51bde8e3360b58fb62e49d | runtime | sha256 |
>| 4172d573062ad265f7d322d38883ccddff7b05e0820fb7ec3cf9801ebae64ed7 | runtime | sha256 |
>| 55759ff83e70935bc16506acc584db6f7b1d4e7f3a4fba044ca90a8e3e5241e0 | runtime | sha256 |
>| b798e287d0d73c389f4ad8e0e55f88aa16d42757cd5ff9168bb855807ab66b6a | runtime | sha256 |
>| c4eada327d83caebe0929b3aa638db533a2d30c4ef15a3dc4f445245dfd53797 | runtime | sha256 |
>| d7b088b36bd43bd4325f7ab98cc6ef1f021559faf97d8d45d23424b0a8fe0e63 | runtime | sha256 |
>| hxxp://32.cc | runtime | url |
>| hxxp://allocator.cc | runtime | url |
>| hxxp://apply.cc | runtime | url |
>| hxxp://arena.cc | runtime | url |
>| hxxp://backup.cc | runtime | url |
>| hxxp://behaviors.cc | runtime | url |
>| hxxp://blink.net | runtime | url |
>| hxxp://call.cc | runtime | url |
>| hxxp://chrome.cc | runtime | url |
>| hxxp://command.cc | runtime | url |
>| hxxp://commands.cc | runtime | url |
>| hxxp://common.cc | runtime | url |
>| hxxp://crash.pb.cc | runtime | url |
>| hxxp://dir.cc | runtime | url |
>| hxxp://elf.cc | runtime | url |
>| hxxp://event.cc | runtime | url |
>| hxxp://experiment.cc | runtime | url |
>| hxxp://gzip.cc | runtime | url |
>| hxxp://handler.cc | runtime | url |
>| hxxp://helper.cc | runtime | url |
>| hxxp://impl.cc | runtime | url |
>| hxxp://in.cc | runtime | url |
>| hxxp://info.cc | runtime | url |
>| hxxp://install.cc | runtime | url |
>| hxxp://integration.cc | runtime | url |
>| hxxp://io.cc | runtime | url |
>| hxxp://item.cc | runtime | url |
>| hxxp://list.cc | runtime | url |
>| hxxp://lite.cc | runtime | url |
>| hxxp://log.cc | runtime | url |
>| hxxp://loop.cc | runtime | url |
>| hxxp://main.cc | runtime | url |
>| hxxp://memory.cc | runtime | url |
>| hxxp://minidump.cc | runtime | url |
>| hxxp://parameters.cc | runtime | url |
>| hxxp://preferences.cc | runtime | url |
>| hxxp://program.cc | runtime | url |
>| hxxp://range.cc | runtime | url |
>| hxxp://reader.cc | runtime | url |
>| hxxp://recorder.cc | runtime | url |
>| hxxp://report.pb.cc | runtime | url |
>| hxxp://reports.cc | runtime | url |
>| hxxp://seeker.cc | runtime | url |
>| hxxp://server.cc | runtime | url |
>| hxxp://settings.cc | runtime | url |
>| hxxp://shortcut.cc | runtime | url |
>| hxxp://snapshot.cc | runtime | url |
>| hxxp://source.cc | runtime | url |
>| hxxp://state.cc | runtime | url |
>| hxxp://storage.cc | runtime | url |
>| hxxp://stream.cc | runtime | url |
>| hxxp://thread.cc | runtime | url |
>| hxxp://tracker.cc | runtime | url |
>| hxxp://trial.cc | runtime | url |
>| hxxp://uninstall.cc | runtime | url |
>| hxxp://util.cc | runtime | url |
>| hxxp://version.cc | runtime | url |
>| hxxp://versions.cc | runtime | url |
>| hxxp://visitor.cc | runtime | url |
>| hxxp://watcher.cc | runtime | url |
>| hxxp://win.cc | runtime | url |
>| hxxp://win32.cc | runtime | url |
>| hxxp://worker.cc | runtime | url |
>| hxxp://writable.cc | runtime | url |
>| hxxp://writer.cc | runtime | url |
