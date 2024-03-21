FortiSandbox is an advanced security tool that goes beyond standard sandboxing. It combines proactive mitigation, enhanced threat detection, and in-depth reporting, using Fortinet's dynamic antivirus technology, dual-level sandboxing, and FortiGuard cloud integration to counter advanced threats. It effectively detects viruses, Advanced Persistent Threats (APTs), and malicious URLs, integrating seamlessly with existing Fortinet devices like FortiGate and FortiMail for comprehensive network protection.
This integration was integrated and tested with version 4.4.3 of FortiSandboxv2.

Some changes have been made that might affect your existing content.
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---fortisandbox-v2).

## Configure FortiSandbox v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FortiSandbox v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | Username |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### file

***
Runs reputation on files.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. Supports sha256, sha1, md5. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.Extension | String | The file extension. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Message | String | Optional message to show an API response. For example, "Not found". |

#### Command example
```!file file=936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "file",
        "Vendor": "FortiSandboxv2"
    },
    "File": {
        "Extension": "txt",
        "Hashes": [
            {
                "type": "SHA256",
                "value": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
            }
        ],
        "Name": "helloworld.txt",
        "SHA256": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### url

***
Runs reputation on URLs.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. |
| URL.DetectionEngines | String | The total number of engines that checked the indicator. |
| URL.PositiveDetections | String | The number of engines that positively detected the indicator as malicious. |
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. |
| URL.Malicious.Description | String | A description of the malicious URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Message | String | Optional message to show an API response. For example, "Not found". |

#### Command example
```!url url=www.google.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "www.google.com",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "url",
        "Vendor": "FortiSandboxv2"
    },
    "URL": {
        "Data": "www.google.com"
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### fortisandbox-submission-file-upload

***
Scheduled command to upload any file type to be sandboxed. The system swiftly identifies and mitigates threats in files.

#### Base Command

`fortisandbox-submission-file-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | An entry ID of any file to be uploaded for analysis. | Required |
| comment | Comment field, max characters allowed: 255. | Optional |
| process_timeout | Cancel processing a submission when timeout in seconds before entering virtual machine. | Optional |
| skip_steps | Comma-separated list of steps to skip from file analysis. Do not use this parameter if no step to skip. Possible values are: anti_virus, cloud, sandbox, static_scan. | Optional |
| archive_passwords | Comma-separated list of passwords needed for extracting archived/zipped files. Non-ASCII passwords are invalid. | Optional |
| overwrite_vm_list | Comma-separated list of virtual machines to use. If this field is not set, default ones will be used. | Optional |
| force_vm_scan | Whether to force the file to be scanned in a virtual machine. Possible values are: true, false. Default is false. | Optional |
| add_to_threat_package | Specifies whether the uploaded sample should be included in the threat package, based on meeting certain malware criteria. When set to true, the system will evaluate the sample and, if it qualifies, add it to the malware package. The default setting is false, indicating that the sample will not be added unless explicitly requested. Possible values are: false, true. Default is false. | Optional |
| record | Record scan process in video if VMs are involved. Possible values are: true, false. Default is false. | Optional |
| enable_ai | Enable Deep-AI mode for this scanning. Possible values are: true, false. Default is false. | Optional |
| get_scan_report | Whether to return a PDF scan report at the end of the file analysis. Possible values are: true, false. Default is false. | Optional |
| interval | The interval between each poll in seconds. Min value is `10`. Default is 30. | Optional |
| timeout | The timeout for the polling in seconds. Default is 600. | Optional |
| sid | The submission ID. Hidden argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSandbox.Submission.name | String | The input file name. |
| FortiSandbox.Submission.sid | String | The ID of the submission. |
| FortiSandbox.Submission.jid | String | The ID of the job. |
| FortiSandbox.Submission.start_ts | Number | Start scan time in epoch, UTC. |
| FortiSandbox.Submission.finish_ts | Number | Finish scan time in epoch, UTC. |
| FortiSandbox.Submission.now | Number | FortiSandbox's time in epoch, UTC. |
| FortiSandbox.Submission.untrusted | Number | 0: the result can be trusted 1: since this file's scan, scan environment has changed. |
| FortiSandbox.Submission.rating | String | The rating can be one or more of the following: Clean, Low Risk, Medium Risk, High Risk, Malicious, or Other. For archive files, the possible ratings of all files in the archive are displayed. During the file scan, the rating is displayed as N/A. If a scan times out or is terminated by the system, the file will have an Other rating. |
| FortiSandbox.Submission.score | Number | One of the following: \`RISK_UNKNOWN -1\`, \`RISK_CLEAN 0\`, \`RISK_MALICIOUS 1\`, \`RISK_HIGH 2\`, \`RISK_MEDIUM 3\`, \`RISK_LOW 4\`. |
| FortiSandbox.Submission.sha256 | String | The SHA256 of the submitted file. |
| FortiSandbox.Submission.sha1 | String | The SHA1 of the submitted file. |
| FortiSandbox.Submission.malware_name | String | Virus name if it's a known virus. |
| FortiSandbox.Submission.vid | Number | The virus ID. Detailed information of the virus can be found at: \`http://www.fortiguard.com/encyclopedia/virus/\#id=virus_id\` by replacing \`virus_id\` with the given value. |
| FortiSandbox.Submission.infected_os | String | The OS version of the FortiSandbox VM that was used to make the suspicious verdict. |
| FortiSandbox.Submission.detection_os | String | The name of the virtual machine images that scanned the file. |
| FortiSandbox.Submission.rating_source | String | One of: \`AV Scan\`, \`Cloud Query\`, \`Sandboxing\`, \`Static Scan\`, \`Other\`. |
| FortiSandbox.Submission.category | String | One of: \`Clean\`, \`Unknown\`, \`Infector\`, \`Worm\`, \`Botnet\`, \`Hijack\`, \`Stealer\`, \`Backdoor\`, \`Injector\`, \`Rootkit\`, \`Adware\`, \`Dropper\`, \`Downloader\`, \`Trojan\`, \`Riskware\`, \`Grayware\`, or \`Attacker\`. |
| FortiSandbox.Submission.detail_url | String | URL to the job overview. |
| FortiSandbox.Submission.download_url | String | The input file name encoded in Base64. |
| FortiSandbox.Submission.false_positive_negative | Number | Not false positive or false negative, 1: false positive, 2: false negative. |
| FortiSandbox.Submission.file_name | String | The name of the submitted file. |
| File.Size | Number | The size of the file. |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.Extension | String | The file extension. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Message | String | Optional message to show an API response. For example, "Not found". |

#### Command example
```!fortisandbox-submission-file-upload entry_id=418@e75b29e7-17a8-41bc-8555-ef233dd8bac9```
#### Human Readable Output

>## No jobs were created yet for the submission 7048126795285831956.

### fortisandbox-submission-url-upload

***
Scheduled command to upload URLs through a text file or directly to be sandboxed individually. The system rigorously examines URLs for online security hazards.

#### Base Command

`fortisandbox-submission-url-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | An entry ID of a text file to be uploaded for analysis. Each URL within file the must be separated with new lines. | Optional |
| urls | Comma-separated list of URLs to upload to scan. | Optional |
| comment | Comment field, max characters allowed: 255. | Optional |
| process_timeout | The time period to stop the URLs scan, in seconds (between 30 and 1200 seconds). | Optional |
| depth | The recursive depth in which URLs are examined. Level 0 for original URL page (between 0 and 5). | Optional |
| overwrite_vm_list | Comma-separated list of virtual machines to use. If this field is not set, default ones will be used. | Optional |
| force_vm_scan | Whether to force the file to be scanned in a virtual machine. Possible values are: true, false. Default is false. | Optional |
| add_to_threat_package | Specifies whether the uploaded sample should be included in the threat package, based on meeting certain malware criteria. When set to true, the system will evaluate the sample and, if it qualifies, add it to the malware package. The default setting is false, indicating that the sample will not be added unless explicitly requested. Possible values are: false, true. Default is false. | Optional |
| record | Record scan process in video if VMs are involved. Possible values are: true, false. | Optional |
| enable_ai | Enable Deep-AI mode for this scanning. Possible values are: true, false. | Optional |
| get_scan_report | Whether to return a PDF scan report at the end of the file analysis. Note: Generating PDF scan reports can be time-consuming, especially when analyzing multiple URLs. Possible values are: true, false. Default is false. | Optional |
| interval | The interval between each poll in seconds. Min value is `10`. Default is 30. | Optional |
| timeout | The timeout for the polling in seconds. Default is 600. | Optional |
| sid | The submission ID. Hidden argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSandbox.Submission.name | String | The input URL/file name. |
| FortiSandbox.Submission.sid | String | The ID of the submission. |
| FortiSandbox.Submission.jid | String | The ID of the job. |
| FortiSandbox.Submission.start_ts | Number | Start scan time in epoch, UTC. |
| FortiSandbox.Submission.finish_ts | Number | Finish scan time in epoch, UTC. |
| FortiSandbox.Submission.now | Number | FortiSandbox's time in epoch, UTC. |
| FortiSandbox.Submission.untrusted | Number | 0: the result can be trusted 1: since this file's scan, scan environment has changed. |
| FortiSandbox.Submission.rating | String | The rating can be one or more of the following: Clean, Low Risk, Medium Risk, High Risk, Malicious, or Other. For archive files, the possible ratings of all files in the archive are displayed. During the file scan, the rating is displayed as N/A. If a scan times out or is terminated by the system, the file will have an Other rating. |
| FortiSandbox.Submission.score | Number | One of the following: \`RISK_UNKNOWN -1\`, \`RISK_CLEAN 0\`, \`RISK_MALICIOUS 1\`, \`RISK_HIGH 2\`, \`RISK_MEDIUM 3\`, \`RISK_LOW 4\`. |
| FortiSandbox.Submission.sha256 | String | The SHA256 of the submitted file. |
| FortiSandbox.Submission.sha1 | String | The SHA1 of the submitted file. |
| FortiSandbox.Submission.malware_name | String | Virus name if it's a known virus. |
| FortiSandbox.Submission.vid | Number | The virus ID. Detailed information of the virus can be found at: \`http://www.fortiguard.com/encyclopedia/virus/\#id=virus_id\` by replacing \`virus_id\` with the given value. |
| FortiSandbox.Submission.infected_os | String | The OS version of the FortiSandbox VM that was used to make the suspicious verdict. |
| FortiSandbox.Submission.detection_os | String | The name of the virtual machine images that scanned the file. |
| FortiSandbox.Submission.rating_source | String | One of: \`AV Scan\`, \`Cloud Query\`, \`Sandboxing\`, \`Static Scan\`, \`Other\`. |
| FortiSandbox.Submission.category | String | One of: \`Clean\`, \`Unknown\`, \`Infector\`, \`Worm\`, \`Botnet\`, \`Hijack\`, \`Stealer\`, \`Backdoor\`, \`Injector\`, \`Rootkit\`, \`Adware\`, \`Dropper\`, \`Downloader\`, \`Trojan\`, \`Riskware\`, \`Grayware\`, or \`Attacker\`. |
| FortiSandbox.Submission.detail_url | String | URL to the job overview. |
| FortiSandbox.Submission.download_url | String | The input URL encoded in Base64. |
| FortiSandbox.Submission.false_positive_negative | Number | Not false positive or false negative, 1: false positive, 2: false negative |
| FortiSandbox.Submission.file_name | String | The name of the submitted file. |
| URL.Data | String | The URL. |
| URL.DetectionEngines | String | The total number of engines that checked the indicator. |
| URL.PositiveDetections | String | The number of engines that positively detected the indicator as malicious. |
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. |
| URL.Malicious.Description | String | A description of the malicious URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Message | String | Optional message to show an API response. For example, "Not found". |

#### Command example
```!fortisandbox-submission-url-upload urls=www.google.com```
#### Human Readable Output

>## No jobs were created yet for the submission 7048126856924000534.

### fortisandbox-submission-cancel

***
Cancel a running job submission. Note: Jobs that are already being processed cannot be canceled, only jobs that are in the queue.

#### Base Command

`fortisandbox-submission-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The submission ID. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortisandbox-submission-cancel id=7047969418633282747```
#### Human Readable Output

>## The cancellation of the submission 7047969418633282747 was successfully sent.

### fortisandbox-submission-job-verdict

***
Get the verdict of the provided job.

#### Base Command

`fortisandbox-submission-job-verdict`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The job ID. Use `!forisandbox-submission-job-list` to fetch a list of job IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSandbox.Submission.name | String | The input URL/file name. |
| FortiSandbox.Submission.start_ts | Number | Start scan time in epoch, UTC. |
| FortiSandbox.Submission.finish_ts | Number | Finish scan time in epoch, UTC. |
| FortiSandbox.Submission.now | Number | FortiSandbox's time in epoch, UTC. |
| FortiSandbox.Submission.behavior_info | Number | 0: There is no analytic report for this URL. 1: There is an analytic report for this URL. |
| FortiSandbox.Submission.category | String | One of: \`Clean\`, \`Unknown\`, \`Infector\`, \`Worm\`, \`Botnet\`, \`Hijack\`, \`Stealer\`, \`Backdoor\`, \`Injector\`, \`Rootkit\`, \`Adware\`, \`Dropper\`, \`Downloader\`, \`Trojan\`, \`Riskware\`, \`Grayware\`, or \`Attacker\`. |
| FortiSandbox.Submission.detection_os | String | The name of the virtual machine images that scanned the file. |
| FortiSandbox.Submission.false_positive_negative | Number | Not false positive or false negative, 1: false positive, 2: false negative. |
| FortiSandbox.Submission.infected_os | String | The OS version of the FortiSandbox VM that was used to make the suspicious verdict. |
| FortiSandbox.Submission.malware_name | String | Virus name if it's a known virus. |
| FortiSandbox.Submission.rating | String | The rating can be one or more of the following: Clean, Low Risk, Medium Risk, High Risk, Malicious, or Other. For archive files, the possible ratings of all files in the archive are displayed. During the file scan, the rating is displayed as N/A. If a scan times out or is terminated by the system, the file will have an Other rating. |
| FortiSandbox.Submission.rating_source | String | One of: \`AV Scan\`, \`Cloud Query\`, \`Sandboxing\`, \`Static Scan\`, \`Other\`. |
| FortiSandbox.Submission.score | Number | One of the following: \`RISK_UNKNOWN -1\`, \`RISK_CLEAN 0\`, \`RISK_MALICIOUS 1\`, \`RISK_HIGH 2\`, \`RISK_MEDIUM 3\`, \`RISK_LOW 4\`. |
| FortiSandbox.Submission.untrusted | Number | 0: the result can be trusted 1: since this files' scan, scan environment has changed. |
| FortiSandbox.Submission.vid | Number | The virus ID. Detailed information of the virus can be found at: \`http://www.fortiguard.com/encyclopedia/virus/\#id=virus_id\` by replacing \`virus_id\` with the given value. |
| FortiSandbox.Submission.detail_url | String | URL to the job overview. |
| FortiSandbox.Submission.download_url | String | The input URL/file name encoded in Base64. |
| FortiSandbox.Submission.jid | String | The ID of the job. |
| FortiSandbox.Submission.sha1 | String | The SHA1 hash of the file. |
| FortiSandbox.Submission.sha256 | String | The SHA256 hash of the file. |
| File.Size | Number | The size of the file. |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.Extension | String | The file extension. |
| URL.Data | String | The URL. |
| URL.DetectionEngines | String | The total number of engines that checked the indicator. |
| URL.PositiveDetections | String | The number of engines that positively detected the indicator as malicious. |
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. |
| URL.Malicious.Description | String | A description of the malicious URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Message | String | Optional message to show an API response. For example, "Not found". |

#### Command example
```!fortisandbox-submission-job-verdict id=7047959279104315513```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af",
        "Message": "https://0.0.0.0/job-detail/?sid=7047959252528592869&jid=7047959279104315513&req_type=file-csearch",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "file",
        "Vendor": "FortiSandboxv2"
    },
    "File": {
        "Extension": "txt",
        "Hashes": [
            {
                "type": "SHA1",
                "value": "6adfb183a4a2c94a2f92dab5ade762a47889a5a1"
            },
            {
                "type": "SHA256",
                "value": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
            }
        ],
        "Name": "helloworld.txt",
        "SHA1": "6adfb183a4a2c94a2f92dab5ade762a47889a5a1",
        "SHA256": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
    },
    "FortiSandbox": {
        "Submission": {
            "category": "NotApplicable",
            "detail_url": "https://0.0.0.0/job-detail/?sid=7047959252528592869&jid=7047959279104315513&req_type=file-csearch",
            "detection_os": "",
            "download_url": "aGVsbG93b3JsZC50eHQK",
            "false_positive_negative": 0,
            "file_name": "helloworld.txt",
            "finish_ts": 1710245223,
            "ftype": "txt",
            "infected_os": "",
            "jid": "7047959279104315513",
            "malware_name": "N/A",
            "name": "helloworld.txt\n",
            "now": 1710254987,
            "rating": "Clean",
            "rating_source": "Static Scan Engine",
            "score": 0,
            "sha1": "6adfb183a4a2c94a2f92dab5ade762a47889a5a1",
            "sha256": "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af",
            "start_ts": 1710245223,
            "untrusted": 1,
            "vid": 0
        }
    }
}
```

#### Human Readable Output

>### The verdict for the job 7047959279104315513:
>|Jid|Name|Start Ts|Finish Ts|Category|Malware Name|Rating|Detail Url|
>|---|---|---|---|---|---|---|---|
>| 7047959279104315513 | helloworld.txt<br/> | 1710245223 | 1710245223 | NotApplicable | N/A | Clean | https:<span>//</span>0.0.0.0/job-detail/?sid=7047959252528592869&jid=7047959279104315513&req_type=file-csearch |


### fortisandbox-submission-job-list

***
Get a list of jobs that were created from a submission.

#### Base Command

`fortisandbox-submission-job-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The submission ID. Use `!fortisandbox-submission-file-upload` or `!fortisandbox-submission-url-upload` to create a submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSandbox.Submission.sid | String | The ID of the submission. |
| FortiSandbox.Submission.jid | String | The ID of the job. |

#### Command example
```!fortisandbox-submission-job-list id=7047969418633282747```
#### Context Example
```json
{
    "FortiSandbox": {
        "Submission": {
            "jid": "7047969436160637757",
            "sid": "7047969418633282747"
        }
    }
}
```

#### Human Readable Output

>### The submission 7047969418633282747 job IDs:
>|Jid|
>|---|
>| 7047969436160637757 |


### fortisandbox-submission-job-report

***
Get a PDF report of the provided submission.

#### Base Command

`fortisandbox-submission-job-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | The job ID or SHA256 of the scanned file or URL. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | File name. |
| InfoFile.EntryID | String | The entry ID of the report. |
| InfoFile.Size | Number | File size. |
| InfoFile.Type | String | File type "pdf". |
| InfoFile.Info | String | Basic information of the file. |

#### Command example
```!fortisandbox-submission-job-report identifier=7047959279104315513```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "449@e75b29e7-17a8-41bc-8555-ef233dd8bac9",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "7047959279104315513.pdf",
        "Size": 2605722,
        "Type": "PDF document, version 1.4"
    }
}
```

#### Human Readable Output



## Breaking changes from the previous version of this integration - FortiSandbox v2
### Commands
#### The following commands were removed in this version:
* ***fortisandbox-simple-file-rating-sha256*** - this command was replaced by ***file***.
* ***fortisandbox-simple-file-rating-sha1*** - this command was replaced by ***file***.
* ***fortisandbox-url-rating*** - this command was replaced by ***url***.
* ***fortisandbox-get-file-verdict-detailed*** - this command was replaced by ***file***.
* ***fortisandbox-upload-file*** - this command was replaced by ***fortisandbox-submission-upload-file***.
* ***fortisandbox-query-job-verdict*** - this command was replaced by ***fortisandbox-submission-job-verdict***.
* ***fortisandbox-jobid-from-submission*** - this command was replaced by ***fortisandbox-submission-job-list***.
* ***fortisandbox-get-pdf-report*** - this command was replaced by ***fortisandbox-submission-job-report***.
* ***fortisandbox-upload-urls*** - this command was replaced by ***fortisandbox-submission-upload-url***.
