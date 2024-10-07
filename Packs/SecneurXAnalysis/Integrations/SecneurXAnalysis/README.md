Use SecneurX Analysis  pack to provide threat analysts and incident response teams with the advanced malware isolation and inspection environment needed to safely execute advanced malware samples, and understand their behavior.
You can use the pack's playbooks to detonate both files and URLs. SecneurX Analysis performs both static and dynamic analysis of advanced threats, including zero day and targeted attacks.

This integration was integrated and tested with version 1.0.0 of SecneurX Analysis

## Configure SecneurX Analysis in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Input the url of SecneurX Analysis server. | True |
| API Key | Input the API key to access the sandbox. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### snx-analysis-get-verdict
***
Get verdict summary report of the analyzed sample


#### Base Command

`snx-analysis-get-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Input the Task UUID value obtained as response from submission. | Required |
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it's ready. Default is False. | Optional |
| interval | Frequency that the polling command will run (seconds). Default is set to "30" | Optional |
| timeout | Amount of time to poll before declaring a timeout and resuming the playbook (in seconds). Default is set "600". | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecneurXAnalysis.Verdict.task_uuid | String | Task UUID is unique id of analyzed sample | 
| SecneurXAnalysis.Verdict.verdict | String | Verdict is summary result of analyzed sample | 
| SecneurXAnalysis.Verdict.sha256 | String | SHA256 value find from analyzed sample | 
| SecneurXAnalysis.Verdict.file_name | String | File Name of analyzed sample | 
| SecneurXAnalysis.Verdict.status | String | Analysis queued sample state | 
| SecneurXAnalysis.Verdict.submission_time | String | Analysis queued sample submission time value. |

#### Human Readable Output
|sha256|status|submission_time|task_uuid|url|verdict|
| 2323714b7571c9c87e71799499d577126a487ff58177247e5b67a83a866f83a5 | Completed | 2022-07-22 07:37:10 | 2323714b7571c9c87e71799499d577126a487ff58177247e5b67a83a866f83a5-2022-07-22-07-37-10 | https://google.com | Clean |

### snx-analysis-get-completed
***
Get the list of submitted samples whose status is marked as "Completed"


#### Base Command

`snx-analysis-get-completed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_hours | Optional. Allows you to specify the number of hours. The value should be as number of hours (e.g. 5) - Lists all the queued samples submitted in the last 5 hrs. | Optional | 
| last_count | Optional. Allows you to specify the max no.of queued samples to list. The value should be number type (e.g. 50) - Lists the last submitted 50 samples that are queued. | Optional | 


#### Context Output

There is no context output for this command.

#### Human Readable Output
|task_uuid|verdict|file_name|report_available|
| ce5869808c1c4e99c7df7122118d06f0b38a7f302d5f5504a419626336156182-2022-07-22-07-45-21 | No Threats |  | true |

### snx-analysis-get-pending
***
Get the list of submitted samples that are still in pending state


#### Base Command

`snx-analysis-get-pending`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_hours | Optional. Allows you to specify the number of hours. The value should be as number of hours (e.g. 5) - Lists all the queued samples submitted in the last 5 hrs. | Optional | 
| last_count | Optional. Allows you to specify the max no.of queued samples to list. The value should be number type (e.g. 50) - Lists the last submitted 50 samples that are queued. | Optional | 


#### Context Output

There is no context output for this command.

#### Human Readable Output
|task_uuid|file_name|status|sha256|
| 4f751e74f7d05e6ebc27de36caa03c889b3d6bb57755aacd454bbce63a0da313-2022-07-21-15-28-20 | 4f751e74f7d05e6ebc27de36caa03c889b3d6bb57755aacd454bbce63a0da313 | Analyzing | 4f751e74f7d05e6ebc27de36caa03c889b3d6bb57755aacd454bbce63a0da313 |

### snx-analysis-get-status
***
Get the status of all the submitted samples


#### Base Command

`snx-analysis-get-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_hours | Optional. Allows you to specify the number of hours. The value should be as number of hours (e.g. 5) - Lists all the queued samples submitted in the last 5 hrs. | Optional | 
| last_count | Optional. Allows you to specify the max no.of queued samples to list. The value should be number type (e.g. 50) - Lists the last submitted 50 samples that are queued. | Optional | 


#### Context Output

There is no context output for this command.

#### Human Readable Output
|task_uuid|file_name|status|sha256|
| ce5869808c1c4e99c7df7122118d06f0b38a7f302d5f5504a419626336156182-2022-07-22-07-45-21 | sample.exe | Completed | ce5869808c1c4e99c7df7122118d06f0b38a7f302d5f5504a419626336156182 |
| 2323714b7571c9c87e71799499d577126a487ff58177247e5b67a83a866f83a5-2022-07-22-07-37-10 | sample_2.dll | Completed | 2323714b7571c9c87e71799499d577126a487ff58177247e5b67a83a866f83a5 |

### snx-analysis-submit-file
***
Submit a file for Analysis


#### Base Command

`snx-analysis-submit-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | Entry ID value of upload file. | Required | 
| Platform | Type the OS platform on which the file to be analysed. Default is set to Windows7. Possible values are Windows7, Windows10, Android, Ubuntu. | Optional | 
| Priority | Type the priority of the sample for analysis. Default is set to Normal. Possible values are High, Normal. | Optional | 
| Duration | Type the duration of the analysis in seconds. Not all malicious programs are active right after the launch. Some of them take time to fully reveal the attack vectors. Default is set to 120. Possible values are 120, 180, 240, 300. | Optional | 
| Extension | If you want the file for submission to be treated and analysed as a specific file extension, mention it. | Optional | 
| Reboot | Reboot the system during the analysis. Default is set to 'False'. Possible values are True, False. | Optional | 
| File Password | If the file for submission is protected with a user-defined password, please enter the password for our system to open and detonate it. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecneurXAnalysis.SubmitFile.task_uuid | String | Task UUID is unique ID for submitted file. Use this ID for get the report and verdict. | 
| SecneurXAnalysis.SubmitFile.submission_time | String | Submission Time Created at the time the file was submitted | 

#### Human Readable Output
|task_uuid|submission_time|
| 2323714b7571c9c87e71799499d577126a487ff58177247e5b67a83a866f83a5-2022-07-22-07-27-42 | 2022-07-22 07:27:42 |

### snx-analysis-submit-url
***
Submit the URL for Analysis


#### Base Command

`snx-analysis-submit-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| URL | Input the URL for analysis. | Required | 
| Priority | Type the priority of the sample for analysis. Default is set to Normal. Possible values are High, Normal. Possible values are: High, Normal. | Optional | 
| Duration | Type the duration of the analysis in seconds. Not all malicious programs are active right after the launch. Some of them take time to fully reveal the attack vectors. Default is set to 120. Possible values are 120, 180, 240, 300. Possible values are: 120, 180, 240, 300. | Optional | 
| Reboot | Reboot the system during the analysis. Default is set to 'False'. Possible values are True, False. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecneurXAnalysis.SubmitURL.task_uuid | String | Task UUID is the unique ID for the submitted file. Use this ID to get the report. | 
| SecneurXAnalysis.SubmitURL.submission_time | String | Submission Time Created at the time the file was submitted | 

#### Human Readable Output
|task_uuid|submission_time|
| 2323714b7571c9c87e71799499d577126a487ff58177247e5b67a83a866f8fff-2022-07-22-07-12-15 | 2022-07-22 07:12:15 |

### snx-analysis-get-report
***
Get the detailed report of the analyzed sample.


#### Base Command

`snx-analysis-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Input the Task UUID value obtained as response from submission. | Required | 
| report_format | Mention the output format of the report. The value should be "json" or "html". The default is set to "json". Possible values are: html, json. Default is json. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecneurXAnalysis.Report.SHA256 | String | SHA256 value of the analyzed sample |
| SecneurXAnalysis.Report.Platform | String | Platform of the analyzed sample |
| SecneurXAnalysis.Report.Verdict | String | Summary result of the analyzed sample | 
| SecneurXAnalysis.Report.Tags | String | More details of the analyzed sample | 
| SecneurXAnalysis.Report.DnsRequests | String | List of DNS data observed in the analyzed sample | 
| SecneurXAnalysis.Report.HttpRequests | String | List of HTTP data observed in the analyzed sample | 
| SecneurXAnalysis.Report.JA3Digests | String | List of JA3 data observed in the analyzed sample | 
| SecneurXAnalysis.Report.ProcessCreated | String | Process behaviour data observed in the analyzed sample | 
| SecneurXAnalysis.Report.RegistrySet | String | List of Registry creations observed in the analyzed sample | 
| SecneurXAnalysis.Report.RegistryDeleted | String | List of Registry deletions observed in the analyzed sample | 
| SecneurXAnalysis.Report.FileCreated | String | List of File creations observed in the analyzed sample | 
| SecneurXAnalysis.Report.FileDropped | String | List of File drops observed in the analyzed sample | 
| SecneurXAnalysis.Report.FileDeleted | String | List of File deletions observed in the analyzed sample | 
| SecneurXAnalysis.Report.FileModified | String | List of File changes observed in the analyzed sample | 
| SecneurXAnalysis.Report.IOC | String | List of IOC's observed in the analyzed sample | 
| SecneurXAnalysis.Report.Status | String | Analysis queued sample state |

### snx-analysis-get-quota
***
Get the API Key quota usage details.

#### Base Command

`snx-analysis-get-quota`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecneurXAnalysis.Quota.start_time | String | Creation Time of the API Key |
| SecneurXAnalysis.Quota.used | Integer | Used count of API Key |
| SecneurXAnalysis.Quota.allowed | Integer | Limitation count of API Key |
| SecneurXAnalysis.Quota.scale | String | API Key expiration renew scale type |
| SecneurXAnalysis.Quota.unused | String | Unused count of API Key |

#### Human Readable Output
| allowed | scale | start_time | unused | used |
| 100 | MONTH | 01 Sep 2022 00:00:00 UTC | 60 | 40 |