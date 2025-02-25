## Overview
This integration supports using ReversingLabs Advanced File Analysis to 'detonate file' on the TitaniumScale Advanced Malware
Analysis Appliance.

The ReversingLabs TitaniumScale Appliance is powered by TitaniumCore, the malware analysis engine that performs 
automated static analysis using the Active File Decomposition technology.

TitaniumCore unpacks and recursively analyzes files without executing them, and extracts internal threat indicators to 
classify files and determine their threat level. TitaniumCore is capable of identifying thousands of file format 
families. It recursively unpacks hundreds of file format families, and fully repairs extracted files to enable further 
analysis.

* * *
## Prerequisites

You need to obtain the following:

*   TitaniumScale instance
*   TitaniumScale API Token


## Configure ReversingLabs TitaniumScale in Cortex


| **Parameter** | **Required** |
| --- | --- |
| ReversingLabs TitaniumScale instance URL | True |
| API Token | True |
| Verify host certificates | False |
| Reliability | False |
| Wait time between report fetching retries (seconds). Deafult is 2 seconds. | False |
| Number of report fetching retries. Default is 30. | False |
| HTTP proxy address with the protocol and port number | False |
| HTTP proxy username | False |
| HTTP proxy password | False |
| HTTPS proxy address with the protocol and port number | False |
| HTTPS proxy username | False |
| HTTPS proxy password | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### reversinglabs-titaniumscale-upload-sample-and-get-results

***
Upload sample to TitaniumScale and retrieve analysis report.

#### Base Command

`reversinglabs-titaniumscale-upload-sample-and-get-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The file entry to upload. | Required | 
| custom_token | A custom token for filtering processing tasks. | Optional | 
| user_data | User-defined data in the form of a JSON string. This data is NOT included in file analysis reports. | Optional | 
| custom_data | User-defined data in the form of a JSON string. This data is included in file analysis reports. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.EntryID | String | The Entry ID. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | MD5 hash of the file. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| ReversingLabs.tc_report | String | Full report. | 

#### Command example
```!reversinglabs-titaniumscale-upload-sample-and-get-results entryId="371@b26c8c3a-8d0e-459f-8f2c-c0b8783a8422" custom_token="a-custom-token"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "0000a0a381d31e0dafcaa22343d2d7e40ff76e06",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "ReversingLabs TitaniumScale"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "a984de0ce47a8d5337ef569c812b57d0"
            },
            {
                "type": "SHA1",
                "value": "0000a0a381d31e0dafcaa22343d2d7e40ff76e06"
            },
            {
                "type": "SHA256",
                "value": "b25e707a78a472d92a99b08be5d0e55072f695275a7408d1e841a5344ca85dc3"
            }
        ],
        "MD5": "a984de0ce47a8d5337ef569c812b57d0",
        "Malicious": {
            "Description": "\n **Antivirus (based on the RCA Classify):** Win32.Downloader.Unruy",
            "Vendor": "ReversingLabs TitaniumScale"
        },
        "SHA1": "0000a0a381d31e0dafcaa22343d2d7e40ff76e06",
        "SHA256": "b25e707a78a472d92a99b08be5d0e55072f695275a7408d1e841a5344ca85dc3"
    },
    "InfoFile": {
        "EntryID": "398@b26c8c3a-8d0e-459f-8f2c-c0b8783a8422",
        "Info": "text/plain",
        "Name": "Full report in JSON",
        "Size": 19763,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "tc_report": [
            {
                "classification": {
                    "classification": 3,
                    "factor": 3,
                    "propagated": false,
                    "rca_factor": 8,
                    "result": "Win32.Downloader.Unruy",
                    "scan_results": [
                        {
                            "classification": 3,
                            "factor": 3,
                            "ignored": false,
                            "name": "Antivirus (based on the RCA Classify)",
                            "rca_factor": 8,
                            "result": "Win32.Downloader.Unruy",
                            "type": "av",
                            "version": "2.91"
                        },
                        {
                            "classification": 3,
                            "factor": 3,
                            "ignored": false,
                            "name": "TitaniumCore RHA1",
                            "rca_factor": 8,
                            "result": "Win32.Downloader.Unruy",
                            "type": "internal",
                            "version": "5.0.1.26"
                        },
                        {
                            "classification": 3,
                            "factor": 1,
                            "ignored": false,
                            "name": "TitaniumCore Machine Learning",
                            "rca_factor": 6,
                            "result": "Win32.Malware.Heuristic",
                            "type": "internal",
                            "version": "5.0.1.26"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "drweb",
                            "rca_factor": 0,
                            "result": "Win32.HLLC.Asdas.7",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "vba32",
                            "rca_factor": 0,
                            "result": "SScope.TrojanInjector.MY",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "endgame",
                            "rca_factor": 0,
                            "result": "malicious (high confidence)",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "ahnlab",
                            "rca_factor": 0,
                            "result": "Trojan/Win32.Kazy.R3559",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "antivir",
                            "rca_factor": 0,
                            "result": "detected",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "avast",
                            "rca_factor": 0,
                            "result": "Win32:Unruy-Z [Trj]",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "bitdefender",
                            "rca_factor": 0,
                            "result": "Gen:Trojan.ProcessHijack.cqX@aaG5Soe",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "carbonblack",
                            "rca_factor": 0,
                            "result": "trojan",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "clamav",
                            "rca_factor": 0,
                            "result": "Win.Trojan.Powp-13",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "crowdstrike",
                            "rca_factor": 0,
                            "result": "win/malicious_confidence_100",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "mcafee_online",
                            "rca_factor": 0,
                            "result": "Downloader-CIS.c (trojan)",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "ffri",
                            "rca_factor": 0,
                            "result": "Detected",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "fireeye_online",
                            "rca_factor": 0,
                            "result": "Generic.mg.a984de0ce47a8d53",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "fortinet",
                            "rca_factor": 0,
                            "result": "W32/Powp.gen!tr",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "gdata",
                            "rca_factor": 0,
                            "result": "Gen:Trojan.ProcessHijack.cqX@aaG5Soe",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "ikarus",
                            "rca_factor": 0,
                            "result": "Trojan.Injector",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "k7computing",
                            "rca_factor": 0,
                            "result": "Riskware (0040eff71)",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "malwarebytes",
                            "rca_factor": 0,
                            "result": "Malware.AI.4098645872",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "mcafeegwedition_online",
                            "rca_factor": 0,
                            "result": "BehavesLike.Win32.VirRansom.pc",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "varist",
                            "rca_factor": 0,
                            "result": "W32/CeeInject.L.gen!Eldorado",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "mcafee_beta",
                            "rca_factor": 0,
                            "result": "Downloader-CIS.c (trojan)",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "sentinelone_online",
                            "rca_factor": 0,
                            "result": "DFI - Malicious PE",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "ahnlab_online",
                            "rca_factor": 0,
                            "result": "Trojan/Win32.Kazy.R3559",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "microsoft",
                            "rca_factor": 0,
                            "result": "TrojanDownloader:Win32/Unruy.H",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "microsoft_online",
                            "rca_factor": 0,
                            "result": "TrojanDownloader:Win32/Unruy.H",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "panda",
                            "rca_factor": 0,
                            "result": "Generic Suspicious",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "panda_online",
                            "rca_factor": 0,
                            "result": "Generic Malware",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "quickheal",
                            "rca_factor": 0,
                            "result": "VirTool.CeeInject.G",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "rising",
                            "rca_factor": 0,
                            "result": "Downloader.Unruy!1.679D",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "rising_online",
                            "rca_factor": 0,
                            "result": "Downloader.Unruy!1.679D",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "sonicwall",
                            "rca_factor": 0,
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "sophos_susi",
                            "rca_factor": 0,
                            "result": "Mal/EncPk-ZC",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "symantec",
                            "rca_factor": 0,
                            "result": "Trojan.Gen",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "symantec_beta",
                            "rca_factor": 0,
                            "result": "Trojan.Gen",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "symantec_online",
                            "rca_factor": 0,
                            "result": "Trojan.Gen",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "trendmicro",
                            "rca_factor": 0,
                            "result": "TROJ_UNRUY.SMJF",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "trendmicro_consumer",
                            "rca_factor": 0,
                            "result": "TROJ_UNRUY.SMJF",
                            "type": "av"
                        },
                        {
                            "classification": 0,
                            "factor": 0,
                            "ignored": false,
                            "name": "mcafee",
                            "rca_factor": 0,
                            "result": "Downloader-CIS.c (trojan)",
                            "type": "av"
                        },
                        {
                            "classification": 3,
                            "factor": 2,
                            "ignored": false,
                            "name": "Next-Generation Antivirus",
                            "rca_factor": 7,
                            "result": "Win32.Malware.Heuristic",
                            "type": "ng_av",
                            "version": "1.0"
                        }
                    ]
                },
                "index": 0,
                "indicators": [
                    {
                        "category": 4,
                        "description": "Allocates additional memory in the calling process.",
                        "id": 17985,
                        "priority": 3,
                        "reasons": [
                            {
                                "category": "Imported API Name",
                                "description": "Imports the following function: HeapAlloc",
                                "propagated": false
                            }
                        ],
                        "relevance": 0
                    },
                    {
                        "category": 10,
                        "description": "Loads additional libraries.",
                        "id": 69,
                        "priority": 2,
                        "reasons": [
                            {
                                "category": "Imported API Name",
                                "description": "Imports the following function: LoadLibraryA",
                                "propagated": false
                            }
                        ],
                        "relevance": 1
                    },
                    {
                        "category": 10,
                        "description": "Loads additional APIs.",
                        "id": 70,
                        "priority": 2,
                        "reasons": [
                            {
                                "category": "Imported API Name",
                                "description": "Imports the following function: GetProcAddress",
                                "propagated": false
                            },
                            {
                                "category": "Indicator Match",
                                "description": "Matched another indicator that describes the following: Loads additional libraries.",
                                "propagated": false
                            }
                        ],
                        "relevance": 0
                    },
                    {
                        "category": 16,
                        "description": "Uses string related methods.",
                        "id": 18050,
                        "priority": 1,
                        "reasons": [
                            {
                                "category": "Imported API Name",
                                "description": "Imports the following function: lstrcatA",
                                "propagated": false
                            }
                        ],
                        "relevance": 0
                    }
                ],
                "info": {
                    "file": {
                        "entropy": 7.222407502197507,
                        "file_name": "b26c8c3a-8d0e-459f-8f2c-c0b8783a8422_371@b26c8c3a-8d0e-459f-8f2c-c0b8783a8422",
                        "file_path": "b26c8c3a-8d0e-459f-8f2c-c0b8783a8422_371@b26c8c3a-8d0e-459f-8f2c-c0b8783a8422",
                        "file_subtype": "Exe",
                        "file_type": "PE",
                        "hashes": [
                            {
                                "name": "imphash",
                                "value": "054e4e5c28d6533b44ae24cbf3e08a15"
                            },
                            {
                                "name": "md5",
                                "value": "a984de0ce47a8d5337ef569c812b57d0"
                            },
                            {
                                "name": "rha0",
                                "value": "6e60e6783d0e5104dab2311c93d6f9b42cebbf03"
                            },
                            {
                                "name": "sha1",
                                "value": "0000a0a381d31e0dafcaa22343d2d7e40ff76e06"
                            },
                            {
                                "name": "sha256",
                                "value": "b25e707a78a472d92a99b08be5d0e55072f695275a7408d1e841a5344ca85dc3"
                            }
                        ],
                        "size": 42544
                    }
                },
                "metadata": {
                    "application": {
                        "capabilities": 4255756
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>## ReversingLabs TitaniumScale upload sample and get results
>
> **Type:** PE/Exe
>                             **Size:** 42544 bytes 
>
> **IMPHASH:** 054e4e5c28d6533b44ae24cbf3e08a15
> **MD5:** a984de0ce47a8d5337ef569c812b57d0
> **RHA0:** 6e60e6783d0e5104dab2311c93d6f9b42cebbf03
> **SHA1:** 0000a0a381d31e0dafcaa22343d2d7e40ff76e06
> **SHA256:** b25e707a78a472d92a99b08be5d0e55072f695275a7408d1e841a5344ca85dc3
>
> **Status:** malicious
> **Antivirus (based on the RCA Classify):** Win32.Downloader.Unruy
> **DBot score:** 3


### reversinglabs-titaniumscale-upload-sample

***
Upload sample to TitaniumScale for analysis.

#### Base Command

`reversinglabs-titaniumscale-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The file entry to upload. | Required | 
| custom_token | A custom token for filtering processing tasks. | Optional | 
| user_data | User-defined data in the form of a JSON string. This data is NOT included in file analysis reports. | Optional | 
| custom_data | User-defined data in the form of a JSON string. This data is included in file analysis reports. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.task_Url | Unknown | url to get report from. | 

#### Command example
```!reversinglabs-titaniumscale-upload-sample entryId="371@b26c8c3a-8d0e-459f-8f2c-c0b8783a8422" custom_token="a-custom-token"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "403@b26c8c3a-8d0e-459f-8f2c-c0b8783a8422",
        "Info": "text/plain",
        "Name": "Full report in JSON",
        "Size": 95,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "tc_task_url": "https://tiscale-worker-integrations-demo-01.rl.lan/api/tiscale/v1/task/42"
    }
}
```

#### Human Readable Output

>## ReversingLabs TitaniumScale upload sample
> **Titanium Scale task URL**: https://tiscale-worker-integrations-demo-01.rl.lan/api/tiscale/v1/task/42

### reversinglabs-titaniumscale-get-results

***
Retrieve report of a previously uploaded file from TitaniumScale.

#### Base Command

`reversinglabs-titaniumscale-get-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| taskUrl | The file entry to upload. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.EntryID | String | The Entry ID. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | MD5 hash of the file. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| ReversingLabs.tc_report | String | Full report. | 

### reversinglabs-titaniumscale-list-processing-tasks

***
List active processing tasks.

#### Base Command

`reversinglabs-titaniumscale-list-processing-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| age | Task age in seconds. | Optional | 
| custom_token | A custom token for filtering processing tasks. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.list_processing_tasks | Unknown | Processing tasks. | 

#### Command example
```!reversinglabs-titaniumscale-list-processing-tasks age="60" custom_token="a-custom-token"```
#### Context Example
```json
{
    "ReversingLabs": {
        "list_processing_tasks": []
    }
}
```

#### Human Readable Output

>## ReversingLabs TitaniumScale List processing tasks
> ### Processing tasks
>**No entries.**


### reversinglabs-titaniumscale-get-processing-task-info

***
Retrieves information about a completed file processing task.

#### Base Command

`reversinglabs-titaniumscale-get-processing-task-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.tc_report | Unknown | Full report. | 

### reversinglabs-titaniumscale-delete-processing-task

***
Deletes a processing task.

#### Base Command

`reversinglabs-titaniumscale-delete-processing-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!reversinglabs-titaniumscale-delete-processing-task task_id="100"```
#### Human Readable Output

>## ReversingLabs TitaniumScale delete processing task
> Task 100 deleted successfully.

### reversinglabs-titaniumscale-delete-multiple-tasks

***
Deletes multiple processing tasks.

#### Base Command

`reversinglabs-titaniumscale-delete-multiple-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| age | Task age in seconds. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!reversinglabs-titaniumscale-delete-multiple-tasks age="20"```
#### Human Readable Output

>## ReversingLabs TitaniumScale delete multiple tasks
> Tasks of age 20 seconds or less deleted successfully.

### reversinglabs-titaniumscale-get-yara-id

***
Retrieves the identifier of the current set of YARA rules on the TitaniumScale Worker instance.

#### Base Command

`reversinglabs-titaniumscale-get-yara-id`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.yara_id | Unknown | Identifier of the current set of YARA rules on the TitaniumScale Worker instance. | 

#### Command example
```!reversinglabs-titaniumscale-get-yara-id```
#### Context Example
```json
{
    "ReversingLabs": {
        "yara_id": {
            "id": "f0a151ce303ae9b9e46b236492ac9196f3f72490"
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs TitaniumScale YARA ruleset ID
> **ID**: f0a151ce303ae9b9e46b236492ac9196f3f72490