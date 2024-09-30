Unique adaptive threat analysis technology, enabling zero-day malware detection and more Indicator of Compromise (IOCs) extraction.

## Configure OPSWAT Filescan Sandbox in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. <https://www.filescan.io/api>) | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Verbose | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### opswat-filescan-scan-url

***
Scan URL with OPSWAT Filescan Sandbox

**Note**: OPSWAT Filescan Sandbox handles URL scanning as a file scan.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`opswat-filescan-scan-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to submit | Required |
| timeout | The timeout for the polling in seconds | Optional |
| hide_polling_output | Hide polling output | Optional |
| description | Uploaded file/url description | Optional |
| tags | Tags array to propagate | Optional |
| password | Custom password, in case uploaded archive is protected | Optional |
| is_private | If file should not be available for download by other users | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| File.Name | String | The full file name. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| OPSWAT.Filescan.Analysis.finalVerdict.verdict | String | The final verdict. | 
| OPSWAT.Filescan.Analysis.allTags | Unknown | All tags. | 
| OPSWAT.Filescan.Analysis.overallState | String | Overall state of the scan. | 
| OPSWAT.Filescan.Analysis.taskReference.name | String | Name of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.additionalInfo | Unknown | Additional informations about the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.ID | String | ID of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.state | String | State of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.resourceReference | Unknown | Resource reference of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.opcount | Number | Counter. | 
| OPSWAT.Filescan.Analysis.taskReference.processTime | Number | processTime. | 
| OPSWAT.Filescan.Analysis.subtaskReferences | Unknown | Status of scan subtasks. | 
| OPSWAT.Filescan.Analysis.allSignalGroups | Unknown | All signal groups. | 
| OPSWAT.Filescan.Analysis.resources | Unknown | Resources. | 
| OPSWAT.Filescan.Analysis.file.name | String | The name of the file. | 
| OPSWAT.Filescan.Analysis.file.hash | String | The SHA256 of the file. | 
| OPSWAT.Filescan.Analysis.file.type| String | The type of the submission. | 

#### Command example

```!opswat-filescan-scan-url url=https://www.test.com```

#### Context Example

```json
{
{
    "DBotScore":
    [
        {
            "Indicator": "1111111111111111111111111111111111111111111111111111111111111111",
            "Score": 1,
            "Type": "file",
            "Vendor": "OPSWAT Filescan Sandbox"
        }
    ],
    "File":
    [
        {
            "Name": "https://www.test.com",
            "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
        }
    ],
    "OPSWAT":
    {
        "Filescan":
        {
            "Analysis":
            [
                {
                    "finalVerdict":
                    {
                        "verdict": "BENIGN"
                    },
                    "allTags":
                    [
                        {
                            "source": "MEDIA_TYPE",
                            "sourceIdentifier": "12345678",
                            "isRootTag": true,
                            "tag":
                            {
                                "name": "html",
                                "synonyms":
                                [],
                                "descriptions":
                                [],
                                "verdict":
                                {
                                    "verdict": "INFORMATIONAL",
                                    "threatLevel": 0.1,
                                    "confidence": 1
                                }
                            }
                        }
                    ],
                    "overallState": "success_partial",
                    "taskReference":
                    {
                        "name": "transform-file",
                        "additionalInfo":
                        {
                            "submitName": "https://www.test.com",
                            "submitTime": 1679014774270,
                            "digests":
                            {
                                "SHA-256": "1111111111111111111111111111111111111111111111111111111111111111"
                            }
                        },
                        "ID": "abcd-1234",
                        "state": "SUCCESS",
                        "resourceReference":
                        {
                            "type": "TRANSFORM_FILE",
                            "name": "file",
                            "ID": "abcd-5678"
                        },
                        "opcount": 1,
                        "processTime": 20350
                    },
                    "subtaskReferences":
                    [
                        {
                            "name": "domain-resolve",
                            "additionalInfo": 72,
                            "ID": "12345678",
                            "state": "SUCCESS",
                            "resourceReference":
                            {
                                "type": "DOMAIN_RESOLVE",
                                "name": "domain-resolve",
                                "ID": "123456789"
                            },
                            "opcount": 20,
                            "processTime": 11309
                        }
                    ],
                    "allSignalGroups":
                    [
                        {
                            "identifier": "I000",
                            "description": "OSINT source detected malicious resource",
                            "averageSignalStrength": 0.75,
                            "peakSignalStrength": 0.75,
                            "finalSignalStrength": 0.75,
                            "verdict":
                            {
                                "verdict": "LIKELY_MALICIOUS",
                                "threatLevel": 0.75,
                                "confidence": 1
                            },
                            "allTags":
                            [],
                            "signals":
                            [
                                {
                                    "strength": 0.75,
                                    "isStrictlyBasedOnInputData": false,
                                    "signalReadable": "OSINT provider TEST provider (2/93)",
                                    "additionalInfo": "https://www.google.com",
                                    "originPath": "osint.results.verdict",
                                    "originType": "INPUT_FILE",
                                    "originIdentifier": "1234"
                                }
                            ]
                        }
                    ],
                    "resources":
                    {
                        "00f1e4d6-27fb-45e8-8a02-dc53818044ec":
                        {
                            "resourceReference":
                            {
                                "name": "osint"
                            },
                            "results":
                            []
                        }
                    },
                    "file":
                    {
                        "name": "https://www.test.com",
                        "hash": "1111111111111111111111111111111111111111111111111111111111111111",
                        "type": "other"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Scan Result (digest):

>|FileHash|FileName|FileType|FinalVerdict|SubtaskReferences|Tags|
>|---|---|---|---|---|---|
>| 1111111111111111111111111111111111111111111111111111111111111111 | <https://www.test.com> | other | BENIGN | osint, url-render, domain-resolve | html, png |

### opswat-filescan-scan-file

***
Scan File with OPSWAT Filescan Sandbox

#### Base Command

`opswat-filescan-scan-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | he War Room entry ID of the file to submit | Required |
| timeout | The timeout for the polling in seconds | Optional |
| hide_polling_output | Hide polling output | Optional |
| description | Uploaded file/url description | Optional |
| tags | Tags array to propagate | Optional |
| password | Custom password, in case uploaded archive is protected | Optional |
| is_private | If file should not be available for download by other users | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. |
| File.Name | String | The full file name. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| OPSWAT.Filescan.Analysis.finalVerdict.verdict | String | The final verdict. | 
| OPSWAT.Filescan.Analysis.allTags | Unknown | All tags. | 
| OPSWAT.Filescan.Analysis.overallState | String | Overall state of the scan. | 
| OPSWAT.Filescan.Analysis.taskReference.name | String | Name of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.additionalInfo | Unknown | Additional informations about the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.ID | String | ID of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.state | String | State of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.resourceReference | Unknown | Resource reference of the main scan task. | 
| OPSWAT.Filescan.Analysis.taskReference.opcount | Number | Counter. | 
| OPSWAT.Filescan.Analysis.taskReference.processTime | Number | processTime. | 
| OPSWAT.Filescan.Analysis.subtaskReferences | Unknown | Status of scan subtasks. | 
| OPSWAT.Filescan.Analysis.allSignalGroups | Unknown | All signal groups. | 
| OPSWAT.Filescan.Analysis.resources | Unknown | Resources. | 
| OPSWAT.Filescan.Analysis.file.name | String | The name of the file. | 
| OPSWAT.Filescan.Analysis.file.hash | String | The SHA256 of the file. | 
| OPSWAT.Filescan.Analysis.file.type| String | The type of the submission. | 

#### Command example

```!opswat-filescan-scan-file  entry_id=1234@abcd-efgh-ijkl-mnop-xyz```

#### Context Example

```json
{
{
    "DBotScore":
    [
        {
            "Indicator": "1111111111111111111111111111111111111111111111111111111111111111",
            "Score": 1,
            "Type": "file",
            "Vendor": "OPSWAT Filescan Sandbox"
        }
    ],
    "File":
    [
        {
            "Name": "1234@abcd-efgh-ijkl-mnop-xyz",
            "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
        }
    ],
    "OPSWAT":
    {
        "Filescan":
        {
            "Analysis":
            [
                {
                    "finalVerdict":
                    {
                        "verdict": "MALICIOUS"
                    },
                    "allTags":
                    [
                        {
                            "source": "SIGNAL",
                            "sourceIdentifier": "1234",
                            "isRootTag": false,
                            "tag": 
                            {
                                "name": "packed",
                                "synonyms": [],
                                "descriptions": [],
                                "verdict": {
                                    "verdict": "SUSPICIOUS",
                                    "threatLevel": 0.5,
                                    "confidence": 1
                                }
                            }
                        }
                    ],
                    "overallState": "success_partial",
                    "taskReference":
                    {
                        "name": "transform-file",
                        "additionalInfo": {
                            "submitName": "bad_file.exe",
                            "submitTime": 1679011634945,
                            "digests": {
                                "SHA-256": "1111111111111111111111111111111111111111111111111111111111111111"
                            }
                        },
                        "ID": "1234",
                        "state": "SUCCESS",
                        "resourceReference": {
                            "type": "TRANSFORM_FILE",
                            "name": "file",
                            "ID": "0101010101"
                        },
                        "opcount": 1,
                        "processTime": 7180
                    },
                    "subtaskReferences":
                    [
                        {
                            "name": "domain-resolve",
                            "additionalInfo": 72,
                            "ID": "12345678",
                            "state": "SUCCESS",
                            "resourceReference":
                            {
                                "type": "DOMAIN_RESOLVE",
                                "name": "domain-resolve",
                                "ID": "123456789"
                            },
                            "opcount": 20,
                            "processTime": 11309
                        }
                    ],
                    "allSignalGroups":
                    [
                        {
                            "identifier": "Y002",
                            "description": "Matched a malicious YARA rule",
                            "averageSignalStrength": 1,
                            "peakSignalStrength": 1,
                            "finalSignalStrength": 1,
                            "verdict": {
                                "verdict": "MALICIOUS",
                                "threatLevel": 1,
                                "confidence": 1
                            },
                            "allTags": [],
                            "signals": [
                                {
                                    "strength": 1,
                                    "isStrictlyBasedOnInputData": true,
                                    "signalReadable": "Matched YARA with strength \"0.75\"",
                                    "additionalInfo": "PUP_InstallRex_AntiFWb",
                                    "originPath": "file.yaraMatches",
                                    "originType": "INPUT_FILE",
                                    "originIdentifier": "111111111111111111111111111"
                                }
                            ]
                        }
                    ],
                    "resources":
                    {
                        "00f1e4d6-27fb-45e8-8a02-dc53818044ec":
                        {
                            "resourceReference":
                            {
                                "name": "osint"
                            },
                            "results":
                            []
                        }
                    },
                    "file":
                    {
                        "name": "1234@abcd-efgh-ijkl-mnop-xyz",
                        "hash": "1111111111111111111111111111111111111111111111111111111111111111",
                        "type": "other"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Scan Result (digest):

>|FileHash|FileName|FileType|FinalVerdict|SubtaskReferences|Tags|
>|---|---|---|---|---|---|
>| 1111111111111111111111111111111111111111111111111111111111111111 | 1234@abcd-efgh-ijkl-mnop-xyz | pe | MALICIOUS | visualization, osint, domain-resolve | html, peexe |

### opswat-filescan-search-query

***
Search for reports. Finds reports and uploaded files by various tokens.

#### Base Command

`opswat-filescan-search-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string | Required |
| limit | Number of total results. Maximum 50 | Optional |
| page | Page number, starting from 1 | Optional |
| page_size | The page size. Can be 5, 10 or 20 | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPSWAT.Filescan.Analysis.id | String | The analysis id. | 
| OPSWAT.Filescan.Analysis.file.name | String | The name of the file. | 
| OPSWAT.Filescan.Analysis.file.sha256 | String | The SHA256 of the file. | 
| OPSWAT.Filescan.Analysis.verdict | String | The final verdict. | 
| OPSWAT.Filescan.Analysis.state | String | Overall state of the scan. | 
| OPSWAT.Filescan.Analysis.date | Date | The scan date. | 
| OPSWAT.Filescan.Analysis.file.mime_type | String | The file MimeType. |
| OPSWAT.Filescan.Analysis.file.short_type | String | The type of the submission. |
| OPSWAT.Filescan.Analysis.tags | Unknown | All tags. | 

#### Command example

```!opswat-filescan-search-query query="834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"```

#### Context Example

```json
{
    "OPSWAT":
    {
        "Filescan":
        {
            "Analysis":
            [
                {
                    "id": "b4f92c03-0fc2-4a40-9d34-8f2b05dd240c",
                    "file": {
                        "name": "bad_file.exe",
                        "mime_type": "application/x-msdownload",
                        "short_type": "peexe",
                        "sha256": "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc",
                    },
                    "state": "success",
                    "verdict": "malicious",
                    "tags": [
                        {
                            "source": "MEDIA_TYPE",
                            "sourceIdentifier": "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc",
                            "isRootTag": true,
                            "tag": {
                                "name": "peexe",
                                "synonyms": [],
                                "descriptions": [],
                                "verdict": {
                                    "verdict": "INFORMATIONAL",
                                    "threatLevel": 0.1,
                                    "confidence": 1
                                }
                            }
                        }
                    ],
                    "date": "03/20/2023, 14:28:09"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Analysis Result:

>| Id | SampleName | SHA256 | Verdict | State | Date |
>|---|---|---|---|---|---|
>| 8c38be8c-7cfd-4d64-be41-c98a795c9ce0| bad_file.exe | 834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc | MALICIOUS | success_partial | 03/14/2023, 15:07:07 |
>| e334d27f-e2b1-46c9-9936-7d3155eb3706| bad_file.exe | 834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc | UNKNOWN | success | 03/14/2020, 15:03:48 |