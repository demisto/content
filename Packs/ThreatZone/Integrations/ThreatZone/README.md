ThreatZone malware analysis sandboxing.
This integration was integrated and tested with ThreatZone

## Configure ThreatZone in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. <https://app.threat.zone>) |  | True |
| ThreatZone API Key |  | True |
| Source Reliability | Reliability of the source. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tz-sandbox-upload-sample

***
Submits a sample to ThreatZone for sandbox analysis.

#### Base Command

`tz-sandbox-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required | 
| environment | Choose what environment you want to run your submission. Possible values are: w7_x64, w10_x64, w11_x64. Default is w7_x64. | Optional | 
| private | Privacy of the submission. Possible values are: true, false. Default is true. | Optional | 
| timeout | Duration of the submission analysis. Possible values are: 60, 120, 180, 300. Default is 60. | Optional | 
| work_path | The working path of the submission. Possible values are: desktop, root, appdata, windows, temp. Default is desktop. | Optional | 
| mouse_simulation | Enable mouse simulation. Possible values are: true, false. Default is false. | Optional | 
| https_inspection | Https inspection to read encrypted traffic. Possible values are: true, false. Default is false. | Optional | 
| internet_connection | Enable internet connection. Possible values are: true, false. Default is false. | Optional | 
| raw_logs | Raw logs. Possible values are: true, false. Default is false. | Optional | 
| snapshot | Snapshot. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Sandbox.UUID | String | UUID of sample. | 
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. | 
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. | 
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. | 
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. | 

### tz-static-upload-sample

***
Submits a sample to ThreatZone for static analysis.

#### Base Command

`tz-static-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required | 
| private | If this is false then everyone can see the submisison. If this is true then only your workspace participants can see the submission. Possible values are: true, false. Default is false. | Optional | 
| extension_check | If extension check is true and you do not know the submission extension or mimetype then our systems automatically detects file extension and mimetype. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Static.UUID | String | UUID of sample. | 
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. | 
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. | 
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. | 
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. | 

### tz-cdr-upload-sample

***
Submits a sample to ThreatZone for CDR.

#### Base Command

`tz-cdr-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required | 
| private | If this is false then everyone can see the submisison. If this is true then only your workspace participants can see the submission. Possible values are: true, false. Default is true. | Optional | 
| extension_check | If extension check is true and you do not know the submission extension or mimetype then our systems automatically detects file extension and mimetype. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.CDR.UUID | String | UUID of sample. | 
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. | 
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. | 
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. | 
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. | 

### tz-get-result

***
Retrive the analysis result from ThreatZone.

#### Base Command

`tz-get-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Analysis.STATUS | String | The status of the submission scanning process. | 
| ThreatZone.Analysis.LEVEL | String | Threat Level of the scanned file. \(malicious, suspicious or informative\). | 
| ThreatZone.Analysis.INFO | String | Contains the file name, scan process status and public status. | 
| ThreatZone.Analysis.REPORT | String | The analysis report of the submission. | 
| ThreatZone.Analysis.MD5 | String | The md5 hash of the submission. | 
| ThreatZone.Analysis.SHA1 | String | The sha1 hash of the submission. | 
| ThreatZone.Analysis.SHA256 | String | The sha256 hash of the submission. | 
| ThreatZone.Analysis.UUID | String | The UUID of the submission. | 
| ThreatZone.IOC.URL | List | The URL data extracted from IOC. | 
| ThreatZone.IOC.IP | List | The IP data extracted from IOC. | 
| ThreatZone.IOC.DOMAIN | List | The DOMAIN data extracted from IOC. | 
| ThreatZone.IOC.EMAIL | List | The EMAIL data extracted from IOC. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 

### tz-get-sanitized

***
Downloads and uploads sanitized file from ThreatZone API to WarRoom & Context Data.

#### Base Command

`tz-get-sanitized`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Extension | String | Extension of the file sanitized by CDR. | 
| InfoFile.Name | String | The name of the file sanitized by CDR. | 
| InfoFile.Size | Number | Size of the file sanitized by CDR. | 
| InfoFile.EntryID | String | EntryID of the file sanitized by CDR. | 
| InfoFile.Info | String | Info of the file sanitized by CDR. | 
| InfoFile.MD5 | String | MD5 hash of the file sanitized by CDR. | 
| InfoFile.SHA1 | String | SHA1 hash of the file sanitized by CDR. | 
| InfoFile.SHA256 | String | SHA256 hash of the file sanitized by CDR. | 
| InfoFile.SHA512 | String | SHA512 hash of the file sanitized by CDR. | 
| InfoFile.SSDeep | String | SSDeep hash of the file sanitized by CDR. | 

### tz-check-limits

***
Check the plan limits from ThreatZone API.

#### Base Command

`tz-check-limits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. | 
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. | 
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. | 
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. | 


#### Command Example

```tz-get-result uuid=95b6bc52-d040-4d82-a98b-af6fd5f6feea``` (Sandbox)

```tz-get-result uuid=7ddad84a-7f9b-4b56-b8f4-914287a0a1a3``` (Static-Scan)

```tz-get-result uuid=1170250a-40ac-4b73-84f7-3c0b6026d8af``` (CDR)

#### Context Example for Sandbox

Note: Long output parts are truncated

```json
{
    "DBotScore": {
        "Indicator": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 3,
        "Type": "file",
        "Vendor": "ThreatZone"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "30bdb7e22e022bcf00d157f4da0e098e"
            },
            {
                "type": "SHA1",
                "value": "0cd47f6bb5bb8e8e9dc01286adcc493acf5dd649"
            },
            {
                "type": "SHA256",
                "value": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108"
            }
        ],
        "MD5": "30bdb7e22e022bcf00d157f4da0e098e",
        "Malicious": {
            "Description": null,
            "Vendor": "ThreatZone"
        },
        "SHA1": "0cd47f6bb5bb8e8e9dc01286adcc493acf5dd649",
        "SHA256": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108"
    },
    "ThreatZone": {
        "Analysis": {
            "INFO": {
                "file_name": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108.exe",
                "private": false
            },
            "LEVEL": 3,
            "MD5": "30bdb7e22e022bcf00d157f4da0e098e",
            "REPORT": {
                "_id": "64f1e57fc9ae854321d3a7f5",
                "additionalFiles": [],
                "enabled": true,
                "indicators": [
                    {
                        "_id": "64f1e5fb7949a5710e1e46be",
                        "attackCodes": [
                            "T1082"
                        ],
                        "author": "Malwation",
                        "category": "Registry",
                        "description": "Target reads computer name",
                        "events": [
                            87430,
                            87431
                        ],
                        "level": "Suspicious",
                        "name": "Reads computer name",
                        "score": 3
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46bf",
                        "attackCodes": [
                            "T1112"
                        ],
                        "author": "Malwation",
                        "category": "Registry",
                        "description": "Target changes registry value",
                        "events": [
                            4872,
                            4874,
                            4876,
                            4878,
                            4880,
                            4883,
                            5597,
                            5603,
                            5609,
                            5615,
                            5621,
                            5628
                        ],
                        "level": "Malicious",
                        "name": "Registry changed",
                        "score": 7
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c0",
                        "attackCodes": [],
                        "author": "Malwation",
                        "category": "Registry",
                        "description": "Target reads the Internet Settings",
                        "events": [
                            5708,
                            6089,
                            6090,
                            6091,
                            6092,
                            6096,
                            6097,
                            6320,
                            6322,
                            6323
                        ],
                        "level": "Suspicious",
                        "name": "Reads the Internet Settings",
                        "score": 5
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c1",
                        "attackCodes": [],
                        "author": "Malwation",
                        "category": "OS",
                        "description": "Target creates mutex",
                        "events": [
                            4842
                        ],
                        "level": "Suspicious",
                        "name": "Create mutex",
                        "score": 5
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c2",
                        "attackCodes": [],
                        "author": "Malwation",
                        "category": "Network",
                        "description": "Target might try to open port and listen for incoming connection",
                        "events": [
                            5512,
                            5509,
                            5386,
                            5385,
                            87138,
                            87137,
                            87136,
                            87134
                        ],
                        "level": "Suspicious",
                        "name": "Network connection",
                        "score": 4
                    }
                ],
                "level": 3,
                "media": [
                    {
                        "_id": "64f1e5fb7949a5710e1e46c3",
                        "id": "75d54195-ede8-48eb-8614-55d3658ed71c",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/1.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c4",
                        "id": "3eb5c83a-79ff-4e04-a173-b6c087a6f578",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/10.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c5",
                        "id": "b966535b-9aaa-4a0b-a1a1-863d8d23c830",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/2.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c6",
                        "id": "68eac6f4-68a1-411b-b349-b919aef3e166",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/3.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c7",
                        "id": "d76344b8-ba3d-411a-adf3-515990623dd9",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/4.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c8",
                        "id": "503b92df-98e1-4e6d-80bc-d18e8e25acb8",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/5.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46c9",
                        "id": "ac0228c8-79d1-40b8-930b-5ad1bbf8996f",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/6.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46ca",
                        "id": "56095f8a-2319-4169-856e-1acb05ec0f7f",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/7.png"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46cb",
                        "id": "4418068d-caa9-4e13-997e-3e631baf5d98",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/8.png"
                    },
                    {
                        "_id": "64f1e5fc7949a5710e1e46cc",
                        "id": "1b025f1b-b5d7-4491-bd29-8696513f04d6",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/9.png"
                    },
                    {
                        "_id": "64f1e5fc7949a5710e1e46cd",
                        "id": "4fc26473-0fe5-4ef7-9caa-050d8a7dbb11",
                        "path": "95b6bc52-d040-4d82-a98b-af6fd5f6feea/dynamic/overview/media/video.mp4"
                    }
                ],
                "metafields": {
                    "environment": "w7_x64",
                    "https_inspection": false,
                    "internet_connection": false,
                    "mouse_simulation": false,
                    "raw_logs": false,
                    "snapshot": false,
                    "timeout": 60,
                    "work_path": "desktop"
                },
                "network": [],
                "process": [
                    {
                        "_id": "64f1e5fb7949a5710e1e46bb",
                        "analysis": "basic",
                        "cmd": "cmd_line",
                        "eventcount": 1,
                        "eventid": 35,
                        "image": "win_image",
                        "method": "NtUserCreateProcess",
                        "operation": "create",
                        "pid": 3060,
                        "ppid": 1452,
                        "process_name": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108.exe",
                        "work_dir": "C:\\Windows\\system32\\"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46bc",
                        "analysis": "basic",
                        "cmd": "cmd_line",
                        "eventcount": 1,
                        "eventid": 36,
                        "image": "win_image",
                        "method": "NtUserCreateProcess",
                        "operation": "create",
                        "pid": 656,
                        "ppid": 3060,
                        "process_name": "cmd.exe",
                        "work_dir": "C:\\Windows\\system32\\"
                    },
                    {
                        "_id": "64f1e5fb7949a5710e1e46bd",
                        "analysis": "basic",
                        "cmd": "cmd_line",
                        "eventcount": 1,
                        "eventid": 38,
                        "image": "win_image",
                        "method": "NtUserCreateProcess",
                        "operation": "create",
                        "pid": 2188,
                        "ppid": 656,
                        "process_name": "timeout.exe",
                        "work_dir": "C:\\Windows\\system32\\"
                    },
                    null
                ],
                "status": 5,
                "vnc": "https://app.threat.zone/cloudvnc/index.html?path=?token=95b6bc52-d040-4d82-a98b-af6fd5f6feea"
            },
            "SHA1": "0cd47f6bb5bb8e8e9dc01286adcc493acf5dd649",
            "SHA256": "80b5c38471c54298259cec965619fccb435641a01ee4254a3d7c62ec47849108",
            "STATUS": 5,
            "TYPE": "dynamic",
            "UUID": "95b6bc52-d040-4d82-a98b-af6fd5f6feea"
        },
        "IOC": {
            "DOMAIN": [],
            "EMAIL": [],
            "IP": [],
            "URL": []
        }
    }
}
```

#### Context Example for Static Scan

Note: Long output parts are truncated

```json
{
    "DBotScore": {
        "Indicator": "a480da20defb3ed0982abd90589aa23ddef915bf92bc41f0186e56bd7a728f2b",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 3,
        "Type": "file",
        "Vendor": "ThreatZone"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "b6900c7d6942a08d829bcf9d68efd5b1"
            },
            {
                "type": "SHA1",
                "value": "500dabee3263b852788d46d3794a372f625c2c55"
            },
            {
                "type": "SHA256",
                "value": "a480da20defb3ed0982abd90589aa23ddef915bf92bc41f0186e56bd7a728f2b"
            }
        ],
        "MD5": "b6900c7d6942a08d829bcf9d68efd5b1",
        "Malicious": {
            "Description": null,
            "Vendor": "ThreatZone"
        },
        "SHA1": "500dabee3263b852788d46d3794a372f625c2c55",
        "SHA256": "a480da20defb3ed0982abd90589aa23ddef915bf92bc41f0186e56bd7a728f2b"
    },
    "ThreatZone": {
        "Analysis": {
            "INFO": {
                "file_name": "AIT.msi",
                "private": false
            },
            "LEVEL": 3,
            "MD5": "b6900c7d6942a08d829bcf9d68efd5b1",
            "REPORT": {
                "analysis_time": "33.30021 seconds",
                "embedded_files": [],
                "enabled": true,
                "file_info": {
                    "_id": "65f74ad56a77b38eba4bab5c",
                    "entropy": 7.66,
                    "file_type": "Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.2, MSI Installer, Code page: 1252, Title: Installation Database, Subject: Autodesk Inventory Tool, Author: Autodesk, Keywords: Installer, Comments: This installer database contains the logic and data required to install Autodesk Inventory Tool., Template: Intel;1033, Revision Number: {D9AFAE91-12C7-4C1D-8466-404FA23EEB67}, Create Time/Date: Mon Jul 17 12:55:22 2023, Last Saved Time/Date: Mon Jul 17 12:55:22 2023, Number of Pages: 200, Number of Words: 2, Name of Creating Application: Windows Installer XML Toolset (3.11.2.4516), Security: 2",
                    "filesize": "7.56 MB",
                    "md5": "b6900c7d6942a08d829bcf9d68efd5b1",
                    "mime_type": "application/x-msi",
                    "sha1": "500dabee3263b852788d46d3794a372f625c2c55",
                    "sha256": "a480da20defb3ed0982abd90589aa23ddef915bf92bc41f0186e56bd7a728f2b",
                    "ssdeep": "98304:mbsxVo2DmWxpMvizM6+Q2+RsN4Tc9N9xhJSPDQ/zLggse/Z39zW/iW8KgWWcC3eX:6sxa2CWgkM6olOgH78D6LgOhNwLLX"
                },
                "ioc": {
                    "_id": "65f74ad56a77b38eba4bab5a",
                    "domain": [],
                    "email": [],
                    "http_requests": [],
                    "ip": [],
                    "irc": [],
                    "possible_payload": [],
                    "ssdp_requests": [],
                    "url": [
                    ]
                },
                "level": 3,
                "matched_yara_rules": {
                    "_id": "65f74ad56a77b38eba4bab5b",
                    "info": [
                        "gzip",
                        "contains_base64",
                        "domain",
                        "office_magic_bytes",
                        "NETexecutableMicrosoft",
                        "IP",
                        "url",
                        "maldoc_OLE_file_magic_number"
                    ],
                    "malware": [],
                    "suspicious": [
                        "anti_dbg",
                        "DebuggerCheck__API",
                        "Anti_Automated_Sandbox",
                        "Qemu_Detection",
                        "Misc_Suspicious_Strings",
                        "win_files_operation",
                        "db_connection",
                        "VMWare_Detection_1",
                        "VBox_Detection",
                        "Embedded_PE",
                        "win_registry",
                        "Debugging_API"
                    ]
                },
                "ole_streams": [],
                "report_info": {
                    "dde_links": [],
                    "external_relationships": [],
                    "vba_project_bin_hash": null,
                    "vba_stomping": false
                },
                "scanType": "Office",
                "score": 7,
                "status": 5
            },
            "SHA1": "500dabee3263b852788d46d3794a372f625c2c55",
            "SHA256": "a480da20defb3ed0982abd90589aa23ddef915bf92bc41f0186e56bd7a728f2b",
            "STATUS": 5,
            "TYPE": "static",
            "UUID": "ffd80363-005f-484d-af96-534c4c40d902"
        },
        "IOC": {
            "DOMAIN": [],
            "EMAIL": [],
            "IP": [],
            "URL": []
        }
    }
}
```

#### Context Example for CDR

Note: Long output parts are truncated

```json
{
    "DBotScore": {
        "Indicator": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 0,
        "Type": "file",
        "Vendor": "ThreatZone"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "cf543c55343c6307349aafd098fb6958"
            },
            {
                "type": "SHA1",
                "value": "1bec0d7bfea812ca7aa1f5399bb7ff3671006331"
            },
            {
                "type": "SHA256",
                "value": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca"
            }
        ],
        "MD5": "cf543c55343c6307349aafd098fb6958",
        "SHA1": "1bec0d7bfea812ca7aa1f5399bb7ff3671006331",
        "SHA256": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca"
    },
    "ThreatZone": {
        "Analysis": {
            "INFO": {
                "file_name": "fff2035c-def9-482c-9e1a-405c4d427833.docx",
                "private": false
            },
            "LEVEL": 0,
            "MD5": "cf543c55343c6307349aafd098fb6958",
            "REPORT": {
                "data": {
                    "analysis_time": "4.59101 seconds",
                    "description": "File sanitized successfully."
                },
                "enabled": true,
                "level": 0,
                "removed": [
                    "VBA Macro"
                ],
                "sanitized": [],
                "status": 5
            },
            "SHA1": "1bec0d7bfea812ca7aa1f5399bb7ff3671006331",
            "SHA256": "945678e901efcd35ece87a1a0eba82f39feb7d45ea4d38330a4795d1338872ca",
            "STATUS": 5,
            "TYPE": "cdr",
            "UUID": "1170250a-40ac-4b73-84f7-3c0b6026d8af"
        },
        "IOC": {
            "DOMAIN": [],
            "EMAIL": [],
            "IP": [],
            "URL": []
        }
    }
}
```

#### Human Readable Output Example For Sandbox

|ANALYSIS TYPE|FILE_NAME|MD5|PRIVATE|SHA1|SHA256|STATUS|THREAT_LEVEL|UUID|
|---|---|---|---|---|---|---|---|---|
| dynamic | 4fa7ece6f7c3866eb2c2eeb56c0b97f1b231afaf89cc77a73fde654bf256ab82.exe | cbb2add696989c174fc38c3782796f9b | true | f9a9dc82a60b041457b5280fa09ef891a379e079 | 4fa7ece6f7c3866eb2c2eeb56c0b97f1b231afaf89cc77a73fde654bf256ab82 | Submission is finished | Suspicious | 98b56bcf-7564-48a7-88a7-c0803a8bb6c6 |


#### Human Readable Output For Static-Scan

|ANALYSIS TYPE|FILE_NAME|MD5|PRIVATE|SHA1|SHA256|STATUS|THREAT_LEVEL|UUID|
|---|---|---|---|---|---|---|---|---|
| static | 75a8d3f14276963f76df3fe789f1d607d5d51dd63a86dde72cc38e9229d3ff4b | c1ee10ff2d67fbf0326b2c66a66a2f5e | false | b5ca1e30b68d158620c334c9489e36e188638c04 | 75a8d3f14276963f76df3fe789f1d607d5d51dd63a86dde72cc38e9229d3ff4b | Submission is finished | Malicious | 953cae36-e712-4bbd-b353-d3fa42b99dbd |


#### Human Readable Output For CDR

|ANALYSIS TYPE|FILE_NAME|MD5|PRIVATE|SHA1|SHA256|STATUS|THREAT_LEVEL|UUID|
|---|---|---|---|---|---|---|---|---|
| cdr | ef75466ef44f193e00c09e827937effd8f3114ef24d34e9b0972fa0fdd3805ba.doc | 269ca98fb9604d8cfe4298f2b966ff73 | false | b02833cd16afa4acd869ad48e00ebcc4211e40d9 | ef75466ef44f193e00c09e827937effd8f3114ef24d34e9b0972fa0fdd3805ba | Submission is finished | Not Measured | d3b1bea1-0b88-4676-a389-eb6eeae3c19c |