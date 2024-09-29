Malwation AIMA malware analysis sandboxing.

## Configure Malwation AIMA in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://aima.malwation.com) |  | True |
| AIMA API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| CAP API Key | It is additional for MALWATION Content Analysis Platform. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aima-upload-sample
***
Submits a sample to AIMA for analysis.


#### Base Command

`aima-upload-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Choose what environment you want to run your submission. Possible values are: win7x64, win10x64. Default is win7x64. | Required | 
| isPublic | Privacy of the submission. Possible values are: true, false. Default is false. | Required | 
| entry_id | Entry ID of the file to submit. Possible values are: . | Required | 
| timeout | Duration of the submission analysis. Possible values are: 1, 2, 5, 8. Default is 1. | Optional | 
| mouse_simulation | Enable human simulation. Possible values are: true, false. Default is false. | Optional | 
| config_extractor | Malware Config Extractor Possible values are: true, false. Default is false. | Optional | 
| https_inspection | Https inspection to read encrypted traffic. Possible values are: true, false. Default is false. | Optional | 
| full_memory_dump | If you want to access MemProcFS Module enable this metafield. Possible values are: true, false. Default is false. | Optional | 
| enable_net | Enable Internet Connection Possible values are: true, false. Default is false. | Optional | 
| work_path | The working path of the submission. Possible values are: desktop, appdata, windows, temp. Default is desktop. | Optional | 
| zip_pass | Password of the zip file. Do not use if archive has no password. | Optional | 
| file_from_zip | Name of the sample in the zip file.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AIMA.Analysis.UUID | String | UUID of sample. | 
| AIMA.Analysis.URL | String | URL of analysis of sample. | 

#### Command Example
```
aima-upload-sample environment=win7x64 isPublic=true  entry_id=79@4 
```

#### Context Example
```json
{
    "message": "File successfully uploaded, now you can track your submissions progress from /checkSubmissionStatus/2661ca6d-8989-45b1-b912-203fa2c60a21 or /getSubmission/2661ca6d-8989-45b1-b912-203fa2c60a21",
    "uuid": "2661ca6d-8989-45b1-b912-203fa2c60a21",
    "link": "https://aima.malwation.com/submission/2661ca6d-8989-45b1-b912-203fa2c60a21"
}
```

### aima-get-result
***
Retrive the analysis result from AIMA Sandbox.


#### Base Command

`aima-get-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AIMA.Result.STATUS | String | The status of the submission scanning process. | 
| AIMA.Result.LEVEL | String | Threat Level of the scanned file. \(malicious, suspicious or informative\) | 
| AIMA.Result.URL | String | The result page url of the submission. | 
| AIMA.Result.MD5 | String | The md5 hash of the submission. | 
| AIMA.Result.INFO | String | Contains the file name, scan process status and public status. | 
| AIMA.Result.SHA1 | String | The sha1 hash of the submission. | 
| AIMA.Result.SHA256 | String | The sha256 hash of the submission. | 
| AIMA.Result.ID | String | The ID of the submission | 

#### Command Example
```
aima-get-result uuid=79@4 
```

#### Context Example
```json
{
    "submission": {
        "file_info": {
            "hashes": {
                "md5": "6ac062d21f08f139d9f3d1e335e72e22",
                "sha1": "9e967a759e894a83c4b693e81c031d7214a8e699",
                "sha256": "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"
            },
            "original_name": "Kraken.exe",
            "status_id": 5,
            "isPublic": false,
            "tags": [
                "analysed"
            ],
            "submission_date": "25.02.2022 16:49:26",
            "level": "Malicious"
        },
        "uuid": "35b7d3f9-79e2-4d65-9a5a-01badcafc782",
        "metafields": {
            "environment": "Windows 7 x64",
            "work_path": "Desktop",
            "timeout": "2",
            "mouse_simulation": false,
            "config_extractor": false,
            "https_inspection": false,
            "full_memory_dump": false,
            "enable_net": false
        },
        "resultURL": "https://aima.malwation.com/submission/35b7d3f9-79e2-4d65-9a5a-01badcafc782/report/overview"
    },
    "submissionLevel": "Malicious",
    "statusID": 5,
    "status": "Finished"
}
```

### aima-cap-static-upload-sample
***
Submits sample to Malwation CAP for static analysis.


#### Base Command

`aima-cap-static-upload-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry id of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CAP.Static.UUID | String | The uuid value of the submission. | 

#### Command Example
```
aima-cap-static-upload-sample entry_id=571@7d
```

#### Context Example
```json
{
    "message": "File successfully uploaded d25d3ae7-78b4-4608-838e-beac5dacb39c.exe",
    "uid": "d25d3ae7-78b4-4608-838e-beac5dacb39c"
}
```

### aima-cap-mav-upload-sample
***
Submits sample to Malwation CAP for mav analysis.


#### Base Command

`aima-cap-mav-upload-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The Entry id of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CAP.Mav.UUID | String | The uuid value of the submission. | 

#### Command Example
```
aima-cap-mav-upload-sample entry_id=571@7d
```

#### Context Example
```json
{
    "message": "File successfully uploaded d25d3ae7-78b4-4608-838e-beac5dacb39c.exe",
    "uid": "d25d3ae7-78b4-4608-838e-beac5dacb39c"
}
```

### aima-cap-static-get-submission
***
Retrive static analysis result from Malwation CAP.


#### Base Command

`aima-cap-static-get-submission`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The uuid of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CAP.Static.SCORE | String | Thread level of the scanned file. \(malicious, suspicious or informative\) | 
| CAP.Static.WEIGHT | Number | The weight score of detection. | 
| CAP.Static.STATUS | String | The status of the submission scanning process. | 
| CAP.Static.YARA | String | The matched yara rules with sample. | 
| CAP.Static.ENTROPY | Number | The entropy value of sample. | 


#### Command Example
```
aima-cap-static-get-submission uuid=407aa78e-cd1c-4568-b1e2-616fce50cacc 
```

#### Context Example
```json
{
    "Score": [
        "Suspicious",
        "6.32"
    ],
    "File Info": {
        "Filename": "fb194ccc2992c2949541d967c2e0d4d14cc95049087cc9a89b76e85a1bd12a64.exe",
        "Filesize": "127.50 KB",
        "MD5": "c916be78c2c7705084ec93aa536955ad",
        "SHA1": "e549f37404220e1be52ad6d23a62ba91b66d598b",
        "SHA256": "fb194ccc2992c2949541d967c2e0d4d14cc95049087cc9a89b76e85a1bd12a64",
        "SSDEEP": "1536:9r6sFY5eejw7xEx0vxEaqhIDImJ0b/6EKEcFpiOWBLD/tn0Kcl:9r68cK7xy0vxihIDImJ0bC77wB3VnbY",
        "MIME Type": "application/x-dosexec",
        "File Type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
        "Entropy": "5.81"
    },
    "Checksum": false,
    "HasOverlay": false,
    "File Header": {
        "Machine": "IMAGE_FILE_MACHINE_I386",
        "Number of Sections": 3,
        "TimeDateStamp": "Sep 03 2021 18:03:53",
        "Pointer to Symbol Table": 0,
        "Number of Symbols": 0,
        "Size of Optional Header": "224 bytes",
        "Characteristics": 258
    },
    "Imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
    "Imports": {
        "mscoree.dll": [
            {
                "address": "0x402000",
                "name": "_CorExeMain",
                "blacklist": false
            }
        ]
    },
    "Exports": null,
    "Sections": [
        {
            "Name": ".text",
            "Virtual Address": "0x2000",
            "Virtual Size": "0x1e654",
            "Raw Size": "0x1e800",
            "Entropy": "5.82",
            "MD5": "9156435bfbb4b37eedd339607096f2af"
        },
        {
            "Name": ".rsrc",
            "Virtual Address": "0x22000",
            "Virtual Size": "0x1077",
            "Raw Size": "0x1200",
            "Entropy": "4.86",
            "MD5": "a423593c987ffa8998c959f2412129f2"
        },
        {
            "Name": ".reloc",
            "Virtual Address": "0x24000",
            "Virtual Size": "0xc",
            "Raw Size": "0x200",
            "Entropy": "0.08",
            "MD5": "42bbc02695d421e6b2eb55c3c54ff7fe"
        }
    ],
    "Resources": [
        {
            "Name": "RT_VERSION",
            "Size": "892.00 B",
            "Offset": "0x000220a0",
            "Type": "data",
            "Lang": "LANG_NEUTRAL",
            "Sublang": "SUBLANG_NEUTRAL",
            "SHA256": "490fdec38fc44d7532cf20175c3679773df3321dab28de967cab68862db5b073",
            "Entropy": "3.43"
        },
        {
            "Name": "RT_MANIFEST",
            "Size": "3.09 KB",
            "Offset": "0x0002241c",
            "Type": "XML 1.0 document, UTF-8 Unicode (with BOM) text, with CRLF line terminators",
            "Lang": "LANG_NEUTRAL",
            "Sublang": "SUBLANG_NEUTRAL",
            "SHA256": "51ac86fb532fb5883231be4ef7538255e6875d63fa62c8035d72f4d65c0ec114",
            "Entropy": "5.01"
        }
    ],
    "Debug Info": null,
    "Strings": [
        {
            "value": "L!This program cannot be run in DOS mode.",
            "hint": null,
            "blacklist": false
        }
    ],
    "ATTCK": {},
    "MBC": {},
    "CAPABILITY": {
        "executable/pe/section/rsrc": [
            "contain a resource (.rsrc) section"
        ],
        "internal/limitation/file": [
            "(internal) dotnet file limitation"
        ],
        "runtime/dotnet": [
            "compiled to the .NET platform"
        ]
    },
    "Matched YARA rules": [
        "IP",
        "NETexecutableMicrosoft",
        "contains_base64",
        "network_smtp_dotNet",
        "keylogger",
        "Microsoft_Visual_Studio_NET",
        "Microsoft_Visual_C_v70_Basic_NET_additional",
        "Microsoft_Visual_C_Basic_NET",
        "Microsoft_Visual_Studio_NET_additional",
        "Microsoft_Visual_C_v70_Basic_NET",
        "NET_executable_",
        "NET_executable",
        "IsPE32",
        "IsNET_EXE",
        "IsWindowsGUI",
        "Big_Numbers1",
        "Dropper_Strings",
        "Misc_Suspicious_Strings",
        "win_hook",
        "domain",
        "url"
    ],
    "Analysis Time": 4.741647481918335
}

```

### aima-cap-mav-get-submission
***
Retrive mav analysis result from Malwation CAP.


#### Base Command

`aima-cap-mav-get-submission`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The uuid value of submission | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CAP.Mav.COUNT | Number | The count of the detection by engines. | 
| CAP.Mav.SCORE | String | Threat Level of the scanned file \(malicious, suspicious or informative\) | 
| CAP.Mav.DETECTIONS | Number | The results of detections by engines. | 
| CAP.Mav.STATUS | String | The status of the submission scanning process. | 

#### Command Example
```
aima-cap-mav-upload-sample entry_id=571@7d
```

#### Context Example
```json
{
    "scan_results": [
        {
            "Engine1": {
                "infected": "false"
            }
        },
        {
            "Engine2": {
                "infected": "true",
                "name": "malware"
            }
        },
        {
            "Engine3": {
                "infected": "true",
                "name": "malware"
            }
        },
        
    ],
    "detection": "2",
    "status": "malicious"
}

```