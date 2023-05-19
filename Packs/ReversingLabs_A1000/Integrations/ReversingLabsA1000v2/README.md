ReversingLabs A1000 advanced Malware Analysis Platform.
This integration was integrated and tested with versions 8.0.0 and up of ReversingLabs A1000.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-reversinglabs-a1000-v2).

## Configure ReversingLabs A1000 v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ReversingLabs A1000 v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | ReversingLabs A1000 instance URL | True |
    | API Token | True |
    | Verify host certificates | False |
    | Reliability | False |
    | Wait time between report fetching retries (seconds). Deafult is 2 seconds. | False |
    | Number of report fetching retries. Default is 30. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### reversinglabs-a1000-get-results

***
Retrieve sample analysis results

#### Base Command

`reversinglabs-a1000-get-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | file hash. | Required | 

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
| ReversingLabs.a1000_report | Unknown | A1000 report | 

#### Command example
```!reversinglabs-a1000-get-results hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "a322205db6c3b1c451725b84f1d010cc"
            },
            {
                "type": "SHA1",
                "value": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6"
            },
            {
                "type": "SHA256",
                "value": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2"
            }
        ],
        "MD5": "a322205db6c3b1c451725b84f1d010cc",
        "Malicious": {
            "Description": "antivirus - Win32.Trojan.Delf",
            "Vendor": "ReversingLabs A1000 v2"
        },
        "SHA1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
        "SHA256": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2"
    },
    "InfoFile": {
        "EntryID": "6928@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "A1000 report file",
        "Size": 13174,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_report": {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [
                {
                    "aliases": [
                        "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl.zip"
                    ],
                    "category": "archive",
                    "classification": "malicious",
                    "classification_origin": {
                        "imphash": "c57e34b759dff2e57f71960b2fdb93da",
                        "md5": "8521e64c683e47c1db64d80577513016",
                        "sha1": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad",
                        "sha256": "43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1",
                        "sha512": "8a1c9512fa167b938ea31c047a48dd6ec36d9b22443bc4ee6b97a116e16ff33427645ac76349f531cd9a672b4fffc3c4c92d1c82d2a71241915c1499336fd221"
                    },
                    "classification_reason": "antivirus",
                    "classification_result": "Win32.Trojan.Delf",
                    "classification_source": 513,
                    "extracted_file_count": 85,
                    "file_size": 607237,
                    "file_subtype": "Archive",
                    "file_type": "Binary",
                    "id": 3065,
                    "identification_name": "ZIP",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-12-19T11:39:10.929115Z",
                    "local_last_seen": "2023-04-27T09:08:18.293435Z",
                    "md5": "a322205db6c3b1c451725b84f1d010cc",
                    "riskscore": 10,
                    "sha1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
                    "sha256": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2",
                    "sha512": "d1fd72d5a52d75f23836016772e8895d901fa5a1cb1f9b25ba455db6cccbd97e9daf43fde4f8bb77b43c0b5c4937405d51dece20cda7fa7db7600715c7769554",
                    "summary": {
                        "id": 3065,
                        "indicators": [
                            {
                                "category": 22,
                                "description": "The file is password-protected or contains a password-protected file.",
                                "id": 1177,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Tag Match",
                                        "description": "Matched password tag",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "The file is encrypted or contains an encrypted file.",
                                "id": 1178,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Tag Match",
                                        "description": "Matched encrypted tag",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            }
                        ],
                        "sha1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
                        "unpacking_status": {
                            "failed": 0,
                            "partial": 0,
                            "success": 1
                        }
                    },
                    "tags": {
                        "ticore": [
                            "antivirus",
                            "entropy-high",
                            "contains-pe",
                            "indicator-file",
                            "encrypted",
                            "password"
                        ],
                        "user": []
                    },
                    "ticloud": {
                        "classification": "goodware",
                        "classification_reason": "antivirus",
                        "classification_result": null,
                        "first_seen": "2022-12-19T11:39:11Z",
                        "last_seen": "2023-04-27T09:09:11Z",
                        "riskscore": 5
                    },
                    "ticore": {
                        "application": {},
                        "attack": [],
                        "behaviour": {},
                        "browser": {},
                        "certificate": {},
                        "classification": {
                            "classification": 3,
                            "factor": 5,
                            "propagated": true,
                            "propagation_source": {
                                "name": "sha1",
                                "value": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad"
                            },
                            "rca_factor": 10,
                            "result": "Win32.Trojan.Delf",
                            "scan_results": [
                                {
                                    "classification": 3,
                                    "factor": 5,
                                    "ignored": false,
                                    "name": "Antivirus (based on the RCA Classify)",
                                    "rca_factor": 10,
                                    "result": "Win32.Trojan.Delf",
                                    "type": 1,
                                    "version": "2.82"
                                },
                                {
                                    "classification": 1,
                                    "factor": 5,
                                    "ignored": false,
                                    "name": "Antivirus (based on the RCA Classify)",
                                    "rca_factor": 5,
                                    "result": "",
                                    "type": 1,
                                    "version": "2.73"
                                }
                            ]
                        },
                        "document": {},
                        "email": {},
                        "indicators": [
                            {
                                "category": 22,
                                "description": "The file is password-protected or contains a password-protected file.",
                                "id": 1177,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Tag Match",
                                        "description": "Matched password tag",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "The file is encrypted or contains an encrypted file.",
                                "id": 1178,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Tag Match",
                                        "description": "Matched encrypted tag",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            }
                        ],
                        "info": {
                            "file": {
                                "entropy": 7.999701516776105,
                                "file_subtype": "Archive",
                                "file_type": "Binary",
                                "hashes": [
                                    {
                                        "name": "md5",
                                        "value": "a322205db6c3b1c451725b84f1d010cc"
                                    },
                                    {
                                        "name": "rha0",
                                        "value": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6"
                                    },
                                    {
                                        "name": "sha1",
                                        "value": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6"
                                    },
                                    {
                                        "name": "sha256",
                                        "value": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2"
                                    },
                                    {
                                        "name": "sha512",
                                        "value": "d1fd72d5a52d75f23836016772e8895d901fa5a1cb1f9b25ba455db6cccbd97e9daf43fde4f8bb77b43c0b5c4937405d51dece20cda7fa7db7600715c7769554"
                                    },
                                    {
                                        "name": "ssdeep",
                                        "value": "12288:CugvoBN+tBSSX/56xDYoZOF0rm48uyJAC9HazaUuM2G0kUZpevP:CugO+f/5wP4sT8Dy4a2UuM25kopg"
                                    }
                                ],
                                "proposed_filename": null,
                                "size": 607237
                            },
                            "identification": {
                                "author": "ReversingLabs",
                                "name": "ZIP",
                                "success": true,
                                "version": "Generic"
                            },
                            "properties": [
                                {
                                    "name": "totalEntries",
                                    "value": "1"
                                },
                                {
                                    "name": "containsEncryptedFiles",
                                    "value": "true"
                                },
                                {
                                    "name": "password",
                                    "value": "infected"
                                },
                                {
                                    "name": "encryptionType",
                                    "value": "ZipCrypto"
                                }
                            ],
                            "statistics": {
                                "file_stats": [
                                    {
                                        "count": 1,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "ZIP:Generic"
                                            }
                                        ],
                                        "subtype": "Archive",
                                        "type": "Binary"
                                    },
                                    {
                                        "count": 38,
                                        "identifications": [
                                            {
                                                "count": 38,
                                                "name": "IconResource:Generic"
                                            }
                                        ],
                                        "subtype": "None",
                                        "type": "Binary"
                                    },
                                    {
                                        "count": 38,
                                        "identifications": [
                                            {
                                                "count": 38,
                                                "name": "ICO:Generic"
                                            }
                                        ],
                                        "subtype": "None",
                                        "type": "Image"
                                    },
                                    {
                                        "count": 1,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "Exe",
                                        "type": "PE"
                                    },
                                    {
                                        "count": 7,
                                        "identifications": [
                                            {
                                                "count": 7,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "None",
                                        "type": "Text"
                                    },
                                    {
                                        "count": 1,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "XML",
                                        "type": "Text"
                                    }
                                ]
                            },
                            "unpacking": {
                                "status": 2,
                                "warnings": [
                                    "Contains encrypted entries"
                                ]
                            }
                        },
                        "interesting_strings": [],
                        "malware": {},
                        "media": {},
                        "mobile": {},
                        "protection": {},
                        "security": {},
                        "signatures": null,
                        "software_package": {},
                        "story": "This file (SHA1: a94775deb818a4d68635eeed3d16abc7f7b8bdd6) was identified as an encrypted ZIP archive. There are 85 extracted files.",
                        "strings": [],
                        "web": {}
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>None

### reversinglabs-a1000-upload-sample

***
Upload sample to A1000 for analysis

#### Base Command

`reversinglabs-a1000-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The file entry to upload. | Required | 
| comment | A comment to add to the file. | Optional | 
| tags | List of tags for the file. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_upload_report | Unknown | A1000 report | 

### reversinglabs-a1000-upload-sample-and-get-results

***
Upload sample to A1000 and retrieve analysis results

#### Base Command

`reversinglabs-a1000-upload-sample-and-get-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The file entry to upload. | Required | 
| comment | A comment to add to the file. | Optional | 
| tags | List of tags for the file. | Optional | 

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
| ReversingLabs.a1000_report | Unknown | A1000 report | 

### reversinglabs-a1000-delete-sample

***
Delete an uploaded sample from A1000

#### Base Command

`reversinglabs-a1000-delete-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The hash to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_delete_report | Unknown | A1000 file delete report | 

#### Command example
```!reversinglabs-a1000-delete-sample hash="024e73a62d01e3a9c030c5e8aafa8a02cdbe17c9"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "6904@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "Delete sample report file",
        "Size": 490,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_delete_report": {
            "results": {
                "code": 200,
                "detail": {
                    "md5": "bd3891cf722dfea02dee568b90ccfc86",
                    "sha1": "024e73a62d01e3a9c030c5e8aafa8a02cdbe17c9",
                    "sha256": "c6b7b99272d3d9eeb591f3ecfab0bca4da5af50669e4a941f421b94676378886",
                    "sha512": "3ed88b382182f968fdea06fabb0113e941841b8f55392a60bd97873a3ecbdcf3b30a38b0b889befa95ec35eca2775b16951425dc83b4e78085c613e20bac5e4e"
                },
                "message": "Sample deleted successfully."
            }
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 delete sample
> **Message:** Sample deleted successfully.
>    **MD5:** bd3891cf722dfea02dee568b90ccfc86
>    **SHA1:** 024e73a62d01e3a9c030c5e8aafa8a02cdbe17c9
>    **SHA256:** c6b7b99272d3d9eeb591f3ecfab0bca4da5af50669e4a941f421b94676378886

### reversinglabs-a1000-list-extracted-files

***
List files extracted from a sample

#### Base Command

`reversinglabs-a1000-list-extracted-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The sample hash. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_list_extracted_report | Unknown | A1000 list extracted files report | 

#### Command example
```!reversinglabs-a1000-list-extracted-files hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "6950@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "List extracted files report file",
        "Size": 71254,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_list_extracted_report": [
            {
                "container_sha1": null,
                "filename": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl",
                "id": 15408,
                "parent_relationship": null,
                "path": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl",
                "sample": {
                    "category": "application",
                    "classification": "malicious",
                    "classification_result": "Win32.Trojan.Delf",
                    "extracted_file_count": 84,
                    "file_size": 1432064,
                    "file_subtype": "Exe",
                    "file_type": "PE",
                    "id": 1327,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 10,
                    "sha1": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad",
                    "type_display": "PE/Exe"
                }
            },
            {
                "container_sha1": null,
                "filename": "1",
                "id": 15409,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "3",
                "id": 15410,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/3",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "6",
                "id": 15411,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/6",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "2",
                "id": 15412,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/2",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "5",
                "id": 15413,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/5",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15414,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/0",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "4",
                "id": 15415,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/4",
                "sample": {
                    "category": "other",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "17",
                "id": 15416,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/17",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1343,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "60bd89bb789125ac03e44b0e4ec32415843397d5",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "26",
                "id": 15417,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/26",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1344,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "1db12816d9768f373609d02a1c7d678575e2e62f",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "18",
                "id": 15418,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/18",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 176,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1354,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "8e6dea88d5f2cecfb7394660fddb722a267d3363",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1c",
                "id": 15419,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1c",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 176,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1351,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "8a33a39e521b9ffd2415a189d309b58a192f8066",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1d",
                "id": 15420,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1d",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1346,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "077f32f892875bc89e052eb0c7573c97b8f73346",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1f",
                "id": 15421,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1f",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1350,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "8755e0026935565828e59785cab69ab3f397c0df",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "20",
                "id": 15422,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/20",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 176,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1352,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "6bfc1aa0d8a8c4d9c808df984579b818b909c1fd",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "23",
                "id": 15423,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/23",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1353,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "dea77c0696b92f9e154623af6bfa7fb17e33f307",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "22",
                "id": 15424,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/22",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1330,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "d2609e009b442fdc4e5afaa3b210b7ddc9cb5f69",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "b",
                "id": 15425,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/b",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 51240,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1340,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "e6abf0eb5b3ce43f340e953ccca2383ee0ff32d4",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "12",
                "id": 15426,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/12",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1345,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "3def4b67ede5f8b341351587cbc075d0f15dd059",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1b",
                "id": 15427,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1b",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1331,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "239540c1fc5a83d910f13cce84e4b7d3ed53f0d5",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1a",
                "id": 15428,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1a",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1361,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "df17eee01598eb575e434351bb40416a1e1a5056",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "25",
                "id": 15429,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/25",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1337,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "42f3f40f7593a529e135f108ce6e34b46008dc7c",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "24",
                "id": 15430,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/24",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1362,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "8b9a547a838565dbd05d5721a3ae954d5167de09",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "27",
                "id": 15431,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/27",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 872,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1363,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "60aed2416795136a12f9361f76e2271d6d1e506e",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "c",
                "id": 15432,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/c",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 176,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1339,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "cdabfb3feffbbdb51ab2f94cc49e82f8af0d9885",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "14",
                "id": 15433,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/14",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 176,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1336,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "2d7a4f4c1da4fde1165a97416017df7276e7a48e",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1e",
                "id": 15434,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/1e",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1367,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "4c4f01b015c9336f32b8cda77ee78e2cd52e2638",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "28",
                "id": 15435,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/28",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1341,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "e703087e3f0dcd1f02c5607eacea9e46e079226b",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2a",
                "id": 15436,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/2a",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 5672,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1335,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "d170ddeef07cea3e564c9fb4cfbbd6470d1dc12c",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "f",
                "id": 15437,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/f",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1342,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "c5e382d5afff3f7a085ac55926131c48ad0159f5",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "e",
                "id": 15438,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/e",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1357,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "7d4388f901fdb64ee211de7e1bb8cba8cbe2a2ab",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "29",
                "id": 15439,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/29",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 16936,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1358,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "6dcb5bf40d754c73ac32ef7bf6d0d1715914323e",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "7",
                "id": 15440,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/7",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 9640,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1360,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "f715ec7bbe280cd9dd6633165838d2ec73b7bea3",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2b",
                "id": 15441,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/2b",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 16936,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1359,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "a143a50e3299a99ae2108ca3cd3e0b36bd92222d",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "16",
                "id": 15442,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/16",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1384,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1333,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "9169528b1429e0b9fd0c05b316d53d550a879856",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "a",
                "id": 15443,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/a",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1347,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "84b704f1ea2d9716587fcb6c2dfb86229939e305",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2d",
                "id": 15444,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/2d",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2159,
                    "file_subtype": "XML",
                    "file_type": "Text",
                    "id": 1348,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "e9667fde189a3f71e9df30825aca97e1a3daf1d6",
                    "type_display": "Text/XML"
                }
            },
            {
                "container_sha1": null,
                "filename": "13",
                "id": 15445,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/13",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 1128,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1334,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "c052d32521ab0628184f38ab9db63c050d3646fe",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "15",
                "id": 15446,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/15",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1364,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "38a6bda9ff8ec010b6fad779a4bfd7987d8107c1",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "10",
                "id": 15447,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/10",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 176,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1332,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "fc2264052c16c695bd374fa92b33735f28215171",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "d",
                "id": 15448,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/d",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1366,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "f1a68f73d60d439245b781aece01845c6a5532aa",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "9",
                "id": 15449,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/9",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 2440,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1338,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "0a671ee7cd4d2622a0bdbd463c715b8a49536305",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "19",
                "id": 15450,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/19",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1349,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "ea61e68ebb9e398b034f7fda99ed88b342ace20a",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "8",
                "id": 15451,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/8",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 4264,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1368,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "cff0173b6ae16c406b5dd83030fdd771683c1db0",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "11",
                "id": 15452,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/11",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1365,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "f4d38677e1908f1ab2f02b4ff37afb66edf8623f",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2c",
                "id": 15453,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/2c",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 5672,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1356,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "d39abb9afb2e411455ba655356b77c5b85ec7e3a",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "21",
                "id": 15454,
                "parent_relationship": 15408,
                "path": "binary_layer/resource/21",
                "sample": {
                    "category": "other",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 1,
                    "file_size": 296,
                    "file_subtype": "None",
                    "file_type": "Binary",
                    "id": 1355,
                    "identification_name": "IconResource",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "99262578f157538a519883d8a6d5ede05409a01b",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15455,
                "parent_relationship": 15416,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1382,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "aa5af319653eb404ddd591f75f961f129f9d06d9",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15456,
                "parent_relationship": 15417,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1383,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "2c690b5029d9b4d2be3d0c8d4164cab183cdf3f4",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15457,
                "parent_relationship": 15418,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 198,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1392,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "16815d109826dcf94fccb9ae2d2101b083c497d5",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15458,
                "parent_relationship": 15419,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 198,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1389,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "f1bc322f92007c31427076b95dc5b8d9731009fa",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15459,
                "parent_relationship": 15420,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1385,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "ce758cd324b76124bb1f5e48eaa71ded017dd047",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15460,
                "parent_relationship": 15421,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1388,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "03f55fb011bfabc67196e1f1ef35799ca98af61a",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15461,
                "parent_relationship": 15422,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 198,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1390,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "806c7adbecfd3f7ce7b4bd1a6577690a28b6d43b",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15462,
                "parent_relationship": 15423,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1391,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "704e3e3da01bfefb40d8608565080937b3952797",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15463,
                "parent_relationship": 15424,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1369,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "5cc3fd269506acfec0377f6e8ada80d4116e270b",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15464,
                "parent_relationship": 15425,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 51262,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1379,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "a0a81aea2c0c2323c03b0ae89cd6a8a6122b1a3f",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15465,
                "parent_relationship": 15426,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1384,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "844bb2a1ad57c086276476802b2a506c359eb21e",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15466,
                "parent_relationship": 15427,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1370,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "d4b79d68d90a7f0c4f4e8aeff761d1041303c977",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15467,
                "parent_relationship": 15428,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1399,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "bcd1471a1a75d97c64568cdf91a1b08fd597414d",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15468,
                "parent_relationship": 15429,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1376,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "d01fc8f188fbd5d4e432bcd06a5a9602021fb2b7",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15469,
                "parent_relationship": 15430,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1400,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "78660b278435fed197fa170d6d2057d52a4d32fc",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15470,
                "parent_relationship": 15431,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 894,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1401,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 1,
                    "sha1": "389715de86e1ce98360dfde8f98c80e42cc77317",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15471,
                "parent_relationship": 15432,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 198,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1378,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "98b3a775f7f2af6b589b2725bdf626989b1a742a",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15472,
                "parent_relationship": 15433,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 198,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1375,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "8e0fca3babf4c04bf939743f1850fb0e616a0fff",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15473,
                "parent_relationship": 15434,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1405,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "31e2528ce9c692a4894f91fd67c09d691ec343d8",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15474,
                "parent_relationship": 15435,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1380,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "686d77a9c1d246ebde36739193b361fc5069a5ac",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15475,
                "parent_relationship": 15436,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 5694,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1374,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "8293460f76f40a878ceaae50489a7b1f088aa218",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15476,
                "parent_relationship": 15437,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1381,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "c1d0c00758f919d02f9e47b0a35a8e22a24a5067",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15477,
                "parent_relationship": 15438,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1395,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "6b564229a3dbad9e8e77825424e1822d5cc148ef",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15478,
                "parent_relationship": 15439,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 16958,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1396,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "cd19ecd89c22abc95c574c67367f353ee00e21df",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15479,
                "parent_relationship": 15440,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 9662,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1398,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "b09a8d37d067c1aba552962bcab18aff50e862a7",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15480,
                "parent_relationship": 15441,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 16958,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1397,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "a4c31f645098965112f4332b9c36b7650ac1bfb2",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15481,
                "parent_relationship": 15442,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1406,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1372,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "c368d6c92821a04d8d2826c54598162dad6b1907",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15482,
                "parent_relationship": 15443,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1386,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "339d968eb02a6fb9580fe41e221bc50d4208eeac",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15483,
                "parent_relationship": 15445,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 1150,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1373,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "72fcc2682762c0a64ecd76caaca00bd208454c8f",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15484,
                "parent_relationship": 15446,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "goodware",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1402,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "fb897b00f84f7abad1ba95fadeab67e2c0a1e5dc",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15485,
                "parent_relationship": 15447,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 198,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1371,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "4ef1a3f6dda1a26cfdfe025df11df34e07f81ce3",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15486,
                "parent_relationship": 15448,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1404,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "64fb9e509fb6014fce5093985412cd9239b452fc",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15487,
                "parent_relationship": 15449,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 2462,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1377,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "b30b457ea55526306a8da2e2f047f0f9dd42a7b6",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15488,
                "parent_relationship": 15450,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1387,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "d8b5210ff37c5e6cec1c69fb63a4a08edc36f412",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15489,
                "parent_relationship": 15451,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 4286,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1406,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "cd88f5bc26e1f6148ce0c21fc4b38f514cb7a8a5",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15490,
                "parent_relationship": 15452,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1403,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "ac83746b0d74b9dd462124f8de47e6d495731135",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15491,
                "parent_relationship": 15453,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 5694,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1394,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "fe46bc76b12dd3f5edb4121f6fd53d332bc04579",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 15492,
                "parent_relationship": 15454,
                "path": "unpacked_files/0",
                "sample": {
                    "category": "media",
                    "classification": "unknown",
                    "classification_result": null,
                    "extracted_file_count": 0,
                    "file_size": 318,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 1393,
                    "identification_name": "ICO",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-05-11T10:45:34.827922Z",
                    "riskscore": 5,
                    "sha1": "2399d6881d887b1df57beccc08a777446602bdcd",
                    "type_display": "ICO:Generic"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Extracted files
>|SHA1|Name|Path|Info|Size|Local First Seen|Local Last Seen|Malware Status|Risk Score|Identification Name|Identification Version|Type Display|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad | aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl | aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl | PE/Exe | 1432064 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | malicious | 10 |  |  | PE/Exe |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 1 | binary_layer/resource/1 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 3 | binary_layer/resource/3 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 6 | binary_layer/resource/6 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 2 | binary_layer/resource/2 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 5 | binary_layer/resource/5 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 0 | binary_layer/resource/0 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 4 | binary_layer/resource/4 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 0 |  |  | Text/None |
>| 60bd89bb789125ac03e44b0e4ec32415843397d5 | 17 | binary_layer/resource/17 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 1db12816d9768f373609d02a1c7d678575e2e62f | 26 | binary_layer/resource/26 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8e6dea88d5f2cecfb7394660fddb722a267d3363 | 18 | binary_layer/resource/18 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8a33a39e521b9ffd2415a189d309b58a192f8066 | 1c | binary_layer/resource/1c | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 077f32f892875bc89e052eb0c7573c97b8f73346 | 1d | binary_layer/resource/1d | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8755e0026935565828e59785cab69ab3f397c0df | 1f | binary_layer/resource/1f | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 6bfc1aa0d8a8c4d9c808df984579b818b909c1fd | 20 | binary_layer/resource/20 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| dea77c0696b92f9e154623af6bfa7fb17e33f307 | 23 | binary_layer/resource/23 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| d2609e009b442fdc4e5afaa3b210b7ddc9cb5f69 | 22 | binary_layer/resource/22 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| e6abf0eb5b3ce43f340e953ccca2383ee0ff32d4 | b | binary_layer/resource/b | IconResource:Generic | 51240 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 3def4b67ede5f8b341351587cbc075d0f15dd059 | 12 | binary_layer/resource/12 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 239540c1fc5a83d910f13cce84e4b7d3ed53f0d5 | 1b | binary_layer/resource/1b | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| df17eee01598eb575e434351bb40416a1e1a5056 | 1a | binary_layer/resource/1a | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 42f3f40f7593a529e135f108ce6e34b46008dc7c | 25 | binary_layer/resource/25 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8b9a547a838565dbd05d5721a3ae954d5167de09 | 24 | binary_layer/resource/24 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 60aed2416795136a12f9361f76e2271d6d1e506e | 27 | binary_layer/resource/27 | IconResource:Generic | 872 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| cdabfb3feffbbdb51ab2f94cc49e82f8af0d9885 | c | binary_layer/resource/c | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 2d7a4f4c1da4fde1165a97416017df7276e7a48e | 14 | binary_layer/resource/14 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 4c4f01b015c9336f32b8cda77ee78e2cd52e2638 | 1e | binary_layer/resource/1e | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| e703087e3f0dcd1f02c5607eacea9e46e079226b | 28 | binary_layer/resource/28 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| d170ddeef07cea3e564c9fb4cfbbd6470d1dc12c | 2a | binary_layer/resource/2a | IconResource:Generic | 5672 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| c5e382d5afff3f7a085ac55926131c48ad0159f5 | f | binary_layer/resource/f | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 7d4388f901fdb64ee211de7e1bb8cba8cbe2a2ab | e | binary_layer/resource/e | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 6dcb5bf40d754c73ac32ef7bf6d0d1715914323e | 29 | binary_layer/resource/29 | IconResource:Generic | 16936 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| f715ec7bbe280cd9dd6633165838d2ec73b7bea3 | 7 | binary_layer/resource/7 | IconResource:Generic | 9640 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| a143a50e3299a99ae2108ca3cd3e0b36bd92222d | 2b | binary_layer/resource/2b | IconResource:Generic | 16936 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 9169528b1429e0b9fd0c05b316d53d550a879856 | 16 | binary_layer/resource/16 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 84b704f1ea2d9716587fcb6c2dfb86229939e305 | a | binary_layer/resource/a | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| e9667fde189a3f71e9df30825aca97e1a3daf1d6 | 2d | binary_layer/resource/2d | Text/XML | 2159 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 |  |  | Text/XML |
>| c052d32521ab0628184f38ab9db63c050d3646fe | 13 | binary_layer/resource/13 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 38a6bda9ff8ec010b6fad779a4bfd7987d8107c1 | 15 | binary_layer/resource/15 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| fc2264052c16c695bd374fa92b33735f28215171 | 10 | binary_layer/resource/10 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| f1a68f73d60d439245b781aece01845c6a5532aa | d | binary_layer/resource/d | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 0a671ee7cd4d2622a0bdbd463c715b8a49536305 | 9 | binary_layer/resource/9 | IconResource:Generic | 2440 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| ea61e68ebb9e398b034f7fda99ed88b342ace20a | 19 | binary_layer/resource/19 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| cff0173b6ae16c406b5dd83030fdd771683c1db0 | 8 | binary_layer/resource/8 | IconResource:Generic | 4264 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| f4d38677e1908f1ab2f02b4ff37afb66edf8623f | 11 | binary_layer/resource/11 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| d39abb9afb2e411455ba655356b77c5b85ec7e3a | 2c | binary_layer/resource/2c | IconResource:Generic | 5672 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 99262578f157538a519883d8a6d5ede05409a01b | 21 | binary_layer/resource/21 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| aa5af319653eb404ddd591f75f961f129f9d06d9 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 5 | ICO | Generic | ICO:Generic |
>| 2c690b5029d9b4d2be3d0c8d4164cab183cdf3f4 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 16815d109826dcf94fccb9ae2d2101b083c497d5 | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| f1bc322f92007c31427076b95dc5b8d9731009fa | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| ce758cd324b76124bb1f5e48eaa71ded017dd047 | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 03f55fb011bfabc67196e1f1ef35799ca98af61a | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 806c7adbecfd3f7ce7b4bd1a6577690a28b6d43b | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 704e3e3da01bfefb40d8608565080937b3952797 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 5cc3fd269506acfec0377f6e8ada80d4116e270b | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| a0a81aea2c0c2323c03b0ae89cd6a8a6122b1a3f | 0 | unpacked_files/0 | ICO:Generic | 51262 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 844bb2a1ad57c086276476802b2a506c359eb21e | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| d4b79d68d90a7f0c4f4e8aeff761d1041303c977 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| bcd1471a1a75d97c64568cdf91a1b08fd597414d | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| d01fc8f188fbd5d4e432bcd06a5a9602021fb2b7 | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 78660b278435fed197fa170d6d2057d52a4d32fc | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 389715de86e1ce98360dfde8f98c80e42cc77317 | 0 | unpacked_files/0 | ICO:Generic | 894 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 1 | ICO | Generic | ICO:Generic |
>| 98b3a775f7f2af6b589b2725bdf626989b1a742a | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 8e0fca3babf4c04bf939743f1850fb0e616a0fff | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 31e2528ce9c692a4894f91fd67c09d691ec343d8 | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 686d77a9c1d246ebde36739193b361fc5069a5ac | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 8293460f76f40a878ceaae50489a7b1f088aa218 | 0 | unpacked_files/0 | ICO:Generic | 5694 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| c1d0c00758f919d02f9e47b0a35a8e22a24a5067 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 6b564229a3dbad9e8e77825424e1822d5cc148ef | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| cd19ecd89c22abc95c574c67367f353ee00e21df | 0 | unpacked_files/0 | ICO:Generic | 16958 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| b09a8d37d067c1aba552962bcab18aff50e862a7 | 0 | unpacked_files/0 | ICO:Generic | 9662 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| a4c31f645098965112f4332b9c36b7650ac1bfb2 | 0 | unpacked_files/0 | ICO:Generic | 16958 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| c368d6c92821a04d8d2826c54598162dad6b1907 | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 339d968eb02a6fb9580fe41e221bc50d4208eeac | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 72fcc2682762c0a64ecd76caaca00bd208454c8f | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| fb897b00f84f7abad1ba95fadeab67e2c0a1e5dc | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | goodware | 5 | ICO | Generic | ICO:Generic |
>| 4ef1a3f6dda1a26cfdfe025df11df34e07f81ce3 | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 64fb9e509fb6014fce5093985412cd9239b452fc | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| b30b457ea55526306a8da2e2f047f0f9dd42a7b6 | 0 | unpacked_files/0 | ICO:Generic | 2462 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| d8b5210ff37c5e6cec1c69fb63a4a08edc36f412 | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| cd88f5bc26e1f6148ce0c21fc4b38f514cb7a8a5 | 0 | unpacked_files/0 | ICO:Generic | 4286 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| ac83746b0d74b9dd462124f8de47e6d495731135 | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| fe46bc76b12dd3f5edb4121f6fd53d332bc04579 | 0 | unpacked_files/0 | ICO:Generic | 5694 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 2399d6881d887b1df57beccc08a777446602bdcd | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2023-05-11T10:45:34.827922Z | unknown | 5 | ICO | Generic | ICO:Generic |


### reversinglabs-a1000-download-sample

***
Download sample from A1000

#### Base Command

`reversinglabs-a1000-download-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Sample hash to download. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!reversinglabs-a1000-download-sample hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6"```
#### Context Example
```json
{
    "File": {
        "EntryID": "6918@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "application/zip",
        "MD5": "a322205db6c3b1c451725b84f1d010cc",
        "Name": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
        "SHA1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
        "SHA256": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2",
        "SHA512": "d1fd72d5a52d75f23836016772e8895d901fa5a1cb1f9b25ba455db6cccbd97e9daf43fde4f8bb77b43c0b5c4937405d51dece20cda7fa7db7600715c7769554",
        "SSDeep": "12288:CugvoBN+tBSSX/56xDYoZOF0rm48uyJAC9HazaUuM2G0kUZpevP:CugO+f/5wP4sT8Dy4a2UuM25kopg",
        "Size": 607237,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 download sample 
>Requested sample is available for download under the name a94775deb818a4d68635eeed3d16abc7f7b8bdd6

### reversinglabs-a1000-reanalyze

***
Re-analyze sample on A1000

#### Base Command

`reversinglabs-a1000-reanalyze`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The hash of an already uploaded sample. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_reanalyze_report | Unknown | Get extracted files report | 

#### Command example
```!reversinglabs-a1000-reanalyze hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "6955@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "ReAnalyze sample report file",
        "Size": 1777,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_reanalyze_report": {
            "results": [
                {
                    "analysis": [
                        {
                            "code": 201,
                            "message": "Sample is queued for analysis.",
                            "name": "cloud"
                        },
                        {
                            "code": 201,
                            "message": "Sample is queued for core analysis.",
                            "name": "core"
                        },
                        {
                            "code": 201,
                            "message": "Sample is queued for analysis.",
                            "name": "rl_cloud_sandbox"
                        },
                        {
                            "code": 405,
                            "message": "Sandbox integration is not configured.",
                            "name": "cuckoo"
                        },
                        {
                            "code": 405,
                            "message": "Sandbox integration is not configured.",
                            "name": "joe"
                        },
                        {
                            "code": 405,
                            "message": "Sandbox integration is not configured.",
                            "name": "cape"
                        },
                        {
                            "code": 405,
                            "message": "Sandbox integration is not configured.",
                            "name": "fireeye"
                        }
                    ],
                    "detail": {
                        "imphash": "",
                        "md5": "a322205db6c3b1c451725b84f1d010cc",
                        "sha1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
                        "sha256": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2",
                        "sha512": "d1fd72d5a52d75f23836016772e8895d901fa5a1cb1f9b25ba455db6cccbd97e9daf43fde4f8bb77b43c0b5c4937405d51dece20cda7fa7db7600715c7769554"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 re-analyze sample
>**Message:** Sample is queued for analysis.
>    **MD5:** a322205db6c3b1c451725b84f1d010cc
>    **SHA1:** a94775deb818a4d68635eeed3d16abc7f7b8bdd6
>    **SHA256:** d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2

### reversinglabs-a1000-download-extracted-files

***
Download samples obtained through the unpacking process

#### Base Command

`reversinglabs-a1000-download-extracted-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The sample hash we want unpacked samples for. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!reversinglabs-a1000-download-extracted-files hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6"```
#### Context Example
```json
{
    "File": {
        "EntryID": "6913@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "f37bf03a535940018fe86cd2dc381e46",
        "Name": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6.zip",
        "SHA1": "ff2161556c4e5f9e260bcb7b405064c68ee02750",
        "SHA256": "76c5a9d90c26a26febcf306ed9fcbff0fa5834027ffbf14a7ef2f17179f64795",
        "SHA512": "4fa3775ca466e1b307b496688fda2f9276d18a2f67c8198813e1ef9c79604b9f2680aad0cb61252caee8529a45a5a8b15cf2da2d8f3bf9d27bed425fb6d47601",
        "SSDeep": "12288:GrLW2iHCZijVsEPYsqp1wzkZqY+JlySSeBSnY4Xf3sXdAeQQIetUpNZSTJEp69:G2DCZijvwsq7QsqFPDSRF3sX6eQnmEpG",
        "Size": 711879,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 download extraced files 
>Extracted files are available for download under the name a94775deb818a4d68635eeed3d16abc7f7b8bdd6.zip

### reversinglabs-a1000-get-classification

***
Retrieve classification report for a sample

#### Base Command

`reversinglabs-a1000-get-classification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The hash of a desired sample. | Required | 
| localOnly | Return only local classification data for the sample, without falling back to querying TitaniumCloud. Default is False. | Optional | 

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
| ReversingLabs.a1000_classification_report | Unknown | A1000 classification report | 

#### Command example
```!reversinglabs-a1000-get-classification hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6" localOnly="False"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "a322205db6c3b1c451725b84f1d010cc"
            },
            {
                "type": "SHA1",
                "value": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6"
            },
            {
                "type": "SHA256",
                "value": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2"
            }
        ],
        "MD5": "a322205db6c3b1c451725b84f1d010cc",
        "Malicious": {
            "Description": "malicious",
            "Vendor": "ReversingLabs A1000 v2"
        },
        "SHA1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
        "SHA256": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2"
    },
    "InfoFile": {
        "EntryID": "6923@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "Get classification report file",
        "Size": 1297,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_classification_report": {
            "av_scanners": {
                "antivirus": {
                    "scanner_count": 32,
                    "scanner_match": 0,
                    "vendor_count": 21,
                    "vendor_match": 0
                },
                "scanner_count": 32,
                "scanner_match": 0,
                "scanner_percent": 0,
                "vendor_count": 21,
                "vendor_match": 0,
                "vendor_percent": 0
            },
            "classification": "malicious",
            "classification_origin": {
                "imphash": "c57e34b759dff2e57f71960b2fdb93da",
                "md5": "8521e64c683e47c1db64d80577513016",
                "sha1": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad",
                "sha256": "43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1",
                "sha512": "8a1c9512fa167b938ea31c047a48dd6ec36d9b22443bc4ee6b97a116e16ff33427645ac76349f531cd9a672b4fffc3c4c92d1c82d2a71241915c1499336fd221"
            },
            "classification_reason": "Antivirus",
            "classification_result": "Win32.Trojan.Delf",
            "cloud_last_lookup": "2023-05-17T09:14:20Z",
            "data_source": "LOCAL",
            "first_seen": "2022-12-19T11:39:11Z",
            "last_seen": "2023-04-27T09:08:18Z",
            "md5": "a322205db6c3b1c451725b84f1d010cc",
            "riskscore": 10,
            "sha1": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6",
            "sha256": "d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2"
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 get classification for sha1: a94775deb818a4d68635eeed3d16abc7f7b8bdd6
>**Classification:** malicious
>**Riskscore:** 10
>**First seen:** 2022-12-19T11:39:11Z
>**Last seen:** 2023-04-27T09:08:18Z
>**Classification result:** Win32.Trojan.Delf
>**Classification reason:** Antivirus
>**Classification origin:** {'sha1': 'aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad', 'sha256': '43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1', 'sha512': '8a1c9512fa167b938ea31c047a48dd6ec36d9b22443bc4ee6b97a116e16ff33427645ac76349f531cd9a672b4fffc3c4c92d1c82d2a71241915c1499336fd221', 'md5': '8521e64c683e47c1db64d80577513016', 'imphash': 'c57e34b759dff2e57f71960b2fdb93da'}
>**Cloud last lookup:** 2023-05-17T09:14:20Z
>**Data source:** LOCAL
>**Sha1:** a94775deb818a4d68635eeed3d16abc7f7b8bdd6
>**Sha256:** d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2
>**Md5:** a322205db6c3b1c451725b84f1d010cc
>**Av scanners:** {'scanner_count': 32, 'scanner_match': 0, 'scanner_percent': 0.0, 'vendor_count': 21, 'vendor_match': 0, 'vendor_percent': 0.0, 'antivirus': {'vendor_match': 0, 'scanner_match': 0, 'vendor_count': 21, 'scanner_count': 32}}


### reversinglabs-a1000-advanced-search

***
Search for hashes on A1000 using multi-part search criteria.

#### Base Command

`reversinglabs-a1000-advanced-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Advanced search query. | Required | 
| ticloud | Show only cloud results. If omitted, the response will show only local results. Possible values are: true, false. Default is false. | Optional | 
| result_limit | Maximum number of results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_advanced_search_report | Unknown | A1000 classification report | 

#### Command example
```!reversinglabs-a1000-advanced-search query="av-count:5 available:TRUE" ticloud="False" result_limit=5```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "6899@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "Advanced search report file",
        "Size": 2,
        "Type": "ASCII text, with no line terminators"
    },
    "ReversingLabs": {
        "a1000_advanced_search_report": []
    }
}
```

#### Human Readable Output

>## Reversinglabs A1000 advanced Search 
>Full report is returned in a downloadable file

### reversinglabs-a1000-url-report

***
Get a report for the submitted URL.

#### Base Command

`reversinglabs-a1000-url-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_url_report | Unknown | A1000 URL report | 

#### Command example
```!reversinglabs-a1000-url-report url="http://akiwinds.duckdns.org/chats/fre.php"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://akiwinds.duckdns.org/chats/fre.php",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "ReversingLabs": {
        "a1000_url_report": {
            "classification": "malicious",
            "requested_url": "http://akiwinds.duckdns.org/chats/fre.php",
            "third_party_reputations": {
                "sources": [
                    {
                        "detection": "undetected",
                        "source": "phishing_database",
                        "update_time": "2023-05-17T23:00:45"
                    },
                    {
                        "detection": "undetected",
                        "source": "cyren",
                        "update_time": "2023-05-18T05:08:54"
                    },
                    {
                        "detection": "undetected",
                        "source": "cyradar",
                        "update_time": "2023-05-17T06:16:21"
                    },
                    {
                        "detection": "undetected",
                        "source": "netstar",
                        "update_time": "2023-05-18T06:06:19"
                    },
                    {
                        "detection": "undetected",
                        "source": "malsilo",
                        "update_time": "2023-05-17T23:05:47"
                    },
                    {
                        "detection": "undetected",
                        "source": "mute",
                        "update_time": "2023-05-18T05:39:08"
                    },
                    {
                        "detect_time": "2022-06-17T10:36:34",
                        "detection": "malicious",
                        "source": "adminus_labs",
                        "update_time": "2023-05-18T06:05:26"
                    },
                    {
                        "detection": "undetected",
                        "source": "apwg",
                        "update_time": "2023-05-18T01:19:38"
                    },
                    {
                        "detection": "undetected",
                        "source": "0xSI_f33d",
                        "update_time": "2023-05-18T05:21:25"
                    },
                    {
                        "detection": "undetected",
                        "source": "threatfox_abuse_ch",
                        "update_time": "2023-05-17T23:20:08"
                    },
                    {
                        "detection": "undetected",
                        "source": "alphamountain",
                        "update_time": "2023-05-18T06:00:06"
                    },
                    {
                        "detection": "undetected",
                        "source": "phishstats",
                        "update_time": "2023-05-18T03:40:49"
                    },
                    {
                        "detection": "undetected",
                        "source": "comodo_valkyrie",
                        "update_time": "2023-05-17T14:41:03"
                    },
                    {
                        "detection": "undetected",
                        "source": "alien_vault",
                        "update_time": "2023-05-18T00:41:21"
                    },
                    {
                        "detection": "undetected",
                        "source": "osint",
                        "update_time": "2023-05-18T00:30:47"
                    },
                    {
                        "detection": "undetected",
                        "source": "openphish",
                        "update_time": "2023-05-17T16:58:19"
                    },
                    {
                        "detection": "undetected",
                        "source": "mrg",
                        "update_time": "2023-05-18T05:46:05"
                    },
                    {
                        "detection": "undetected",
                        "source": "phishtank",
                        "update_time": "2023-05-18T02:23:29"
                    },
                    {
                        "detection": "undetected",
                        "source": "crdf",
                        "update_time": "2023-05-18T01:32:36"
                    },
                    {
                        "detection": "undetected",
                        "source": "urlhaus",
                        "update_time": "2023-05-17T21:32:27"
                    }
                ],
                "statistics": {
                    "clean": 0,
                    "malicious": 1,
                    "total": 20,
                    "undetected": 19
                }
            }
        }
    },
    "URL": {
        "Data": "http://akiwinds.duckdns.org/chats/fre.php",
        "Malicious": {
            "Description": "malicious",
            "Vendor": "ReversingLabs A1000 v2"
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 URL Report for http:<span>//</span>akiwinds.duckdns.org/chats/fre.php
> **Classification**: malicious
> ## Analysis
> ### Statistics
> **Unknown**: None
>    **Suspicious**: None
>    **Malicious**: None
>    **Goodware**: None
>    **Total**: None
>
>    
>**First analysis**: None
>    **Analysis count**: None
>    
> ### Last analysis
>**No entries.**
>
> ### Analysis history
>**No entries.**
>
> ## Third party reputations
> ### Statistics
> **Total**: 20
>    **Malicious**: 1
>    **Clean**: 0
>    **Undetected**: 19
>    
> ### Sources
>|detection|source|update_time|
>|---|---|---|
>| undetected | phishing_database | 2023-05-17T23:00:45 |
>| undetected | cyren | 2023-05-18T05:08:54 |
>| undetected | cyradar | 2023-05-17T06:16:21 |
>| undetected | netstar | 2023-05-18T06:06:19 |
>| undetected | malsilo | 2023-05-17T23:05:47 |
>| undetected | mute | 2023-05-18T05:39:08 |
>| malicious | adminus_labs | 2023-05-18T06:05:26 |
>| undetected | apwg | 2023-05-18T01:19:38 |
>| undetected | 0xSI_f33d | 2023-05-18T05:21:25 |
>| undetected | threatfox_abuse_ch | 2023-05-17T23:20:08 |
>| undetected | alphamountain | 2023-05-18T06:00:06 |
>| undetected | phishstats | 2023-05-18T03:40:49 |
>| undetected | comodo_valkyrie | 2023-05-17T14:41:03 |
>| undetected | alien_vault | 2023-05-18T00:41:21 |
>| undetected | osint | 2023-05-18T00:30:47 |
>| undetected | openphish | 2023-05-17T16:58:19 |
>| undetected | mrg | 2023-05-18T05:46:05 |
>| undetected | phishtank | 2023-05-18T02:23:29 |
>| undetected | crdf | 2023-05-18T01:32:36 |
>| undetected | urlhaus | 2023-05-17T21:32:27 |


### reversinglabs-a1000-domain-report

***
Get a report for the submitted domain.

#### Base Command

`reversinglabs-a1000-domain-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_domain_report | Unknown | A1000 domain report | 

#### Command example
```!reversinglabs-a1000-domain-report domain="ink-scape.online"```
#### Context Example
```json
{
    "Domain": {
        "Name": "ink-scape.online"
    },
    "ReversingLabs": {
        "a1000_domain_report": {
            "downloaded_files_statistics": {
                "goodware": 0,
                "malicious": 4,
                "suspicious": 0,
                "total": 4,
                "unknown": 0
            },
            "last_dns_records": [
                {
                    "provider": "ReversingLabs",
                    "type": "A",
                    "value": "37.140.192.210"
                }
            ],
            "last_dns_records_time": "2023-05-11T17:46:01",
            "modified_time": "2023-05-18T06:06:19",
            "requested_domain": "ink-scape.online",
            "third_party_reputations": {
                "sources": [
                    {
                        "detection": "undetected",
                        "source": "phishing_database",
                        "update_time": "2023-05-18T01:26:00"
                    },
                    {
                        "detection": "undetected",
                        "source": "0xSI_f33d",
                        "update_time": "2023-05-18T05:21:25"
                    },
                    {
                        "detection": "undetected",
                        "source": "cyradar",
                        "update_time": "2023-05-17T06:16:21"
                    },
                    {
                        "detection": "undetected",
                        "source": "adminus_labs",
                        "update_time": "2023-05-18T05:40:37"
                    },
                    {
                        "detection": "undetected",
                        "source": "apwg",
                        "update_time": "2023-05-18T05:35:59"
                    },
                    {
                        "category": "malware_file",
                        "detect_time": "2023-05-11T05:21:55",
                        "detection": "malicious",
                        "source": "netstar",
                        "update_time": "2023-05-18T06:06:19"
                    },
                    {
                        "detection": "undetected",
                        "source": "threatfox_abuse_ch",
                        "update_time": "2023-05-17T23:20:08"
                    },
                    {
                        "detection": "undetected",
                        "source": "botvrij",
                        "update_time": "2023-05-18T01:25:37"
                    },
                    {
                        "detection": "undetected",
                        "source": "alphamountain",
                        "update_time": "2023-05-18T06:00:06"
                    },
                    {
                        "detection": "undetected",
                        "source": "comodo_valkyrie",
                        "update_time": "2023-05-18T04:52:55"
                    },
                    {
                        "detection": "undetected",
                        "source": "web_security_guard",
                        "update_time": "2022-01-21T06:56:15"
                    },
                    {
                        "detection": "undetected",
                        "source": "osint",
                        "update_time": "2023-05-18T00:30:47"
                    },
                    {
                        "detection": "undetected",
                        "source": "crdf",
                        "update_time": "2023-05-18T01:32:36"
                    }
                ],
                "statistics": {
                    "clean": 0,
                    "malicious": 1,
                    "total": 13,
                    "undetected": 12
                }
            },
            "top_threats": [
                {
                    "files_count": 1,
                    "risk_score": 10,
                    "threat_name": "Win64.Trojan.Casdet"
                },
                {
                    "files_count": 1,
                    "risk_score": 10,
                    "threat_name": "ByteCode-MSIL.Backdoor.DCRat"
                },
                {
                    "files_count": 1,
                    "risk_score": 10,
                    "threat_name": "ByteCode-MSIL.Infostealer.RedLine"
                },
                {
                    "files_count": 1,
                    "risk_score": 10,
                    "threat_name": "Win32.Trojan.Fragtor"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 Domain Report for ink-scape.online
> **Modified time**: 2023-05-18T06:06:19
> ### Top threats
>|files_count|risk_score|threat_name|
>|---|---|---|
>| 1 | 10 | Win64.Trojan.Casdet |
>| 1 | 10 | ByteCode-MSIL.Backdoor.DCRat |
>| 1 | 10 | ByteCode-MSIL.Infostealer.RedLine |
>| 1 | 10 | Win32.Trojan.Fragtor |
>
> ### Downloaded files statistics
> **Unknown**: 0
>    **Suspicious**: 0
>    **Malicious**: 4
>    **Goodware**: 0
>    **Total**: 4
>    
>**Last DNS records time**: 2023-05-11T17:46:01
>    
> ### Last DNS records
>|provider|type|value|
>|---|---|---|
>| ReversingLabs | A | 37.140.192.210 |
>
> ## Third party reputations
> ### Statistics
> **Malicious**: 1
>    **Undetected**: 12
>    **Clean**: 0
>    **Total**: 13
>    
> ### Sources
>|detection|source|update_time|
>|---|---|---|
>| undetected | phishing_database | 2023-05-18T01:26:00 |
>| undetected | 0xSI_f33d | 2023-05-18T05:21:25 |
>| undetected | cyradar | 2023-05-17T06:16:21 |
>| undetected | adminus_labs | 2023-05-18T05:40:37 |
>| undetected | apwg | 2023-05-18T05:35:59 |
>| malicious | netstar | 2023-05-18T06:06:19 |
>| undetected | threatfox_abuse_ch | 2023-05-17T23:20:08 |
>| undetected | botvrij | 2023-05-18T01:25:37 |
>| undetected | alphamountain | 2023-05-18T06:00:06 |
>| undetected | comodo_valkyrie | 2023-05-18T04:52:55 |
>| undetected | web_security_guard | 2022-01-21T06:56:15 |
>| undetected | osint | 2023-05-18T00:30:47 |
>| undetected | crdf | 2023-05-18T01:32:36 |


### reversinglabs-a1000-ip-address-report

***
Get a report for the submitted IP address.

#### Base Command

`reversinglabs-a1000-ip-address-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipAddress | IP address string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_address_report | Unknown | A1000 IP address report | 

#### Command example
```!reversinglabs-a1000-ip-address-report ipAddress="105.101.110.37"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "105.101.110.37",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "IP": {
        "Address": "105.101.110.37"
    },
    "ReversingLabs": {
        "a1000_ip_address_report": {
            "downloaded_files_statistics": {
                "goodware": 0,
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
                "unknown": 0
            },
            "modified_time": "2023-05-18T06:00:06",
            "requested_ip": "105.101.110.37",
            "third_party_reputations": {
                "sources": [
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "alphamountain",
                        "update_time": "2023-05-18T06:00:06"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "apwg",
                        "update_time": "2023-05-17T20:24:44"
                    },
                    {
                        "category": "command_and_control",
                        "detect_time": "2023-05-15T15:20:23",
                        "detection": "malicious",
                        "source": "threatfox_abuse_ch",
                        "update_time": "2023-05-17T23:20:08"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "adminus_labs",
                        "update_time": "2023-05-18T05:40:37"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "osint",
                        "update_time": "2023-05-18T00:30:47"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "feodotracker",
                        "update_time": "2023-05-18T04:27:51"
                    },
                    {
                        "category": null,
                        "detect_time": "2023-05-15T16:32:36",
                        "detection": "malicious",
                        "source": "crdf",
                        "update_time": "2023-05-18T01:32:36"
                    }
                ],
                "statistics": {
                    "clean": 0,
                    "malicious": 2,
                    "total": 7,
                    "undetected": 5
                }
            },
            "top_threats": []
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 IP Address Report for 105.101.110.37
> **Modified time**: 2023-05-18T06:00:06
> ### Top threats
>**No entries.**
>
> ### Downloaded files statistics
> **Unknown**: 0
>    **Suspicious**: 0
>    **Malicious**: 0
>    **Goodware**: 0
>    **Total**: 0
>    
> ## Third party reputations
> ### Statistics
> **Malicious**: 2
>    **Undetected**: 5
>    **Clean**: 0
>    **Total**: 7
>    
> ### Sources
>|category|detect_time|detection|source|update_time|
>|---|---|---|---|---|
>|  |  | undetected | alphamountain | 2023-05-18T06:00:06 |
>|  |  | undetected | apwg | 2023-05-17T20:24:44 |
>| command_and_control | 2023-05-15T15:20:23 | malicious | threatfox_abuse_ch | 2023-05-17T23:20:08 |
>|  |  | undetected | adminus_labs | 2023-05-18T05:40:37 |
>|  |  | undetected | osint | 2023-05-18T00:30:47 |
>|  |  | undetected | feodotracker | 2023-05-18T04:27:51 |
>|  | 2023-05-15T16:32:36 | malicious | crdf | 2023-05-18T01:32:36 |


### reversinglabs-a1000-ip-downloaded-files

***
Get a list of files downloaded from an IP address.

#### Base Command

`reversinglabs-a1000-ip-downloaded-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipAddress | IP address string. | Required | 
| extendedResults | Return extended results. Default is True. | Optional | 
| classification | Return only results with this classification. | Optional | 
| pageSize | Number of results per query page. Default is 500. | Optional | 
| maxResults | Maximum number of returned results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_address_downloaded_files | Unknown | A1000 Files downloaded from IP address | 

### reversinglabs-a1000-ip-domain-resolutions

***
Get a list of IP-to-domain resolutions.

#### Base Command

`reversinglabs-a1000-ip-domain-resolutions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipAddress | IP address string. | Required | 
| pageSize | Number of results per query page. Default is 500. | Optional | 
| maxResults | Maximum number of returned results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_domain_resolutions | Unknown | A1000 IP-to-domain resolutions | 

#### Command example
```!reversinglabs-a1000-ip-domain-resolutions ipAddress="142.250.186.142" pageSize="5" maxResults="20"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "142.250.186.142",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "IP": {
        "Address": "142.250.186.142"
    },
    "ReversingLabs": {
        "a1000_ip_domain_resolutions": [
            {
                "host_name": "pl16304805.trustedcpmrevenue.com",
                "last_resolution_time": "2022-01-22T14:42:19",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl16023914.revenuenetworkcpm.com",
                "last_resolution_time": "2022-02-15T13:54:37",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "oflinktracker.com",
                "last_resolution_time": "2021-10-21T21:46:53",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl14051455.pvclouds.com",
                "last_resolution_time": "2021-10-24T13:09:25",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "harsh.ehabreda.com",
                "last_resolution_time": "2022-02-12T10:54:41",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl15210080.pvclouds.com",
                "last_resolution_time": "2021-10-24T12:36:38",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "fslink.guvtec.com",
                "last_resolution_time": "2022-04-19T21:13:44",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl16814653.effectivegatetocontent.com",
                "last_resolution_time": "2022-01-22T14:42:38",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "ggle.io",
                "last_resolution_time": "2022-01-06T21:00:37",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl16989062.trustedcpmrevenue.com",
                "last_resolution_time": "2022-02-18T21:26:24",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "ns3.bnhtml.com",
                "last_resolution_time": "2021-10-24T12:35:42",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "api.targetx.com",
                "last_resolution_time": "2022-01-27T21:07:29",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl16898119.trustedcpmrevenue.com",
                "last_resolution_time": "2022-01-22T15:12:57",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "fslink.victig.com",
                "last_resolution_time": "2021-10-23T06:13:46",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "email.mg.agenticpro.com",
                "last_resolution_time": "2021-11-10T20:44:25",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl16800509.effectivegatetocontent.com",
                "last_resolution_time": "2022-01-22T14:42:38",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl16840660.trustedcpmrevenue.com",
                "last_resolution_time": "2022-01-22T14:52:01",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "events-b.mb.mtatradeoftheday.com",
                "last_resolution_time": "2022-04-20T09:45:21",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "pl15739171.cpmgatenetwork.com",
                "last_resolution_time": "2021-10-21T15:37:32",
                "provider": "ReversingLabs"
            },
            {
                "host_name": "plannerladyreality.com",
                "last_resolution_time": "2021-10-25T12:40:09",
                "provider": "ReversingLabs"
            }
        ]
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 IP-to-domain Resolutions for IP address 142.250.186.142
> ### IP-to-domain resolutions
>|host_name|last_resolution_time|provider|
>|---|---|---|
>| pl16304805.trustedcpmrevenue.com | 2022-01-22T14:42:19 | ReversingLabs |
>| pl16023914.revenuenetworkcpm.com | 2022-02-15T13:54:37 | ReversingLabs |
>| oflinktracker.com | 2021-10-21T21:46:53 | ReversingLabs |
>| pl14051455.pvclouds.com | 2021-10-24T13:09:25 | ReversingLabs |
>| harsh.ehabreda.com | 2022-02-12T10:54:41 | ReversingLabs |
>| pl15210080.pvclouds.com | 2021-10-24T12:36:38 | ReversingLabs |
>| fslink.guvtec.com | 2022-04-19T21:13:44 | ReversingLabs |
>| pl16814653.effectivegatetocontent.com | 2022-01-22T14:42:38 | ReversingLabs |
>| ggle.io | 2022-01-06T21:00:37 | ReversingLabs |
>| pl16989062.trustedcpmrevenue.com | 2022-02-18T21:26:24 | ReversingLabs |
>| ns3.bnhtml.com | 2021-10-24T12:35:42 | ReversingLabs |
>| api.targetx.com | 2022-01-27T21:07:29 | ReversingLabs |
>| pl16898119.trustedcpmrevenue.com | 2022-01-22T15:12:57 | ReversingLabs |
>| fslink.victig.com | 2021-10-23T06:13:46 | ReversingLabs |
>| email.mg.agenticpro.com | 2021-11-10T20:44:25 | ReversingLabs |
>| pl16800509.effectivegatetocontent.com | 2022-01-22T14:42:38 | ReversingLabs |
>| pl16840660.trustedcpmrevenue.com | 2022-01-22T14:52:01 | ReversingLabs |
>| events-b.mb.mtatradeoftheday.com | 2022-04-20T09:45:21 | ReversingLabs |
>| pl15739171.cpmgatenetwork.com | 2021-10-21T15:37:32 | ReversingLabs |
>| plannerladyreality.com | 2021-10-25T12:40:09 | ReversingLabs |


### reversinglabs-a1000-ip-urls

***
Get a list of URLs hosted on the requested IP address.

#### Base Command

`reversinglabs-a1000-ip-urls`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipAddress | IP address string. | Required | 
| pageSize | Number of results per query page. Default is 500. | Optional | 
| maxResults | Maximum number of returned results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_urls | Unknown | A1000 URL-s hosted on an IP address | 

#### Command example
```!reversinglabs-a1000-ip-urls ipAddress="142.250.186.142" pageSize="5" maxResults="20"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "142.250.186.142",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "IP": {
        "Address": "142.250.186.142"
    },
    "ReversingLabs": {
        "a1000_ip_urls": [
            {
                "url": "https://vam.simpleintactloop.com/?kw=25&s1=dfadc40091de4d20b5ae5178a3ed04cf&s2=25&s3=1812092"
            },
            {
                "url": "https://consent.youtube.com/m?continue=https://www.youtube.com/playlist?list=PLUdyEkajrVvQgvw3E7Ms4YAvqa8yze0mk&bsft_aaid=d3faaff4-8ea9-405d-9544-4da5a26dc24a&bsft_eid=9ee948cc-69cb-27ef-383f-8b42608edab0&bsft_clkid=a51526e6-0d0d-42ba-a5b2-4ffe739b39b3&bsft_uid=13d7aa07-4c09-453f-85ae-fbd4e975b709&bsft_mid=5b0f75fb-615d-401c-b15c-8e301bce51a0&bsft_txnid=a887540d-743a-4d12-ab6a-9e9a09073a67&bsft_mime_type=html&bsft_ek=2022-03-20T12%253A10%253A17Z&bsft_lx=7&bsft_tv=25&amp&list_code=MONMARW&email_id=000139679745&cbrd=1&gl=DE&hl=de&m=0&pc=yt&src=1&uxe=23983171"
            },
            {
                "url": "https://dividedscientific.com/pixel"
            },
            {
                "url": "http://sproutunfairprovisions.com/88/2c/e3"
            },
            {
                "url": "https://api.targetx.com/email-interact/redirect?id=MTEwMDAwNTY5IDcwMTFRMDAwMDAxSldVd1FBTyBhMGoxUTAwMDAwUTdkZkNRQVIgMDAzMVEwMDAwMlJxMDNGUUFS&link=https://www.youtube.com/watch?v=evZZlsbyNWs&t=2s&tlink=aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g_dj1ldlpabHNieU5XcyZ0PTJz"
            },
            {
                "url": "http://xclh.lkd.www-1netflix.com/"
            },
            {
                "url": "https://youtube.com/watch?v=H_oiWtgOfcA"
            },
            {
                "url": "https://consent.youtube.com/m?continue=https://www.youtube.com/user/BarbourABI?cbrd=1&gl=DE&hl=de&m=0&pc=yt&src=1&uxe=23983171"
            },
            {
                "url": "http://url338.badger-alloys.com/ls/click?upn=jzTSFpa3izh8c0opdUgrLSRCAstyvK9FweHZK82U7uLNrGyk6zhME9Lk3x31cX1rM-2BEqz6BG25h-2BDFwjdt7bOQ-3D-3D9SFq_AlnObYhnAMOUjpZ-2F98kIC9hyKrXdf5p-2BXwqf2zzRDfpr1b6v-2Bwn-2FJEvsbih-2FT-2F0plvqrfRbb4Yw0gK1IiGkTRjghMiwN-2FqUB-2BQFoYEsOvJAZkxNX-2BQlFks89iGeBO1Hd05DYj6dotfQsTnJ3eMqCHfA1HxnLUTASlx-2BO8CSl7mk54nBfX-2Bzn0pkH6UksHizBcAa9U3flVmrw1HqtadVz3GXJJb3SsUG-2FovGgGoxT1n6s4gwFilZo8mxE2WVfb-2Fvtlusi8ATxzNsF6yIT3TMufu8GAZRB1pOVGS9wTIqSE8X6khbhWKFS29iN4dgjQkiAyhep-2BgQu6GFSPfTWz2BuhG8JiMvEl0Y5xBD0w8R9FJ-2BNN-2FdxBslekxg-2FOdrEh-2BmS8VUzo4NpfFZcxSqzUv1q1DZDJNHoiVbu-2F2dKbCN-2BO0E-3D"
            },
            {
                "url": "https://vam.simpleintactloop.com/?kw=239&s1=35d6d078d9dc4a4b8feeee01bc1dcb05&s2=239&s3=1858866"
            },
            {
                "url": "http://email.btobtechinsight.com/c/17fBCKg4EMxsyQl4BluULeFOwoI"
            },
            {
                "url": "https://api.targetx.com/email-interact/redirect?id=MTEwMDAwNTE0IDcwMTViMDAwMDA1SG82UEFBUyBhMFU1YjAwMDAwS2tmT2tFQUogMDAzNWIwMDAwMmM0TmZxQUFF&link=https://youtu.be/hkyB9Uodvdo&tlink=aHR0cHM6Ly95b3V0dS5iZS9oa3lCOVVvZHZkbw=="
            },
            {
                "url": "https://api.targetx.com/email-interact/redirect?id=MTEwMDAwNTE0IDcwMTViMDAwMDA1SG82UEFBUyBhMFU1YjAwMDAwS2tmT2tFQUogMDAzMzYwMDAwMUVDaHkxQUFE&link=https://youtu.be/hkyB9Uodvdo&tlink=aHR0cHM6Ly95b3V0dS5iZS9oa3lCOVVvZHZkbw=="
            },
            {
                "url": "https://youtube.com/channel/UChLnhKjHRlCl4DSncwJ1D_A"
            },
            {
                "url": "https://play.google.com/store/apps/details?gl=US&hl=es_AR&id=com.dominospizza"
            },
            {
                "url": "https://drive.google.com/open?id=1JhCtYo-JQY8Lnr91aGwGN4mQxKxGBqIm"
            },
            {
                "url": "http://dolphinanthill.com/dc/f2/7a"
            },
            {
                "url": "http://pl14479056.pvclouds.com/"
            },
            {
                "url": "http://shazam1.dynserv.org/fqdst.html/b2Q9MXN5bTYxZjE1ZWE4NWVjM2VfdmxfQWN0aXZlMTF2bF8wdDZjLm92dzBpZi5PMDAwMHJmbnA3ZzFmYWEyajNfdnExMDUwLmZucDdnMGJ5MHl0LTJzaDdtaGE=1q5Nfe"
            },
            {
                "url": "http://link.gmgb4.net/x/d?c=19032618&l=1492d2ef-4747-42b7-bdaa-9fefa20c0e27&r=697a6210-db5f-4161-8bc2-a99cc3f1aa93"
            }
        ]
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 URL-s Hosted On IP Address 142.250.186.142
> ### URL-s hosted on the IP address
>|url|
>|---|
>| https:<span>//</span>vam.simpleintactloop.com/?kw=25&s1=dfadc40091de4d20b5ae5178a3ed04cf&s2=25&s3=1812092 |
>| https:<span>//</span>consent.youtube.com/m?continue=https:<span>//</span>www.youtube.com/playlist?list=PLUdyEkajrVvQgvw3E7Ms4YAvqa8yze0mk&bsft_aaid=d3faaff4-8ea9-405d-9544-4da5a26dc24a&bsft_eid=9ee948cc-69cb-27ef-383f-8b42608edab0&bsft_clkid=a51526e6-0d0d-42ba-a5b2-4ffe739b39b3&bsft_uid=13d7aa07-4c09-453f-85ae-fbd4e975b709&bsft_mid=5b0f75fb-615d-401c-b15c-8e301bce51a0&bsft_txnid=a887540d-743a-4d12-ab6a-9e9a09073a67&bsft_mime_type=html&bsft_ek=2022-03-20T12%253A10%253A17Z&bsft_lx=7&bsft_tv=25&amp&list_code=MONMARW&email_id=000139679745&cbrd=1&gl=DE&hl=de&m=0&pc=yt&src=1&uxe=23983171 |
>| https:<span>//</span>dividedscientific.com/pixel |
>| http:<span>//</span>sproutunfairprovisions.com/88/2c/e3 |
>| https:<span>//</span>api.targetx.com/email-interact/redirect?id=MTEwMDAwNTY5IDcwMTFRMDAwMDAxSldVd1FBTyBhMGoxUTAwMDAwUTdkZkNRQVIgMDAzMVEwMDAwMlJxMDNGUUFS&link=https:<span>//</span>www.youtube.com/watch?v=evZZlsbyNWs&t=2s&tlink=aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g_dj1ldlpabHNieU5XcyZ0PTJz |
>| http:<span>//</span>xclh.lkd.www-1netflix.com/ |
>| https:<span>//</span>youtube.com/watch?v=H_oiWtgOfcA |
>| https:<span>//</span>consent.youtube.com/m?continue=https:<span>//</span>www.youtube.com/user/BarbourABI?cbrd=1&gl=DE&hl=de&m=0&pc=yt&src=1&uxe=23983171 |
>| http:<span>//</span>url338.badger-alloys.com/ls/click?upn=jzTSFpa3izh8c0opdUgrLSRCAstyvK9FweHZK82U7uLNrGyk6zhME9Lk3x31cX1rM-2BEqz6BG25h-2BDFwjdt7bOQ-3D-3D9SFq_AlnObYhnAMOUjpZ-2F98kIC9hyKrXdf5p-2BXwqf2zzRDfpr1b6v-2Bwn-2FJEvsbih-2FT-2F0plvqrfRbb4Yw0gK1IiGkTRjghMiwN-2FqUB-2BQFoYEsOvJAZkxNX-2BQlFks89iGeBO1Hd05DYj6dotfQsTnJ3eMqCHfA1HxnLUTASlx-2BO8CSl7mk54nBfX-2Bzn0pkH6UksHizBcAa9U3flVmrw1HqtadVz3GXJJb3SsUG-2FovGgGoxT1n6s4gwFilZo8mxE2WVfb-2Fvtlusi8ATxzNsF6yIT3TMufu8GAZRB1pOVGS9wTIqSE8X6khbhWKFS29iN4dgjQkiAyhep-2BgQu6GFSPfTWz2BuhG8JiMvEl0Y5xBD0w8R9FJ-2BNN-2FdxBslekxg-2FOdrEh-2BmS8VUzo4NpfFZcxSqzUv1q1DZDJNHoiVbu-2F2dKbCN-2BO0E-3D |
>| https:<span>//</span>vam.simpleintactloop.com/?kw=239&s1=35d6d078d9dc4a4b8feeee01bc1dcb05&s2=239&s3=1858866 |
>| http:<span>//</span>email.btobtechinsight.com/c/17fBCKg4EMxsyQl4BluULeFOwoI |
>| https:<span>//</span>api.targetx.com/email-interact/redirect?id=MTEwMDAwNTE0IDcwMTViMDAwMDA1SG82UEFBUyBhMFU1YjAwMDAwS2tmT2tFQUogMDAzNWIwMDAwMmM0TmZxQUFF&link=https:<span>//</span>youtu.be/hkyB9Uodvdo&tlink=aHR0cHM6Ly95b3V0dS5iZS9oa3lCOVVvZHZkbw== |
>| https:<span>//</span>api.targetx.com/email-interact/redirect?id=MTEwMDAwNTE0IDcwMTViMDAwMDA1SG82UEFBUyBhMFU1YjAwMDAwS2tmT2tFQUogMDAzMzYwMDAwMUVDaHkxQUFE&link=https:<span>//</span>youtu.be/hkyB9Uodvdo&tlink=aHR0cHM6Ly95b3V0dS5iZS9oa3lCOVVvZHZkbw== |
>| https:<span>//</span>youtube.com/channel/UChLnhKjHRlCl4DSncwJ1D_A |
>| https:<span>//</span>play.google.com/store/apps/details?gl=US&hl=es_AR&id=com.dominospizza |
>| https:<span>//</span>drive.google.com/open?id=1JhCtYo-JQY8Lnr91aGwGN4mQxKxGBqIm |
>| http:<span>//</span>dolphinanthill.com/dc/f2/7a |
>| http:<span>//</span>pl14479056.pvclouds.com/ |
>| http:<span>//</span>shazam1.dynserv.org/fqdst.html/b2Q9MXN5bTYxZjE1ZWE4NWVjM2VfdmxfQWN0aXZlMTF2bF8wdDZjLm92dzBpZi5PMDAwMHJmbnA3ZzFmYWEyajNfdnExMDUwLmZucDdnMGJ5MHl0LTJzaDdtaGE=1q5Nfe |
>| http:<span>//</span>link.gmgb4.net/x/d?c=19032618&l=1492d2ef-4747-42b7-bdaa-9fefa20c0e27&r=697a6210-db5f-4161-8bc2-a99cc3f1aa93 |

