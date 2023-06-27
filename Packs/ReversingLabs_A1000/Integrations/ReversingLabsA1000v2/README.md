ReversingLabs A1000 advanced Malware Analysis Platform.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see the release notes for this version.

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
        "EntryID": "6373@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "A1000 report file",
        "Size": 12736,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
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
                        "last_seen": "2022-12-19T11:48:23Z",
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
                                    "version": "2.72"
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

>## ReversingLabs A1000 results for: a94775deb818a4d68635eeed3d16abc7f7b8bdd6
>    **Type:** Binary/Archive  
>    **Size:** 607237 bytes  
>    **MD5:** a322205db6c3b1c451725b84f1d010cc  
>    **SHA1:** a94775deb818a4d68635eeed3d16abc7f7b8bdd6  
>    **SHA256:** d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2  
>    **SHA512:** d1fd72d5a52d75f23836016772e8895d901fa5a1cb1f9b25ba455db6cccbd97e9daf43fde4f8bb77b43c0b5c4937405d51dece20cda7fa7db7600715c7769554  
>    **ID:** 3065  
>    **Malware status:** malicious  
>    **Local first seen:** 2022-12-19T11:39:10.929115Z  
>    **Local last seen:** 2022-12-20T17:37:24.670052Z  
>    **First seen:** 2022-12-19T11:39:11Z  
>    **Last seen:** 2022-12-20T17:37:29Z  
>    **DBot score:** 3  
>    **Risk score:** 10  
>    **Threat name:** Win32.Trojan.Delf  
>    **Category:** archive  
>    **Classification origin:** {'sha1': 'aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad', 'sha256': '43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1', 'sha512': '8a1c9512fa167b938ea31c047a48dd6ec36d9b22443bc4ee6b97a116e16ff33427645ac76349f531cd9a672b4fffc3c4c92d1c82d2a71241915c1499336fd221', 'md5': '8521e64c683e47c1db64d80577513016', 'imphash': 'c57e34b759dff2e57f71960b2fdb93da'}  
>    **Classification reason:** antivirus  
>    **Aliases:** aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl.zip  
>    **Extracted file count:** 85  
>    **Identification name:** ZIP  
>    **Identification version:** Generic  

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

#### Command example
```!reversinglabs-a1000-upload-sample entryId="6343@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59" comment="this_is_a_comment" tags="one_tag"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "6389@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "Upload sample report file",
        "Size": 307,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_upload_report": {
            "code": 201,
            "detail": {
                "created": "2022-12-20T17:37:32.103792Z",
                "filename": "ytm.jpg",
                "href": "/?q=4501a9f42e2b52a67bdefbd9d1c07e446d559d0c",
                "id": 73,
                "sha1": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c",
                "user": 1
            },
            "message": "Done."
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 upload sample
> **Message:** Done.  
>    **ID:** 73  
>    **SHA1:** 4501a9f42e2b52a67bdefbd9d1c07e446d559d0c  
>    **Created:** 2022-12-20T17:37:32.103792Z  

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

#### Command example
```!reversinglabs-a1000-upload-sample-and-get-results entryId="6343@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59" comment="this_is_a_comment" tags="one_tag"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "267218e9952b7448984995629891e9a3"
            },
            {
                "type": "SHA1",
                "value": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c"
            },
            {
                "type": "SHA256",
                "value": "bf54c9d48e0db04676518bdc699a999f868f023ef5fdc30bbf77c73892363fd7"
            }
        ],
        "MD5": "267218e9952b7448984995629891e9a3",
        "SHA1": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c",
        "SHA256": "bf54c9d48e0db04676518bdc699a999f868f023ef5fdc30bbf77c73892363fd7"
    },
    "InfoFile": {
        "EntryID": "6394@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "A1000 report file",
        "Size": 8094,
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
                        "ytm.jpg"
                    ],
                    "category": "media",
                    "classification": "unknown",
                    "classification_origin": null,
                    "classification_reason": "reason is unknown",
                    "classification_result": null,
                    "classification_source": 0,
                    "extracted_file_count": 1,
                    "file_size": 240336,
                    "file_subtype": "None",
                    "file_type": "Image",
                    "id": 3076,
                    "identification_name": "JPEG",
                    "identification_version": "Generic",
                    "local_first_seen": "2022-12-20T17:37:33.147453Z",
                    "local_last_seen": "2022-12-20T17:37:33.147453Z",
                    "md5": "267218e9952b7448984995629891e9a3",
                    "riskscore": 5,
                    "sha1": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c",
                    "sha256": "bf54c9d48e0db04676518bdc699a999f868f023ef5fdc30bbf77c73892363fd7",
                    "sha512": "19908bee916323c7713950f7e319c34b042329550e4da47ccda6b416e4cda28d2f15621151dbf1ead6948d2d34b3f1c02affc46477b35117f56a7e4a54b78f6c",
                    "summary": {
                        "id": 3076,
                        "indicators": [],
                        "sha1": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c",
                        "unpacking_status": {
                            "failed": 0,
                            "partial": 0,
                            "success": 1
                        }
                    },
                    "tags": {
                        "ticore": [
                            "entropy-high"
                        ],
                        "user": [
                            "one_tag"
                        ]
                    },
                    "ticloud": {
                        "classification": "unknown",
                        "classification_reason": "reason is unknown",
                        "classification_result": null,
                        "first_seen": null,
                        "last_seen": null,
                        "riskscore": 5
                    },
                    "ticore": {
                        "application": {},
                        "attack": [],
                        "behaviour": {},
                        "browser": {},
                        "certificate": {},
                        "classification": {
                            "classification": 0,
                            "factor": 0,
                            "propagated": false,
                            "rca_factor": 5,
                            "scan_results": [
                                {
                                    "classification": 0,
                                    "factor": 0,
                                    "ignored": false,
                                    "name": "TitaniumCore",
                                    "rca_factor": 0,
                                    "result": "",
                                    "type": 5,
                                    "version": "4.1.0.0"
                                }
                            ]
                        },
                        "document": {},
                        "email": {},
                        "indicators": [],
                        "info": {
                            "file": {
                                "entropy": 7.83433160178956,
                                "file_subtype": "None",
                                "file_type": "Image",
                                "hashes": [
                                    {
                                        "name": "md5",
                                        "value": "267218e9952b7448984995629891e9a3"
                                    },
                                    {
                                        "name": "rha0",
                                        "value": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c"
                                    },
                                    {
                                        "name": "sha1",
                                        "value": "4501a9f42e2b52a67bdefbd9d1c07e446d559d0c"
                                    },
                                    {
                                        "name": "sha256",
                                        "value": "bf54c9d48e0db04676518bdc699a999f868f023ef5fdc30bbf77c73892363fd7"
                                    },
                                    {
                                        "name": "sha512",
                                        "value": "19908bee916323c7713950f7e319c34b042329550e4da47ccda6b416e4cda28d2f15621151dbf1ead6948d2d34b3f1c02affc46477b35117f56a7e4a54b78f6c"
                                    },
                                    {
                                        "name": "ssdeep",
                                        "value": "6144:n4YbbTcLsexPcAZTpkE8h82PxSSSe0yVF:n46Tc3x758dPgSL0w"
                                    }
                                ],
                                "proposed_filename": null,
                                "size": 240336
                            },
                            "identification": {
                                "author": "ReversingLabs",
                                "name": "JPEG",
                                "success": true,
                                "version": "Generic"
                            },
                            "properties": [
                                {
                                    "name": "JFIFVersionMajor",
                                    "value": "1"
                                },
                                {
                                    "name": "JFIFVersionMinor",
                                    "value": "1"
                                },
                                {
                                    "name": "JFIFThumbnailWidth",
                                    "value": "0"
                                },
                                {
                                    "name": "JFIFThumbnailHeight",
                                    "value": "0"
                                },
                                {
                                    "name": "JFIFDensityUnits",
                                    "value": "pixels per inch"
                                },
                                {
                                    "name": "JFIFDensityHorizontal",
                                    "value": "72"
                                },
                                {
                                    "name": "JFIFDensityVertical",
                                    "value": "72"
                                }
                            ],
                            "statistics": {
                                "file_stats": [
                                    {
                                        "count": 1,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "None",
                                        "type": "Binary"
                                    },
                                    {
                                        "count": 1,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "JPEG:Generic"
                                            }
                                        ],
                                        "subtype": "None",
                                        "type": "Image"
                                    }
                                ]
                            },
                            "unpacking": {
                                "status": 2
                            }
                        },
                        "interesting_strings": [],
                        "malware": {},
                        "media": {
                            "image": {
                                "bit_depth": 24,
                                "frame_count": 1,
                                "frame_rate": 0,
                                "height": 1200,
                                "horizontal_resolution": 72,
                                "vertical_resolution": 72,
                                "width": 1200
                            }
                        },
                        "mobile": {},
                        "protection": {},
                        "security": {},
                        "signatures": null,
                        "software_package": {},
                        "story": "This file (SHA1: 4501a9f42e2b52a67bdefbd9d1c07e446d559d0c) was identified as a generic JPEG image. There is one extracted file.",
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

>## ReversingLabs A1000 results for: 4501a9f42e2b52a67bdefbd9d1c07e446d559d0c
> **Type:** Image/None  
>    **Size:** 240336 bytes   
>**MD5:** 267218e9952b7448984995629891e9a3  
>**SHA1:** 4501a9f42e2b52a67bdefbd9d1c07e446d559d0c  
>**SHA256:** bf54c9d48e0db04676518bdc699a999f868f023ef5fdc30bbf77c73892363fd7  
>**SHA512:** 19908bee916323c7713950f7e319c34b042329550e4da47ccda6b416e4cda28d2f15621151dbf1ead6948d2d34b3f1c02affc46477b35117f56a7e4a54b78f6c  
>**ID:** 3076  
>    **Malware status:** unknown  
>    **Local first seen:** 2022-12-20T17:37:33.147453Z  
>    **Local last seen:** 2022-12-20T17:37:33.147453Z  
>    **First seen:** None  
>    **Last seen:** None  
>    **DBot score:** 0  
>    **Risk score:** 5   
>
> **Category:** media  
>    **Classification origin:** None  
>    **Classification reason:** reason is unknown  
>    **Aliases:** ytm.jpg  
>    **Extracted file count:** 1  
>    **Identification name:** JPEG  
>    **Identification version:** Generic  


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
        "EntryID": "6353@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
        "EntryID": "6379@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
                "id": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 10,
                    "sha1": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad",
                    "type_display": "PE/Exe"
                }
            },
            {
                "container_sha1": null,
                "filename": "3",
                "id": 10151,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "4",
                "id": 10152,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "5",
                "id": 10153,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "1",
                "id": 10154,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "6",
                "id": 10155,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "2",
                "id": 10156,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10157,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 0,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "type_display": "Text/None"
                }
            },
            {
                "container_sha1": null,
                "filename": "2d",
                "id": 10158,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "e9667fde189a3f71e9df30825aca97e1a3daf1d6",
                    "type_display": "Text/XML"
                }
            },
            {
                "container_sha1": null,
                "filename": "22",
                "id": 10159,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "d2609e009b442fdc4e5afaa3b210b7ddc9cb5f69",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "12",
                "id": 10160,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "3def4b67ede5f8b341351587cbc075d0f15dd059",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "14",
                "id": 10161,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "2d7a4f4c1da4fde1165a97416017df7276e7a48e",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "9",
                "id": 10162,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "0a671ee7cd4d2622a0bdbd463c715b8a49536305",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "13",
                "id": 10163,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "c052d32521ab0628184f38ab9db63c050d3646fe",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2a",
                "id": 10164,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "d170ddeef07cea3e564c9fb4cfbbd6470d1dc12c",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "c",
                "id": 10165,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "cdabfb3feffbbdb51ab2f94cc49e82f8af0d9885",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "b",
                "id": 10166,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "e6abf0eb5b3ce43f340e953ccca2383ee0ff32d4",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "16",
                "id": 10167,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "9169528b1429e0b9fd0c05b316d53d550a879856",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "17",
                "id": 10168,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "60bd89bb789125ac03e44b0e4ec32415843397d5",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "18",
                "id": 10169,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "8e6dea88d5f2cecfb7394660fddb722a267d3363",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "26",
                "id": 10170,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "1db12816d9768f373609d02a1c7d678575e2e62f",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1d",
                "id": 10171,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "077f32f892875bc89e052eb0c7573c97b8f73346",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "a",
                "id": 10172,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "84b704f1ea2d9716587fcb6c2dfb86229939e305",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "19",
                "id": 10173,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "ea61e68ebb9e398b034f7fda99ed88b342ace20a",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1c",
                "id": 10174,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "8a33a39e521b9ffd2415a189d309b58a192f8066",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1f",
                "id": 10175,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "8755e0026935565828e59785cab69ab3f397c0df",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "20",
                "id": 10176,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "6bfc1aa0d8a8c4d9c808df984579b818b909c1fd",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1b",
                "id": 10177,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "239540c1fc5a83d910f13cce84e4b7d3ed53f0d5",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "25",
                "id": 10178,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "42f3f40f7593a529e135f108ce6e34b46008dc7c",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "23",
                "id": 10179,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "dea77c0696b92f9e154623af6bfa7fb17e33f307",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "28",
                "id": 10180,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "e703087e3f0dcd1f02c5607eacea9e46e079226b",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "f",
                "id": 10181,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "c5e382d5afff3f7a085ac55926131c48ad0159f5",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "21",
                "id": 10182,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "99262578f157538a519883d8a6d5ede05409a01b",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2c",
                "id": 10183,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "d39abb9afb2e411455ba655356b77c5b85ec7e3a",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "e",
                "id": 10184,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "7d4388f901fdb64ee211de7e1bb8cba8cbe2a2ab",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "29",
                "id": 10185,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "6dcb5bf40d754c73ac32ef7bf6d0d1715914323e",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "2b",
                "id": 10186,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "a143a50e3299a99ae2108ca3cd3e0b36bd92222d",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "7",
                "id": 10187,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "f715ec7bbe280cd9dd6633165838d2ec73b7bea3",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1a",
                "id": 10188,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "df17eee01598eb575e434351bb40416a1e1a5056",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "24",
                "id": 10189,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "8b9a547a838565dbd05d5721a3ae954d5167de09",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "27",
                "id": 10190,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "60aed2416795136a12f9361f76e2271d6d1e506e",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "d",
                "id": 10191,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "f1a68f73d60d439245b781aece01845c6a5532aa",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "15",
                "id": 10192,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "38a6bda9ff8ec010b6fad779a4bfd7987d8107c1",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "10",
                "id": 10193,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "fc2264052c16c695bd374fa92b33735f28215171",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "8",
                "id": 10194,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "cff0173b6ae16c406b5dd83030fdd771683c1db0",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "11",
                "id": 10195,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "f4d38677e1908f1ab2f02b4ff37afb66edf8623f",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "1e",
                "id": 10196,
                "parent_relationship": 10150,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "4c4f01b015c9336f32b8cda77ee78e2cd52e2638",
                    "type_display": "IconResource:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10197,
                "parent_relationship": 10159,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "5cc3fd269506acfec0377f6e8ada80d4116e270b",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10198,
                "parent_relationship": 10160,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "844bb2a1ad57c086276476802b2a506c359eb21e",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10199,
                "parent_relationship": 10161,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "8e0fca3babf4c04bf939743f1850fb0e616a0fff",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10200,
                "parent_relationship": 10162,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "b30b457ea55526306a8da2e2f047f0f9dd42a7b6",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10201,
                "parent_relationship": 10163,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "72fcc2682762c0a64ecd76caaca00bd208454c8f",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10202,
                "parent_relationship": 10164,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "8293460f76f40a878ceaae50489a7b1f088aa218",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10203,
                "parent_relationship": 10165,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "98b3a775f7f2af6b589b2725bdf626989b1a742a",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10204,
                "parent_relationship": 10166,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "a0a81aea2c0c2323c03b0ae89cd6a8a6122b1a3f",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10205,
                "parent_relationship": 10167,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "c368d6c92821a04d8d2826c54598162dad6b1907",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10206,
                "parent_relationship": 10168,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "aa5af319653eb404ddd591f75f961f129f9d06d9",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10207,
                "parent_relationship": 10169,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "16815d109826dcf94fccb9ae2d2101b083c497d5",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10208,
                "parent_relationship": 10170,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "2c690b5029d9b4d2be3d0c8d4164cab183cdf3f4",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10209,
                "parent_relationship": 10171,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "ce758cd324b76124bb1f5e48eaa71ded017dd047",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10210,
                "parent_relationship": 10172,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "339d968eb02a6fb9580fe41e221bc50d4208eeac",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10211,
                "parent_relationship": 10173,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "d8b5210ff37c5e6cec1c69fb63a4a08edc36f412",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10212,
                "parent_relationship": 10174,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "f1bc322f92007c31427076b95dc5b8d9731009fa",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10213,
                "parent_relationship": 10175,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "03f55fb011bfabc67196e1f1ef35799ca98af61a",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10214,
                "parent_relationship": 10176,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "806c7adbecfd3f7ce7b4bd1a6577690a28b6d43b",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10215,
                "parent_relationship": 10177,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "d4b79d68d90a7f0c4f4e8aeff761d1041303c977",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10216,
                "parent_relationship": 10178,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "d01fc8f188fbd5d4e432bcd06a5a9602021fb2b7",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10217,
                "parent_relationship": 10179,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "704e3e3da01bfefb40d8608565080937b3952797",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10218,
                "parent_relationship": 10180,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "686d77a9c1d246ebde36739193b361fc5069a5ac",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10219,
                "parent_relationship": 10181,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "c1d0c00758f919d02f9e47b0a35a8e22a24a5067",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10220,
                "parent_relationship": 10182,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "2399d6881d887b1df57beccc08a777446602bdcd",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10221,
                "parent_relationship": 10183,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "fe46bc76b12dd3f5edb4121f6fd53d332bc04579",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10222,
                "parent_relationship": 10184,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "6b564229a3dbad9e8e77825424e1822d5cc148ef",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10223,
                "parent_relationship": 10185,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "cd19ecd89c22abc95c574c67367f353ee00e21df",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10224,
                "parent_relationship": 10186,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "a4c31f645098965112f4332b9c36b7650ac1bfb2",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10225,
                "parent_relationship": 10187,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "b09a8d37d067c1aba552962bcab18aff50e862a7",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10226,
                "parent_relationship": 10188,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "bcd1471a1a75d97c64568cdf91a1b08fd597414d",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10227,
                "parent_relationship": 10189,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "78660b278435fed197fa170d6d2057d52a4d32fc",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10228,
                "parent_relationship": 10190,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 1,
                    "sha1": "389715de86e1ce98360dfde8f98c80e42cc77317",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10229,
                "parent_relationship": 10191,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "64fb9e509fb6014fce5093985412cd9239b452fc",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10230,
                "parent_relationship": 10192,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "fb897b00f84f7abad1ba95fadeab67e2c0a1e5dc",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10231,
                "parent_relationship": 10193,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "4ef1a3f6dda1a26cfdfe025df11df34e07f81ce3",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10232,
                "parent_relationship": 10194,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "cd88f5bc26e1f6148ce0c21fc4b38f514cb7a8a5",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10233,
                "parent_relationship": 10195,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "ac83746b0d74b9dd462124f8de47e6d495731135",
                    "type_display": "ICO:Generic"
                }
            },
            {
                "container_sha1": null,
                "filename": "0",
                "id": 10234,
                "parent_relationship": 10196,
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
                    "local_last_seen": "2022-12-19T11:46:40.855554Z",
                    "riskscore": 5,
                    "sha1": "31e2528ce9c692a4894f91fd67c09d691ec343d8",
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
>| aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad | aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl | aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl | PE/Exe | 1432064 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | malicious | 10 |  |  | PE/Exe |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 3 | binary_layer/resource/3 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 4 | binary_layer/resource/4 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 5 | binary_layer/resource/5 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 1 | binary_layer/resource/1 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 6 | binary_layer/resource/6 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 2 | binary_layer/resource/2 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 0 | binary_layer/resource/0 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 0 |  |  | Text/None |
>| e9667fde189a3f71e9df30825aca97e1a3daf1d6 | 2d | binary_layer/resource/2d | Text/XML | 2159 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 |  |  | Text/XML |
>| d2609e009b442fdc4e5afaa3b210b7ddc9cb5f69 | 22 | binary_layer/resource/22 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 3def4b67ede5f8b341351587cbc075d0f15dd059 | 12 | binary_layer/resource/12 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 2d7a4f4c1da4fde1165a97416017df7276e7a48e | 14 | binary_layer/resource/14 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 0a671ee7cd4d2622a0bdbd463c715b8a49536305 | 9 | binary_layer/resource/9 | IconResource:Generic | 2440 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| c052d32521ab0628184f38ab9db63c050d3646fe | 13 | binary_layer/resource/13 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| d170ddeef07cea3e564c9fb4cfbbd6470d1dc12c | 2a | binary_layer/resource/2a | IconResource:Generic | 5672 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| cdabfb3feffbbdb51ab2f94cc49e82f8af0d9885 | c | binary_layer/resource/c | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| e6abf0eb5b3ce43f340e953ccca2383ee0ff32d4 | b | binary_layer/resource/b | IconResource:Generic | 51240 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 9169528b1429e0b9fd0c05b316d53d550a879856 | 16 | binary_layer/resource/16 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 60bd89bb789125ac03e44b0e4ec32415843397d5 | 17 | binary_layer/resource/17 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8e6dea88d5f2cecfb7394660fddb722a267d3363 | 18 | binary_layer/resource/18 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 1db12816d9768f373609d02a1c7d678575e2e62f | 26 | binary_layer/resource/26 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 077f32f892875bc89e052eb0c7573c97b8f73346 | 1d | binary_layer/resource/1d | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 84b704f1ea2d9716587fcb6c2dfb86229939e305 | a | binary_layer/resource/a | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| ea61e68ebb9e398b034f7fda99ed88b342ace20a | 19 | binary_layer/resource/19 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8a33a39e521b9ffd2415a189d309b58a192f8066 | 1c | binary_layer/resource/1c | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8755e0026935565828e59785cab69ab3f397c0df | 1f | binary_layer/resource/1f | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 6bfc1aa0d8a8c4d9c808df984579b818b909c1fd | 20 | binary_layer/resource/20 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 239540c1fc5a83d910f13cce84e4b7d3ed53f0d5 | 1b | binary_layer/resource/1b | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 42f3f40f7593a529e135f108ce6e34b46008dc7c | 25 | binary_layer/resource/25 | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| dea77c0696b92f9e154623af6bfa7fb17e33f307 | 23 | binary_layer/resource/23 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| e703087e3f0dcd1f02c5607eacea9e46e079226b | 28 | binary_layer/resource/28 | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| c5e382d5afff3f7a085ac55926131c48ad0159f5 | f | binary_layer/resource/f | IconResource:Generic | 1128 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 99262578f157538a519883d8a6d5ede05409a01b | 21 | binary_layer/resource/21 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| d39abb9afb2e411455ba655356b77c5b85ec7e3a | 2c | binary_layer/resource/2c | IconResource:Generic | 5672 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 7d4388f901fdb64ee211de7e1bb8cba8cbe2a2ab | e | binary_layer/resource/e | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 6dcb5bf40d754c73ac32ef7bf6d0d1715914323e | 29 | binary_layer/resource/29 | IconResource:Generic | 16936 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| a143a50e3299a99ae2108ca3cd3e0b36bd92222d | 2b | binary_layer/resource/2b | IconResource:Generic | 16936 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| f715ec7bbe280cd9dd6633165838d2ec73b7bea3 | 7 | binary_layer/resource/7 | IconResource:Generic | 9640 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| df17eee01598eb575e434351bb40416a1e1a5056 | 1a | binary_layer/resource/1a | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 8b9a547a838565dbd05d5721a3ae954d5167de09 | 24 | binary_layer/resource/24 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 60aed2416795136a12f9361f76e2271d6d1e506e | 27 | binary_layer/resource/27 | IconResource:Generic | 872 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| f1a68f73d60d439245b781aece01845c6a5532aa | d | binary_layer/resource/d | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 38a6bda9ff8ec010b6fad779a4bfd7987d8107c1 | 15 | binary_layer/resource/15 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| fc2264052c16c695bd374fa92b33735f28215171 | 10 | binary_layer/resource/10 | IconResource:Generic | 176 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| cff0173b6ae16c406b5dd83030fdd771683c1db0 | 8 | binary_layer/resource/8 | IconResource:Generic | 4264 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| f4d38677e1908f1ab2f02b4ff37afb66edf8623f | 11 | binary_layer/resource/11 | IconResource:Generic | 296 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 4c4f01b015c9336f32b8cda77ee78e2cd52e2638 | 1e | binary_layer/resource/1e | IconResource:Generic | 1384 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | IconResource | Generic | IconResource:Generic |
>| 5cc3fd269506acfec0377f6e8ada80d4116e270b | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 844bb2a1ad57c086276476802b2a506c359eb21e | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 8e0fca3babf4c04bf939743f1850fb0e616a0fff | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| b30b457ea55526306a8da2e2f047f0f9dd42a7b6 | 0 | unpacked_files/0 | ICO:Generic | 2462 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 72fcc2682762c0a64ecd76caaca00bd208454c8f | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 8293460f76f40a878ceaae50489a7b1f088aa218 | 0 | unpacked_files/0 | ICO:Generic | 5694 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 98b3a775f7f2af6b589b2725bdf626989b1a742a | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| a0a81aea2c0c2323c03b0ae89cd6a8a6122b1a3f | 0 | unpacked_files/0 | ICO:Generic | 51262 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| c368d6c92821a04d8d2826c54598162dad6b1907 | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| aa5af319653eb404ddd591f75f961f129f9d06d9 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 5 | ICO | Generic | ICO:Generic |
>| 16815d109826dcf94fccb9ae2d2101b083c497d5 | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 2c690b5029d9b4d2be3d0c8d4164cab183cdf3f4 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| ce758cd324b76124bb1f5e48eaa71ded017dd047 | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 339d968eb02a6fb9580fe41e221bc50d4208eeac | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| d8b5210ff37c5e6cec1c69fb63a4a08edc36f412 | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| f1bc322f92007c31427076b95dc5b8d9731009fa | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 03f55fb011bfabc67196e1f1ef35799ca98af61a | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 806c7adbecfd3f7ce7b4bd1a6577690a28b6d43b | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| d4b79d68d90a7f0c4f4e8aeff761d1041303c977 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| d01fc8f188fbd5d4e432bcd06a5a9602021fb2b7 | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 704e3e3da01bfefb40d8608565080937b3952797 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 686d77a9c1d246ebde36739193b361fc5069a5ac | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| c1d0c00758f919d02f9e47b0a35a8e22a24a5067 | 0 | unpacked_files/0 | ICO:Generic | 1150 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 2399d6881d887b1df57beccc08a777446602bdcd | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| fe46bc76b12dd3f5edb4121f6fd53d332bc04579 | 0 | unpacked_files/0 | ICO:Generic | 5694 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 6b564229a3dbad9e8e77825424e1822d5cc148ef | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| cd19ecd89c22abc95c574c67367f353ee00e21df | 0 | unpacked_files/0 | ICO:Generic | 16958 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| a4c31f645098965112f4332b9c36b7650ac1bfb2 | 0 | unpacked_files/0 | ICO:Generic | 16958 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| b09a8d37d067c1aba552962bcab18aff50e862a7 | 0 | unpacked_files/0 | ICO:Generic | 9662 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| bcd1471a1a75d97c64568cdf91a1b08fd597414d | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 78660b278435fed197fa170d6d2057d52a4d32fc | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 389715de86e1ce98360dfde8f98c80e42cc77317 | 0 | unpacked_files/0 | ICO:Generic | 894 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 1 | ICO | Generic | ICO:Generic |
>| 64fb9e509fb6014fce5093985412cd9239b452fc | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| fb897b00f84f7abad1ba95fadeab67e2c0a1e5dc | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | goodware | 5 | ICO | Generic | ICO:Generic |
>| 4ef1a3f6dda1a26cfdfe025df11df34e07f81ce3 | 0 | unpacked_files/0 | ICO:Generic | 198 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| cd88f5bc26e1f6148ce0c21fc4b38f514cb7a8a5 | 0 | unpacked_files/0 | ICO:Generic | 4286 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| ac83746b0d74b9dd462124f8de47e6d495731135 | 0 | unpacked_files/0 | ICO:Generic | 318 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |
>| 31e2528ce9c692a4894f91fd67c09d691ec343d8 | 0 | unpacked_files/0 | ICO:Generic | 1406 | 2022-10-27T11:03:31.473395Z | 2022-12-19T11:46:40.855554Z | unknown | 5 | ICO | Generic | ICO:Generic |


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
        "EntryID": "6363@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
        "EntryID": "6384@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
                            "message": "Sample is queued for core analysis.",
                            "name": "core"
                        },
                        {
                            "code": 201,
                            "message": "Sample is queued for analysis.",
                            "name": "cloud"
                        },
                        {
                            "code": 405,
                            "message": "Sandbox integration is not configured.",
                            "name": "cuckoo"
                        },
                        {
                            "code": 201,
                            "message": "Sample is queued for analysis.",
                            "name": "rl_cloud_sandbox"
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
                        },
                        {
                            "code": 405,
                            "message": "Sandbox integration is not configured.",
                            "name": "joe"
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
        "EntryID": "6358@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "9e61c81592323802fa959040f0d2ef26",
        "Name": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6.zip",
        "SHA1": "ad164fa3d395069b049cccb837331883b58d70ba",
        "SHA256": "bd7b8192d511fe5148c51b2ab5210c8e8604776ee66136703503772649d986c0",
        "SHA512": "32453bf96fa25fab7d83c29e20f80e0062ba841e28318cd1243caca89cbc6f863306b2b6316f866099b545fce95ff51b8ad7d3a5695b037a040c89b07f173438",
        "SSDeep": "12288:qrLW2iHCZijVsEPYsqp1wzkZqY+JlySSeBSnY4Xf3sXdAeQQIetUpNZHbsO29u:q2DCZijvwsq7QsqFPDSRF3sX6eQnHd28",
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
        "EntryID": "6368@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "Get classification report file",
        "Size": 1297,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_classification_report": {
            "av_scanners": {
                "antivirus": {
                    "scanner_count": 31,
                    "scanner_match": 0,
                    "vendor_count": 21,
                    "vendor_match": 0
                },
                "scanner_count": 31,
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
            "cloud_last_lookup": "2022-12-20T17:20:44Z",
            "data_source": "LOCAL",
            "first_seen": "2022-12-19T11:39:11Z",
            "last_seen": "2022-12-19T11:46:40Z",
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
>**Last seen:** 2022-12-19T11:46:40Z  
>**Classification result:** Win32.Trojan.Delf  
>**Classification reason:** Antivirus  
>**Classification origin:** {'sha1': 'aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad', 'sha256': '43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1', 'sha512': '8a1c9512fa167b938ea31c047a48dd6ec36d9b22443bc4ee6b97a116e16ff33427645ac76349f531cd9a672b4fffc3c4c92d1c82d2a71241915c1499336fd221', 'md5': '8521e64c683e47c1db64d80577513016', 'imphash': 'c57e34b759dff2e57f71960b2fdb93da'}  
>**Cloud last lookup:** 2022-12-20T17:20:44Z  
>**Data source:** LOCAL  
>**Sha1:** a94775deb818a4d68635eeed3d16abc7f7b8bdd6  
>**Sha256:** d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2  
>**Md5:** a322205db6c3b1c451725b84f1d010cc  
>**Av scanners:** {'scanner_count': 31, 'scanner_match': 0, 'scanner_percent': 0.0, 'vendor_count': 21, 'vendor_match': 0, 'vendor_percent': 0.0, 'antivirus': {'vendor_match': 0, 'scanner_match': 0, 'vendor_count': 21, 'scanner_count': 31}}  


### reversinglabs-a1000-advanced-search
***
Search for hashes on A1000 using multi-part search criteria


#### Base Command

`reversinglabs-a1000-advanced-search`
#### Input

| **Argument Name** | **Description**                                                                                   | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------| --- |
| query             | Advanced search query.                                                                            | Required | 
| ticloud           | Show only cloud results. If omitted, the response will show only local results. Default is False. | Optional | 
| result_limit      | Maximum number of results. Default is 5000.                                                       | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_advanced_search_report | Unknown | A1000 classification report | 

#### Command example
```!reversinglabs-a1000-advanced-search query="av-count:5 available:TRUE" ticloud=False result_limit=5```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "6348@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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

