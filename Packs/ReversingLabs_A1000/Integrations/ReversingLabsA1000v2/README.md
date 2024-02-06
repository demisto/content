ReversingLabs A1000 advanced Malware Analysis Platform.


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
    | HTTP proxy address with the protocol and port number. | False |
    | HTTP proxy username | False |
    | HTTP proxy password | False |
    | HTTPS proxy address with the protocol and port number. | False |
    | HTTPS proxy username | False |
    | HTTPS proxy password | False |
    

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
        "EntryID": "7503@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
                    "local_last_seen": "2023-06-06T16:02:03.674591Z",
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
                        "last_seen": "2023-06-06T16:03:51Z",
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

>## ReversingLabs A1000 results for: a94775deb818a4d68635eeed3d16abc7f7b8bdd6
>    **Type:** Binary/Archive  
>    **Size:** 607237 bytes  
>**MD5:** a322205db6c3b1c451725b84f1d010cc  
>**SHA1:** a94775deb818a4d68635eeed3d16abc7f7b8bdd6  
>**SHA256:** d3d8091a287c8aee0ee5c54838540e714f22eef7cbeb65eb2b6af42116f5d5f2  
>**SHA512:** d1fd72d5a52d75f23836016772e8895d901fa5a1cb1f9b25ba455db6cccbd97e9daf43fde4f8bb77b43c0b5c4937405d51dece20cda7fa7db7600715c7769554  
>**ID:** 3065  
>    **Malware status:** malicious  
>    **Local first seen:** 2022-12-19T11:39:10.929115Z  
>    **Local last seen:** 2022-12-20T17:37:24.670052Z  
>    **First seen:** 2022-12-19T11:39:11Z  
>    **Last seen:** 2022-12-20T17:37:29Z  
>    **DBot score:** 3  
>    **Risk score:** 10  
>**Threat name:** Win32.Trojan.Delf  
> **Category:** archive  
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
```!reversinglabs-a1000-upload-sample entryId="7469@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59" comment="this_is_a_comment" tags="one_tag"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "7535@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "Upload sample report file",
        "Size": 341,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_upload_report": {
            "code": 201,
            "detail": {
                "created": "2023-06-06T16:40:33.541071Z",
                "filename": "0000a0a549be5b7a95b782d31f73d8f608c4a440",
                "href": "/?q=0000a0a549be5b7a95b782d31f73d8f608c4a440",
                "id": 150,
                "sha1": "0000a0a549be5b7a95b782d31f73d8f608c4a440",
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
>    **ID:** 150
>    **SHA1:** 0000a0a549be5b7a95b782d31f73d8f608c4a440
>    **Created:** 2023-06-06T16:40:33.541071Z

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
```!reversinglabs-a1000-upload-sample-and-get-results entryId="7469@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59" comment="this_is_a_comment" tags="one_tag"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "0000a0a549be5b7a95b782d31f73d8f608c4a440",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "96d17cad51f2b7c817481e5a724c9b3f"
            },
            {
                "type": "SHA1",
                "value": "0000a0a549be5b7a95b782d31f73d8f608c4a440"
            },
            {
                "type": "SHA256",
                "value": "0b40fb0cef3b557a34a3d7a9cd75d5180099205ccdceb8a73e1dfe73dbd282fd"
            }
        ],
        "MD5": "96d17cad51f2b7c817481e5a724c9b3f",
        "Malicious": {
            "Description": "antivirus - Win32.Browser.StartPage",
            "Vendor": "ReversingLabs A1000 v2"
        },
        "SHA1": "0000a0a549be5b7a95b782d31f73d8f608c4a440",
        "SHA256": "0b40fb0cef3b557a34a3d7a9cd75d5180099205ccdceb8a73e1dfe73dbd282fd"
    },
    "InfoFile": {
        "EntryID": "7540@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "A1000 report file",
        "Size": 200767,
        "Type": "ASCII text, with very long lines"
    },
    "ReversingLabs": {
        "a1000_report": {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [
                {
                    "aliases": [
                        "0000a0a549be5b7a95b782d31f73d8f608c4a440"
                    ],
                    "category": "application",
                    "classification": "malicious",
                    "classification_origin": null,
                    "classification_reason": "antivirus",
                    "classification_result": "Win32.Browser.StartPage",
                    "classification_source": 1,
                    "extracted_file_count": 6,
                    "file_size": 385774,
                    "file_subtype": "Exe",
                    "file_type": "PE",
                    "id": 5722,
                    "identification_name": "NSIS",
                    "identification_version": "Generic",
                    "local_first_seen": "2023-06-06T16:40:34.604510Z",
                    "local_last_seen": "2023-06-06T16:40:34.604510Z",
                    "md5": "96d17cad51f2b7c817481e5a724c9b3f",
                    "riskscore": 9,
                    "sha1": "0000a0a549be5b7a95b782d31f73d8f608c4a440",
                    "sha256": "0b40fb0cef3b557a34a3d7a9cd75d5180099205ccdceb8a73e1dfe73dbd282fd",
                    "sha512": "4546796ffd5075fc317549f6522df808f03d0d9e97398243259ed3d1bfb0b108083a2200fff49e4de25c5521eaef751d420763c089327b384feea27dc36d316a",
                    "summary": {
                        "id": 5722,
                        "indicators": [
                            {
                                "category": 22,
                                "description": "Deletes files in Windows system directories.",
                                "id": 101,
                                "priority": 7,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: DeleteFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 11,
                                "description": "Requests permission required to shut down a system.",
                                "id": 990,
                                "priority": 7,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: AdjustTokenPrivileges",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: SeShutdownPrivilege",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Contains lzma compressed PE file.",
                                "id": 1052,
                                "priority": 7,
                                "reasons": [
                                    {
                                        "category": "Pattern Match",
                                        "description": "Found a pattern [3c 2d 57 47 be 2d be 94 bd 8b dc 6f 25 97 af 50 f1 d2 5b 85 52 e1 d4 7c 3d 4c 75 4d a7 1f 1b 73 ed eb 01 c5 71 2f 70 5f b4 25 6f 1e a3 c5 c8 f1 1b bd] that ends at offset 138465",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Executes a file.",
                                "id": 21,
                                "priority": 6,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateProcessA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Writes to files in Windows system directories.",
                                "id": 99,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: WriteFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 11,
                                "description": "Tampers with user/account privileges.",
                                "id": 329,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: AdjustTokenPrivileges",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Checks operating system version.",
                                "id": 930,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetVersion",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates temporary files.",
                                "id": 969,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetTempFileNameA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 6,
                                "description": "Contains a reference to ActiveX GUID with the Kill-Bit flag set.",
                                "id": 1086,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Pattern Match",
                                        "description": "Found a pattern [65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 00 00 00 ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46] that ends at offset 25492",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Deletes files.",
                                "id": 5,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: DeleteFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 9,
                                "description": "Accesses/modifies registry.",
                                "id": 7,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: RegDeleteValueA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: RegDeleteKeyExA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates/opens files in Windows system directories.",
                                "id": 95,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Reads from files in Windows system directories.",
                                "id": 97,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ReadFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Tampers with system shutdown.",
                                "id": 117,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ExitWindowsEx",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 13,
                                "description": "Enumerates system information.",
                                "id": 149,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 0,
                                "description": "Contains URLs.",
                                "id": 310,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: http://ailiao.liaoban.com/",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: http://nsis.sf.net/",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: open http://ailiao.liaoban.com/",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Modifies file/directory attributes.",
                                "id": 384,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: SetFileAttributesA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Copies, moves, renames, or deletes a file system object.",
                                "id": 965,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: SHFileOperationA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Reads paths to special directories on Windows.",
                                "id": 966,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: SHGetSpecialFolderLocation",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Reads paths to system directories on Windows.",
                                "id": 967,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Reads path to temporary file location on Windows.",
                                "id": 968,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetTempPathA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 11,
                                "description": "Enumerates user/account privilege information.",
                                "id": 1215,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: LookupPrivilegeValueA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Writes to files.",
                                "id": 3,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: WriteFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 1,
                                "description": "Uses anti-debugging methods.",
                                "id": 9,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetTickCount",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 7,
                                "description": "Detects/enumerates process modules.",
                                "id": 81,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetModuleFileNameA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Removes a directory.",
                                "id": 340,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: RemoveDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 7,
                                "description": "Tampers with keyboard/mouse status.",
                                "id": 381,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: EnableWindow",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Copies a file.",
                                "id": 1031,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CopyFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Reads from files.",
                                "id": 1,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ReadFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Might load additional DLLs and APIs.",
                                "id": 69,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetProcAddress",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: LoadLibraryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Enumerates files.",
                                "id": 119,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: FindFirstFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 13,
                                "description": "Enumerates system variables.",
                                "id": 151,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ExpandEnvironmentStringsA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates a directory.",
                                "id": 338,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Renames files.",
                                "id": 920,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: MoveFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates/Opens a file.",
                                "id": 0,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Contains references to executable file extensions.",
                                "id": 313,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: $PLUGINSDIR\\SkinBtn.dll",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Contains references to source code file extensions.",
                                "id": 314,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: http://ailiao.liaoban.com/xszd/index.html",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: open http://ailiao.liaoban.com/xszd/index.html",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Contains references to image file extensions.",
                                "id": 315,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: /IMGID=$PLUGINSDIR\\checkbox1.bmp",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: /IMGID=$PLUGINSDIR\\checkbox2.bmp",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 18,
                                "description": "Accesses clipboard.",
                                "id": 328,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Capability Match",
                                        "description": "Matched the following application capabilities: Clipboard",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            }
                        ],
                        "sha1": "0000a0a549be5b7a95b782d31f73d8f608c4a440",
                        "unpacking_status": {
                            "failed": 0,
                            "partial": 0,
                            "success": 1
                        }
                    },
                    "tags": {
                        "ticore": [
                            "antivirus",
                            "arch-x86",
                            "capability-execution",
                            "desktop",
                            "entropy-high",
                            "gui",
                            "ng-antivirus",
                            "overlay",
                            "rich-header",
                            "contains-pe",
                            "antidebugging",
                            "capability-filesystem",
                            "capability-security",
                            "guid-activex-killbit",
                            "indicator-anomaly",
                            "indicator-registry",
                            "indicator-search",
                            "indicator-settings",
                            "string-http",
                            "indicator-execution",
                            "indicator-file",
                            "indicator-network",
                            "indicator-permissions",
                            "capability-deprecated",
                            "privilege-escalation",
                            "installer",
                            "stego-compressed"
                        ],
                        "user": [
                            "one_tag"
                        ]
                    },
                    "ticloud": {
                        "classification": "malicious",
                        "classification_reason": "antivirus",
                        "classification_result": "Win32.Browser.StartPage",
                        "first_seen": "2014-02-10T18:16:00Z",
                        "last_seen": "2023-03-06T12:17:51Z",
                        "riskscore": 9
                    },
                    "ticore": {
                        "application": {
                            "capabilities": [
                                [
                                    "clipboard",
                                    true
                                ],
                                [
                                    "ipc",
                                    true
                                ],
                                [
                                    "threads",
                                    true
                                ],
                                [
                                    "processes",
                                    true
                                ],
                                [
                                    "storage",
                                    true
                                ],
                                [
                                    "filesystem",
                                    true
                                ],
                                [
                                    "peripherals",
                                    true
                                ],
                                [
                                    "user_input",
                                    true
                                ],
                                [
                                    "hardware_interfaces",
                                    false
                                ],
                                [
                                    "networking",
                                    false
                                ],
                                [
                                    "cryptography",
                                    false
                                ],
                                [
                                    "security",
                                    true
                                ],
                                [
                                    "system",
                                    true
                                ],
                                [
                                    "modules",
                                    true
                                ],
                                [
                                    "memory_management",
                                    true
                                ],
                                [
                                    "user_interface",
                                    true
                                ],
                                [
                                    "command_line",
                                    true
                                ],
                                [
                                    "time_and_date",
                                    true
                                ],
                                [
                                    "identity",
                                    false
                                ],
                                [
                                    "monitoring",
                                    true
                                ],
                                [
                                    "configuration",
                                    true
                                ],
                                [
                                    "compression",
                                    false
                                ],
                                [
                                    "multimedia",
                                    true
                                ],
                                [
                                    "deprecated",
                                    true
                                ],
                                [
                                    "undocumented",
                                    false
                                ],
                                [
                                    "application_management",
                                    false
                                ],
                                [
                                    "service_management",
                                    false
                                ],
                                [
                                    "messaging",
                                    false
                                ],
                                [
                                    "protection",
                                    false
                                ],
                                [
                                    "drivers",
                                    false
                                ]
                            ],
                            "pe": {
                                "analysis": {
                                    "analysis_state": 3,
                                    "issues": [
                                        {
                                            "code": 21060,
                                            "count": 1,
                                            "description": "Detected that image_rich_header_t::product list includes no references to linker used to generate object files.",
                                            "name": "WC21060",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 24014,
                                            "count": 4,
                                            "description": "Section virtual size will be automatically rounded up by section alignment value.",
                                            "name": "WC24014",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 31501,
                                            "count": 2,
                                            "description": "Detected that image_rich_header_t::product list includes a reference to an older toolchain version. This outdated compiler version lacks built-in protection from integer based overflow attacks while dynamically allocation memory buffers. Lowers grade to D.",
                                            "name": "SC31501",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 32004,
                                            "count": 1,
                                            "description": "Non-optimal file_header_t::characteristics value. File has relocations stripped, which eliminates the possibility of ASLR being used. Lowers grade to C.",
                                            "name": "SC32004",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 33012,
                                            "count": 1,
                                            "description": "Detected security mitigation policy issue in optional_header_t::dll_characteristics. Data execution prevention feature flag is not set. Lowers grade to D.",
                                            "name": "SC33012",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 33013,
                                            "count": 1,
                                            "description": "Detected security mitigation policy issue in optional_header_t::dll_characteristics. Control flow guard feature flag is not set. Lowers grade to B.",
                                            "name": "SC33013",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 33014,
                                            "count": 1,
                                            "description": "Detected security mitigation policy issue in optional_header_t::dll_characteristics. Address space layout randomization feature flag is not set. Lowers grade to C.",
                                            "name": "SC33014",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 38610,
                                            "count": 1,
                                            "description": "Detected security mitigation policy issue in dll_extended_data_t::flags. The image is not compatible with Intel Control Flow Enforcement Technology. No impact to the final grade at this time.",
                                            "name": "SC38610",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 39194,
                                            "count": 1,
                                            "description": "Detected the use of SDLC banned function kernel32.lstrcpynA. Use of this function is considered unsafe because it's an unbound string operation. Lowers grade to C.",
                                            "name": "SC39194",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 39196,
                                            "count": 1,
                                            "description": "Detected the use of SDLC banned function kernel32.lstrcatA. Use of this function is considered unsafe because it's an unbound string operation. Lowers grade to D.",
                                            "name": "SC39196",
                                            "relevance": 0
                                        },
                                        {
                                            "code": 39200,
                                            "count": 1,
                                            "description": "Detected the use of SDLC banned function user32.wsprintfA. Use of this function is considered unsafe because it's an unbound string operation. Lowers grade to D.",
                                            "name": "SC39200",
                                            "relevance": 0
                                        }
                                    ],
                                    "security_grade": 3
                                },
                                "dos_header": {
                                    "e_cblp": 144,
                                    "e_cp": 3,
                                    "e_cparhdr": 4,
                                    "e_crlc": 0,
                                    "e_cs": 0,
                                    "e_csum": 0,
                                    "e_ip": 0,
                                    "e_lfanew": 200,
                                    "e_lfarlc": 64,
                                    "e_maxalloc": 65535,
                                    "e_minalloc": 0,
                                    "e_oemid": 0,
                                    "e_oeminfo": 0,
                                    "e_ovno": 0,
                                    "e_res": "0000000000000000",
                                    "e_res2": "0000000000000000000000000000000000000000",
                                    "e_sp": 184,
                                    "e_ss": 0
                                },
                                "file_header": {
                                    "characteristics": 271,
                                    "machine": 332,
                                    "number_of_sections": 5,
                                    "number_of_symbols": 0,
                                    "pointer_to_symbol_table": 0,
                                    "size_of_optional_headers": 224,
                                    "time_date_stamp": 1245360803,
                                    "time_date_stamp_decoded": "2009-06-18T21:33:23Z"
                                },
                                "imports": [
                                    {
                                        "apis": [
                                            "RegQueryValueExA",
                                            "RegSetValueExA",
                                            "RegEnumKeyA",
                                            "RegEnumValueA",
                                            "RegOpenKeyExA",
                                            "RegDeleteKeyA",
                                            "RegDeleteValueA",
                                            "RegCloseKey",
                                            "RegCreateKeyExA"
                                        ],
                                        "name": "ADVAPI32.dll"
                                    },
                                    {
                                        "apis": [
                                            "ImageList_AddMasked",
                                            "ImageList_Destroy",
                                            "0x0011",
                                            "ImageList_Create"
                                        ],
                                        "name": "COMCTL32.dll"
                                    },
                                    {
                                        "apis": [
                                            "SetBkColor",
                                            "GetDeviceCaps",
                                            "DeleteObject",
                                            "CreateBrushIndirect",
                                            "CreateFontIndirectA",
                                            "SetBkMode",
                                            "SetTextColor",
                                            "SelectObject"
                                        ],
                                        "name": "GDI32.dll"
                                    },
                                    {
                                        "apis": [
                                            "CompareFileTime",
                                            "SearchPathA",
                                            "GetShortPathNameA",
                                            "GetFullPathNameA",
                                            "MoveFileA",
                                            "SetCurrentDirectoryA",
                                            "GetFileAttributesA",
                                            "GetLastError",
                                            "CreateDirectoryA",
                                            "SetFileAttributesA",
                                            "Sleep",
                                            "GetTickCount",
                                            "GetFileSize",
                                            "GetModuleFileNameA",
                                            "GetCurrentProcess",
                                            "CopyFileA",
                                            "ExitProcess",
                                            "GetWindowsDirectoryA",
                                            "SetFileTime",
                                            "GetCommandLineA",
                                            "SetErrorMode",
                                            "LoadLibraryA",
                                            "lstrcpynA",
                                            "GetDiskFreeSpaceA",
                                            "GlobalUnlock",
                                            "GlobalLock",
                                            "CreateThread",
                                            "CreateProcessA",
                                            "RemoveDirectoryA",
                                            "CreateFileA",
                                            "GetTempFileNameA",
                                            "lstrlenA",
                                            "lstrcatA",
                                            "GetSystemDirectoryA",
                                            "GetVersion",
                                            "CloseHandle",
                                            "lstrcmpiA",
                                            "lstrcmpA",
                                            "ExpandEnvironmentStringsA",
                                            "GlobalFree",
                                            "GlobalAlloc",
                                            "WaitForSingleObject",
                                            "GetExitCodeProcess",
                                            "GetModuleHandleA",
                                            "LoadLibraryExA",
                                            "GetProcAddress",
                                            "FreeLibrary",
                                            "MultiByteToWideChar",
                                            "WritePrivateProfileStringA",
                                            "GetPrivateProfileStringA",
                                            "WriteFile",
                                            "ReadFile",
                                            "MulDiv",
                                            "SetFilePointer",
                                            "FindClose",
                                            "FindNextFileA",
                                            "FindFirstFileA",
                                            "DeleteFileA",
                                            "GetTempPathA"
                                        ],
                                        "name": "KERNEL32.dll"
                                    },
                                    {
                                        "apis": [
                                            "SHGetPathFromIDListA",
                                            "SHBrowseForFolderA",
                                            "SHGetFileInfoA",
                                            "ShellExecuteA",
                                            "SHFileOperationA",
                                            "SHGetSpecialFolderLocation"
                                        ],
                                        "name": "SHELL32.dll"
                                    },
                                    {
                                        "apis": [
                                            "EndDialog",
                                            "ScreenToClient",
                                            "GetWindowRect",
                                            "EnableMenuItem",
                                            "GetSystemMenu",
                                            "SetClassLongA",
                                            "IsWindowEnabled",
                                            "SetWindowPos",
                                            "GetSysColor",
                                            "GetWindowLongA",
                                            "SetCursor",
                                            "LoadCursorA",
                                            "CheckDlgButton",
                                            "GetMessagePos",
                                            "LoadBitmapA",
                                            "CallWindowProcA",
                                            "IsWindowVisible",
                                            "CloseClipboard",
                                            "SetClipboardData",
                                            "EmptyClipboard",
                                            "RegisterClassA",
                                            "TrackPopupMenu",
                                            "AppendMenuA",
                                            "CreatePopupMenu",
                                            "GetSystemMetrics",
                                            "SetDlgItemTextA",
                                            "GetDlgItemTextA",
                                            "MessageBoxIndirectA",
                                            "CharPrevA",
                                            "DispatchMessageA",
                                            "PeekMessageA",
                                            "DestroyWindow",
                                            "CreateDialogParamA",
                                            "SetTimer",
                                            "SetWindowTextA",
                                            "PostQuitMessage",
                                            "SetForegroundWindow",
                                            "wsprintfA",
                                            "SendMessageTimeoutA",
                                            "FindWindowExA",
                                            "SystemParametersInfoA",
                                            "CreateWindowExA",
                                            "GetClassInfoA",
                                            "DialogBoxParamA",
                                            "CharNextA",
                                            "OpenClipboard",
                                            "ExitWindowsEx",
                                            "IsWindow",
                                            "GetDlgItem",
                                            "SetWindowLongA",
                                            "LoadImageA",
                                            "GetDC",
                                            "EnableWindow",
                                            "InvalidateRect",
                                            "SendMessageA",
                                            "DefWindowProcA",
                                            "BeginPaint",
                                            "GetClientRect",
                                            "FillRect",
                                            "DrawTextA",
                                            "EndPaint",
                                            "ShowWindow"
                                        ],
                                        "name": "USER32.dll"
                                    },
                                    {
                                        "apis": [
                                            "GetFileVersionInfoSizeA",
                                            "GetFileVersionInfoA",
                                            "VerQueryValueA"
                                        ],
                                        "name": "VERSION.dll"
                                    },
                                    {
                                        "apis": [
                                            "CoTaskMemFree",
                                            "OleInitialize",
                                            "OleUninitialize",
                                            "CoCreateInstance"
                                        ],
                                        "name": "ole32.dll"
                                    }
                                ],
                                "optional_header": {
                                    "address_of_entry_point": 12577,
                                    "base_of_code": 4096,
                                    "base_of_data": 28672,
                                    "checksum": 1829480,
                                    "data_directories": [
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 29604,
                                            "size": 180
                                        },
                                        {
                                            "address": 299008,
                                            "size": 97856
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 1780448,
                                            "size": 6784
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 28672,
                                            "size": 652
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        },
                                        {
                                            "address": 0,
                                            "size": 0
                                        }
                                    ],
                                    "dll_characteristics": 32768,
                                    "file_alignment": 512,
                                    "image_base": 4194304,
                                    "is_checksum_valid": false,
                                    "loader_flags": 0,
                                    "major_image_version": 6,
                                    "major_linker_version": 6,
                                    "major_os_version": 4,
                                    "major_subsystem_version": 4,
                                    "minor_image_version": 0,
                                    "minor_linker_version": 0,
                                    "minor_os_version": 0,
                                    "minor_subsystem_version": 0,
                                    "number_of_rva_and_sizes": 16,
                                    "section_alignment": 4096,
                                    "size_of_code": 23552,
                                    "size_of_headers": 4096,
                                    "size_of_heap_commit": 4096,
                                    "size_of_heap_reserve": 1048576,
                                    "size_of_image": 397312,
                                    "size_of_initialized_data": 119808,
                                    "size_of_stack_commit": 4096,
                                    "size_of_stack_reserve": 1048576,
                                    "size_of_uninitialized_data": 1024,
                                    "subsystem": 2,
                                    "win32_version_value": 0
                                },
                                "resources": [
                                    {
                                        "code_page": 0,
                                        "entropy": 7.985862505328084,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "8a4d18bba9b8ac0e19c2f607987d2d91"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "d8eab701c50233d5df7a7378114ce7a4f50ea02d"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "1c565b92910b9bb3675f2d4229750edd2d579223b6b48a457fa788641e81919d"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "1",
                                        "offset": 30896,
                                        "size": 76115,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 5.568665732102147,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "074f624ad8bf31d2270ffb16539bef50"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "f2b72d1097dd653c59bd73d095f3f3460923f112"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "3d5b9035786114d86687684cbe56370b0b4ad02f6fe623ea963f0bb458d58c90"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "2",
                                        "offset": 107016,
                                        "size": 9640,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 5.709442226504938,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "f221acc077fa64d83684baed47ce3eda"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "df0039a4eaa334e951be732c27c35426b1eba5a7"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "fe0266e9ea02050aacef6e5bf6b8ce5468ace3145a5c6341fe4455bc1a62094e"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "3",
                                        "offset": 116656,
                                        "size": 4264,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 5.828920162711904,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "e080fe806bac7bee60192a1d075337cf"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "322c0d0852972dda236128c5c103d5806860e278"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "d822f69786b1cf729e3bb0bd8925b5c6800c60808f8df74328f54d4a8c7f8d2c"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "4",
                                        "offset": 120920,
                                        "size": 2216,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 3.8867394667403925,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "98a72af52ec27f1e21dc7662a82f9074"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "6514ed14e0f11654f6753643e87867b1f3ef265a"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "e59184b4acc4ca0c45f18a3d1d04b280cf50b27be2e13e45a15c27fcf2717ede"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "5",
                                        "offset": 123136,
                                        "size": 1384,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 5.839608667526498,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "fa5241aafb845894790530b60497cb2a"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "278687d81bc60d4c3387d4066da28e0c3df8c06a"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "7e3e2b0943722049773d5608fca398c0b9c5db9a0f7d600c700f110a0c2e3999"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "6",
                                        "offset": 124520,
                                        "size": 1128,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 3.8709246515797724,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "f8b6c2299c0954392c2d0725c55d37fc"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "c8d5923ca2bfeaea8f6b5744fa29ab07fc91a684"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "0ad1e776378969726d2cec8310e8384838951bfec73d8c17b2fc0937c38f1b30"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "7",
                                        "offset": 125648,
                                        "size": 744,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 3.341242211670808,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "f58a53c67d602cee2e1a3b1e1d2f5cea"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "a13170e3da473da7f2a7376691c0fba13f0d16bc"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "6090b9cd90ee016a86735a381195f754847fe06e993cf292e910165943a18dc9"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "8",
                                        "offset": 126392,
                                        "size": 296,
                                        "type": "RT_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 2.6873340555785346,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "c0c4f9be63c9d286b8d1265977ac9d86"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "f9c0d915ded3ea188f342d0e5341e67701eed813"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "349420ba5b5de0b0081e96a686c826e0f409f2f3413f2e9fb7e6f71cb544c325"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "105",
                                        "offset": 126688,
                                        "size": 494,
                                        "type": "RT_DIALOG"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 2.930400865292582,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "2497a44fff8b76b5129662b60a617c85"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "f73bd7c9caa4c1f7a0e4840d69b0accdc6d167a0"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "a10617b39293152a65ad5c91ca4f35135845c7b785e3a582e58f6c8229045b85"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "111",
                                        "offset": 127184,
                                        "size": 218,
                                        "type": "RT_DIALOG"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 2.7791801352986436,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "3b779b7b3d2821ed9692dd7bd894b5f7"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "a175950a5287742555de01a06aec0644f4dbcdac"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "81be2a95c48e3aba71a2de5dfd57cab07acf582cc17aa574dc53e1b68d886180"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "103",
                                        "offset": 127408,
                                        "size": 118,
                                        "type": "RT_GROUP_ICON"
                                    },
                                    {
                                        "code_page": 0,
                                        "entropy": 5.106089527314914,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "efed251ab209699bd9e66be7265f34c2"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "67ad91d74057843c0888dd2f49e2e503672b573d"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "21c97d123cc0d703224d1c64b197f6322f7896999ca0b389df18f98192e6ece7"
                                            }
                                        ],
                                        "language_id": 1033,
                                        "language_id_name": "English - United States",
                                        "name": "1",
                                        "offset": 127528,
                                        "size": 533,
                                        "type": "RT_MANIFEST"
                                    }
                                ],
                                "rich_header": {
                                    "checksum": 3520932213,
                                    "entries": [
                                        {
                                            "counter": 2,
                                            "product": 95,
                                            "tooling": 1,
                                            "version": 4035
                                        },
                                        {
                                            "counter": 155,
                                            "product": 1,
                                            "tooling": 7,
                                            "version": 0
                                        },
                                        {
                                            "counter": 17,
                                            "product": 93,
                                            "tooling": 7,
                                            "version": 4035
                                        },
                                        {
                                            "counter": 10,
                                            "product": 10,
                                            "tooling": 1,
                                            "version": 8168
                                        },
                                        {
                                            "counter": 1,
                                            "product": 6,
                                            "tooling": 10,
                                            "version": 1735
                                        }
                                    ],
                                    "offset": 128,
                                    "size": 72
                                },
                                "sections": [
                                    {
                                        "entropy": 6.403453617755809,
                                        "flags": 1610612768,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "092e164daa50385128d3c5b319373035"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "2eb99403e1719d12eac2774ec4022c70b5c9c3a3"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "13817fd13c9476480b664e19137f80df23125cc031e655d7c91184ba9c992c6c"
                                            }
                                        ],
                                        "name": ".text",
                                        "physical_base": 1024,
                                        "physical_size": 23552,
                                        "relative_base": 4096,
                                        "relative_size": 24576
                                    },
                                    {
                                        "entropy": 5.179614628422103,
                                        "flags": 1073741888,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "4e7f519777030dd2f0ea0d2092babed3"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "fb84d751c3b62a4a520b71ee2c2702ca14591d38"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "8c6a303709c952e0ce0d8b8e5750ba40c4ee66e6adb9cce02791e0ee74d15ab0"
                                            }
                                        ],
                                        "name": ".rdata",
                                        "physical_base": 24576,
                                        "physical_size": 4608,
                                        "relative_base": 28672,
                                        "relative_size": 8192
                                    },
                                    {
                                        "entropy": 4.617894309842984,
                                        "flags": 3221225536,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "f6d93c048bf148a2daee8a6b0505e38b"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "83ca6a92e89470b5ead78e6d4da29e5437addf6d"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "de24de65c95ea0e1a0197cabcb48827c9246fc47010a8dcb9d9535bbf18afd0c"
                                            }
                                        ],
                                        "name": ".data",
                                        "physical_base": 29184,
                                        "physical_size": 1024,
                                        "relative_base": 36864,
                                        "relative_size": 110592
                                    },
                                    {
                                        "entropy": 0,
                                        "flags": 3221225600,
                                        "name": ".ndata",
                                        "physical_base": 0,
                                        "physical_size": 0,
                                        "relative_base": 147456,
                                        "relative_size": 151552
                                    },
                                    {
                                        "entropy": 7.668251063803404,
                                        "flags": 1073741888,
                                        "hashes": [
                                            {
                                                "name": "md5",
                                                "value": "0d75d437922c1a3cf56c613d56bcff47"
                                            },
                                            {
                                                "name": "sha1",
                                                "value": "b3afa41b94bd303385e55c12ee45f1744369aede"
                                            },
                                            {
                                                "name": "sha256",
                                                "value": "1fdad28ab0543118fafeaa55ef287d7a7be2393d86e508dc1bb2d653a9c3ff94"
                                            }
                                        ],
                                        "name": ".rsrc",
                                        "physical_base": 30208,
                                        "physical_size": 98304,
                                        "relative_base": 299008,
                                        "relative_size": 98304
                                    }
                                ]
                            }
                        },
                        "attack": [
                            {
                                "matrix": "Enterprise",
                                "tactics": [
                                    {
                                        "description": "The adversary is trying to avoid being detected.",
                                        "id": "TA0005",
                                        "name": "Defense Evasion",
                                        "techniques": [
                                            {
                                                "description": "Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.",
                                                "id": "T1107",
                                                "indicators": [
                                                    {
                                                        "category": 22,
                                                        "description": "Deletes files in Windows system directories.",
                                                        "id": 101,
                                                        "priority": 7,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 22,
                                                        "description": "Deletes files.",
                                                        "id": 5,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 22,
                                                        "description": "Removes a directory.",
                                                        "id": 340,
                                                        "priority": 3,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "File Deletion"
                                            },
                                            {
                                                "description": "Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in Persistence and Execution.",
                                                "id": "T1112",
                                                "indicators": [
                                                    {
                                                        "category": 9,
                                                        "description": "Accesses/modifies registry.",
                                                        "id": 7,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "Modify Registry"
                                            },
                                            {
                                                "description": "File and directory permissions are commonly managed by discretionary access control lists (DACLs) specified by the file or directory owner. File and directory DACL implementations may vary by platform, but generally explicitly designate which users/groups can perform which actions (ex: read, write, execute, etc.).",
                                                "id": "T1222",
                                                "indicators": [
                                                    {
                                                        "category": 22,
                                                        "description": "Modifies file/directory attributes.",
                                                        "id": 384,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "File and Directory Permissions Modification"
                                            },
                                            {
                                                "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.",
                                                "id": "T1027",
                                                "indicators": [
                                                    {
                                                        "category": 10,
                                                        "description": "Contains lzma compressed PE file.",
                                                        "id": 1052,
                                                        "priority": 7,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "Obfuscated Files or Information"
                                            }
                                        ]
                                    },
                                    {
                                        "description": "The adversary is trying to figure out your environment.",
                                        "id": "TA0007",
                                        "name": "Discovery",
                                        "techniques": [
                                            {
                                                "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
                                                "id": "T1012",
                                                "indicators": [
                                                    {
                                                        "category": 9,
                                                        "description": "Accesses/modifies registry.",
                                                        "id": 7,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "Query Registry"
                                            },
                                            {
                                                "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
                                                "id": "T1083",
                                                "indicators": [
                                                    {
                                                        "category": 12,
                                                        "description": "Reads paths to special directories on Windows.",
                                                        "id": 966,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 12,
                                                        "description": "Reads paths to system directories on Windows.",
                                                        "id": 967,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 12,
                                                        "description": "Reads path to temporary file location on Windows.",
                                                        "id": 968,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 12,
                                                        "description": "Enumerates files.",
                                                        "id": 119,
                                                        "priority": 2,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "File and Directory Discovery"
                                            },
                                            {
                                                "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
                                                "id": "T1082",
                                                "indicators": [
                                                    {
                                                        "category": 12,
                                                        "description": "Checks operating system version.",
                                                        "id": 930,
                                                        "priority": 5,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 13,
                                                        "description": "Enumerates system information.",
                                                        "id": 149,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    },
                                                    {
                                                        "category": 13,
                                                        "description": "Enumerates system variables.",
                                                        "id": 151,
                                                        "priority": 2,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "System Information Discovery"
                                            }
                                        ]
                                    },
                                    {
                                        "description": "The adversary is trying to run malicious code.",
                                        "id": "TA0002",
                                        "name": "Execution",
                                        "techniques": [
                                            {
                                                "description": "Adversary tools may directly use the Windows application programming interface (API) to execute binaries. Functions such as the Windows API CreateProcess will allow programs and scripts to start other processes with proper path and argument parameters.",
                                                "id": "T1106",
                                                "indicators": [
                                                    {
                                                        "category": 10,
                                                        "description": "Executes a file.",
                                                        "id": 21,
                                                        "priority": 6,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "Execution through API"
                                            }
                                        ]
                                    },
                                    {
                                        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                                        "id": "TA0040",
                                        "name": "Impact",
                                        "techniques": [
                                            {
                                                "description": "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer. Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.",
                                                "id": "T1529",
                                                "indicators": [
                                                    {
                                                        "category": 10,
                                                        "description": "Tampers with system shutdown.",
                                                        "id": 117,
                                                        "priority": 4,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "System Shutdown/Reboot"
                                            }
                                        ]
                                    },
                                    {
                                        "description": "The adversary is trying to gather data of interest to their goal.",
                                        "id": "TA0009",
                                        "name": "Collection",
                                        "techniques": [
                                            {
                                                "description": "Adversaries may collect data stored in the Windows clipboard from users copying information within or between applications.",
                                                "id": "T1115",
                                                "indicators": [
                                                    {
                                                        "category": 18,
                                                        "description": "Accesses clipboard.",
                                                        "id": 328,
                                                        "priority": 1,
                                                        "relevance": 0
                                                    }
                                                ],
                                                "name": "Clipboard Data"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "behaviour": {
                            "process_start": [
                                {
                                    "arguments": "/A",
                                    "create_no_window": true,
                                    "domain": "",
                                    "environment_variables": "",
                                    "filename": "\"%InstallDir%\\$_INTVAR_88_\"",
                                    "password": "",
                                    "username": "",
                                    "working_directory": ""
                                },
                                {
                                    "arguments": "/fix",
                                    "create_no_window": true,
                                    "domain": "",
                                    "environment_variables": "",
                                    "filename": "$PLUGINSDIR\\$_INTVAR_88_",
                                    "password": "",
                                    "username": "",
                                    "working_directory": ""
                                }
                            ],
                            "registry": [
                                {
                                    "key": "HKCU\\SOFTWARE\\ailiao",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_DWORD"
                                        }
                                    ],
                                    "value": "65538",
                                    "value_name": "UpdateVer"
                                },
                                {
                                    "key": "HKLM\\SOFTWARE\\ailiao",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_DWORD"
                                        }
                                    ],
                                    "value": "65538",
                                    "value_name": "UpdateVer"
                                },
                                {
                                    "key": "HKLM\\SOFTWARE\\ailiao",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "$_INTVAR_90_",
                                    "value_name": "ailiaofiledir"
                                },
                                {
                                    "key": "HKLM\\SOFTWARE\\ailiao",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "$_INTVAR_88_",
                                    "value_name": "ailiaofilename"
                                },
                                {
                                    "key": "HKLM\\SOFTWARE\\ailiao",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "$_INTVAR_89_",
                                    "value_name": "ailiaosvrname"
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ailiao",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "%InstallDir%\\$_INTVAR_88_",
                                    "value_name": ""
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\°®ÁÄ",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "%InstallDir%\\$_INTVAR_88_",
                                    "value_name": "DisplayIcon"
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\°®ÁÄ",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "爱聊",
                                    "value_name": "DisplayName"
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\°®ÁÄ",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "",
                                    "value_name": "DisplayVersion"
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\°®ÁÄ",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "ailiao Inc.",
                                    "value_name": "Publisher"
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\°®ÁÄ",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "",
                                    "value_name": "URLInfoAbout"
                                },
                                {
                                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\°®ÁÄ",
                                    "properties": [
                                        {
                                            "name": "action",
                                            "value": "create"
                                        },
                                        {
                                            "name": "type",
                                            "value": "REG_SZ"
                                        }
                                    ],
                                    "value": "%InstallDir%\\uninst.exe",
                                    "value_name": "UninstallString"
                                }
                            ],
                            "remove": [
                                {
                                    "path": "$_INTVAR_65516_"
                                }
                            ],
                            "shortcut": [
                                {
                                    "command_options": "",
                                    "description": "",
                                    "destination_path": "%InstallDir%\\$_INTVAR_88_",
                                    "hotkey": "",
                                    "icon_index": 0,
                                    "icon_path": "",
                                    "source_path": "%DesktopCommon%\\°®ÁÄ.lnk",
                                    "working_directory": ""
                                },
                                {
                                    "command_options": "",
                                    "description": "",
                                    "destination_path": "%InstallDir%\\$_INTVAR_88_",
                                    "hotkey": "",
                                    "icon_index": 0,
                                    "icon_path": "",
                                    "source_path": "%InstallDir%\\$_INTVAR_87_.lnk",
                                    "working_directory": ""
                                },
                                {
                                    "command_options": "",
                                    "description": "",
                                    "destination_path": "%InstallDir%\\$_INTVAR_88_",
                                    "hotkey": "",
                                    "icon_index": 0,
                                    "icon_path": "",
                                    "source_path": "%StartMenuProgramsCommon%\\°®ÁÄ\\°®ÁÄ.lnk",
                                    "working_directory": ""
                                },
                                {
                                    "command_options": "",
                                    "description": "",
                                    "destination_path": "%InstallDir%\\uninst.exe",
                                    "hotkey": "",
                                    "icon_index": 0,
                                    "icon_path": "",
                                    "source_path": "%StartMenuProgramsCommon%\\°®ÁÄ\\Ð¶ÔØ°®ÁÄ.lnk",
                                    "working_directory": ""
                                }
                            ]
                        },
                        "browser": {},
                        "certificate": {},
                        "classification": {
                            "classification": 3,
                            "factor": 4,
                            "propagated": false,
                            "rca_factor": 9,
                            "result": "Win32.Browser.StartPage",
                            "scan_results": [
                                {
                                    "classification": 3,
                                    "factor": 4,
                                    "ignored": false,
                                    "name": "Antivirus (based on the RCA Classify)",
                                    "rca_factor": 9,
                                    "result": "Win32.Browser.StartPage",
                                    "type": 1,
                                    "version": "2.79"
                                },
                                {
                                    "classification": 3,
                                    "factor": 2,
                                    "ignored": false,
                                    "name": "Next-Generation Antivirus",
                                    "rca_factor": 7,
                                    "result": "Win32.Malware.Heuristic",
                                    "type": 11,
                                    "version": "1.0"
                                }
                            ]
                        },
                        "document": {},
                        "email": {},
                        "indicators": [
                            {
                                "category": 22,
                                "description": "Deletes files in Windows system directories.",
                                "id": 101,
                                "priority": 7,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: DeleteFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 11,
                                "description": "Requests permission required to shut down a system.",
                                "id": 990,
                                "priority": 7,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: AdjustTokenPrivileges",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: SeShutdownPrivilege",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Contains lzma compressed PE file.",
                                "id": 1052,
                                "priority": 7,
                                "reasons": [
                                    {
                                        "category": "Pattern Match",
                                        "description": "Found a pattern [3c 2d 57 47 be 2d be 94 bd 8b dc 6f 25 97 af 50 f1 d2 5b 85 52 e1 d4 7c 3d 4c 75 4d a7 1f 1b 73 ed eb 01 c5 71 2f 70 5f b4 25 6f 1e a3 c5 c8 f1 1b bd] that ends at offset 138465",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Executes a file.",
                                "id": 21,
                                "priority": 6,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateProcessA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Writes to files in Windows system directories.",
                                "id": 99,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: WriteFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 11,
                                "description": "Tampers with user/account privileges.",
                                "id": 329,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: AdjustTokenPrivileges",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Checks operating system version.",
                                "id": 930,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetVersion",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates temporary files.",
                                "id": 969,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetTempFileNameA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 6,
                                "description": "Contains a reference to ActiveX GUID with the Kill-Bit flag set.",
                                "id": 1086,
                                "priority": 5,
                                "reasons": [
                                    {
                                        "category": "Pattern Match",
                                        "description": "Found a pattern [65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 00 00 00 ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46] that ends at offset 25492",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Deletes files.",
                                "id": 5,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: DeleteFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 9,
                                "description": "Accesses/modifies registry.",
                                "id": 7,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: RegDeleteValueA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: RegDeleteKeyExA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates/opens files in Windows system directories.",
                                "id": 95,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Reads from files in Windows system directories.",
                                "id": 97,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ReadFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Tampers with system shutdown.",
                                "id": 117,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ExitWindowsEx",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 13,
                                "description": "Enumerates system information.",
                                "id": 149,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 0,
                                "description": "Contains URLs.",
                                "id": 310,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: http://ailiao.liaoban.com/",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: http://nsis.sf.net/",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: open http://ailiao.liaoban.com/",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Modifies file/directory attributes.",
                                "id": 384,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: SetFileAttributesA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Copies, moves, renames, or deletes a file system object.",
                                "id": 965,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: SHFileOperationA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Reads paths to special directories on Windows.",
                                "id": 966,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: SHGetSpecialFolderLocation",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Reads paths to system directories on Windows.",
                                "id": 967,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetSystemDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Reads path to temporary file location on Windows.",
                                "id": 968,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetTempPathA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 11,
                                "description": "Enumerates user/account privilege information.",
                                "id": 1215,
                                "priority": 4,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: LookupPrivilegeValueA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Writes to files.",
                                "id": 3,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: WriteFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 1,
                                "description": "Uses anti-debugging methods.",
                                "id": 9,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetTickCount",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 7,
                                "description": "Detects/enumerates process modules.",
                                "id": 81,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetModuleFileNameA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Removes a directory.",
                                "id": 340,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: RemoveDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 7,
                                "description": "Tampers with keyboard/mouse status.",
                                "id": 381,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: EnableWindow",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Copies a file.",
                                "id": 1031,
                                "priority": 3,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CopyFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Reads from files.",
                                "id": 1,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ReadFile",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 10,
                                "description": "Might load additional DLLs and APIs.",
                                "id": 69,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: GetProcAddress",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: LoadLibraryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Enumerates files.",
                                "id": 119,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: FindFirstFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 13,
                                "description": "Enumerates system variables.",
                                "id": 151,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: ExpandEnvironmentStringsA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates a directory.",
                                "id": 338,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateDirectoryA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Renames files.",
                                "id": 920,
                                "priority": 2,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: MoveFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 22,
                                "description": "Creates/Opens a file.",
                                "id": 0,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Imported API Name",
                                        "description": "Imports the following function: CreateFileA",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Contains references to executable file extensions.",
                                "id": 313,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: $PLUGINSDIR\\SkinBtn.dll",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Contains references to source code file extensions.",
                                "id": 314,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: http://ailiao.liaoban.com/xszd/index.html",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: open http://ailiao.liaoban.com/xszd/index.html",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 12,
                                "description": "Contains references to image file extensions.",
                                "id": 315,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: /IMGID=$PLUGINSDIR\\checkbox1.bmp",
                                        "propagated": false
                                    },
                                    {
                                        "category": "Strings",
                                        "description": "Contains the following string: /IMGID=$PLUGINSDIR\\checkbox2.bmp",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            },
                            {
                                "category": 18,
                                "description": "Accesses clipboard.",
                                "id": 328,
                                "priority": 1,
                                "reasons": [
                                    {
                                        "category": "Capability Match",
                                        "description": "Matched the following application capabilities: Clipboard",
                                        "propagated": false
                                    }
                                ],
                                "relevance": 0
                            }
                        ],
                        "info": {
                            "file": {
                                "entropy": 7.8997380394839265,
                                "file_subtype": "Exe",
                                "file_type": "PE",
                                "hashes": [
                                    {
                                        "name": "imphash",
                                        "value": "7fa974366048f9c551ef45714595665e"
                                    },
                                    {
                                        "name": "md5",
                                        "value": "96d17cad51f2b7c817481e5a724c9b3f"
                                    },
                                    {
                                        "name": "rha0",
                                        "value": "70cff177ebd10584dddff8fe1463cdd7772e2e9a"
                                    },
                                    {
                                        "name": "sha1",
                                        "value": "0000a0a549be5b7a95b782d31f73d8f608c4a440"
                                    },
                                    {
                                        "name": "sha256",
                                        "value": "0b40fb0cef3b557a34a3d7a9cd75d5180099205ccdceb8a73e1dfe73dbd282fd"
                                    },
                                    {
                                        "name": "sha512",
                                        "value": "4546796ffd5075fc317549f6522df808f03d0d9e97398243259ed3d1bfb0b108083a2200fff49e4de25c5521eaef751d420763c089327b384feea27dc36d316a"
                                    },
                                    {
                                        "name": "ssdeep",
                                        "value": "6144:3eTeM/nwFduF5gh8HafVR6A272Yx6lTYfknoERSZdSwmIaPD1aYqRjZlbeiAcGS4:7M/wFIFW86fAKgQTnsSwSD1j6ZlbGZD5"
                                    }
                                ],
                                "proposed_filename": null,
                                "size": 385774
                            },
                            "identification": {
                                "author": "ReversingLabs",
                                "name": "NSIS",
                                "success": true,
                                "version": "Generic"
                            },
                            "overlays": [
                                {
                                    "entropy": 0,
                                    "from": 0,
                                    "hashes": [
                                        {
                                            "name": "md5",
                                            "value": "35edca133d1a18c6e9e7adda155503f3"
                                        },
                                        {
                                            "name": "sha1",
                                            "value": "1b619e85482ba763f8eef33ef52cff11343896bc"
                                        },
                                        {
                                            "name": "sha256",
                                            "value": "0a6b9ed60a35bac8f127bd6e7a178f6b07aa8fa8f26162f384a11f4898bc2f67"
                                        }
                                    ],
                                    "offset": 128512,
                                    "size": 257262
                                }
                            ],
                            "statistics": {
                                "file_stats": [
                                    {
                                        "count": 4,
                                        "identifications": [
                                            {
                                                "count": 4,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "None",
                                        "type": "None"
                                    },
                                    {
                                        "count": 1,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "Dll",
                                        "type": "PE"
                                    },
                                    {
                                        "count": 2,
                                        "identifications": [
                                            {
                                                "count": 1,
                                                "name": "NSIS:Generic"
                                            },
                                            {
                                                "count": 1,
                                                "name": "Unknown"
                                            }
                                        ],
                                        "subtype": "Exe",
                                        "type": "PE"
                                    }
                                ]
                            },
                            "unpacking": {
                                "status": 3
                            },
                            "validation": {
                                "scan_results": [
                                    {
                                        "name": "TitaniumCore PE Rich Header Validator",
                                        "type": 5,
                                        "valid": true,
                                        "version": "4.1.2.0"
                                    },
                                    {
                                        "name": "TitaniumCore PE Checksum Validator",
                                        "type": 5,
                                        "valid": false,
                                        "version": "4.1.2.0"
                                    },
                                    {
                                        "name": "TitaniumCore PECOFF Validator",
                                        "type": 3,
                                        "valid": false,
                                        "version": "5.0.6",
                                        "warnings": [
                                            "PE.SecurityTable is invalid"
                                        ]
                                    }
                                ],
                                "valid": false
                            }
                        },
                        "interesting_strings": [
                            {
                                "category": "http",
                                "values": [
                                    {
                                        "occurrences": 2,
                                        "offset": 18446744073709552000,
                                        "value": "http://ailiao.liaoban.com/xszd/index.html"
                                    },
                                    {
                                        "occurrences": 1,
                                        "offset": 29410,
                                        "value": "http://nsis.sf.net/NSIS_Error"
                                    }
                                ]
                            }
                        ],
                        "malware": {},
                        "media": {},
                        "mobile": {},
                        "protection": {},
                        "security": {},
                        "signatures": null,
                        "software_package": {},
                        "story": "This file (SHA1: 0000a0a549be5b7a95b782d31f73d8f608c4a440) is a 32-bit portable executable application. Additionally, it was identified as NSIS installer, and unpacking was partial. According to behaviour metadata, the file can create new processes, remove files, tamper with registry and create shortcuts. The application uses the Windows graphical user interface (GUI) subsystem, while the language used is English from United States. Appended data was detected at the file&#x27;s end. Its length is smaller than the size of the image. This application has access to device configuration, monitoring and running processes, has security related capabilities and uses deprecated APIs. There are 6 extracted files.",
                        "strings": [
                            {
                                "c": 2,
                                "f": 2,
                                "o": 1050,
                                "v": "\rh>B"
                            },
                            {
                                "c": 3,
                                "f": 2,
                                "o": 1082,
                                "v": "5p>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 1360,
                                "v": "5Xp@"
                            },
                            {
                                "c": 4,
                                "f": 2,
                                "o": 1382,
                                "v": "h`6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 1581,
                                "v": "t\u000b9M\ft"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 1727,
                                "v": " s495"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 2043,
                                "v": "546B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 2054,
                                "v": "5L6B"
                            },
                            {
                                "c": 3,
                                "f": 2,
                                "o": 2101,
                                "v": "\rp>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 2448,
                                "v": "\r06B"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 2454,
                                "v": "5`r@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 2471,
                                "v": "\rD6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 2542,
                                "v": "tBj\\V"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 3095,
                                "v": "u{9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 3174,
                                "v": "Ht Vj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 3473,
                                "v": "t\t9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 3916,
                                "v": "tGH;"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 4099,
                                "v": "t\nj3"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 4115,
                                "v": "t\njD"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 4413,
                                "v": "PShr"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 4447,
                                "v": "jHjZ"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 4587,
                                "v": "PVu\u000b"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 5101,
                                "v": "t=9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 5292,
                                "v": "Phts@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 5593,
                                "v": "u\rSj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 5770,
                                "v": "t\tj\""
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 5788,
                                "v": "PSWV"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6007,
                                "v": "SQSSSPW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6174,
                                "v": "VQSPW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6291,
                                "v": "t\fQVPW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6311,
                                "v": "SQVPW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6448,
                                "v": "SQPhL"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6564,
                                "v": "u_9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6572,
                                "v": "}\u000b\rt+"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6578,
                                "v": "}\u000b\nt%"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6593,
                                "v": "E\u000bt@;u"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 6623,
                                "v": "8E\u000bt"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 7259,
                                "v": "t#9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 7364,
                                "v": "t\u000bSS"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 7874,
                                "v": "u:9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 7926,
                                "v": "X_^["
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8143,
                                "v": "PjdQ"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8269,
                                "v": "v#Vh"
                            },
                            {
                                "c": 6,
                                "f": 2,
                                "o": 8281,
                                "v": "5`>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8313,
                                "v": "(SV3"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8498,
                                "v": "=t>B"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 8540,
                                "v": "Instu`"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 8549,
                                "v": "softuW"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 8558,
                                "v": "NulluN\tE"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8591,
                                "v": "\rt>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8641,
                                "v": "Y;5 "
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8648,
                                "v": "}\rWS"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8694,
                                "v": "YtS9]"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 8858,
                                "v": "j@Vh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9120,
                                "v": "tC+E"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9193,
                                "v": "t:9E"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9218,
                                "v": "t09u"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9411,
                                "v": "t\n9u\fu"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9511,
                                "v": "SUV3"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9579,
                                "v": "D$4h`"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9587,
                                "v": "PSh$"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9721,
                                "v": "8/u3@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9746,
                                "v": "8NCRCu"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9770,
                                "v": " /D=t"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9900,
                                "v": "tMSW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9916,
                                "v": "> _?=t"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9951,
                                "v": "t*Vh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 9980,
                                "v": "\r\f?B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10087,
                                "v": "u\u000bVh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10177,
                                "v": "t-SV"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10313,
                                "v": "D$$Ph("
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10328,
                                "v": "D$(SPS"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10573,
                                "v": ",j\fj@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10671,
                                "v": "SWSh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 10830,
                                "v": "tT<\"u"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 10982,
                                "v": "\r`>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11045,
                                "v": "SPSj0"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11064,
                                "v": "D$(+D$ SSP"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11075,
                                "v": "D$0+D$(P"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 11092,
                                "v": "t$0h"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11222,
                                "v": "-$6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11241,
                                "v": "ih 9@"
                            },
                            {
                                "c": 4,
                                "f": 2,
                                "o": 11327,
                                "v": "_^]["
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11335,
                                "v": "SUVW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11589,
                                "v": "|$$3"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11601,
                                "v": "UUUUW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11624,
                                "v": "D$,H"
                            },
                            {
                                "c": 9,
                                "f": 2,
                                "o": 11656,
                                "v": "586B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11717,
                                "v": "t$,VW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11774,
                                "v": "u\f9-"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11793,
                                "v": "u49-"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11877,
                                "v": "t$0S"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11896,
                                "v": "|$$;"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 11909,
                                "v": "5,r@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11918,
                                "v": "=h>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 11951,
                                "v": "5H6B"
                            },
                            {
                                "c": 3,
                                "f": 2,
                                "o": 12048,
                                "v": "9-,6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12219,
                                "v": "D$,t"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12611,
                                "v": "t$ U"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12689,
                                "v": "-h>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12709,
                                "v": "9-86B"
                            },
                            {
                                "c": 8,
                                "f": 2,
                                "o": 12773,
                                "v": "5h>B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12788,
                                "v": "t$\fj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12877,
                                "v": "t$\fP"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 12999,
                                "v": "_t\nP"
                            },
                            {
                                "c": 3,
                                "f": 2,
                                "o": 13148,
                                "v": "\r<6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 13224,
                                "v": "s8j#"
                            },
                            {
                                "c": 8,
                                "f": 2,
                                "o": 13289,
                                "v": "5Dr@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 13921,
                                "v": "u\rVS"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 13987,
                                "v": "=86B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 14220,
                                "v": "u Pj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 14576,
                                "v": "t+Pj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 14594,
                                "v": "t\u000bWj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 14843,
                                "v": "j\n_j"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 15066,
                                "v": "j\th\n"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 15316,
                                "v": "hsM@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 15408,
                                "v": "}\fWSh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 15463,
                                "v": "PWhC"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 15475,
                                "v": "SPhQ"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 16180,
                                "v": "j _W"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 16221,
                                "v": "9E\fu\nj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 16451,
                                "v": "9]\fu5"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 16772,
                                "v": " u}h"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 16839,
                                "v": "9u\fu;9"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 17036,
                                "v": "5(6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17051,
                                "v": "uDSSh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17270,
                                "v": "5D6B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17332,
                                "v": "=,r@"
                            },
                            {
                                "c": 3,
                                "f": 2,
                                "o": 17382,
                                "v": "506B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17473,
                                "v": "PPh6"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17485,
                                "v": "9]\f|"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 17491,
                                "v": "u\fSh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17505,
                                "v": "u\fSh&"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17741,
                                "v": "=`r@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17791,
                                "v": "t&jx"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17871,
                                "v": "}\f{u"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 17973,
                                "v": "SPQh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18116,
                                "v": "\r\nFFC;]\f|"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18181,
                                "v": "hh$B"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18186,
                                "v": "PPPPPP"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18480,
                                "v": "t\rh("
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18512,
                                "v": "\\u\u000bh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18610,
                                "v": "u\u000b8F"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18621,
                                "v": "t^VS"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18766,
                                "v": "tM9u"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18873,
                                "v": "8\\t\u000bh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18936,
                                "v": "8\\t\fPV"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18970,
                                "v": "9\\\\t"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 18975,
                                "v": "<a|\n<z"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19027,
                                "v": ";:\\u"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19039,
                                "v": "?\\\\u"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19046,
                                "v": "^j\\P"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19248,
                                "v": "7t\u000bV"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19397,
                                "v": "Wjc_"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19463,
                                "v": "SUVWj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19596,
                                "v": "VUh4"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19678,
                                "v": "\nPj@"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 19700,
                                "v": "PWVU"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19712,
                                "v": "t[;|$"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19718,
                                "v": "uUh\fs@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19737,
                                "v": ">h\fs@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 19770,
                                "v": "PPPU"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20023,
                                "v": "SVW3"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20457,
                                "v": "@PWSh"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20552,
                                "v": "9M\ft"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20646,
                                "v": "u\u000bhHs@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20788,
                                "v": "_^[t\tP"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20809,
                                "v": "t$\fW"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 20875,
                                "v": "v\"Ph<"
                            },
                            {
                                "c": 2,
                                "f": 2,
                                "o": 21391,
                                "v": "j\tYj"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 21458,
                                "v": "<6;}"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 24103,
                                "v": "%pr@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 24109,
                                "v": "%lr@"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 24115,
                                "v": "%hr@"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25228,
                                "v": "RichEdit"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25240,
                                "v": "RichEdit20A"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25252,
                                "v": "RichEd32"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25264,
                                "v": "RichEd20"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25276,
                                "v": ".DEFAULT\\Control Panel\\International"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25316,
                                "v": "Control Panel\\Desktop\\ResourceLocale"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25356,
                                "v": "[Rename]\r\n"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25372,
                                "v": "Software\\Microsoft\\Windows\\CurrentVersion"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 25416,
                                "v": "\\Microsoft\\Internet Explorer\\Quick Launch"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29208,
                                "v": "verifying installer: %d%%"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29236,
                                "v": "Installer integrity check has failed. Common causes include\nincomplete download and damaged media. Contact the\ninstaller's author to obtain a new copy.\n\nMore information at:\nhttp://nsis.sf.net/NSIS_Error"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29440,
                                "v": "Error launching installer"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 29468,
                                "v": "... %d%%"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29480,
                                "v": "SeShutdownPrivilege"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29500,
                                "v": "~nsu.tmp"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29512,
                                "v": "\\Temp"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29520,
                                "v": "NSIS Error"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29532,
                                "v": "Error writing temporary file. Make sure your temp folder is valid."
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29624,
                                "v": ".exe"
                            },
                            {
                                "c": 2,
                                "f": 3,
                                "o": 29632,
                                "v": "open"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 29640,
                                "v": "%u.%u%s%s"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29768,
                                "v": "SHGetFolderPathA"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29788,
                                "v": "SHFOLDER"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29800,
                                "v": "SHAutoComplete"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29816,
                                "v": "SHLWAPI"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29824,
                                "v": "GetUserDefaultUILanguage"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29852,
                                "v": "AdjustTokenPrivileges"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29876,
                                "v": "LookupPrivilegeValueA"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29900,
                                "v": "OpenProcessToken"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29920,
                                "v": "RegDeleteKeyExA"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29936,
                                "v": "ADVAPI32"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29948,
                                "v": "MoveFileExA"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29960,
                                "v": "GetDiskFreeSpaceExA"
                            },
                            {
                                "c": 1,
                                "f": 3,
                                "o": 29980,
                                "v": "KERNEL32"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 29992,
                                "v": "\\*.*"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 30004,
                                "v": "%s=%s\r\n"
                            },
                            {
                                "c": 1,
                                "f": 2,
                                "o": 30012,
                                "v": "*?|<>/\":"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "ProgramFilesDir"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "C:\\Program Files"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%ProgramFiles32%"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "CommonFilesDir"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%ProgramFiles32%\\Common Files"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%ProgramFilesCommon32%"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%ProgramFiles32%\\ailiao"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$HWNDPARENT"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1037"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_63_"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_62_"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "0x0030"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1038"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_64_"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1034"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_65_"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1039"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_66_"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1028"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_68_"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1256"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$_INTVAR_67_"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "Nullsoft Install System v2.45 "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "0x000C"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1035"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "1045"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$PLUGINSDIR\\SkinBtn.dll"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "/IMGID=$PLUGINSDIR\\checkbox1.bmp"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "/IMGID=$PLUGINSDIR\\checkbox2.bmp"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "kernel32::CreateMutexA(i 0, i 0, t \"ailiao_Mutex_Setup\") i .R1 ?e"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "Call"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "kernel32::CloseHandle(i R1) i.s"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "$PLUGINSDIR"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "Alloc"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "kernel32::GetLocalTime(isR0)"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "*$R0(&i2.R1,&i2.R2,&i2,&i2.R4,&i2.R5)"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "Free"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "0$R2"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "0$R4"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "0$R5"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "$R1$R2$R4$R5"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "ailiao.exe"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%AppDataCommon%\\ailiaoweb"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%InstallDir%\\%InstallDir%\\uninst.exe"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%StartMenuProgramsCommon%\\°®ÁÄ"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "TaskbarPin"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "TaskbarPin %InstallDir%\\$_INTVAR_87_.lnk"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "http://ailiao.liaoban.com/xszd/index.html"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "open http://ailiao.liaoban.com/xszd/index.html"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "MainSetup"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%TempDir%"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "´íÎó! ÎÞ·¨³õÊ¼»¯²å¼þÄ¿Â¼. ÇëÉÔºóÖØÊÔ."
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "爱聊 °²×°"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÎÞ·¨Ð´Èë: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "¸´ÖÆÊ§°Ü "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "¸´ÖÆµ½: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÎÞ·¨ÕÒµ½·ûºÅ: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÎÞ·¨¼ÓÔØ: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "´´½¨ÎÄ¼þ¼Ð: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "´´½¨¿ì½Ý·½Ê½: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "´´½¨Ð¶ÔØ³ÌÐò: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "É¾³ýÎÄ¼þ: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÖØÐÂÆô¶¯ºóÉ¾³ý: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÕýÔÚ´´½¨¿ì½Ý·½Ê½Ê±·¢Éú´íÎó: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÕýÔÚ´´½¨Ê±·¢Éú´íÎó: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÕýÔÚ½âÑ¹ËõÊý¾Ý·¢Éú´íÎó£¡ÒÑËð»µµÄ°²×°³ÌÐò£¿"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÔËÐÐÍâ²¿³ÌÐò: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÔËÐÐ: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "³éÈ¡: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "³éÈ¡: ÎÞ·¨Ð´ÈëÎÄ¼þ "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "°²×°Ëð»Ù: ÎÞÐ§µÄ²Ù×÷´úÂë "
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "Ã»ÓÐ OLE ÓÃÓÚ: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "Êä³öÄ¿Â¼: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÒÆ³ýÄ¿Â¼: "
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÒÑÌø¹ý: "
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "ËÎÌå"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "ÄãÈ·ÊµÒªÍË³ö¡°爱聊¡±°²×°³ÌÐò£¿"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "²»ÄÜ´ò¿ªÒªÐ´ÈëµÄÎÄ¼þ: \r\n\t\"$_INTVAR_65516_\"\r\nµ¥»÷ [Abort] ·ÅÆú°²×°£¬\r\n [Retry] ÖØÐÂ³¢ÊÔÐ´ÈëÎÄ¼þ£¬»ò\r\n [Ignore] ºöÂÔÕâ¸öÎÄ¼þ¡£"
                            },
                            {
                                "c": 1,
                                "f": 12,
                                "o": -1,
                                "v": "×Ô¶¨Òå"
                            },
                            {
                                "c": 1,
                                "f": 13,
                                "o": -1,
                                "v": "%Windows%\\wininit.ini"
                            }
                        ],
                        "web": {}
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 results for: 0000a0a549be5b7a95b782d31f73d8f608c4a440
> **Type:** PE/Exe
>    **Size:** 385774 bytes 
>**MD5:** 96d17cad51f2b7c817481e5a724c9b3f
>**SHA1:** 0000a0a549be5b7a95b782d31f73d8f608c4a440
>**SHA256:** 0b40fb0cef3b557a34a3d7a9cd75d5180099205ccdceb8a73e1dfe73dbd282fd
>**SHA512:** 4546796ffd5075fc317549f6522df808f03d0d9e97398243259ed3d1bfb0b108083a2200fff49e4de25c5521eaef751d420763c089327b384feea27dc36d316a
>**ID:** 5722
>    **Malware status:** malicious
>    **Local first seen:** 2023-06-06T16:40:34.604510Z
>    **Local last seen:** 2023-06-06T16:40:34.604510Z
>    **First seen:** 2014-02-10T18:16:00Z
>    **Last seen:** 2023-03-06T12:17:51Z
>    **DBot score:** 3
>    **Risk score:** 9 
>**Threat name:** Win32.Browser.StartPage
> **Category:** application
>    **Classification origin:** None
>    **Classification reason:** antivirus
>    **Aliases:** 0000a0a549be5b7a95b782d31f73d8f608c4a440
>    **Extracted file count:** 6
>    **Identification name:** NSIS
>    **Identification version:** Generic
>### ReversingLabs threat indicators
>|category|description|id|priority|reasons|relevance|
>|---|---|---|---|---|---|
>| 22 | Deletes files in Windows system directories. | 101 | 7 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: DeleteFileA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetSystemDirectoryA'} | 0 |
>| 11 | Requests permission required to shut down a system. | 990 | 7 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: AdjustTokenPrivileges'},<br/>{'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: SeShutdownPrivilege'} | 0 |
>| 10 | Contains lzma compressed PE file. | 1052 | 7 | {'propagated': False, 'category': 'Pattern Match', 'description': 'Found a pattern [3c 2d 57 47 be 2d be 94 bd 8b dc 6f 25 97 af 50 f1 d2 5b 85 52 e1 d4 7c 3d 4c 75 4d a7 1f 1b 73 ed eb 01 c5 71 2f 70 5f b4 25 6f 1e a3 c5 c8 f1 1b bd] that ends at offset 138465'} | 0 |
>| 10 | Executes a file. | 21 | 6 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateProcessA'} | 0 |
>| 22 | Writes to files in Windows system directories. | 99 | 5 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateFileA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetSystemDirectoryA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: WriteFile'} | 0 |
>| 11 | Tampers with user/account privileges. | 329 | 5 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: AdjustTokenPrivileges'} | 0 |
>| 12 | Checks operating system version. | 930 | 5 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetVersion'} | 0 |
>| 22 | Creates temporary files. | 969 | 5 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetTempFileNameA'} | 0 |
>| 6 | Contains a reference to ActiveX GUID with the Kill-Bit flag set. | 1086 | 5 | {'propagated': False, 'category': 'Pattern Match', 'description': 'Found a pattern [65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 00 00 00 ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46] that ends at offset 25492'} | 0 |
>| 22 | Deletes files. | 5 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: DeleteFileA'} | 0 |
>| 9 | Accesses/modifies registry. | 7 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: RegDeleteValueA'},<br/>{'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: RegDeleteKeyExA'} | 0 |
>| 22 | Creates/opens files in Windows system directories. | 95 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateFileA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetSystemDirectoryA'} | 0 |
>| 22 | Reads from files in Windows system directories. | 97 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateFileA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetSystemDirectoryA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: ReadFile'} | 0 |
>| 10 | Tampers with system shutdown. | 117 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: ExitWindowsEx'} | 0 |
>| 13 | Enumerates system information. | 149 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetSystemDirectoryA'} | 0 |
>| 0 | Contains URLs. | 310 | 4 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: http:<span>//</span>ailiao.liaoban.com/'},<br/>{'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: http:<span>//</span>nsis.sf.net/'},<br/>{'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: open http:<span>//</span>ailiao.liaoban.com/'} | 0 |
>| 22 | Modifies file/directory attributes. | 384 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: SetFileAttributesA'} | 0 |
>| 22 | Copies, moves, renames, or deletes a file system object. | 965 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: SHFileOperationA'} | 0 |
>| 12 | Reads paths to special directories on Windows. | 966 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: SHGetSpecialFolderLocation'} | 0 |
>| 12 | Reads paths to system directories on Windows. | 967 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetSystemDirectoryA'} | 0 |
>| 12 | Reads path to temporary file location on Windows. | 968 | 4 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetTempPathA'} | 0 |
>| 11 | Enumerates user/account privilege information. | 1215 | 4 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: LookupPrivilegeValueA'} | 0 |
>| 22 | Writes to files. | 3 | 3 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateFileA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: WriteFile'} | 0 |
>| 1 | Uses anti-debugging methods. | 9 | 3 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetTickCount'} | 0 |
>| 7 | Detects/enumerates process modules. | 81 | 3 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetModuleFileNameA'} | 0 |
>| 22 | Removes a directory. | 340 | 3 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: RemoveDirectoryA'} | 0 |
>| 7 | Tampers with keyboard/mouse status. | 381 | 3 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: EnableWindow'} | 0 |
>| 22 | Copies a file. | 1031 | 3 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CopyFileA'} | 0 |
>| 22 | Reads from files. | 1 | 2 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateFileA'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: ReadFile'} | 0 |
>| 10 | Might load additional DLLs and APIs. | 69 | 2 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: GetProcAddress'},<br/>{'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: LoadLibraryA'} | 0 |
>| 12 | Enumerates files. | 119 | 2 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: FindFirstFileA'} | 0 |
>| 13 | Enumerates system variables. | 151 | 2 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: ExpandEnvironmentStringsA'} | 0 |
>| 22 | Creates a directory. | 338 | 2 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateDirectoryA'} | 0 |
>| 22 | Renames files. | 920 | 2 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: MoveFileA'} | 0 |
>| 22 | Creates/Opens a file. | 0 | 1 | {'propagated': False, 'category': 'Imported API Name', 'description': 'Imports the following function: CreateFileA'} | 0 |
>| 12 | Contains references to executable file extensions. | 313 | 1 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: $PLUGINSDIR\\SkinBtn.dll'} | 0 |
>| 12 | Contains references to source code file extensions. | 314 | 1 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: http:<span>//</span>ailiao.liaoban.com/xszd/index.html'},<br/>{'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: open http:<span>//</span>ailiao.liaoban.com/xszd/index.html'} | 0 |
>| 12 | Contains references to image file extensions. | 315 | 1 | {'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: /IMGID=$PLUGINSDIR\\checkbox1.bmp'},<br/>{'propagated': False, 'category': 'Strings', 'description': 'Contains the following string: /IMGID=$PLUGINSDIR\\checkbox2.bmp'} | 0 |
>| 18 | Accesses clipboard. | 328 | 1 | {'propagated': False, 'category': 'Capability Match', 'description': 'Matched the following application capabilities: Clipboard'} | 0 |


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
```!reversinglabs-a1000-delete-sample hash="0000a0a381d31e0dafcaa22343d2d7e40ff76e06"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "7479@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
                    "md5": "a984de0ce47a8d5337ef569c812b57d0",
                    "sha1": "0000a0a381d31e0dafcaa22343d2d7e40ff76e06",
                    "sha256": "b25e707a78a472d92a99b08be5d0e55072f695275a7408d1e841a5344ca85dc3",
                    "sha512": "9357144084c64531dec928de2a85c924d8079b50b5e98ab2c61ae59b97992a39b833f618341e91b071ec94e65bd901ebdf892851e5a4247e1557a55c14923da5"
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
>    **MD5:** a984de0ce47a8d5337ef569c812b57d0
>    **SHA1:** 0000a0a381d31e0dafcaa22343d2d7e40ff76e06
>    **SHA256:** b25e707a78a472d92a99b08be5d0e55072f695275a7408d1e841a5344ca85dc3


### reversinglabs-a1000-list-extracted-files

***
List files extracted from a sample.

#### Base Command

`reversinglabs-a1000-list-extracted-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The sample hash. | Required |
| max_results | Maximum number of results to return. Default is 5000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_list_extracted_report | Unknown | A1000 list extracted files report. |

#### Command example
```!reversinglabs-a1000-list-extracted-files hash="a94775deb818a4d68635eeed3d16abc7f7b8bdd6" max_results="2"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "8968@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Info": "text/plain",
        "Name": "List extracted files report file",
        "Size": 2034,
        "Type": "ASCII text"
    },
    "ReversingLabs": {
        "a1000_list_extracted_report": [
            {
                "container_sha1": null,
                "filename": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl",
                "id": 20010,
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
                    "local_last_seen": "2023-08-10T00:15:32.849362Z",
                    "md5": "8521e64c683e47c1db64d80577513016",
                    "riskscore": 10,
                    "sha1": "aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad",
                    "sha256": "43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1",
                    "type_display": "PE/Exe"
                }
            },
            {
                "container_sha1": null,
                "filename": "1",
                "id": 20011,
                "parent_relationship": 20010,
                "path": "binary_layer/resource/1",
                "sample": {
                    "category": "other",
                    "classification": "malicious",
                    "classification_result": "Win32.Malware.Generic",
                    "extracted_file_count": 0,
                    "file_size": 2,
                    "file_subtype": "None",
                    "file_type": "Text",
                    "id": 1329,
                    "identification_name": "",
                    "identification_version": "",
                    "local_first_seen": "2022-10-27T11:03:31.473395Z",
                    "local_last_seen": "2023-08-10T00:15:32.849362Z",
                    "md5": "c4103f122d27677c9db144cae1394a66",
                    "riskscore": 10,
                    "sha1": "1489f923c4dca729178b3e3233458550d8dddf29",
                    "sha256": "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "type_display": "Text/None"
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
>| aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad | aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl | aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad.rl | PE/Exe | 1432064 | 2022-10-27T11:03:31.473395Z | 2023-08-10T00:15:32.849362Z | malicious | 10 |  |  | PE/Exe |
>| 1489f923c4dca729178b3e3233458550d8dddf29 | 1 | binary_layer/resource/1 | Text/None | 2 | 2022-10-27T11:03:31.473395Z | 2023-08-10T00:15:32.849362Z | malicious | 10 |  |  | Text/None |



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
        "EntryID": "7493@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
        "EntryID": "7530@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
        "EntryID": "7488@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "cd1128f60819e50bb5d75ebe8e73d210",
        "Name": "a94775deb818a4d68635eeed3d16abc7f7b8bdd6.zip",
        "SHA1": "b13d1ba232376250ce061a84aa38a7a68cfdd24e",
        "SHA256": "697a4df08b104623d7a5bb81535210cb4ba398ba8709889ceeb5ce50b1c59d8a",
        "SHA512": "89addd59cfe696bf41a38c7175323476d7f0646e89d149d736d8a70023fa12baa24897d092cb9bf7d8ed4a945480fde3a0ce937fbc34023d5e630e0294becfdb",
        "SSDeep": "12288:wrLW2iHCZijVsEPYsqp1wzkZqY+JlySSeBSnY4Xf3sXdAeQQIetUpNZlx8wcQS:w2DCZijvwsq7QsqFPDSRF3sX6eQnljZS",
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
        "EntryID": "7498@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
            "cloud_last_lookup": "2023-06-06T16:05:02Z",
            "data_source": "LOCAL",
            "first_seen": "2022-12-19T11:39:11Z",
            "last_seen": "2023-06-06T16:02:03Z",
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
>**Last seen:** 2023-06-06T16:02:03Z
>**Classification result:** Win32.Trojan.Delf
>**Classification reason:** Antivirus
>**Classification origin:** {'sha1': 'aeb8cb59f158ca853a41c55ca3cfa14c0bf1baad', 'sha256': '43d51f009bf94707556031b9688e84bb85df2c59854fba8fcb90be6c0d19e1d1', 'sha512': '8a1c9512fa167b938ea31c047a48dd6ec36d9b22443bc4ee6b97a116e16ff33427645ac76349f531cd9a672b4fffc3c4c92d1c82d2a71241915c1499336fd221', 'md5': '8521e64c683e47c1db64d80577513016', 'imphash': 'c57e34b759dff2e57f71960b2fdb93da'}
>**Cloud last lookup:** 2023-06-06T16:05:02Z
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
```!reversinglabs-a1000-advanced-search query="av-count:5 available:TRUE" ticloud="False" result_limit=2```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "7474@08d0efc0-7fc6-4c26-8ae9-f3bfc7b92a59",
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
                        "update_time": "2023-06-06T10:57:14"
                    },
                    {
                        "detection": "undetected",
                        "source": "cyren",
                        "update_time": "2023-06-06T13:09:05"
                    },
                    {
                        "detection": "undetected",
                        "source": "cyradar",
                        "update_time": "2023-06-06T07:37:28"
                    },
                    {
                        "detection": "undetected",
                        "source": "netstar",
                        "update_time": "2023-06-06T11:25:58"
                    },
                    {
                        "detection": "undetected",
                        "source": "malsilo",
                        "update_time": "2023-06-06T11:06:03"
                    },
                    {
                        "detection": "undetected",
                        "source": "mute",
                        "update_time": "2023-06-06T13:39:52"
                    },
                    {
                        "detect_time": "2022-06-17T10:36:34",
                        "detection": "malicious",
                        "source": "adminus_labs",
                        "update_time": "2023-06-06T14:33:53"
                    },
                    {
                        "detection": "undetected",
                        "source": "apwg",
                        "update_time": "2023-06-06T13:21:19"
                    },
                    {
                        "detection": "undetected",
                        "source": "0xSI_f33d",
                        "update_time": "2023-06-06T05:21:10"
                    },
                    {
                        "detection": "undetected",
                        "source": "threatfox_abuse_ch",
                        "update_time": "2023-06-06T07:20:33"
                    },
                    {
                        "detection": "undetected",
                        "source": "alphamountain",
                        "update_time": "2023-06-06T13:52:05"
                    },
                    {
                        "detection": "undetected",
                        "source": "phishstats",
                        "update_time": "2023-06-06T04:12:33"
                    },
                    {
                        "detection": "undetected",
                        "source": "comodo_valkyrie",
                        "update_time": "2023-06-06T14:40:10"
                    },
                    {
                        "detection": "undetected",
                        "source": "alien_vault",
                        "update_time": "2023-06-06T00:34:26"
                    },
                    {
                        "detection": "undetected",
                        "source": "osint",
                        "update_time": "2023-06-06T00:30:41"
                    },
                    {
                        "detection": "undetected",
                        "source": "openphish",
                        "update_time": "2023-06-05T17:01:38"
                    },
                    {
                        "detection": "undetected",
                        "source": "mrg",
                        "update_time": "2023-06-06T13:44:31"
                    },
                    {
                        "detection": "undetected",
                        "source": "phishtank",
                        "update_time": "2023-06-06T10:31:21"
                    },
                    {
                        "detection": "undetected",
                        "source": "crdf",
                        "update_time": "2023-06-06T11:30:27"
                    },
                    {
                        "detection": "undetected",
                        "source": "urlhaus",
                        "update_time": "2023-06-06T09:24:38"
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
>    
>## Third party reputation statistics
> **Total**: 20
>    **Malicious**: 1
>    **Clean**: 0
>    **Undetected**: 19
>    
>## Analysis statistics
> **Unknown**: None
>    **Suspicious**: None
>    **Malicious**: None
>    **Goodware**: None
>    **Total**: None
>    
>**First analysis**: None
>    **Analysis count**: None
>    
> ## Third party reputation sources
>
> ### Sources
>|detection|source|update_time|
>|---|---|---|
>| undetected | phishing_database | 2023-06-06T10:57:14 |
>| undetected | cyren | 2023-06-06T13:09:05 |
>| undetected | cyradar | 2023-06-06T07:37:28 |
>| undetected | netstar | 2023-06-06T11:25:58 |
>| undetected | malsilo | 2023-06-06T11:06:03 |
>| undetected | mute | 2023-06-06T13:39:52 |
>| malicious | adminus_labs | 2023-06-06T14:33:53 |
>| undetected | apwg | 2023-06-06T13:21:19 |
>| undetected | 0xSI_f33d | 2023-06-06T05:21:10 |
>| undetected | threatfox_abuse_ch | 2023-06-06T07:20:33 |
>| undetected | alphamountain | 2023-06-06T13:52:05 |
>| undetected | phishstats | 2023-06-06T04:12:33 |
>| undetected | comodo_valkyrie | 2023-06-06T14:40:10 |
>| undetected | alien_vault | 2023-06-06T00:34:26 |
>| undetected | osint | 2023-06-06T00:30:41 |
>| undetected | openphish | 2023-06-05T17:01:38 |
>| undetected | mrg | 2023-06-06T13:44:31 |
>| undetected | phishtank | 2023-06-06T10:31:21 |
>| undetected | crdf | 2023-06-06T11:30:27 |
>| undetected | urlhaus | 2023-06-06T09:24:38 |
>
> ### Last analysis
>**No entries.**
>
> ### Analysis history
>**No entries.**


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
            "modified_time": "2023-06-06T13:52:05",
            "requested_domain": "ink-scape.online",
            "third_party_reputations": {
                "sources": [
                    {
                        "detection": "undetected",
                        "source": "phishing_database",
                        "update_time": "2023-06-06T01:26:52"
                    },
                    {
                        "detection": "undetected",
                        "source": "0xSI_f33d",
                        "update_time": "2023-06-06T05:21:10"
                    },
                    {
                        "detection": "undetected",
                        "source": "cyradar",
                        "update_time": "2023-06-06T07:37:28"
                    },
                    {
                        "detection": "undetected",
                        "source": "adminus_labs",
                        "update_time": "2023-06-06T13:48:57"
                    },
                    {
                        "detection": "undetected",
                        "source": "apwg",
                        "update_time": "2023-06-06T05:48:47"
                    },
                    {
                        "category": "malware_file",
                        "detect_time": "2023-05-11T05:21:55",
                        "detection": "malicious",
                        "source": "netstar",
                        "update_time": "2023-06-06T11:25:58"
                    },
                    {
                        "detection": "undetected",
                        "source": "threatfox_abuse_ch",
                        "update_time": "2023-06-06T07:20:33"
                    },
                    {
                        "detection": "undetected",
                        "source": "botvrij",
                        "update_time": "2023-06-06T01:26:07"
                    },
                    {
                        "detection": "undetected",
                        "source": "alphamountain",
                        "update_time": "2023-06-06T13:52:05"
                    },
                    {
                        "detection": "undetected",
                        "source": "comodo_valkyrie",
                        "update_time": "2023-06-06T04:52:55"
                    },
                    {
                        "detection": "undetected",
                        "source": "web_security_guard",
                        "update_time": "2022-01-21T06:56:15"
                    },
                    {
                        "detection": "undetected",
                        "source": "osint",
                        "update_time": "2023-06-06T00:30:41"
                    },
                    {
                        "detection": "undetected",
                        "source": "crdf",
                        "update_time": "2023-06-06T11:30:27"
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
> **Modified time**: 2023-06-06T13:52:05
> ### Top threats
>|files_count|risk_score|threat_name|
>|---|---|---|
>| 1 | 10 | Win64.Trojan.Casdet |
>| 1 | 10 | ByteCode-MSIL.Backdoor.DCRat |
>| 1 | 10 | ByteCode-MSIL.Infostealer.RedLine |
>| 1 | 10 | Win32.Trojan.Fragtor |
>
> ### Third party reputation statistics
> **Malicious**: 1
>    **Undetected**: 12
>    **Clean**: 0
>    **Total**: 13
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
> ### Third party reputation sources
>|detection|source|update_time|
>|---|---|---|
>| undetected | phishing_database | 2023-06-06T01:26:52 |
>| undetected | 0xSI_f33d | 2023-06-06T05:21:10 |
>| undetected | cyradar | 2023-06-06T07:37:28 |
>| undetected | adminus_labs | 2023-06-06T13:48:57 |
>| undetected | apwg | 2023-06-06T05:48:47 |
>| malicious | netstar | 2023-06-06T11:25:58 |
>| undetected | threatfox_abuse_ch | 2023-06-06T07:20:33 |
>| undetected | botvrij | 2023-06-06T01:26:07 |
>| undetected | alphamountain | 2023-06-06T13:52:05 |
>| undetected | comodo_valkyrie | 2023-06-06T04:52:55 |
>| undetected | web_security_guard | 2022-01-21T06:56:15 |
>| undetected | osint | 2023-06-06T00:30:41 |
>| undetected | crdf | 2023-06-06T11:30:27 |


### reversinglabs-a1000-ip-address-report

***
Get a report for the submitted IP address.

#### Base Command

`reversinglabs-a1000-ip-address-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_address_report | Unknown | A1000 IP address report | 

#### Command example
```!reversinglabs-a1000-ip-address-report ip_address="105.101.110.37"```
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
            "modified_time": "2023-06-06T14:00:43",
            "requested_ip": "105.101.110.37",
            "third_party_reputations": {
                "sources": [
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "alphamountain",
                        "update_time": "2023-06-06T13:52:05"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "apwg",
                        "update_time": "2023-06-06T08:24:03"
                    },
                    {
                        "category": "command_and_control",
                        "detect_time": "2023-05-15T15:20:23",
                        "detection": "malicious",
                        "source": "threatfox_abuse_ch",
                        "update_time": "2023-06-06T07:20:33"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "adminus_labs",
                        "update_time": "2023-06-06T14:00:43"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "osint",
                        "update_time": "2023-06-06T00:30:41"
                    },
                    {
                        "category": null,
                        "detect_time": null,
                        "detection": "undetected",
                        "source": "feodotracker",
                        "update_time": "2023-06-06T04:27:58"
                    },
                    {
                        "category": null,
                        "detect_time": "2023-05-28T05:00:06",
                        "detection": "malicious",
                        "source": "crdf",
                        "update_time": "2023-06-06T11:30:27"
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
> **Modified time**: 2023-06-06T14:00:43
> ### Top threats
>**No entries.**
>
> ### Third party reputation statistics
> **Malicious**: 2
>    **Undetected**: 5
>    **Clean**: 0
>    **Total**: 7
>    
> ### Downloaded files statistics
> **Unknown**: 0
>    **Suspicious**: 0
>    **Malicious**: 0
>    **Goodware**: 0
>    **Total**: 0
>    
> ### Third party reputation sources
>|category|detect_time|detection|source|update_time|
>|---|---|---|---|---|
>|  |  | undetected | alphamountain | 2023-06-06T13:52:05 |
>|  |  | undetected | apwg | 2023-06-06T08:24:03 |
>| command_and_control | 2023-05-15T15:20:23 | malicious | threatfox_abuse_ch | 2023-06-06T07:20:33 |
>|  |  | undetected | adminus_labs | 2023-06-06T14:00:43 |
>|  |  | undetected | osint | 2023-06-06T00:30:41 |
>|  |  | undetected | feodotracker | 2023-06-06T04:27:58 |
>|  | 2023-05-28T05:00:06 | malicious | crdf | 2023-06-06T11:30:27 |


### reversinglabs-a1000-ip-downloaded-files

***
Get a list of files downloaded from an IP address.

#### Base Command

`reversinglabs-a1000-ip-downloaded-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address string. | Required | 
| extended_results | Return extended results. Default is True. | Optional | 
| classification | Return only results with this classification. | Optional | 
| page_size | Number of results per query page. Default is 500. | Optional | 
| max_results | Maximum number of returned results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_address_downloaded_files | Unknown | A1000 Files downloaded from IP address | 

#### Command example
```!reversinglabs-a1000-ip-downloaded-files classification="MALICIOUS" page_size="2" max_results="2" ip_address="123.140.161.243" extended_results="true"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "123.140.161.243",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ReversingLabs A1000 v2"
    },
    "IP": {
        "Address": "123.140.161.243"
    },
    "ReversingLabs": {
        "a1000_ip_address_downloaded_files": [
            {
                "classification": "MALICIOUS",
                "first_download": "2022-11-02T07:38:05",
                "first_seen": "2022-11-02T07:38:05",
                "last_download": "2022-11-02T07:38:05",
                "last_download_url": "http://uaery.top/dl/buildz.exe",
                "last_seen": "2023-04-27T15:22:05",
                "malware_family": "RedLine",
                "malware_type": "Trojan",
                "md5": "1af44914e2340ab6da17a3a61609a2e4",
                "platform": "Win32",
                "risk_score": 10,
                "sample_available": true,
                "sample_size": 840704,
                "sample_type": null,
                "sha1": "03359456add1d7c5eae291f8f50576e0a324cbbd",
                "sha256": "069027da6066f79736223dbc9fa99a42533cfbdf24f6e683f6e9d3934f009afa",
                "subplatform": null,
                "threat_name": "Win32.Trojan.RedLine"
            },
            {
                "classification": "MALICIOUS",
                "first_download": "2023-03-28T04:12:36",
                "first_seen": "2023-03-28T04:12:36",
                "last_download": "2023-03-28T04:12:36",
                "last_download_url": "https://worldofcreatures.at/Launcher.exe",
                "last_seen": "2023-04-29T15:38:56",
                "malware_family": "TrickOrTreat",
                "malware_type": "Trojan",
                "md5": "aea58c2837e8dd1850d46198e9870c5e",
                "platform": "Win64",
                "risk_score": 10,
                "sample_available": true,
                "sample_size": 1179894205,
                "sample_type": "PE+/Exe",
                "sha1": "1181efbb5f267554a4ca8ffe98434c83e456d6bb",
                "sha256": "33ba1893894e50bc960af51348b99e3064e98e533f255b255846b49ea5ed5421",
                "subplatform": null,
                "threat_name": "Win64.Trojan.TrickOrTreat"
            }
        ]
    }
}
```

#### Human Readable Output

>## ReversingLabs A1000 Files Downloaded From IP Address 123.140.161.243
> ### Files downloaded from IP address
>|classification|first_download|first_seen|last_download|last_download_url|last_seen|malware_family|malware_type|md5|platform|risk_score|sample_available|sample_size|sample_type|sha1|sha256|subplatform|threat_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| MALICIOUS | 2022-11-02T07:38:05 | 2022-11-02T07:38:05 | 2022-11-02T07:38:05 | http:<span>//</span>uaery.top/dl/buildz.exe | 2023-04-27T15:22:05 | RedLine | Trojan | 1af44914e2340ab6da17a3a61609a2e4 | Win32 | 10 | true | 840704 |  | 03359456add1d7c5eae291f8f50576e0a324cbbd | 069027da6066f79736223dbc9fa99a42533cfbdf24f6e683f6e9d3934f009afa |  | Win32.Trojan.RedLine |
>| MALICIOUS | 2023-03-28T04:12:36 | 2023-03-28T04:12:36 | 2023-03-28T04:12:36 | https:<span>//</span>worldofcreatures.at/Launcher.exe | 2023-04-29T15:38:56 | TrickOrTreat | Trojan | aea58c2837e8dd1850d46198e9870c5e | Win64 | 10 | true | 1179894205 | PE+/Exe | 1181efbb5f267554a4ca8ffe98434c83e456d6bb | 33ba1893894e50bc960af51348b99e3064e98e533f255b255846b49ea5ed5421 |  | Win64.Trojan.TrickOrTreat |


### reversinglabs-a1000-ip-domain-resolutions

***
Get a list of IP-to-domain resolutions.

#### Base Command

`reversinglabs-a1000-ip-domain-resolutions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address string. | Required | 
| page_size | Number of results per query page. Default is 500. | Optional | 
| max_results | Maximum number of returned results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_domain_resolutions | Unknown | A1000 IP-to-domain resolutions | 

#### Command example
```!reversinglabs-a1000-ip-domain-resolutions ip_address="142.250.186.142" page_size="2" max_results="2"```
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


### reversinglabs-a1000-ip-urls

***
Get a list of URLs hosted on the requested IP address.

#### Base Command

`reversinglabs-a1000-ip-urls`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address string. | Required | 
| page_size | Number of results per query page. Default is 500. | Optional | 
| max_results | Maximum number of returned results. Default is 5000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ReversingLabs.a1000_ip_urls | Unknown | A1000 URL-s hosted on an IP address | 

#### Command example
```!reversinglabs-a1000-ip-urls ip_address="142.250.186.142" page_size="2" max_results="2"```
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


