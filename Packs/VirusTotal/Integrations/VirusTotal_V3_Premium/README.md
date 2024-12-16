Use the premium API capabilities of VirusTotal to analyze retro hunts, read live hunt notifications, and download files from VirusTotal.
The differences between VirusTotal's Public API and Premium API can be found [in the VirusTotal v3 API documentation](https://docs.virustotal.com/reference/public-vs-premium-api).

This integration was integrated and tested with VirusTotal - Premium (API v3)

## Use Cases
- Fetch live hunt notifications as incidents.
- Use retro hunt to analyze files with custom YARA rule.
- Download suspicious files from VirusTotal for further analysis.
- Group several files from VirusTotal into a password-protected ZIP file.
- Get a PCAP file generated from VirusTotal's sandbox for further analysis. 

## Configure VirusTotal - Premium (API v3) in Cortex

| **Parameter** | **Required** |
| --- | --- |
| API Key | API Key  | True |
| Fetch incidents | False |
| Incident type | False |
| Maximum number of incidents per fetch | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) or a date or epoch timestamp. | False |
| Tag: The ruleset's name or the identifier for the YARA rule matching the file to fetch its notifications. Leave blank to fetch all. | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


### Acquire API Key 
Your API key can be found in your VirusTotal account user menu.
Your API key carries all your privileges, so keep it secure and don't share it with anyone.

## Fetch Incidents
Fetch incidents will fetch livehunt notifications of the given ruleset or identifier. 
As an example, you can fetch incidents that were created by the CyberGate ruleset by using the "cybergate" tag.
The scope of the rule-set should be narrowed to catch only indicators that you want to analyze by a playbook.
Defining a broad rule-set will cause the integration to create multiple redundant incidents.  

## VirusTotal - Private API compatibility
The following 2 commands appear in both the *VirusTotal - Private API* and *VirusTotal Premium - (API v3)* integrations.
- **vt-private-search-file**
- **vt-private-download-file**
- It is recommended to use these commands in the *VirusTotal Premium - (API v3)* integration.   
- For all other commands, you should use the *VirusTotal - Private API* integration.

## Report commands alternatives / Enrichment
To enrich indicators, you can use the *VirusTotal (API v3)* integration reputation commands.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vt-private-download-file
***
Downloads file from VirusTotal


#### Base Command

`vt-private-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | SHA-256, SHA-1 or MD5 identifying the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 


#### Command Example
```!vt-private-download-file hash=0f555ed56bb78c5511f4e488cd37f24d1425fcfa```

#### Context Example
```json
{
    "File": {
        "EntryID": "siaXc5aYZGhuDY3iZVZtTg@2c18b8c3-8f96-458e-8849-39fc741e78fa",
        "Info": "image/png",
        "MD5": "49a3d343611a87c510e6ec692bb4fd72",
        "Name": "616a0f7baca32f253bd7836ed743319e556f2dfdd0fac5e6a0b371f9a34d5f79-vt-file",
        "SHA1": "0f555ed56bb78c5511f4e488cd37f24d1425fcfa",
        "SHA256": "616a0f7baca32f253bd7836ed743319e556f2dfdd0fac5e6a0b371f9a34d5f79",
        "SHA512": "8fbebc03aac2a0c0869597d4496c366674ee0f232dec7d9459adb8b8c3273f6644e0d2c9a90933c1e0120746131bc82be3d96ad5f7a722bdd2f8e99543a3c904",
        "SSDeep": "192:XIFt+lLuT9Qk9iw7AOMOAHz2tsO/FgNO7sXbqXi765r2pB:ct+Bk9MOMBHz2tZGN4Y6M",
        "Size": 7633,
        "Type": "PNG image data, 240 x 165, 8-bit/color RGBA, non-interlaced"
    }
}
```


### vt-private-zip-create
***
Creates a password-protected ZIP file containing files from VirusTotal.


#### Base Command

`vt-private-zip-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A commma separated list of hashes (SHA-256, SHA-1, or MD5) for the files included in the ZIP. | Required | 
| password | A password to protect the zip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Zip.id | String | ID of the zip | 
| VirusTotal.Zip.type | String | Type of the ID \(zip_file\) | 
| VirusTotal.Zip.links.self | String | Self link to file | 
| VirusTotal.Zip.attributes.files_error | Number | The number of files resulted in error | 
| VirusTotal.Zip.attributes.files_ok | Number | The number of files resulted in success zipped. | 
| VirusTotal.Zip.attributes.progress | Number | Progress of the zipping command in percentage. | 
| VirusTotal.Zip.attributes.status | String | The status of the zip process. "finished" is the state when finished. | 


#### Command Example
```!vt-private-zip-create file=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f password=apassword```

#### Context Example
```json
{
    "VirusTotal": {
        "Zip": {
            "attributes": {
                "files_error": 0,
                "files_ok": 0,
                "progress": 0,
                "status": "starting"
            },
            "id": "6268237216776192",
            "links": {
                "self": "https://www.virustotal.com/api/v3/zip_files/6268237216776192"
            },
            "type": "zip_file"
        }
    }
}
```

#### Human Readable Output

>### The request to create the ZIP was submitted successfully!
>|id|status|
>|---|---|
>| 6268237216776192 | starting |


### vt-private-zip-get
***
Retrieve information about a ZIP file.


#### Base Command

`vt-private-zip-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zip_id | A zip ID. Can be retrieved from the output of vt-private-zip-create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Zip.id | String | ID of the zip | 
| VirusTotal.Zip.type | String | Type of the ID \(zip_file\) | 
| VirusTotal.Zip.links.self | String | Self link to file | 
| VirusTotal.Zip.attributes.files_error | Number | The number of files resulted in error | 
| VirusTotal.Zip.attributes.files_ok | Number | The number of files resulted in success zipped. | 
| VirusTotal.Zip.attributes.progress | Number | Progress of the zipping command in percentage. | 
| VirusTotal.Zip.attributes.status | String | The status of the zip process. "finished" is the state when finished. | 


#### Command Example
```!vt-private-zip-get zip_id=5548746369433600```

#### Context Example
```json
{
    "VirusTotal": {
        "Zip": {
            "attributes": {
                "files_error": 0,
                "files_ok": 3,
                "progress": 1,
                "status": "finished"
            },
            "id": "5548746369433600",
            "links": {
                "self": "https://www.virustotal.com/api/v3/zip_files/5548746369433600"
            },
            "type": "zip_file"
        }
    }
}
```

#### Human Readable Output

>ZIP creation status is "finished"

### vt-private-zip-download
***
Download a ZIP file.


#### Base Command

`vt-private-zip-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zip_id | A zip ID. Can be retrieved from the output of vt-private-zip-create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 


#### Command Example
```!vt-private-zip-download zip_id=5548746369433600```



### vt-private-file-sandbox-pcap
***
Extracted PCAP from a sandbox analysis.


#### Base Command

`vt-private-file-sandbox-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Sandbox report ID. Can be aquired from vt-file-sandbox-report. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 


#### Command Example
```!vt-private-file-sandbox-pcap report_id="699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_VirusTotal Jujubox"```


### vt-private-intelligence-search
***
Search for files.


#### Base Command

`vt-private-intelligence-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query. | Required | 
| limit | Maximum number of results. Default is 10. | Optional | 
| order | The order value can be sorted depends on the query type. See documentation. https://docs.virustotal.com/reference/intelligence-search. | Optional | 
| cursor | Continuation cursor. | Optional | 
| descriptors_only | Whether to return full object information or just object descriptors. Possible values are: true, false. Default is false. | Optional | 
| extended_data | Whether to return full data information. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.IntelligenceSearch.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.IntelligenceSearch.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.IntelligenceSearch.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.IntelligenceSearch.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.IntelligenceSearch.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.IntelligenceSearch.type | String | The type of the indicator \(ip_address, domain, url, file\) | 
| VirusTotal.IntelligenceSearch.id | String | ID of the indicator | 
| VirusTotal.IntelligenceSearch.links.self | String | Link to the response | 


#### Command Example
```!vt-private-intelligence-search query=699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3```

#### Context Example
```json
{
    "VirusTotal": {
        "IntelligenceSearch": {
            "attributes": {
                "authentihash": "249ffc3cf7a9e7e8970089eb468262484bc9dd197bd0eab49469bb4a31b16776",
                "capabilities_tags": [],
                "creation_date": 1516090519,
                "dot_net_assembly": {
                    "assembly_data": {
                        "buildnumber": 7,
                        "culture": "",
                        "flags": 0,
                        "flags_text": "afPA_None",
                        "hashalgid": 32772,
                        "majorversion": 17,
                        "minorversion": 18,
                        "name": "Po160118",
                        "pubkey": "",
                        "revisionnumber": 0
                    },
                    "assembly_flags": 3,
                    "assembly_flags_txt": "COMIMAGE_FLAGS_ILONLY, COMIMAGE_FLAGS_32BITREQUIRED",
                    "assembly_name": "Po160118.exe",
                    "clr_meta_version": "1.1",
                    "clr_version": "v4.0.30319",
                    "entry_point_rva": 32856,
                    "entry_point_token": 100663315,
                    "external_assemblies": {
                        "Microsoft.VisualBasic": {
                            "version": "10.0.0.0"
                        },
                        "System": {
                            "version": "4.0"
                        },
                        "mscorlib": {
                            "version": "4.0"
                        }
                    },
                    "manifest_resource": [
                        "Bmf.Resources.resources"
                    ],
                    "metadata_header_rva": 274480,
                    "resources_va": 241622,
                    "streams": {
                        "#Blob": {
                            "chi2": 91925.3125,
                            "entropy": 3.741455316543579,
                            "md5": "406538c401776a3398e3f350249889ff",
                            "size": 1944
                        },
                        "#GUID": {
                            "chi2": 240,
                            "entropy": 4,
                            "md5": "e6777e9fe14ccf9d6f246304551050d2",
                            "size": 16
                        },
                        "#Strings": {
                            "chi2": 20380.203125,
                            "entropy": 4.854885101318359,
                            "md5": "47bd71fae4b150ff3a0484c3bfaa7977",
                            "size": 1724
                        },
                        "#US": {
                            "chi2": 10436212,
                            "entropy": 3.9474689960479736,
                            "md5": "3a0604a1944e85f1b38d3e9ca3e42a70",
                            "size": 163116
                        },
                        "#~": {
                            "chi2": 78347.59375,
                            "entropy": 4.5347442626953125,
                            "md5": "5134507689ba5ca0af57836ecfad8923",
                            "size": 1616
                        }
                    },
                    "strongname_va": 0,
                    "tables_present": 19,
                    "tables_present_map": "f0909a21557L",
                    "tables_rows_map": "1267050130403702f0000d000205500900001003000012320",
                    "tables_rows_map_log": "4765758864556454454",
                    "type_definition_list": [
                        {
                            "namespace": "System.Reflection",
                            "type_definitions": [
                                "AssemblyFileVersionAttribute"
                            ]
                        }
                    ]
                },
                "dot_net_guids": {
                    "mvid": "746a48dd-5234-4945-aa08-2ebddca5a942"
                },
                "downloadable": true,
                "exiftool": {
                    "AssemblyVersion": "assemlyVersion",
                    "CharacterSet": "Unicode",
                    "CodeSize": "435200",
                    "Comments": "Comverse Technology Kopl",
                    "CompanyName": "Comverse Technology",
                    "EntryPoint": "0x6c2ce",
                    "FileDescription": "Comverse Technology",
                    "FileFlagsMask": "0x003f",
                    "FileOS": "Win32",
                    "FileSubtype": "0",
                    "FileType": "Win32 EXE",
                    "FileTypeExtension": "exe",
                    "FileVersion": "file version",
                    "FileVersionNumber": "file version",
                    "ImageFileCharacteristics": "Executable, 32-bit",
                    "ImageVersion": "0.0",
                    "InitializedDataSize": "25088",
                    "InternalName": "Po160118.exe",
                    "LanguageCode": "Neutral",
                    "LegalCopyright": "(c) 2015Comverse Technology",
                    "LinkerVersion": "11.0",
                    "MIMEType": "application/octet-stream",
                    "MachineType": "Intel 386 or later, and compatibles",
                    "OSVersion": "4.0",
                    "ObjectFileType": "Executable application",
                    "OriginalFileName": "Po160118.exe",
                    "PEType": "PE32",
                    "ProductName": "Comverse Technology Cemp Kopl",
                    "ProductVersion": "file version",
                    "ProductVersionNumber": "file version",
                    "Subsystem": "Windows GUI",
                    "SubsystemVersion": "4.0",
                    "TimeStamp": "2018:01:16 08:15:19+00:00",
                    "UninitializedDataSize": "0"
                },
                "first_seen_itw_date": 1516269526,
                "first_submission_date": 1516098585,
                "last_analysis_date": 1616590701,
                "last_analysis_stats": {
                    "confirmed-timeout": 0,
                    "failure": 0,
                    "harmless": 0,
                    "malicious": 51,
                    "suspicious": 0,
                    "timeout": 0,
                    "type-unsupported": 5,
                    "undetected": 19
                },
                "last_modification_date": 1616598130,
                "last_submission_date": 1614668707,
                "magic": "PE32 executable for MS Windows (GUI) Intel 80386 32-bit Mono/.Net assembly",
                "main_icon": {
                    "dhash": "ce92b2b2f2321e0a",
                    "raw_md5": "e96f5b5bf8d769b31cf1d0c4a77bc0e8"
                },
                "md5": "2b294b3499d1cce794badffc959b7618",
                "meaningful_name": "Po160118.exe",
                "names": [
                    "Po160118.exe",
                    "C:\\Users\\TCS1\\Desktop\\Win32.AgentTesla.exe",
                ],
                "reputation": 0,
                "sha1": "9aa826795798948e8058e3ff1342d81d5d8ee4fa",
                "sha256": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3",
                "signature_info": {
                    "comments": "Comverse Technology Kopl",
                    "copyright": "(c) 2015Comverse Technology",
                    "description": "Comverse Technology",
                    "file version": "file version",
                    "internal name": "Po160118.exe",
                    "original name": "Po160118.exe",
                    "product": "Comverse Technology Cemp Kopl"
                },
                "size": 460800,
                "ssdeep": "12288:5qIrEFD09leQEA49darfr3/2AbitnVYE96ltR:5AFD1A498H2D",
                "tags": [
                    "peexe",
                    "assembly"
                ],
                "times_submitted": 41,
                "tlsh": "T106A4063C2DEA602BF2B2EF718BD47597E9DAB6733635585A1482030AC513983EEC153D",
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "trid": [
                    {
                        "file_type": "Generic CIL Executable (.NET, Mono, etc.)",
                        "probability": 72.5
                    }
                ],
                "type_description": "Win32 EXE",
                "type_extension": "exe",
                "type_tag": "peexe",
                "unique_sources": 23,
                "vhash": "24503665151e06161z22"
            },
            "id": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3",
            "links": {
                "self": "https://www.virustotal.com/api/v3/files/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3"
            },
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>### Results
>|attributes|id|
>|---|---| 
>| type_description: Win32 EXE | 699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3 | 


### vt-private-search-file
***
Search for files.


#### Base Command

`vt-private-search-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | File search query. For example, query="type:peexe size:90kb+ positives:5+ behaviour:'taskkill'". | Required | 
| fullResponse | Return all of the results, note that it can be thousands of results. Prefer not to use in playbooks. The default value is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.SearchFile.SearchResult | string | The hashes of files that fit the query | 
| VirusTotal.SearchFile.Query | string | Original search query | 


#### Command Example
```!vt-private-search-file query="type:peexe size:90kb+ positives:5+ behaviour:'taskkill'"```

#### Human Readable Output
> ### Found hashes for query: "type:peexe size:90kb+ positives:5+ behaviour:'taskkill'"
>| Found hashes |
>|---|
>| 83bafb3147b885c78fbda8a4f6a7f9f58c82b86681da38f48232e0205c57774b |


### vt-private-livehunt-rules-get-by-id
***
Retrieve VT Hunting livehunt rulesets.


#### Base Command

`vt-private-livehunt-rules-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ruleset identifier. Can be retreived from the vt-private-livehunt-rules-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | Creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 


#### Command Example
```!vt-private-livehunt-rules-get-by-id id=6360290934161408```

#### Human Readable Output
> ### Livehunt Ruleset 5950298890469376
> | name | enabled | rule_names |
> |---|---|---|
> | A rule name | false | foobar | 


### vt-private-livehunt-rules-list
***
Retrieve VT Hunting livehunt rulesets.


#### Base Command

`vt-private-livehunt-rules-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Return the rulesets matching the given criteria only. | Optional | 
| limit | Maximum number of results. Default is 10. | Optional | 
| order | Sort order. Possible values are: name-, creation_date-, modification_date-, name+, creation_date+, modification_date+. | Optional | 
| cursor | Continuation cursor. | Optional | 
| enabled | Should list only enabled or disabled rules. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 


#### Command Example
```!vt-private-livehunt-rules-list limit=1 enabled=false order="modification_date-"```

#### Context Example
```json
{
    "VirusTotal": {
        "LiveHuntRule": {
            "attributes": {
                "creation_date": 1617056763,
                "enabled": false,
                "limit": 100,
                "modification_date": 1617056763,
                "name": "a new rule",
                "notification_emails": [],
                "number_of_rules": 1,
                "rule_names": [
                    "foobar"
                ],
                "rules": "rule foobar { strings: $ = \"foobar\" condition: all of them }"
            },
            "id": "5551558908215296",
            "links": {
                "self": "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets/5551558908215296"
            },
            "type": "hunting_ruleset"
        }
    }
}
```

#### Human Readable Output

>### VT Hunting Livehunt rulesets
>|id|name|enabled|rule_names|
>|---|---|---|---|
>| 5551558908215296 | a new rule | false | foobar |


### vt-private-livehunt-rules-create
***
Create a new VT Hunting Livehunt ruleset.


#### Base Command

`vt-private-livehunt-rules-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule. | Required | 
| yara_rule | The rule itself. | Required | 
| enabled | Whatever to enable the rule. Possible values are: true, false. Default is false. | Optional | 
| notification_emails | A comma-separated list of emails to notify. | Optional | 
| limit | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 


#### Command Example
```!vt-private-livehunt-rules-create limit=100 name="a new rule" yara_rule=`rule foobar { strings: $ = "foobar" condition: all of them }````

#### Context Example
```json
{
    "VirusTotal": {
        "LiveHuntRule": {
            "attributes": {
                "creation_date": 1617056763,
                "enabled": false,
                "limit": 100,
                "modification_date": 1617056763,
                "name": "a new rule",
                "notification_emails": [],
                "number_of_rules": 1,
                "rule_names": [
                    "foobar"
                ],
                "rules": "rule foobar { strings: $ = \"foobar\" condition: all of them }"
            },
            "id": "5551558908215296",
            "links": {
                "self": "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets/5551558908215296"
            },
            "type": "hunting_ruleset"
        }
    }
}
```

#### Human Readable Output

>### New rule "a new rule" was created successfully
>|id|name|number_of_rules|
>|---|---|---|
>| 5551558908215296 | a new rule | 1 |


### vt-private-livehunt-rules-update
***
Update a VT Hunting Livehunt ruleset.


#### Base Command

`vt-private-livehunt-rules-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule identifier. Can be retrieved from the vt-private-livehunt-rules-list command. | Required | 
| yara_rule | The rule itself. | Optional | 
| enabled | Whatever to enable the rule. Possible values are: true, false. Default is false. | Optional | 
| notification_emails | A comma-separated list of emails to notify. | Optional | 
| limit | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntRule.attributes.name | String | The rule's name | 
| VirusTotal.LiveHuntRule.attributes.modification_date | Number | last modification date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rules | String | rule file contents | 
| VirusTotal.LiveHuntRule.attributes.enabled | Boolean | whether it's enabled or not | 
| VirusTotal.LiveHuntRule.attributes.creation_date | Number | creation date as UTC timestamp. | 
| VirusTotal.LiveHuntRule.attributes.rule_names | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntRule.attributes.limit | Number | max number of notifications that will be generated by the ruleset in a 24h period. If a match is found, number of generated hunting notifications in the last 24h is looked up and if it's greater than this limit, that match is ignored. | 
| VirusTotal.LiveHuntRule.attributes.number_of_rules | Number | Number of rules presented in the set | 
| VirusTotal.LiveHuntRule.type | String | The type of the entry \(hunting_ruleset\) | 
| VirusTotal.LiveHuntRule.id | Date | ID of the ruleset | 
| VirusTotal.LiveHuntRule.links.self | String | Link to the ruleset | 


#### Command Example
```!vt-private-livehunt-rules-update id=6360290934161408 enabled=false```

#### Context Example
```json
{
    "VirusTotal": {
        "LiveHuntRule": {
            "attributes": {
                "creation_date": 1615821390,
                "enabled": false,
                "limit": 100,
                "modification_date": 1617056770,
                "name": "a new rule",
                "notification_emails": [],
                "number_of_rules": 1,
                "rule_names": [
                    "new_file_from_china"
                ],
                "rules": "import \"vt\"\n\nrule new_file_from_china {\n  condition:\n    vt.metadata.submitter.country == \"CN\"\n}\n"
            },
            "id": "6360290934161408",
            "links": {
                "self": "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets/6360290934161408"
            },
            "type": "hunting_ruleset"
        }
    }
}
```

#### Human Readable Output

>### Rule "6360290934161408" has been updated!
>|id|name|number_of_rules|
>|---|---|---|
>| 6360290934161408 | a new rule | 1 |


### vt-private-livehunt-rules-delete
***
Delete a VT Hunting Livehunt ruleset.


#### Base Command

`vt-private-livehunt-rules-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Ruleset identifier. Can be retreived from the vt-private-livehunt-rules-list. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vt-private-livehunt-rules-delete id=5030439520337920```

#### Human Readable Output

>Rule "5030439520337920" was deleted successfully

### vt-private-livehunt-notifications-list
***
Retrieve VT Hunting Livehunt notifications.


#### Base Command

`vt-private-livehunt-notifications-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of notifications to retrieve. Maximum can be up to 40. Default is 10. | Optional | 
| from_time | Fetch notification from given time. Can be epoch time, a date or time range (3 days, 1 year). | Optional | 
| to_time | Fetch notification from given time. Can be epoch time or a date. | Optional | 
| cursor | Continuation cursor. | Optional | 
| tag | Filter notifications by tag. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntNotification.meta.count | Number | Notification count | 
| VirusTotal.LiveHuntNotification.meta.cursor | String | The cursor of the list | 
| VirusTotal.LiveHuntNotification.data.attributes.tags | String | notification tags. | 
| VirusTotal.LiveHuntNotification.data.attributes.source_country | String | Source country of the notification | 
| VirusTotal.LiveHuntNotification.data.attributes.source_key | String | Source key of the notificaton | 
| VirusTotal.LiveHuntNotification.data.attributes.snippet | String | The snippet ID \(if exists\) | 
| VirusTotal.LiveHuntNotification.data.attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntNotification.data.attributes.date | Number | The date of the notification in epoch | 
| VirusTotal.LiveHuntNotification.data.attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.LiveHuntNotification.data.type | String | Type of the notification \(hunting_notification\) | 
| VirusTotal.LiveHuntNotification.data.id | String | The ID of the notification | 
| VirusTotal.LiveHuntNotification.data.links.self | String | The link to the notificaton | 
| VirusTotal.LiveHuntNotification.links.self | String | The link to the current page | 
| VirusTotal.LiveHuntNotification.links.next | String | The link to the next page | 


#### Command Example
```!vt-private-livehunt-notifications-list filter=malicious_executables limit=1```

#### Context Example
```json
{
    "VirusTotal": {
        "LiveHuntNotification": {
            "data": [
                {
                    "attributes": {
                        "date": 1617025254,
                        "match_in_subfile": false,
                        "rule_name": "CyberGate",
                        "rule_tags": [],
                        "snippet": "23 23 20 23 23 23 23 40 23 23 23 23 F0 DD D1 D1  ## ####@####....\nD9 CE 23 23 23 23 40 23 23 23 23 8A 8A 8A 85 *begin_highlight*23*end_highlight*  ..####@####....*begin_highlight*#*end_highlight*\n*begin_highlight*23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23*end_highlight*  *begin_highlight*###@####....####*end_highlight*\n*begin_highlight*40 23 23 23 23 *end_highlight*88 23 23 23 23 40 23 23 23 23 DF  *begin_highlight*@####*end_highlight*.####@####.\nF9 E9 9C EF F5 EF E8 F9 F1 FD 9C EF F9 EE 7D 9C  ..............}.\nFA F3 EE F1 FD E8 FD F8 F3 92 *begin_highlight*23 23 23 23 40 23*end_highlight*  ..........*begin_highlight*####@#*end_highlight*\n*begin_highlight*23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23*end_highlight*  *begin_highlight*###....####@####*end_highlight*\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 FA FD F0  ....####@####...\nFA F3 EE F1 FD E8 FD F8 F3 92 23 23 23 23 40 23  ..........####@#\n23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23 23*end_highlight*  ###....*begin_highlight*####@####*end_highlight*\n*begin_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23 23 *end_highlight*FA FD F0  *begin_highlight*....####@####*end_highlight*...\nEF F9 23 23 23 23 40 23 23 23 23 20 23 23 23 23  ..####@#### ####\n23 23 23 23 20 23 23 23 23 40 23 23 23 23 20 23  #### ####@#### #\n23 23 23 40 23 23 23 23 8F 8C *begin_highlight*23 23 23 23 40 23*end_highlight*  ###@####..*begin_highlight*####@#*end_highlight*\n*begin_highlight*23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23*end_highlight*  *begin_highlight*###....####@####*end_highlight*\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9  ....####@####...\n23 23 23 40 23 23 23 23 8F 8C 23 23 23 23 40 23  ###@####..####@#\n23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23 23*end_highlight*  ###....*begin_highlight*####@####*end_highlight*\n*begin_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23 23 *end_highlight*E8 EE E9  *begin_highlight*....####@####*end_highlight*...\nF9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23  .####@####....##\n23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23  ###....####@####\nE8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23 23 E8 EE E9*end_highlight*  ....*begin_highlight*####@####...*end_highlight*\n*begin_highlight*F9 23 23 23 23 40 23 23 23 23 *end_highlight*E8 EE E9 F9 23 23  *begin_highlight*.####@####*end_highlight*....##\n23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40  ##@####....####@\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9  ....####@####...\nF9 *begin_highlight*23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23*end_highlight*  .*begin_highlight*####@####....##*end_highlight*\n*begin_highlight*23 23 40 23 23 23 23 *end_highlight*E8 EE E9 F9 23 23 23 23 40  *begin_highlight*##@####*end_highlight*....####@\n23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23  ####....####@###\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9  ....####@####...\nF9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 *begin_highlight*23 23*end_highlight*  .####@####....*begin_highlight*##*end_highlight*\n*begin_highlight*23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40*end_highlight*  *begin_highlight*##@####....####@*end_highlight*\n*begin_highlight*23 23 23 23 *end_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23  *begin_highlight*####*end_highlight*....####@###\nF9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23  .####@####....##\n23 23 40 23 23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40*end_highlight*  ##@####....*begin_highlight*####@*end_highlight*\n*begin_highlight*23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23*end_highlight*  *begin_highlight*####....####@###*end_highlight*\n*begin_highlight*23 *end_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE  *begin_highlight*#*end_highlight*....####@####..\n23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40  ##@####....####@\n23 23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23*end_highlight*  ####....*begin_highlight*####@###*end_highlight*\n*begin_highlight*23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23 *end_highlight*E8 EE  *begin_highlight*#....####@####*end_highlight*..\nE9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23  ..####@####....#\n\n...",
                        "tags": [
                            "cybergate",
                            "843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2"
                        ]
                    },
                    "id": "5883562783178752-e3df8c66cef961b7ddcb0d21a4d1eabc-843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2-1617025081",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/intelligence/hunting_notifications/5883562783178752-e3df8c66cef961b7ddcb0d21a4d1eabc-843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2-1617025081"
                    },
                    "type": "hunting_notification"
                }
            ],
            "links": {
                "next": "https://www.virustotal.com/api/v3/users/akrupnik_panw/hunting_notifications?cursor=CsYBChEKBGRhdGUSCQjHo_q-0NXvAhKsAWoRc352aXJ1c3RvdGFsY2xvdWRylgELEhNIdW50aW5nTm90aWZpY2F0aW9uIn01ODgzNTYyNzgzMTc4NzUyLWUzZGY4YzY2Y2VmOTYxYjdkZGNiMGQyMWE0ZDFlYWJjLTg0M2JkZDhmNzg0M2ZkMWY5Y2U0ODg2NjZkZDZjZjg4ZTc5YzZiMDk4ZTljOWFhZGE5NmFmMWQ4MDJhYWI3ZTItMTYxNzAyNTA4MQwYACAB&limit=1",
                "self": "https://www.virustotal.com/api/v3/users/akrupnik_panw/hunting_notifications?limit=1"
            },
            "meta": {
                "count": 200,
                "cursor": "CsYBChEKBGRhdGUSCQjHo_q-0NXvAhKsAWoRc352aXJ1c3RvdGFsY2xvdWRylgELEhNIdW50aW5nTm90aWZpY2F0aW9uIn01ODgzNTYyNzgzMTc4NzUyLWUzZGY4YzY2Y2VmOTYxYjdkZGNiMGQyMWE0ZDFlYWJjLTg0M2JkZDhmNzg0M2ZkMWY5Y2U0ODg2NjZkZDZjZjg4ZTc5YzZiMDk4ZTljOWFhZGE5NmFmMWQ4MDJhYWI3ZTItMTYxNzAyNTA4MQwYACAB"
            }
        }
    }
}
```

#### Human Readable Output

>### Notifications found:
>|id|
>|---|
>| 5883562783178752-e3df8c66cef961b7ddcb0d21a4d1eabc-843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2-1617025081 |


### vt-private-livehunt-notifications-files-list
***
Retrieve file objects for VT Hunting Livehunt notifications.


#### Base Command

`vt-private-livehunt-notifications-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | String to search within the hunting notification tags. | Optional | 
| cursor | Continuation cursor. | Optional | 
| limit | Maximum number of notifications to retrieve. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntFiles.meta.count | Number | Total file's count. | 
| VirusTotal.LiveHuntFiles.meta.cursor | String | Cursor of the call | 
| VirusTotal.LiveHuntFiles.data.attributes.type_description | String | describes the file type. | 
| VirusTotal.LiveHuntFiles.data.attributes.tlsh | String | Trend Micro's TLSH hash | 
| VirusTotal.LiveHuntFiles.data.attributes.vhash | String | in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | 
| VirusTotal.LiveHuntFiles.data.attributes.exiftool | String | exiftool is a program for extracting Exif metadata from different file formats. Metadata shown may vary depending on the file type, and given the nature of Exif metadata, some fields may appear or not. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.file_type | String | TrID is a utility designed to identify file types from their binary signatures. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.probability | Number | probability of file format identification \(given as percentage\). | 
| VirusTotal.LiveHuntFiles.data.attributes.creation_date | Number | extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.LiveHuntFiles.data.attributes.names | String | all file names associated with the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_tag | String | tag representing the file type. Can be used in vt-private-intelligence-search | 
| VirusTotal.LiveHuntFiles.data.attributes.times_submitted | Number | number of times the file has been posted to VirusTotal. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.size | Number | file size in bytes. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_extension | String | specifies file extension. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_submission_date | Number | most recent date the file was posted to VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.downloadable | Boolean | true if the file can be downloaded, false otherwise. \(use vt-private-file-download to download the file\) | 
| VirusTotal.LiveHuntFiles.data.attributes.sha256 | String | SHA-256 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.tags | String | The file's tags. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_date | Number | most recent scan date. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.unique_sources | Number | indicates from how many different sources the file has been posted from. | 
| VirusTotal.LiveHuntFiles.data.attributes.first_submission_date | Number | date when the file was first seen in VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.ssdeep | String | SSDeep of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.md5 | String | MD5 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.sha1 | String | SHA-1 if the file | 
| VirusTotal.LiveHuntFiles.data.attributes.magic | String | magic identifier of this app in hex format. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.raw_md5 | String | MD5 of the file's icon. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.dhash | Date | The dhash of the file's icon | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.type-unsupported | Number | number of AV engines that don't support that type of file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.confirmed-timeout | Number | number of AV engines that reach a timeout when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.failure | Number | number of AV engines that fail when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.LiveHuntFiles.data.attributes.meaningful_name | String | the most interesting name out of all file's names. | 
| VirusTotal.LiveHuntFiles.data.type | String | Type of the entry \(file\) | 
| VirusTotal.LiveHuntFiles.data.id | String | file ID | 
| VirusTotal.LiveHuntFiles.data.links.self | String | link to the file | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_id | String | The notification ID the file is connected to | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_key | String | The notification's source key | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_tags | String | notification tags. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_name | String | matched rule's ruleset name. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_country | String | The notification's source country of the notification | 
| VirusTotal.LiveHuntFiles.data.context_attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_snippet | String | The notification snippet ID | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_id | Date | VirusTotal's ruleset ID. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_date | Number | The notification date in epch. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.LiveHuntFiles.links.self | String | Link to the current apge | 
| VirusTotal.LiveHuntFiles.links.next | String | Link to the next page | 


#### Command Example
```!vt-private-livehunt-notifications-files-list limit=1```

#### Context Example
```json
{
    "VirusTotal": {
        "LiveHuntFiles": {
            "data": [
                {
                    "attributes": {
                        "authentihash": "c97af7168729300235d61fbc405dcc587db11c2596628f514fa2f0a90e74e194",
                        "bytehero_info": "Trojan.Malware.Obscu.Gen.007",
                        "capabilities_tags": [],
                        "creation_date": 708992537,
                        "crowdsourced_yara_results": [
                            {
                                "author": "Kevin Breen <kevin@techanarchy.net>",
                                "description": "Detects CyberGate RAT",
                                "rule_name": "RAT_CyberGate",
                                "ruleset_id": "0004c6f3bf",
                                "ruleset_name": "gen_rats_malwareconfig",
                                "source": "https://github.com/Neo23x0/signature-base"
                            }
                        ],
                        "downloadable": true,
                        "exiftool": {
                            "CodeSize": "45568",
                            "EntryPoint": "0xbbf0",
                            "FileType": "Win32 EXE",
                            "FileTypeExtension": "exe",
                            "ImageFileCharacteristics": "Executable, No line numbers, No symbols, Bytes reversed lo, 32-bit, Bytes reversed hi",
                            "ImageVersion": "0.0",
                            "InitializedDataSize": "235520",
                            "LinkerVersion": "2.25",
                            "MIMEType": "application/octet-stream",
                            "MachineType": "Intel 386 or later, and compatibles",
                            "OSVersion": "4.0",
                            "PEType": "PE32",
                            "Subsystem": "Windows GUI",
                            "SubsystemVersion": "4.0",
                            "TimeStamp": "1992:06:19 22:22:17+00:00",
                            "UninitializedDataSize": "0"
                        },
                        "first_submission_date": 1525234132,
                        "last_analysis_date": 1617025081,
                        "last_analysis_stats": {
                            "confirmed-timeout": 0,
                            "failure": 0,
                            "harmless": 0,
                            "malicious": 64,
                            "suspicious": 0,
                            "timeout": 0,
                            "type-unsupported": 5,
                            "undetected": 6
                        },
                        "last_modification_date": 1617032450,
                        "last_submission_date": 1525234132,
                        "magic": "PE32 executable for MS Windows (GUI) Intel 80386 32-bit",
                        "md5": "be8e1ffca139bcd0513eb9a10e3bcab2",
                        "meaningful_name": "Warface Repair Assistent.exe",
                        "names": [
                            "Warface Repair Assistent.exe"
                        ],
                        "reputation": 0,
                        "sha1": "671e3938fd88a17e7e16045411a678406b751003",
                        "sha256": "843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2",
                        "size": 282112,
                        "ssdeep": "6144:vxJsGLnmpoxDNT/xQphU+jrlgzfuzt91C9NDyWId98HhqbxtHGZA:5JsGap4h/xQp6+tqOYy9zo0T",
                        "tags": [
                            "peexe"
                        ],
                        "times_submitted": 1,
                        "tlsh": "T1B754029AB5C1E673C2244EFC5D2981D4B959BD333E3B1897B4ED2F0C897E1829A1C643",
                        "total_votes": {
                            "harmless": 0,
                            "malicious": 0
                        },
                        "trid": [
                            {
                                "file_type": "Win32 Executable (generic)",
                                "probability": 35.7
                            },
                            {
                                "file_type": "Win16/32 Executable Delphi generic",
                                "probability": 16.4
                            },
                            {
                                "file_type": "OS/2 Executable (generic)",
                                "probability": 16
                            },
                            {
                                "file_type": "Generic Win/DOS Executable",
                                "probability": 15.8
                            },
                            {
                                "file_type": "DOS Executable Generic",
                                "probability": 15.8
                            }
                        ],
                        "type_description": "Win32 EXE",
                        "type_extension": "exe",
                        "type_tag": "peexe",
                        "unique_sources": 1,
                        "vhash": "0250866d1c0d5c05156570c3z12z127z2035z13z1fz"
                    },
                    "context_attributes": {
                        "match_in_subfile": false,
                        "notification_date": 1617025254,
                        "notification_id": "5883562783178752-e3df8c66cef961b7ddcb0d21a4d1eabc-843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2-1617025081",
                        "notification_snippet": "23 23 20 23 23 23 23 40 23 23 23 23 F0 DD D1 D1  ## ####@####....\nD9 CE 23 23 23 23 40 23 23 23 23 8A 8A 8A 85 *begin_highlight*23*end_highlight*  ..####@####....*begin_highlight*#*end_highlight*\n*begin_highlight*23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23*end_highlight*  *begin_highlight*###@####....####*end_highlight*\n*begin_highlight*40 23 23 23 23 *end_highlight*88 23 23 23 23 40 23 23 23 23 DF  *begin_highlight*@####*end_highlight*.####@####.\nF9 E9 9C EF F5 EF E8 F9 F1 FD 9C EF F9 EE 7D 9C  ..............}.\nFA F3 EE F1 FD E8 FD F8 F3 92 *begin_highlight*23 23 23 23 40 23*end_highlight*  ..........*begin_highlight*####@#*end_highlight*\n*begin_highlight*23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23*end_highlight*  *begin_highlight*###....####@####*end_highlight*\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 FA FD F0  ....####@####...\nFA F3 EE F1 FD E8 FD F8 F3 92 23 23 23 23 40 23  ..........####@#\n23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23 23*end_highlight*  ###....*begin_highlight*####@####*end_highlight*\n*begin_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23 23 *end_highlight*FA FD F0  *begin_highlight*....####@####*end_highlight*...\nEF F9 23 23 23 23 40 23 23 23 23 20 23 23 23 23  ..####@#### ####\n23 23 23 23 20 23 23 23 23 40 23 23 23 23 20 23  #### ####@#### #\n23 23 23 40 23 23 23 23 8F 8C *begin_highlight*23 23 23 23 40 23*end_highlight*  ###@####..*begin_highlight*####@#*end_highlight*\n*begin_highlight*23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23*end_highlight*  *begin_highlight*###....####@####*end_highlight*\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9  ....####@####...\n23 23 23 40 23 23 23 23 8F 8C 23 23 23 23 40 23  ###@####..####@#\n23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23 23*end_highlight*  ###....*begin_highlight*####@####*end_highlight*\n*begin_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23 23 *end_highlight*E8 EE E9  *begin_highlight*....####@####*end_highlight*...\nF9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23  .####@####....##\n23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23  ###....####@####\nE8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23 23 E8 EE E9*end_highlight*  ....*begin_highlight*####@####...*end_highlight*\n*begin_highlight*F9 23 23 23 23 40 23 23 23 23 *end_highlight*E8 EE E9 F9 23 23  *begin_highlight*.####@####*end_highlight*....##\n23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40  ##@####....####@\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9  ....####@####...\nF9 *begin_highlight*23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23*end_highlight*  .*begin_highlight*####@####....##*end_highlight*\n*begin_highlight*23 23 40 23 23 23 23 *end_highlight*E8 EE E9 F9 23 23 23 23 40  *begin_highlight*##@####*end_highlight*....####@\n23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23  ####....####@###\nE8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9  ....####@####...\nF9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 *begin_highlight*23 23*end_highlight*  .####@####....*begin_highlight*##*end_highlight*\n*begin_highlight*23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40*end_highlight*  *begin_highlight*##@####....####@*end_highlight*\n*begin_highlight*23 23 23 23 *end_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23  *begin_highlight*####*end_highlight*....####@###\nF9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23  .####@####....##\n23 23 40 23 23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40*end_highlight*  ##@####....*begin_highlight*####@*end_highlight*\n*begin_highlight*23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23*end_highlight*  *begin_highlight*####....####@###*end_highlight*\n*begin_highlight*23 *end_highlight*E8 EE E9 F9 23 23 23 23 40 23 23 23 23 E8 EE  *begin_highlight*#*end_highlight*....####@####..\n23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40  ##@####....####@\n23 23 23 23 E8 EE E9 F9 *begin_highlight*23 23 23 23 40 23 23 23*end_highlight*  ####....*begin_highlight*####@###*end_highlight*\n*begin_highlight*23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23 *end_highlight*E8 EE  *begin_highlight*#....####@####*end_highlight*..\nE9 F9 23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23  ..####@####....#\n\n...",
                        "notification_source_country": null,
                        "notification_source_key": null,
                        "notification_tags": [
                            "cybergate",
                            "843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2"
                        ],
                        "rule_name": "CyberGate",
                        "rule_tags": [],
                        "ruleset_id": "5883562783178752",
                        "ruleset_name": "CyberGate"
                    },
                    "id": "843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/files/843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2"
                    },
                    "type": "file"
                }
            ],
            "links": {
                "next": "https://www.virustotal.com/api/v3/users/akrupnik_panw/hunting_notification_files?cursor=CsYBChEKBGRhdGUSCQjHo_q-0NXvAhKsAWoRc352aXJ1c3RvdGFsY2xvdWRylgELEhNIdW50aW5nTm90aWZpY2F0aW9uIn01ODgzNTYyNzgzMTc4NzUyLWUzZGY4YzY2Y2VmOTYxYjdkZGNiMGQyMWE0ZDFlYWJjLTg0M2JkZDhmNzg0M2ZkMWY5Y2U0ODg2NjZkZDZjZjg4ZTc5YzZiMDk4ZTljOWFhZGE5NmFmMWQ4MDJhYWI3ZTItMTYxNzAyNTA4MQwYACAB&limit=1",
                "self": "https://www.virustotal.com/api/v3/users/akrupnik_panw/hunting_notification_files?limit=1"
            },
            "meta": {
                "count": 200,
                "cursor": "CsYBChEKBGRhdGUSCQjHo_q-0NXvAhKsAWoRc352aXJ1c3RvdGFsY2xvdWRylgELEhNIdW50aW5nTm90aWZpY2F0aW9uIn01ODgzNTYyNzgzMTc4NzUyLWUzZGY4YzY2Y2VmOTYxYjdkZGNiMGQyMWE0ZDFlYWJjLTg0M2JkZDhmNzg0M2ZkMWY5Y2U0ODg2NjZkZDZjZjg4ZTc5YzZiMDk4ZTljOWFhZGE5NmFmMWQ4MDJhYWI3ZTItMTYxNzAyNTA4MQwYACAB"
            }
        }
    }
}
```

#### Human Readable Output

>### Notifications file listed:
>|id|meaningful_name|last_analysis_stats|
>|---|---|---|
>| 843bdd8f7843fd1f9ce488666dd6cf88e79c6b098e9c9aada96af1d802aab7e2 | Warface Repair Assistent.exe | harmless: 0<br/>type-unsupported: 5<br/>suspicious: 0<br/>confirmed-timeout: 0<br/>timeout: 0<br/>failure: 0<br/>malicious: 64<br/>undetected: 6 |


### vt-private-livehunt-notifications-files-get-by-hash
***
Retrieve file objects for VT Hunting Livehunt notifications.


#### Base Command

`vt-private-livehunt-notifications-files-get-by-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Hashes to search within VirusTotal. Will search only hashes and will ignore any other value. | Required | 
| cursor | Continuation cursor. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntFiles.meta.count | Number | Total file's count. | 
| VirusTotal.LiveHuntFiles.meta.cursor | String | Cursor of the call | 
| VirusTotal.LiveHuntFiles.data.attributes.type_description | String | describes the file type. | 
| VirusTotal.LiveHuntFiles.data.attributes.tlsh | String | Trend Micro's TLSH hash | 
| VirusTotal.LiveHuntFiles.data.attributes.vhash | String | in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | 
| VirusTotal.LiveHuntFiles.data.attributes.exiftool | String | exiftool is a program for extracting Exif metadata from different file formats. Metadata shown may vary depending on the file type, and given the nature of Exif metadata, some fields may appear or not. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.file_type | String | TrID is a utility designed to identify file types from their binary signatures. | 
| VirusTotal.LiveHuntFiles.data.attributes.trid.probability | Number | probability of file format identification \(given as percentage\). | 
| VirusTotal.LiveHuntFiles.data.attributes.creation_date | Number | extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.LiveHuntFiles.data.attributes.names | String | all file names associated with the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_tag | String | tag representing the file type. Can be used in vt-private-intelligence-search | 
| VirusTotal.LiveHuntFiles.data.attributes.times_submitted | Number | number of times the file has been posted to VirusTotal. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.LiveHuntFiles.data.attributes.size | Number | file size in bytes. | 
| VirusTotal.LiveHuntFiles.data.attributes.type_extension | String | specifies file extension. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_submission_date | Number | most recent date the file was posted to VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.downloadable | Boolean | true if the file can be downloaded, false otherwise. \(use vt-private-file-download to download the file\) | 
| VirusTotal.LiveHuntFiles.data.attributes.sha256 | String | SHA-256 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.tags | String | The file's tags. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_date | Number | most recent scan date. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.unique_sources | Number | indicates from how many different sources the file has been posted from. | 
| VirusTotal.LiveHuntFiles.data.attributes.first_submission_date | Number | date when the file was first seen in VirusTotal. UTC timestamp. | 
| VirusTotal.LiveHuntFiles.data.attributes.ssdeep | String | SSDeep of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.md5 | String | MD5 of the file. | 
| VirusTotal.LiveHuntFiles.data.attributes.sha1 | String | SHA-1 if the file | 
| VirusTotal.LiveHuntFiles.data.attributes.magic | String | magic identifier of this app in hex format. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.raw_md5 | String | MD5 of the file's icon. | 
| VirusTotal.LiveHuntFiles.data.attributes.main_icon.dhash | Date | The dhash of the file's icon | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.type-unsupported | Number | number of AV engines that don't support that type of file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.confirmed-timeout | Number | number of AV engines that reach a timeout when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.failure | Number | number of AV engines that fail when analysing that file. | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.LiveHuntFiles.data.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.LiveHuntFiles.data.attributes.meaningful_name | String | the most interesting name out of all file's names. | 
| VirusTotal.LiveHuntFiles.data.type | String | Type of the entry \(file\) | 
| VirusTotal.LiveHuntFiles.data.id | String | file ID | 
| VirusTotal.LiveHuntFiles.data.links.self | String | link to the file | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_id | String | The notification ID the file is connected to | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_key | String | The notification's source key | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_tags | String | notification tags. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_name | String | matched rule's ruleset name. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_source_country | String | The notification's source country of the notification | 
| VirusTotal.LiveHuntFiles.data.context_attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_snippet | String | The notification snippet ID | 
| VirusTotal.LiveHuntFiles.data.context_attributes.ruleset_id | Date | VirusTotal's ruleset ID. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.notification_date | Number | The notification date in epch. | 
| VirusTotal.LiveHuntFiles.data.context_attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.LiveHuntFiles.links.self | String | Link to the current apge | 
| VirusTotal.LiveHuntFiles.links.next | String | Link to the next page | 


#### Command Example
```!vt-private-livehunt-notifications-files-get-by-hash hash=389647cfa6f2ffd56601f6f18f69e6874d2068486d1c72d19fc5f2a2571eda79```

#### Human Readable Output
>### Notifications file listed:
>|id|meaningful_name|last_analysis_stats|
>|---|---|---|
>| 389647cfa6f2ffd56601f6f18f69e6874d2068486d1c72d19fc5f2a2571eda79 | /tmp/eml_attach_for_scan/c1726acd63066eeabfb9af65d1e7c3ba.file | harmless: 0<br>type-unsupported: 12<br>suspicious: 0<br>confirmed-timeout: 0<br>timeout: 1<br>failure: 1<br>malicious: 0<br>undetected: 59 |


### vt-private-livehunt-rule-list-files
***
Get a VT Hunting Livehunt ruleset by hunting notification files relationship.


#### Base Command

`vt-private-livehunt-rule-list-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule identifier. Can be retrieved from the vt-private-livehunt-rules-list command. | Required | 
| cursor | Continuation cursor. | Optional | 
| limit | Maximum number of notifications to retrieve. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.LiveHuntFiles.id | String | ID of the file | 
| VirusTotal.LiveHuntFiles.type | String | Type of the entry \(file\) | 


#### Command Example
```!vt-private-livehunt-rule-list-files id=6393327418376192```

#### Human Readable Output
>### Files found by rule 6393327418376192
>|context_attributes|id|type|
>|---|---|---|
>| notification_id: 6393327418376192-9d90aa797c1c16ea7afac7368c53cc0b-389647cfa6f2ffd56601f6f18f69e6874d2068486d1c72d19fc5f2a2571eda79-1617876439<br>notification_source_key: 9d712fef<br>notification_tags: new_file_from_china,<br>389647cfa6f2ffd56601f6f18f69e6874d2068486d1c72d19fc5f2a2571eda79,<br>chinese_files<br>ruleset_name: Chinese Files<br>notification_source_country: CN<br>rule_name: new_file_from_china<br>notification_snippet: <br>ruleset_id: 6393327418376192<br>rule_tags: <br>notification_date: 1617880045<br>match_in_subfile: false | 389647cfa6f2ffd56601f6f18f69e6874d2068486d1c72d19fc5f2a2571eda79 | file |


### vt-private-retrohunt-jobs-list
***
Get a VT Hunting Livehunt ruleset by hunting notification files relationship.


#### Base Command

`vt-private-retrohunt-jobs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Return the jobs matching the given criteria only. | Optional | 
| cursor | Continuation cursor. | Optional | 
| limit | Maximum number jobs to retrieve. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJob.attributes.status | String | can be either "starting", "running", "aborting", "aborted" or "finished". | 
| VirusTotal.RetroHuntJob.attributes.finish_date | Number | date when the Retrohunt job finished | 
| VirusTotal.RetroHuntJob.attributes.rules | String | The ruleset in the job | 
| VirusTotal.RetroHuntJob.attributes.num_matches_outside_time_range | Number | Matches outside time range | 
| VirusTotal.RetroHuntJob.attributes.scanned_bytes | Date | Total scanned bytes | 
| VirusTotal.RetroHuntJob.attributes.time_range.start | Number | Start of job's time range | 
| VirusTotal.RetroHuntJob.attributes.time_range.end | Number | End of job's time range | 
| VirusTotal.RetroHuntJob.attributes.num_matches | Number | Number of matches. | 
| VirusTotal.RetroHuntJob.attributes.progress | Number | The progress in percentage | 
| VirusTotal.RetroHuntJob.attributes.corpus | String | Corpus of the job \(main/goodware\) | 
| VirusTotal.RetroHuntJob.attributes.creation_date | Number | Job's creation date as UTC timestamp. | 
| VirusTotal.RetroHuntJob.attributes.start_date | Number | The start date of the job in epch. | 
| VirusTotal.RetroHuntJob.type | String | Type of the entry \(retrohunt_job\) | 
| VirusTotal.RetroHuntJob.id | String | ID of the retro job. | 
| VirusTotal.RetroHuntJob.links.self | String | Link to the entry | 


#### Command Example
```!vt-private-retrohunt-jobs-list limit=1```

#### Context Example
```json
    {"VirusTotal": {
        "RetroHuntJob": {
            "attributes": {
                "corpus": "goodware",
                "creation_date": 1617056777,
                "num_matches": 0,
                "num_matches_outside_time_range": 0,
                "progress": 0,
                "rules": "rule foobar { strings: $ = \"foobar\" condition: all of them }",
                "scanned_bytes": 0,
                "status": "starting",
                "time_range": {
                    "end": 1617056776,
                    "start": 1616797576
                }
            },
            "id": "akrupnik_panw-1617056777",
            "links": {
                "self": "https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/akrupnik_panw-1617056777"
            },
            "type": "retrohunt_job"
        }
    }
}
```

#### Human Readable Output

>### Retrohunt jobs listed:
>|id|corpus|status|rules|
>|---|---|---|---|
>| akrupnik_panw-1617056777 | goodware | starting | rule foobar { strings: $ = "foobar" condition: all of them } |


### vt-private-retrohunt-jobs-get-by-id
***
Retrieve a retrohunt job.


#### Base Command

`vt-private-retrohunt-jobs-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Job identifier. Can be acquired from vt-private-retrohunt-jobs-list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJob.attributes.status | String | can be either "starting", "running", "aborting", "aborted" or "finished". | 
| VirusTotal.RetroHuntJob.attributes.finish_date | Number | date when the Retrohunt job finished | 
| VirusTotal.RetroHuntJob.attributes.rules | String | The ruleset in the job | 
| VirusTotal.RetroHuntJob.attributes.num_matches_outside_time_range | Number | Matches outside time range | 
| VirusTotal.RetroHuntJob.attributes.scanned_bytes | Date | Total scanned bytes | 
| VirusTotal.RetroHuntJob.attributes.time_range.start | Number | Start of job's time range | 
| VirusTotal.RetroHuntJob.attributes.time_range.end | Number | End of job's time range | 
| VirusTotal.RetroHuntJob.attributes.num_matches | Number | Number of matches. | 
| VirusTotal.RetroHuntJob.attributes.progress | Number | The progress in percentage | 
| VirusTotal.RetroHuntJob.attributes.corpus | String | Corpus of the job \(main/goodware\) | 
| VirusTotal.RetroHuntJob.attributes.creation_date | Number | Job's creation date as UTC timestamp. | 
| VirusTotal.RetroHuntJob.attributes.start_date | Number | The start date of the job in epch. | 
| VirusTotal.RetroHuntJob.type | String | Type of the entry \(retrohunt_job\) | 
| VirusTotal.RetroHuntJob.id | String | ID of the retro job. | 
| VirusTotal.RetroHuntJob.links.self | String | Link to the entry | 


#### Command Example
```!vt-private-retrohunt-jobs-get-by-id id=akrupnik_panw-1615822819```

#### Context Example
```json
{
    "VirusTotal": {
        "RetroHuntJob": {
            "attributes": {
                "corpus": "goodware",
                "creation_date": 1615822819,
                "finish_date": 1615822869,
                "num_matches": 0,
                "num_matches_outside_time_range": 556,
                "progress": 100,
                "rules": "rule foobar { strings: $ = \"foobar\" condition: all of them }",
                "scanned_bytes": 146897923532,
                "start_date": 1615822824,
                "status": "finished",
                "time_range": {
                    "end": 1615822818,
                    "start": 1615563618
                }
            },
            "id": "akrupnik_panw-1615822819",
            "links": {
                "self": "https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/akrupnik_panw-1615822819"
            },
            "type": "retrohunt_job"
        }
    }
}
```

#### Human Readable Output

>### Retrohunt job: akrupnik_panw-1615822819
>|attributes|corpus|creation_date|finish_date|id|links|num_matches|num_matches_outside_time_range|progress|rules|scanned_bytes|start_date|status|time_range|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| status: finished<br/>finish_date: 1615822869<br/>rules: rule foobar { strings: $ = "foobar" condition: all of them }<br/>num_matches_outside_time_range: 556<br/>scanned_bytes: 146897923532<br/>time_range: {"start": 1615563618, "end": 1615822818}<br/>num_matches: 0<br/>progress: 100.0<br/>corpus: goodware<br/>creation_date: 1615822819<br/>start_date: 1615822824 | goodware | 1615822819 | 1615822869 | akrupnik_panw-1615822819 | self: https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/akrupnik_panw-1615822819 | 0 | 556 | 100.0 | rule foobar { strings: $ = "foobar" condition: all of them } | 146897923532 | 1615822824 | finished | start: 1615563618<br/>end: 1615822818 | retrohunt_job |


### vt-private-retrohunt-jobs-get-matching-files
***
Retrieve matches for a retrohunt job matching file relationship.


#### Base Command

`vt-private-retrohunt-jobs-get-matching-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Job identifier. Can be acquired from vt-private-retrohunt-jobs-list. | Required | 
| extended_data | Whether to return full data information. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJobFiles.attributes.type_description | String | describes the file type. | 
| VirusTotal.RetroHuntJobFiles.attributes.tlsh | String | Trend Micro's TLSH hash | 
| VirusTotal.RetroHuntJobFiles.attributes.vhash | String | in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | 
| VirusTotal.RetroHuntJobFiles.attributes.exiftool | String | exiftool is a program for extracting Exif metadata from different file formats. Metadata shown may vary depending on the file type, and given the nature of Exif metadata, some fields may appear or not. | 
| VirusTotal.RetroHuntJobFiles.attributes.trid.file_type | String | TrID is a utility designed to identify file types from their binary signatures. | 
| VirusTotal.RetroHuntJobFiles.attributes.trid.probability | Number | probability of file format identification \(given as percentage\). | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.description | String | matched rule description. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.author | String | rule author. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.ruleset_id | String | VirusTotal's ruleset ID. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.ruleset_name | String | matched rule's ruleset name. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.match_in_subfile | Boolean | whether the match was in a subfile or not. | 
| VirusTotal.RetroHuntJobFiles.attributes.crowdsourced_yara_results.source | String | ruleset source. | 
| VirusTotal.RetroHuntJobFiles.attributes.creation_date | Number | extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.names | String | all file names associated with the file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_modification_date | Number | date when the object itself was last modified. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.type_tag | String | tag representing the file type. Can be used in vt-private-intelligence-search | 
| VirusTotal.RetroHuntJobFiles.attributes.capabilities_tags | String | list of representative tags related to the file's capabilities | 
| VirusTotal.RetroHuntJobFiles.attributes.total_votes.harmless | Number | number of positive votes. | 
| VirusTotal.RetroHuntJobFiles.attributes.total_votes.malicious | Number | number of negative votes. | 
| VirusTotal.RetroHuntJobFiles.attributes.size | Number | file size in bytes. | 
| VirusTotal.RetroHuntJobFiles.attributes.authentihash | String | sha256 hash used by Microsoft to verify that the relevant sections of a PE image file have not been altered. This specific type of hash is used by Microsoft AppLocker. | 
| VirusTotal.RetroHuntJobFiles.attributes.times_submitted | Number | number of times the file has been posted to VirusTotal. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_submission_date | Number | most recent date the file was posted to VirusTotal. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.meaningful_name | String | the most interesting name out of all file's names. | 
| VirusTotal.RetroHuntJobFiles.attributes.downloadable | Boolean | true if the file can be downloaded, false otherwise. | 
| VirusTotal.RetroHuntJobFiles.attributes.sha256 | String | SHA-256 of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.type_extension | String | specifies file extension. | 
| VirusTotal.RetroHuntJobFiles.attributes.tags | String | list of representative tags related to the file's capabilities | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_date | Number | Most recent scan date. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.unique_sources | Number | indicates from how many different sources the file has been posted from. | 
| VirusTotal.RetroHuntJobFiles.attributes.first_submission_date | Number | date when the file was first seen in VirusTotal. UTC timestamp. | 
| VirusTotal.RetroHuntJobFiles.attributes.sha1 | String | SHA-1 of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.magic | String | magic identifier of this app in hex format. | 
| VirusTotal.RetroHuntJobFiles.attributes.ssdeep | String | SSDeep of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.md5 | String | MD5 of the file | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.harmless | Number | number of reports saying that is harmless. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.type-unsupported | Number | number of AV engines that don't support that type of file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.suspicious | Number | number of reports saying that is suspicious. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.confirmed-timeout | Number | number of AV engines that reach a timeout when analysing that file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.timeout | Number | number of timeouts when analysing this URL/file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.failure | Number | number of AV engines that fail when analysing that file. | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.malicious | Number | number of reports saying that is malicious | 
| VirusTotal.RetroHuntJobFiles.attributes.last_analysis_stats.undetected | Number | number of reports saying that is undetected. | 
| VirusTotal.RetroHuntJobFiles.attributes.reputation | Number | file's score calculated from all votes posted by the VirusTotal community. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.high | Number | number of matched high severity rules. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.medium | Number | number of matched medium severity rules. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.critical | Number | number of matched critical severity rules. | 
| VirusTotal.RetroHuntJobFiles.attributes.sigma_analysis_stats.low | Number | number of matched low severity rules. | 
| VirusTotal.RetroHuntJobFiles.type | String | The type of the entry \(file\) | 
| VirusTotal.RetroHuntJobFiles.id | String | ID of file | 
| VirusTotal.RetroHuntJobFiles.links.self | String | A link to the entry | 
| VirusTotal.RetroHuntJobFiles.context_attributes.rule_name | String | contains the names of all rules in the ruleset. | 
| VirusTotal.RetroHuntJobFiles.context_attributes.match_in_subfile | Boolean | whether the match was in a subfile or not. | 


#### Command Example
```!vt-private-retrohunt-jobs-get-matching-files id=akrupnik_panw-1610969096```

#### Human Readable Output
>### Files matching id "akrupnik_panw-1610969096"
>|sha256|popular_threat_classification|reputation|
>|---|---|---|
>| cf13811bb818c02149ad1745c95a11ef8b122801953aee463343627a2ffaa29a |  | 0 |


### vt-private-retrohunt-jobs-create
***
Create a new retrohunt job.


#### Base Command

`vt-private-retrohunt-jobs-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rules | The rules to create. | Required | 
| corpus | The "main" corpus is a composition of files sent to VirusTotal during the last few months. The "goodware" corpus is a random selection of ~1.000.000 files from the NSRL that are not detected by any antivirus engine. Possible values are: main, goodware. Default is main. | Optional | 
| notification_email | A comma-separated list of emails to notify. | Optional | 
| start_time | Fetch retrohunt jobs from given time. Can be epoch time, a date or time range (3 days, 1 year). | Optional | 
| end_time | Fetch retrohunt jobs to given time. Can be epoch time, a date or time range. If start_time supplied and not end_time, end_time will be the current time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.RetroHuntJob.attributes.status | String | can be either "starting", "running", "aborting", "aborted" or "finished". | 
| VirusTotal.RetroHuntJob.attributes.finish_date | Number | date when the Retrohunt job finished | 
| VirusTotal.RetroHuntJob.attributes.rules | String | The ruleset in the job | 
| VirusTotal.RetroHuntJob.attributes.num_matches_outside_time_range | Number | Matches outside time range | 
| VirusTotal.RetroHuntJob.attributes.scanned_bytes | Date | Total scanned bytes | 
| VirusTotal.RetroHuntJob.attributes.time_range.start | Number | Start of job's time range | 
| VirusTotal.RetroHuntJob.attributes.time_range.end | Number | End of job's time range | 
| VirusTotal.RetroHuntJob.attributes.num_matches | Number | Number of matches. | 
| VirusTotal.RetroHuntJob.attributes.progress | Number | The progress in percentage | 
| VirusTotal.RetroHuntJob.attributes.corpus | String | Corpus of the job \(main/goodware\) | 
| VirusTotal.RetroHuntJob.attributes.creation_date | Number | Job's creation date as UTC timestamp. | 
| VirusTotal.RetroHuntJob.attributes.start_date | Number | The start date of the job in epch. | 
| VirusTotal.RetroHuntJob.type | String | Type of the entry \(retrohunt_job\) | 
| VirusTotal.RetroHuntJob.id | String | ID of the retro job. | 
| VirusTotal.RetroHuntJob.links.self | String | Link to the entry | 


#### Command Example
```!vt-private-retrohunt-jobs-create rules=`rule foobar { strings: $ = "foobar" condition: all of them }` corpus=goodware start_time="3 days"```

#### Context Example
```json
{
    "VirusTotal": {
        "RetroHuntJob": {
            "attributes": {
                "corpus": "goodware",
                "creation_date": 1617056777,
                "num_matches": 0,
                "num_matches_outside_time_range": 0,
                "progress": 0,
                "rules": "rule foobar { strings: $ = \"foobar\" condition: all of them }",
                "scanned_bytes": 0,
                "status": "starting",
                "time_range": {
                    "end": 1617056776,
                    "start": 1616797576
                }
            },
            "id": "akrupnik_panw-1617056777",
            "links": {
                "self": "https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/akrupnik_panw-1617056777"
            },
            "type": "retrohunt_job"
        }
    }
}
```

#### Human Readable Output

>### Retrohunt job has been successfully created
>|id|corpus|status|rules|
>|---|---|---|---|
>| akrupnik_panw-1617056777 | goodware | starting | rule foobar { strings: $ = "foobar" condition: all of them } |


### vt-private-quota-limits-list
***
Retrieve user's API usage.


#### Base Command

`vt-private-quota-limits-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID or API key. If not supplied, will use the API Key configured in the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.QuotaLimits.cases_creation_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.cases_creation_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_vtdiff_creation_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_uploaded_files.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_uploaded_files.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_uploaded_bytes.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_uploaded_bytes.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_storage_files.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_storage_files.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.api_requests_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_downloads_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_hourly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.api_requests_hourly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_hourly.group.allowed | Number | hourly api requests group's quota limit | 
| VirusTotal.QuotaLimits.api_requests_hourly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_hourly.user.allowed | Date | hourly api requests user's quota limit | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.group.allowed | Number | intelligence_hunting_rules group's quota limit | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_hunting_rules.user.allowed | Number | intelligence_hunting_rules user's quota limit | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_graphs_private.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_daily.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.api_requests_daily.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_daily.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.api_requests_daily.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.api_requests_daily.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.monitor_storage_bytes.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.monitor_storage_bytes.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_retrohunt_jobs_monthly.user.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.group.inherited_from | String | group from which the quota is inherited. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.group.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.group.allowed | Number | quota limit. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.user.group.used | Number | quota has been used. | 
| VirusTotal.QuotaLimits.intelligence_searches_monthly.user.allowed | Number | quota limit. | 


#### Command Example
```!vt-private-quota-limits-list```

#### Context Example
```json
{
    "VirusTotal": {
        "QuotaLimits": {
            "api_requests_daily": {
                "group": {
                    "allowed": 30000000,
                    "inherited_from": "palo_alto_networks",
                    "used": 535676
                },
                "user": {
                    "allowed": 1000,
                    "used": 74
                }
            },
            "api_requests_hourly": {
                "group": {
                    "allowed": 1800000,
                    "inherited_from": "palo_alto_networks",
                    "used": 8712
                },
                "user": {
                    "allowed": 60000000000,
                    "used": 12
                }
            },
            "api_requests_monthly": {
                "group": {
                    "allowed": 1000000000,
                    "inherited_from": "palo_alto_networks",
                    "used": 13551234
                },
                "user": {
                    "allowed": 1000000000,
                    "used": 2564
                }
            },
            "cases_creation_monthly": {
                "user": {
                    "allowed": 20,
                    "used": 0
                }
            },
            "intelligence_downloads_monthly": {
                "group": {
                    "allowed": 100000,
                    "inherited_from": "palo_alto_networks",
                    "used": 6214
                },
                "user": {
                    "allowed": 0,
                    "used": 5
                }
            },
            "intelligence_graphs_private": {
                "group": {
                    "allowed": 0,
                    "inherited_from": "palo_alto_networks",
                    "used": 0
                },
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            },
            "intelligence_hunting_rules": {
                "group": {
                    "allowed": 25,
                    "inherited_from": "palo_alto_networks",
                    "used": 1829
                },
                "user": {
                    "allowed": 0,
                    "used": 3
                }
            },
            "intelligence_retrohunt_jobs_monthly": {
                "group": {
                    "allowed": 300,
                    "inherited_from": "palo_alto_networks",
                    "used": 163
                },
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            },
            "intelligence_searches_monthly": {
                "group": {
                    "allowed": 100000,
                    "inherited_from": "palo_alto_networks",
                    "used": 16328
                },
                "user": {
                    "allowed": 0,
                    "used": 12
                }
            },
            "intelligence_vtdiff_creation_monthly": {
                "group": {
                    "allowed": 100000000,
                    "inherited_from": "palo_alto_networks",
                    "used": 23
                },
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            },
            "monitor_storage_bytes": {
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            },
            "monitor_storage_files": {
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            },
            "monitor_uploaded_bytes": {
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            },
            "monitor_uploaded_files": {
                "user": {
                    "allowed": 0,
                    "used": 0
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Monthly quota data: More data can be found in the Context.
>|api_requests_monthly|cases_creation_monthly|intelligence_downloads_monthly|intelligence_retrohunt_jobs_monthly|intelligence_searches_monthly|intelligence_vtdiff_creation_monthly|
>|---|---|---|---|---|---|
>| group: {"inherited_from": "palo_alto_networks", "used": 13551234, "allowed": 1000000000}<br/>user: {"used": 2564, "allowed": 1000000000} | user: {"used": 0, "allowed": 20} | group: {"inherited_from": "palo_alto_networks", "used": 6214, "allowed": 100000}<br/>user: {"used": 5, "allowed": 0} | group: {"inherited_from": "palo_alto_networks", "used": 163, "allowed": 300}<br/>user: {"used": 0, "allowed": 0} | group: {"inherited_from": "palo_alto_networks", "used": 16328, "allowed": 100000}<br/>user: {"used": 12, "allowed": 0} | group: {"inherited_from": "palo_alto_networks", "used": 23, "allowed": 100000000}<br/>user: {"used": 0, "allowed": 0} |
