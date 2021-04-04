Use the Palo Alto Networks Wildfire integration to automatically identify unknown threats and stop attackers in their tracks by performing malware dynamic analysis.

## Palo Alto Networks WildFire v2 Playbooks

1. WildFire - Detonate File
2. Detonate URL - WildFire v2.1

##Use Cases

1. Send a File sample to WildFire.
2. Upload a file hosted on a website to WildFire.
3. Submit a webpage to WildFire.
4. Get a report regarding the sent samples using file hash.
5. Get sample file from WildFire.
6. Get verdict regarding multiple hashes(up to 500) using the wildfire-get-verdicts command.

## Configure WildFire v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WildFire v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server base URL (e.g. https://192.168.0.1/publicapi) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Return warning entry for unsupported file types | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Retrieve results for a file hash using WildFire


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash to check. | Optional | 
| md5 | MD5 hash to check. | Optional | 
| sha256 | SHA256 hash to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | string | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| InfoFile.EntryID | Unknown | The EntryID of the report file. | 
| InfoFile.Extension | string | Extension of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | Size of the report file. | 
| InfoFile.Type | string | The report file type. | 


#### Command Example
```!file file=735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f",
            "Score": 1,
            "Type": "hash",
            "Vendor": "WildFire"
        },
        {
            "Indicator": "735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f",
            "Score": 1,
            "Type": "file",
            "Vendor": "WildFire"
        }
    ],
    "WildFire": {
        "Report": {
            "SHA256": "735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f",
            "Status": "Success"
        }
    }
}
```

#### Human Readable Output

>### WildFire File Report
>|FileType|MD5|SHA256|Size|Status|
>|---|---|---|---|---|
>| JScript | ccdb1053f56a2d297906746bc720ef2a | 735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f | 12 | Completed |


### wildfire-upload
***
Uploads a file to WildFire for analysis.


#### Base Command

`wildfire-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | ID of the entry containing the file to upload. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 hash of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| WildFire.Report.FileType | string | The submission type. | 
| WildFire.Report.Size | number | The size of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 


#### Command Example
```!wildfire-upload upload=294@675f238c-ed75-4cae-83d2-02b6b820168b```

#### Context Example
```json
{
    "WildFire": {
        "Report": {
            "FileType": "Jscript for WSH",
            "MD5": "ccdb1053f56a2d297906746bc720ef2a",
            "SHA256": "735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f",
            "Size": "12",
            "Status": "Pending",
            "URL": null
        }
    }
}
```

#### Human Readable Output

>### WildFire Upload File
>|FileType|MD5|SHA256|Size|Status|
>|---|---|---|---|---|
>| Jscript for WSH | ccdb1053f56a2d297906746bc720ef2a | 735bcfa56930d824f9091188eeaac2a1d68bc64a21f90a49c5ff836ed6ea723f | 12 | Pending |


### wildfire-upload-file-url
***
Uploads the URL of a remote file to WildFire for analysis.


#### Base Command

`wildfire-upload-file-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | URL of the remote file to upload. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 hash of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.URL | string | URL of the submission. | 


#### Command Example
```!wildfire-upload-file-url upload=http://www.software995.net/bin/pdf995s.exe```

#### Context Example
```json
{
    "WildFire": {
        "Report": {
            "FileType": "PE32 executable",
            "MD5": "891b77e864c88881ea98be867e74177f",
            "SHA256": "555092d994b8838b8fa18d59df4fdb26289d146e071e831fcf0c6851b5fb04f8",
            "Size": "5958304",
            "Status": "Pending",
            "URL": "http://www.software995.net/bin/pdf995s.exe"
        }
    }
}
```

#### Human Readable Output

>### WildFire Upload File URL
>|FileType|MD5|SHA256|Size|Status|URL|
>|---|---|---|---|---|---|
>| PE32 executable | 891b77e864c88881ea98be867e74177f | 555092d994b8838b8fa18d59df4fdb26289d146e071e831fcf0c6851b5fb04f8 | 5958304 | Pending | http://www.software995.net/bin/pdf995s.exe |


### wildfire-report
***
Retrieves results for a file hash using WildFire.


#### Base Command

`wildfire-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | MD5 hash to check. | Optional | 
| sha256 | SHA256 hash to check. | Optional | 
| hash | Deprecated - Use the sha256 argument instead. | Optional | 
| format | Request a structured report (XML or PDF). Possible values are: xml, pdf. Default is pdf. | Optional | 
| verbose | Receive extended information from WildFire. Possible values are: true, false. Default is false. | Optional | 
| url | Retrieves results for a URL using WildFire. The report format is in JSON. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Report.Status | string | The status of the submissiom. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.Network.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.Network.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.Network.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.Network.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.Network.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.Network.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 


#### Command Example
```!wildfire-report url=https://www.demisto.com```

#### Context Example
```json
{
    "WildFire": {
        "Report": {
            "Status": "Success",
            "URL": "https://www.demisto.com",
            "da_packages": [
                "package--5420f34e-5eb9-499b-c6a3-5f34abd73232",
                "package--36e99aa9-abc1-468a-7035-e43756ce9250"
            ],
            "detection_reasons": [
                {
                    "artifacts": [
                        {
                            "entity_id": "malware-instance--4c958c0e-0cd1-4749-c887-a0372acfe8fc",
                            "package": "package--903b10d4-d6b9-4a99-f09f-576dd0b36d51",
                            "type": "artifact-ref"
                        }
                    ],
                    "description": "Known benign by a trusted source",
                    "name": "trusted_list",
                    "type": "detection-reason",
                    "verdict": "benign"
                }
            ],
            "iocs": [],
            "maec_packages": [
                {
                    "id": "package--5420f34e-5eb9-499b-c6a3-5f34abd73232",
                    "maec_objects": [
                        {
                            "analysis_metadata": [
                                {
                                    "analysis_type": "combination",
                                    "conclusion": "unknown",
                                    "description": "Automated analysis inside a web browser",
                                    "end_time": "2021-03-10T16:59:49.910871563Z",
                                    "is_automated": true,
                                    "start_time": "2021-03-10T16:58:50.614000082Z",
                                    "tool_refs": [
                                        "382"
                                    ]
                                }
                            ],
                            "id": "malware-instance--df22b5b9-22b5-490a-9535-4f5ba7663455",
                            "instance_object_refs": [
                                "381"
                            ],
                            "type": "malware-instance"
                        }
                    ],
                    "observable_objects": {
                        "0": {
                            "type": "ipv4-addr",
                            "value": "1.1.1.1"
                        },
                        "1": {
                            "resolves_to_refs": [
                                "0"
                            ],
                            "type": "domain-name",
                            "value": "www.demisto.com"
                        },
                        "10": {
                            "global_variable_refs": [
                                "7"
                            ],
                            "is_main": true,
                            "observed_alert_refs": [
                                "8"
                            ],
                            "request_ref": "6",
                            "type": "x-wf-url-page-frame",
                            "url_ref": "9"
                        },
                        "100": {
                            "artifact_ref": "99",
                            "type": "x-wf-url-resource"
                        },
                        "148": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 86,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "56006cc15834ed33e0e22a69039a4c8f61502a536d05986e455680456686ca52"
                            },
                            "type": "artifact"
                        },
                        "149": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:32.855999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/apps/pan/public/singlePageReactModel?pageId=/content/pan/en_US/cortex/xsoar"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "148",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-credentials": "true",
                                        "cache-control": "max-age=0, no-cache, no-store",
                                        "content-encoding": "gzip",
                                        "content-length": "91",
                                        "content-type": "application/javascript;charset=iso-8859-1",
                                        "date": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "expires": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "pragma": "no-cache",
                                        "server": "Apache",
                                        "server-timing": "edge; dur=1, origin; dur=50, cdn-cache; desc=MISS",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-content-type-options": "nosniff",
                                        "x-frame-options": "SAMEORIGIN",
                                        "x-robots-tag": "noindex"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        }
                        
                    },
                    "schema_version": "5.0",
                    "type": "package"
                },
                {
                    "id": "package--36e99aa9-abc1-468a-7035-e43756ce9250",
                    "maec_objects": [
                        {
                            "analysis_metadata": [
                                {
                                    "analysis_type": "combined",
                                    "conclusion": "unknown",
                                    "description": "Automated phishing analysis inside a custom web browser",
                                    "end_time": "2021-03-10T01:20:37.126363Z",
                                    "is_automated": true,
                                    "tool_refs": [
                                        "1"
                                    ]
                                }
                            ],
                            "id": "malware-instance--b9bcff27-b691-4040-55bb-a3620f2231ce",
                            "instance_object_refs": [
                                "0"
                            ],
                            "type": "malware-instance"
                        }
                    ],
                    "observable_objects": {
                        "0": {
                            "type": "url",
                            "value": "https://www.demisto.com"
                        },
                        "1": {
                            "name": "HtmlUnit v2.35",
                            "type": "software",
                            "vendor": "SourceForge Media, LLC dba Slashdot Media"
                        }
                    },
                    "schema_version": "5.0",
                    "type": "package"
                },
                {
                    "id": "package--903b10d4-d6b9-4a99-f09f-576dd0b36d51",
                    "maec_objects": [
                        {
                            "analysis_metadata": [
                                {
                                    "analysis_type": "static",
                                    "conclusion": "unknown",
                                    "description": "Automated static URL analysis",
                                    "end_time": "2021-03-10T15:43:25.604059Z",
                                    "is_automated": true
                                },
                                {
                                    "analysis_type": "static",
                                    "conclusion": "benign",
                                    "is_automated": true
                                }
                            ],
                            "dynamic_features": {
                                "behavior_refs": [
                                    "behavior--77aa4e6e-d9d1-46d6-1fc7-86ec1b24cd84"
                                ]
                            },
                            "id": "malware-instance--4c958c0e-0cd1-4749-c887-a0372acfe8fc",
                            "instance_object_refs": [
                                "0"
                            ],
                            "type": "malware-instance"
                        },
                        {
                            "description": "Known benign by a trusted source",
                            "id": "behavior--77aa4e6e-d9d1-46d6-1fc7-86ec1b24cd84",
                            "name": "trusted_list",
                            "type": "behavior"
                        }
                    ],
                    "observable_objects": {
                        "0": {
                            "type": "url",
                            "value": "https://www.demisto.com"
                        }
                    },
                    "schema_version": "5.0",
                    "type": "package"
                }
            ],
            "primary_malware_instances": {
                "package--36e99aa9-abc1-468a-7035-e43756ce9250": "malware-instance--b9bcff27-b691-4040-55bb-a3620f2231ce",
                "package--5420f34e-5eb9-499b-c6a3-5f34abd73232": "malware-instance--df22b5b9-22b5-490a-9535-4f5ba7663455",
                "package--903b10d4-d6b9-4a99-f09f-576dd0b36d51": "malware-instance--4c958c0e-0cd1-4749-c887-a0372acfe8fc"
            },
            "sa_package": "package--903b10d4-d6b9-4a99-f09f-576dd0b36d51",
            "schema_version": "1.0",
            "sha256": "288cd35401e334a2defc0b428d709f58d4ea28c8e9c6e47fdba88da2d6bc88a7",
            "type": "wf-report",
            "verdict": "benign"
        }
    }
}
```

#### Human Readable Output

>### Wildfire URL report for https://www.demisto.com
>|sha256|type|verdict|
>|---|---|---|
>| 288cd35401e334a2defc0b428d709f58d4ea28c8e9c6e47fdba88da2d6bc88a7 | wf-report | benign |


### wildfire-get-verdict
***
Returns a verdict for a hash.


#### Base Command

`wildfire-get-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Hash to get the verdict for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Verdicts.MD5 | string | MD5 hash of the file. | 
| WildFire.Verdicts.SHA256 | string | SHA256 hash of the file. | 
| WildFire.Verdicts.Verdict | number | Verdict of the file. | 
| WildFire.Verdicts.VerdictDescription | string | Description of the file verdict. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 


#### Command Example
```!wildfire-get-verdict hash=afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc",
            "Score": 3,
            "Type": "hash",
            "Vendor": "WildFire"
        },
        {
            "Indicator": "afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc",
            "Score": 3,
            "Type": "file",
            "Vendor": "WildFire"
        }
    ],
    "WildFire": {
        "Verdicts": {
            "MD5": "0e4e3c2d84a9bc726a50b3c91346fbb1",
            "SHA256": "afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc",
            "Verdict": "1",
            "VerdictDescription": "malware"
        }
    }
}
```

#### Human Readable Output

>### WildFire Verdict
>|MD5|SHA256|Verdict|VerdictDescription|
>|---|---|---|---|
>| 0e4e3c2d84a9bc726a50b3c91346fbb1 | afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc | 1 | malware |


### wildfire-get-verdicts
***
Returns a verdict regarding multiple hashes, stored in a TXT file or given as list.


#### Base Command

`wildfire-get-verdicts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | EntryID of the text file that contains multiple hashes. Limit is 500 hashes. | Optional | 
| hash_list | A list of hashes to get verdicts for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Verdicts.MD5 | string | MD5 hash of the file. | 
| WildFire.Verdicts.SHA256 | string | SHA256 hash of the file. | 
| WildFire.Verdicts.Verdict | number | Verdict of the file. | 
| WildFire.Verdicts.VerdictDescription | string | Description of the file verdict. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 


#### Command Example
``` ```

#### Human Readable Output



### wildfire-upload-url
***
Uploads a URL of a webpage to WildFire for analysis.


#### Base Command

`wildfire-upload-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| upload | URL to submit to WildFire. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WildFire.Report.MD5 | string | MD5 of the submission. | 
| WildFire.Report.SHA256 | string | SHA256 of the submission. | 
| WildFire.Report.Status | string | The status of the submission. | 
| WildFire.Report.URL | string | URL of the submission. | 


#### Command Example
```!wildfire-upload-url upload=https://www.demisto.com```

#### Context Example
```json
{
    "WildFire": {
        "Report": {
            "MD5": "67632f32e6af123aa8ffd1fe8765a783",
            "SHA256": "c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb",
            "Status": "Pending",
            "URL": "https://www.demisto.com"
        }
    }
}
```

#### Human Readable Output

>### WildFire Upload URL
>|MD5|SHA256|Status|URL|
>|---|---|---|---|
>| 67632f32e6af123aa8ffd1fe8765a783 | c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb | Pending | https://www.demisto.com |


### wildfire-get-sample
***
Retrieves a sample.


#### Base Command

`wildfire-get-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | MD5 hash of the sample. | Optional | 
| sha256 | SHA256 hash of the sample. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!wildfire-get-sample sha256=afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc```

#### Context Example
```json
{
    "File": {
        "EntryID": "318@675f238c-ed75-4cae-83d2-02b6b820168b",
        "Extension": "xls",
        "Info": "application/vnd.ms-excel",
        "MD5": "0e4e3c2d84a9bc726a50b3c91346fbb1",
        "Name": "afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc.xls",
        "SHA1": "52eb16966670b76f8728fda28c48bc6c49f20e07",
        "SHA256": "afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc",
        "SHA512": "4634c1e7ae6526527167682a8b5f0aa6d0e5a17c7bd3b8ee6ac81b9f306577e543a89afbcbfe2a5a6178e7225fe35aa01a49ab814dc5d4917b2312787bb3c165",
        "SSDeep": "1536:zeeeqopd5TCMWNo/QXo3VjgvRjha2wnLW8W:odpCMW6QIFAf8W",
        "Size": 86016,
        "Type": "Composite Document File V2 Document, Little Endian, Os: Windows, Version 5.2, Code page: 936, Name of Creating Application: Microsoft Excel, Create Time/Date: Tue Dec 17 01:32:42 1996, Last Saved Time/Date: Mon May 11 03:39:41 2009, Security: 0"
    }
}
```

#### Human Readable Output



### wildfire-get-url-webartifacts
***
Get web artifacts for a URL webpage. An empty tgz will be returned, no matter what the verdict, or even if the URL is malformed.


#### Base Command

`wildfire-get-url-webartifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL of the webpage. | Required | 
| types | Whether to download as screenshots or as downloadable files. if not specified, both will be downloaded. Possible values are: download_files, screenshot. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | Unknown | The EntryID of the webartifacts. | 
| InfoFile.Extension | string | Extension of the webartifacts. | 
| InfoFile.Name | string | Name of the webartifacts. | 
| InfoFile.Info | string | Details of the webartifacts. | 
| InfoFile.Size | number | Size of the webartifacts. | 
| InfoFile.Type | string | The webartifacts file type. | 

#### Command Example
```!wildfire-get-url-webartifacts url=http://royalmail-login.com```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "326@675f238c-ed75-4cae-83d2-02b6b820168b",
        "Extension": "tgz",
        "Info": "tgz",
        "Name": "http://royalmail-login.com_webartifacts.tgz",
        "Size": 619775,
        "Type": "gzip compressed data, original size modulo 2^32 1828864"
    }
}
```

#### Human Readable Output


