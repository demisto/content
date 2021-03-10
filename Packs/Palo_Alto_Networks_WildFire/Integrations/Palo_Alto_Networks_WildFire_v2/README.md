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
                            "value": "34.120.160.120"
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
                        "101": {
                            "type": "ipv4-addr",
                            "value": "34.216.140.121"
                        },
                        "102": {
                            "resolves_to_refs": [
                                "101"
                            ],
                            "type": "domain-name",
                            "value": "dpm.demdex.net"
                        },
                        "103": {
                            "dst_ref": "102",
                            "end": "2021-03-10T16:58:31.207Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Content-Type": "application/x-www-form-urlencoded",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/id?d_visid_ver=5.1.1&d_fieldgroup=MC&d_rtbd=json&d_ver=2&d_verify=1&d_orgid=9A531C8B532965080A490D4D%40AdobeOrg&d_nsid=0&ts=1615395510267"
                                },
                                "x-wf-http-response-ext": {
                                    "response_code": 302,
                                    "response_header": {
                                        "Access-Control-Allow-Credentials": "true",
                                        "Access-Control-Allow-Origin": "https://www.paloaltonetworks.com",
                                        "Cache-Control": "no-cache,no-store,must-revalidate,max-age=0,proxy-revalidate,no-transform,private",
                                        "Connection": "keep-alive",
                                        "Content-Length": "0",
                                        "Expires": "Thu, 01 Jan 1970 00:00:00 GMT",
                                        "Location": "https://dpm.demdex.net/id/rd?d_visid_ver=5.1.1&d_fieldgroup=MC&d_rtbd=json&d_ver=2&d_verify=1&d_orgid=9A531C8B532965080A490D4D%40AdobeOrg&d_nsid=0&ts=1615395510267",
                                        "P3P": "policyref=\"/w3c/p3p.xml\", CP=\"NOI NID CURa ADMa DEVa PSAa PSDa OUR SAMa BUS PUR COM NAV INT\"",
                                        "Pragma": "no-cache",
                                        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                                        "Vary": "Origin",
                                        "X-TID": "riDpPuYaSgU="
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "104": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 33462,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "d6b423c91328eec9c218dd8b21ae1e676987d574e5432411a32806e5dd2bde32"
                            },
                            "type": "artifact"
                        },
                        "105": {
                            "dst_ref": "72",
                            "end": "2021-03-10T16:58:31.213999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/extensions/EPbde2f7ca14e540399dcc1f8208860b7b/AppMeasurement.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "104",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "no-cache",
                                        "content-encoding": "gzip",
                                        "content-length": "12184",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:30 GMT",
                                        "etag": "\"f259ee6445c19c2ce3c64a1b117a4f35:1597270192.577101\"",
                                        "expires": "Wed, 10 Mar 2021 17:58:30 GMT",
                                        "last-modified": "Wed, 12 Aug 2020 22:09:52 GMT",
                                        "server": "AkamaiNetStorage",
                                        "status": "200",
                                        "timing-allow-origin": "*",
                                        "vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "106": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 3303,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "0486530f1e98818865754a08e1b5442ac5a6a36a6bf6042e3b3338a532e998d2"
                            },
                            "type": "artifact"
                        },
                        "107": {
                            "dst_ref": "72",
                            "end": "2021-03-10T16:58:31.214999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/extensions/EPbde2f7ca14e540399dcc1f8208860b7b/AppMeasurement_Module_ActivityMap.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "106",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "no-cache",
                                        "content-encoding": "gzip",
                                        "content-length": "1594",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:30 GMT",
                                        "etag": "\"5dedcda2c8a6c3a51fd419d306427010:1597270192.857753\"",
                                        "expires": "Wed, 10 Mar 2021 17:58:30 GMT",
                                        "last-modified": "Wed, 12 Aug 2020 22:09:52 GMT",
                                        "server": "AkamaiNetStorage",
                                        "status": "200",
                                        "timing-allow-origin": "*",
                                        "vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "108": {
                            "type": "ipv4-addr",
                            "value": "142.250.138.139"
                        },
                        "109": {
                            "resolves_to_refs": [
                                "108"
                            ],
                            "type": "domain-name",
                            "value": "www.google-analytics.com"
                        },
                        "11": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 232
                                }
                            },
                            "hashes": {
                                "SHA-256": "2ffeb7d574a98dd20c695ac29f2ea225f0ef25308151dbdc53c3d89fd2c2b41c"
                            },
                            "type": "artifact"
                        },
                        "110": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 47332,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "0f3be44690ae9914ae3e47b7752e1bdea316f09938e9094f99e0de19ccd8987a"
                            },
                            "type": "artifact"
                        },
                        "111": {
                            "dst_ref": "109",
                            "end": "2021-03-10T16:58:31.216Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/analytics.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "110",
                                    "response_code": 200,
                                    "response_header": {
                                        "age": "1393",
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "public, max-age=7200",
                                        "content-encoding": "gzip",
                                        "content-length": "18980",
                                        "content-type": "text/javascript",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:35:17 GMT",
                                        "expires": "Wed, 10 Mar 2021 18:35:17 GMT",
                                        "last-modified": "Fri, 05 Feb 2021 21:33:27 GMT",
                                        "server": "Golfe2",
                                        "status": "200",
                                        "strict-transport-security": "max-age=10886400; includeSubDomains; preload",
                                        "vary": "Accept-Encoding",
                                        "x-content-type-options": "nosniff"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "112": {
                            "type": "ipv4-addr",
                            "value": "199.232.8.157"
                        },
                        "113": {
                            "resolves_to_refs": [
                                "112"
                            ],
                            "type": "domain-name",
                            "value": "static.ads-twitter.com"
                        },
                        "114": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 5160,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "8247f4332667950989fe6bf790f87723343db2ec83d975503e9c5dc13a6eb5dc"
                            },
                            "type": "artifact"
                        },
                        "115": {
                            "dst_ref": "113",
                            "end": "2021-03-10T16:58:31.217Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/uwt.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "114",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "69973",
                                        "cache-control": "no-cache",
                                        "content-encoding": "gzip",
                                        "content-length": "1958",
                                        "content-type": "application/javascript; charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:30 GMT",
                                        "etag": "\"a4cc3f907681b24a3efd540acd5d2996+gzip\"",
                                        "last-modified": "Fri, 04 Dec 2020 00:33:09 GMT",
                                        "p3p": "CP=\"CAO DSP LAW CURa ADMa DEVa TAIa PSAa PSDa IVAa IVDa OUR BUS IND UNI COM NAV INT\"",
                                        "status": "200",
                                        "vary": "Accept-Encoding,Host",
                                        "via": "1.1 varnish",
                                        "x-cache": "HIT",
                                        "x-served-by": "cache-dal21235-DAL",
                                        "x-timer": "S1615395511.919569,VS0,VE0"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "116": {
                            "type": "ipv4-addr",
                            "value": "172.217.9.168"
                        },
                        "117": {
                            "resolves_to_refs": [
                                "116"
                            ],
                            "type": "domain-name",
                            "value": "ssl.google-analytics.com"
                        },
                        "118": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 46274,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "1259ea99bd76596239bfd3102c679eb0a5052578dc526b0452f4d42f8bcdd45f"
                            },
                            "type": "artifact"
                        },
                        "119": {
                            "dst_ref": "117",
                            "end": "2021-03-10T16:58:31.217999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/ga.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "118",
                                    "response_code": 200,
                                    "response_header": {
                                        "age": "600",
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "public, max-age=7200",
                                        "content-encoding": "gzip",
                                        "content-length": "17168",
                                        "content-type": "text/javascript",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:48:30 GMT",
                                        "expires": "Wed, 10 Mar 2021 18:48:30 GMT",
                                        "last-modified": "Fri, 05 Feb 2021 21:33:27 GMT",
                                        "server": "Golfe2",
                                        "status": "200",
                                        "strict-transport-security": "max-age=10886400; includeSubDomains; preload",
                                        "vary": "Accept-Encoding",
                                        "x-content-type-options": "nosniff"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "12": {
                            "artifact_ref": "11",
                            "type": "x-wf-url-resource"
                        },
                        "120": {
                            "resolves_to_refs": [
                                "116"
                            ],
                            "type": "domain-name",
                            "value": "www.googletagmanager.com"
                        },
                        "121": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 100372,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "144ef03938418664edf87fe69d7ed3afc965c21310f2e837ddc8344ad3f3b697"
                            },
                            "type": "artifact"
                        },
                        "122": {
                            "dst_ref": "120",
                            "end": "2021-03-10T16:58:31.219Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/gtag/js?id=UA-146275556-9&l=dataLayer"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "121",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-headers": "Cache-Control",
                                        "access-control-allow-origin": "*",
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "private, max-age=900",
                                        "content-encoding": "br",
                                        "content-length": "39472",
                                        "content-type": "application/javascript; charset=UTF-8",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:58:30 GMT",
                                        "expires": "Wed, 10 Mar 2021 16:58:30 GMT",
                                        "last-modified": "Wed, 10 Mar 2021 15:00:00 GMT",
                                        "server": "Google Tag Manager",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000; includeSubDomains",
                                        "vary": "Accept-Encoding",
                                        "x-xss-protection": "0"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "123": {
                            "type": "ipv4-addr",
                            "value": "172.217.6.142"
                        },
                        "124": {
                            "resolves_to_refs": [
                                "123"
                            ],
                            "type": "domain-name",
                            "value": "www.youtube.com"
                        },
                        "125": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 810,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "a88cc7da1973bf847e3740685fc737b04d4bb5b5ab78c8158ac66adc3cd56391"
                            },
                            "type": "artifact"
                        },
                        "126": {
                            "dst_ref": "124",
                            "end": "2021-03-10T16:58:31.221999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/iframe_api"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "125",
                                    "response_code": 200,
                                    "response_header": {
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "private, max-age=0",
                                        "content-encoding": "br",
                                        "content-type": "text/javascript; charset=utf-8",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:58:31 GMT",
                                        "expires": "Wed, 10 Mar 2021 16:58:31 GMT",
                                        "p3p": "CP=\"This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=en for more info.\"",
                                        "server": "ESF",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "x-content-type-options": "nosniff",
                                        "x-frame-options": "SAMEORIGIN",
                                        "x-xss-protection": "0"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "127": {
                            "type": "ipv4-addr",
                            "value": "13.226.201.45"
                        },
                        "128": {
                            "resolves_to_refs": [
                                "127"
                            ],
                            "type": "domain-name",
                            "value": "scripts.demandbase.com"
                        },
                        "129": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 5451,
                                    "sniffed_mime_type": "text/x-c"
                                }
                            },
                            "hashes": {
                                "SHA-256": "c9c183c8efe02b849d685a1a9b5989159335f62e89d0510162efef636d90c84e"
                            },
                            "type": "artifact"
                        },
                        "13": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 879
                                }
                            },
                            "hashes": {
                                "SHA-256": "56e3b0fc03febbdef3a0513827daabe4290188114b2d2cea25ba17e307fa4323"
                            },
                            "type": "artifact"
                        },
                        "130": {
                            "dst_ref": "128",
                            "end": "2021-03-10T16:58:31.221999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/adobeanalytics/e78feef73ff94c88.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "129",
                                    "response_code": 200,
                                    "response_header": {
                                        "age": "19710",
                                        "content-encoding": "gzip",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 11:31:59 GMT",
                                        "etag": "W/\"2c4db711e40a8d2f0e54d9ff6d4a1c6a\"",
                                        "last-modified": "Thu, 11 Feb 2021 17:03:06 GMT",
                                        "server": "AmazonS3",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "via": "1.1 78487ffbca2380a1b0612e6718bb8f2f.cloudfront.net (CloudFront)",
                                        "x-amz-cf-id": "qXzafsLP4Jg9lB8uvcy_XFBksdMCoaixfJK4YO3tjnEGhW7G8WrWxw==",
                                        "x-amz-cf-pop": "DFW55-C2",
                                        "x-amz-version-id": "42._nTKlB0W0a7nUUVM5_0UTxFNlGqWt",
                                        "x-cache": "Hit from cloudfront"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "131": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1634,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "27f843f7aef36145251abbe79405508a0cf397d5073316afb68caf2f95f386b2"
                            },
                            "type": "artifact"
                        },
                        "132": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:31.940999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "same-origin",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/etc/clientlibs/pan-webworker.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "131",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "br",
                                        "content-length": "676",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:24 GMT",
                                        "etag": "\"662-5bd22a8959a9f-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:24 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:11:47 GMT",
                                        "server": "Akamai Resource Optimizer",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-akamai-http2-push": "1",
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
                        },
                        "133": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 217,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "46970ab9c3d09f08c2d4babe2a4bd7847b273cfa878ff0dd9173c980fbdd20d5"
                            },
                            "type": "artifact"
                        },
                        "134": {
                            "dst_ref": "102",
                            "end": "2021-03-10T16:58:32.408999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/id/rd?d_visid_ver=5.1.1&d_fieldgroup=MC&d_rtbd=json&d_ver=2&d_verify=1&d_orgid=9A531C8B532965080A490D4D%40AdobeOrg&d_nsid=0&ts=1615395510267"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "133",
                                    "response_code": 200,
                                    "response_header": {
                                        "Access-Control-Allow-Credentials": "true",
                                        "Access-Control-Allow-Origin": "https://www.paloaltonetworks.com",
                                        "Cache-Control": "no-cache,no-store,must-revalidate,max-age=0,proxy-revalidate,no-transform,private",
                                        "Connection": "keep-alive",
                                        "Content-Length": "217",
                                        "Content-Type": "application/json;charset=utf-8",
                                        "DCS": "dcs-prod-usw2-v078-036f4d9bb.edge-usw2.demdex.com 5.80.7.20210304103356 2ms (+1ms)",
                                        "Expires": "Thu, 01 Jan 1970 00:00:00 GMT",
                                        "P3P": "policyref=\"/w3c/p3p.xml\", CP=\"NOI NID CURa ADMa DEVa PSAa PSDa OUR SAMa BUS PUR COM NAV INT\"",
                                        "Pragma": "no-cache",
                                        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                                        "Vary": "Origin, Accept-Encoding, User-Agent",
                                        "X-TID": "dHE5sW96Sic="
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "135": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1414
                                }
                            },
                            "hashes": {
                                "SHA-256": "d1f69f0532d63639f510e1077aa6f382df656897806de91e89bb057713dc3888"
                            },
                            "type": "artifact"
                        },
                        "136": {
                            "artifact_ref": "135",
                            "type": "x-wf-url-resource"
                        },
                        "137": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 555
                                }
                            },
                            "hashes": {
                                "SHA-256": "5278dc56525cb8c18c26a93f5241b3715a98cb460dd1354d18037ac3708b1c43"
                            },
                            "type": "artifact"
                        },
                        "138": {
                            "artifact_ref": "137",
                            "type": "x-wf-url-resource"
                        },
                        "139": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 5858
                                }
                            },
                            "hashes": {
                                "SHA-256": "b494b03ef888c746b0cc22ec80693d9abda2cb433825f8307faba05bc93a192f"
                            },
                            "type": "artifact"
                        },
                        "14": {
                            "artifact_ref": "13",
                            "type": "x-wf-url-resource"
                        },
                        "140": {
                            "artifact_ref": "139",
                            "type": "x-wf-url-resource"
                        },
                        "141": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 50043,
                                    "sniffed_mime_type": "application/octet-stream"
                                }
                            },
                            "hashes": {
                                "SHA-256": "608b798fdf97f51a3f9d2e43beee8b6236465ba265b7f2920fecec1f39971713"
                            },
                            "type": "artifact"
                        },
                        "142": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:32.733Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "*/*",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36",
                                        "X-Requested-With": "XMLHttpRequest"
                                    },
                                    "request_method": "get",
                                    "request_value": "/_jcr_content/globals/cleanHeader.fullRenderer.html"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "141",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "public, max-age=900",
                                        "content-encoding": "gzip",
                                        "content-length": "7095",
                                        "content-type": "text/html; charset=UTF-8",
                                        "date": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "etag": "\"c37d-5bd22a603e6e5-gzip\"",
                                        "expires": "Wed, 10 Mar 2021 17:13:32 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:09:55 GMT",
                                        "server": "Apache",
                                        "server-timing": "cdn-cache; desc=MISS, edge; dur=22, origin; dur=36",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-akamai-transformed": "9 7096 0 pmb=mRUM,2",
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
                        },
                        "143": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 181
                                }
                            },
                            "hashes": {
                                "SHA-256": "ccefc80b5eb31d6768bbd0b424973acdea232ceba0b649e3d9aa306c5faeb80d"
                            },
                            "type": "artifact"
                        },
                        "144": {
                            "artifact_ref": "143",
                            "type": "x-wf-url-resource"
                        },
                        "145": {
                            "dst_ref": "117",
                            "end": "2021-03-10T16:58:32.838999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/r/__utm.gif?utmwv=5.7.2&utms=1&utmn=748248569&utmhn=www.paloaltonetworks.com&utmcs=UTF-8&utmsr=800x600&utmvp=1585x1200&utmsc=24-bit&utmul=en-us&utmje=0&utmfl=-&utmdt=Cortex%20XSOAR%20-%20Security%20Orchestration%2C%20Automation%20and%20Response%20(SOAR)%20-%20Palo%20Alto%20Networks&utmhid=1799938522&utmr=-&utmp=%2Fcortex%2Fxsoar&utmht=1615395512525&utmac=UA-494959-2&utmcc=__utma%3D85376408.544523977.1615395512.1615395512.1615395512.1%3B%2B__utmz%3D85376408.1615395512.1.1.utmcsr%3D(direct)%7Cutmccn%3D(direct)%7Cutmcmd%3D(none)%3B&utmjid=78474002&utmredir=1&utmu=qBAAAAAAAAAAAAAAAAABAAAE~"
                                },
                                "x-wf-http-response-ext": {
                                    "response_code": 302,
                                    "response_header": {
                                        "access-control-allow-origin": "*",
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "no-cache, no-store, must-revalidate",
                                        "content-length": "365",
                                        "content-type": "text/html; charset=UTF-8",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "expires": "Fri, 01 Jan 1990 00:00:00 GMT",
                                        "last-modified": "Sun, 17 May 1998 03:00:00 GMT",
                                        "location": "https://stats.g.doubleclick.net/r/collect?v=1&aip=1&t=dc&_r=3&tid=UA-494959-2&cid=544523977.1615395512&jid=78474002&_v=5.7.2&z=748248569",
                                        "pragma": "no-cache",
                                        "server": "Golfe2",
                                        "status": "302"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "146": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 0,
                                    "sniffed_mime_type": "application/x-empty"
                                }
                            },
                            "hashes": {
                                "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            },
                            "type": "artifact"
                        },
                        "147": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:32.841Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "*/*",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36",
                                        "X-Requested-With": "XMLHttpRequest"
                                    },
                                    "request_method": "get",
                                    "request_value": "/apps/public/tracking/trackView"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "146",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "max-age=0, no-cache, no-store",
                                        "content-length": "0",
                                        "date": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "expires": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "pragma": "no-cache",
                                        "server": "Apache",
                                        "server-timing": "edge; dur=1, origin; dur=37, cdn-cache; desc=MISS",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
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
                        },
                        "15": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 342
                                }
                            },
                            "hashes": {
                                "SHA-256": "48fe072600310a03817ce5ad8362c615b49cbdd17732d81c1555fff5ae0bcb99"
                            },
                            "type": "artifact"
                        },
                        "150": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 3756,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "dac8bfebb4b63724c5ec1c068f142999c44950ec55208499d1ef0408025eedd9"
                            },
                            "type": "artifact"
                        },
                        "151": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:32.858999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36",
                                        "X-Requested-With": "XMLHttpRequest"
                                    },
                                    "request_method": "get",
                                    "request_value": "/content/dam/pan/en_US/includes/jquery.auto-complete.min.js?_=1615395506999"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "150",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "gzip",
                                        "content-length": "1359",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "etag": "\"eac-5b634e2543dd4-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:32 GMT",
                                        "last-modified": "Fri, 11 Dec 2020 18:58:55 GMT",
                                        "server": "Apache",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
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
                        },
                        "152": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 172758,
                                    "sniffed_mime_type": "application/octet-stream"
                                }
                            },
                            "hashes": {
                                "SHA-256": "ad24442cdd47254b7b15a26660b7189c6ae73c9055649ef90a72a3f9d42d23b2"
                            },
                            "type": "artifact"
                        },
                        "153": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:32.861Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "application/json, text/javascript, */*; q=0.01",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36",
                                        "X-Requested-With": "XMLHttpRequest"
                                    },
                                    "request_method": "get",
                                    "request_value": "/etc/formsconfig/joblevelandrole.json"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "152",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=0, no-cache, no-store",
                                        "content-length": "178540",
                                        "content-type": "application/json",
                                        "date": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "etag": "\"2b96c-5bd22a62d8509\"",
                                        "expires": "Wed, 10 Mar 2021 16:58:32 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:09:58 GMT",
                                        "pragma": "no-cache",
                                        "server": "Apache",
                                        "server-timing": "edge; dur=1, origin; dur=44, cdn-cache; desc=MISS",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "x-frame-options": "SAMEORIGIN"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "154": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 108467,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "c2d0c281519e31954278ba8946fa818eaeb68051112d3b030b9af11062df26fb"
                            },
                            "type": "artifact"
                        },
                        "155": {
                            "dst_ref": "124",
                            "end": "2021-03-10T16:58:32.901Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/s/player/d91669a4/www-widgetapi.vflset/www-widgetapi.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "154",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "173580",
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "public, max-age=31536000",
                                        "content-encoding": "gzip",
                                        "content-length": "38484",
                                        "content-type": "text/javascript",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Mon, 08 Mar 2021 16:45:32 GMT",
                                        "expires": "Tue, 08 Mar 2022 16:45:32 GMT",
                                        "last-modified": "Mon, 08 Mar 2021 01:18:06 GMT",
                                        "server": "sffe",
                                        "status": "200",
                                        "vary": "Accept-Encoding, Origin",
                                        "x-content-type-options": "nosniff",
                                        "x-xss-protection": "0"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "156": {
                            "type": "ipv4-addr",
                            "value": "65.8.226.12"
                        },
                        "157": {
                            "resolves_to_refs": [
                                "156"
                            ],
                            "type": "domain-name",
                            "value": "api.company-target.com"
                        },
                        "158": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 3973,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "074a45a1a94067423254d0844a1b51bc9375d8f1f3e7769d528bc91c74dc060f"
                            },
                            "type": "artifact"
                        },
                        "159": {
                            "dst_ref": "157",
                            "end": "2021-03-10T16:58:32.904Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/api/v2/ip.json?auth=mTSWoP7tDDj1bmrfd7DoCwq1MAt3SukHko7rQP5o&callback=Dmdbase_CDC.callback"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "158",
                                    "response_code": 200,
                                    "response_header": {
                                        "api-version": "v2",
                                        "cache-control": "no-cache, no-store, max-age=0, must-revalidate",
                                        "content-encoding": "gzip",
                                        "content-type": "application/javascript;charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:33 GMT",
                                        "expires": "Tue, 09 Mar 2021 16:58:33 GMT",
                                        "identification-source": "CACHE",
                                        "pragma": "no-cache",
                                        "request-id": "87189f83-ebf1-4120-ae6d-4889cb3efb37",
                                        "server": "nginx",
                                        "status": "200",
                                        "vary": "Accept-Encoding, Origin",
                                        "via": "1.1 8475262a7d3b8601272ede312d08be5f.cloudfront.net (CloudFront)",
                                        "x-amz-cf-id": "bF04p2L_3BhX74kgoQ-iSI3GOq2OS-oK69973EdmefFu6xVeGXZ62A==",
                                        "x-amz-cf-pop": "DFW55-C3",
                                        "x-cache": "Miss from cloudfront"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "16": {
                            "artifact_ref": "15",
                            "type": "x-wf-url-resource"
                        },
                        "160": {
                            "resolves_to_refs": [
                                "85"
                            ],
                            "type": "domain-name",
                            "value": "static.matterport.com"
                        },
                        "161": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 2101083,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "db4475ff3816b2b4343c671b232c35acb9c6785a4e1424668e7cbf90cb98a5dc"
                            },
                            "type": "artifact"
                        },
                        "162": {
                            "dst_ref": "160",
                            "end": "2021-03-10T16:58:33.194999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/showcase/3.1.35.16-0-g5f6f72877/js/showcase.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "161",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "664658",
                                        "cache-control": "max-age=604800",
                                        "content-encoding": "gzip",
                                        "content-length": "555532",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:33 GMT",
                                        "etag": "\"166b936572c07246d138fb8db3961fa7\"",
                                        "last-modified": "Wed, 24 Feb 2021 00:17:21 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 18",
                                        "x-content-type-options": "nosniff",
                                        "x-served-by": "cache-bwi5135-BWI, cache-dal21226-DAL",
                                        "x-timer": "S1615395514.554414,VS0,VE0",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "163": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 5727,
                                    "sniffed_mime_type": "text/html"
                                }
                            },
                            "hashes": {
                                "SHA-256": "95f1d51ae65daf73df5f4a87b6368c8a4affc3b1eda8387423275403cce0987b"
                            },
                            "type": "artifact"
                        },
                        "164": {
                            "dst_ref": "160",
                            "end": "2021-03-10T16:58:33.194999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/showcase/3.1.35.16-0-g5f6f72877/js/browser-check.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "163",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "74639",
                                        "cache-control": "max-age=604800",
                                        "content-encoding": "gzip",
                                        "content-length": "1995",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:33 GMT",
                                        "etag": "\"9dd1c754e49c84c466f530738272f785\"",
                                        "last-modified": "Wed, 24 Feb 2021 00:17:21 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 1011",
                                        "x-content-type-options": "nosniff",
                                        "x-served-by": "cache-bwi5165-BWI, cache-dal21226-DAL",
                                        "x-timer": "S1615395513.192992,VS0,VE0",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "165": {
                            "type": "ipv4-addr",
                            "value": "34.227.41.189"
                        },
                        "166": {
                            "resolves_to_refs": [
                                "165"
                            ],
                            "type": "domain-name",
                            "value": "paloaltonetworks.d1.sc.omtrdc.net"
                        },
                        "167": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 2,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                            },
                            "type": "artifact"
                        },
                        "168": {
                            "dst_ref": "166",
                            "end": "2021-03-10T16:58:33.66Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Content-Type": "application/x-www-form-urlencoded",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/id?d_visid_ver=5.1.1&d_fieldgroup=A&mcorgid=9A531C8B532965080A490D4D%40AdobeOrg&mid=43662614647497207373238360663372119555&ts=1615395513189"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "167",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "no-cache, no-store, max-age=0, no-transform, private",
                                        "content-length": "2",
                                        "content-type": "application/x-javascript;charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:34 GMT",
                                        "p3p": "CP=\"This is not a P3P policy\"",
                                        "server": "jag",
                                        "status": "200",
                                        "vary": "Origin",
                                        "x-c": "main-1434.I637bed.M0-481",
                                        "x-content-type-options": "nosniff",
                                        "x-xss-protection": "1; mode=block",
                                        "xserver": "anedge-847dcdb7c8-z5ht5"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "169": {
                            "type": "ipv4-addr",
                            "value": "54.200.111.201"
                        },
                        "17": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 27
                                }
                            },
                            "hashes": {
                                "SHA-256": "ea2be42be351f4249cff7b0d50d07ed3a7130e56b45215e08a664d46bd1ad0af"
                            },
                            "type": "artifact"
                        },
                        "170": {
                            "resolves_to_refs": [
                                "169"
                            ],
                            "type": "domain-name",
                            "value": "paloaltonetworks.tt.omtrdc.net"
                        },
                        "171": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1838,
                                    "sniffed_mime_type": "text/html"
                                }
                            },
                            "hashes": {
                                "SHA-256": "2fef3a2eeca2cdc68293e1c295c2f9a4bfb09036bcdc310dd503a4c4afecec8e"
                            },
                            "type": "artifact"
                        },
                        "172": {
                            "dst_ref": "170",
                            "end": "2021-03-10T16:58:33.661Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/m2/paloaltonetworks/mbox/json?mbox=target-global-mbox&mboxSession=a5b62bd6203a47ab8a408f030c130ef4&mboxPC=&mboxPage=9779f1de31da45af9cb61aa118571e59&mboxRid=6eab3fdd48044e0a816cf27c10040cf7&mboxVersion=1.8.2&mboxCount=1&mboxTime=1615395511137&mboxHost=www.paloaltonetworks.com&mboxURL=https%3A%2F%2Fwww.paloaltonetworks.com%2Fcortex%2Fxsoar&mboxReferrer=&mboxXDomain=enabled&browserHeight=1200&browserWidth=1585&browserTimeOffset=0&screenHeight=600&screenWidth=800&colorDepth=24&devicePixelRatio=1&screenOrientation=landscape&webGLRenderer=Google%20SwiftShader&pageName=en_us%3Acortex%3Axsoar&pageChannel=cortex&companyDomain=IP%20not%20matched&profile.companyDomain=IP%20not%20matched&mboxMCSDID=38AEA3BE75F922FB-7D96130F94BD82B9&vst.trk=paloaltonetworks.d1.sc.omtrdc.net&mboxMCGVID=43662614647497207373238360663372119555&mboxAAMB=RKhpRz8krg2tLO6pguXWp5olkAcUniQYPHaMWWgdJ3xzPWQmdj0y&mboxMCGLH=9"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "171"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "173": {
                            "type": "ipv4-addr",
                            "value": "142.250.138.156"
                        },
                        "174": {
                            "resolves_to_refs": [
                                "173"
                            ],
                            "type": "domain-name",
                            "value": "stats.g.doubleclick.net"
                        },
                        "175": {
                            "dst_ref": "174",
                            "end": "2021-03-10T16:58:33.946Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/r/collect?v=1&aip=1&t=dc&_r=3&tid=UA-494959-2&cid=544523977.1615395512&jid=78474002&_v=5.7.2&z=748248569"
                                },
                                "x-wf-http-response-ext": {
                                    "response_code": 302,
                                    "response_header": {
                                        "access-control-allow-origin": "*",
                                        "alt-svc": "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"",
                                        "cache-control": "no-cache, no-store, must-revalidate",
                                        "content-length": "363",
                                        "content-type": "text/html; charset=UTF-8",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:58:34 GMT",
                                        "expires": "Fri, 01 Jan 1990 00:00:00 GMT",
                                        "last-modified": "Sun, 17 May 1998 03:00:00 GMT",
                                        "location": "https://www.google.com/ads/ga-audiences?v=1&aip=1&t=sr&_r=4&tid=UA-494959-2&cid=544523977.1615395512&jid=78474002&_v=5.7.2&z=748248569",
                                        "pragma": "no-cache",
                                        "server": "Golfe2",
                                        "status": "302",
                                        "strict-transport-security": "max-age=10886400; includeSubDomains; preload"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "176": {
                            "type": "ipv4-addr",
                            "value": "96.6.85.184"
                        },
                        "177": {
                            "resolves_to_refs": [
                                "176"
                            ],
                            "type": "domain-name",
                            "value": "munchkin.marketo.net"
                        },
                        "178": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1284,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "5cc2628039ee08964a5f46fb8abb1d5e1ec87e1200d12862ef1232bbfed7da55"
                            },
                            "type": "artifact"
                        },
                        "179": {
                            "dst_ref": "177",
                            "end": "2021-03-10T16:58:35.006Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/munchkin.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "178",
                                    "response_code": 200,
                                    "response_header": {
                                        "Accept-Ranges": "bytes",
                                        "Connection": "keep-alive",
                                        "Content-Encoding": "gzip",
                                        "Content-Length": "752",
                                        "Content-Type": "application/x-javascript",
                                        "Date": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "ETag": "\"a67ed8ce0a86706b9f73a86806ce5bd3:1596597060.25158\"",
                                        "Last-Modified": "Wed, 05 Aug 2020 03:11:00 GMT",
                                        "P3P": "policyref=\"http://www.marketo.com/w3c/p3p.xml\", CP=\"NOI DSP COR NID CURi OUR NOR\", policyref=\"http://www.marketo.com/w3c/p3p.xml\", CP=\"NOI DSP COR NID CURi OUR NOR\"",
                                        "Server": "AkamaiNetStorage",
                                        "Vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "18": {
                            "artifact_ref": "17",
                            "type": "x-wf-url-resource"
                        },
                        "180": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 648,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "028d966c68ffd8cc0bae085f6b1acfe37a3187d88b1e3adbabf3af74ba90d24f"
                            },
                            "type": "artifact"
                        },
                        "181": {
                            "dst_ref": "72",
                            "end": "2021-03-10T16:58:35.006999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/9273d4aedcd2/0d76ae0322d7/a5e8dc8a9ed9/RCc83bf1fcf63c42ab99b7a25acce52c39-source.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "180",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "max-age=3600",
                                        "content-encoding": "gzip",
                                        "content-length": "391",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "etag": "\"f3b35ff48ce18a058616e18a2efde92e:1614190927.245815\"",
                                        "expires": "Wed, 10 Mar 2021 17:58:36 GMT",
                                        "last-modified": "Wed, 24 Feb 2021 18:22:07 GMT",
                                        "server": "AkamaiNetStorage",
                                        "status": "200",
                                        "timing-allow-origin": "*",
                                        "vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "182": {
                            "type": "ipv4-addr",
                            "value": "23.38.181.40"
                        },
                        "183": {
                            "resolves_to_refs": [
                                "182"
                            ],
                            "type": "domain-name",
                            "value": "snap.licdn.com"
                        },
                        "184": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 4322,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "5f3b103a1268f862a5e432d607f8e5220dea9d301d13565b0ecded3ad9c25ab2"
                            },
                            "type": "artifact"
                        },
                        "185": {
                            "dst_ref": "183",
                            "end": "2021-03-10T16:58:35.006999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/li.lms-analytics/insight.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "184",
                                    "response_code": 200,
                                    "response_header": {
                                        "Accept-Ranges": "bytes",
                                        "Cache-Control": "max-age=54527",
                                        "Connection": "keep-alive",
                                        "Content-Encoding": "gzip",
                                        "Content-Length": "1855",
                                        "Content-Type": "application/x-javascript;charset=utf-8",
                                        "Date": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "Last-Modified": "Mon, 04 Jan 2021 22:14:03 GMT",
                                        "Vary": "Accept-Encoding",
                                        "X-CDN": "AKAM"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "186": {
                            "type": "ipv4-addr",
                            "value": "204.79.197.200"
                        },
                        "187": {
                            "resolves_to_refs": [
                                "186"
                            ],
                            "type": "domain-name",
                            "value": "bat.bing.com"
                        },
                        "188": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 28733,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "f14f0d4ca69db0c2914322578f10bf3f9393771f439c9f670cc4d40971b0af8d"
                            },
                            "type": "artifact"
                        },
                        "189": {
                            "dst_ref": "187",
                            "end": "2021-03-10T16:58:35.006999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/bat.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "188",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "*",
                                        "cache-control": "private,max-age=1800",
                                        "content-encoding": "gzip",
                                        "content-length": "8562",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:35 GMT",
                                        "etag": "\"804e75f6fd11d71:0\"",
                                        "last-modified": "Fri, 05 Mar 2021 20:27:29 GMT",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "x-msedge-ref": "Ref A: 362B845A2BDB44C6BE0AFDEA8CB3C919 Ref B: DFW30EDGE1110 Ref C: 2021-03-10T16:58:36Z"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "19": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 2596
                                }
                            },
                            "hashes": {
                                "SHA-256": "1b3d9d0eb85498f1963085684d50821b7186765179a7d059ed8b657004418657"
                            },
                            "type": "artifact"
                        },
                        "190": {
                            "type": "ipv4-addr",
                            "value": "23.206.124.134"
                        },
                        "191": {
                            "resolves_to_refs": [
                                "190"
                            ],
                            "type": "domain-name",
                            "value": "c.go-mpulse.net"
                        },
                        "192": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 6406,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "7638ae483bbdfbf7aeaf2c8e56091f2792a824fccb47111011a43aeff79f966b"
                            },
                            "type": "artifact"
                        },
                        "193": {
                            "dst_ref": "191",
                            "end": "2021-03-10T16:58:35.642999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/api/config.json?key=6KU9W-5DTLL-AXSJY-VNWUZ-RTS7Q&d=www.paloaltonetworks.com&t=5384652&v=1.632.0&if=&sl=0&si=xi1wzi1ezd9-qprj5k&plugins=AK,ConfigOverride,Continuity,PageParams,IFrameDelay,AutoXHR,SPA,Angular,Backbone,Ember,History,RT,CrossDomain,BW,PaintTiming,NavigationTiming,ResourceTiming,Memory,CACHE_RELOAD,Errors,TPAnalytics,UserTiming,Akamai,LOGN&acao=&ak.ai=287050"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "192",
                                    "response_code": 200,
                                    "response_header": {
                                        "Access-Control-Allow-Origin": "*",
                                        "Cache-Control": "private, max-age=300, stale-while-revalidate=60, stale-if-error=120",
                                        "Connection": "keep-alive",
                                        "Content-Encoding": "gzip",
                                        "Content-Length": "1494",
                                        "Content-Type": "application/json",
                                        "Date": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "Timing-Allow-Origin": "*",
                                        "Vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "194": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 96,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "673714f786cbf35e6710d6716b44a754737f37f6fd7c580cfe6c75be5104674e"
                            },
                            "type": "artifact"
                        },
                        "195": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:36.756999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "application/json, text/javascript, */*; q=0.01",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36",
                                        "X-Requested-With": "XMLHttpRequest"
                                    },
                                    "request_method": "get",
                                    "request_value": "/apps/pan/public/filterleads.getLeadsByCookie.json"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "194",
                                    "response_code": 200,
                                    "response_header": {
                                        "cache-control": "max-age=0, no-cache, no-store",
                                        "content-length": "96",
                                        "content-type": "application/json;charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "expires": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "pragma": "no-cache",
                                        "server": "Apache",
                                        "server-timing": "edge; dur=1, origin; dur=36, cdn-cache; desc=MISS",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
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
                        },
                        "196": {
                            "type": "ipv4-addr",
                            "value": "13.226.205.222"
                        },
                        "197": {
                            "resolves_to_refs": [
                                "196"
                            ],
                            "type": "domain-name",
                            "value": "d10lpsik1i8c69.cloudfront.net"
                        },
                        "198": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 5349,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "610ab00f8de8912637a2f94ba8a2976e1eef3c240276657b55851f6f6d8163cb"
                            },
                            "type": "artifact"
                        },
                        "199": {
                            "dst_ref": "197",
                            "end": "2021-03-10T16:58:36.878999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/w.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "198",
                                    "response_code": 200,
                                    "response_header": {
                                        "age": "782",
                                        "cache-control": "max-age=3600",
                                        "content-encoding": "gzip",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:45:34 GMT",
                                        "etag": "W/\"8e8d63ac39f7baa3ae59c19edea3f4a7\"",
                                        "last-modified": "Mon, 08 Mar 2021 19:45:34 GMT",
                                        "server": "AmazonS3",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "via": "1.1 433ba08ebf88b9d52f845d0398884b16.cloudfront.net (CloudFront)",
                                        "x-amz-cf-id": "cWiBzYTTChU5aFeOHjA7t4BgCCnIl5DpWa6lKlf9yGJi1TzlYsHxiA==",
                                        "x-amz-cf-pop": "DFW55-C2",
                                        "x-cache": "Hit from cloudfront"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "2": {
                            "dst_ref": "1",
                            "end": "2021-03-10T16:58:23.864Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Sec-Fetch-Mode": "navigate",
                                        "Sec-Fetch-User": "?1",
                                        "Upgrade-Insecure-Requests": "1",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/"
                                },
                                "x-wf-http-response-ext": {
                                    "response_code": 301,
                                    "response_header": {
                                        "alt-svc": "clear",
                                        "content-length": "253",
                                        "content-type": "text/html; charset=iso-8859-1",
                                        "date": "Wed, 10 Mar 2021 16:58:24 GMT",
                                        "location": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "server": "Apache",
                                        "status": "301",
                                        "strict-transport-security": "max-age=15811200",
                                        "via": "1.1 google"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "20": {
                            "artifact_ref": "19",
                            "type": "x-wf-url-resource"
                        },
                        "200": {
                            "type": "ipv4-addr",
                            "value": "104.16.149.64"
                        },
                        "201": {
                            "resolves_to_refs": [
                                "200"
                            ],
                            "type": "domain-name",
                            "value": "cdn.cookielaw.org"
                        },
                        "202": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 148423,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "f1b9ec4cde7f055a1a829106e4c84a735f084445e2d9506ab00bff4ffb8e6ba5"
                            },
                            "type": "artifact"
                        },
                        "203": {
                            "dst_ref": "201",
                            "end": "2021-03-10T16:58:36.88Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/consent/8bcc5ac4-8859-46fe-b843-fe246f4188f1.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "202",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "*",
                                        "access-control-expose-headers": "x-ms-request-id,Server,x-ms-version,Content-Type,Content-Encoding,Cache-Control,Last-Modified,ETag,Content-MD5,x-ms-lease-status,x-ms-blob-type,Content-Length,Date,Transfer-Encoding",
                                        "age": "2809",
                                        "cache-control": "public, max-age=14400",
                                        "cf-cache-status": "HIT",
                                        "cf-ray": "62de16bce81be03b-DFW",
                                        "cf-request-id": "08beac8a160000e03ba4899000000001",
                                        "content-encoding": "GZIP",
                                        "content-length": "20138",
                                        "content-md5": "hrhuXO0W8TDgfMbG3q+cnA==",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:36 GMT",
                                        "etag": "0x8D86F317165C349",
                                        "expect-ct": "max-age=604800, report-uri=\"https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct\"",
                                        "last-modified": "Tue, 13 Oct 2020 04:35:41 GMT",
                                        "server": "cloudflare",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                                        "vary": "Accept-Encoding",
                                        "x-content-type-options": "nosniff",
                                        "x-ms-blob-type": "BlockBlob",
                                        "x-ms-lease-status": "unlocked",
                                        "x-ms-request-id": "e2d16aac-001e-00b8-5146-b33a15000000",
                                        "x-ms-version": "2009-09-19"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "204": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 421,
                                    "sniffed_mime_type": "text/html"
                                }
                            },
                            "hashes": {
                                "SHA-256": "6cc84f565c21b78b2669b95529c50af7c0ebb7f950139c424f775065f6724919"
                            },
                            "type": "artifact"
                        },
                        "205": {
                            "dst_ref": "170",
                            "end": "2021-03-10T16:58:36.88Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/m2/paloaltonetworks/mbox/json?mbox=panw-custom-global-mbox&mboxSession=a5b62bd6203a47ab8a408f030c130ef4&mboxPC=&mboxPage=9779f1de31da45af9cb61aa118571e59&mboxRid=535e9eda631145129b110a44a0b6f8a4&mboxVersion=1.8.2&mboxCount=2&mboxTime=1615395515914&mboxHost=www.paloaltonetworks.com&mboxURL=https%3A%2F%2Fwww.paloaltonetworks.com%2Fcortex%2Fxsoar&mboxReferrer=&mboxXDomain=enabled&browserHeight=1200&browserWidth=1585&browserTimeOffset=0&screenHeight=600&screenWidth=800&colorDepth=24&devicePixelRatio=1&screenOrientation=landscape&webGLRenderer=Google%20SwiftShader&companyDomain=IP%20not%20matched&companyName=&pageChannel=cortex&pageName=en_us%3Acortex%3Axsoar&profile.companyDomain=IP%20not%20matched&profile.companyName=&mboxMCSDID=38AEA3BE75F922FB-7D96130F94BD82B9&vst.trk=paloaltonetworks.d1.sc.omtrdc.net&mboxMCGVID=43662614647497207373238360663372119555&mboxAAMB=RKhpRz8krg2tLO6pguXWp5olkAcUniQYPHaMWWgdJ3xzPWQmdj0y&mboxMCGLH=9"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "204"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "206": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 154
                                }
                            },
                            "hashes": {
                                "SHA-256": "7cb62649225a10294d273087e09d0fdb0132788156c419b5a8d359738cf49e5e"
                            },
                            "type": "artifact"
                        },
                        "207": {
                            "artifact_ref": "206",
                            "type": "x-wf-url-resource"
                        },
                        "208": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 150
                                }
                            },
                            "hashes": {
                                "SHA-256": "e8cd27c8d79b6827f65efda9a79375881be0a21aa734c9b79cc8fb0bfa546b35"
                            },
                            "type": "artifact"
                        },
                        "209": {
                            "artifact_ref": "208",
                            "type": "x-wf-url-resource"
                        },
                        "21": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 441
                                }
                            },
                            "hashes": {
                                "SHA-256": "f124ae6fb11846725777da8208990ad8b1ed3ff2267d3416adf7e830b1bc2a76"
                            },
                            "type": "artifact"
                        },
                        "210": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 288
                                }
                            },
                            "hashes": {
                                "SHA-256": "122fdbf1fd8f4d71aeebc69bd561030ebc8125c78fd49df47944a680dac74d34"
                            },
                            "type": "artifact"
                        },
                        "211": {
                            "artifact_ref": "210",
                            "type": "x-wf-url-resource"
                        },
                        "212": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 260
                                }
                            },
                            "hashes": {
                                "SHA-256": "14e589c48e3209fc398979f73f23103d020d45b746894f014378411d6313eea1"
                            },
                            "type": "artifact"
                        },
                        "213": {
                            "artifact_ref": "212",
                            "type": "x-wf-url-resource"
                        },
                        "214": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 2730
                                }
                            },
                            "hashes": {
                                "SHA-256": "babce8bcc4e2fa73f430d8a69dffed17f585d580f25696aee8cd62913cbcb1a5"
                            },
                            "type": "artifact"
                        },
                        "215": {
                            "artifact_ref": "214",
                            "type": "x-wf-url-resource"
                        },
                        "216": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1219
                                }
                            },
                            "hashes": {
                                "SHA-256": "a338d45dfedcf7f8419ee7102954b29df3a63e983fb7addb457bcfa9b8e10050"
                            },
                            "type": "artifact"
                        },
                        "217": {
                            "artifact_ref": "216",
                            "type": "x-wf-url-resource"
                        },
                        "218": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 123
                                }
                            },
                            "hashes": {
                                "SHA-256": "dc4d97782a4150dad0acd0c3e743b9495aca0d5d4ebf736e2ed65e5fd33fffe1"
                            },
                            "type": "artifact"
                        },
                        "219": {
                            "artifact_ref": "218",
                            "type": "x-wf-url-resource"
                        },
                        "22": {
                            "artifact_ref": "21",
                            "type": "x-wf-url-resource"
                        },
                        "220": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 613
                                }
                            },
                            "hashes": {
                                "SHA-256": "b039f82b4bdab3adac228863017bf942661334e21c5884fa6946c46745082549"
                            },
                            "type": "artifact"
                        },
                        "221": {
                            "artifact_ref": "220",
                            "type": "x-wf-url-resource"
                        },
                        "222": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 197
                                }
                            },
                            "hashes": {
                                "SHA-256": "ba8b1b81078c8ff35858cd3c38673efa302c80d18a95a21f09346140eb1ef8fd"
                            },
                            "type": "artifact"
                        },
                        "223": {
                            "artifact_ref": "222",
                            "type": "x-wf-url-resource"
                        },
                        "224": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 460
                                }
                            },
                            "hashes": {
                                "SHA-256": "293bac9c5865a9fc68eb7b0a836d9aa21f25e156691b9b37bfe1ee7a31390f17"
                            },
                            "type": "artifact"
                        },
                        "225": {
                            "artifact_ref": "224",
                            "type": "x-wf-url-resource"
                        },
                        "226": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 699
                                }
                            },
                            "hashes": {
                                "SHA-256": "9f4302114cf21baaa78e28110be3982fa39c86ec1a4de5ce50d90db1235e7ce9"
                            },
                            "type": "artifact"
                        },
                        "227": {
                            "artifact_ref": "226",
                            "type": "x-wf-url-resource"
                        },
                        "228": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 992
                                }
                            },
                            "hashes": {
                                "SHA-256": "4dab548fc0a4c2c83f21a592b971803cae88afd143713997390992d7b99eda20"
                            },
                            "type": "artifact"
                        },
                        "229": {
                            "artifact_ref": "228",
                            "type": "x-wf-url-resource"
                        },
                        "23": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 124
                                }
                            },
                            "hashes": {
                                "SHA-256": "acad3650a7118c53d84dbb7f7c97b0013e57f04e2c7c167dded53d7aa4bdb07a"
                            },
                            "type": "artifact"
                        },
                        "230": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 332
                                }
                            },
                            "hashes": {
                                "SHA-256": "3f1b84a78a61b5c3e37c6c48c6a8753a19fd9793bc949816a694c3454733eacd"
                            },
                            "type": "artifact"
                        },
                        "231": {
                            "artifact_ref": "230",
                            "type": "x-wf-url-resource"
                        },
                        "232": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 144
                                }
                            },
                            "hashes": {
                                "SHA-256": "62d7f0e007603665a98339cb5b44e3b8625c8a451a759abe25ad341ac2b62754"
                            },
                            "type": "artifact"
                        },
                        "233": {
                            "artifact_ref": "232",
                            "type": "x-wf-url-resource"
                        },
                        "234": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 180
                                }
                            },
                            "hashes": {
                                "SHA-256": "0a81afb1fcffc30dbd0c5dcded73f721364ea489f6186b531c3c73c7d5101509"
                            },
                            "type": "artifact"
                        },
                        "235": {
                            "artifact_ref": "234",
                            "type": "x-wf-url-resource"
                        },
                        "236": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 868
                                }
                            },
                            "hashes": {
                                "SHA-256": "a45b2cf9fd98490dbc9af3cf0a637209c97cf9178bac7fdd921d10ab12cc2299"
                            },
                            "type": "artifact"
                        },
                        "237": {
                            "artifact_ref": "236",
                            "type": "x-wf-url-resource"
                        },
                        "238": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1087
                                }
                            },
                            "hashes": {
                                "SHA-256": "55513224d28a931559f2f6182caf305f76838cc982f7458d6dbd4c5383ef7ca8"
                            },
                            "type": "artifact"
                        },
                        "239": {
                            "artifact_ref": "238",
                            "type": "x-wf-url-resource"
                        },
                        "24": {
                            "artifact_ref": "23",
                            "type": "x-wf-url-resource"
                        },
                        "240": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 346
                                }
                            },
                            "hashes": {
                                "SHA-256": "d0e078fce2f557c71ea6503aeb4475a66871525055b27be0643733bf1bc10cfe"
                            },
                            "type": "artifact"
                        },
                        "241": {
                            "artifact_ref": "240",
                            "type": "x-wf-url-resource"
                        },
                        "242": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 693
                                }
                            },
                            "hashes": {
                                "SHA-256": "db855f6f58749c4a1e159dedae57b7890b41055e26786e9d682d85cc6ac66ab6"
                            },
                            "type": "artifact"
                        },
                        "243": {
                            "artifact_ref": "242",
                            "type": "x-wf-url-resource"
                        },
                        "244": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 74
                                }
                            },
                            "hashes": {
                                "SHA-256": "46482d32978fa1d739dc91f087c3e838e8b28311b170b03fd89d8739e05cc9fe"
                            },
                            "type": "artifact"
                        },
                        "245": {
                            "artifact_ref": "244",
                            "type": "x-wf-url-resource"
                        },
                        "246": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 232
                                }
                            },
                            "hashes": {
                                "SHA-256": "9fbe4c5dd9f1176966f368949432cf80986f47c7bc7ae1c8acf2d9af40758e1e"
                            },
                            "type": "artifact"
                        },
                        "247": {
                            "artifact_ref": "246",
                            "type": "x-wf-url-resource"
                        },
                        "248": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 351
                                }
                            },
                            "hashes": {
                                "SHA-256": "0098e92161cb7509d32db83e89a8905f30b931a382a4f1fe4872081391b6ff44"
                            },
                            "type": "artifact"
                        },
                        "249": {
                            "artifact_ref": "248",
                            "type": "x-wf-url-resource"
                        },
                        "25": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 109620
                                }
                            },
                            "hashes": {
                                "SHA-256": "93bb40c7f1306f0634ac10c2586504dbdb40ccb338190ea9e05992c1e4300743"
                            },
                            "type": "artifact"
                        },
                        "250": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 203
                                }
                            },
                            "hashes": {
                                "SHA-256": "ba97e161a220c12915de9b9ff465c8701a8df199acdc41b04b3564d9e27fcdcb"
                            },
                            "type": "artifact"
                        },
                        "251": {
                            "artifact_ref": "250",
                            "type": "x-wf-url-resource"
                        },
                        "252": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 271
                                }
                            },
                            "hashes": {
                                "SHA-256": "bae85a2f5f5673817b11a83bd53b6edfca6fc67ba6a5ee626eb4b59e4e0a8a52"
                            },
                            "type": "artifact"
                        },
                        "253": {
                            "artifact_ref": "252",
                            "type": "x-wf-url-resource"
                        },
                        "254": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 292
                                }
                            },
                            "hashes": {
                                "SHA-256": "2cf89ed38d5c4a42cb26bcf423a462dee7a77481a21011d7bda886d0e1cfd88c"
                            },
                            "type": "artifact"
                        },
                        "255": {
                            "artifact_ref": "254",
                            "type": "x-wf-url-resource"
                        },
                        "256": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 174
                                }
                            },
                            "hashes": {
                                "SHA-256": "4db1755224b6954fbccd1ca52c090d3e214096059540685fbce0a0e00c1061de"
                            },
                            "type": "artifact"
                        },
                        "257": {
                            "artifact_ref": "256",
                            "type": "x-wf-url-resource"
                        },
                        "258": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 257
                                }
                            },
                            "hashes": {
                                "SHA-256": "d520aff0021c39a978db830dfba3b2b13ddd1cf3de9798eb028b9781b09e75e5"
                            },
                            "type": "artifact"
                        },
                        "259": {
                            "artifact_ref": "258",
                            "type": "x-wf-url-resource"
                        },
                        "26": {
                            "artifact_ref": "25",
                            "type": "x-wf-url-resource"
                        },
                        "260": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 585
                                }
                            },
                            "hashes": {
                                "SHA-256": "0753b8793036f2e4e46f00a8799582059120d62bc67ae4e56e1417f9d9a0d01d"
                            },
                            "type": "artifact"
                        },
                        "261": {
                            "artifact_ref": "260",
                            "type": "x-wf-url-resource"
                        },
                        "262": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 181
                                }
                            },
                            "hashes": {
                                "SHA-256": "e788cbc91a6bc58f720c09c561e205b9a5ebb04e649f803a64131d146e2a4eec"
                            },
                            "type": "artifact"
                        },
                        "263": {
                            "artifact_ref": "262",
                            "type": "x-wf-url-resource"
                        },
                        "264": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 161
                                }
                            },
                            "hashes": {
                                "SHA-256": "d674c9de6db49b8991eefa8efabcaeef8efc6ec8ac08f1a09efafc811c0a2da8"
                            },
                            "type": "artifact"
                        },
                        "265": {
                            "artifact_ref": "264",
                            "type": "x-wf-url-resource"
                        },
                        "266": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1944
                                }
                            },
                            "hashes": {
                                "SHA-256": "ee9b783bd78c7e53439f77f106f49edcc8768c0cc949bd3ffe8e430f658faa35"
                            },
                            "type": "artifact"
                        },
                        "267": {
                            "artifact_ref": "266",
                            "type": "x-wf-url-resource"
                        },
                        "268": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 599
                                }
                            },
                            "hashes": {
                                "SHA-256": "996c60ae0247b024b00edcda425ff5285e873b41e63e1d844e1f55f4f48358c9"
                            },
                            "type": "artifact"
                        },
                        "269": {
                            "artifact_ref": "268",
                            "type": "x-wf-url-resource"
                        },
                        "27": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 68
                                }
                            },
                            "hashes": {
                                "SHA-256": "620524cbdaf74e2fcd63d31f260bcce190f4697018e3e2ae7ae34e9828efc7be"
                            },
                            "type": "artifact"
                        },
                        "270": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 193
                                }
                            },
                            "hashes": {
                                "SHA-256": "decd952402365b5766516862ccc2e1fbfb0d1b42cbfc8f50ba7f484e1350a78c"
                            },
                            "type": "artifact"
                        },
                        "271": {
                            "artifact_ref": "270",
                            "type": "x-wf-url-resource"
                        },
                        "272": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 75
                                }
                            },
                            "hashes": {
                                "SHA-256": "729835964db37320a8a938fb4f612136735686cb426474e04c4460df0302e2d8"
                            },
                            "type": "artifact"
                        },
                        "273": {
                            "artifact_ref": "272",
                            "type": "x-wf-url-resource"
                        },
                        "274": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 95
                                }
                            },
                            "hashes": {
                                "SHA-256": "e743dff30774ac81c55e39e09839e4d461d9a65e40bc72e1a740f3dcc259dde3"
                            },
                            "type": "artifact"
                        },
                        "275": {
                            "artifact_ref": "274",
                            "type": "x-wf-url-resource"
                        },
                        "276": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 93
                                }
                            },
                            "hashes": {
                                "SHA-256": "18a814231eac56a2f6e5273ddbb1641991c25655ae33e4aaecb1fd674565476f"
                            },
                            "type": "artifact"
                        },
                        "277": {
                            "artifact_ref": "276",
                            "type": "x-wf-url-resource"
                        },
                        "278": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 10488,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "5557b6b0da10e484a5d100f8f7abd7877d34a526e1c31817f65c0dc6a8d7fa26"
                            },
                            "type": "artifact"
                        },
                        "279": {
                            "dst_ref": "72",
                            "end": "2021-03-10T16:58:37.088999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/9273d4aedcd2/0d76ae0322d7/a5e8dc8a9ed9/RCa6110f023810467bb84ff9b8f52b16e7-source.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "278",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "max-age=3600",
                                        "content-encoding": "gzip",
                                        "content-length": "2027",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:37 GMT",
                                        "etag": "\"f3b35ff48ce18a058616e18a2efde92e:1614190927.245815\"",
                                        "expires": "Wed, 10 Mar 2021 17:58:37 GMT",
                                        "last-modified": "Wed, 24 Feb 2021 18:22:07 GMT",
                                        "server": "AkamaiNetStorage",
                                        "status": "200",
                                        "timing-allow-origin": "*",
                                        "vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "28": {
                            "artifact_ref": "27",
                            "type": "x-wf-url-resource"
                        },
                        "280": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 875
                                }
                            },
                            "hashes": {
                                "SHA-256": "a5ff31e0efb055fa9add7c1f8859e15e21eb54705fb52849e2dd58e7a5640216"
                            },
                            "type": "artifact"
                        },
                        "281": {
                            "artifact_ref": "280",
                            "type": "x-wf-url-resource"
                        },
                        "282": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1736
                                }
                            },
                            "hashes": {
                                "SHA-256": "88fc029f5a978f4fc83ecdad8b16983d89b61c86ef519703bee92a2d7284c8a9"
                            },
                            "type": "artifact"
                        },
                        "283": {
                            "artifact_ref": "282",
                            "type": "x-wf-url-resource"
                        },
                        "284": {
                            "type": "domain-name",
                            "value": "static.matterport.com"
                        },
                        "285": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 5727
                                }
                            },
                            "hashes": {
                                "SHA-256": "f077b9b9c5129303063fdb6faeaf9b30dcd863f60106df18d1ce52576cfc6b34"
                            },
                            "type": "artifact"
                        },
                        "286": {
                            "dst_ref": "284",
                            "end": "2021-03-10T16:58:38.493Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_method": "get",
                                    "request_value": "/showcase/3.1.35.16-0-g5f6f72877/js/browser-check.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "285"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "287": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1775,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "fb818900c47736449fea7ea2d310a75f4d1d116a9ffbde0b66c884a8f4c455c8"
                            },
                            "type": "artifact"
                        },
                        "288": {
                            "dst_ref": "86",
                            "end": "2021-03-10T16:58:39.408999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "application/json",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/api/v2/users/current"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "287",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "allow": "GET, PUT, PATCH, HEAD, OPTIONS",
                                        "cache-control": "private, no-store, must-revalidate",
                                        "content-encoding": "gzip",
                                        "content-length": "603",
                                        "content-security-policy": "frame-ancestors 'self';",
                                        "content-type": "application/json",
                                        "date": "Wed, 10 Mar 2021 16:58:40 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin, X-Forwarded-Host, X-Backend",
                                        "x-cache": "MISS, MISS",
                                        "x-cache-hits": "0, 0",
                                        "x-content-type-options": "nosniff",
                                        "x-frame-options": "SAMEORIGIN",
                                        "x-request-id": "124dfcde0c34a34ffea8600749054c2792bdc3ab",
                                        "x-served-by": "cache-bwi5145-BWI, cache-dal21226-DAL",
                                        "x-timer": "S1615395520.063407,VS0,VE43",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "289": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 11110,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "459e23d23ffe65a86f3a1f67c07edc92e0c69461ff83fbd63764d7b36cac92fc"
                            },
                            "type": "artifact"
                        },
                        "29": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 121
                                }
                            },
                            "hashes": {
                                "SHA-256": "b2af44313e604a91fba6a2ffebc79315a5b67aefe67a2d3e109c64b954df309f"
                            },
                            "type": "artifact"
                        },
                        "290": {
                            "dst_ref": "177",
                            "end": "2021-03-10T16:58:39.49Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/159/munchkin.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "289",
                                    "response_code": 200,
                                    "response_header": {
                                        "Accept-Ranges": "bytes",
                                        "Cache-Control": "max-age=8640000",
                                        "Connection": "keep-alive",
                                        "Content-Encoding": "gzip",
                                        "Content-Length": "4810",
                                        "Content-Type": "application/x-javascript",
                                        "Date": "Wed, 10 Mar 2021 16:58:40 GMT",
                                        "ETag": "\"79274ffc293e4f76fc372b953f780d16:1588904654.430334\"",
                                        "Expires": "Fri, 18 Jun 2021 16:58:40 GMT",
                                        "Last-Modified": "Fri, 08 May 2020 02:24:14 GMT",
                                        "P3P": "policyref=\"http://www.marketo.com/w3c/p3p.xml\", CP=\"NOI DSP COR NID CURi OUR NOR\", policyref=\"http://www.marketo.com/w3c/p3p.xml\", CP=\"NOI DSP COR NID CURi OUR NOR\"",
                                        "Server": "AkamaiNetStorage",
                                        "Vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "291": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 2101083
                                }
                            },
                            "hashes": {
                                "SHA-256": "1c37c58d6485a4522fb227f2c34fb014a9c199acc16478643957199a9134db0a"
                            },
                            "type": "artifact"
                        },
                        "292": {
                            "dst_ref": "284",
                            "end": "2021-03-10T16:58:40.437Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_method": "get",
                                    "request_value": "/showcase/3.1.35.16-0-g5f6f72877/js/showcase.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "291"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "293": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 76
                                }
                            },
                            "hashes": {
                                "SHA-256": "3cc4131c7777d5cd2a6edeb9b79931998d8a83272494770d2323d0357aa95d16"
                            },
                            "type": "artifact"
                        },
                        "294": {
                            "artifact_ref": "293",
                            "type": "x-wf-url-resource"
                        },
                        "295": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 78
                                }
                            },
                            "hashes": {
                                "SHA-256": "01b82178fabbaa478ef2a595b981772a6e12bbf4663aa21686a0df5fe1b8ea54"
                            },
                            "type": "artifact"
                        },
                        "296": {
                            "artifact_ref": "295",
                            "type": "x-wf-url-resource"
                        },
                        "297": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 84
                                }
                            },
                            "hashes": {
                                "SHA-256": "93bf6ec1219c422f7c663ef9cdbe98797af35635d1b0881050aee226a6193283"
                            },
                            "type": "artifact"
                        },
                        "298": {
                            "artifact_ref": "297",
                            "type": "x-wf-url-resource"
                        },
                        "299": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 82
                                }
                            },
                            "hashes": {
                                "SHA-256": "c94f423c656a6131bb29e0a54bd52bcc842148a82175c6d2c9af368e61116572"
                            },
                            "type": "artifact"
                        },
                        "3": {
                            "type": "ipv4-addr",
                            "value": "104.102.227.106"
                        },
                        "30": {
                            "artifact_ref": "29",
                            "type": "x-wf-url-resource"
                        },
                        "300": {
                            "artifact_ref": "299",
                            "type": "x-wf-url-resource"
                        },
                        "301": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 82
                                }
                            },
                            "hashes": {
                                "SHA-256": "5ee954b0b39d700ed4a25650400dc00d83c950828eb1c56d2f3e26f5dc1eefcb"
                            },
                            "type": "artifact"
                        },
                        "302": {
                            "artifact_ref": "301",
                            "type": "x-wf-url-resource"
                        },
                        "303": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 80
                                }
                            },
                            "hashes": {
                                "SHA-256": "be52bf3d4a5e853ff66d7894f58fa8fb11d5c4010f5890b9c00c6c6f968c1572"
                            },
                            "type": "artifact"
                        },
                        "304": {
                            "artifact_ref": "303",
                            "type": "x-wf-url-resource"
                        },
                        "305": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 85
                                }
                            },
                            "hashes": {
                                "SHA-256": "74e56a505bea0251aa5ba93763447ad1184b643c43028412cf90092a6de26e3c"
                            },
                            "type": "artifact"
                        },
                        "306": {
                            "artifact_ref": "305",
                            "type": "x-wf-url-resource"
                        },
                        "307": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 84
                                }
                            },
                            "hashes": {
                                "SHA-256": "800f15791fb52d85e7ed4da52f100d11f8788d24b8c9ca6f478e8290b561f408"
                            },
                            "type": "artifact"
                        },
                        "308": {
                            "artifact_ref": "307",
                            "type": "x-wf-url-resource"
                        },
                        "309": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 86
                                }
                            },
                            "hashes": {
                                "SHA-256": "64cf164489e9fbaa98ae487f296e37fc25bc923436f2ac5fd8743241f50c243d"
                            },
                            "type": "artifact"
                        },
                        "31": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 28
                                }
                            },
                            "hashes": {
                                "SHA-256": "ac7eaf64fc2ef289a3181ae761644e5b667bfd012aab814d1826dcd7fefeae2c"
                            },
                            "type": "artifact"
                        },
                        "310": {
                            "artifact_ref": "309",
                            "type": "x-wf-url-resource"
                        },
                        "311": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 84
                                }
                            },
                            "hashes": {
                                "SHA-256": "d5be7fc8c1f213f618c604479184faaf582d46cd627ee8bb1002929b2e4c311c"
                            },
                            "type": "artifact"
                        },
                        "312": {
                            "artifact_ref": "311",
                            "type": "x-wf-url-resource"
                        },
                        "313": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 79
                                }
                            },
                            "hashes": {
                                "SHA-256": "f23e8d7b5ddb5e2ac8c70eb6ca06f3f7f988bf662ad46fd29bcd10fe607c63b4"
                            },
                            "type": "artifact"
                        },
                        "314": {
                            "artifact_ref": "313",
                            "type": "x-wf-url-resource"
                        },
                        "315": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 348
                                }
                            },
                            "hashes": {
                                "SHA-256": "95a5ed342a19fbf80e89ff5538b7b6f17024cfbadb3042d610788af12689e70f"
                            },
                            "type": "artifact"
                        },
                        "316": {
                            "artifact_ref": "315",
                            "type": "x-wf-url-resource"
                        },
                        "317": {
                            "type": "ipv4-addr",
                            "value": "104.26.11.16"
                        },
                        "318": {
                            "resolves_to_refs": [
                                "317"
                            ],
                            "type": "domain-name",
                            "value": "settings.luckyorange.net"
                        },
                        "319": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1881,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "b08b7a96c4aeb4a21f19a6409770466f95dde844ca8257711ad0d120a9cffd71"
                            },
                            "type": "artifact"
                        },
                        "32": {
                            "artifact_ref": "31",
                            "type": "x-wf-url-resource"
                        },
                        "320": {
                            "dst_ref": "318",
                            "end": "2021-03-10T16:58:40.572999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/?u=https%3A%2F%2Fwww.paloaltonetworks.com%2Fcortex%2Fxsoar&s=109287"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "319",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-headers": "Authorization,Content-Type,Accept,Origin,User-Agent,DNT,Cache-Control,Keep-Alive,X-Requested-With,If-Modified-Since",
                                        "access-control-allow-methods": "GET, POST, OPTIONS",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cf-cache-status": "DYNAMIC",
                                        "cf-ray": "62de16d7ef80eccb-DFW",
                                        "cf-request-id": "08beac9af40000eccba9049000000001",
                                        "content-encoding": "br",
                                        "content-type": "application/json",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "expect-ct": "max-age=604800, report-uri=\"https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct\"",
                                        "nel": "{\"report_to\":\"cf-nel\",\"max_age\":604800}",
                                        "report-to": "{\"endpoints\":[{\"url\":\"https:\\/\\/a.nel.cloudflare.com\\/report?s=hmFnK2RsYD2vkP1Wsb7JYxF%2BYrDjqAg%2BcVecoLra6IG18eszsoKoWPQ8y%2F2gAGHVFq35cmmPa%2Fq3Dc5U9sai%2Fx%2F2JSPtR3u1CBjtmRErjB4lJ3beiYBcFHU%3D\"}],\"max_age\":604800,\"group\":\"cf-nel\"}",
                                        "server": "cloudflare",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "x-frame-options": "SAMEORIGIN"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "321": {
                            "type": "ipv4-addr",
                            "value": "69.16.175.42"
                        },
                        "322": {
                            "resolves_to_refs": [
                                "321"
                            ],
                            "type": "domain-name",
                            "value": "code.jquery.com"
                        },
                        "323": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 86927,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "160a426ff2894252cd7cebbdd6d6b7da8fcd319c65b70468f10b6690c45d02ef"
                            },
                            "type": "artifact"
                        },
                        "324": {
                            "dst_ref": "322",
                            "end": "2021-03-10T16:58:40.582Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Origin": "https://www.paloaltonetworks.com",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/jquery-3.3.1.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "323",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "*",
                                        "cache-control": "max-age=315360000, public",
                                        "content-encoding": "gzip",
                                        "content-length": "30288",
                                        "content-type": "application/javascript; charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "etag": "W/\"5a637bd4-1538f\"",
                                        "last-modified": "Sat, 20 Jan 2018 17:26:44 GMT",
                                        "server": "nginx",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "x-hw": "1615395521.dop201.de1.t,1615395521.cds218.de1.hn,1615395521.cds028.de1.c"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "325": {
                            "type": "ipv4-addr",
                            "value": "199.232.9.2"
                        },
                        "326": {
                            "resolves_to_refs": [
                                "325"
                            ],
                            "type": "domain-name",
                            "value": "a.quora.com"
                        },
                        "327": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 39437,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "ef6de6beb1cf5bf809eccfe10f99aea0e0969c71d4eab5446410fef72695679f"
                            },
                            "type": "artifact"
                        },
                        "328": {
                            "dst_ref": "326",
                            "end": "2021-03-10T16:58:40.582999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/qevents.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "327",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "1447",
                                        "cache-control": "max-age=7200",
                                        "content-encoding": "gzip",
                                        "content-length": "13681",
                                        "content-type": "text/plain",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "etag": "\"f32ebb1e93a72c0a57add6d07f688510\"",
                                        "last-modified": "Fri, 25 Oct 2019 19:28:38 GMT",
                                        "server": "AmazonS3",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "via": "1.1 varnish, 1.1 varnish",
                                        "x-amz-id-2": "ignX2Ghmc4D8uIjM1wme+2Ph5BGP7d2zDckaUHnKviAG2ybKqhlwcN4Qnr7ufKlK+jDfsOCJh4w=",
                                        "x-amz-meta-s3cmd-attrs": "atime:1572031715/ctime:1572031714/gid:1000000/gname:employee/md5:f32ebb1e93a72c0a57add6d07f688510/mode:33188/mtime:1149709104/uid:1000332/uname:tzhou",
                                        "x-amz-request-id": "B6A2400A82744A43",
                                        "x-amz-version-id": "s3LlaOWABX1LUjiLldBNr49lVAylKDRo",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 364",
                                        "x-served-by": "cache-bwi5132-BWI, cache-dal21278-DAL",
                                        "x-timer": "S1615395521.248252,VS0,VE0"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "329": {
                            "resolves_to_refs": [
                                "127"
                            ],
                            "type": "domain-name",
                            "value": "tag.demandbase.com"
                        },
                        "33": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1124
                                }
                            },
                            "hashes": {
                                "SHA-256": "dce16e6d66a66a63ee5a9e10db25e99d6f35a0712a8a3aeffb3ceb8f01feb826"
                            },
                            "type": "artifact"
                        },
                        "330": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 63173,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "e580b42df6f33e3a81878a9f2e672b9ffaf4c78745a3eb2f0211fdc014aba2e6"
                            },
                            "type": "artifact"
                        },
                        "331": {
                            "dst_ref": "329",
                            "end": "2021-03-10T16:58:40.584Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/e78feef73ff94c88.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "330",
                                    "response_code": 200,
                                    "response_header": {
                                        "age": "674",
                                        "cache-control": "public, max-age=3600",
                                        "content-encoding": "gzip",
                                        "content-type": "application/javascript; charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:48:45 GMT",
                                        "etag": "W/\"1952a77a840be970e4cc64bfc1a65554\"",
                                        "last-modified": "Wed, 03 Mar 2021 22:34:04 GMT",
                                        "server": "AmazonS3",
                                        "status": "200",
                                        "vary": "Accept-Encoding",
                                        "via": "1.1 78487ffbca2380a1b0612e6718bb8f2f.cloudfront.net (CloudFront)",
                                        "x-amz-cf-id": "sJcglhkS3Neq7GS4dvAC8bmlg85ua454rDnwDf_NVMM5YJLeLCwWlQ==",
                                        "x-amz-cf-pop": "DFW55-C2",
                                        "x-amz-version-id": "ok42sUjiDncJjCtLDUt6jhSKHcsHunhj",
                                        "x-cache": "Hit from cloudfront"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "332": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 501
                                }
                            },
                            "hashes": {
                                "SHA-256": "5c1d3834ce7afedafa3150281689f78918b60c01ec8ff7a165334f18aa5cfbc7"
                            },
                            "type": "artifact"
                        },
                        "333": {
                            "artifact_ref": "332",
                            "type": "x-wf-url-resource"
                        },
                        "334": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 375
                                }
                            },
                            "hashes": {
                                "SHA-256": "0ff9f8c8c6f535591fe348cc299df182b0e9c8800f4e20e9b82b5ccb103e3ee7"
                            },
                            "type": "artifact"
                        },
                        "335": {
                            "artifact_ref": "334",
                            "type": "x-wf-url-resource"
                        },
                        "336": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 259
                                }
                            },
                            "hashes": {
                                "SHA-256": "78740dff5f2c6dfd0b492ed4b6bd0c4ac309222b2090a03a151ad15286c85f76"
                            },
                            "type": "artifact"
                        },
                        "337": {
                            "artifact_ref": "336",
                            "type": "x-wf-url-resource"
                        },
                        "338": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 411
                                }
                            },
                            "hashes": {
                                "SHA-256": "2ff03fa46d80b1deaabbf2f683b77e75a60ba1f9ee7173ee2ea1755643fa1f2e"
                            },
                            "type": "artifact"
                        },
                        "339": {
                            "artifact_ref": "338",
                            "type": "x-wf-url-resource"
                        },
                        "34": {
                            "artifact_ref": "33",
                            "type": "x-wf-url-resource"
                        },
                        "340": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 9710
                                }
                            },
                            "hashes": {
                                "SHA-256": "1221ee176b430a05afc106f3480b4c92445c7599e21a6df2c7a81e3b6471261d"
                            },
                            "type": "artifact"
                        },
                        "341": {
                            "artifact_ref": "340",
                            "type": "x-wf-url-resource"
                        },
                        "342": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 66348,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "d81f6d383c5bb706de6624a62377da1987060051b23ab25ce3ee9edaa68d24c9"
                            },
                            "type": "artifact"
                        },
                        "343": {
                            "dst_ref": "160",
                            "end": "2021-03-10T16:58:41.405999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/showcase/3.1.35.16-0-g5f6f72877/js/268.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "342",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "59865",
                                        "cache-control": "max-age=604800",
                                        "content-encoding": "gzip",
                                        "content-length": "19258",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "etag": "\"af869fb32fd06206676147f7e4b68053\"",
                                        "last-modified": "Wed, 24 Feb 2021 00:17:21 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 702",
                                        "x-content-type-options": "nosniff",
                                        "x-served-by": "cache-bwi5165-BWI, cache-dal21226-DAL",
                                        "x-timer": "S1615395521.416287,VS0,VE0",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "344": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 10698,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "faaa7451a57dded66bd40cff046a59a57776323bd00c6e49954af37af2fe9032"
                            },
                            "type": "artifact"
                        },
                        "345": {
                            "dst_ref": "160",
                            "end": "2021-03-10T16:58:41.407Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/showcase/3.1.35.16-0-g5f6f72877/locale/strings-en-US.json"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "344",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-headers": "X-CSRFToken, X-Requested-With, X-Matterport-Referrer, X-Matterport-Application-Key, Content-Type, X-API-Key, Authorization",
                                        "access-control-allow-methods": "GET, HEAD, OPTIONS",
                                        "access-control-allow-origin": "https://my.matterport.com",
                                        "access-control-max-age": "900",
                                        "age": "20990",
                                        "cache-control": "max-age=604800",
                                        "content-encoding": "gzip",
                                        "content-length": "3362",
                                        "content-type": "application/json",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "etag": "\"86783662ff02311fbd8982eff0572e59\"",
                                        "last-modified": "Wed, 24 Feb 2021 00:17:21 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 239",
                                        "x-content-type-options": "nosniff",
                                        "x-served-by": "cache-bwi5140-BWI, cache-dal21251-DAL",
                                        "x-timer": "S1615395521.432862,VS0,VE0",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "346": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 11566,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "66f1f95e689d2f8933d59e9c44de3365a33a1b2754b1f4c8ed234cbb60321c5d"
                            },
                            "type": "artifact"
                        },
                        "347": {
                            "dst_ref": "86",
                            "end": "2021-03-10T16:58:41.408999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "application/json",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/api/v2/models/q3s3ktjhjC9/sweeps?tag=showcase"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "346",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "862",
                                        "allow": "GET, PATCH, HEAD, OPTIONS",
                                        "cache-control": "private, no-store, must-revalidate",
                                        "content-encoding": "gzip",
                                        "content-length": "3134",
                                        "content-security-policy": "frame-ancestors 'self';",
                                        "content-type": "application/json",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin, X-Forwarded-Host, X-Backend",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 1",
                                        "x-content-type-options": "nosniff",
                                        "x-frame-options": "SAMEORIGIN",
                                        "x-request-id": "0624f62b1d68aa81533db991bfb3cc1748226ee3",
                                        "x-served-by": "cache-bwi5136-BWI, cache-dal21226-DAL",
                                        "x-timer": "S1615395521.433093,VS0,VE1",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "348": {
                            "type": "ipv4-addr",
                            "value": "192.28.144.124"
                        },
                        "349": {
                            "resolves_to_refs": [
                                "348"
                            ],
                            "type": "domain-name",
                            "value": "531-ocs-018.mktoresp.com"
                        },
                        "35": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 161
                                }
                            },
                            "hashes": {
                                "SHA-256": "106534cd559b52cc05c7154513b8cad2cfded8c5df155671a45ae489d25349d8"
                            },
                            "type": "artifact"
                        },
                        "350": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 2,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3"
                            },
                            "type": "artifact"
                        },
                        "351": {
                            "dst_ref": "349",
                            "end": "2021-03-10T16:58:41.413Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/webevents/visitWebPage?_mchNc=1615395521324&_mchCn=&_mchId=531-OCS-018&_mchTk=_mch-paloaltonetworks.com-1615395521298-98188&_mchHo=www.paloaltonetworks.com&_mchPo=&_mchRu=%2Fcortex%2Fxsoar&_mchPc=https%3A&_mchVr=159&_mchEcid=9A531C8B532965080A490D4D%40AdobeOrg%3A%3A43662614647497207373238360663372119555&_mchHa=&_mchRe=&_mchQp="
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "350",
                                    "response_code": 200,
                                    "response_header": {
                                        "Access-Control-Allow-Origin": "*",
                                        "Connection": "keep-alive",
                                        "Content-Encoding": "gzip",
                                        "Content-Type": "text/plain; charset=UTF-8",
                                        "Date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "Server": "nginx",
                                        "Transfer-Encoding": "chunked",
                                        "X-Request-Id": "d3a28b56-1e6f-40a7-b13e-c55cd9598b02"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "352": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 3549,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "f1b0c731a436c925ad817659283b8d8156fe483fbc4d4f257860ef26fa1af08d"
                            },
                            "type": "artifact"
                        },
                        "353": {
                            "dst_ref": "157",
                            "end": "2021-03-10T16:58:41.733Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/api/v2/ip.json?referrer=&page=https%3A%2F%2Fwww.paloaltonetworks.com%2Fcortex%2Fxsoar&page_title=Cortex%20XSOAR%20-%20Security%20Orchestration%2C%20Automation%20and%20Response%20(SOAR)%20-%20Palo%20Alto%20Networks&src=tag&auth=rhHs2pCwtW45bcDMDhiTIJL5K8XiLPQcWK62xuW4"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "352",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-headers": "DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type",
                                        "access-control-allow-methods": "GET, POST, OPTIONS",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "access-control-expose-headers": "",
                                        "access-control-max-age": "7200",
                                        "api-version": "v2",
                                        "cache-control": "no-cache, no-store, max-age=0, must-revalidate",
                                        "content-encoding": "gzip",
                                        "content-type": "application/json;charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:41 GMT",
                                        "expires": "Tue, 09 Mar 2021 16:58:41 GMT",
                                        "identification-source": "CACHE",
                                        "pragma": "no-cache",
                                        "request-id": "b4cd5ed1-6289-4d91-bc58-bacf22bc8c91",
                                        "server": "nginx",
                                        "status": "200",
                                        "vary": "Accept-Encoding, Origin",
                                        "via": "1.1 8475262a7d3b8601272ede312d08be5f.cloudfront.net (CloudFront)",
                                        "x-amz-cf-id": "OilIkIy_WEkNxidaTxogKtgqL-ZS727zvtNYg87vE4m0yHQGPDxaKQ==",
                                        "x-amz-cf-pop": "DFW55-C3",
                                        "x-cache": "Miss from cloudfront"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "354": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 293239,
                                    "sniffed_mime_type": "application/octet-stream"
                                }
                            },
                            "hashes": {
                                "SHA-256": "73ea69ea75b3045c53f48e64ddc55cc8352bb7bd2c8dec1be13a568f0c2b3e6c"
                            },
                            "type": "artifact"
                        },
                        "355": {
                            "dst_ref": "197",
                            "end": "2021-03-10T16:58:42.391Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Origin": "https://www.paloaltonetworks.com",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/js/clickstream.js?v=126f613"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "354",
                                    "response_code": 200,
                                    "response_header": {
                                        "access-control-allow-methods": "GET",
                                        "access-control-allow-origin": "*",
                                        "access-control-max-age": "3000",
                                        "age": "162752",
                                        "cache-control": "max-age=31536000",
                                        "content-encoding": "gzip",
                                        "content-type": "application/javascript",
                                        "date": "Mon, 08 Mar 2021 19:46:11 GMT",
                                        "etag": "W/\"74b6b3f5336ab86dc9cb0f338001d9bc\"",
                                        "last-modified": "Mon, 08 Mar 2021 19:45:33 GMT",
                                        "server": "AmazonS3",
                                        "status": "200",
                                        "vary": "Accept-Encoding,Origin,Access-Control-Request-Headers,Access-Control-Request-Method",
                                        "via": "1.1 78487ffbca2380a1b0612e6718bb8f2f.cloudfront.net (CloudFront)",
                                        "x-amz-cf-id": "kGXWStdSnvKPd1Kky5KaCuyCPiCe_GY4h93u4x9TubsgR8A9NI_6sw==",
                                        "x-amz-cf-pop": "DFW55-C2",
                                        "x-cache": "Hit from cloudfront"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "356": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 82,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "8c833b2dc1ece5743040e80e8c3d2e25a23d6e43f8e4e90091d3e3058084b7c0"
                            },
                            "type": "artifact"
                        },
                        "357": {
                            "dst_ref": "160",
                            "end": "2021-03-10T16:58:42.717999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "application/json",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/geoip/"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "356",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-credentials": "true",
                                        "access-control-allow-headers": "X-CSRFToken, X-Requested-With, X-Matterport-Referrer, X-Matterport-Application-Key, Content-Type, X-API-Key, Authorization",
                                        "access-control-allow-methods": "GET, HEAD, OPTIONS",
                                        "access-control-allow-origin": "https://my.matterport.com",
                                        "access-control-max-age": "900",
                                        "content-length": "82",
                                        "date": "Wed, 10 Mar 2021 16:58:43 GMT",
                                        "retry-after": "0",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Origin",
                                        "x-cache": "HIT",
                                        "x-cache-hits": "0",
                                        "x-content-type-options": "nosniff",
                                        "x-served-by": "cache-dal21251-DAL",
                                        "x-timer": "S1615395523.035408,VS0,VE0",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "358": {
                            "type": "ipv4-addr",
                            "value": "157.240.19.26"
                        },
                        "359": {
                            "resolves_to_refs": [
                                "358"
                            ],
                            "type": "domain-name",
                            "value": "connect.facebook.net"
                        },
                        "36": {
                            "artifact_ref": "35",
                            "type": "x-wf-url-resource"
                        },
                        "360": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 93376,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "9e7ea2b4ba8e2bcc4a964d6192e4671dc5f6863a1c7e35b52b229a3c1e67a68d"
                            },
                            "type": "artifact"
                        },
                        "361": {
                            "dst_ref": "359",
                            "end": "2021-03-10T16:58:42.868999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/en_US/fbevents.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "360",
                                    "response_code": 200,
                                    "response_header": {
                                        "alt-svc": "h3-29=\":443\"; ma=3600,h3-27=\":443\"; ma=3600",
                                        "cache-control": "public, max-age=1200",
                                        "content-encoding": "gzip",
                                        "content-length": "23762",
                                        "content-security-policy": "default-src * data: blob: 'self';script-src *.facebook.com *.fbcdn.net *.facebook.net *.google-analytics.com *.virtualearth.net *.google.com 127.0.0.1:* *.spotilocal.com:* 'unsafe-inline' 'unsafe-eval' blob: data: 'self';style-src data: blob: 'unsafe-inline' *;connect-src *.facebook.com facebook.com *.fbcdn.net *.facebook.net *.spotilocal.com:* wss://*.facebook.com:* https://fb.scanandcleanlocal.com:* attachment.fbsbx.com ws://localhost:* blob: *.cdninstagram.com 'self' chrome-extension://boadgeojelhgndaghljhdicfkmllpafd chrome-extension://dliochdbjfkdbacpmhlcpmleaejidimm;block-all-mixed-content;upgrade-insecure-requests;",
                                        "content-type": "application/x-javascript; charset=utf-8",
                                        "cross-origin-embedder-policy-report-only": "require-corp;report-to=\"coep_report\"",
                                        "cross-origin-resource-policy": "cross-origin",
                                        "date": "Wed, 10 Mar 2021 16:58:43 GMT",
                                        "expires": "Sat, 01 Jan 2000 00:00:00 GMT",
                                        "pragma": "public",
                                        "priority": "u=3,i",
                                        "report-to": "{\"group\":\"coep_report\",\"max_age\":86400,\"endpoints\":[{\"url\":\"https:\\/\\/www.facebook.com\\/browser_reporting\\/\"}]}",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000; preload; includeSubDomains",
                                        "vary": "Accept-Encoding",
                                        "x-content-type-options": "nosniff",
                                        "x-fb-debug": "FVC6W34VWU4/vOxnvQLvoyZ4l2gppdCikvq6imtnZeCxZBAqh1po6vAcGH5OlGFKMhC6Jfwrrv7EkUJY9+0avw==",
                                        "x-fb-rlafr": "0",
                                        "x-fb-trip-id": "2050670934",
                                        "x-frame-options": "DENY",
                                        "x-xss-protection": "0"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "362": {
                            "type": "ipv4-addr",
                            "value": "199.232.9.128"
                        },
                        "363": {
                            "resolves_to_refs": [
                                "362"
                            ],
                            "type": "domain-name",
                            "value": "events.matterport.com"
                        },
                        "364": {
                            "dst_ref": "363",
                            "end": "2021-03-10T16:58:42.868999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept": "application/json",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Content-Type": "application/json, application/json",
                                        "Referer": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0",
                                        "Sec-Fetch-Mode": "cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36",
                                        "X-API-Key": "Rk5K64KYkKq9ZbcheBn4d"
                                    },
                                    "request_method": "get",
                                    "request_value": "/api/v1/event"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "146",
                                    "response_code": 204,
                                    "response_header": {
                                        "Accept-Ranges": "bytes",
                                        "Access-Control-Allow-Headers": "X-CSRFToken, X-Requested-With, X-Matterport-Referrer, X-Matterport-Application-Key, Content-Type, X-API-Key",
                                        "Access-Control-Allow-Methods": "GET, PUT, POST, DELETE, HEAD, PATCH, OPTIONS",
                                        "Access-Control-Allow-Origin": "*",
                                        "Access-Control-Max-Age": "3600",
                                        "Connection": "keep-alive",
                                        "Content-Security-Policy": "frame-ancestors 'self';",
                                        "Date": "Wed, 10 Mar 2021 16:58:43 GMT",
                                        "Strict-Transport-Security": "max-age=31536000",
                                        "Vary": "Origin",
                                        "X-Cache": "MISS, MISS",
                                        "X-Cache-Hits": "0, 0",
                                        "X-Content-Type-Options": "nosniff",
                                        "X-Frame-Options": "SAMEORIGIN",
                                        "X-Request-Id": "caaaefc6f08258e683fd2da984d7a5ff43068504",
                                        "X-Served-By": "cache-bwi5135-BWI, cache-dal21228-DAL",
                                        "X-Timer": "S1615395523.179697,VS0,VE35",
                                        "X-XSS-Protection": "1; mode=block",
                                        "content-type": "application/json"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "365": {
                            "type": "domain-name",
                            "value": "d10lpsik1i8c69.cloudfront.net"
                        },
                        "366": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 293239
                                }
                            },
                            "hashes": {
                                "SHA-256": "d6c10793ea0a88610c90a678e36837a097a8a81feda026420dd361a3f4929d7e"
                            },
                            "type": "artifact"
                        },
                        "367": {
                            "dst_ref": "365",
                            "end": "2021-03-10T16:58:46.697999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_method": "get",
                                    "request_value": "/js/clickstream.js?v=126f613"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "366"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "368": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 246322,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "afa3097dec47a8ba4491751e8239aefcaa6f5f28f5ce226f64c01846349a2d77"
                            },
                            "type": "artifact"
                        },
                        "369": {
                            "dst_ref": "359",
                            "end": "2021-03-10T16:58:46.707999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/signals/config/370217679980519?v=2.9.33&r=stable"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "368"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "37": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 703
                                }
                            },
                            "hashes": {
                                "SHA-256": "be5f767b158cf36db422e3af2f22b4610888cde100f48492d2096e12505c528f"
                            },
                            "type": "artifact"
                        },
                        "370": {
                            "type": "ipv4-addr",
                            "value": "65.8.226.113"
                        },
                        "371": {
                            "resolves_to_refs": [
                                "370"
                            ],
                            "type": "domain-name",
                            "value": "js.driftt.com"
                        },
                        "372": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 208743,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "b7d59f711d9cf3aecb9957ec373002a25794f288a1a2c1c20cad2e9760b88bf7"
                            },
                            "type": "artifact"
                        },
                        "373": {
                            "dst_ref": "371",
                            "end": "2021-03-10T16:58:46.73Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/include/1615395600000/4tkv88zdpmnh.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "372"
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "374": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 48
                                }
                            },
                            "hashes": {
                                "SHA-256": "c17c4be4a0d0c93178aee06d36f7f5a8f51fb511d95e18062c335f55ef1fc2e3"
                            },
                            "type": "artifact"
                        },
                        "375": {
                            "artifact_ref": "374",
                            "type": "x-wf-url-resource"
                        },
                        "376": {
                            "type": "x-wf-url-websocket-messages"
                        },
                        "377": {
                            "type": "url",
                            "value": "wss://in.visitors.live/socket.io/?EIO=3&transport=websocket"
                        },
                        "378": {
                            "type": "url",
                            "value": "wss://visitors.live/socket.io/?siteId=109287&EIO=3&transport=websocket"
                        },
                        "379": {
                            "hashes": {
                                "SHA-256": "c659c6d409b75df27dd0a30c342bb093661be2117d421055f47c36b9ac73900a"
                            },
                            "type": "artifact"
                        },
                        "38": {
                            "artifact_ref": "37",
                            "type": "x-wf-url-resource"
                        },
                        "380": {
                            "page_frame_refs": [
                                "10",
                                "91"
                            ],
                            "screenshot_ref": "379",
                            "type": "x-wf-url-browser-information",
                            "websocket_messages_ref": "376",
                            "websocket_url_refs": [
                                "377",
                                "378"
                            ]
                        },
                        "381": {
                            "type": "url",
                            "value": "https://www.demisto.com"
                        },
                        "382": {
                            "name": "Chrome",
                            "type": "software",
                            "vendor": "Google Inc."
                        },
                        "39": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 527
                                }
                            },
                            "hashes": {
                                "SHA-256": "af7ffe58f32925647bdbccd0d2c89d41bb9adb4d4c36e148bf251329ef7e7155"
                            },
                            "type": "artifact"
                        },
                        "4": {
                            "resolves_to_refs": [
                                "3"
                            ],
                            "type": "domain-name",
                            "value": "www.paloaltonetworks.com"
                        },
                        "40": {
                            "artifact_ref": "39",
                            "type": "x-wf-url-resource"
                        },
                        "41": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 733
                                }
                            },
                            "hashes": {
                                "SHA-256": "101ff598547f9938101bb9efcc28718376ff723615e208151cab1b6cab069829"
                            },
                            "type": "artifact"
                        },
                        "42": {
                            "artifact_ref": "41",
                            "type": "x-wf-url-resource"
                        },
                        "43": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 318
                                }
                            },
                            "hashes": {
                                "SHA-256": "d2d72e71e209db08f2799aa818211d5f024394aaf370af22a56ed761d7143bd4"
                            },
                            "type": "artifact"
                        },
                        "44": {
                            "artifact_ref": "43",
                            "type": "x-wf-url-resource"
                        },
                        "45": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 4182
                                }
                            },
                            "hashes": {
                                "SHA-256": "b2deb6277d59bd891dc34c40981ddcf622fe8c2fad518955d57b0812de5e7ba0"
                            },
                            "type": "artifact"
                        },
                        "46": {
                            "artifact_ref": "45",
                            "type": "x-wf-url-resource"
                        },
                        "47": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 692
                                }
                            },
                            "hashes": {
                                "SHA-256": "0c13ee9c545878807427682ca62cd75ae0acdb08672357fa2e0ca04ed2575187"
                            },
                            "type": "artifact"
                        },
                        "48": {
                            "artifact_ref": "47",
                            "type": "x-wf-url-resource"
                        },
                        "49": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 91
                                }
                            },
                            "hashes": {
                                "SHA-256": "4bf3b9a55ce11016ac04fbc74ee827b69a7ce83e7f174ae1f1fddf5f6ba92b76"
                            },
                            "type": "artifact"
                        },
                        "5": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 649743,
                                    "sniffed_mime_type": "application/octet-stream"
                                }
                            },
                            "hashes": {
                                "SHA-256": "6a25d1bff4f207937194244cf026880b16bd132f505c4219c3f4308867c1cf51"
                            },
                            "type": "artifact"
                        },
                        "50": {
                            "artifact_ref": "49",
                            "type": "x-wf-url-resource"
                        },
                        "51": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 174
                                }
                            },
                            "hashes": {
                                "SHA-256": "a39ff842bd52e8ac94ed77c067e924dcc70edb4fa09ebd0313773719de63fa98"
                            },
                            "type": "artifact"
                        },
                        "52": {
                            "artifact_ref": "51",
                            "type": "x-wf-url-resource"
                        },
                        "53": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 160
                                }
                            },
                            "hashes": {
                                "SHA-256": "8222b0bf62e90de12bb8ad3aa64803e03d0dbc5a28d3e5487b3f1dce70e60a81"
                            },
                            "type": "artifact"
                        },
                        "54": {
                            "artifact_ref": "53",
                            "type": "x-wf-url-resource"
                        },
                        "55": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 21642
                                }
                            },
                            "hashes": {
                                "SHA-256": "e67000a1244cf9053a0eebb8e75c425947adf3785c5c23e8a813025ea1857923"
                            },
                            "type": "artifact"
                        },
                        "56": {
                            "artifact_ref": "55",
                            "type": "x-wf-url-resource"
                        },
                        "57": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 925
                                }
                            },
                            "hashes": {
                                "SHA-256": "8922d9d0582542264313537a642b72aef46d184727ccd1fecf730e79b4482595"
                            },
                            "type": "artifact"
                        },
                        "58": {
                            "artifact_ref": "57",
                            "type": "x-wf-url-resource"
                        },
                        "59": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 1819
                                }
                            },
                            "hashes": {
                                "SHA-256": "2b19c07379941cdbb7b202ba0d01d1e4d0aedb950ef27a8626e83947ffa92637"
                            },
                            "type": "artifact"
                        },
                        "6": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:24.450999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Sec-Fetch-Mode": "navigate",
                                        "Sec-Fetch-User": "?1",
                                        "Upgrade-Insecure-Requests": "1",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/cortex/xsoar"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "5",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "public, max-age=900",
                                        "content-encoding": "gzip",
                                        "content-type": "text/html; charset=UTF-8",
                                        "date": "Wed, 10 Mar 2021 16:58:24 GMT",
                                        "etag": "\"9da6c-5bd22a9f261da-gzip\"",
                                        "expires": "Wed, 10 Mar 2021 17:13:24 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:11:01 GMT",
                                        "link": "<https://www.paloaltonetworks.com/etc/clientlibs/clean/dependencies/fonts/merriweather/merriweather-v21-latin-700.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://www.paloaltonetworks.com/etc/clientlibs/clean/dependencies/fonts/merriweather/merriweather-v21-latin-300.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin\n<https://www.paloaltonetworks.com/etc/clientlibs/clean/dependencies/fonts/decimal/Decimal-Semibold-Pro_Web.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://www.paloaltonetworks.com/etc/clientlibs/clean/dependencies/fonts/merriweather/merriweather-v21-latin-regular.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://www.paloaltonetworks.com/etc/clientlibs/clean/dependencies/fonts/decimal/Decimal-Medium-Pro_Web.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://www.paloaltonetworks.com/etc/clientlibs/clean/dependencies/fonts/decimal/Decimal-Bold-Pro_Web.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin\n<https://assets.adobedtm.com>;rel=\"preconnect\",<https://static.ads-twitter.com>;rel=\"preconnect\",<https://www.google-analytics.com>;rel=\"preconnect\",<https://ssl.google-analytics.com>;rel=\"preconnect\",<https://scripts.demandbase.com>;rel=\"preconnect\",<https://www.youtube.com>;rel=\"preconnect\",<https://api.company-target.com>;rel=\"preconnect\",<https://d10lpsik1i8c69.cloudfront.net>;rel=\"preconnect\"",
                                        "server": "Apache",
                                        "server-timing": "cdn-cache; desc=HIT\nedge; dur=54",
                                        "set-cookie": "AKA_A2=A; expires=Wed, 10-Mar-2021 17:58:24 GMT; path=/; domain=paloaltonetworks.com; secure; HttpOnly",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-akamai-transformed": "9 134220 0 pmb=mRUM,2",
                                        "x-frame-options": "SAMEORIGIN"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "60": {
                            "artifact_ref": "59",
                            "type": "x-wf-url-resource"
                        },
                        "61": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 36
                                }
                            },
                            "hashes": {
                                "SHA-256": "b4a638188889bb608c5aa261d80da29467b8fa38da5831961815b191952fa118"
                            },
                            "type": "artifact"
                        },
                        "62": {
                            "artifact_ref": "61",
                            "type": "x-wf-url-resource"
                        },
                        "63": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 90802
                                }
                            },
                            "hashes": {
                                "SHA-256": "d5c36e1fb25b74b826ea42d12f2ab2c064607775f1f764eb69130a293a4989f5"
                            },
                            "type": "artifact"
                        },
                        "64": {
                            "artifact_ref": "63",
                            "type": "x-wf-url-resource"
                        },
                        "65": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 109172
                                }
                            },
                            "hashes": {
                                "SHA-256": "c0eb6a59eec466557d27776cd35edacfb47f8c7d80738c4cdad5c281b5ed00d3"
                            },
                            "type": "artifact"
                        },
                        "66": {
                            "artifact_ref": "65",
                            "type": "x-wf-url-resource"
                        },
                        "67": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 128904,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "4713a4b482f93de08e2ce67cf9e40664a9ad638df1ee7809f3c0da0d20edac7f"
                            },
                            "type": "artifact"
                        },
                        "68": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:27.132999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/etc/clientlibs/clean/dependencies/swiper/swiper-4.5.3.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "67",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "br",
                                        "content-length": "29106",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:24 GMT",
                                        "etag": "W/\"1f788-5bd22aee8b4db-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:24 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:12:40 GMT",
                                        "server": "Akamai Resource Optimizer",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-akamai-http2-push": "1",
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
                        },
                        "69": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 12979,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "7564a7b763a37e6dbb2b65f950f4ccb6f1222b6b28b1989f294f9d6582fc58cf"
                            },
                            "type": "artifact"
                        },
                        "7": {
                            "type": "x-wf-url-global-variables",
                            "values": [
                                "$",
                                "$component",
                                "3eiXJRXgVuLsYGH9303q",
                                "AppMeasurement",
                                "AppMeasurement_Module_ActivityMap",
                                "BOOMR",
                                "BOOMR_API_key",
                                "BOOMR_configt",
                                "BOOMR_lstart",
                                "BOOMR_mq",
                                "BOOMR_onload",
                                "Collapse",
                                "Cookies",
                                "Coveo_organizationId",
                                "DBSegment",
                                "Demandbase",
                                "Dmdbase_CDC",
                                "Dropdown",
                                "GoogleAnalyticsObject",
                                "Granite",
                                "LO",
                                "Munchkin",
                                "MunchkinTracker",
                                "OneTrust",
                                "OnetrustActiveGroups",
                                "Optanon",
                                "OptanonActiveGroups",
                                "OptanonWrapper",
                                "PAN",
                                "PAN_AttemptRenderOfNav",
                                "PAN_Clean_Util",
                                "PAN_IS_AUTHOR",
                                "PAN_IS_RECAPTCHA_LOADED",
                                "PAN_LOAD_RECAPTCHA",
                                "PAN_LOAD_RECAPTCHA_LANGUAGE",
                                "PAN_MainNavAsyncUrl",
                                "PAN_RUN_ON_LAZY_LOAD",
                                "PAN_RunOnPageModelLoad",
                                "PAN_deferedCssList",
                                "PAN_initializeCleanNav",
                                "PAN_jsAfterDeferedCssFunctionList",
                                "PAN_renderCleanNavAccountMenu",
                                "Popper",
                                "Swiper",
                                "Tab",
                                "UET",
                                "Util",
                                "Visitor",
                                "WTW_Watcher",
                                "Waypoint",
                                "YT",
                                "YTConfig",
                                "__DRIFT_BRANCH__",
                                "__DRIFT_BUILD_ID__",
                                "__DRIFT_ENV__",
                                "___target_traces",
                                "__core-js_shared__",
                                "__db",
                                "__extends",
                                "__lo_csr_added",
                                "__lo_site_id",
                                "__post_robot_10_0_16__",
                                "__satelliteLoaded",
                                "_already_called_lintrk",
                                "_driftFrames",
                                "_fbq",
                                "_gaq",
                                "_gat",
                                "_linkedin_data_partner_id",
                                "_loq",
                                "_satellite",
                                "a",
                                "adobe",
                                "backgroundImageObserver",
                                "botSelector",
                                "buildDropdown",
                                "c",
                                "callBuyBox",
                                "captchaComplete",
                                "captchaComplete01",
                                "captchaExpired01",
                                "cbVarMap",
                                "chrome",
                                "cookieDomainObject",
                                "cookieDomainResult",
                                "coveoSearchEl",
                                "currentPageModel",
                                "dName",
                                "dataLayer",
                                "disableOverridden",
                                "drift",
                                "drift_campaign_refresh",
                                "drift_event_listeners",
                                "drift_invoked",
                                "drift_page_view_started",
                                "drift_session_id",
                                "drift_session_started",
                                "driftt",
                                "fbq",
                                "ga",
                                "gaData",
                                "gaGlobal",
                                "gaplugins",
                                "getCookie",
                                "getCookieHomeProduct",
                                "getSerializedTracking",
                                "globalConfig",
                                "google_tag_data",
                                "google_tag_manager",
                                "gtag",
                                "head",
                                "imageObserver",
                                "index",
                                "initPanCoverSearch",
                                "isCaptchaComplete01",
                                "isCom",
                                "jQuery",
                                "jQuery33100453454193236231261",
                                "jQuery35100027653193483465621",
                                "jsonFeed",
                                "languageFromPage",
                                "languageFromPath",
                                "lintrk",
                                "lity",
                                "loadNewMenu",
                                "loadNewMenuAccount",
                                "loadOriginalPageLoadVars",
                                "loadScript",
                                "lozad",
                                "m",
                                "mboxCreate",
                                "mboxDefine",
                                "mboxUpdate",
                                "mktoConfig",
                                "mktoMunchkin",
                                "mktoMunchkinFunction",
                                "mobileSelector",
                                "noScriptNode",
                                "nonCriticalCss",
                                "onPlayerReady",
                                "onPlayerStateChange",
                                "onYTReady",
                                "onYouTubeIframeAPIReady",
                                "onYouTubePlayerAPIReady",
                                "players",
                                "populateCompanyData",
                                "populateLeadDetails",
                                "qevents",
                                "qp",
                                "quietConsole",
                                "rcLandingPageId",
                                "recaptchaExpired",
                                "regeneratorRuntime",
                                "s",
                                "s_c_il",
                                "s_c_in",
                                "s_gi",
                                "s_giq",
                                "s_objectID",
                                "s_pgicq",
                                "script",
                                "scriptUrl",
                                "searchResultsPagePath",
                                "setVisitorCompanyDetailsCookieHomeProduct",
                                "shortCutURL",
                                "startWorker",
                                "techDocsPagePath",
                                "trackPrefillAnalyticsForLoggedInUsers",
                                "twq",
                                "twttr",
                                "uetq",
                                "updateChangedFieldList",
                                "userHeaderModel",
                                "userHeaderModelWorker",
                                "utmparam",
                                "waypointContextKey",
                                "webData",
                                "yt",
                                "ytDomDomGetNextId",
                                "ytEventsEventsCounter",
                                "ytEventsEventsListeners",
                                "ytLoggingGelSequenceIdObj_",
                                "ytLoggingTransportGELQueue_",
                                "ytLoggingTransportTokensToCttTargetIds_",
                                "ytPubsub2Pubsub2Instance",
                                "ytPubsub2Pubsub2IsAsync",
                                "ytPubsub2Pubsub2SkipSubKey",
                                "ytPubsub2Pubsub2SubscribedKeys",
                                "ytPubsub2Pubsub2TopicToKeys",
                                "ytPubsubPubsubInstance",
                                "ytPubsubPubsubIsSynchronous",
                                "ytPubsubPubsubSubscribedKeys",
                                "ytPubsubPubsubTopicToKeys",
                                "ytglobal"
                            ]
                        },
                        "70": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:27.134999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/etc/clientlibs/pan/js/lazyload.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "69",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "br",
                                        "content-length": "3897",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:27 GMT",
                                        "etag": "W/\"32b3-5bd22af6d432c-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:27 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:12:33 GMT",
                                        "server": "Akamai Resource Optimizer",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
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
                        },
                        "71": {
                            "type": "ipv4-addr",
                            "value": "173.222.136.236"
                        },
                        "72": {
                            "resolves_to_refs": [
                                "71"
                            ],
                            "type": "domain-name",
                            "value": "assets.adobedtm.com"
                        },
                        "73": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 493939,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "bee92ae5519d0a40a1a5190e17d19ce01f8d7d7bf7773bfd640960424fa7f00f"
                            },
                            "type": "artifact"
                        },
                        "74": {
                            "dst_ref": "72",
                            "end": "2021-03-10T16:58:27.197999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/9273d4aedcd2/0d76ae0322d7/launch-425c423d843b.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "73",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "access-control-allow-origin": "https://www.paloaltonetworks.com",
                                        "cache-control": "max-age=3600",
                                        "content-encoding": "gzip",
                                        "content-length": "121404",
                                        "content-type": "application/x-javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:27 GMT",
                                        "etag": "\"445becd268d7c756d19cfbb95ab508ff:1614190925.704917\"",
                                        "expires": "Wed, 10 Mar 2021 17:58:27 GMT",
                                        "last-modified": "Wed, 24 Feb 2021 18:22:05 GMT",
                                        "server": "AkamaiNetStorage",
                                        "status": "200",
                                        "timing-allow-origin": "*",
                                        "vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "75": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 17707,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "d718c45b01eea7701ef1798152554c1f4bb2bb022427de2391a61265ed762da5"
                            },
                            "type": "artifact"
                        },
                        "76": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:27.198999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/etc/clientlibs/pan/js/prefill-leaddetails.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "75",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "br",
                                        "content-length": "1977",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:24 GMT",
                                        "etag": "W/\"452b-5bd22bf293a0c-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:24 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:17:11 GMT",
                                        "server": "Akamai Resource Optimizer",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-akamai-http2-push": "1",
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
                        },
                        "77": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 14592,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "91ab2ab1acd0eaf0a69a3409f44c41aea2a91f0b1757b3e1ad5030beaa4cb67d"
                            },
                            "type": "artifact"
                        },
                        "78": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:27.198999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/content/dam/pan/en_US/includes/attribution.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "77",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "br",
                                        "content-length": "2891",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:24 GMT",
                                        "etag": "W/\"3900-5bd22b862b49f-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:24 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:15:05 GMT",
                                        "server": "Akamai Resource Optimizer",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
                                        "x-akamai-http2-push": "1",
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
                        },
                        "79": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 20721,
                                    "sniffed_mime_type": "text/plain"
                                }
                            },
                            "hashes": {
                                "SHA-256": "fce66949bcffbd5acd83dccaad874f8b5fbc7c838e1c2d6358cb6e867f79d061"
                            },
                            "type": "artifact"
                        },
                        "8": {
                            "type": "x-wf-url-alert-messages"
                        },
                        "80": {
                            "dst_ref": "4",
                            "end": "2021-03-10T16:58:27.217Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/etc/clientlibs/clean/panClean/productDetails/defered.min.js"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "79",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "cache-control": "max-age=172800",
                                        "content-encoding": "br",
                                        "content-length": "5296",
                                        "content-type": "application/javascript",
                                        "date": "Wed, 10 Mar 2021 16:58:29 GMT",
                                        "etag": "W/\"50f1-5bd22c3c734b5-gzip\"",
                                        "expires": "Fri, 12 Mar 2021 16:58:29 GMT",
                                        "last-modified": "Tue, 09 Mar 2021 23:18:21 GMT",
                                        "server": "Akamai Resource Optimizer",
                                        "server-timing": "cdn-cache; desc=HIT, edge; dur=1",
                                        "status": "200",
                                        "strict-transport-security": "max-age=15811200",
                                        "vary": "Accept-Encoding",
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
                        },
                        "81": {
                            "type": "ipv4-addr",
                            "value": "23.206.164.135"
                        },
                        "82": {
                            "resolves_to_refs": [
                                "81"
                            ],
                            "type": "domain-name",
                            "value": "s.go-mpulse.net"
                        },
                        "83": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 207040,
                                    "sniffed_mime_type": "text/x-c"
                                }
                            },
                            "hashes": {
                                "SHA-256": "95a439c4e11ace2484e8d42c30ff56cf7db5ea7c6463df9ce2fdafa7f6ccbf54"
                            },
                            "type": "artifact"
                        },
                        "84": {
                            "dst_ref": "82",
                            "end": "2021-03-10T16:58:29.496Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "no-cors",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/boomerang/6KU9W-5DTLL-AXSJY-VNWUZ-RTS7Q"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "83",
                                    "response_code": 200,
                                    "response_header": {
                                        "cache-control": "max-age=604800",
                                        "content-encoding": "br",
                                        "content-length": "51580",
                                        "content-type": "application/javascript; charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:29 GMT",
                                        "last-modified": "Sun, 27 Dec 2020 09:35:04 GMT",
                                        "status": "200",
                                        "timing-allow-origin": "*",
                                        "vary": "Accept-Encoding"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "85": {
                            "type": "ipv4-addr",
                            "value": "199.232.9.186"
                        },
                        "86": {
                            "resolves_to_refs": [
                                "85"
                            ],
                            "type": "domain-name",
                            "value": "my.matterport.com"
                        },
                        "87": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 26862,
                                    "sniffed_mime_type": "text/html"
                                }
                            },
                            "hashes": {
                                "SHA-256": "eb45f4dd12238b60318220efb7759ac4e395355e57a31e8fc782de106ab9d699"
                            },
                            "type": "artifact"
                        },
                        "88": {
                            "dst_ref": "86",
                            "end": "2021-03-10T16:58:29.497999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_header": {
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "Referer": "https://www.paloaltonetworks.com/cortex/xsoar",
                                        "Sec-Fetch-Mode": "nested-navigate",
                                        "Upgrade-Insecure-Requests": "1",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
                                    },
                                    "request_method": "get",
                                    "request_value": "/show/?m=q3s3ktjhjC9&brand=0"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "87",
                                    "response_code": 200,
                                    "response_header": {
                                        "accept-ranges": "bytes",
                                        "age": "37651",
                                        "allow": "GET, HEAD, OPTIONS",
                                        "cache-control": "private, no-store, must-revalidate",
                                        "content-encoding": "gzip",
                                        "content-length": "6819",
                                        "content-type": "text/html; charset=utf-8",
                                        "date": "Wed, 10 Mar 2021 16:58:29 GMT",
                                        "status": "200",
                                        "strict-transport-security": "max-age=31536000",
                                        "vary": "Accept-Encoding, Origin, X-Forwarded-Host, X-Backend",
                                        "x-cache": "HIT, HIT",
                                        "x-cache-hits": "1, 1",
                                        "x-content-type-options": "nosniff",
                                        "x-request-id": "dc9b5f7d8bf852a90c15535929b18dc23083a87e",
                                        "x-served-by": "cache-bwi5168-BWI, cache-dal21226-DAL",
                                        "x-timer": "S1615395510.531616,VS0,VE1",
                                        "x-xss-protection": "1; mode=block"
                                    }
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "89": {
                            "type": "x-wf-url-global-variables",
                            "values": [
                                "MP_PREFETCHED_MODELDATA",
                                "MP_SDK",
                                "THREE",
                                "chrome",
                                "detailObject",
                                "mpBrowserCheck",
                                "profilingData",
                                "webpackChunkcwf_applications"
                            ]
                        },
                        "9": {
                            "type": "url",
                            "value": "https://www.paloaltonetworks.com/cortex/xsoar"
                        },
                        "90": {
                            "type": "url",
                            "value": "https://my.matterport.com/show/?m=q3s3ktjhjC9&brand=0"
                        },
                        "91": {
                            "global_variable_refs": [
                                "89"
                            ],
                            "is_main": false,
                            "observed_alert_refs": [
                                "8"
                            ],
                            "request_ref": "88",
                            "type": "x-wf-url-page-frame",
                            "url_ref": "90"
                        },
                        "92": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 224
                                }
                            },
                            "hashes": {
                                "SHA-256": "ce59cb63c0c65971204ecb88fa86435833137890cc08bdbe2d4e30ad0c141681"
                            },
                            "type": "artifact"
                        },
                        "93": {
                            "artifact_ref": "92",
                            "type": "x-wf-url-resource"
                        },
                        "94": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 21778
                                }
                            },
                            "hashes": {
                                "SHA-256": "414c385f47f1768b11b973965109ce03d76f7c67ffd1bd6bbd3bad0153b1b9b3"
                            },
                            "type": "artifact"
                        },
                        "95": {
                            "artifact_ref": "94",
                            "type": "x-wf-url-resource"
                        },
                        "96": {
                            "type": "domain-name",
                            "value": "www.paloaltonetworks.com"
                        },
                        "97": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 492
                                }
                            },
                            "hashes": {
                                "SHA-256": "79655440e7b5e5f4bbe63f4a9135b6ce3e5ebff35f136ceea8229adee029a1d2"
                            },
                            "type": "artifact"
                        },
                        "98": {
                            "dst_ref": "96",
                            "end": "2021-03-10T16:58:29.566999Z",
                            "extensions": {
                                "http-request-ext": {
                                    "request_method": "get",
                                    "request_value": "/apps/pan/public/userHeaderModel"
                                },
                                "x-wf-http-response-ext": {
                                    "message_body_data_ref": "97",
                                    "response_code": 200
                                }
                            },
                            "protocols": [
                                "ipv4",
                                "tcp",
                                "https"
                            ],
                            "type": "network-traffic"
                        },
                        "99": {
                            "extensions": {
                                "x-wf-content-description": {
                                    "content_size_bytes": 109172
                                }
                            },
                            "hashes": {
                                "SHA-256": "f09b678c75e9a3f946c82f25b0db0c675c8889b060b929ceb778edc710c7f57e"
                            },
                            "type": "artifact"
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


