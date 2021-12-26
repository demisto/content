URLhaus has the goal of sharing malicious URLs that are being used for malware distribution.

## Configure URLhaus on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for URLhaus.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://192.168.0.1) |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Blacklists appearances threshold |  | False |
    | Compromised (is malicious) |  | False |
    | Number of retries | Determines how many times a command should be retried before raising an error. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
Retrieves URL information from URLhaus.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to query. Vendor does not support non-latin characters. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL. Cannot contain non-latin characters. | 
| URL.Malicious.Vendor | string | Vendor that reported the URL as malicious. | 
| URL.Malicious.Description | string | Description of the malicious URL. | 
| URLhaus.URL.ID | string | Unique identifier of the URLhaus database entry. | 
| URLhaus.URL.Status | string | The current status of the URL. | 
| URLhaus.URL.Host | string | The extracted host of the malware URL \(IP address or domain name/FQDN\). | 
| URLhaus.URL.DateAdded | date | Date the URL was added to URLhaus. | 
| URLhaus.URL.Threat | string | The threat corresponding to this malware URL. | 
| URLhaus.URL.Blacklist.Name | String | Name of the block list. | 
| URLhaus.URL.Tags | string | A list of tags associated with the queried malware URL. | 
| URLhaus.URL.Payload.Name | String | Payload file name. | 
| URLhaus.URL.Payload.Type | String | Payload file type. | 
| URLhaus.URL.Payload.MD5 | String | MD5 hash of the HTTP response body \(payload\). | 
| URLhaus.URL.Payload.VT.Result | Number | VirusTotal results for the payload. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URLhaus.URL.Blacklist.Status | String | Status of the URL in the block list. | 
| URLhaus.URL.Payload.VT.Link | String | Link to the VirusTotal report. | 


#### Command Example
```!url url="http://example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "url",
        "Vendor": "URLhaus"
    },
    "URL": {
        "Data": "http://example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"
    },
    "URLhaus": {
        "URL": {
            "Blacklist": [
                {
                    "Name": "spamhaus_dbl",
                    "Status": "not listed"
                },
                {
                    "Name": "surbl",
                    "Status": "not listed"
                }
            ],
            "DateAdded": "2019-01-19T01:33:26",
            "Host": "example.com",
            "ID": "105821",
            "Payload": [
                {
                    "MD5": "cf6bc359bc8a667c1b8d241e9591f392",
                    "Name": "676860772178.doc",
                    "Type": "doc",
                    "VT": {
                        "Link": "https://www.example.com/file/72820698de9b69166ab226b99ccf70f3f58345b88246f7d5e4e589c21dd44435/analysis/1547876224/",
                        "Result": 31.03
                    }
                },
                {
                    "MD5": "aa713b461bd1a4bc07aba59475c9e2b1",
                    "Name": "PAY845086736936754.doc",
                    "Type": "doc",
                    "VT": null
                },
                {
                    "MD5": "a7342ea622b093753ee6177a94212613",
                    "Name": "36985490218.doc",
                    "Type": "doc",
                    "VT": {
                        "Link": "https://www.example.com/file/a0ccb310c7ec618ab516be8b95923254a6724b1a03696ec6dbb6e47c60321391/analysis/1547845755/",
                        "Result": 21.82
                    }
                }                
            ],
            "Status": "offline",
            "Tags": [
                "emotet",
                "epoch2",
                "heodo"
            ],
            "Threat": "malware_download"
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for http:<span>//</span>example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/
>|Date added|Description|Status|Threat|URLhaus ID|URLhaus link|
>|---|---|---|---|---|---|
>| 2019-01-19T01:33:26 | Not listed in any block list | offline | malware_download | 105821 | https:<span>//</span>urlhaus.abuse.ch/url/105821/ |


### domain
***
Retrieves domain information from URLhaus.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example, google.com. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URLhaus.Domain.FirstSeen | Date | Date that the IP was seen for the first time \(UTC\). | 
| URLhaus.Domain.Blacklist.Name | String | The status of the domain in different block lists. | 
| URLhaus.Domain.URL | String | URLs observed on this domain. | 
| Domain.Malicious.Vendor | String | Vendor that reported the domain as malicious. | 
| Domain.Malicious.Description | String | Description of the malicious domain. | 
| URLhaus.Domain.Blacklist.Status | String | Status of the URL in the block list. | 


#### Command Example
```!domain domain="example.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "domain",
        "Vendor": "URLhaus"
    },
    "Domain": {
        "Name": "example.com"
    },
    "URLhaus": {
        "Domain": {
            "Blacklist": {
                "spamhaus_dbl": "not listed",
                "surbl": "not listed"
            },
            "FirstSeen": "2019-01-15T07:09:01",
            "URL": [
                {
                    "date_added": "2019-02-14 18:02:23 UTC",
                    "id": "124617",
                    "larted": "true",
                    "reporter": "JayTHL",
                    "tags": [
                        "Loki"
                    ],
                    "takedown_time_seconds": "46393",
                    "threat": "malware_download",
                    "url": "http://example.com/jobs/cgi/86010322.jpg",
                    "url_status": "offline",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/example/"
                },
                {
                    "date_added": "2019-02-14 06:39:08 UTC",
                    "id": "124195",
                    "larted": "true",
                    "reporter": "abuse_ch",
                    "tags": [
                        "AZORult",
                        "exe"
                    ],
                    "takedown_time_seconds": "1681",
                    "threat": "malware_download",
                    "url": "http://example.com/jobs/cgi/25061013.png",
                    "url_status": "offline",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/example/"
                }               
            ]
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for example.com
>|Description|First seen|URLhaus link|
>|---|---|---|
>| Not listed in any block list | 2019-01-15T07:09:01 | https:<span>//</span>urlhaus.abuse.ch/host/example.com/ |


### file
***
Retrieves file information from URLhaus.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | MD5 hash or SHA256 hash of the file to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | File size \(in bytes\). | 
| File.MD5 | String | MD5 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| URLhaus.File.MD5 | String | MD5 hash of the file. | 
| URLhaus.File.SHA256 | String | SHA256 hash of the file. | 
| URLhaus.File.Type | String | File type guessed by URLhaus, for example: .exe, .doc. | 
| URLhaus.File.Size | Number | File size \(in bytes\). | 
| URLhaus.File.Signature | String | Malware family. | 
| URLhaus.File.FirstSeen | Date | Date and time \(UTC\) that URLhaus first saw this file \(payload\). | 
| URLhaus.File.LastSeen | Date | Date and time \(UTC\) that URLhaus last saw this file \(payload\). | 
| URLhaus.File.DownloadLink | String | Location \(URL\) where you can download a copy of this file. | 
| URLhaus.File.VirusTotal.Percent | Number | AV detection \(percentage\), for example: 24.14. | 
| URLhaus.File.VirusTotal.Link | String | Link to the VirusTotal report. | 
| URLhaus.File.URL | Unknown | A list of malware URLs associated with this payload \(max. 100\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 


#### Command Example
```!file file="254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b"```

#### Context Example
```json
{
    "File": {
        "MD5": "a820381c8acf07cfcb4d9b13498db71d",
        "SHA256": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
        "Size": 125952
    },
    "URLhaus": {
        "File": {
            "DownloadLink": "https://urlhaus-api.abuse.ch/v1/download/254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b/",
            "FirstSeen": "2019-01-02T12:42:23",
            "LastSeen": "2019-01-02T13:13:25",
            "MD5": "a820381c8acf07cfcb4d9b13498db71d",
            "SHA256": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
            "Signature": "Gozi",
            "Size": 125952,
            "Type": "exe",
            "URL": [
                {
                    "filename": null,
                    "firstseen": "2019-01-02",
                    "lastseen": "2019-01-02",
                    "url": "http://185.189.149.164/adobe_update.exe",
                    "url_id": "100211",
                    "url_status": "offline",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/example/"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for SHA256 : 254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b
>|First seen|Last seen|MD5|SHA256|Signature|URLhaus link|
>|---|---|---|---|---|---|
>| 2019-01-02T12:42:23 | 2019-01-02T13:13:25 | a820381c8acf07cfcb4d9b13498db71d | 254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b | Gozi | https://urlhaus-api.abuse.ch/v1/download/254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b/ |


### urlhaus-download-sample
***
Downloads a malware sample from URLhaus.


#### Base Command

`urlhaus-download-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | SHA256 hash of the file to download. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Name | string | File name. | 
| File.SSDeep | string | SSDeep hash of the file. | 
| File.EntryID | string | File entry ID. | 
| File.Info | string | File information. | 
| File.Type | string | File type. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.Extension | string | File extension. | 


#### Command Example
```!urlhaus-download-sample file=254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b using-brand=URLhaus```

#### Context Example
```json
{
    "File": {
        "EntryID": "147@ed06aeb1-14fd-47b4-8369-e1f0cbdcde56",
        "Info": "application/x-dosexec",
        "MD5": "a820381c8acf07cfcb4d9b13498db71d",
        "Name": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
        "SHA1": "15a6cc5c894986aa8079ba0a07ce99778dd57db1",
        "SHA256": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
        "SHA512": "f2c2d1f99286ea4c34d3dcab93aa61ea2b5956d35f928569c3be15f8aefa96aec3e9328c36a4cf3d252c56db5b110325effd0f4dd642c9fe1839fc1268a74d94",
        "SSDeep": "1536:HL8ZkobQKXYG8I9WHVIIVLfldAjoaEgnell/SYkq59L48eKq0P:gnIHVxtsjp5s/7kq59MP0",
        "Size": 125952,
        "Type": "PE32 executable (GUI) Intel 80386, for MS Windows"
    }
}
```