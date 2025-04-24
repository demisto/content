URLhaus shares malicious URLs that are being used for malware distribution.
This integration was integrated and tested with version v1 of URLhaus.

## Configure URLhaus in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://192.168.0.1) |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Create relationships |  | False |
| Maximum number of relationships to fetch per indicator | Maximal value is 1000. | False |
| Blacklists appearances threshold |  | False |
| Compromised (is malicious) |  | False |
| Number of retries | Determines how many times a command should be retried before raising an error. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
Retrieves URL information from URLhaus.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL. | 
| URL.Malicious.Vendor | string | Vendor that reported the URL as malicious. | 
| URL.Malicious.Description | string | Description of the malicious URL. | 
| URL.Tags | string | A list of tags associated with the queried malware URL. | 
| URL.Relationships.EntityA | String | The source of the relationship. | 
| URL.Relationships.EntityB | String | The destination of the relationship. | 
| URL.Relationships.Relationship | String | The name of the relationship. | 
| URL.Relationships.EntityAType | String | The type of the source of the relationship. | 
| URL.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| URLhaus.URL.ID | String | Unique identifier of the URLhaus database entry. | 
| URLhaus.URL.Status | String | The current status of the URL. | 
| URLhaus.URL.Host | String | The extracted host of the malware URL \(IP address or domain name/FQDN\). | 
| URLhaus.URL.DateAdded | date | Date the URL was added to URLhaus. | 
| URLhaus.URL.Threat | String | The threat corresponding to this malware URL. | 
| URLhaus.URL.Blacklist.Name | String | Name of the block list. | 
| URLhaus.URL.Tags | String | A list of tags associated with the queried malware URL. | 
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

#### Command example
```!url using-brand=URLhaus url=http://example.com/anklet/WQG1/?i=1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://example.com/anklet/WQG1/?i=1",
        "Reliability": "C - Fairly reliable",
        "Score": 2,
        "Type": "url",
        "Vendor": "URLhaus"
    },
    "URL": {
        "Data": "http://example.com/anklet/WQG1/?i=1",
        "Relationships": [
            {
                "EntityA": "http://example.com/anklet/WQG1/?i=1",
                "EntityAType": "URL",
                "EntityB": "example.com",
                "EntityBType": "Domain",
                "Relationship": "hosted-on"
            }
        ],
        "Tags": [
            "doc",
            "emotet",
            "epoch5",
            "heodo",
            "malware_download"
        ]
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
            "DateAdded": "2022-01-20T14:11:09",
            "Host": "example.com",
            "ID": "1992762",
            "Payload": [
                {
                    "MD5": "716c3aa1e0da98b6e99cadd60363ae7e",
                    "Name": "BC-77388.xlsm",
                    "SHA256": "64c6ba33444e5db3cc9c99613d04fd163ec1971ee5eb90041a17068e37578fc0",
                    "Type": "xls",
                    "VT": null
              }
            ],
            "Status": "offline",
            "Tags": [
                "doc",
                "emotet",
                "epoch5",
                "heodo",
                "malware_download"
            ],
            "Threat": "malware_download"
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for http:<span>//</span>example.com/anklet/WQG1/?i=1
>|Date added|Description|Status|Threat|URLhaus ID|URLhaus link|
>|---|---|---|---|---|---|
>| 2022-01-20T14:11:09 | The URL is inactive (offline) and serving no payload | offline | malware_download | 1992762 | https:<span>//</span>urlhaus.abuse.ch/url/1992762/ |


### domain
***
Retrieves domain information from URLhaus.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example, google.com. | 
| Domain.Tags | string | A list of tags associated with the queried malware Domain. | 
| Domain.Relationships.EntityA | String | The source of the relationship. | 
| Domain.Relationships.EntityB | String | The destination of the relationship. | 
| Domain.Relationships.Relationship | String | The name of the relationship. | 
| Domain.Relationships.EntityAType | String | The type of the source of the relationship. | 
| Domain.Relationships.EntityBType | String | The type of the destination of the relationship. | 
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

#### Command example
```!domain using-brand=URLhaus domain=example.com```
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
        "Name": "example.com",
        "Relationships": [
            {
                "EntityA": "example.com",
                "EntityAType": "Domain",
                "EntityB": "http://example.com:443/wp-content/plugins/wp-roilbask/includes/",
                "EntityBType": "URL",
                "Relationship": "hosts"
            }
        ],
        "Tags": [
            "abused_legit_malware"
        ]
    },
    "URLhaus": {
        "Domain": {
            "Blacklist": {
                "spamhaus_dbl": "abused_legit_malware",
                "surbl": "not listed"
            },
            "FirstSeen": "2022-01-27T12:51:03",
            "URL": [
                {
                    "date_added": "2022-01-28 04:41:03 UTC",
                    "id": "2010874",
                    "larted": "false",
                    "reporter": "Cryptolaemus1",
                    "tags": [
                        "IcedID"
                    ],
                    "takedown_time_seconds": null,
                    "threat": "malware_download",
                    "url": "http://example.com:443/wp-content/plugins/wp-roilbask/includes/",
                    "url_status": "offline",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/2010874/"
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
>| There is no information about Domain in the blacklist | 2022-01-27T12:51:03 | https:<span>//</span>urlhaus.abuse.ch/host/example.com/ |


### file
***
Retrieves file information from URLhaus.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of MD5 or SHA256 hashes of the file to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | File size \(in bytes\). | 
| File.MD5 | String | MD5 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.SSDeep | String | SSDeep of the file. | 
| File.Type | String | Type of the file. | 
| File.Relationships.EntityA | String | The source of the relationship. | 
| File.Relationships.EntityB | String | The destination of the relationship. | 
| File.Relationships.Relationship | String | The name of the relationship. | 
| File.Relationships.EntityAType | String | The type of the source of the relationship. | 
| File.Relationships.EntityBType | String | The type of the destination of the relationship. | 
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

#### Command example
```!file using-brand=URLhaus file=7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "URLhaus"
    },
    "File": {
        "Malicious": {
            "Description": "This file is malicious",
            "Vendor": "URLhaus"
        },
        "Relationships": [
            {
                "EntityA": "7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89",
                "EntityAType": "File",
                "EntityB": "BazaLoader",
                "EntityBType": "Malware",
                "Relationship": "indicator-of"
            }
        ],
        "SHA256": "7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89",
        "SSDeep": "24576:la1QHwgJMrQqj/wAc6QORNx2nAjwkaMm0GV9igWwlnwXQBwfalj21X4GtZ+FdnZ8:vH5qloBMd8A",
        "Type": "dll"
    },
    "URLhaus": {
        "File": {
            "DownloadLink": "https://urlhaus-api.abuse.ch/v1/download/7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89/",
            "FirstSeen": "2022-01-18T11:18:31",
            "LastSeen": "2022-01-28T09:36:21",
            "MD5": "2ff9cce7a08215ded0945de5965d2a0a",
            "SHA256": "7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89",
            "Signature": "BazaLoader",
            "Size": 1816064,
            "Type": "dll",
            "URL": [
                {
                    "filename": "DH-1643319814.xll",
                    "firstseen": "2022-01-27",
                    "lastseen": null,
                    "url": "http://www.example.com/wp-content/plugins/wp-roilbask/includes/",
                    "url_id": "2009726",
                    "url_status": "online",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/2009726/"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for SHA256 : 7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89
>|First seen|Last seen|MD5|SHA256|Signature|URLhaus link|
>|---|---|---|---|---|---|
>| 2022-01-18T11:18:31 | 2022-01-28T09:36:21 | 2ff9cce7a08215ded0945de5965d2a0a | 7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89 | BazaLoader | https://urlhaus-api.abuse.ch/v1/download/7855068e0cfb093ab9be9ec172676e3c119e16511f3d631d715a4e77ddad9d89/ |


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

#### Command example
```!urlhaus-download-sample file=254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b```
#### Human Readable Output

>```
>{
>    "HumanReadable": "No results for SHA256: 254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
>    "HumanReadableFormat": "markdown",
>    "Type": 1
>}
>```