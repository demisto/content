URLhaus has the goal of sharing malicious URLs that are being used for malware distribution.
This integration was integrated and tested with version xx of URLhaus

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
    | Create relationships |  | False |
    | Maximum number of relationships to fetch per indicator | Maximum relationships to display\(Max 1000\). | False |
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
| url | URL to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL. | 
| URL.Malicious.Vendor | string | Vendor that reported the URL as malicious. | 
| URL.Malicious.Description | string | Description of the malicious URL. | 
| URL.Tags | string | A list of tags associated with the queried malware URL. | 
| URL.Relationships | Unknown | A list of Relationships associated with the queried malware URL\(Optional on configurtion\). | 
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
```!url using-brand=URLhaus url=http://example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "url",
        "Vendor": "URLhaus"
    },
    "URL": {
        "Data": "http://example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"
    }
}
```

#### Human Readable Output

>## URLhaus reputation for http:<span>//</span>example.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/
>No results!

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
| Domain.Tags | string | A list of tags associated with the queried malware Domain. | 
| Domain.Relationships | Unknown | A list of Relationships associated with the queried malware Domain\(Optional on configurtion\). | 
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
        "Score": 0,
        "Type": "domain",
        "Vendor": "URLhaus"
    },
    "Domain": {
        "Name": "example.com"
    }
}
```

#### Human Readable Output

>## URLhaus reputation for example.com
>No results!

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
| File.SSDeep | string | SSDeep of the file. | 
| File.Type | stringd | Type of the file. | 
| File.Relationships | Unknown | A list of Relationships associated with the queried malware file\(Optional on configurtion\). | 
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
```!file using-brand=URLhaus file=b5cf68c7cb5bb2d21d60bf6654926f61566d95bfd7c9f9e182d032f1da5b4601```
#### Human Readable Output

>## URLhaus reputation for SHA256 : b5cf68c7cb5bb2d21d60bf6654926f61566d95bfd7c9f9e182d032f1da5b4601
>No results!

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
