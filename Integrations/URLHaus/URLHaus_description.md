## Overview
---

URLhaus has the goal of sharing malicious URLs that are being used for malware distribution.
This integration was integrated and tested with version xx of URLhaus
## URLhaus Playbook
---

## Use Cases
---

## Configure URLhaus on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for URLhaus.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://192.168.0.1)__
    * __Trust any certificate (unsecure)__
    * __Use system proxy__
    * __Blacklists appearances threshold__
    * __Compromised is malicious__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. url
2. domain
3. file
4. urlhaus-download-sample
### 1. url
---
Retrieve URL information from URLhaus
##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to query | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL | 
| URL.Malicious.Vendor | string | Vendor reporting the malicious status | 
| URL.Malicious.Description | string | Description of the malicious url | 
| URLhaus.URL.ID | string | Unique idendifier of the URLhaus database entry | 
| URLhaus.URL.Status | string | The current status of the URL. | 
| URLhaus.URL.Host | string | The extracted host of the malware URL (IP address or domain name/FQDN) | 
| URLhaus.URL.DateAdded | date | Date the URL was added to URLHaus | 
| URLhaus.URL.Threat | string | The threat corresponding to this malware URL. | 
| URLhaus.URL.Blacklist.Name | String | Name of the blacklist | 
| URLhaus.URL.Tags | string | A list of tags associated with the queried malware URL. | 
| URLhaus.URL.Payload.Name | String | Payload file name | 
| URLhaus.URL.Payload.Type | String | Payload file type | 
| URLhaus.URL.Payload.MD5 | String | MD5 hash of the HTTP response body (payload) | 
| URLhaus.URL.Payload.VT.Result | Number | Results from Virustotal about the payload | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| DBotScore.Indicator | string | The indicator that was tested | 
| URLhaus.URL.Blacklist.Status | String | Status of the URL in the blacklist | 
| URLhaus.URL.Payload.VT.Link | String | Link to the VT report | 


##### Command Example
```!url url="http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"```

##### Human Readable Output


### 2. domain
---
Retrieve domain information from URLhaus
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | domain to query | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name e.g. google.com | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| DBotScore.Indicator | string | The indicator that was tested | 
| URLhaus.Domain.FirstSeen | Date | When the IP was seen for the first time (UTC) | 
| URLhaus.Domain.Blacklist.Name | String | The status of the domain in different blacklists | 
| URLhaus.Domain.URL | String | URLs observed on this domain | 
| Domain.Malicious.Vendor | String | Vendor reporting the malicious status | 
| Domain.Malicious.Description | String | Description of the malicious domain | 
| URLhaus.Domain.Blacklist.Status | String | Status of the URL in the blacklist | 


##### Command Example
```!domain domain="vektorex.com"```

##### Human Readable Output


### 3. file
---
Retrieve file information from URLhaus
##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | MD5 or SHA256 of the file to query | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | Size of the file in bytes | 
| File.MD5 | String | MD5 Hash of the file | 
| File.SHA256 | String | SHA256 hash of the file | 
| URLhaus.File.MD5 | String | MD5 Hash of the file | 
| URLhaus.File.SHA256 | String | SHA256 hash of the file | 
| URLhaus.File.Type | String | File type guessed by URLhaus (e.g. exe, doc, etc) | 
| URLhaus.File.Size | Number | File size in bytes | 
| URLhaus.File.Signature | String | Malware familiy | 
| URLhaus.File.FirstSeen | Date | UTC time when URLhaus has first seen this file (payload) | 
| URLhaus.File.LastSeen | Date | UTC time when URLhaus has last seen this file (payload) | 
| URLhaus.File.DownloadLink | String | Location (URL) where you can download a copy of this file | 
| URLhaus.File.VirusTotal.Percent | Number | AV detection in percent (e.g. 24.14) | 
| URLhaus.File.VirusTotal.Link | String | Link to the Virustotal report | 
| URLhaus.File.URL | Unknown | A list of malware URLs associated with this payload (max 100) | 


##### Command Example
```!file hash="01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b01" hash_type="SHA256"```

##### Human Readable Output


### 4. urlhaus-download-sample
---
Download a malware sample from URLhaus
##### Base Command

`urlhaus-download-sample`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The sha256 of the file to download | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size | 
| File.SHA1 | string | File sha1 | 
| File.SHA256 | string | File sha256 | 
| File.Name | string | File name | 
| File.SSDeep | string | File SSDeep | 
| File.EntryID | string | File entry ID | 
| File.Info | string | File information | 
| File.Type | string | File type | 
| File.MD5 | string | File md5 | 
| File.Extension | string | File extension | 


##### Command Example
```!urlhaus-download-sample file="254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b"```

##### Human Readable Output


## Additional Information
---
DBot score calculations work as follows:
A URL or domain can appear in a blacklist as either one of:
1. Malicious - if the site is a known malware site.
2. Compromised - if the site is legitimate but has been compromised.
3. Not listed.

If the parameter 'compromised_is_malicious' is True, then we treat compromised URLs/domains as malicious ones.
Otherwise - we treat them as if they were legitimate.

Counting the appearances of the URL/domain in the blacklists, it is considered bad if the total count exceeded the 'threshold' parameter.
If the URL/domain appeared in at least one blacklist, but not enough blacklists to exceed the threshold, it is considered suspicious.
If it didn't appear in any blacklist it is considered good.
If there is no data about the URL/domain - it doesn't get a DBot score (0).

## Known Limitations
---

## Troubleshooting
--- 