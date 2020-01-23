## Overview
---

IBM X-Force Exchange lets you receive threat intelligence about applications, IP addresses, URls and hashes
This integration was integrated and tested with version xx of XFE_v2
## XFE_v2 Playbook
---

## Use Cases
---

## Configure XFE_v2 on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for XFE_v2.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://api.xforce.ibmcloud.com)__
    * __API Key__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __IP Threshold. Minimum risk score for the IP to be consodered malicious (ranges from 1 to 10).__
    * __URL Threshold. Minimum risk score for the URL to be consodered malicious (ranges from 1 to 10).__
    * __CVE Threshold. Minimum risk score for the URL to be consodered malicious (ranges from 1 to 10).__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. ip
2. url
3. file
4. domain
5. cve-search
6. cve-latest
7. xfe-whois
8. xfe-search-cves
### 1. ip
---
IP to check
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP to check | Required | 
| threshold | score treshold  | Optional | 
| long | Should we return full response | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | Unknown | Bad IP found | 
| IP.Malicious.Vendor | Unknown | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | Unknown | For malicious IPs, the reason for the vendor to make the decision | 
| IP.Malicious.Score | Unknown | For malicious IPs, the score from the vendor | 
| DBotScore.Indicator | Unknown | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | Unknown | Vendor used to calculate the score | 
| DBotScore.Score | Unknown | The actual score | 
| XFE.IP(obj.Address==val.Address).Reason | String | The reason for the given score from X-Force Exchange | 
| XFE.IP(obj.Address==val.Address).Reasondescription | String | Additional details of the score's reason | 
| XFE.IP(obj.Address==val.Address).Subnets | Unknown | The subnets of the IP | 


##### Command Example
``` ```

##### Human Readable Output


### 2. url
---
Check the given URL reputation
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threshold | If the score is above the given threshold, will be considered malicious. If threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. | Optional | 
| long | Should we return full response with detected malware on the URLs | Optional | 
| url | The URL to check | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL(obj.Data==val.Data).Data | String | The given URL from the user | 
| URL(obj.Data==val.Data).Malicious.Vendor | String | For malicious URLs, the vendor that made the decision | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
``` ```

##### Human Readable Output


### 3. file
---
Check file reputation
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file hash md5/sha1/sha256 to check | Required | 
| long | Should we return full response | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | Bad hash MD5 | 
| File.SHA1 | String | Bad hash SHA1 | 
| File.SHA256 | String | Bad hash SHA256 | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision | 
| File.Malicious.Description | String | For malicious files, the reason for the vendor to make the decision | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| XFE.File.CnCServers | Unknown | C&C servers related to the given file | 
| XFE.File.emails | Unknown | Emails related to the given file | 
| XFE.File.downloadServers | Unknown | Download servers related to the given file | 
| XFE.File.subjects | Unknown | Subjects related to the given file | 
| XFE.File.external | Unknown | Additional information about the given file | 


##### Command Example
``` ```

##### Human Readable Output


### 4. domain
---
Check domain reputation
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check | Required | 
| threshold | If the score is above the given threshold, will be considered malicious. If threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. | Optional | 
| long | Should we return full response | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL(obj.Data==val.Data).Data | String | Bad URLs found | 
| URL(obj.Data==val.Data).Malicious.Vendor | String | For malicious URLs, the vendor that made the decision | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
``` ```

##### Human Readable Output


### 5. cve-search
---
Search for details about the given CVE
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`cve-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The cve to search for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE(obj.ID==val.ID).ID | String | The ID of the CVE | 
| CVE(obj.ID==val.ID).CVSS | String | The CVSS of the CVE | 
| CVE(obj.ID==val.ID).Published | Date | The date this was published | 
| CVE(obj.ID==val.ID).Description | Unknown | The CVE description | 
| XFE.CVE(obj.ID==val.ID).Xfdbid | String | The XFBID of the CVE | 
| XFE.CVE(obj.ID==val.ID).RiskLevel | Number | The risk level of the CVE | 
| XFE.CVE(obj.ID==val.ID).Reported | Date | The reported date of the CVE | 
| XFE.CVE(obj.ID==val.ID).Cvss | Unknown | The CVSS information of the CVE | 
| XFE.CVE(obj.ID==val.ID).Stdcode | Unknown | The CVE stdcodes | 
| XFE.CVE(obj.ID==val.ID).Title | String | the title of the CVE | 
| XFE.CVE(obj.ID==val.ID).Description | String | The description of the CVE | 
| XFE.CVE(obj.ID==val.ID).PlatformsAffected | Unknown | The affetcted platforms due to the CVE | 
| XFE.CVE(obj.ID==val.ID).Exploitability | String | The exploitability of the CVE. | 


##### Command Example
``` ```

##### Human Readable Output


### 6. cve-latest
---
Return the latest vulnerabilities found
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`cve-latest`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of results to return | Optional | 
| start_date | The start of the date range for searching | Optional | 
| end_date | The end of the date range for searching | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE(obj.ID==val.ID).ID | String | The ID of the CVE | 
| CVE(obj.ID==val.ID).CVSS | String | The CVSS of the CVE | 
| CVE(obj.ID==val.ID).Published | Date | The date this was published | 
| CVE(obj.ID==val.ID).Description | Unknown | The CVE description | 
| XFE.CVE(obj.ID==val.ID).Xfdbid | String | The XFBID of the CVE | 
| XFE.CVE(obj.ID==val.ID).RiskLevel | Number | The risk level of the CVE | 
| XFE.CVE(obj.ID==val.ID).Reported | Date | The reported date of the CVE | 
| XFE.CVE(obj.ID==val.ID).Cvss | Unknown | The CVSS information of the CVE | 
| XFE.CVE(obj.ID==val.ID).Stdcode | Unknown | The CVE stdcodes | 
| XFE.CVE(obj.ID==val.ID).Title | String | the title of the CVE | 
| XFE.CVE(obj.ID==val.ID).Description | String | The description of the CVE | 
| XFE.CVE(obj.ID==val.ID).PlatformsAffected | Unknown | The affetcted platforms due to the CVE | 
| XFE.CVE(obj.ID==val.ID).Exploitability | String | The exploitability of the CVE. | 


##### Command Example
``` ```

##### Human Readable Output


### 7. xfe-whois
---
Gets information about the given host address
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xfe-whois`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The host or address to search inside X-Force Exchange (e.g. google.com) | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XFE.Whois(obj.Host==val.Host).Host | String | The given host from the user. | 
| XFE.Whois(obj.Host==val.Host).RegistrarName | String | The domain name registrar of the host. | 
| XFE.Whois(obj.Host==val.Host).Created | Date | The date the host was created. | 
| XFE.Whois(obj.Host==val.Host).Updated | Date | The date the host's information has been updated. | 
| XFE.Whois(obj.Host==val.Host).Expires | Date | The date the host will be expired | 
| XFE.Whois(obj.Host==val.Host).Email | String | The contact email of the host owners. | 
| XFE.Whois(obj.Host==val.Host).Contact | Unknown | Contact information of the host's organization | 


##### Command Example
``` ```

##### Human Readable Output


### 8. xfe-search-cves
---
Gets list of all vulnerabilities associated with the search term.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xfe-search-cves`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | The query for the search. | Required | 
| start_date | The start of the date range for searching. | Optional | 
| end_date | The end of the date range for searching. | Optional | 
| bookmark | Bookmark used to page through results. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE(obj.ID==val.ID).ID | String | The ID of the CVE | 
| CVE(obj.ID==val.ID).CVSS | String | The CVSS of the CVE | 
| CVE(obj.ID==val.ID).Published | Date | The date this was published | 
| CVE(obj.ID==val.ID).Description | Unknown | The CVE description | 
| XFE.CVE(obj.ID==val.ID).Xfdbid | String | The XFBID of the CVE | 
| XFE.CVE(obj.ID==val.ID).RiskLevel | Number | The risk level of the CVE | 
| XFE.CVE(obj.ID==val.ID).Reported | Date | The reported date of the CVE | 
| XFE.CVE(obj.ID==val.ID).Cvss | Unknown | The CVSS information of the CVE | 
| XFE.CVE(obj.ID==val.ID).Stdcode | Unknown | The CVE stdcodes | 
| XFE.CVE(obj.ID==val.ID).Title | String | the title of the CVE | 
| XFE.CVE(obj.ID==val.ID).Description | String | The description of the CVE | 
| XFE.CVE(obj.ID==val.ID).PlatformsAffected | Unknown | The affetcted platforms due to the CVE | 
| XFE.CVE(obj.ID==val.ID).Exploitability | String | The exploitability of the CVE. | 
| XFE.CVESearch.TotalRows | String | The total rows received after search | 
| XFE.CVESearch.Bookmark | String | Bookmark used to page through results. | 


##### Command Example
``` !ip ip="8.8.8.8" ```

##### Human Readable Output
##### X-Force IP Reputation for: 8.8.8.8
https://exchange.xforce.ibmcloud.com/ip/8.8.8.8

|Reason|Score|Subnets|
|---|---|---|
| Regional Internet Registry:<br>One of the five RIRs announced a (new) location mapping of the IP. | 1 | 8.0.0.0/8, 8.0.0.0/9, 8.8.8.0/24 |


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* 'The given IP was invalid'
* 'Command not found.'
* f'Failed to execute {command} command. Error: {e}'