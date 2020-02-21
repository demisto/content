## Overview
---

IBM X-Force Exchange lets you receive threat intelligence about applications, IP addresses, URls and hashes
This integration was integrated and tested with version xx of XFE_v2
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
| IP.Address | Unknown | The IP address | 
| IP.Malicious.Vendor | Unknown | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | Unknown | For malicious IPs, the reason for the vendor to make the decision | 
| IP.Malicious.Score | Unknown | For malicious IPs, the score from the vendor | 
| DBotScore.Indicator | Unknown | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | Unknown | Vendor used to calculate the score | 
| DBotScore.Score | Unknown | The actual score | 
| XFE.IP.Reason | String | The reason for the given score from X-Force Exchange | 
| XFE.IP.Reasondescription | String | Additional details of the score's reason | 
| XFE.IP.Subnets | Unknown | The subnets of the IP | 


##### Command Example
```!ip ip="8.8.8.8"
```

##### Context Example
```
{
    "IP": {
        "Malicious": {
            "Vendor": "XFE"
        }, 
        "Geo": {
            "Country": "United States"
        }, 
        "Score": 1, 
        "Address": "8.8.8.8"
    }, 
    "DBotScore": {
        "Vendor": "XFE", 
        "Indicator": "8.8.8.8", 
        "Score": 1, 
        "Type": "ip"
    }, 
    "XFE.IP": {
        "Subnets": [
            {
                "subnet": "8.0.0.0/8", 
                "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.", 
                "score": 1, 
                "created": "2018-04-24T06:22:00.000Z", 
                "ip": "8.0.0.0", 
                "asns": {
                    "3356": {
                        "cidr": 8, 
                        "removed": true
                    }
                }, 
                "reason": "Regional Internet Registry", 
                "cats": {}, 
                "categoryDescriptions": {}, 
                "reason_removed": true
            }, 
            {
                "reason_removed": true, 
                "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.", 
                "score": 1, 
                "created": "2020-01-17T09:09:00.000Z", 
                "ip": "8.0.0.0", 
                "asns": {
                    "3356": {
                        "cidr": 9, 
                        "removed": true
                    }
                }, 
                "reason": "Regional Internet Registry", 
                "cats": {}, 
                "categoryDescriptions": {}, 
                "subnet": "8.0.0.0/9", 
                "geo": {
                    "country": "United States", 
                    "countrycode": "US"
                }
            }, 
            {
                "subnet": "8.8.8.0/24", 
                "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.", 
                "score": 1, 
                "created": "2020-01-17T09:09:00.000Z", 
                "ip": "8.8.8.0", 
                "asns": {
                    "15169": {
                        "cidr": 24, 
                        "removed": true
                    }
                }, 
                "reason": "Regional Internet Registry", 
                "cats": {}, 
                "categoryDescriptions": {}, 
                "reason_removed": true
            }
        ], 
        "Reason": "Regional Internet Registry", 
        "Reasondescription": "One of the five RIRs announced a (new) location mapping of the IP."
    }
}
```

##### Human Readable Output
### X-Force IP Reputation for: 8.8.8.8
https://exchange.xforce.ibmcloud.com/ip/8.8.8.8

|Reason|Score|Subnets|
|---|---|---|
| Regional Internet Registry:<br>One of the five RIRs announced a (new) location mapping of the IP. | 1 | 8.0.0.0/8, 8.0.0.0/9, 8.8.8.0/24 |


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
| URL.Data | String | The given URL from the user | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
```!url url="https://www.google.com"
```

##### Context Example
```
{
    "URL": {
        "Malicious": {
            "Vendor": "XFE"
        }, 
        "Data": "https://www.google.com"
    }, 
    "DBotScore": {
        "Vendor": "XFE", 
        "Indicator": "https://www.google.com", 
        "Score": 1, 
        "Type": "url"
    }
}
```

##### Human Readable Output
### X-Force URL Reputation for: https://www.google.com
https://exchange.xforce.ibmcloud.com/ip/https://www.google.com

|Categories|Score|
|---|---|
| Search Engines / Web Catalogues / Portals | 1 |


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
| File.MD5 | String | The file's MD5 | 
| File.SHA1 | String | The file's SHA1 | 
| File.SHA256 | String | The file's SHA256 | 
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
```!file file="f2b8d790dab6d2c6945f9a0bce441921"
```

##### Context Example
```
{
    "DBotScore": {
        "Vendor": "XFE", 
        "Indicator": "f2b8d790dab6d2c6945f9a0bce441921", 
        "Score": 3, 
        "Type": "file"
    }, 
    "XFE.File": {
        "Family": [
            "Spam Zero-Day"
        ], 
        "CnCServers": {}, 
        "subjects": {
            "count": 1, 
            "rows": [
                {
                    "count": 1, 
                    "origin": "email", 
                    "ips": [
                        "217.76.151.72"
                    ], 
                    "lastseen": "2018-08-13T07:15:00Z", 
                    "subject": "Court Order", 
                    "type": "email", 
                    "firstseen": "2018-08-13T07:15:00Z", 
                    "md5": "F2B8D790DAB6D2C6945F9A0BCE441921"
                }
            ]
        }, 
        "external": {
            "family": [
                "kryptik"
            ], 
            "source": "reversingLabs", 
            "subPlatform": "JAVA", 
            "detectionCoverage": 34, 
            "platform": "ByteCode", 
            "lastSeen": "2018-08-14T09:22:00Z", 
            "malwareType": "Trojan", 
            "firstSeen": "2018-08-13T07:48:30Z"
        }, 
        "downloadServers": {}, 
        "FamilyMembers": {
            "Spam Zero-Day": {
                "count": 5023461
            }
        }, 
        "emails": {
            "count": 1, 
            "rows": [
                {
                    "count": 1, 
                    "origin": "SPM", 
                    "domain": "dhl.com", 
                    "filepath": "Case File 5368.zip", 
                    "ip": "217.76.151.72", 
                    "uri": "Case File 5368.zip", 
                    "lastseen": "2018-08-13T07:15:00Z", 
                    "type": "SPM", 
                    "firstseen": "2018-08-13T07:15:00Z", 
                    "md5": "F2B8D790DAB6D2C6945F9A0BCE441921"
                }
            ]
        }
    }, 
    "File": {
        "Malicious": {
            "Vendor": "XFE", 
            "Description": null
        }, 
        "MD5": "f2b8d790dab6d2c6945f9a0bce441921"
    }
}
```

##### Human Readable Output
### X-Force md5 Reputation for f2b8d790dab6d2c6945f9a0bce441921
https://exchange.xforce.ibmcloud.com/malware/f2b8d790dab6d2c6945f9a0bce441921

|Created Date|Source|Type|
|---|---|---|
| 2018-08-13T07:15:00Z | reversingLabs | Trojan |


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
| URL.Data | String | The file's URL | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
```!domain domain="google.com"
```

##### Context Example
```
{
    "URL": {
        "Malicious": {
            "Vendor": "XFE"
        }, 
        "Data": "google.com"
    }, 
    "DBotScore": {
        "Vendor": "XFE", 
        "Indicator": "google.com", 
        "Score": 1, 
        "Type": "url"
    }
}
```

##### Human Readable Output
### X-Force URL Reputation for: google.com
https://exchange.xforce.ibmcloud.com/ip/google.com

|Categories|Score|
|---|---|
| Search Engines / Web Catalogues / Portals | 1 |


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
| CVE.ID | String | The ID of the CVE | 
| CVE.CVSS | String | The CVSS of the CVE | 
| CVE.Published | Date | The date this was published | 
| CVE.Description | Unknown | The CVE description | 
| XFE.CVE.Xfdbid | String | The XFBID of the CVE | 
| XFE.CVE.RiskLevel | Number | The risk level of the CVE | 
| XFE.CVE.Reported | Date | The reported date of the CVE | 
| XFE.CVE.Cvss | Unknown | The CVSS information of the CVE | 
| XFE.CVE.Stdcode | Unknown | The CVE stdcodes | 
| XFE.CVE.Title | String | the title of the CVE | 
| XFE.CVE.Description | String | The description of the CVE | 
| XFE.CVE.PlatformsAffected | Unknown | The affetcted platforms due to the CVE | 
| XFE.CVE.Exploitability | String | The exploitability of the CVE. | 


##### Command Example
```!cve-search cve_id="CVE-2020-3142"
```

##### Context Example
```
{
    "DBotScore": {
        "Vendor": "XFE", 
        "Indicator": "CVE-2020-3142", 
        "Score": 3, 
        "Type": "cve"
    }, 
    "CVE": {
        "ID": "CVE-2020-3142", 
        "Published": "2020-01-24T00:00:00Z", 
        "CVSS": "3.0", 
        "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password."
    }, 
    "XFE.CVE": {
        "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password.", 
        "Stdcode": [
            "CVE-2020-3142"
        ], 
        "RiskLevel": 7.5, 
        "Xfdbid": 175033, 
        "Title": "Cisco Webex Meetings Suite sites information disclosure", 
        "Reported": "2020-01-24T00:00:00Z", 
        "PlatformsAffected": [
            "Cisco Webex Meetings Suite sites 39.11.0", 
            "Cisco Webex Meetings Suite sites 40.1.0", 
            "Cisco Webex Meetings Online sites 39.11.0", 
            "Cisco Webex Meetings Online sites 40.1.0"
        ], 
        "Tagname": "cisco-webex-cve20203142-info-disc", 
        "Cvss": {
            "access_complexity": "Low", 
            "availability_impact": "None", 
            "confidentiality_impact": "High", 
            "privilegesrequired": "None", 
            "userinteraction": "None", 
            "remediation_level": "Official Fix", 
            "access_vector": "Network", 
            "version": "3.0", 
            "integrity_impact": "None", 
            "scope": "Unchanged"
        }, 
        "Exploitability": "Unproven"
    }
}
```

##### Human Readable Output
### X-Force CVE Reputation for CVE-2020-3142
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2020-3142

|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | Cisco Webex Meetings Suite sites 39.11.0<br>Cisco Webex Meetings Suite sites 40.1.0<br>Cisco Webex Meetings Online sites 39.11.0<br>Cisco Webex Meetings Online sites 40.1.0 | Low | Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile devices web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password. | Unproven | 2020-01-24T00:00:00Z | 7.5 | CVE-2020-3142 | Cisco Webex Meetings Suite sites information disclosure | 3.0 |


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
| CVE.ID | String | The ID of the CVE | 
| CVE.CVSS | String | The CVSS of the CVE | 
| CVE.Published | Date | The date this was published | 
| CVE.Description | Unknown | The CVE description | 
| XFE.CVE.Xfdbid | String | The XFBID of the CVE | 
| XFE.CVE.RiskLevel | Number | The risk level of the CVE | 
| XFE.CVE.Reported | Date | The reported date of the CVE | 
| XFE.CVE.Cvss | Unknown | The CVSS information of the CVE | 
| XFE.CVE.Stdcode | Unknown | The CVE stdcodes | 
| XFE.CVE.Title | String | the title of the CVE | 
| XFE.CVE.Description | String | The description of the CVE | 
| XFE.CVE.PlatformsAffected | Unknown | The affetcted platforms due to the CVE | 
| XFE.CVE.Exploitability | String | The exploitability of the CVE. | 


##### Command Example
```!cve-latest limit=2
```

##### Context Example
```
{
    "DBotScore": [
        {
            "Vendor": "XFE", 
            "Indicator": "", 
            "Score": 3, 
            "Type": "cve"
        }, 
        {
            "Vendor": "XFE", 
            "Indicator": "CVE-2020-3142", 
            "Score": 3, 
            "Type": "cve"
        }
    ], 
    "CVE": [
        {
            "ID": "", 
            "Published": "2020-01-24T00:00:00Z", 
            "CVSS": "3.0", 
            "Description": "TP-Link TP-SG105E is vulnerable to a denial of service, caused by the failure to properly restrict access to an internal API. By sending a specially crafted HTTP POST request, an attacker could exploit this vulnerability to cause the device to reboot."
        }, 
        {
            "ID": "CVE-2020-3142", 
            "Published": "2020-01-24T00:00:00Z", 
            "CVSS": "3.0", 
            "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password."
        }
    ], 
    "XFE.CVE": [
        {
            "Description": "TP-Link TP-SG105E is vulnerable to a denial of service, caused by the failure to properly restrict access to an internal API. By sending a specially crafted HTTP POST request, an attacker could exploit this vulnerability to cause the device to reboot.", 
            "Stdcode": null, 
            "RiskLevel": 7.5, 
            "Xfdbid": 175035, 
            "Title": "TP-Link TP-SG105E denial of service", 
            "Reported": "2020-01-24T00:00:00Z", 
            "PlatformsAffected": [
                "TP-LINK TP-SG105E 1.0.0"
            ], 
            "Tagname": "tplink-tpsg105e-dos", 
            "Cvss": {
                "access_complexity": "Low", 
                "availability_impact": "High", 
                "confidentiality_impact": "None", 
                "privilegesrequired": "None", 
                "userinteraction": "None", 
                "remediation_level": "Official Fix", 
                "access_vector": "Network", 
                "version": "3.0", 
                "integrity_impact": "None", 
                "scope": "Unchanged"
            }, 
            "Exploitability": "Proof of Concept"
        }, 
        {
            "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password.", 
            "Stdcode": [
                "CVE-2020-3142"
            ], 
            "RiskLevel": 7.5, 
            "Xfdbid": 175033, 
            "Title": "Cisco Webex Meetings Suite sites information disclosure", 
            "Reported": "2020-01-24T00:00:00Z", 
            "PlatformsAffected": [
                "Cisco Webex Meetings Suite sites 39.11.0", 
                "Cisco Webex Meetings Suite sites 40.1.0", 
                "Cisco Webex Meetings Online sites 39.11.0", 
                "Cisco Webex Meetings Online sites 40.1.0"
            ], 
            "Tagname": "cisco-webex-cve20203142-info-disc", 
            "Cvss": {
                "access_complexity": "Low", 
                "availability_impact": "None", 
                "confidentiality_impact": "High", 
                "privilegesrequired": "None", 
                "userinteraction": "None", 
                "remediation_level": "Official Fix", 
                "access_vector": "Network", 
                "version": "3.0", 
                "integrity_impact": "None", 
                "scope": "Unchanged"
            }, 
            "Exploitability": "Unproven"
        }
    ]
}
```

##### Human Readable Output
### X-Force CVE Reputation for 
https://exchange.xforce.ibmcloud.com/vulnerability/search/

|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|Title|Version|
|---|---|---|---|---|---|---|---|---|
| Network | TP-LINK TP-SG105E 1.0.0 | Low | TP-Link TP-SG105E is vulnerable to a denial of service, caused by the failure to properly restrict access to an internal API. By sending a specially crafted HTTP POST request, an attacker could exploit this vulnerability to cause the device to reboot. | Proof of Concept | 2020-01-24T00:00:00Z | 7.5 | TP-Link TP-SG105E denial of service | 3.0 |
### X-Force CVE Reputation for CVE-2020-3142
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2020-3142

|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | Cisco Webex Meetings Suite sites 39.11.0<br>Cisco Webex Meetings Suite sites 40.1.0<br>Cisco Webex Meetings Online sites 39.11.0<br>Cisco Webex Meetings Online sites 40.1.0 | Low | Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile devices web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password. | Unproven | 2020-01-24T00:00:00Z | 7.5 | CVE-2020-3142 | Cisco Webex Meetings Suite sites information disclosure | 3.0 |


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
| XFE.Whois.Host | String | The given host from the user. | 
| XFE.Whois.RegistrarName | String | The domain name registrar of the host. | 
| XFE.Whois.Created | Date | The date the host was created. | 
| XFE.Whois.Updated | Date | The date the host's information has been updated. | 
| XFE.Whois.Expires | Date | The date the host will be expired | 
| XFE.Whois.Email | String | The contact email of the host owners. | 
| XFE.Whois.Contact | Unknown | Contact information of the host's organization | 


##### Command Example
```!xfe-whois host="google.com"
```

##### Context Example
```
{
    "XFE.Whois": {
        "Updated": "2019-09-09T15:39:04.000Z", 
        "Created": "1997-09-15T07:00:00.000Z", 
        "Expires": "2028-09-13T07:00:00.000Z", 
        "RegistrarName": "MarkMonitor, Inc.", 
        "Host": "google.com", 
        "Contact": [
            {
                "Country": "United States", 
                "Type": "registrant", 
                "Organization": "Google LLC"
            }
        ], 
        "Email": "abusecomplaints@markmonitor.com"
    }
}
```

##### Human Readable Output
### X-Force Whois result for google.com
|Contact|Created|Email|Expires|Host|RegistrarName|Updated|
|---|---|---|---|---|---|---|
| {'Type': 'registrant', 'Organization': 'Google LLC', 'Country': 'United States'} | 1997-09-15T07:00:00.000Z | abusecomplaints@markmonitor.com | 2028-09-13T07:00:00.000Z | google.com | MarkMonitor, Inc. | 2019-09-09T15:39:04.000Z |


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
| CVE.ID | String | The ID of the CVE | 
| CVE.CVSS | String | The CVSS of the CVE | 
| CVE.Published | Date | The date this was published | 
| CVE.Description | Unknown | The CVE description | 
| XFE.CVE.Xfdbid | String | The XFBID of the CVE | 
| XFE.CVE.RiskLevel | Number | The risk level of the CVE | 
| XFE.CVE.Reported | Date | The reported date of the CVE | 
| XFE.CVE.Cvss | Unknown | The CVSS information of the CVE | 
| XFE.CVE.Stdcode | Unknown | The CVE stdcodes | 
| XFE.CVE.Title | String | the title of the CVE | 
| XFE.CVE.Description | String | The description of the CVE | 
| XFE.CVE.PlatformsAffected | Unknown | The affetcted platforms due to the CVE | 
| XFE.CVE.Exploitability | String | The exploitability of the CVE. | 
| XFE.CVESearch.TotalRows | String | The total rows received after search | 
| XFE.CVESearch.Bookmark | String | Bookmark used to page through results. | 


##### Command Example
```!xfe-search-cves q="Heartbleed"```

##### Context Example
```
{
    "XFE.CVESearch": {
        "Bookmark": "g1AAAAEpeJzLYWBgYM5gTmFQTUlKzi9KdUhJstTLTMrVrUjLL0pONTAw1EvOyS9NScwr0ctLLckBKmdKUgCSSfb____PAvNzgYSIkYGhia4BEJmHGBhYgVFUEgODc2YWqukmhEzPYwGSDA1ACmjBfCw2GJmg2MBtBLZBDW6DoTlxViyAWLEfwwpTXQMLFCs492dlAQB2wVA4", 
        "TotalRows": 3
    }, 
    "DBotScore": [
        {
            "Vendor": "XFE", 
            "Indicator": "CVE-2014-0964", 
            "Score": 3, 
            "Type": "cve"
        }, 
        {
            "Vendor": "XFE", 
            "Indicator": "BID-67054", 
            "Score": 3, 
            "Type": "cve"
        }, 
        {
            "Vendor": "XFE", 
            "Indicator": "CVE-2014-0160", 
            "Score": 2, 
            "Type": "cve"
        }
    ], 
    "CVE": [
        {
            "ID": "CVE-2014-0964", 
            "Published": "2014-05-08T00:00:00Z", 
            "CVSS": "2.0", 
            "Description": "IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages."
        }, 
        {
            "ID": "BID-67054", 
            "Published": "2014-04-24T00:00:00Z", 
            "CVSS": "2.0", 
            "Description": "HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash."
        }, 
        {
            "ID": "CVE-2014-0160", 
            "Published": "2014-04-07T00:00:00Z", 
            "CVSS": "2.0", 
            "Description": "OpenSSL could allow a remote attacker to obtain sensitive information, caused by an error in the TLS/DTLS heartbeat functionality. An attacker could exploit this vulnerability to remotely read system memory contents without needing to log on to the server. Successful exploitation could allow an attacker to retrieve private keys, passwords or other sensitive information.\r\n\r\nThis vulnerability is commonly referred to as \"Heartbleed\"."
        }
    ], 
    "XFE.CVE": [
        {
            "Description": "IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages.", 
            "Stdcode": [
                "CVE-2014-0964", 
                "BID-67322"
            ], 
            "RiskLevel": 7.1, 
            "Xfdbid": 92877, 
            "Title": "IBM WebSphere Application Server and Scanning Tool denial of service", 
            "Reported": "2014-05-08T00:00:00Z", 
            "PlatformsAffected": [
                "IBM WebSphere Application Server 6.0.2", 
                "IBM WebSphere Application Server 6.1"
            ], 
            "Tagname": "ibm-websphere-cve20140964-dos", 
            "Cvss": {
                "access_complexity": "Medium", 
                "availability_impact": "Complete", 
                "confidentiality_impact": "None", 
                "remediation_level": "Official Fix", 
                "access_vector": "Network", 
                "authentication": "None", 
                "version": "2.0", 
                "integrity_impact": "None"
            }, 
            "Exploitability": "Unproven"
        }, 
        {
            "Description": "HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash.", 
            "Stdcode": [
                "BID-67054", 
                "SA58224", 
                "CVE-2014-2601"
            ], 
            "RiskLevel": 7.8, 
            "Xfdbid": 92744, 
            "Title": "HP Integrated Lights-Out 2 Heartbleed denial of service", 
            "Reported": "2014-04-24T00:00:00Z", 
            "PlatformsAffected": [
                "HP Integrated Lights-Out 2 (iLO2) 2.23"
            ], 
            "Tagname": "hp-ilo-cve20142601-dos", 
            "Cvss": {
                "access_complexity": "Low", 
                "availability_impact": "Complete", 
                "confidentiality_impact": "None", 
                "remediation_level": "Official Fix", 
                "access_vector": "Network", 
                "authentication": "None", 
                "version": "2.0", 
                "integrity_impact": "None"
            }, 
            "Exploitability": "Unproven"
        }, 
        {
            "Description": "OpenSSL could allow a remote attacker to obtain sensitive information, caused by an error in the TLS/DTLS heartbeat functionality. An attacker could exploit this vulnerability to remotely read system memory contents without needing to log on to the server. Successful exploitation could allow an attacker to retrieve private keys, passwords or other sensitive information.\r\n\r\nThis vulnerability is commonly referred to as \"Heartbleed\".", 
            "Stdcode": [
                "CVE-2014-0160", 
                "US-CERT VU#720951", 
                "BID-66690", 
                "SA57347", 
                "RHSA-2014-0376", 
                "RHSA-2014-0378", 
                "SA57692", 
                "SA57764", 
                "SA57759", 
                "SA57758", 
                "SA57756", 
                "SA57786", 
                "SA57755", 
                "BID-67206"
            ], 
            "RiskLevel": 5, 
            "Xfdbid": 92322, 
            "Title": "OpenSSL heartbeat information disclosure", 
            "Reported": "2014-04-07T00:00:00Z", 
            "PlatformsAffected": [
                "OpenSSL OpenSSL 1.0.1A", 
                "OpenSSL OpenSSL 1.0.1B", 
                "OpenSSL OpenSSL 1.0.1c", 
                "OpenSSL OpenSSL 1.0.1D", 
                "OpenSSL OpenSSL 1.0.1E", 
                "OpenSSL OpenSSL 1.0.1f"
            ], 
            "Tagname": "openssl-cve20140160-info-disc", 
            "Cvss": {
                "access_complexity": "Low", 
                "availability_impact": "None", 
                "confidentiality_impact": "Partial", 
                "remediation_level": "Official Fix", 
                "access_vector": "Network", 
                "authentication": "None", 
                "version": "2.0", 
                "integrity_impact": "None"
            }, 
            "Exploitability": "Functional"
        }
    ]
}
```

##### Human Readable Output
### X-Force CVE Reputation for CVE-2014-0964
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2014-0964

|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | IBM WebSphere Application Server 6.0.2<br>IBM WebSphere Application Server 6.1 | Medium | IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages. | Unproven | 2014-05-08T00:00:00Z | 7.1 | CVE-2014-0964<br>BID-67322 | IBM WebSphere Application Server and Scanning Tool denial of service | 2.0 |
### X-Force CVE Reputation for BID-67054
https://exchange.xforce.ibmcloud.com/vulnerability/search/BID-67054

|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | HP Integrated Lights-Out 2 (iLO2) 2.23 | Low | HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash. | Unproven | 2014-04-24T00:00:00Z | 7.8 | BID-67054<br>SA58224<br>CVE-2014-2601 | HP Integrated Lights-Out 2 Heartbleed denial of service | 2.0 |
### X-Force CVE Reputation for CVE-2014-0160
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2014-0160

|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | OpenSSL OpenSSL 1.0.1A<br>OpenSSL OpenSSL 1.0.1B<br>OpenSSL OpenSSL 1.0.1c<br>OpenSSL OpenSSL 1.0.1D<br>OpenSSL OpenSSL 1.0.1E<br>OpenSSL OpenSSL 1.0.1f | Low | OpenSSL could allow a remote attacker to obtain sensitive information, caused by an error in the TLS/DTLS heartbeat functionality. An attacker could exploit this vulnerability to remotely read system memory contents without needing to log on to the server. Successful exploitation could allow an attacker to retrieve private keys, passwords or other sensitive information.<br><br>This vulnerability is commonly referred to as "Heartbleed". | Functional | 2014-04-07T00:00:00Z | 5 | CVE-2014-0160<br>US-CERT VU#720951<br>BID-66690<br>SA57347<br>RHSA-2014-0376<br>RHSA-2014-0378<br>SA57692<br>SA57764<br>SA57759<br>SA57758<br>SA57756<br>SA57786<br>SA57755<br>SA57683<br>SA57810<br>SA57386<br>SA57715<br>SA57822<br>SA57833<br>SA57816<br>SA57772<br>SA57799<br>SA57742<br>SA57785<br>SA57805<br>RHSA-2014-0396<br>SA57887<br>SA57858<br>SA57863<br>SA57894<br>SA57881<br>SA57774<br>SA57866<br>SA57884<br>SA57251<br>SA57775<br>SA57890<br>SA57701<br>SA57888<br>SA57738<br>SA57909<br>SA57900<br>SA57853<br>SA57770<br>SA57773<br>SA57735<br>SA57958<br>SA57483<br>SA57744<br>SA57757<br>SA57850<br>SA57876<br>SA57869<br>SA57921<br>SA57920<br>SA57454<br>SA57628<br>SA57793<br>SA57857<br>SA57972<br>SA57970<br>SA57836<br>SA57966<br>SA57968<br>SA58004<br>SA58005<br>SA58028<br>SA57864<br>SA57979<br>SA58032<br>SA57954<br>SA57999<br>SA57763<br>SA57982<br>SA58024<br>SA57824<br>SA58009<br>SA58033<br>SA57974<br>SA58049<br>SA58046<br>SA57817<br>SA58098<br>SA58048<br>SA58040<br>SA58062<br>SA57815<br>SA58102<br>SA58052<br>SA57941<br>SA57807<br>SA57852<br>SA58113<br>SA58107<br>SA58114<br>SA58115<br>SA58008<br>SA57983<br>SA57969<br>SA57961<br>SA57851<br>SA57960<br>SA57789<br>SA57985<br>SA57984<br>SA58056<br>SA58029<br>SA57512<br>SA58164<br>SA58184<br>SA57911<br>SA58183<br>SA58175<br>SA58166<br>SA57951<br>SA57947<br>SA58171<br>SA58178<br>SA57963<br>SA58167<br>SA57949<br>SA58146<br>SA58019<br>SA58172<br>SA57826<br>SA58182<br>SA58244<br>SA58162<br>SA58188<br>SA58185<br>SA58069<br>SA58058<br>SA58148<br>SA58223<br>SA58124<br>SA58204<br>SA58187<br>SA58190<br>SA58161<br>SA58017<br>SA58195<br>SA58053<br>SA58007<br>SA58022<br>SA58176<br>BID-67206 | OpenSSL heartbeat information disclosure | 2.0 |

## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* 'The given IP was invalid'
* 'Command not found.'
* f'Failed to execute {command} command. Error: {e}'
