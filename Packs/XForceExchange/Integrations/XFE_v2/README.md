IBM X-Force Exchange lets you receive threat intelligence about applications, IP addresses, URls and hashes

## Configure XFE v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL (e.g. https://api.xforce.ibmcloud.com) | True |
| credentials | API Key | True |
| Source Reliability | Reliability of the source providing the intelligence data. The default value is C - Fairly reliable. | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |
| ip_threshold | IP Threshold. Minimum risk score for the IP to be consodered malicious (ranges from 1 to 10). | False |
| url_threshold | URL Threshold. Minimum risk score for the URL to be consodered malicious (ranges from 1 to 10). | False |
| cve_threshold | CVE Threshold. Minimum risk score for the URL to be consodered malicious (ranges from 1 to 10). | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
IP to check


##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP to check | Required | 
| threshold | score threshold  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | Unknown | The IP address. | 
| IP.Malicious.Vendor | Unknown | For malicious IPs, the vendor that made the decision. | 
| IP.Malicious.Description | Unknown | For malicious IPs, the reason for the vendor to make the decision. | 
| IP.Malicious.Score | Unknown | For malicious IPs, the score from the vendor. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| XFE.IP.Reason | String | The reason for the given score from X-Force Exchange. | 
| XFE.IP.Reasondescription | String | Additional details of the score's reason. | 
| XFE.IP.Subnets | Unknown | The subnets of the IP. | 


##### Command Example
```!ip ip=8.8.8.8```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 1,
        "Type": "ip",
        "Vendor": "XFE"
    },
    "IP": {
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "United States"
        },
        "Score": 1
    },
    "XFE": {
        "IP": {
            "Reason": "Regional Internet Registry",
            "Reasondescription": "One of the five RIRs announced a (new) location mapping of the IP.",
            "Subnets": [
                {
                    "asns": {
                        "3356": {
                            "cidr": 8,
                            "removed": true
                        }
                    },
                    "categoryDescriptions": {},
                    "cats": {},
                    "created": "2018-04-24T06:22:00.000Z",
                    "ip": "8.0.0.0",
                    "reason": "Regional Internet Registry",
                    "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
                    "reason_removed": true,
                    "score": 1,
                    "subnet": "8.0.0.0/8"
                },
                {
                    "asns": {
                        "3356": {
                            "cidr": 9,
                            "removed": true
                        }
                    },
                    "categoryDescriptions": {},
                    "cats": {},
                    "created": "2020-03-22T07:54:00.000Z",
                    "geo": {
                        "country": "United States",
                        "countrycode": "US"
                    },
                    "ip": "8.0.0.0",
                    "reason": "Regional Internet Registry",
                    "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
                    "reason_removed": true,
                    "score": 1,
                    "subnet": "8.0.0.0/9"
                },
                {
                    "asns": {
                        "15169": {
                            "cidr": 24,
                            "removed": true
                        }
                    },
                    "categoryDescriptions": {},
                    "cats": {},
                    "created": "2020-03-22T07:54:00.000Z",
                    "ip": "8.8.8.0",
                    "reason": "Regional Internet Registry",
                    "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
                    "reason_removed": true,
                    "score": 1,
                    "subnet": "8.8.8.0/24"
                }
            ]
        }
    }
}
```

##### Human Readable Output
### X-Force IP Reputation for: 8.8.8.8
https://exchange.xforce.ibmcloud.com/ip/8.8.8.8
|Reason|Score|Subnets|
|---|---|---|
| Regional Internet Registry:One of the five RIRs announced a (new) location mapping of the IP. | 1 | 8.0.0.0/8, 8.0.0.0/9, 8.8.8.0/24 |


### url
***
Check the given URL reputation

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threshold | If the score is above the given threshold, will be considered malicious. If threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. | Optional | 
| url | The URL to check | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The given URL from the user. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 


##### Command Example
```!url url="https://www.google.com"```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "https://www.google.com",
        "Score": 1,
        "Type": "url",
        "Vendor": "XFE"
    },
    "URL": {
        "Data": "https://www.google.com"
    }
}
```

##### Human Readable Output
### X-Force URL Reputation for: https://www.google.com
https://exchange.xforce.ibmcloud.com/url/https://www.google.com
|Categories|Score|
|---|---|
| Search Engines / Web Catalogues / Portals | 1 |


### file
***
Check file reputation


##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file hash md5/sha1/sha256 to check | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The file's MD5. | 
| File.SHA1 | String | The file's SHA1. | 
| File.SHA256 | String | The file's SHA256. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the reason for the vendor to make the decision. |
| File.Relationships.EntityA | String | The source of the relationship. |
| File.Relationships.EntityB | String | The destination of the relationship. |
| File.Relationships.Relationship | String | The name of the relationship. |
| File.Relationships.EntityAType | String | The type of the source of the relationship. |
| File.Relationships.EntityBType | String | The type of the destination of the relationship. |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| XFE.File.CnCServers | Unknown | C&C servers related to the given file. | 
| XFE.File.emails | Unknown | Emails related to the given file. | 
| XFE.File.downloadServers | Unknown | Download servers related to the given file. | 
| XFE.File.subjects | Unknown | Subjects related to the given file. | 
| XFE.File.external | Unknown | Additional information about the given file. | 


##### Command Example
```!file file="f2b8d790dab6d2c6945f9a0bce441921"```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "f2b8d790dab6d2c6945f9a0bce441921",
        "Score": 3,
        "Type": "file",
        "Vendor": "XFE"
    },
    "File": {
        "MD5": "f2b8d790dab6d2c6945f9a0bce441921",
        "Malicious": {
            "Description": null,
            "Vendor": "XFE"
        }
    },
    "XFE": {
        "File": {
            "CnCServers": {},
            "Family": "kryptik",
            "FamilyMembers": null,
            "downloadServers": {},
            "emails": {
                "count": 1,
                "rows": [
                    {
                        "count": 1,
                        "domain": "dtest.com",
                        "filepath": "Case File 5368.zip",
                        "firstseen": "2018-08-13T07:15:00Z",
                        "ip": "217.76.151.72",
                        "lastseen": "2018-08-13T07:15:00Z",
                        "md5": "F2B8D790DAB6D2C6945F9A0BCE441921",
                        "origin": "SPM",
                        "type": "SPM",
                        "uri": "Case File 5368.zip"
                    }
                ]
            },
            "external": {
                "detectionCoverage": 34,
                "family": [
                    "kryptik"
                ],
                "firstSeen": "2018-08-13T07:48:30Z",
                "lastSeen": "2018-08-14T09:22:00Z",
                "malwareType": "Trojan",
                "platform": "ByteCode",
                "source": "reversingLabs",
                "subPlatform": "JAVA"
            },
            "subjects": {
                "count": 1,
                "rows": [
                    {
                        "count": 1,
                        "firstseen": "2018-08-13T07:15:00Z",
                        "ips": [
                            "217.76.151.72"
                        ],
                        "lastseen": "2018-08-13T07:15:00Z",
                        "md5": "F2B8D790DAB6D2C6945F9A0BCE441921",
                        "origin": "email",
                        "subject": "Court Order",
                        "type": "email"
                    }
                ]
            }
        }
    }
}
```

##### Human Readable Output
### X-Force md5 Reputation for f2b8d790dab6d2c6945f9a0bce441921
https://exchange.xforce.ibmcloud.com/malware/f2b8d790dab6d2c6945f9a0bce441921
|Created Date|Source|Type|
|---|---|---|
| 2018-08-13T07:48:30Z | reversingLabs | Trojan |


### domain
***
Check domain reputation

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check | Required | 
| threshold | If the score is above the given threshold, will be considered malicious. If threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain. | 
| Domain.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 


##### Command Example
```!domain domain="google.com"```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "XFE"
    },
    "Domain": {
        "Name": "google.com"
    }
}
```

##### Human Readable Output
### X-Force Domain Reputation for: google.com
https://exchange.xforce.ibmcloud.com/url/google.com
|Categories|Score|
|---|---|
| Search Engines / Web Catalogues / Portals | 1 |


### cve-search
***
Search for details about the given CVE


##### Base Command

`cve-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The cve to search for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS of the CVE. | 
| CVE.Published | Date | The date this was published. | 
| CVE.Description | Unknown | The CVE description. | 
| XFE.CVE.Xfdbid | String | The XFBID of the CVE. | 
| XFE.CVE.RiskLevel | Number | The risk level of the CVE. | 
| XFE.CVE.Reported | Date | The reported date of the CVE. | 
| XFE.CVE.Cvss | Unknown | The CVSS information of the CVE. | 
| XFE.CVE.Stdcode | Unknown | The CVE stdcodes. | 
| XFE.CVE.Title | String | The title of the CVE. | 
| XFE.CVE.Description | String | The description of the CVE. | 
| XFE.CVE.PlatformsAffected | Unknown | The affetcted platforms due to the CVE. | 
| XFE.CVE.Exploitability | String | The exploitability of the CVE. | 


##### Command Example
```!cve-search cve_id="CVE-2020-3142"```

##### Context Example
```
{
    "CVE": {
        "CVSS": "3.0",
        "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password.",
        "ID": "CVE-2020-3142",
        "Malicious": {
            "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password.",
            "Vendor": "XFE"
        },
        "Published": "2020-01-24T00:00:00Z"
    },
    "DBotScore": {
        "Indicator": "CVE-2020-3142",
        "Score": 3,
        "Type": "cve",
        "Vendor": "XFE"
    },
    "XFE": {
        "CVE": {
            "Cvss": {
                "access_complexity": "Low",
                "access_vector": "Network",
                "availability_impact": "None",
                "confidentiality_impact": "High",
                "integrity_impact": "None",
                "privilegesrequired": "None",
                "remediation_level": "Official Fix",
                "scope": "Unchanged",
                "userinteraction": "None",
                "version": "3.0"
            },
            "Description": "Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile device\u0092s web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password.",
            "Exploitability": "Unproven",
            "PlatformsAffected": [
                "Cisco Webex Meetings Suite sites 39.11.0",
                "Cisco Webex Meetings Suite sites 40.1.0",
                "Cisco Webex Meetings Online sites 39.11.0",
                "Cisco Webex Meetings Online sites 40.1.0"
            ],
            "Reported": "2020-01-24T00:00:00Z",
            "RiskLevel": 7.5,
            "Stdcode": [
                "CVE-2020-3142"
            ],
            "Tagname": "cisco-webex-cve20203142-info-disc",
            "Title": "Cisco Webex Meetings Suite sites information disclosure",
            "Xfdbid": 175033
        }
    }
}
```

##### Human Readable Output
### X-Force CVE Reputation for CVE-2020-3142
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2020-3142
|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | Cisco Webex Meetings Suite sites 39.11.0<br/>Cisco Webex Meetings Suite sites 40.1.0<br/>Cisco Webex Meetings Online sites 39.11.0<br/>Cisco Webex Meetings Online sites 40.1.0<br/> | Low | Cisco Webex Meetings Suite sites and Cisco Webex Meetings Online sites could allow a remote attacker to obtain sensitive information, caused by unintended meeting information exposure in a specific meeting join flow for mobile applications. By accessing a known meeting ID or meeting URL from the mobile devices web browser, an attacker could exploit this vulnerability to join a password-protected meeting without providing the meeting password. | Unproven | 2020-01-24T00:00:00Z | 7.5 | CVE-2020-3142 | Cisco Webex Meetings Suite sites information disclosure | 3.0 |


### cve-latest
***
Return the latest vulnerabilities found


##### Base Command

`cve-latest`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of results to return | Optional | 
| start_date | The start of the date range for searching.<br />The format should be YYYY-MM-DDThh:mm:ssZ (e.g. 2016-01-01T00:00:00Z). | Optional | 
| end_date | The end of the date range for searching.<br />The format should be YYYY-MM-DDThh:mm:ssZ (e.g. 2016-01-01T00:00:00Z). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS of the CVE. | 
| CVE.Published | Date | The date this was published. | 
| CVE.Description | Unknown | The CVE description. | 
| XFE.CVE.Xfdbid | String | The XFBID of the CVE. | 
| XFE.CVE.RiskLevel | Number | The risk level of the CVE. | 
| XFE.CVE.Reported | Date | The reported date of the CVE. | 
| XFE.CVE.Cvss | Unknown | The CVSS information of the CVE. | 
| XFE.CVE.Stdcode | Unknown | The CVE stdcodes. | 
| XFE.CVE.Title | String | The title of the CVE. | 
| XFE.CVE.Description | String | The description of the CVE. | 
| XFE.CVE.PlatformsAffected | Unknown | The affetcted platforms due to the CVE. | 
| XFE.CVE.Exploitability | String | The exploitability of the CVE. | 


##### Command Example
```!cve-latest limit=2```

##### Context Example
```
{
    "CVE": [
        {
            "CVSS": "3.0",
            "Description": "Sunnet eHRD could allow a remote attacker to obtain sensitive information, caused by improperly storing system files. By using a specific URL, a remote attacker could exploit this vulnerability to obtain sensitive information.",
            "ID": "CVE-2020-10508",
            "Published": "2020-03-27T00:00:00Z"
        },
        {
            "CVSS": "3.0",
            "Description": "Sunnet eHRD is vulnerable to cross-site scripting, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to inject malicious script into a Web page which would be executed in a victim's Web browser within the security context of the hosting Web site, once the page is viewed. An attacker could use this vulnerability to steal the victim's cookie-based authentication credentials.",
            "ID": "CVE-2020-10509",
            "Malicious": {
                "Description": "Sunnet eHRD is vulnerable to cross-site scripting, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to inject malicious script into a Web page which would be executed in a victim's Web browser within the security context of the hosting Web site, once the page is viewed. An attacker could use this vulnerability to steal the victim's cookie-based authentication credentials.",
                "Vendor": "XFE"
            },
            "Published": "2020-03-27T00:00:00Z"
        }
    ],
    "DBotScore": [
        {
            "Indicator": "CVE-2020-10508",
            "Score": 2,
            "Type": "cve",
            "Vendor": "XFE"
        },
        {
            "Indicator": "CVE-2020-10509",
            "Score": 3,
            "Type": "cve",
            "Vendor": "XFE"
        }
    ],
    "XFE": {
        "CVE": [
            {
                "Cvss": {
                    "access_complexity": "Low",
                    "access_vector": "Network",
                    "availability_impact": "None",
                    "confidentiality_impact": "Low",
                    "integrity_impact": "None",
                    "privilegesrequired": "None",
                    "remediation_level": "Official Fix",
                    "scope": "Unchanged",
                    "userinteraction": "None",
                    "version": "3.0"
                },
                "Description": "Sunnet eHRD could allow a remote attacker to obtain sensitive information, caused by improperly storing system files. By using a specific URL, a remote attacker could exploit this vulnerability to obtain sensitive information.",
                "Exploitability": "Unproven",
                "PlatformsAffected": [
                    "Sunnet eHRD 9.0",
                    "Sunnet eHRD 8.0"
                ],
                "Reported": "2020-03-27T00:00:00Z",
                "RiskLevel": 5.3,
                "Stdcode": [
                    "CVE-2020-10508"
                ],
                "Tagname": "sunnet-ehrd-cve202010508-info-disc",
                "Title": "Sunnet eHRD information disclosure",
                "Xfdbid": 178668
            },
            {
                "Cvss": {
                    "access_complexity": "Low",
                    "access_vector": "Network",
                    "availability_impact": "None",
                    "confidentiality_impact": "Low",
                    "integrity_impact": "Low",
                    "privilegesrequired": "None",
                    "remediation_level": "Official Fix",
                    "scope": "Changed",
                    "userinteraction": "Required",
                    "version": "3.0"
                },
                "Description": "Sunnet eHRD is vulnerable to cross-site scripting, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to inject malicious script into a Web page which would be executed in a victim's Web browser within the security context of the hosting Web site, once the page is viewed. An attacker could use this vulnerability to steal the victim's cookie-based authentication credentials.",
                "Exploitability": "High",
                "PlatformsAffected": [
                    "Sunnet eHRD 9.0",
                    "Sunnet eHRD 8.0"
                ],
                "Reported": "2020-03-27T00:00:00Z",
                "RiskLevel": 6.1,
                "Stdcode": [
                    "CVE-2020-10509"
                ],
                "Tagname": "sunnet-ehrd-cve202010509-xss",
                "Title": "Sunnet eHRD cross-site scripting",
                "Xfdbid": 178664
            }
        ]
    }
}
```

##### Human Readable Output
### X-Force CVE Reputation for CVE-2020-10508
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2020-10508
|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | Sunnet eHRD 9.0<br />Sunnet eHRD 8.0 | Low | Sunnet eHRD could allow a remote attacker to obtain sensitive information, caused by improperly storing system files. By using a specific URL, a remote attacker could exploit this vulnerability to obtain sensitive information. | Unproven | 2020-03-27T00:00:00Z | 5.3 | CVE-2020-10508 | Sunnet eHRD information disclosure | 3.0 |
### X-Force CVE Reputation for CVE-2020-10509
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2020-10509
|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | Sunnet eHRD 9.0<br />Sunnet eHRD 8.0 | Low | Sunnet eHRD is vulnerable to cross-site scripting, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to inject malicious script into a Web page which would be executed in a victim's Web browser within the security context of the hosting Web site, once the page is viewed. An attacker could use this vulnerability to steal the victim's cookie-based authentication credentials. | High | 2020-03-27T00:00:00Z | 6.1 | CVE-2020-10509 | Sunnet eHRD cross-site scripting | 3.0 |


### xfe-whois
***
Gets information about the given host address


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
| XFE.Whois.Expires | Date | The date the host will be expired. | 
| XFE.Whois.Email | String | The contact email of the host owners. | 
| XFE.Whois.Contact | Unknown | Contact information of the host's organization. | 
| Domain.Name | String | The name of the domain. | 
| Domain.CreationDate | Date | The creation date of the domain. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.UpdatedDate | Date | The date the domain has been updated. | 
| Domain.Organization | String | The organizaton which owns the domain. | 
| Domain.Registrant.Country | String | The country of the domain's registrant. | 
| Domain.Registrant.Name | String | The name of the domain's registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the domain's registar. | 
| Domain.WHOIS.Registrar.Email | String | The email of the domain's registar. | 
| Domain.WHOIS.UpdatedDate | String | The date the domain has been updated. | 
| Domain.WHOIS.ExpirationDate | Unknown | The date the domain has been updated. | 
| Domain.WHOIS.CreationDate | String | The creation date of the domain. | 
| Domain.WHOIS.Registrant.Country | String | The country of the domain's registrant. | 
| Domain.WHOIS.Registrant.Name | String | The name of the domain's registrant. | 


##### Command Example
```!xfe-whois host="google.com"```

##### Context Example
```
{
    "Domain": {
        "CreationDate": "1997-09-15T07:00:00.000Z",
        "ExpirationDate": "2028-09-13T07:00:00.000Z",
        "Name": "google.com",
        "Organization": "Google LLC",
        "Registrant": {
            "Country": "United States",
            "Name": "Google LLC"
        },
        "UpdatedDate": "2019-09-09T15:39:04.000Z",
        "WHOIS": {
            "CreationDate": "1997-09-15T07:00:00.000Z",
            "ExpirationDate": "2028-09-13T07:00:00.000Z",
            "Registrant": {
                "Country": "United States",
                "Name": "Google LLC"
            },
            "Registrar": {
                "Email": "abusecomplaints@markmonitor.com",
                "Name": "MarkMonitor, Inc."
            },
            "UpdatedDate": "2019-09-09T15:39:04.000Z"
        }
    },
    "XFE": {
        "Whois": {
            "Contact": [
                {
                    "Country": "United States",
                    "Organization": "Google LLC",
                    "Type": "registrant"
                }
            ],
            "Created": "1997-09-15T07:00:00.000Z",
            "Email": "abusecomplaints@markmonitor.com",
            "Expires": "2028-09-13T07:00:00.000Z",
            "Host": "google.com",
            "RegistrarName": "MarkMonitor, Inc.",
            "Updated": "2019-09-09T15:39:04.000Z"
        }
    }
}
```

##### Human Readable Output
### X-Force Whois result for google.com
|Contact|Created|Email|Expires|Host|RegistrarName|Updated|
|---|---|---|---|---|---|---|
| {'Type': 'registrant', 'Organization': 'Google LLC', 'Country': 'United States'} | 1997-09-15T07:00:00.000Z | abusecomplaints@markmonitor.com | 2028-09-13T07:00:00.000Z | google.com | MarkMonitor, Inc. | 2019-09-09T15:39:04.000Z |


### xfe-search-cves
***
Gets list of all vulnerabilities associated with the search term.


##### Base Command

`xfe-search-cves`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | The query for the search.<br />(https://exchange.xforce.ibmcloud.com/api/doc/?#Vulnerabilities_get_vulnerabilities_fulltext) | Required | 
| start_date | The start of the date range for searching.<br />The format should be YYYY-MM-DDThh:mm:ssZ (e.g. 2016-01-01T00:00:00Z). | Optional | 
| end_date | The end of the date range for searching.<br />The format should be YYYY-MM-DDThh:mm:ssZ (e.g. 2016-01-01T00:00:00Z). | Optional | 
| bookmark | Bookmark used to page through results.<br />(https://exchange.xforce.ibmcloud.com/api/doc/?#Vulnerabilities_get_vulnerabilities_fulltext) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS of the CVE. | 
| CVE.Published | Date | The date this was published. | 
| CVE.Description | Unknown | The CVE description. | 
| XFE.CVE.Xfdbid | String | The XFBID of the CVE. | 
| XFE.CVE.RiskLevel | Number | The risk level of the CVE. | 
| XFE.CVE.Reported | Date | The reported date of the CVE. | 
| XFE.CVE.Cvss | Unknown | The CVSS information of the CVE. | 
| XFE.CVE.Stdcode | Unknown | The CVE stdcodes. | 
| XFE.CVE.Title | String | The title of the CVE. | 
| XFE.CVE.Description | String | The description of the CVE. | 
| XFE.CVE.PlatformsAffected | Unknown | The affetcted platforms due to the CVE. | 
| XFE.CVE.Exploitability | String | The exploitability of the CVE. | 
| XFE.CVESearch.TotalRows | String | The total rows received after search. | 
| XFE.CVESearch.Bookmark | String | Bookmark used to page through results. | 


##### Command Example
```!xfe-search-cves q="Heartbleed"```

##### Context Example
```
{
    "CVE": [
        {
            "CVSS": "2.0",
            "Description": "IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages.",
            "ID": "CVE-2014-0964",
            "Malicious": {
                "Description": "IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages.",
                "Vendor": "XFE"
            },
            "Published": "2014-05-08T00:00:00Z"
        },
        {
            "CVSS": "2.0",
            "Description": "HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash.",
            "ID": "BID-67054",
            "Malicious": {
                "Description": "HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash.",
                "Vendor": "XFE"
            },
            "Published": "2014-04-24T00:00:00Z"
        },
        {
            "CVSS": "2.0",
            "Description": "OpenSSL could allow a remote attacker to obtain sensitive information, caused by an error in the TLS/DTLS heartbeat functionality. An attacker could exploit this vulnerability to remotely read system memory contents without needing to log on to the server. Successful exploitation could allow an attacker to retrieve private keys, passwords or other sensitive information.\r\n\r\nThis vulnerability is commonly referred to as \"Heartbleed\".",
            "ID": "CVE-2014-0160",
            "Published": "2014-04-07T00:00:00Z"
        }
    ],
    "DBotScore": [
        {
            "Indicator": "CVE-2014-0964",
            "Score": 3,
            "Type": "cve",
            "Vendor": "XFE"
        },
        {
            "Indicator": "BID-67054",
            "Score": 3,
            "Type": "cve",
            "Vendor": "XFE"
        },
        {
            "Indicator": "CVE-2014-0160",
            "Score": 2,
            "Type": "cve",
            "Vendor": "XFE"
        }
    ],
    "XFE": {
        "CVE": [
            {
                "Cvss": {
                    "access_complexity": "Medium",
                    "access_vector": "Network",
                    "authentication": "None",
                    "availability_impact": "Complete",
                    "confidentiality_impact": "None",
                    "integrity_impact": "None",
                    "remediation_level": "Official Fix",
                    "version": "2.0"
                },
                "Description": "IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages.",
                "Exploitability": "Unproven",
                "PlatformsAffected": [
                    "IBM WebSphere Application Server 6.0.2",
                    "IBM WebSphere Application Server 6.1"
                ],
                "Reported": "2014-05-08T00:00:00Z",
                "RiskLevel": 7.1,
                "Stdcode": [
                    "CVE-2014-0964",
                    "BID-67322"
                ],
                "Tagname": "ibm-websphere-cve20140964-dos",
                "Title": "IBM WebSphere Application Server and Scanning Tool denial of service",
                "Xfdbid": 92877
            },
            {
                "Cvss": {
                    "access_complexity": "Low",
                    "access_vector": "Network",
                    "authentication": "None",
                    "availability_impact": "Complete",
                    "confidentiality_impact": "None",
                    "integrity_impact": "None",
                    "remediation_level": "Official Fix",
                    "version": "2.0"
                },
                "Description": "HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash.",
                "Exploitability": "Unproven",
                "PlatformsAffected": [
                    "HP Integrated Lights-Out 2 (iLO2) 2.23"
                ],
                "Reported": "2014-04-24T00:00:00Z",
                "RiskLevel": 7.8,
                "Stdcode": [
                    "BID-67054",
                    "SA58224",
                    "CVE-2014-2601"
                ],
                "Tagname": "hp-ilo-cve20142601-dos",
                "Title": "HP Integrated Lights-Out 2 Heartbleed denial of service",
                "Xfdbid": 92744
            },
            {
                "Cvss": {
                    "access_complexity": "Low",
                    "access_vector": "Network",
                    "authentication": "None",
                    "availability_impact": "None",
                    "confidentiality_impact": "Partial",
                    "integrity_impact": "None",
                    "remediation_level": "Official Fix",
                    "version": "2.0"
                },
                "Description": "OpenSSL could allow a remote attacker to obtain sensitive information, caused by an error in the TLS/DTLS heartbeat functionality. An attacker could exploit this vulnerability to remotely read system memory contents without needing to log on to the server. Successful exploitation could allow an attacker to retrieve private keys, passwords or other sensitive information.\r\n\r\nThis vulnerability is commonly referred to as \"Heartbleed\".",
                "Exploitability": "Functional",
                "PlatformsAffected": [
                    "OpenSSL OpenSSL 1.0.1A",
                    "OpenSSL OpenSSL 1.0.1B",
                    "OpenSSL OpenSSL 1.0.1c",
                    "OpenSSL OpenSSL 1.0.1D",
                    "OpenSSL OpenSSL 1.0.1E",
                    "OpenSSL OpenSSL 1.0.1f"
                ],
                "Reported": "2014-04-07T00:00:00Z",
                "RiskLevel": 5,
                "Stdcode": [
                    "CVE-2014-0160",
                    "US-CERT VU#720951",
                    "BID-66690",
                    "SA57347",
                    "RHSA-2014-0376",
                "SA57742",
                    "SA57785",
                    "SA57805",
                    "RHSA-2014-0396",
                    "SA57887",
                    "SA57858",
                    "SA57863",
                    "SA57894",
                    "SA57881",
                    "SA57774",
                    "SA57866",
                    "SA58176",
                    "BID-67206"
                ],
                "Tagname": "openssl-cve20140160-info-disc",
                "Title": "OpenSSL heartbeat information disclosure",
                "Xfdbid": 92322
            }
        ],
        "CVESearch": {
            "Bookmark": "g1AAAAEpeJzLYWBgYM5gTmFQS0lKzi9KdUhJMjTXy0zK1a1Iyy9KTjUwMNRLzskvTUnMK9HLSy3JAapnSlIAkkn2____zwLzc4GEiJGBoYmuARCZhxgYWIFRVBIDg7NqFsh4VbjxJoRMz2MBkgwNQApowXwsNhiZoNjArY9mgylxNiyA2LAfwwZTXQMLFBs492RlAQAvQE_q",
            "TotalRows": 3
        }
    }
}
```

##### Human Readable Output
### X-Force CVE Reputation for CVE-2014-0964
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2014-0964
|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | IBM WebSphere Application Server 6.0.2<br />IBM WebSphere Application Server 6.1 | Medium | IBM WebSphere Application Server is not vulnerable to the Heartbleed vulnerability (CVE-2014-0160) where secure data might not be protected. However, there is a potential denial of service on IBM WebSphere Application Server Version 6.1 and 6.0.2 when running the Heartbleed scanning tools or if sending specially-crafted Heartbeat messages. | Unproven | 2014-05-08T00:00:00Z | 7.1 | CVE-2014-0964<br />BID-67322 | IBM WebSphere Application Server and Scanning Tool denial of service | 2.0 |
### X-Force CVE Reputation for BID-67054
https://exchange.xforce.ibmcloud.com/vulnerability/search/BID-67054
|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | HP Integrated Lights-Out 2 (iLO2) 2.23 | Low | HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service, caused by an error when scanned by vulnerability assessment tools scan for the Heartbleed vulnerability. A remote attacker could exploit this vulnerability to cause the server to crash. | Unproven | 2014-04-24T00:00:00Z | 7.8 | BID-67054<br />SA58224<br />CVE-2014-2601 | HP Integrated Lights-Out 2 Heartbleed denial of service | 2.0 |
### X-Force CVE Reputation for CVE-2014-0160
https://exchange.xforce.ibmcloud.com/vulnerability/search/CVE-2014-0160
|Access Vector|Affected Platforms|Complexity|Description|Exploitability|Reported|Risk Level|STD Code|Title|Version|
|---|---|---|---|---|---|---|---|---|---|
| Network | OpenSSL OpenSSL 1.0.1A<br />OpenSSL OpenSSL 1.0.1B<br />OpenSSL OpenSSL 1.0.1c<br />OpenSSL OpenSSL 1.0.1D<br />OpenSSL OpenSSL 1.0.1E<br />OpenSSL OpenSSL 1.0.1f | Low | OpenSSL could allow a remote attacker to obtain sensitive information, caused by an error in the TLS/DTLS heartbeat functionality. An attacker could exploit this vulnerability to remotely read system memory contents without needing to log on to the server. Successful exploitation could allow an attacker to retrieve private keys, passwords or other sensitive information.<br /><br />This vulnerability is commonly referred to as "Heartbleed". | Functional | 2014-04-07T00:00:00Z | 5 | CVE-2014-0160<br />US-CERT VU#720951<br />BID-66690<br />SA57347<br />RHSA-2014-0376<br />RHSA-2014-0378<br />SA57692<br />SA57764<br />SA57759<br />SA57758<br />SA57756<br />SA57786<br />SA57755<br />SA57683<br />SA57810<br />SA57386<br />SA57715<br />SA57822<br />SA57833<br />SA57816<br />SA57772<br />SA57799<br />SA57742<br />SA57785<br />SA57805<br />RHSA-2014-0396<br />SA57887<br />SA57858<br />SA57863<br />SA57894<br />SA57881<br />SA57774<br />SA57866<br />SA57884<br />SA57251<br />SA57775<br />SA57890<br />SA57701<br />SA57888<br />SA57738<br />SA57909<br />SA57900<br />SA57853<br />SA57770<br />SA57773<br />SA57735<br />SA57958<br />SA57483<br />SA57744<br />SA57757<br />SA57850<br />SA57876<br />SA57869<br />SA57921<br />SA57920<br />SA57454<br />SA57628<br />SA57793<br />SA57857<br />SA57972<br />SA57970<br />SA57836<br />SA57966<br />SA57968<br />SA58004<br />SA58005<br />SA58028<br />SA57864<br />SA57979<br />SA58032<br />SA57954<br />SA57999<br />SA57763<br />SA57982<br />SA58024<br />SA57824<br />SA58009<br />SA58033<br />SA57974<br />SA58049<br />SA58046<br />SA57817<br />SA58098<br />SA58048<br />SA58040<br />SA58062<br />SA57815<br />SA58102<br />SA58052<br />SA57941<br />SA57807<br />SA57852<br />SA58113<br />SA58107<br />SA58114<br />SA58115<br />SA58008<br />SA57983<br />SA57969<br />SA57961<br />SA57851<br />SA57960<br />SA57789<br />SA57985<br />SA57984<br />SA58056<br />SA58029<br />SA57512<br />SA58164<br />SA58184<br />SA57911<br />SA58183<br />SA58175<br />SA58166<br />SA57951<br />SA57947<br />SA58171<br />SA58178<br />SA57963<br />SA58167<br />SA57949<br />SA58146<br />SA58019<br />SA58172<br />SA57826<br />SA58182<br />SA58244<br />SA58162<br />SA58188<br />SA58185<br />SA58069<br />SA58058<br />SA58148<br />SA58223<br />SA58124<br />SA58204<br />SA58187<br />SA58190<br />SA58161<br />SA58017<br />SA58195<br />SA58053<br />SA58007<br />SA58022<br />SA58176<br />BID-67206 | OpenSSL heartbeat information disclosure | 2.0 |