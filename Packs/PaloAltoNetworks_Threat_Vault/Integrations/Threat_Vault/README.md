Use the Palo Alto Networks Threat Vault to research the latest threats (vulnerabilities/exploits, viruses, and spyware) that Palo Alto Networks next-generation firewalls can detect and prevent.

## Configure Palo Alto Networks Threat Vault on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks Threat Vault.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_key | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### threatvault-antivirus-signature-get
***
Gets the antivirus signature.


#### Base Command

`threatvault-antivirus-signature-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The SHA256 hash of the antivirus signature. | Optional | 
| signature_id | The signature ID of the antivirus. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.Antivirus.active | Bool | Whether the antivirus signature is active. | 
| ThreatVault.Antivirus.category | String | The category of the antivirus signature. | 
| ThreatVault.Antivirus.createTime | String | The time the antivirus signature was created. | 
| ThreatVault.Antivirus.release | Unknown | The release details of the antivirus signature. | 
| ThreatVault.Antivirus.sha256 | String | The sha256 hash of the antivirus signature. | 
| ThreatVault.Antivirus.signatureId | Number | The ID of the antivirus signature. | 
| ThreatVault.Antivirus.signatureName | String | The name of the antivirus signature. | 


#### Command Example
```!threatvault-antivirus-signature-get signature_id=93534285```

#### Context Example
```json
{
    "ThreatVault": {
        "Antivirus": {
            "active": true,
            "createTime": "2010-10-01 10:28:57 (UTC)",
            "release": {
                "antivirus": {
                    "firstReleaseTime": "2010-10-03 15:04:58 UTC",
                    "firstReleaseVersion": 334,
                    "latestReleaseVersion": 0
                },
                "wildfire": {
                    "firstReleaseVersion": 0,
                    "latestReleaseVersion": 0
                }
            },
            "sha256": [
                "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
                "9e12c5cdb069f74487c11758e732d72047b72bedf4373aa9e3a58e8e158380f8"
            ],
            "signatureId": 93534285,
            "signatureName": "Worm/Win32.autorun.crck"
        }
    }
}
```

#### Human Readable Output

>### Antivirus:
>|active|createTime|release|sha256|signatureId|signatureName|
>|---|---|---|---|---|---|
>| true | 2010-10-01 10:28:57 (UTC) | wildfire: {"latestReleaseVersion": 0, "firstReleaseVersion": 0}<br/>antivirus: {"latestReleaseVersion": 0, "firstReleaseVersion": 334, "firstReleaseTime": "2010-10-03 15:04:58 UTC"} | 7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8,<br/>9e12c5cdb069f74487c11758e732d72047b72bedf4373aa9e3a58e8e158380f8 | 93534285 | Worm/Win32.autorun.crck |


### file
***
Checks the reputation of an antivirus in Threat Vault.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the antivirus signature. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 


#### Command Example
```!file file= 7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "Score": 0,
            "Type": "file",
            "Vendor": "Zimperium"
        },
        {
            "Indicator": "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "Score": 3,
            "Type": "file",
            "Vendor": "ThreatVault"
        },
        {
            "Indicator": "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "Score": 3,
            "Type": "hash",
            "Vendor": "WildFire"
        },
        {
            "Indicator": "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "Score": 3,
            "Type": "file",
            "Vendor": "WildFire"
        }
    ],
    "File": {
        "MD5": "7e8d3744c0a06d3c7ca7f6dbfce3d576",
        "Malicious": {
            "Vendor": "WildFire"
        },
        "Name": null,
        "SHA1": null,
        "SHA256": "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
        "Size": "117760",
        "Type": "PE"
    },
    "ThreatVault": {
        "Antivirus": {
            "active": true,
            "createTime": "2010-10-01 10:28:57 (UTC)",
            "release": {
                "antivirus": {
                    "firstReleaseTime": "2010-10-03 15:04:58 UTC",
                    "firstReleaseVersion": 334,
                    "latestReleaseVersion": 0
                },
                "wildfire": {
                    "firstReleaseVersion": 0,
                    "latestReleaseVersion": 0
                }
            },
            "sha256": [
                "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
                "9e12c5cdb069f74487c11758e732d72047b72bedf4373aa9e3a58e8e158380f8"
            ],
            "signatureId": 93534285,
            "signatureName": "Worm/Win32.autorun.crck"
        }
    },
    "WildFire": {
        "Report": {
            "SHA256": "7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8",
            "Status": "Success"
        }
    },
    "Zimperium": {
        "Application": null
    }
}
```

#### Human Readable Output

>### WildFire File Report
>|FileType|MD5|SHA256|Size|Status|
>|---|---|---|---|---|
>| PE | 7e8d3744c0a06d3c7ca7f6dbfce3d576 | 7a520be9db919a09d8ccd9b78c11885a6e97bc9cc87414558254cef3081dccf8 | 117760 | Completed |


### threatvault-dns-signature-get-by-id
***
Gets the DNS signature.
For more information about getting the IDs, see: https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/threat-prevention/learn-more-about-and-assess-threats/learn-more-about-threat-signatures.html

#### Base Command

`threatvault-dns-signature-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dns_signature_id | The ID of the DNS signature. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.DNS.active | Bool | Whether the DNS signature is active. | 
| ThreatVault.DNS.category | String | The category of the DNS signature. | 
| ThreatVault.DNS.createTime | String | The time the DNS signature was created. | 
| ThreatVault.DNS.domainName | String | The domain name of the DNS signature. | 
| ThreatVault.DNS.release | Unknown | The release details of the DNS signature. | 
| ThreatVault.DNS.signatureId | Number | The ID of the DNS signature. | 
| ThreatVault.DNS.signatureName | String | The name of the DNS signature. | 


#### Command Example
```!threatvault-dns-signature-get-by-id signature_id=325235352```

#### Context Example
```json
{
    "ThreatVault": {
        "DNS": {}
    }
}
```

#### Human Readable Output

>DNS signature was not found. Please try with a different dns_signature_id.

### threatvault-antispyware-signature-get-by-id
***
Gets the antispyware signature.
For more information about getting the IDs, see: https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/threat-prevention/learn-more-about-and-assess-threats/learn-more-about-threat-signatures.html

#### Base Command

`threatvault-antispyware-signature-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signature_id | ID of the antispyware signature. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.AntiSpyware.firstReleaseVersion | Number | The first released version of the antispyware. | 
| ThreatVault.AntiSpyware.signatureName | String | The name of the antispyware signature. | 
| ThreatVault.AntiSpyware.firstReleaseTime | AntiSpyware | The time the antispyware was first released. | 
| ThreatVault.AntiSpyware.vendor | String | The antispyware vendor. | 
| ThreatVault.AntiSpyware.latestReleaseTime | String | The latest release time of the antispyware. | 
| ThreatVault.AntiSpyware.metadata | Unknown | The metadata of the antispyware. | 
| ThreatVault.AntiSpyware.signatureType | String | The signature type of the antispyware. | 
| ThreatVault.AntiSpyware.cve | String | The status of the antispyware CVE. | 
| ThreatVault.AntiSpyware.status | String | The status of the antispyware. | 
| ThreatVault.AntiSpyware.signatureId | Number | The antispyware signature ID. | 
| ThreatVault.AntiSpyware.latestReleaseVersion | Number | The latest released version of the antispyware. | 


#### Command Example
```!threatvault-antispyware-signature-get-by-id signature_id=10001```

#### Context Example
```json
{
    "ThreatVault": {
        "AntiSpyware": {
            "cve": "",
            "firstReleaseTime": "2011-05-23 UTC",
            "firstReleaseVersion": 248,
            "latestReleaseTime": "2020-11-06 UTC",
            "latestReleaseVersion": 8340,
            "metadata": {
                "action": "alert",
                "category": "spyware",
                "changeData": "",
                "description": "This signature detects a variety of user-agents in HTTP request headers that have been known to be used by the Autorun family of malicious software, and not known to be used by legitimate clients. The request header should be inspected to investigate the suspect user-agent. If the user-agent is atypical or unexpected, the endpoint should be inspected to determine the user-agent used to generate the request on the machine (typically malware).",
                "panOsMaximumVersion": "",
                "panOsMinimumVersion": "6.1.0",
                "reference": "http://www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Win32/Autorun,http://blogs.technet.com/b/mmpc/archive/2011/02/08/breaking-up-the-romance-between-malware-and-autorun.aspx,http://nakedsecurity.sophos.com/2011/06/15/usb-autorun-malware-on-the-wane/",
                "severity": "medium"
            },
            "signatureId": 10001,
            "signatureName": "Autorun User-Agent Traffic",
            "signatureType": "spyware",
            "status": "released",
            "vendor": ""
        }
    }
}
```

#### Human Readable Output

>### Anti Spyware Signature:
>|signatureId|signatureName|signatureType|status|firstReleaseTime|latestReleaseTime|
>|---|---|---|---|---|---|
>| 10001 | Autorun User-Agent Traffic | spyware | released | 2011-05-23 UTC | 2020-11-06 UTC |


### threatvault-ip-geo-get
***
Get the IP address geolocation.


#### Base Command

`threatvault-ip-geo-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.IP.CountryCode | String | The country code. | 
| ThreatVault.IP.CountryName | String | The country name. | 
| ThreatVault.IP.ipAddress | String | The IP address. | 


#### Command Example
```!threatvault-ip-geo-get ip=8.8.8.8```

#### Context Example
```json
{
    "ThreatVault": {
        "IP": {
            "countryCode": "US",
            "countryName": "United States",
            "ipAddress": "8.8.8.8"
        }
    }
}
```

#### Human Readable Output

>### IP location:
>|countryCode|countryName|ipAddress|
>|---|---|---|
>| US | United States | 8.8.8.8 |


### ip
***
Check IP location.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query, e.g., !ip 1.1.1.1 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. | 
| IP.Geo.Country | String | The country of the IP address. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 


#### Command Example
```!ip ip=1.1.1.1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ThreatVault"
    },
    "IP": {
        "Address": "1.1.1.1",
        "Geo": {
            "Country": "Australia"
        }
    },
    "ThreatVault": {
        "IP": {
            "countryCode": "AU",
            "countryName": "Australia",
            "ipAddress": "1.1.1.1"
        }
    }
}
```

#### Human Readable Output

>### IP location:
>|countryCode|countryName|ipAddress|
>|---|---|---|
>| AU | Australia | 1.1.1.1 |


### threatvault-antivirus-signature-search
***
Initiates an antivirus signature search.


#### Base Command

`threatvault-antivirus-signature-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signature_name | The signature name to search. | Required | 
| from | From which signature to return results. Default is 0. | Optional | 
| to | To which signature to return results. Default is from plus 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.Search.search_request_id | String | The ID that was searched. | 
| ThreatVault.Search.status | String | The status of the search. | 


#### Command Example
```!threatvault-antivirus-signature-search signature_name=Worm/Win32.autorun.crck```

#### Context Example
```json
{
    "ThreatVault": {
        "Search": {
            "from": 0,
            "search_request_id": "5d10d1f1-2191-11eb-8c3b-396ee8360b80",
            "search_type": "panav",
            "status": "submitted",
            "to": 10
        }
    }
}
```

#### Human Readable Output

>### Antivirus Signature Search:
>|from|search_request_id|search_type|status|to|
>|---|---|---|---|---|
>| 0 | 5d10d1f1-2191-11eb-8c3b-396ee8360b80 | panav | submitted | 10 |


### threatvault-dns-signature-search
***
Initiates a DNS signature search.


#### Base Command

`threatvault-dns-signature-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signature_name | The signature name to search. | Optional | 
| domain_name | The domain name to search. | Optional | 
| from | From which signature to return results. Default is 0. | Optional | 
| to | To which signature to return results. Default is from plus 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.Search.search_request_id | String | The ID to search. | 
| ThreatVault.Search.status | String | The status of the search. | 


#### Command Example
```!threatvault-dns-signature-search domain_name=google.com```

#### Context Example
```json
{
    "ThreatVault": {
        "Search": {
            "from": 0,
            "search_request_id": "5a2e4b67-2191-11eb-aaa0-476a91ad21a0",
            "search_type": "dns",
            "status": "submitted",
            "to": 10
        }
    }
}
```

#### Human Readable Output

>### DNS Signature Search:
>|from|search_request_id|search_type|status|to|
>|---|---|---|---|---|
>| 0 | 5a2e4b67-2191-11eb-aaa0-476a91ad21a0 | dns | submitted | 10 |


### threatvault-antispyware-signature-search
***
Initiates an antispyware signature search.


#### Base Command

`threatvault-antispyware-signature-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signature_name | The signature name to search. | Optional | 
| vendor | The vendor name to search. | Optional | 
| cve | The CVE name to search. | Optional | 
| from | From which signature to return results. Default is 0. | Optional | 
| to | To which signature to return results. Default is from plus 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.Search.search_request_id | String | The ID to search. | 
| ThreatVault.Search.status | String | The status of the search. | 


#### Command Example
```!threatvault-antispyware-signature-search cve=CVE-2015-8650```

#### Context Example
```json
{
    "ThreatVault": {
        "Search": {
            "from": 0,
            "search_request_id": "5bb4285c-2191-11eb-b288-43f099eed11d",
            "search_type": "ips",
            "status": "submitted",
            "to": 10
        }
    }
}
```

#### Human Readable Output

>### Anti Spyware Signature Search:
>|from|search_request_id|search_type|status|to|
>|---|---|---|---|---|
>| 0 | 5bb4285c-2191-11eb-b288-43f099eed11d | ips | submitted | 10 |


### threatvault-signature-search-results
***
Initiates an antispyware signature search.


#### Base Command

`threatvault-signature-search-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_request_id | The ID to search. | Required | 
| search_type | Search type. "ips" for antispyware, "dns" for DNS, and "panav" for antivirus. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatVault.Search.search_request_id | String | The ID that was searched. | 
| ThreatVault.Search.status | String | The status of the search. | 
| ThreatVault.Search.page_count | Number | The number of results returned in this specific search. | 
| ThreatVault.Search.total_count | Number | The number of results available for this specific search. | 
| ThreatVault.Search.search_type | String | The search type. Can be either "ips", "dns". or "panav". | 
| ThreatVault.Searchf.signatures | Unknown | A list of all the signatures found for this specific search. | 


#### Command Example
```!threatvault-signature-search-results search_type=dns search_request_id=8e9e2289-218f-11eb-b876-aba382af19b4```

#### Context Example
```json
{
    "ThreatVault": {
        "Search": {
            "page_count": 10,
            "search_request_id": "8e9e2289-218f-11eb-b876-aba382af19b4",
            "signatures": [
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-03-03 14:45:03 (UTC)",
                    "domainName": "mail-google.com.co",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-03-03 15:11:53 UTC",
                            "firstReleaseVersion": 1890,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 44101494,
                    "signatureName": "generic:mail-google.com.co"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-03-16 12:06:22 (UTC)",
                    "domainName": "www.google.com.shufaren.com.cn",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-03-16 15:13:36 UTC",
                            "firstReleaseVersion": 1903,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 45245562,
                    "signatureName": "generic:ogle.com.shufaren.com.cn"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-08-01 12:05:04 (UTC)",
                    "domainName": "verify.google.com.drive.viewdocument.buyers-exporters.com",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-08-01 15:12:15 UTC",
                            "firstReleaseVersion": 2055,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 60834054,
                    "signatureName": "generic:ent.buyers-exporters.com"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-08-01 12:05:05 (UTC)",
                    "domainName": "www.google.com-document-view.alibabatradegroup.com",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-08-01 15:12:15 UTC",
                            "firstReleaseVersion": 2055,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 60834216,
                    "signatureName": "generic:ew.alibabatradegroup.com"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-09-02 06:35:01 (UTC)",
                    "domainName": "accounts.google.com-sl.com",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-09-02 15:12:14 UTC",
                            "firstReleaseVersion": 2087,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 63218626,
                    "signatureName": "generic:counts.google.com-sl.com"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-10-10 23:06:14 (UTC)",
                    "domainName": "firstpagegoogle.com.au",
                    "release": {
                        "antivirus": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 69081944,
                    "signatureName": "None:firstpagegoogle.com.au"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-10-17 17:26:42 (UTC)",
                    "domainName": "plus.google.com.sxn.us",
                    "release": {
                        "antivirus": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 70722314,
                    "signatureName": "generic:plus.google.com.sxn.us"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-11-22 16:47:53 (UTC)",
                    "domainName": "chinagoogle.com.cn",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-11-22 15:10:51 UTC",
                            "firstReleaseVersion": 2178,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 82194404,
                    "signatureName": "generic:chinagoogle.com.cn"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-12-01 16:37:43 (UTC)",
                    "domainName": "google.com.im",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-12-01 15:11:36 UTC",
                            "firstReleaseVersion": 2191,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 83804135,
                    "signatureName": "generic:google.com.im"
                },
                {
                    "active": true,
                    "category": "malware",
                    "createTime": "2015-12-02 17:13:32 (UTC)",
                    "domainName": "documents.google.com.hjkeme3fxcncyygkfmsjvxsn.shhitmobil.com.ua",
                    "release": {
                        "antivirus": {
                            "firstReleaseTime": "2015-12-02 15:11:48 UTC",
                            "firstReleaseVersion": 2192,
                            "latestReleaseVersion": 0
                        },
                        "wildfire": {
                            "firstReleaseVersion": 0,
                            "latestReleaseVersion": 0
                        }
                    },
                    "signatureId": 84099818,
                    "signatureName": "generic:sjvxsn.shhitmobil.com.ua"
                }
            ],
            "status": "completed",
            "total_count": 5385
        }
    }
}
```

#### Human Readable Output

>### Signature search are showing 10 of 5385 results:
>|signatureId|signatureName|domainName|category|
>|---|---|---|---|
>| 44101494 | generic:mail-google.com.co | mail-google.com.co | malware |
>| 45245562 | generic:ogle.com.shufaren.com.cn | www.google.com.shufaren.com.cn | malware |
>| 60834054 | generic:ent.buyers-exporters.com | verify.google.com.drive.viewdocument.buyers-exporters.com | malware |
>| 60834216 | generic:ew.alibabatradegroup.com | www.google.com-document-view.alibabatradegroup.com | malware |
>| 63218626 | generic:counts.google.com-sl.com | accounts.google.com-sl.com | malware |
>| 69081944 | None:firstpagegoogle.com.au | firstpagegoogle.com.au | malware |
>| 70722314 | generic:plus.google.com.sxn.us | plus.google.com.sxn.us | malware |
>| 82194404 | generic:chinagoogle.com.cn | chinagoogle.com.cn | malware |
>| 83804135 | generic:google.com.im | google.com.im | malware |
>| 84099818 | generic:sjvxsn.shhitmobil.com.ua | documents.google.com.hjkeme3fxcncyygkfmsjvxsn.shhitmobil.com.ua | malware |

