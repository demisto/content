Query Indicators of Compromise in AlienVault OTX.
## Configure AlienVault OTX v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server address |  | True |
| API Token |  | False |
| Indicator Threshold. The minimum number of pulses to consider the indicator as malicious. |  | False |
| Maximum number of relationships for indicators | If not provided, no relationships will be added. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Queries an IP address in AlienVault OTX.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the IP address is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The address of the IP. | 
| IP.ASN | String | The autonomous system name for the IP address. For example, "AS8948". | 
| IP.Geo.Country | String | The country where the IP address is located. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| AlienVaultOTX.IP.Reputation | String | The reputation of the IP address. | 
| AlienVaultOTX.IP.IP | String | IP address | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 


#### Command Example
```!ip ip=98.136.103.23```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "IP": {
            "IP": {
                "IP": "98.136.103.23",
                "Reputation": 0
            }
        }
    },
    "DBotScore": {
        "Indicator": "98.136.103.23",
        "Reliability": "C - Fairly reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "AlienVault OTX v2"
    },
    "IP": {
        "ASN": "AS36647 YAHOO-GQ1",
        "Address": "98.136.103.23",
        "Geo": {
            "Country": "US",
            "Location": "37.751:-97.822"
        },
        "Relationships": [
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "EntityB": "T1140 - Deobfuscate/Decode Files or Information",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "EntityB": "T1040 - Network Sniffing",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "EntityB": "T1053 - Scheduled Task/Job",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "EntityB": "T1060 - Registry Run Keys / Startup Folder",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "EntityB": "T1071 - Application Layer Protocol",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "entityB": "mojorojorestaurante.com",
                "entityBType": "URL",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "entityB": "nguyenhoangai-4g.xyz",
                "entityBType": "Domain",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "98.136.103.23",
                "EntityAType": "IP",
                "entityB": "0b4d4a7c35a185680bc5102bdd98218297e2cdf0a552bde10e377345f3622c1c",
                "entityBType": "File",
                "Relationship": "indicator-of"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for ips query
>|ASN|Address|Geo|Relationships|
>|---|---|---|---|
>| AS36647 YAHOO-GQ1 | 98.136.103.23 | Location: 37.751:-97.822<br/>Country: US | {'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP', 'EntityB': 'T1140 - Deobfuscate/Decode Files or Information', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP', 'EntityB': 'T1040 - Network Sniffing', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP', 'EntityB': 'T1053 - Scheduled Task/Job', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP', 'EntityB': 'T1060 - Registry Run Keys / Startup Folder', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP', 'EntityB': 'T1071 - Application Layer Protocol', 'EntityBType': 'Attack Pattern'} |


### domain
***
Queries a domain in AlienVault OTX.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the domain is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. For example, "google.com". | 
| AlienVaultOTX.Domain.Alexa | String | Alexa URL for the domain data. | 
| AlienVaultOTX.Domain.Whois | String | Whois URL for the domain data. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Relationships.EntityA | string | The source of the relationship. | 
| Domain.Relationships.EntityB | string | The destination of the relationship. | 
| Domain.Relationships.Relationship | string | The name of the relationship. | 
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. | 
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. | 


#### Command Example
```!domain domain=ahnlab.myfw.us```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "Domain": {
            "Alexa": "http://www.alexa.com/siteinfo/ahnlab.myfw.us",
            "Name": "ahnlab.myfw.us",
            "Whois": "http://whois.domaintools.com/ahnlab.myfw.us"
        }
    },
    "DBotScore": {
        "Indicator": "ahnlab.myfw.us",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "AlienVault OTX v2"
    },
    "Domain": {
        "Name": "ahnlab.myfw.us",
        "Relationships":[
            {
                "EntityA": "ahnlab.myfw.us",
                "EntityAType": "Domain",
                "EntityB": "b3558ad9f46b72a0319f11889870457dfd611cc4020dbc63945a92869581f774",
                "EntityBType": "File",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "ahnlab.myfw.us",
                "EntityAType": "Domain",
                "EntityB": "219c6da3c6555bba5a3c1138180351dd6d39bc14d3cb491e93a46bff6c5ca271",
                "EntityBType": "File",
                "Relationship": "indicator-of",
            },
            {
                "EntityA": "ahnlab.myfw.us",
                "EntityAType": "Domain",
                "EntityB": "98.136.103.23",
                "EntityBType": "IP",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "ahnlab.myfw.us",
                "EntityAType": "Domain",
                "EntityB": "ahnlab.myfw.us",
                "EntityBType": "IP",
                "Relationship": "indicator-of"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for Domain query
>|Alexa|Name|Whois|
>|---|---|---|
>| http://www.alexa.com/siteinfo/ahnlab.myfw.us | ahnlab.myfw.us | http://whois.domaintools.com/ahnlab.myfw.us |


### alienvault-search-ipv6
***
Queries IPv6 in AlienVault OTX.


#### Base Command

`alienvault-search-ipv6`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the IP address is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. | 
| IP.ASN | String | The autonomous system name for the IP address. For example, "AS8948". | 
| IP.AlienVaultOTX.Reputation | String | The IP reputation in AlienVault OTX. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example
```!alienvault-search-ipv6 ip=2001:4860:4860::8888```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "IP": {
            "IP": {
                "IP": "2001:4860:4860::8888",
                "Reputation": 0
            }
        }
    },
    "DBotScore": {
        "Indicator": "2001:4860:4860::8888",
        "Reliability": "C - Fairly reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "AlienVault OTX v2"
    },
    "IP": {
        "ASN": "AS15169 GOOGLE",
        "Address": "2001:4860:4860::8888",
        "Geo": {
            "Country": "US",
            "Location": "37.751:-97.822"
        },
        "Relationships": [
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1071.004 - DNS",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1071.001 - Web Protocols",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1071 - Application Layer Protocol",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1071.003 - Mail Protocols",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1071.002 - File Transfer Protocols",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "TA0011 - Command and Control",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1048 - Exfiltration Over Alternative Protocol",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            },
            {
                "EntityA": "2001:4860:4860::8888",
                "EntityAType": "IPv6",
                "EntityB": "T1041 - Exfiltration Over C2 Channel",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for ips query
>|ASN|Address|Geo|Relationships|
>|---|---|---|---|
>| AS15169 GOOGLE | 2001:4860:4860::8888 | Location: 37.751:-97.822<br/>Country: US | {'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1071.004 - DNS', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1071.001 - Web Protocols', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1071 - Application Layer Protocol', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1071.003 - Mail Protocols', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1071.002 - File Transfer Protocols', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'TA0011 - Command and Control', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1048 - Exfiltration Over Alternative Protocol', 'EntityBType': 'Attack Pattern'},<br/>{'Relationship': 'indicator-of', 'EntityA': '2001:4860:4860::8888', 'EntityAType': 'IPv6', 'EntityB': 'T1041 - Exfiltration Over C2 Channel', 'EntityBType': 'Attack Pattern'} |


### alienvault-search-hostname
***
Searches for a host name in AlienVault OTX.


#### Base Command

`alienvault-search-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The host name to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the host name is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The hostname that is mapped to the endpoint. | 
| AlienVaultOTX.Endpoint.Hostname | String | The hostname that is mapped to the endpoint. | 
| AlienVaultOTX.Endpoint.Alexa | String | The Alexa URL endpoint. | 
| AlienVaultOTX.Endpoint.Whois | String | The Whois URL endpoint. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 


#### Command Example
```!alienvault-search-hostname hostname=demisto.com```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "Endpoint": {
            "Alexa": "http://www.alexa.com/siteinfo/demisto.com",
            "Hostname": "demisto.com",
            "Whois": "http://whois.domaintools.com/demisto.com"
        }
    },
    "DBotScore": {
        "Indicator": "demisto.com",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "hostname",
        "Vendor": "AlienVault OTX v2"
    },
    "Endpoint": {
        "Hostname": "demisto.com"
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for Hostname query
>|Alexa|Hostname|Whois|
>|---|---|---|
>| http://www.alexa.com/siteinfo/demisto.com | demisto.com | http://whois.domaintools.com/demisto.com |


### file
***
Query a file in AlienVault OTX.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file hash to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the file is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Malicious.PulseIDs | String | IDs of pulses which are marked as malicious. | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| File.Size | Number | The size of the file in bytes. | 
| File.SSDeep | String | The SSDeep hash of the file \(same as displayed in file entries\). | 
| File.Relationships.EntityA | string | The source of the relationship. | 
| File.Relationships.EntityB | string | The destination of the relationship. | 
| File.Relationships.Relationship | string | The name of the relationship. | 
| File.Relationships.EntityAType | string | The type of the source of the relationship. | 
| File.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example
```!file file=6c5360d41bd2b14b1565f5b18e5c203cf512e493```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "6c5360d41bd2b14b1565f5b18e5c203cf512e493",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "AlienVault OTX v2"
    },
    "File": {
        "MD5": "2eb14920c75d5e73264f77cfa273ad2c",
        "Malicious": {
            "PulseIDs": []
        },
        "SHA1": "6c5360d41bd2b14b1565f5b18e5c203cf512e493",
        "SHA256": "4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412",
        "SSDeep": "",
        "Size": "437760",
        "Type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows"
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for File hash query
>|MD5|Malicious|SHA1|SHA256|SSDeep|Size|Type|
>|---|---|---|---|---|---|---|
>| 2eb14920c75d5e73264f77cfa273ad2c | PulseIDs:  | 6c5360d41bd2b14b1565f5b18e5c203cf512e493 | 4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412 |  | 437760 | PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows |


### alienvault-search-cve
***
Query Common Vulnerabilities and Exposures (CVE) in AlienVault OTX.


#### Base Command

`alienvault-search-cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The CVE to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the CVE is considered as malicious. If the threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. For example, "CVE-2015-1653". | 
| CVE.CVSS | String | The CVSS of the CVE. For example, "10.0". | 
| CVE.Published | String | The timestamp of when the CVE was published. | 
| CVE.Modified | String | The timestamp of when the CVE was last modified. | 
| CVE.Description | String | A description of the CVE. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 


#### Command Example
```!alienvault-search-cve cve_id=CVE-2014-0160```

#### Context Example
```json
{
    "CVE": {
        "CVSS": "5.0",
        "Description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.",
        "ID": "CVE-2014-0160",
        "Modified": "2020-07-28T17:11:00",
        "Published": "2014-04-07T22:55:00"
    },
    "DBotScore": {
        "Indicator": "CVE-2014-0160",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "cve",
        "Vendor": "AlienVault OTX v2"
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for Hostname query
>|CVSS|Description|ID|Modified|Published|
>|---|---|---|---|---|
>| 5.0 | The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug. | CVE-2014-0160 | 2020-07-28T17:11:00 | 2014-04-07T22:55:00 |


### alienvault-get-related-urls-by-indicator
***
Returns related URLs by indicator.


#### Base Command

`alienvault-get-related-urls-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indicator type. Can be: "IPv4", "IPv6", "domain", "hostname", or "url". Possible values are: IPv4, IPv6, domain, hostname, url. | Required | 
| indicator | The indicator for which to search related URLs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlienVaultOTX.URL.Data | Unknown | The path of the related URLs. | 


#### Command Example
```!alienvault-get-related-urls-by-indicator indicator=8.8.8.8 indicator_type=IPv4```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "URL": [
            {
                "Data": "https://test.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Related url list to queried indicator
>|Data|
>|---|
>| https://test.com |


### alienvault-get-related-hashes-by-indicator
***
Returns related hashes by indicator.


#### Base Command

`alienvault-get-related-hashes-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator for which to search for related hashes. | Optional | 
| indicator_type | The indicator type. Can be: "IPv4", "IPv6", "domain", or "hostname". Possible values are: IPv4, IPv6, domain, hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlienVaultOTX.File.Hash | Unknown | The path of the url. | 


#### Command Example
```!alienvault-get-related-hashes-by-indicator indicator=8.8.8.8 indicator_type=IPv4```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "File": [
            {
                "Hash": "ffc2595aefa80b61621023252b5f0ccb22b6e31d7f1640913cd8ff74ddbd8b41"
            },
            {
                "Hash": "0b4d4a7c35a185680bc5102bdd98218297e2cdf0a552bde10e377345f3622c1c"
            },
            {
                "Hash": "d8b8a5c941b6a1c3cb58f7e59489b2554ed14e6c6655d1fbf6852e45404b7516"
            },
            {
                "Hash": "b3d8adc185834ab858ebf55082828cb9fc1170bbe8de222821d225a6056ff5dc"
            },
            {
                "Hash": "e43cf3f5fa5e14972ba3f159dee6e98330bd19dccc1267cfc91b1000aef975d9"
            },
            {
                "Hash": "9e11b1e769da3c8059345b36c62b4a857845bd7e14c7c14af2945ce26570d91f"
            },
            {
                "Hash": "ae695ce9b8ff4bb831721a8c60377c1757d6d4fe579640b54f3c7f62b175f506"
            },
            {
                "Hash": "093bde5d50daba59bfe68b31251cf2c39353bdfe8ad510284935ca027f269637"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Related malware list to queried indicator
>**No entries.**


### alienvault-get-passive-dns-data-by-indicator
***
Returns passive DNS records by indicator.


#### Base Command

`alienvault-get-passive-dns-data-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indicator type. Can be: "IPv4", "IPv6", "domain", or "hostname". Possible values are: IPv4, IPv6, domain, hostname. | Required | 
| indicator | The indicator for which to search URLs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlienVaultOTX.PassiveDNS.Hostname | String | The domain value. | 
| AlienVaultOTX.PassiveDNS.IP | String | The IP passive DNS. | 
| AlienVaultOTX.PassiveDNS.Domain | String | The domain value. | 
| AlienVaultOTX.PassiveDNS.Type | String | The asset type. | 
| AlienVaultOTX.PassiveDNS.FirstSeen | Date | The date first seen. | 
| AlienVaultOTX.PassiveDNS.LastSeen | Date | The date last seen. | 


#### Command Example
```!alienvault-get-passive-dns-data-by-indicator indicator=8.8.8.8 indicator_type=IPv4```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "PassiveDNS": [
            {
                "FirstSeen": "2021-04-27T09:48:48",
                "Hostname": "www.heyheyitskateforay.com",
                "IP": "8.8.8.8",
                "LastSeen": "2021-04-27T09:49:05",
                "Type": "hostname"
            },
            {
                "FirstSeen": "2021-04-27T09:48:30",
                "Hostname": "www.djjimmykennedy.com",
                "IP": "8.8.8.8",
                "LastSeen": "2021-04-27T09:49:11",
                "Type": "hostname"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Related passive dns list to queried indicator
>|FirstSeen|Hostname|IP|LastSeen|Type|
>|---|---|---|---|---|
>| 2021-04-27T09:48:48 | www.heyheyitskateforay.com | 8.8.8.8 | 2021-04-27T09:49:05 | hostname |
>| 2021-04-27T09:48:30 | www.djjimmykennedy.com | 8.8.8.8 | 2021-04-27T09:49:11 | hostname |


### alienvault-search-pulses
***
Searches for pulses in AlienVault OTX.


#### Base Command

`alienvault-search-pulses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page of the pulse to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlienVaultOTX.Pulses.ID | String | The ID of the pulse. | 
| AlienVaultOTX.Pulses.Author.ID | String | The ID of the Author. | 
| AlienVaultOTX.Pulses.Author.Username | String | The username of the Author. | 
| AlienVaultOTX.Pulses.Count | String | The pulse count. | 
| AlienVaultOTX.Pulses.Modified | Date | The date of the pulse modification. | 
| AlienVaultOTX.Pulses.Name | String | The name of the pulse. | 
| AlienVaultOTX.Pulses.Source | String | The source of the Pulse. | 
| AlienVaultOTX.Pulses.SubscriberCount | String | The count of the pulse subscriber. | 
| AlienVaultOTX.Pulses.Tags | String | The tags of the pulse. | 
| AlienVaultOTX.Pulses.Description | String | The description of the pulse. | 


#### Command Example
```!alienvault-search-pulses page=1```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "Pulses": [
            {
                "Author": {
                    "ID": "2",
                    "Username": "AlienVault"
                },
                "Count": 28,
                "ID": "546ce8eb11d40838dc6e43f1",
                "Modified": "1273 days ago ",
                "Name": "PoS Scammers Toolbox",
                "Source": "web",
                "SubscriberCount": 141735
            },
            {
                "Author": {
                    "ID": "2",
                    "Username": "AlienVault"
                },
                "Count": 11,
                "ID": "546cf5ba11d40839ea8821ca",
                "Modified": "2098 days ago ",
                "Name": " RAZOR BLADES IN THE CANDY JAR",
                "Source": "web",
                "SubscriberCount": 141715
            },
            {
                "Author": {
                    "ID": "2",
                    "Username": "AlienVault"
                },
                "Count": 10,
                "ID": "546e2e4f11d4083bc021c37d",
                "Modified": "1342 days ago ",
                "Name": "Linking Asprox, Zemot, Rovix and  Rerdom Malware Families ",
                "Source": "web",
                "SubscriberCount": 141707,
                "Tags": [
                    "Asprox",
                    "Zemot",
                    "Rovix"
                ]
            },
            {
                "Author": {
                    "ID": "2",
                    "Username": "AlienVault"
                },
                "Count": 23,
                "ID": "546fc7bf11d4083bc021c37f",
                "Modified": "1341 days ago ",
                "Name": "Operation Double Tap",
                "Source": "web",
                "SubscriberCount": 141711
            },
            {
                "Author": {
                    "ID": "2",
                    "Username": "AlienVault"
                },
                "Count": 60,
                "Description": "Regin is a multi-purpose data collection tool which dates back several years. Symantec first began looking into this threat in the fall of 2013. Multiple versions of Regin were found in the wild, targeting several corporations, institutions, academics, and individuals.\nRegin has a wide range of standard capabilities, particularly around monitoring targets and stealing data. It also has the ability to load custom features tailored to individual targets. Some of Regin\u2019s custom payloads point to a high level of specialist knowledge in particular sectors, such as telecoms infrastructure software, on the part of\nthe developers.",
                "ID": "5473709d11d4083bc021c387",
                "Modified": "824 days ago ",
                "Name": "Regin",
                "Source": "web",
                "SubscriberCount": 141690
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - pulse page 1
>|Author|Count|ID|Modified|Name|Source|SubscriberCount|
>|---|---|---|---|---|---|---|
>| ID: 2<br/>Username: AlienVault | 28 | 546ce8eb11d40838dc6e43f1 | 1273 days ago  | PoS Scammers Toolbox | web | 141735 |
>| ID: 2<br/>Username: AlienVault | 11 | 546cf5ba11d40839ea8821ca | 2098 days ago  |  RAZOR BLADES IN THE CANDY JAR | web | 141715 |
>| ID: 2<br/>Username: AlienVault | 10 | 546e2e4f11d4083bc021c37d | 1342 days ago  | Linking Asprox, Zemot, Rovix and  Rerdom Malware Families  | web | 141707 |
>| ID: 2<br/>Username: AlienVault | 23 | 546fc7bf11d4083bc021c37f | 1341 days ago  | Operation Double Tap | web | 141711 |
>| ID: 2<br/>Username: AlienVault | 60 | 5473709d11d4083bc021c387 | 824 days ago  | Regin | web | 141690 |


### alienvault-get-pulse-details
***
Returns pulse details.


#### Base Command

`alienvault-get-pulse-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pulse_id | The ID of the pulse. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlienVaultOTX.Pulses.Created | Date | The date the pulse was created. | 
| AlienVaultOTX.Pulses.Author.Username | String | The author username of the pulse. | 
| AlienVaultOTX.Pulses.ID | String | The ID of the pulse. | 
| AlienVaultOTX.Pulses.Name | String | The name of the pulse. | 
| AlienVaultOTX.Pulses.Tags | String | The tags of the pulse. | 
| AlienVaultOTX.Pulses.TargetedCountries | String | The targeted countries of the pulse. | 
| AlienVaultOTX.Pulses.Description | String | The description of the pulse. | 


#### Command Example
```!alienvault-get-pulse-details pulse_id=57204e9b3c4c3e015d93cb12```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "Pulses": {
            "Author": {
                "Username": "AlienVault"
            },
            "Created": "2016-04-27T05:31:06.941000",
            "Description": "The infamous Remote Access Trojan (RAT) Poison Ivy (hereafter referred to as PIVY) has resurfaced recently, and exhibits some new behaviors. PIVY has been observed targeting a number of Asian countries for various purposes over the past year. Palo Alto Networks\u2019 Unit 42 recently blogged about a new Poison Ivy variant targeting Hong Kong activists dubbed SPIVY that uses DLL sideloading and operates quite differently from a variant recently observed by ASERT that has been active for at least the past 12 months.",
            "ID": "57204e9b3c4c3e015d93cb12",
            "Name": "Poison Ivy Activity Targeting Myanmar, Asian Countries",
            "Tags": [
                "rat",
                "remote access trojan",
                "poison ivy",
                "pivy",
                "Myanmar",
                "asia",
                "Hong Kong",
                "arbornetworks"
            ],
            "TargetedCountries": []
        }
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - pulse id details
>|Author|Created|Description|ID|Name|Tags|TargetedCountries|
>|---|---|---|---|---|---|---|
>| Username: AlienVault | 2016-04-27T05:31:06.941000 | The infamous Remote Access Trojan (RAT) Poison Ivy (hereafter referred to as PIVY) has resurfaced recently, and exhibits some new behaviors. PIVY has been observed targeting a number of Asian countries for various purposes over the past year. Palo Alto Networks’ Unit 42 recently blogged about a new Poison Ivy variant targeting Hong Kong activists dubbed SPIVY that uses DLL sideloading and operates quite differently from a variant recently observed by ASERT that has been active for at least the past 12 months. | 57204e9b3c4c3e015d93cb12 | Poison Ivy Activity Targeting Myanmar, Asian Countries | rat,<br/>remote access trojan,<br/>poison ivy,<br/>pivy,<br/>Myanmar,<br/>asia,<br/>Hong Kong,<br/>arbornetworks |  |


### url
***
Queries a URL in AlienVault OTX.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to query. | Required | 
| threshold | If the number of pulses is bigger than the threshold, the URL is considered as malicious. If threshold is not specified, the default indicator threshold is used, which is configured in the instance settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. | 
| AlienVaultOTX.URL.Hostname | String | The host name of the URL. | 
| AlienVaultOTX.URL.Domain | String | The domain of the URL. | 
| AlienVaultOTX.URL.Alexa | String | The domain data for the Alexa URL. | 
| AlienVaultOTX.URL.Url | String | Url | 
| AlienVaultOTX.URL.Whois | String | The Whois URL for domain data. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Relationships.EntityA | string | The source of the relationship. | 
| URL.Relationships.EntityB | string | The destination of the relationship. | 
| URL.Relationships.Relationship | string | The name of the relationship. | 
| URL.Relationships.EntityAType | string | The type of the source of the relationship. | 
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. | 


#### Command Example
```!url url="http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list"```

#### Context Example
```json
{
    "AlienVaultOTX": {
        "URL": {
            "Alexa": "http://www.alexa.com/siteinfo/fotoidea.com",
            "Domain": "fotoidea.com",
            "Hostname": "www.fotoidea.com",
            "Url": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
            "Whois": "http://whois.domaintools.com/fotoidea.com"
        }
    },
    "DBotScore": {
        "Indicator": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "url",
        "Vendor": "AlienVault OTX v2"
    },
    "URL": {
        "Data": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
        "Relationships": [
            {
                "EntityA": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
                "EntityAType": "URL",
                "EntityB": "fotoidea.com",
                "EntityBType": "Domain",
                "Relationship": "hosted-on"
            }
        ]
    }
}
```

#### Human Readable Output

>### AlienVault OTX v2 - Results for url query
>|Alexa|Domain|Hostname|Url|Whois|
>|---|---|---|---|---|
>| http://www.alexa.com/siteinfo/fotoidea.com | fotoidea.com | www.fotoidea.com | http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list | http://whois.domaintools.com/fotoidea.com |


## Additional Information
 - AlienVault considers non lowercased URL protocol as invalid, e.g, HTTP://www.google.com. Hence such submissions will be lowercased to ensure a seamless usage of the integration.


## Dbot score calculation method
In case AlienVault OTX API response contains `accepted` under the `false_positive.assessment` key, the DbotScore will be set to **Good**.

Otherwise, if the response includes one validation, DbotScore will be set to **SUSPICIOUS**, if there's no validation in the response then the DbotScore will be set by the `pulse_info` length in the following manner:
   - **Bad** - If the length of is greater or equal to the default threshold given by the user.
   - **SUSPICIOUS** - If the length is shorter than the default threshold.
   - **None** - If the length is zero.

In any other case, the DbotScore will be set to **Good**.