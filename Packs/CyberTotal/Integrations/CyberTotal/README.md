CyberTotal is a cloud-based threat intelligence service developed by CyCraft.
This integration was integrated and tested with version 1.6.4 of CyberTotal
## Configure CyberTotal in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | CyberTotal URL | True |
| token | CyberTotal API Token | True |
| feed | Fetch indicators | False |
| threshold_ip | Bad ip threshold | False |
| threshold_file | Bad hash threshold | False |
| threshold_domain | Bad domain threshold | False |
| threshold_url | Bad url threshold | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP information and reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 
| threshold | If the IP has reputation above the threshold then the IP defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.IP.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.IP.resource | string |  The scan target sent to CyberTotal. | 
| CyberTotal.IP.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.IP.permalink | string | The link of this IP’s report in CyberTotal. | 
| CyberTotal.IP.severity | number | Severity of this IP. The range is from 0 to 10. | 
| CyberTotal.IP.confidence | number | Confidence of this IP. The range is from 0 to 10. | 
| CyberTotal.IP.threat | string | Threat of this IP, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.IP.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.IP.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.IP.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.IP.message | string | Message about this search. | 
| IP.Address | String | IP address | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!ip ip=1.1.1.1```

#### Context Example
```
{
    "CyberTotal": {
        "IP": {
            "confidence": 3,
            "detection_engines": 87,
            "detection_ratio": "4/87",
            "message": "search success",
            "permalink": "https://cybertotal.cycraft.com/app/intelligence/5a2601d575ea44058efeb1aba995dc8d",
            "positive_detections": 4,
            "resource": "1.1.1.1",
            "scan_date": "2020-07-28T14:11:19+00:00",
            "severity": 9,
            "task_id": "5a2601d575ea44058efeb1aba995dc8d",
            "threat": "High"
        }
    },
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 1,
        "Type": "ip",
        "Vendor": "CyberTotal"
    },
    "IP": {
        "Address": "1.1.1.1",
        "DetectionEngines": 87,
        "PositiveDetections": 4
    }
}
```

#### Human Readable Output

>### IP List
>|confidence|detection_engines|detection_ratio|message|permalink|positive_detections|resource|scan_date|severity|task_id|threat|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 3 | 87 | 4/87 | search success | https://cybertotal.cycraft.com/app/intelligence/5a2601d575ea44058efeb1aba995dc8d | 4 | 1.1.1.1 | 2020-07-28T14:11:19+00:00 | 9 | 5a2601d575ea44058efeb1aba995dc8d | High |


### file
***
Return file's information and reputation


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | list of hash(s). | Required | 
| threshold | If the HASH has reputation above the threshold then the HASH defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.File.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.File.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.File.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.File.permalink | string | The link of this HASH’s report in CyberTotal. | 
| CyberTotal.File.severity | number | Severity of this HASH. The range is from 0 to 10. | 
| CyberTotal.File.confidence | number | Confidence of this HASH. The range is from 0 to 10. | 
| CyberTotal.File.threat | string | Threat of this HASH, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.File.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.File.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.File.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.File.message | string | Message about this search. | 
| CyberTotal.File.size | string | Size of this file. | 
| CyberTotal.File.md5 | string | This file’s md5 value. | 
| CyberTotal.File.sha1 | string | This file’s sha1 value. | 
| CyberTotal.File.sha256 | string | This file’s sha256 value. | 
| CyberTotal.File.extension | string | This file’s extension type. | 
| CyberTotal.File.name | string | This file’s name, separated by ‘,’ if more than 2 names. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.Extension | String | The file extension, for example: 'xls'. | 
| File.Size | Number | The size of the file in bytes. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!file file=b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e```

#### Context Example
```
{
    "CyberTotal": {
        "File": {
            "confidence": 10,
            "detection_engines": 70,
            "detection_ratio": "58/70",
            "extension": "exe",
            "md5": "19063b2a1b1a7930aef31678903b7088",
            "message": "search success",
            "name": "19063b2a1b1a7930aef31678903b7088.virus",
            "permalink": "https://cybertotal.cycraft.com/app/intelligence/7a37a8d7a32847c9b3eee5a4431c9ab5",
            "positive_detections": 58,
            "resource": "b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e",
            "scan_date": "2020-07-09T15:11:56+00:00",
            "severity": 10,
            "sha1": "c771b33f4f3867f95721d0eceed5c4040c78d3ee",
            "sha256": "b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e",
            "size": "28672",
            "task_id": "7a37a8d7a32847c9b3eee5a4431c9ab5",
            "threat": "High"
        }
    },
    "DBotScore": {
        "Indicator": "b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e",
        "Score": 3,
        "Type": "file",
        "Vendor": "CyberTotal"
    },
    "File": {
        "Extension": "exe",
        "MD5": "19063b2a1b1a7930aef31678903b7088",
        "Malicious": {
            "Description": "CyberTotal returned reputation 58",
            "Vendor": "CyberTotal"
        },
        "Name": "19063b2a1b1a7930aef31678903b7088.virus",
        "SHA1": "c771b33f4f3867f95721d0eceed5c4040c78d3ee",
        "SHA256": "b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e",
        "Size": "28672"
    }
}
```

#### Human Readable Output

>### File List
>|confidence|detection_engines|detection_ratio|extension|md5|message|name|permalink|positive_detections|resource|scan_date|severity|sha1|sha256|size|task_id|threat|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 10 | 70 | 58/70 | exe | 19063b2a1b1a7930aef31678903b7088 | search success | 19063b2a1b1a7930aef31678903b7088.virus | https://cybertotal.cycraft.com/app/intelligence/7a37a8d7a32847c9b3eee5a4431c9ab5 | 58 | b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e | 2020-07-09T15:11:56+00:00 | 10 | c771b33f4f3867f95721d0eceed5c4040c78d3ee | b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e | 28672 | 7a37a8d7a32847c9b3eee5a4431c9ab5 | High |


### domain
***
Return domain information and reputation


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Required | 
| threshold | If the domain has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.Domain.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.Domain.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.Domain.permalink | string | The link of this domain’s report in CyberTotal. | 
| CyberTotal.Domain.severity | number | Severity of this domain. The range is from 0 to 10. | 
| CyberTotal.Domain.confidence | number | Confidence of this domain. The range is from 0 to 10. | 
| CyberTotal.Domain.threat | string | Threat of this domain, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.Domain.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.Domain.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.Domain.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.Domain.message | string | Message about this search. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!domain domain=abc.com```

#### Context Example
```
{
    "CyberTotal": {
        "Domain": {
            "confidence": 7,
            "detection_engines": 79,
            "detection_ratio": "0/79",
            "message": "search success",
            "permalink": "https://cybertotal.cycraft.com/app/intelligence/79ca1bd740564c36a7a4a78df5dc719d",
            "positive_detections": 0,
            "resource": "abc.com",
            "scan_date": "2020-06-18T03:19:48+00:00",
            "severity": 6,
            "task_id": "79ca1bd740564c36a7a4a78df5dc719d",
            "threat": "Medium"
        }
    },
    "DBotScore": {
        "Indicator": "abc.com",
        "Score": 0,
        "Type": "domain",
        "Vendor": "CyberTotal"
    },
    "Domain": {
        "DetectionEngines": 79,
        "Name": "abc.com"
    }
}
```

#### Human Readable Output

>### Domain List
>|confidence|detection_engines|detection_ratio|message|permalink|positive_detections|resource|scan_date|severity|task_id|threat|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 7 | 79 | 0/79 | search success | https://cybertotal.cycraft.com/app/intelligence/79ca1bd740564c36a7a4a78df5dc719d | 0 | abc.com | 2020-06-18T03:19:48+00:00 | 6 | 79ca1bd740564c36a7a4a78df5dc719d | Medium |


### url
***
Return domain information and reputation


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of url(s). | Required | 
| threshold | If the URL has reputation above the threshold then the URL defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.URL.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.URL.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.URL.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.URL.permalink | string | The link of this URL’s report in CyberTotal. | 
| CyberTotal.URL.severity | number | Severity of this URL. The range is from 0 to 10. | 
| CyberTotal.URL.confidence | number | Confidence of this URL. The range is from 0 to 10. | 
| CyberTotal.URL.threat | string | Threat of this URL, which is a select from ‘High’, ‘Medium’ and ‘Low’. | 
| CyberTotal.URL.detection_engines | number | The number of all antivirus vendors scanned. | 
| CyberTotal.URL.positive_detections | number | The number of antivirus vendors scanned with positive detection. | 
| CyberTotal.URL.detection_ratio | string | The ratio of positive\_detections and detection\_engines. | 
| CyberTotal.URL.message | string | Message about this search. | 
| URL.Data | String | The URL | 
| URL.DetectionEngines | String | The total number of engines that checked the indicator. | 
| URL.PositiveDetections | String | The number of engines that positively detected the indicator as malicious. | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!url url=http://abc.com```

#### Context Example
```
{
    "CyberTotal": {
        "URL": {
            "confidence": 1,
            "detection_engines": 79,
            "detection_ratio": "0/79",
            "message": "search success",
            "permalink": "https://cybertotal.cycraft.com/app/intelligence/61bbc65f5c034930b8a659c39e745d96",
            "positive_detections": 0,
            "resource": "http://abc.com",
            "scan_date": "2020-06-22T07:24:16+00:00",
            "severity": 5,
            "task_id": "61bbc65f5c034930b8a659c39e745d96",
            "threat": "Medium"
        }
    },
    "DBotScore": {
        "Indicator": "http://abc.com",
        "Score": 0,
        "Type": "url",
        "Vendor": "CyberTotal"
    },
    "URL": {
        "Data": "http://abc.com",
        "DetectionEngines": 79
    }
}
```

#### Human Readable Output

>### URL List
>|confidence|detection_engines|detection_ratio|message|permalink|positive_detections|resource|scan_date|severity|task_id|threat|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 79 | 0/79 | search success | https://cybertotal.cycraft.com/app/intelligence/61bbc65f5c034930b8a659c39e745d96 | 0 | http://abc.com | 2020-06-22T07:24:16+00:00 | 5 | 61bbc65f5c034930b8a659c39e745d96 | Medium |


### cybertotal-ip-whois
***
Return ip whois information


#### Base Command

`cybertotal-ip-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IP(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.WHOIS-IP.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-IP.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-IP.message | string | Message about this search. | 
| CyberTotal.WHOIS-IP.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-IP.createdAt | date | Create date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.updatedAt | date | Update date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.status | string | Status of this IP | 
| CyberTotal.WHOIS-IP.domain | string | Domain of this IP | 
| CyberTotal.WHOIS-IP.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-IP.domain | 
| CyberTotal.WHOIS-IP.domainUnicode | string | Encode CyberTotal.WHOIS\-IP.domain by using unicode | 
| CyberTotal.WHOIS-IP.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-IP.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-IP.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-IP.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-IP.registrarCreatedAt | date | Registrar create date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.registrarUpdatedAt | date | Registrar update date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.registrarExpiresAt | date | Registrar expire date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.auditCreatedAt | date | Registrar update date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.auditUpdatedAt | date | Registrar expire date format: ISO 8601 | 
| CyberTotal.WHOIS-IP.registrant.name | string | The name of registrant | 
| CyberTotal.WHOIS-IP.registrant.organization | string | The organization name of registrant | 
| CyberTotal.WHOIS-IP.registrant.street | string | The street name of registrant | 
| CyberTotal.WHOIS-IP.registrant.city | string | The location city of registrant | 
| CyberTotal.WHOIS-IP.registrant.state | string | The location state name of registrant | 
| CyberTotal.WHOIS-IP.registrant.zip | string | The post zip code of registrant | 
| CyberTotal.WHOIS-IP.registrant.country | string | The country of registrant | 
| CyberTotal.WHOIS-IP.registrant.address | string | The address of registrant | 
| CyberTotal.WHOIS-IP.admin.name | string | The name of admin | 
| CyberTotal.WHOIS-IP.admin.organization | string | The organization name of admin | 
| CyberTotal.WHOIS-IP.admin.street | string | The street name of admin | 
| CyberTotal.WHOIS-IP.admin.city | string | The location city of admin | 
| CyberTotal.WHOIS-IP.admin.state | string | The location state name of admin | 
| CyberTotal.WHOIS-IP.admin.zip | string | The post zip code of admin | 
| CyberTotal.WHOIS-IP.admin.country | string | The country of admin | 
| CyberTotal.WHOIS-IP.admin.address | string | The address of admin | 
| CyberTotal.WHOIS-IP.technical.name | string | The name of technical | 
| CyberTotal.WHOIS-IP.technical.organization | string | The organization name of technical | 
| CyberTotal.WHOIS-IP.technical.street | string | The street name of technical | 
| CyberTotal.WHOIS-IP.technical.city | string | The location city of technical | 
| CyberTotal.WHOIS-IP.technical.state | string | The location state name of technical | 
| CyberTotal.WHOIS-IP.technical.zip | string | The post zip code of technical | 
| CyberTotal.WHOIS-IP.technical.country | string | The country of technical | 
| CyberTotal.WHOIS-IP.technical.address | string | The address of technical | 
| CyberTotal.WHOIS-IP.contactEmails | string | An array of all contact email address | 
| CyberTotal.WHOIS-IP.contacts | string | An array of all contact details | 
| CyberTotal.WHOIS-IP.contactNames | string | An array of all contact names | 
| CyberTotal.WHOIS-IP.contactCountries | string | An array of all contact countries | 
| CyberTotal.WHOIS-IP.domainAvailable | boolean | If this domain is available | 
| CyberTotal.WHOIS-IP.expired | boolean | If this IP is expired | 


#### Command Example
```!cybertotal-ip-whois ip=1.1.1.1```

#### Context Example
```
{
    "CyberTotal": {
        "WHOIS-IP": {
            "abuse": {
                "address": "po box 3646\n4101\nqld\naustralia\n",
                "country": "australia",
                "email": "xxx@xxx.net",
                "id": 0,
                "name": "IRT-APNICRANDNET-AU",
                "state": "qld",
                "street": "po box 3646",
                "whoisContactID": 0,
                "zip": "4101"
            },
            "admin": {
                "address": "po box 3646\n4101\nqld\naustralia\n",
                "country": "australia",
                "email": "research@apnic.net",
                "fax": "+61-7-3858-3199",
                "id": 0,
                "name": "APNIC RESEARCH",
                "phone": "+61-7-3858-3188",
                "state": "qld",
                "street": "po box 3646",
                "whoisContactID": 0,
                "zip": "4101"
            },
            "auditCreatedAt": "2020-07-18T02:07:02+00:00",
            "auditUpdatedAt": "2020-07-18T02:07:02+00:00",
            "compositeParseCode": 10528,
            "contactCountries": [
                "australia"
            ],
            "contactEmails": [
                "research@apnic.net"
            ],
            "contactNames": [
                "APNIC RESEARCH"
            ],
            "contactOrganizations": [],
            "contacts": [
                {
                    "address": "po box 3646\n4101\nqld\naustralia\n",
                    "country": "australia",
                    "email": "research@apnic.net",
                    "fax": "+61-7-3858-3199",
                    "id": 0,
                    "name": "APNIC RESEARCH",
                    "phone": "+61-7-3858-3188",
                    "state": "qld",
                    "street": "po box 3646",
                    "whoisContactID": 0,
                    "zip": "4101"
                }
            ],
            "createdAt": "2020-07-18T02:07:02+00:00",
            "domain": "1.1.1.0",
            "domainAvailable": false,
            "domainMd5": "ede514d996ecdf82a0abf5356ff6a13c",
            "domainUnicode": "1.1.1.0",
            "expired": false,
            "id": 6690074356934458000,
            "message": "search success",
            "nameservers": [],
            "netRange": {
                "ipEnd": "1.1.1.255",
                "ipStart": "1.1.1.0",
                "netName": "APNIC-LABS",
                "netRange": "1.1.1.0 - 1.1.1.255",
                "numericEnd": 16843263,
                "numericStart": 16843008,
                "status": "INACTIVE",
                "whoisNetRangeID": 0
            },
            "noRecord": false,
            "permalink": [
                "https://cybertotal.cycraft.com/app/intelligence/5a2601d575ea44058efeb1aba995dc8d"
            ],
            "registrarName": "APNIC",
            "registrarParseCode": 10528,
            "registrarUpdatedAt": "2020-07-15T13:10:57+00:00",
            "resource": [
                "1.1.1.1"
            ],
            "scan_date": [
                "2020-07-28 14:11:19"
            ],
            "status": "ACTIVE",
            "task_id": "5a2601d575ea44058efeb1aba995dc8d",
            "technical": {
                "address": "po box 3646\n4101\nqld\naustralia\n",
                "country": "australia",
                "email": "research@apnic.net",
                "fax": "+61-7-3858-3199",
                "id": 0,
                "name": "APNIC RESEARCH",
                "phone": "+61-7-3858-3188",
                "state": "qld",
                "street": "po box 3646",
                "whoisContactID": 0,
                "zip": "4101"
            },
            "tld": "ipv4",
            "updatedAt": "2020-07-18T02:07:02+00:00",
            "whoisID": 6690074356934458000,
            "whoisServer": "rdap.apnic.net"
        }
    }
}
```

#### Human Readable Output

>### Results
>|abuse|admin|auditCreatedAt|auditUpdatedAt|compositeParseCode|contactCountries|contactEmails|contactNames|contactOrganizations|contacts|createdAt|domain|domainAvailable|domainMd5|domainUnicode|expired|id|message|nameservers|netRange|noRecord|permalink|registrarName|registrarParseCode|registrarUpdatedAt|resource|scan_date|status|task_id|technical|tld|updatedAt|whoisID|whoisServer|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: IRT-APNICRANDNET-AU<br/>street: po box 3646<br/>state: qld<br/>zip: 4101<br/>country: australia<br/>address: po box 3646<br/>4101<br/>qld<br/>australia<br/><br/>id: 0 | whoisContactID: 0<br/>email: research@apnic.net<br/>name: APNIC RESEARCH<br/>street: po box 3646<br/>state: qld<br/>zip: 4101<br/>country: australia<br/>phone: +61-7-3858-3188<br/>fax: +61-7-3858-3199<br/>address: po box 3646<br/>4101<br/>qld<br/>australia<br/><br/>id: 0 | 2020-07-18T02:07:02+00:00 | 2020-07-18T02:07:02+00:00 | 10528 | australia | research@apnic.net | APNIC RESEARCH |  | {'whoisContactID': 0, 'email': 'research@apnic.net', 'name': 'APNIC RESEARCH', 'street': 'po box 3646', 'state': 'qld', 'zip': '4101', 'country': 'australia', 'phone': '+61-7-3858-3188', 'fax': '+61-7-3858-3199', 'address': 'po box 3646\n4101\nqld\naustralia\n', 'id': 0} | 2020-07-18T02:07:02+00:00 | 1.1.1.0 | false | ede514d996ecdf82a0abf5356ff6a13c | 1.1.1.0 | false | 6690074356934458403 | search success |  | status: INACTIVE<br/>whoisNetRangeID: 0<br/>netRange: 1.1.1.0 - 1.1.1.255<br/>netName: APNIC-LABS<br/>ipStart: 1.1.1.0<br/>ipEnd: 1.1.1.255<br/>numericEnd: 16843263<br/>numericStart: 16843008 | false | ["https://cybertotal.cycraft.com/app/intelligence/5a2601d575ea44058efeb1aba995dc8d"] | APNIC | 10528 | 2020-07-15T13:10:57+00:00 | ["1.1.1.1"] | ["2020-07-28 14:11:19"] | ACTIVE | 5a2601d575ea44058efeb1aba995dc8d | whoisContactID: 0<br/>email: research@apnic.net<br/>name: APNIC RESEARCH<br/>street: po box 3646<br/>state: qld<br/>zip: 4101<br/>country: australia<br/>phone: +61-7-3858-3188<br/>fax: +61-7-3858-3199<br/>address: po box 3646<br/>4101<br/>qld<br/>australia<br/><br/>id: 0 | ipv4 | 2020-07-18T02:07:02+00:00 | 6690074356934458403 | rdap.apnic.net |


### cybertotal-url-whois
***
Return url whois information


#### Base Command

`cybertotal-url-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URL(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.WHOIS-URL.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-URL.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-URL.message | string | Message about this search. | 
| CyberTotal.WHOIS-URL.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-URL.createdAt | date | Create date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.updatedAt | date | Update date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.status | string | Status of this IP | 
| CyberTotal.WHOIS-URL.domain | string | Domain of this IP | 
| CyberTotal.WHOIS-URL.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-URL.domain | 
| CyberTotal.WHOIS-URL.domainUnicode | string | Encode CyberTotal.WHOIS\-URL.domain by using unicode | 
| CyberTotal.WHOIS-URL.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-URL.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-URL.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-URL.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-URL.registrarCreatedAt | date | Registrar create date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.registrarUpdatedAt | date | Registrar update date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.registrarExpiresAt | date | Registrar expire date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.auditCreatedAt | date | Registrar update date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.auditUpdatedAt | date | Registrar expire date format: ISO 8601 | 
| CyberTotal.WHOIS-URL.registrant.name | string | The name of registrant | 
| CyberTotal.WHOIS-URL.registrant.organization | string | The organization name of registrant | 
| CyberTotal.WHOIS-URL.registrant.street | string | The street name of registrant | 
| CyberTotal.WHOIS-URL.registrant.city | string | The location city of registrant | 
| CyberTotal.WHOIS-URL.registrant.state | string | The location state name of registrant | 
| CyberTotal.WHOIS-URL.registrant.zip | string | The post zip code of registrant | 
| CyberTotal.WHOIS-URL.registrant.country | string | The country of registrant | 
| CyberTotal.WHOIS-URL.registrant.address | string | The address of registrant | 
| CyberTotal.WHOIS-URL.admin.name | string | The name of admin | 
| CyberTotal.WHOIS-URL.admin.organization | string | The organization name of admin | 
| CyberTotal.WHOIS-URL.admin.street | string | The street name of admin | 
| CyberTotal.WHOIS-URL.admin.city | string | The location city of admin | 
| CyberTotal.WHOIS-URL.admin.state | string | The location state name of admin | 
| CyberTotal.WHOIS-URL.admin.zip | string | The post zip code of admin | 
| CyberTotal.WHOIS-URL.admin.country | string | The country of admin | 
| CyberTotal.WHOIS-URL.admin.address | string | The address of admin | 
| CyberTotal.WHOIS-URL.technical.name | string | The name of technical | 
| CyberTotal.WHOIS-URL.technical.organization | string | The organization name of technical | 
| CyberTotal.WHOIS-URL.technical.street | string | The street name of technical | 
| CyberTotal.WHOIS-URL.technical.city | string | The location city of technical | 
| CyberTotal.WHOIS-URL.technical.state | string | The location state name of technical | 
| CyberTotal.WHOIS-URL.technical.zip | string | The post zip code of technical | 
| CyberTotal.WHOIS-URL.technical.country | string | The country of technical | 
| CyberTotal.WHOIS-URL.technical.address | string | The address of technical | 
| CyberTotal.WHOIS-URL.contactEmails | string | An array of all contact email address | 
| CyberTotal.WHOIS-URL.contacts | string | An array of all contact details | 
| CyberTotal.WHOIS-URL.contactNames | string | An array of all contact names | 
| CyberTotal.WHOIS-URL.contactCountries | string | An array of all contact countries | 
| CyberTotal.WHOIS-URL.domainAvailable | boolean | If this domain is available | 
| CyberTotal.WHOIS-URL.expired | boolean | If this URL is expired | 


#### Command Example
```!cybertotal-url-whois url=http://abc.com```

#### Context Example
```
{
    "CyberTotal": {
        "WHOIS-URL": {
            "admin": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "xxx@xxx.net",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "auditCreatedAt": "2020-04-09T07:17:45+00:00",
            "auditUpdatedAt": "2020-04-09T07:17:45+00:00",
            "compositeParseCode": 3579,
            "contactCountries": [
                "US"
            ],
            "contactEmails": [
                "corp.dns.domains@disney.com"
            ],
            "contactNames": [
                "ABC, Inc.; Domain Administrator"
            ],
            "contactOrganizations": [
                "ABC, Inc."
            ],
            "contacts": [
                {
                    "address": "New York\n10023-6298\nNY\nUS\n",
                    "city": "New York",
                    "country": "US",
                    "email": "xxx@xxx.net",
                    "fax": "18182384694",
                    "id": 0,
                    "name": "ABC, Inc.; Domain Administrator",
                    "organization": "ABC, Inc.",
                    "phone": "18182384694",
                    "state": "NY",
                    "whoisContactID": 0,
                    "zip": "10023-6298"
                }
            ],
            "createdAt": "2020-04-09T07:17:45+00:00",
            "domain": "abc.com",
            "domainAvailable": false,
            "domainMd5": "929ba26f492f86d4a9d66a080849865a",
            "domainStatus": "clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited",
            "domainUnicode": "abc.com",
            "expired": false,
            "id": 6653913764397840000,
            "message": "search success",
            "nameservers": [
                "ns-1368.awsdns-43.org",
                "ns-1869.awsdns-41.co.uk",
                "ns-318.awsdns-39.com",
                "ns-736.awsdns-28.net"
            ],
            "noRecord": false,
            "permalink": [
                "https://cybertotal.cycraft.com/app/intelligence/61bbc65f5c034930b8a659c39e745d96"
            ],
            "registrant": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "xxx@xxx.net",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "registrarCreatedAt": "1996-05-22T04:00:00+00:00",
            "registrarEmail": "domainabuse@cscglobal.com",
            "registrarExpiresAt": "2021-05-23T04:00:00+00:00",
            "registrarIanaID": 299,
            "registrarName": "CSC Corporate Domains, Inc.",
            "registrarParseCode": 3579,
            "registrarPhone": "+1.8887802723",
            "registrarUpdatedAt": "2020-04-08T07:06:06+00:00",
            "registryParseCode": 251,
            "resource": [
                "http://abc.com"
            ],
            "scan_date": [
                "2020-06-22 07:24:16"
            ],
            "status": "ACTIVE",
            "task_id": "61bbc65f5c034930b8a659c39e745d96",
            "technical": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "xxx@xxx.net",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "tld": "com",
            "updatedAt": "2020-04-09T07:17:45+00:00",
            "whoisID": 6653913764397840000,
            "whoisServer": "whois.corporatedomains.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|admin|auditCreatedAt|auditUpdatedAt|compositeParseCode|contactCountries|contactEmails|contactNames|contactOrganizations|contacts|createdAt|domain|domainAvailable|domainMd5|domainStatus|domainUnicode|expired|id|message|nameservers|noRecord|permalink|registrant|registrarCreatedAt|registrarEmail|registrarExpiresAt|registrarIanaID|registrarName|registrarParseCode|registrarPhone|registrarUpdatedAt|registryParseCode|resource|scan_date|status|task_id|technical|tld|updatedAt|whoisID|whoisServer|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 2020-04-09T07:17:45+00:00 | 2020-04-09T07:17:45+00:00 | 3579 | US | corp.dns.domains@disney.com | ABC, Inc.; Domain Administrator | ABC, Inc. | {'whoisContactID': 0, 'email': 'xxx@xxx.net', 'name': 'ABC, Inc.; Domain Administrator', 'organization': 'ABC, Inc.', 'city': 'New York', 'state': 'NY', 'zip': '10023-6298', 'country': 'US', 'phone': '18182384694', 'fax': '18182384694', 'address': 'New York\n10023-6298\nNY\nUS\n', 'id': 0} | 2020-04-09T07:17:45+00:00 | abc.com | false | 929ba26f492f86d4a9d66a080849865a | clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited | abc.com | false | 6653913764397840884 | search success | ns-1368.awsdns-43.org,<br/>ns-1869.awsdns-41.co.uk,<br/>ns-318.awsdns-39.com,<br/>ns-736.awsdns-28.net | false | ["https://cybertotal.cycraft.com/app/intelligence/61bbc65f5c034930b8a659c39e745d96"] | whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 1996-05-22T04:00:00+00:00 | domainabuse@cscglobal.com | 2021-05-23T04:00:00+00:00 | 299 | CSC Corporate Domains, Inc. | 3579 | +1.8887802723 | 2020-04-08T07:06:06+00:00 | 251 | ["http://abc.com"] | ["2020-06-22 07:24:16"] | ACTIVE | 61bbc65f5c034930b8a659c39e745d96 | whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | com | 2020-04-09T07:17:45+00:00 | 6653913764397840884 | whois.corporatedomains.com |


### cybertotal-domain-whois
***
Return domain whois information


#### Base Command

`cybertotal-domain-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domain(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.WHOIS-Domain.scan_date | date | Scan date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-Domain.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-Domain.message | string | Message about this search. | 
| CyberTotal.WHOIS-Domain.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-Domain.createdAt | date | Create date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.updatedAt | date | Update date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.status | string | Status of this Domain | 
| CyberTotal.WHOIS-Domain.domain | string | Top level Domain of this domain | 
| CyberTotal.WHOIS-Domain.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-Domain.domain | 
| CyberTotal.WHOIS-Domain.domainUnicode | string | Encode CyberTotal.WHOIS\-Domain.domain by using unicode | 
| CyberTotal.WHOIS-Domain.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-Domain.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-Domain.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-Domain.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-Domain.registrarCreatedAt | date | Registrar create date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.registrarUpdatedAt | date | Registrar update date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.registrarExpiresAt | date | Registrar expire date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.auditCreatedAt | date | Registrar update date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.auditUpdatedAt | date | Registrar expire date format: ISO 8601 | 
| CyberTotal.WHOIS-Domain.registrant.name | string | The name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.organization | string | The organization name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.street | string | The street name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.city | string | The location city of registrant | 
| CyberTotal.WHOIS-Domain.registrant.state | string | The location state name of registrant | 
| CyberTotal.WHOIS-Domain.registrant.zip | string | The post zip code of registrant | 
| CyberTotal.WHOIS-Domain.registrant.country | string | The country of registrant | 
| CyberTotal.WHOIS-Domain.registrant.address | string | The address of registrant | 
| CyberTotal.WHOIS-Domain.admin.name | string | The name of admin | 
| CyberTotal.WHOIS-Domain.admin.organization | string | The organization name of admin | 
| CyberTotal.WHOIS-Domain.admin.street | string | The street name of admin | 
| CyberTotal.WHOIS-Domain.admin.city | string | The location city of admin | 
| CyberTotal.WHOIS-Domain.admin.state | string | The location state name of admin | 
| CyberTotal.WHOIS-Domain.admin.zip | string | The post zip code of admin | 
| CyberTotal.WHOIS-Domain.admin.country | string | The country of admin | 
| CyberTotal.WHOIS-Domain.admin.address | string | The address of admin | 
| CyberTotal.WHOIS-Domain.technical.name | string | The name of technical | 
| CyberTotal.WHOIS-Domain.technical.organization | string | The organization name of technical | 
| CyberTotal.WHOIS-Domain.technical.street | string | The street name of technical | 
| CyberTotal.WHOIS-Domain.technical.city | string | The location city of technical | 
| CyberTotal.WHOIS-Domain.technical.state | string | The location state name of technical | 
| CyberTotal.WHOIS-Domain.technical.zip | string | The post zip code of technical | 
| CyberTotal.WHOIS-Domain.technical.country | string | The country of technical | 
| CyberTotal.WHOIS-Domain.technical.address | string | The address of technical | 
| CyberTotal.WHOIS-Domain.contactEmails | string | An array of all contact email address | 
| CyberTotal.WHOIS-Domain.contacts | string | An array of all contact details | 
| CyberTotal.WHOIS-Domain.contactNames | string | An array of all contact names | 
| CyberTotal.WHOIS-Domain.contactCountries | string | An array of all contact countries | 
| CyberTotal.WHOIS-Domain.domainAvailable | boolean | If this domain is available | 
| CyberTotal.WHOIS-Domain.expired | boolean | If this domain is expired | 


#### Command Example
```!cybertotal-domain-whois domain=abc.com```

#### Context Example
```
{
    "CyberTotal": {
        "WHOIS-Domain": {
            "admin": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "xxx@xxx.net",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "auditCreatedAt": "2020-04-09T07:17:45+00:00",
            "auditUpdatedAt": "2020-04-09T07:17:45+00:00",
            "compositeParseCode": 3579,
            "contactCountries": [
                "US"
            ],
            "contactEmails": [
                "corp.dns.domains@disney.com"
            ],
            "contactNames": [
                "ABC, Inc.; Domain Administrator"
            ],
            "contactOrganizations": [
                "ABC, Inc."
            ],
            "contacts": [
                {
                    "address": "New York\n10023-6298\nNY\nUS\n",
                    "city": "New York",
                    "country": "US",
                    "email": "xxx@xxx.net",
                    "fax": "18182384694",
                    "id": 0,
                    "name": "ABC, Inc.; Domain Administrator",
                    "organization": "ABC, Inc.",
                    "phone": "18182384694",
                    "state": "NY",
                    "whoisContactID": 0,
                    "zip": "10023-6298"
                }
            ],
            "createdAt": "2020-04-09T07:17:45+00:00",
            "domain": "abc.com",
            "domainAvailable": false,
            "domainMd5": "929ba26f492f86d4a9d66a080849865a",
            "domainStatus": "clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited",
            "domainUnicode": "abc.com",
            "expired": false,
            "id": 6653913764397840000,
            "message": "search success",
            "nameservers": [
                "ns-1368.awsdns-43.org",
                "ns-1869.awsdns-41.co.uk",
                "ns-318.awsdns-39.com",
                "ns-736.awsdns-28.net"
            ],
            "noRecord": false,
            "permalink": [
                "https://cybertotal.cycraft.com/app/intelligence/79ca1bd740564c36a7a4a78df5dc719d"
            ],
            "registrant": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "xxx@xxx.net",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "registrarCreatedAt": "1996-05-22T04:00:00+00:00",
            "registrarEmail": "domainabuse@cscglobal.com",
            "registrarExpiresAt": "2021-05-23T04:00:00+00:00",
            "registrarIanaID": 299,
            "registrarName": "CSC Corporate Domains, Inc.",
            "registrarParseCode": 3579,
            "registrarPhone": "+1.8887802723",
            "registrarUpdatedAt": "2020-04-08T07:06:06+00:00",
            "registryParseCode": 251,
            "resource": [
                "abc.com"
            ],
            "scan_date": [
                "2020-06-18 03:19:48"
            ],
            "status": "ACTIVE",
            "task_id": "79ca1bd740564c36a7a4a78df5dc719d",
            "technical": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "xxx@xxx.net",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "tld": "com",
            "updatedAt": "2020-04-09T07:17:45+00:00",
            "whoisID": 6653913764397840000,
            "whoisServer": "whois.corporatedomains.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|admin|auditCreatedAt|auditUpdatedAt|compositeParseCode|contactCountries|contactEmails|contactNames|contactOrganizations|contacts|createdAt|domain|domainAvailable|domainMd5|domainStatus|domainUnicode|expired|id|message|nameservers|noRecord|permalink|registrant|registrarCreatedAt|registrarEmail|registrarExpiresAt|registrarIanaID|registrarName|registrarParseCode|registrarPhone|registrarUpdatedAt|registryParseCode|resource|scan_date|status|task_id|technical|tld|updatedAt|whoisID|whoisServer|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 2020-04-09T07:17:45+00:00 | 2020-04-09T07:17:45+00:00 | 3579 | US | corp.dns.domains@disney.com | ABC, Inc.; Domain Administrator | ABC, Inc. | {'whoisContactID': 0, 'email': 'xxx@xxx.net', 'name': 'ABC, Inc.; Domain Administrator', 'organization': 'ABC, Inc.', 'city': 'New York', 'state': 'NY', 'zip': '10023-6298', 'country': 'US', 'phone': '18182384694', 'fax': '18182384694', 'address': 'New York\n10023-6298\nNY\nUS\n', 'id': 0} | 2020-04-09T07:17:45+00:00 | abc.com | false | 929ba26f492f86d4a9d66a080849865a | clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited | abc.com | false | 6653913764397840884 | search success | ns-1368.awsdns-43.org,<br/>ns-1869.awsdns-41.co.uk,<br/>ns-318.awsdns-39.com,<br/>ns-736.awsdns-28.net | false | ["https://cybertotal.cycraft.com/app/intelligence/79ca1bd740564c36a7a4a78df5dc719d"] | whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 1996-05-22T04:00:00+00:00 | domainabuse@cscglobal.com | 2021-05-23T04:00:00+00:00 | 299 | CSC Corporate Domains, Inc. | 3579 | +1.8887802723 | 2020-04-08T07:06:06+00:00 | 251 | ["abc.com"] | ["2020-06-18 03:19:48"] | ACTIVE | 79ca1bd740564c36a7a4a78df5dc719d | whoisContactID: 0<br/>email: xxx@xxx.net<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | com | 2020-04-09T07:17:45+00:00 | 6653913764397840884 | whois.corporatedomains.com |
