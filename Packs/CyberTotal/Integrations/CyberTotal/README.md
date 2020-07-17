CyberTotal is a cloud-based threat intelligence service developed by CyCraft.
This integration was integrated and tested with version xx of CyberTotal
## Configure CyberTotal on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberTotal.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
| CyberTotal.IP.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
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
            "detection_engines": 85,
            "detection_ratio": "4/85",
            "message": "search success",
            "permalink": "https://cybertotal.cycraft.com/app/intelligence/2e11509eb3034aabaf3c006425050247",
            "positive_detections": 4,
            "resource": "1.1.1.1",
            "scan_date": "2020-07-08 14:11:17",
            "severity": 9,
            "task_id": "2e11509eb3034aabaf3c006425050247",
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
        "DetectionEngines": 85,
        "PositiveDetections": 4
    }
}
```

#### Human Readable Output

>### IP List
>|confidence|detection_engines|detection_ratio|message|permalink|positive_detections|resource|scan_date|severity|task_id|threat|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 3 | 85 | 4/85 | search success | https://cybertotal.cycraft.com/app/intelligence/2e11509eb3034aabaf3c006425050247 | 4 | 1.1.1.1 | 2020-07-08 14:11:17 | 9 | 2e11509eb3034aabaf3c006425050247 | High |


### file
***
Return file's information and reputation


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | list of hash(s). | Required | 
| threshold | If the HASH has reputation above the threshold then the HASH defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberTotal.File.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS | 
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
```!file hash=b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e```

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
            "scan_date": "2020-07-09 15:11:56",
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
        "Score": 2,
        "Type": "file",
        "Vendor": "CyberTotal"
    },
    "File": {
        "Extension": "exe",
        "MD5": "19063b2a1b1a7930aef31678903b7088",
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
>| 10 | 70 | 58/70 | exe | 19063b2a1b1a7930aef31678903b7088 | search success | 19063b2a1b1a7930aef31678903b7088.virus | https://cybertotal.cycraft.com/app/intelligence/7a37a8d7a32847c9b3eee5a4431c9ab5 | 58 | b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e | 2020-07-09 15:11:56 | 10 | c771b33f4f3867f95721d0eceed5c4040c78d3ee | b5e8793b216cf2e63c47af4ac424ac9a77601405c131c32a2eaa22812306123e | 28672 | 7a37a8d7a32847c9b3eee5a4431c9ab5 | High |


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
| CyberTotal.Domain.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
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
            "scan_date": "2020-06-18 03:19:48",
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
>| 7 | 79 | 0/79 | search success | https://cybertotal.cycraft.com/app/intelligence/79ca1bd740564c36a7a4a78df5dc719d | 0 | abc.com | 2020-06-18 03:19:48 | 6 | 79ca1bd740564c36a7a4a78df5dc719d | Medium |


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
| CyberTotal.URL.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
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
            "scan_date": "2020-06-22 07:24:16",
            "severity": 5,
            "task_id": "61bbc65f5c034930b8a659c39e745d96",
            "threat": "Medium"
        }
    },
    "DBotScore": {
        "Indicator": "http://abc.com",
        "Score": 1,
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
>| 1 | 79 | 0/79 | search success | https://cybertotal.cycraft.com/app/intelligence/61bbc65f5c034930b8a659c39e745d96 | 0 | http://abc.com | 2020-06-22 07:24:16 | 5 | 61bbc65f5c034930b8a659c39e745d96 | Medium |


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
| CyberTotal.WHOIS-IP.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-IP.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-IP.message | string | Message about this search. | 
| CyberTotal.WHOIS-IP.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-IP.createdAt | date | Create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.updatedAt | date | Update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.status | string | Status of this IP | 
| CyberTotal.WHOIS-IP.domain | string | Domain of this IP | 
| CyberTotal.WHOIS-IP.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-IP.domain | 
| CyberTotal.WHOIS-IP.domainUnicode | string | Encode CyberTotal.WHOIS\-IP.domain by using unicode | 
| CyberTotal.WHOIS-IP.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-IP.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-IP.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-IP.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-IP.registrarCreatedAt | date | Registrar create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.registrarUpdatedAt | date | Registrar update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-IP.registrarExpiresAt | date | Registrar expire date format: YYYY\-MM\-DD HH:mm:SS  | 
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
                "email": "abuse@apnic.net",
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
            "auditCreatedAt": 1589320232,
            "auditUpdatedAt": 1589320232,
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
            "createdAt": 1589320232,
            "domain": "1.1.1.0",
            "domainAvailable": false,
            "domainMd5": "ede514d996ecdf82a0abf5356ff6a13c",
            "domainUnicode": "1.1.1.0",
            "expired": false,
            "id": 6666092209009726000,
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
                "https://cybertotal.cycraft.com/app/intelligence/2e11509eb3034aabaf3c006425050247"
            ],
            "registrarName": "APNIC",
            "registrarParseCode": 10528,
            "registrarUpdatedAt": 1522374688,
            "resource": [
                "1.1.1.1"
            ],
            "scan_date": [
                "2020-07-08 14:11:17"
            ],
            "status": "ACTIVE",
            "task_id": "2e11509eb3034aabaf3c006425050247",
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
            "updatedAt": 1589320232,
            "whoisID": 6666092209009726000,
            "whoisServer": "rdap.apnic.net"
        }
    }
}
```

#### Human Readable Output

>### Results
>|abuse|admin|auditCreatedAt|auditUpdatedAt|compositeParseCode|contactCountries|contactEmails|contactNames|contactOrganizations|contacts|createdAt|domain|domainAvailable|domainMd5|domainUnicode|expired|id|message|nameservers|netRange|noRecord|permalink|registrarName|registrarParseCode|registrarUpdatedAt|resource|scan_date|status|task_id|technical|tld|updatedAt|whoisID|whoisServer|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| whoisContactID: 0<br/>email: abuse@apnic.net<br/>name: IRT-APNICRANDNET-AU<br/>street: po box 3646<br/>state: qld<br/>zip: 4101<br/>country: australia<br/>address: po box 3646<br/>4101<br/>qld<br/>australia<br/><br/>id: 0 | whoisContactID: 0<br/>email: research@apnic.net<br/>name: APNIC RESEARCH<br/>street: po box 3646<br/>state: qld<br/>zip: 4101<br/>country: australia<br/>phone: +61-7-3858-3188<br/>fax: +61-7-3858-3199<br/>address: po box 3646<br/>4101<br/>qld<br/>australia<br/><br/>id: 0 | 1589320232 | 1589320232 | 10528 | australia | research@apnic.net | APNIC RESEARCH |  | {'whoisContactID': 0, 'email': 'research@apnic.net', 'name': 'APNIC RESEARCH', 'street': 'po box 3646', 'state': 'qld', 'zip': '4101', 'country': 'australia', 'phone': '+61-7-3858-3188', 'fax': '+61-7-3858-3199', 'address': 'po box 3646\n4101\nqld\naustralia\n', 'id': 0} | 1589320232 | 1.1.1.0 | false | ede514d996ecdf82a0abf5356ff6a13c | 1.1.1.0 | false | 6666092209009726294 | search success |  | status: INACTIVE<br/>whoisNetRangeID: 0<br/>netRange: 1.1.1.0 - 1.1.1.255<br/>netName: APNIC-LABS<br/>ipStart: 1.1.1.0<br/>ipEnd: 1.1.1.255<br/>numericEnd: 16843263<br/>numericStart: 16843008 | false | ["https://cybertotal.cycraft.com/app/intelligence/2e11509eb3034aabaf3c006425050247"] | APNIC | 10528 | 1522374688 | ["1.1.1.1"] | ["2020-07-08 14:11:17"] | ACTIVE | 2e11509eb3034aabaf3c006425050247 | whoisContactID: 0<br/>email: research@apnic.net<br/>name: APNIC RESEARCH<br/>street: po box 3646<br/>state: qld<br/>zip: 4101<br/>country: australia<br/>phone: +61-7-3858-3188<br/>fax: +61-7-3858-3199<br/>address: po box 3646<br/>4101<br/>qld<br/>australia<br/><br/>id: 0 | ipv4 | 1589320232 | 6666092209009726294 | rdap.apnic.net |


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
| CyberTotal.WHOIS-URL.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-URL.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-URL.message | string | Message about this search. | 
| CyberTotal.WHOIS-URL.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-URL.createdAt | date | Create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.updatedAt | date | Update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.status | string | Status of this IP | 
| CyberTotal.WHOIS-URL.domain | string | Domain of this IP | 
| CyberTotal.WHOIS-URL.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-URL.domain | 
| CyberTotal.WHOIS-URL.domainUnicode | string | Encode CyberTotal.WHOIS\-URL.domain by using unicode | 
| CyberTotal.WHOIS-URL.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-URL.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-URL.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-URL.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-URL.registrarCreatedAt | date | Registrar create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.registrarUpdatedAt | date | Registrar update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-URL.registrarExpiresAt | date | Registrar expire date format: YYYY\-MM\-DD HH:mm:SS  | 
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
                "email": "Corp.DNS.Domains@disney.com",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "auditCreatedAt": 1586416665,
            "auditUpdatedAt": 1586416665,
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
                    "email": "Corp.DNS.Domains@disney.com",
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
            "createdAt": 1586416665,
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
            "rawResponse": {
                "domain": "abc.com",
                "raw": "Domain Name: ABC.COM\n   Registry Domain ID: 893646_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.corporatedomains.com\n   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html\n   Updated Date: 2020-04-08T07:06:06Z\n   Creation Date: 1996-05-22T04:00:00Z\n   Registry Expiry Date: 2021-05-23T04:00:00Z\n   Registrar: CSC Corporate Domains, Inc.\n   Registrar IANA ID: 299\n   Registrar Abuse Contact Email: domainabuse@cscglobal.com\n   Registrar Abuse Contact Phone: 8887802723\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS-1368.AWSDNS-43.ORG\n   Name Server: NS-1869.AWSDNS-41.CO.UK\n   Name Server: NS-318.AWSDNS-39.COM\n   Name Server: NS-736.AWSDNS-28.NET\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2020-04-09T07:17:38Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n\nDomain Name: abc.com\nRegistry Domain ID: 893646_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: www.cscprotectsbrands.com\nUpdated Date: 2020-04-08T03:06:06Z\nCreation Date: 1996-05-22T00:00:00Z\nRegistrar Registration Expiration Date: 2021-05-23T04:00:00Z\nRegistrar: CSC CORPORATE DOMAINS, INC.\nSponsoring Registrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: +1.8887802723\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nRegistry Registrant ID: \nRegistrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant Street: \nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Phone Ext: \nRegistrant Fax: +1.8182384694\nRegistrant Fax Ext: \nRegistrant Email: Corp.DNS.Domains@disney.com\nRegistry Admin ID: \nAdmin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin Street: \nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Phone Ext: \nAdmin Fax: +1.8182384694\nAdmin Fax Ext: \nAdmin Email: Corp.DNS.Domains@disney.com\nRegistry Tech ID: \nTech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech Street: \nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Phone Ext: \nTech Fax: +1.8182384694\nTech Fax Ext: \nTech Email: Corp.DNS.Domains@disney.com\nName Server: ns-1869.awsdns-41.co.uk\nName Server: ns-1368.awsdns-43.org\nName Server: ns-736.awsdns-28.net\nName Server: ns-318.awsdns-39.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2020-04-08T03:06:06Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nCorporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.\n\nContact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.\n\nNOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.\n\nRegister your domain name at http://www.cscglobal.com",
                "source": "WHOIS_XML_API",
                "unparsed": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<WhoisRecord>\n  <createdDate>1996-05-22T00:00:00Z</createdDate>\n  <updatedDate>2020-04-08T03:06:06Z</updatedDate>\n  <expiresDate>2021-05-23T04:00:00Z</expiresDate>\n  <registrant>\n    <name>ABC, Inc.; Domain Administrator</name>\n    <organization>ABC, Inc.</organization>\n    <city>New York</city>\n    <state>NY</state>\n    <postalCode>10023-6298</postalCode>\n    <country>US</country>\n    <email>Corp.DNS.Domains@disney.com</email>\n    <telephone>18182384694</telephone>\n    <fax>18182384694</fax>\n    <rawText>Registrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Fax: +1.8182384694\nRegistrant Email: Corp.DNS.Domains@disney.com</rawText>\n  </registrant>\n  <administrativeContact>\n    <name>ABC, Inc.; Domain Administrator</name>\n    <organization>ABC, Inc.</organization>\n    <city>New York</city>\n    <state>NY</state>\n    <postalCode>10023-6298</postalCode>\n    <country>US</country>\n    <email>Corp.DNS.Domains@disney.com</email>\n    <telephone>18182384694</telephone>\n    <fax>18182384694</fax>\n    <rawText>Admin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Fax: +1.8182384694\nAdmin Email: Corp.DNS.Domains@disney.com</rawText>\n  </administrativeContact>\n  <technicalContact>\n    <name>ABC, Inc.; Domain Administrator</name>\n    <organization>ABC, Inc.</organization>\n    <city>New York</city>\n    <state>NY</state>\n    <postalCode>10023-6298</postalCode>\n    <country>US</country>\n    <email>Corp.DNS.Domains@disney.com</email>\n    <telephone>18182384694</telephone>\n    <fax>18182384694</fax>\n    <rawText>Tech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Fax: +1.8182384694\nTech Email: Corp.DNS.Domains@disney.com</rawText>\n  </technicalContact>\n  <domainName>abc.com</domainName>\n  <nameServers>\n    <rawText>ns-1869.awsdns-41.co.uk\nns-1368.awsdns-43.org\nns-736.awsdns-28.net\nns-318.awsdns-39.com\n</rawText>\n    <hostNames>\n      <Address>ns-1869.awsdns-41.co.uk</Address>\n      <Address>ns-1368.awsdns-43.org</Address>\n      <Address>ns-736.awsdns-28.net</Address>\n      <Address>ns-318.awsdns-39.com</Address>\n    </hostNames>\n    <ips/>\n  </nameServers>\n  <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status>\n  <rawText>Domain Name: abc.com\nRegistry Domain ID: 893646_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: www.cscprotectsbrands.com\nUpdated Date: 2020-04-08T03:06:06Z\nCreation Date: 1996-05-22T00:00:00Z\nRegistrar Registration Expiration Date: 2021-05-23T04:00:00Z\nRegistrar: CSC CORPORATE DOMAINS, INC.\nSponsoring Registrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: +1.8887802723\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nRegistry Registrant ID: \nRegistrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant Street: \nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Phone Ext: \nRegistrant Fax: +1.8182384694\nRegistrant Fax Ext: \nRegistrant Email: Corp.DNS.Domains@disney.com\nRegistry Admin ID: \nAdmin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin Street: \nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Phone Ext: \nAdmin Fax: +1.8182384694\nAdmin Fax Ext: \nAdmin Email: Corp.DNS.Domains@disney.com\nRegistry Tech ID: \nTech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech Street: \nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Phone Ext: \nTech Fax: +1.8182384694\nTech Fax Ext: \nTech Email: Corp.DNS.Domains@disney.com\nName Server: ns-1869.awsdns-41.co.uk\nName Server: ns-1368.awsdns-43.org\nName Server: ns-736.awsdns-28.net\nName Server: ns-318.awsdns-39.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n&gt;&gt;&gt; Last update of WHOIS database: 2020-04-08T03:06:06Z &lt;&lt;&lt;\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nCorporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.\n\nContact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.\n\nNOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.\n\nRegister your domain name at http://www.cscglobal.com</rawText>\n  <parseCode>3579</parseCode>\n  <header/>\n  <strippedText>Domain Name: abc.com\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: www.cscprotectsbrands.com\nUpdated Date: 2020-04-08T03:06:06Z\nCreation Date: 1996-05-22T00:00:00Z\nRegistrar Registration Expiration Date: 2021-05-23T04:00:00Z\nRegistrar: CSC CORPORATE DOMAINS, INC.\nSponsoring Registrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: +1.8887802723\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nRegistrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Fax: +1.8182384694\nRegistrant Email: Corp.DNS.Domains@disney.com\nAdmin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Fax: +1.8182384694\nAdmin Email: Corp.DNS.Domains@disney.com\nTech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Fax: +1.8182384694\nTech Email: Corp.DNS.Domains@disney.com\nName Server: ns-1869.awsdns-41.co.uk\nName Server: ns-1368.awsdns-43.org\nName Server: ns-736.awsdns-28.net\nName Server: ns-318.awsdns-39.com\n</strippedText>\n  <footer/>\n  <audit>\n    <createdDate>2020-04-09 07:17:45.138 UTC</createdDate>\n    <updatedDate>2020-04-09 07:17:45.138 UTC</updatedDate>\n  </audit>\n  <customField1Name>RegistrarContactEmail</customField1Name>\n  <customField1Value>domainabuse@cscglobal.com</customField1Value>\n  <registrarName>CSC CORPORATE DOMAINS, INC.</registrarName>\n  <registrarIANAID>299</registrarIANAID>\n  <whoisServer>whois.corporatedomains.com</whoisServer>\n  <customField2Name>RegistrarContactPhone</customField2Name>\n  <customField3Name>RegistrarURL</customField3Name>\n  <customField2Value>+1.8887802723</customField2Value>\n  <customField3Value>www.cscprotectsbrands.com</customField3Value>\n  <registryData>\n    <createdDate>1996-05-22T04:00:00Z</createdDate>\n    <updatedDate>2020-04-08T07:06:06Z</updatedDate>\n    <expiresDate>2021-05-23T04:00:00Z</expiresDate>\n    <domainName>abc.com</domainName>\n    <nameServers>\n      <rawText>NS-1368.AWSDNS-43.ORG\nNS-1869.AWSDNS-41.CO.UK\nNS-318.AWSDNS-39.COM\nNS-736.AWSDNS-28.NET\n</rawText>\n      <hostNames>\n        <Address>NS-1368.AWSDNS-43.ORG</Address>\n        <Address>NS-1869.AWSDNS-41.CO.UK</Address>\n        <Address>NS-318.AWSDNS-39.COM</Address>\n        <Address>NS-736.AWSDNS-28.NET</Address>\n      </hostNames>\n      <ips/>\n    </nameServers>\n    <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status>\n    <rawText>Domain Name: ABC.COM\n   Registry Domain ID: 893646_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.corporatedomains.com\n   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html\n   Updated Date: 2020-04-08T07:06:06Z\n   Creation Date: 1996-05-22T04:00:00Z\n   Registry Expiry Date: 2021-05-23T04:00:00Z\n   Registrar: CSC Corporate Domains, Inc.\n   Registrar IANA ID: 299\n   Registrar Abuse Contact Email: domainabuse@cscglobal.com\n   Registrar Abuse Contact Phone: 8887802723\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS-1368.AWSDNS-43.ORG\n   Name Server: NS-1869.AWSDNS-41.CO.UK\n   Name Server: NS-318.AWSDNS-39.COM\n   Name Server: NS-736.AWSDNS-28.NET\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.</rawText>\n    <parseCode>251</parseCode>\n    <header/>\n    <strippedText>Domain Name: ABC.COM\nRegistry Domain ID: 893646_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html\nUpdated Date: 2020-04-08T07:06:06Z\nCreation Date: 1996-05-22T04:00:00Z\nRegistry Expiry Date: 2021-05-23T04:00:00Z\nRegistrar: CSC Corporate Domains, Inc.\nRegistrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: 8887802723\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS-1368.AWSDNS-43.ORG\nName Server: NS-1869.AWSDNS-41.CO.UK\nName Server: NS-318.AWSDNS-39.COM\nName Server: NS-736.AWSDNS-28.NET\nDNSSEC: unsigned\nURL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;\nFor more information on Whois status codes, please visit https://icann.org/epp\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n</strippedText>\n    <footer/>\n    <audit>\n      <createdDate>2020-04-09 07:17:44.973 UTC</createdDate>\n      <updatedDate>2020-04-09 07:17:44.973 UTC</updatedDate>\n    </audit>\n    <customField1Name>RegistrarContactEmail</customField1Name>\n    <customField1Value>domainabuse@cscglobal.com</customField1Value>\n    <registrarName>CSC Corporate Domains, Inc.</registrarName>\n    <registrarIANAID>299</registrarIANAID>\n    <createdDateNormalized>1996-05-22 04:00:00 UTC</createdDateNormalized>\n    <updatedDateNormalized>2020-04-08 07:06:06 UTC</updatedDateNormalized>\n    <expiresDateNormalized>2021-05-23 04:00:00 UTC</expiresDateNormalized>\n    <customField2Name>RegistrarContactPhone</customField2Name>\n    <customField3Name>RegistrarURL</customField3Name>\n    <customField2Value>8887802723</customField2Value>\n    <customField3Value>http://www.cscglobal.com/global/web/csc/digital-brand-services.html</customField3Value>\n    <whoisServer>whois.corporatedomains.com</whoisServer>\n  </registryData>\n  <contactEmail>Corp.DNS.Domains@disney.com</contactEmail>\n  <domainNameExt>.com</domainNameExt>\n  <estimatedDomainAge>8723</estimatedDomainAge>\n</WhoisRecord>",
                "whoisID": 6653913764397840000,
                "whoisRawID": 0
            },
            "registrant": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "Corp.DNS.Domains@disney.com",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "registrarCreatedAt": 832737600,
            "registrarEmail": "domainabuse@cscglobal.com",
            "registrarExpiresAt": 1621742400,
            "registrarIanaID": 299,
            "registrarName": "CSC Corporate Domains, Inc.",
            "registrarParseCode": 3579,
            "registrarPhone": "+1.8887802723",
            "registrarUpdatedAt": 1586329566,
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
                "email": "Corp.DNS.Domains@disney.com",
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
            "updatedAt": 1586416665,
            "whoisID": 6653913764397840000,
            "whoisServer": "whois.corporatedomains.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|admin|auditCreatedAt|auditUpdatedAt|compositeParseCode|contactCountries|contactEmails|contactNames|contactOrganizations|contacts|createdAt|domain|domainAvailable|domainMd5|domainStatus|domainUnicode|expired|id|message|nameservers|noRecord|permalink|rawResponse|registrant|registrarCreatedAt|registrarEmail|registrarExpiresAt|registrarIanaID|registrarName|registrarParseCode|registrarPhone|registrarUpdatedAt|registryParseCode|resource|scan_date|status|task_id|technical|tld|updatedAt|whoisID|whoisServer|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| whoisContactID: 0<br/>email: Corp.DNS.Domains@disney.com<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 1586416665 | 1586416665 | 3579 | US | corp.dns.domains@disney.com | ABC, Inc.; Domain Administrator | ABC, Inc. | {'whoisContactID': 0, 'email': 'Corp.DNS.Domains@disney.com', 'name': 'ABC, Inc.; Domain Administrator', 'organization': 'ABC, Inc.', 'city': 'New York', 'state': 'NY', 'zip': '10023-6298', 'country': 'US', 'phone': '18182384694', 'fax': '18182384694', 'address': 'New York\n10023-6298\nNY\nUS\n', 'id': 0} | 1586416665 | abc.com | false | 929ba26f492f86d4a9d66a080849865a | clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited | abc.com | false | 6653913764397840884 | search success | ns-1368.awsdns-43.org,<br/>ns-1869.awsdns-41.co.uk,<br/>ns-318.awsdns-39.com,<br/>ns-736.awsdns-28.net | false | ["https://cybertotal.cycraft.com/app/intelligence/61bbc65f5c034930b8a659c39e745d96"] | whoisRawID: 0<br/>whoisID: 6653913764397840884<br/>domain: abc.com<br/>raw: Domain Name: ABC.COM<br/>   Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>   Registrar WHOIS Server: whois.corporatedomains.com<br/>   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html<br/>   Updated Date: 2020-04-08T07:06:06Z<br/>   Creation Date: 1996-05-22T04:00:00Z<br/>   Registry Expiry Date: 2021-05-23T04:00:00Z<br/>   Registrar: CSC Corporate Domains, Inc.<br/>   Registrar IANA ID: 299<br/>   Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>   Registrar Abuse Contact Phone: 8887802723<br/>   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited<br/>   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited<br/>   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited<br/>   Name Server: NS-1368.AWSDNS-43.ORG<br/>   Name Server: NS-1869.AWSDNS-41.CO.UK<br/>   Name Server: NS-318.AWSDNS-39.COM<br/>   Name Server: NS-736.AWSDNS-28.NET<br/>   DNSSEC: unsigned<br/>   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/<br/>>>> Last update of whois database: 2020-04-09T07:17:38Z <<<<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>NOTICE: The expiration date displayed in this record is the date the<br/>registrar's sponsorship of the domain name registration in the registry is<br/>currently set to expire. This date does not necessarily reflect the expiration<br/>date of the domain name registrant's agreement with the sponsoring<br/>registrar.  Users may consult the sponsoring registrar's Whois database to<br/>view the registrar's reported date of expiration for this registration.<br/><br/>TERMS OF USE: You are not authorized to access or query our Whois<br/>database through the use of electronic processes that are high-volume and<br/>automated except as reasonably necessary to register domain names or<br/>modify existing registrations; the Data in VeriSign Global Registry<br/>Services' ("VeriSign") Whois database is provided by VeriSign for<br/>information purposes only, and to assist persons in obtaining information<br/>about or related to a domain name registration record. VeriSign does not<br/>guarantee its accuracy. By submitting a Whois query, you agree to abide<br/>by the following terms of use: You agree that you may use this Data only<br/>for lawful purposes and that under no circumstances will you use this Data<br/>to: (1) allow, enable, or otherwise support the transmission of mass<br/>unsolicited, commercial advertising or solicitations via e-mail, telephone,<br/>or facsimile; or (2) enable high volume, automated, electronic processes<br/>that apply to VeriSign (or its computer systems). The compilation,<br/>repackaging, dissemination or other use of this Data is expressly<br/>prohibited without the prior written consent of VeriSign. You agree not to<br/>use electronic processes that are automated and high-volume to access or<br/>query the Whois database except as reasonably necessary to register<br/>domain names or modify existing registrations. VeriSign reserves the right<br/>to restrict your access to the Whois database in its sole discretion to ensure<br/>operational stability.  VeriSign may restrict or terminate your access to the<br/>Whois database for failure to abide by these terms of use. VeriSign<br/>reserves the right to modify these terms at any time.<br/><br/>The Registry database contains ONLY .COM, .NET, .EDU domains and<br/>Registrars.<br/><br/>Domain Name: abc.com<br/>Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: www.cscprotectsbrands.com<br/>Updated Date: 2020-04-08T03:06:06Z<br/>Creation Date: 1996-05-22T00:00:00Z<br/>Registrar Registration Expiration Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC CORPORATE DOMAINS, INC.<br/>Sponsoring Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: +1.8887802723<br/>Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited<br/>Registry Registrant ID: <br/>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant Street: <br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Phone Ext: <br/>Registrant Fax: +1.8182384694<br/>Registrant Fax Ext: <br/>Registrant Email: Corp.DNS.Domains@disney.com<br/>Registry Admin ID: <br/>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin Street: <br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Phone Ext: <br/>Admin Fax: +1.8182384694<br/>Admin Fax Ext: <br/>Admin Email: Corp.DNS.Domains@disney.com<br/>Registry Tech ID: <br/>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech Street: <br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Phone Ext: <br/>Tech Fax: +1.8182384694<br/>Tech Fax Ext: <br/>Tech Email: Corp.DNS.Domains@disney.com<br/>Name Server: ns-1869.awsdns-41.co.uk<br/>Name Server: ns-1368.awsdns-43.org<br/>Name Server: ns-736.awsdns-28.net<br/>Name Server: ns-318.awsdns-39.com<br/>DNSSEC: unsigned<br/>URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/<br/>>>> Last update of WHOIS database: 2020-04-08T03:06:06Z <<<<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>Corporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.<br/><br/>Contact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.<br/><br/>NOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.<br/><br/>Register your domain name at http://www.cscglobal.com<br/>unparsed: <?xml version="1.0" encoding="utf-8"?><br/><WhoisRecord><br/>  <createdDate>1996-05-22T00:00:00Z</createdDate><br/>  <updatedDate>2020-04-08T03:06:06Z</updatedDate><br/>  <expiresDate>2021-05-23T04:00:00Z</expiresDate><br/>  <registrant><br/>    <name>ABC, Inc.; Domain Administrator</name><br/>    <organization>ABC, Inc.</organization><br/>    <city>New York</city><br/>    <state>NY</state><br/>    <postalCode>10023-6298</postalCode><br/>    <country>US</country><br/>    <email>Corp.DNS.Domains@disney.com</email><br/>    <telephone>18182384694</telephone><br/>    <fax>18182384694</fax><br/>    <rawText>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Fax: +1.8182384694<br/>Registrant Email: Corp.DNS.Domains@disney.com</rawText><br/>  </registrant><br/>  <administrativeContact><br/>    <name>ABC, Inc.; Domain Administrator</name><br/>    <organization>ABC, Inc.</organization><br/>    <city>New York</city><br/>    <state>NY</state><br/>    <postalCode>10023-6298</postalCode><br/>    <country>US</country><br/>    <email>Corp.DNS.Domains@disney.com</email><br/>    <telephone>18182384694</telephone><br/>    <fax>18182384694</fax><br/>    <rawText>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Fax: +1.8182384694<br/>Admin Email: Corp.DNS.Domains@disney.com</rawText><br/>  </administrativeContact><br/>  <technicalContact><br/>    <name>ABC, Inc.; Domain Administrator</name><br/>    <organization>ABC, Inc.</organization><br/>    <city>New York</city><br/>    <state>NY</state><br/>    <postalCode>10023-6298</postalCode><br/>    <country>US</country><br/>    <email>Corp.DNS.Domains@disney.com</email><br/>    <telephone>18182384694</telephone><br/>    <fax>18182384694</fax><br/>    <rawText>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Fax: +1.8182384694<br/>Tech Email: Corp.DNS.Domains@disney.com</rawText><br/>  </technicalContact><br/>  <domainName>abc.com</domainName><br/>  <nameServers><br/>    <rawText>ns-1869.awsdns-41.co.uk<br/>ns-1368.awsdns-43.org<br/>ns-736.awsdns-28.net<br/>ns-318.awsdns-39.com<br/></rawText><br/>    <hostNames><br/>      <Address>ns-1869.awsdns-41.co.uk</Address><br/>      <Address>ns-1368.awsdns-43.org</Address><br/>      <Address>ns-736.awsdns-28.net</Address><br/>      <Address>ns-318.awsdns-39.com</Address><br/>    </hostNames><br/>    <ips/><br/>  </nameServers><br/>  <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status><br/>  <rawText>Domain Name: abc.com<br/>Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: www.cscprotectsbrands.com<br/>Updated Date: 2020-04-08T03:06:06Z<br/>Creation Date: 1996-05-22T00:00:00Z<br/>Registrar Registration Expiration Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC CORPORATE DOMAINS, INC.<br/>Sponsoring Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: +1.8887802723<br/>Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited<br/>Registry Registrant ID: <br/>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant Street: <br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Phone Ext: <br/>Registrant Fax: +1.8182384694<br/>Registrant Fax Ext: <br/>Registrant Email: Corp.DNS.Domains@disney.com<br/>Registry Admin ID: <br/>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin Street: <br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Phone Ext: <br/>Admin Fax: +1.8182384694<br/>Admin Fax Ext: <br/>Admin Email: Corp.DNS.Domains@disney.com<br/>Registry Tech ID: <br/>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech Street: <br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Phone Ext: <br/>Tech Fax: +1.8182384694<br/>Tech Fax Ext: <br/>Tech Email: Corp.DNS.Domains@disney.com<br/>Name Server: ns-1869.awsdns-41.co.uk<br/>Name Server: ns-1368.awsdns-43.org<br/>Name Server: ns-736.awsdns-28.net<br/>Name Server: ns-318.awsdns-39.com<br/>DNSSEC: unsigned<br/>URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/<br/>&gt;&gt;&gt; Last update of WHOIS database: 2020-04-08T03:06:06Z &lt;&lt;&lt;<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>Corporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.<br/><br/>Contact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.<br/><br/>NOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.<br/><br/>Register your domain name at http://www.cscglobal.com</rawText><br/>  <parseCode>3579</parseCode><br/>  <header/><br/>  <strippedText>Domain Name: abc.com<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: www.cscprotectsbrands.com<br/>Updated Date: 2020-04-08T03:06:06Z<br/>Creation Date: 1996-05-22T00:00:00Z<br/>Registrar Registration Expiration Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC CORPORATE DOMAINS, INC.<br/>Sponsoring Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: +1.8887802723<br/>Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited<br/>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Fax: +1.8182384694<br/>Registrant Email: Corp.DNS.Domains@disney.com<br/>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Fax: +1.8182384694<br/>Admin Email: Corp.DNS.Domains@disney.com<br/>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Fax: +1.8182384694<br/>Tech Email: Corp.DNS.Domains@disney.com<br/>Name Server: ns-1869.awsdns-41.co.uk<br/>Name Server: ns-1368.awsdns-43.org<br/>Name Server: ns-736.awsdns-28.net<br/>Name Server: ns-318.awsdns-39.com<br/></strippedText><br/>  <footer/><br/>  <audit><br/>    <createdDate>2020-04-09 07:17:45.138 UTC</createdDate><br/>    <updatedDate>2020-04-09 07:17:45.138 UTC</updatedDate><br/>  </audit><br/>  <customField1Name>RegistrarContactEmail</customField1Name><br/>  <customField1Value>domainabuse@cscglobal.com</customField1Value><br/>  <registrarName>CSC CORPORATE DOMAINS, INC.</registrarName><br/>  <registrarIANAID>299</registrarIANAID><br/>  <whoisServer>whois.corporatedomains.com</whoisServer><br/>  <customField2Name>RegistrarContactPhone</customField2Name><br/>  <customField3Name>RegistrarURL</customField3Name><br/>  <customField2Value>+1.8887802723</customField2Value><br/>  <customField3Value>www.cscprotectsbrands.com</customField3Value><br/>  <registryData><br/>    <createdDate>1996-05-22T04:00:00Z</createdDate><br/>    <updatedDate>2020-04-08T07:06:06Z</updatedDate><br/>    <expiresDate>2021-05-23T04:00:00Z</expiresDate><br/>    <domainName>abc.com</domainName><br/>    <nameServers><br/>      <rawText>NS-1368.AWSDNS-43.ORG<br/>NS-1869.AWSDNS-41.CO.UK<br/>NS-318.AWSDNS-39.COM<br/>NS-736.AWSDNS-28.NET<br/></rawText><br/>      <hostNames><br/>        <Address>NS-1368.AWSDNS-43.ORG</Address><br/>        <Address>NS-1869.AWSDNS-41.CO.UK</Address><br/>        <Address>NS-318.AWSDNS-39.COM</Address><br/>        <Address>NS-736.AWSDNS-28.NET</Address><br/>      </hostNames><br/>      <ips/><br/>    </nameServers><br/>    <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status><br/>    <rawText>Domain Name: ABC.COM<br/>   Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>   Registrar WHOIS Server: whois.corporatedomains.com<br/>   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html<br/>   Updated Date: 2020-04-08T07:06:06Z<br/>   Creation Date: 1996-05-22T04:00:00Z<br/>   Registry Expiry Date: 2021-05-23T04:00:00Z<br/>   Registrar: CSC Corporate Domains, Inc.<br/>   Registrar IANA ID: 299<br/>   Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>   Registrar Abuse Contact Phone: 8887802723<br/>   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited<br/>   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited<br/>   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited<br/>   Name Server: NS-1368.AWSDNS-43.ORG<br/>   Name Server: NS-1869.AWSDNS-41.CO.UK<br/>   Name Server: NS-318.AWSDNS-39.COM<br/>   Name Server: NS-736.AWSDNS-28.NET<br/>   DNSSEC: unsigned<br/>   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/<br/>&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>NOTICE: The expiration date displayed in this record is the date the<br/>registrar's sponsorship of the domain name registration in the registry is<br/>currently set to expire. This date does not necessarily reflect the expiration<br/>date of the domain name registrant's agreement with the sponsoring<br/>registrar.  Users may consult the sponsoring registrar's Whois database to<br/>view the registrar's reported date of expiration for this registration.<br/><br/>TERMS OF USE: You are not authorized to access or query our Whois<br/>database through the use of electronic processes that are high-volume and<br/>automated except as reasonably necessary to register domain names or<br/>modify existing registrations; the Data in VeriSign Global Registry<br/>Services' ("VeriSign") Whois database is provided by VeriSign for<br/>information purposes only, and to assist persons in obtaining information<br/>about or related to a domain name registration record. VeriSign does not<br/>guarantee its accuracy. By submitting a Whois query, you agree to abide<br/>by the following terms of use: You agree that you may use this Data only<br/>for lawful purposes and that under no circumstances will you use this Data<br/>to: (1) allow, enable, or otherwise support the transmission of mass<br/>unsolicited, commercial advertising or solicitations via e-mail, telephone,<br/>or facsimile; or (2) enable high volume, automated, electronic processes<br/>that apply to VeriSign (or its computer systems). The compilation,<br/>repackaging, dissemination or other use of this Data is expressly<br/>prohibited without the prior written consent of VeriSign. You agree not to<br/>use electronic processes that are automated and high-volume to access or<br/>query the Whois database except as reasonably necessary to register<br/>domain names or modify existing registrations. VeriSign reserves the right<br/>to restrict your access to the Whois database in its sole discretion to ensure<br/>operational stability.  VeriSign may restrict or terminate your access to the<br/>Whois database for failure to abide by these terms of use. VeriSign<br/>reserves the right to modify these terms at any time.<br/><br/>The Registry database contains ONLY .COM, .NET, .EDU domains and<br/>Registrars.</rawText><br/>    <parseCode>251</parseCode><br/>    <header/><br/>    <strippedText>Domain Name: ABC.COM<br/>Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html<br/>Updated Date: 2020-04-08T07:06:06Z<br/>Creation Date: 1996-05-22T04:00:00Z<br/>Registry Expiry Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC Corporate Domains, Inc.<br/>Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: 8887802723<br/>Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited<br/>Name Server: NS-1368.AWSDNS-43.ORG<br/>Name Server: NS-1869.AWSDNS-41.CO.UK<br/>Name Server: NS-318.AWSDNS-39.COM<br/>Name Server: NS-736.AWSDNS-28.NET<br/>DNSSEC: unsigned<br/>URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/<br/>&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;<br/>For more information on Whois status codes, please visit https://icann.org/epp<br/>NOTICE: The expiration date displayed in this record is the date the<br/>registrar's sponsorship of the domain name registration in the registry is<br/>currently set to expire. This date does not necessarily reflect the expiration<br/>date of the domain name registrant's agreement with the sponsoring<br/>registrar.  Users may consult the sponsoring registrar's Whois database to<br/>view the registrar's reported date of expiration for this registration.<br/>TERMS OF USE: You are not authorized to access or query our Whois<br/>database through the use of electronic processes that are high-volume and<br/>automated except as reasonably necessary to register domain names or<br/>modify existing registrations; the Data in VeriSign Global Registry<br/>Services' ("VeriSign") Whois database is provided by VeriSign for<br/>information purposes only, and to assist persons in obtaining information<br/>about or related to a domain name registration record. VeriSign does not<br/>guarantee its accuracy. By submitting a Whois query, you agree to abide<br/>by the following terms of use: You agree that you may use this Data only<br/>for lawful purposes and that under no circumstances will you use this Data<br/>to: (1) allow, enable, or otherwise support the transmission of mass<br/>unsolicited, commercial advertising or solicitations via e-mail, telephone,<br/>or facsimile; or (2) enable high volume, automated, electronic processes<br/>that apply to VeriSign (or its computer systems). The compilation,<br/>repackaging, dissemination or other use of this Data is expressly<br/>prohibited without the prior written consent of VeriSign. You agree not to<br/>use electronic processes that are automated and high-volume to access or<br/>query the Whois database except as reasonably necessary to register<br/>domain names or modify existing registrations. VeriSign reserves the right<br/>to restrict your access to the Whois database in its sole discretion to ensure<br/>operational stability.  VeriSign may restrict or terminate your access to the<br/>Whois database for failure to abide by these terms of use. VeriSign<br/>reserves the right to modify these terms at any time.<br/>The Registry database contains ONLY .COM, .NET, .EDU domains and<br/>Registrars.<br/></strippedText><br/>    <footer/><br/>    <audit><br/>      <createdDate>2020-04-09 07:17:44.973 UTC</createdDate><br/>      <updatedDate>2020-04-09 07:17:44.973 UTC</updatedDate><br/>    </audit><br/>    <customField1Name>RegistrarContactEmail</customField1Name><br/>    <customField1Value>domainabuse@cscglobal.com</customField1Value><br/>    <registrarName>CSC Corporate Domains, Inc.</registrarName><br/>    <registrarIANAID>299</registrarIANAID><br/>    <createdDateNormalized>1996-05-22 04:00:00 UTC</createdDateNormalized><br/>    <updatedDateNormalized>2020-04-08 07:06:06 UTC</updatedDateNormalized><br/>    <expiresDateNormalized>2021-05-23 04:00:00 UTC</expiresDateNormalized><br/>    <customField2Name>RegistrarContactPhone</customField2Name><br/>    <customField3Name>RegistrarURL</customField3Name><br/>    <customField2Value>8887802723</customField2Value><br/>    <customField3Value>http://www.cscglobal.com/global/web/csc/digital-brand-services.html</customField3Value><br/>    <whoisServer>whois.corporatedomains.com</whoisServer><br/>  </registryData><br/>  <contactEmail>Corp.DNS.Domains@disney.com</contactEmail><br/>  <domainNameExt>.com</domainNameExt><br/>  <estimatedDomainAge>8723</estimatedDomainAge><br/></WhoisRecord><br/>source: WHOIS_XML_API | whoisContactID: 0<br/>email: Corp.DNS.Domains@disney.com<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 832737600 | domainabuse@cscglobal.com | 1621742400 | 299 | CSC Corporate Domains, Inc. | 3579 | +1.8887802723 | 1586329566 | 251 | ["http://abc.com"] | ["2020-06-22 07:24:16"] | ACTIVE | 61bbc65f5c034930b8a659c39e745d96 | whoisContactID: 0<br/>email: Corp.DNS.Domains@disney.com<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | com | 1586416665 | 6653913764397840884 | whois.corporatedomains.com |


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
| CyberTotal.WHOIS-Domain.scan_date | date | Scan date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.task_id | string | The unique id of each scan in CyberTotal. | 
| CyberTotal.WHOIS-Domain.resource | string | The scan target sent to CyberTotal. | 
| CyberTotal.WHOIS-Domain.message | string | Message about this search. | 
| CyberTotal.WHOIS-Domain.permalink | string | The link of this whois report in CyberTotal. | 
| CyberTotal.WHOIS-Domain.createdAt | date | Create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.updatedAt | date | Update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.status | string | Status of this Domain | 
| CyberTotal.WHOIS-Domain.domain | string | Top level Domain of this domain | 
| CyberTotal.WHOIS-Domain.domainMd5 | string | MD5 translation of CyberTotal.WHOIS\-Domain.domain | 
| CyberTotal.WHOIS-Domain.domainUnicode | string | Encode CyberTotal.WHOIS\-Domain.domain by using unicode | 
| CyberTotal.WHOIS-Domain.nameservers | string | An array of all DNS nameservers | 
| CyberTotal.WHOIS-Domain.registrarName | string | The name of registrar | 
| CyberTotal.WHOIS-Domain.registrarEmail | string | The email address of registrar | 
| CyberTotal.WHOIS-Domain.registrarPhone | string | The phone number of registrar | 
| CyberTotal.WHOIS-Domain.registrarCreatedAt | date | Registrar create date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.registrarUpdatedAt | date | Registrar update date format: YYYY\-MM\-DD HH:mm:SS  | 
| CyberTotal.WHOIS-Domain.registrarExpiresAt | date | Registrar expire date format: YYYY\-MM\-DD HH:mm:SS  | 
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
                "email": "Corp.DNS.Domains@disney.com",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "auditCreatedAt": 1586416665,
            "auditUpdatedAt": 1586416665,
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
                    "email": "Corp.DNS.Domains@disney.com",
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
            "createdAt": 1586416665,
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
            "rawResponse": {
                "domain": "abc.com",
                "raw": "Domain Name: ABC.COM\n   Registry Domain ID: 893646_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.corporatedomains.com\n   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html\n   Updated Date: 2020-04-08T07:06:06Z\n   Creation Date: 1996-05-22T04:00:00Z\n   Registry Expiry Date: 2021-05-23T04:00:00Z\n   Registrar: CSC Corporate Domains, Inc.\n   Registrar IANA ID: 299\n   Registrar Abuse Contact Email: domainabuse@cscglobal.com\n   Registrar Abuse Contact Phone: 8887802723\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS-1368.AWSDNS-43.ORG\n   Name Server: NS-1869.AWSDNS-41.CO.UK\n   Name Server: NS-318.AWSDNS-39.COM\n   Name Server: NS-736.AWSDNS-28.NET\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2020-04-09T07:17:38Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n\nDomain Name: abc.com\nRegistry Domain ID: 893646_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: www.cscprotectsbrands.com\nUpdated Date: 2020-04-08T03:06:06Z\nCreation Date: 1996-05-22T00:00:00Z\nRegistrar Registration Expiration Date: 2021-05-23T04:00:00Z\nRegistrar: CSC CORPORATE DOMAINS, INC.\nSponsoring Registrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: +1.8887802723\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nRegistry Registrant ID: \nRegistrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant Street: \nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Phone Ext: \nRegistrant Fax: +1.8182384694\nRegistrant Fax Ext: \nRegistrant Email: Corp.DNS.Domains@disney.com\nRegistry Admin ID: \nAdmin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin Street: \nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Phone Ext: \nAdmin Fax: +1.8182384694\nAdmin Fax Ext: \nAdmin Email: Corp.DNS.Domains@disney.com\nRegistry Tech ID: \nTech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech Street: \nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Phone Ext: \nTech Fax: +1.8182384694\nTech Fax Ext: \nTech Email: Corp.DNS.Domains@disney.com\nName Server: ns-1869.awsdns-41.co.uk\nName Server: ns-1368.awsdns-43.org\nName Server: ns-736.awsdns-28.net\nName Server: ns-318.awsdns-39.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2020-04-08T03:06:06Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nCorporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.\n\nContact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.\n\nNOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.\n\nRegister your domain name at http://www.cscglobal.com",
                "source": "WHOIS_XML_API",
                "unparsed": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<WhoisRecord>\n  <createdDate>1996-05-22T00:00:00Z</createdDate>\n  <updatedDate>2020-04-08T03:06:06Z</updatedDate>\n  <expiresDate>2021-05-23T04:00:00Z</expiresDate>\n  <registrant>\n    <name>ABC, Inc.; Domain Administrator</name>\n    <organization>ABC, Inc.</organization>\n    <city>New York</city>\n    <state>NY</state>\n    <postalCode>10023-6298</postalCode>\n    <country>US</country>\n    <email>Corp.DNS.Domains@disney.com</email>\n    <telephone>18182384694</telephone>\n    <fax>18182384694</fax>\n    <rawText>Registrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Fax: +1.8182384694\nRegistrant Email: Corp.DNS.Domains@disney.com</rawText>\n  </registrant>\n  <administrativeContact>\n    <name>ABC, Inc.; Domain Administrator</name>\n    <organization>ABC, Inc.</organization>\n    <city>New York</city>\n    <state>NY</state>\n    <postalCode>10023-6298</postalCode>\n    <country>US</country>\n    <email>Corp.DNS.Domains@disney.com</email>\n    <telephone>18182384694</telephone>\n    <fax>18182384694</fax>\n    <rawText>Admin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Fax: +1.8182384694\nAdmin Email: Corp.DNS.Domains@disney.com</rawText>\n  </administrativeContact>\n  <technicalContact>\n    <name>ABC, Inc.; Domain Administrator</name>\n    <organization>ABC, Inc.</organization>\n    <city>New York</city>\n    <state>NY</state>\n    <postalCode>10023-6298</postalCode>\n    <country>US</country>\n    <email>Corp.DNS.Domains@disney.com</email>\n    <telephone>18182384694</telephone>\n    <fax>18182384694</fax>\n    <rawText>Tech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Fax: +1.8182384694\nTech Email: Corp.DNS.Domains@disney.com</rawText>\n  </technicalContact>\n  <domainName>abc.com</domainName>\n  <nameServers>\n    <rawText>ns-1869.awsdns-41.co.uk\nns-1368.awsdns-43.org\nns-736.awsdns-28.net\nns-318.awsdns-39.com\n</rawText>\n    <hostNames>\n      <Address>ns-1869.awsdns-41.co.uk</Address>\n      <Address>ns-1368.awsdns-43.org</Address>\n      <Address>ns-736.awsdns-28.net</Address>\n      <Address>ns-318.awsdns-39.com</Address>\n    </hostNames>\n    <ips/>\n  </nameServers>\n  <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status>\n  <rawText>Domain Name: abc.com\nRegistry Domain ID: 893646_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: www.cscprotectsbrands.com\nUpdated Date: 2020-04-08T03:06:06Z\nCreation Date: 1996-05-22T00:00:00Z\nRegistrar Registration Expiration Date: 2021-05-23T04:00:00Z\nRegistrar: CSC CORPORATE DOMAINS, INC.\nSponsoring Registrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: +1.8887802723\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nRegistry Registrant ID: \nRegistrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant Street: \nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Phone Ext: \nRegistrant Fax: +1.8182384694\nRegistrant Fax Ext: \nRegistrant Email: Corp.DNS.Domains@disney.com\nRegistry Admin ID: \nAdmin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin Street: \nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Phone Ext: \nAdmin Fax: +1.8182384694\nAdmin Fax Ext: \nAdmin Email: Corp.DNS.Domains@disney.com\nRegistry Tech ID: \nTech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech Street: \nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Phone Ext: \nTech Fax: +1.8182384694\nTech Fax Ext: \nTech Email: Corp.DNS.Domains@disney.com\nName Server: ns-1869.awsdns-41.co.uk\nName Server: ns-1368.awsdns-43.org\nName Server: ns-736.awsdns-28.net\nName Server: ns-318.awsdns-39.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n&gt;&gt;&gt; Last update of WHOIS database: 2020-04-08T03:06:06Z &lt;&lt;&lt;\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nCorporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.\n\nContact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.\n\nNOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.\n\nRegister your domain name at http://www.cscglobal.com</rawText>\n  <parseCode>3579</parseCode>\n  <header/>\n  <strippedText>Domain Name: abc.com\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: www.cscprotectsbrands.com\nUpdated Date: 2020-04-08T03:06:06Z\nCreation Date: 1996-05-22T00:00:00Z\nRegistrar Registration Expiration Date: 2021-05-23T04:00:00Z\nRegistrar: CSC CORPORATE DOMAINS, INC.\nSponsoring Registrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: +1.8887802723\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nRegistrant Name: ABC, Inc.; Domain Administrator\nRegistrant Organization: ABC, Inc.\nRegistrant City: New York\nRegistrant State/Province: NY\nRegistrant Postal Code: 10023-6298\nRegistrant Country: US\nRegistrant Phone: +1.8182384694\nRegistrant Fax: +1.8182384694\nRegistrant Email: Corp.DNS.Domains@disney.com\nAdmin Name: ABC, Inc.; Domain Administrator\nAdmin Organization: ABC, Inc.\nAdmin City: New York\nAdmin State/Province: NY\nAdmin Postal Code: 10023-6298\nAdmin Country: US\nAdmin Phone: +1.8182384694\nAdmin Fax: +1.8182384694\nAdmin Email: Corp.DNS.Domains@disney.com\nTech Name: ABC, Inc.; Domain Administrator\nTech Organization: ABC, Inc.\nTech City: New York\nTech State/Province: NY\nTech Postal Code: 10023-6298\nTech Country: US\nTech Phone: +1.8182384694\nTech Fax: +1.8182384694\nTech Email: Corp.DNS.Domains@disney.com\nName Server: ns-1869.awsdns-41.co.uk\nName Server: ns-1368.awsdns-43.org\nName Server: ns-736.awsdns-28.net\nName Server: ns-318.awsdns-39.com\n</strippedText>\n  <footer/>\n  <audit>\n    <createdDate>2020-04-09 07:17:45.138 UTC</createdDate>\n    <updatedDate>2020-04-09 07:17:45.138 UTC</updatedDate>\n  </audit>\n  <customField1Name>RegistrarContactEmail</customField1Name>\n  <customField1Value>domainabuse@cscglobal.com</customField1Value>\n  <registrarName>CSC CORPORATE DOMAINS, INC.</registrarName>\n  <registrarIANAID>299</registrarIANAID>\n  <whoisServer>whois.corporatedomains.com</whoisServer>\n  <customField2Name>RegistrarContactPhone</customField2Name>\n  <customField3Name>RegistrarURL</customField3Name>\n  <customField2Value>+1.8887802723</customField2Value>\n  <customField3Value>www.cscprotectsbrands.com</customField3Value>\n  <registryData>\n    <createdDate>1996-05-22T04:00:00Z</createdDate>\n    <updatedDate>2020-04-08T07:06:06Z</updatedDate>\n    <expiresDate>2021-05-23T04:00:00Z</expiresDate>\n    <domainName>abc.com</domainName>\n    <nameServers>\n      <rawText>NS-1368.AWSDNS-43.ORG\nNS-1869.AWSDNS-41.CO.UK\nNS-318.AWSDNS-39.COM\nNS-736.AWSDNS-28.NET\n</rawText>\n      <hostNames>\n        <Address>NS-1368.AWSDNS-43.ORG</Address>\n        <Address>NS-1869.AWSDNS-41.CO.UK</Address>\n        <Address>NS-318.AWSDNS-39.COM</Address>\n        <Address>NS-736.AWSDNS-28.NET</Address>\n      </hostNames>\n      <ips/>\n    </nameServers>\n    <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status>\n    <rawText>Domain Name: ABC.COM\n   Registry Domain ID: 893646_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.corporatedomains.com\n   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html\n   Updated Date: 2020-04-08T07:06:06Z\n   Creation Date: 1996-05-22T04:00:00Z\n   Registry Expiry Date: 2021-05-23T04:00:00Z\n   Registrar: CSC Corporate Domains, Inc.\n   Registrar IANA ID: 299\n   Registrar Abuse Contact Email: domainabuse@cscglobal.com\n   Registrar Abuse Contact Phone: 8887802723\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS-1368.AWSDNS-43.ORG\n   Name Server: NS-1869.AWSDNS-41.CO.UK\n   Name Server: NS-318.AWSDNS-39.COM\n   Name Server: NS-736.AWSDNS-28.NET\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.</rawText>\n    <parseCode>251</parseCode>\n    <header/>\n    <strippedText>Domain Name: ABC.COM\nRegistry Domain ID: 893646_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html\nUpdated Date: 2020-04-08T07:06:06Z\nCreation Date: 1996-05-22T04:00:00Z\nRegistry Expiry Date: 2021-05-23T04:00:00Z\nRegistrar: CSC Corporate Domains, Inc.\nRegistrar IANA ID: 299\nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: 8887802723\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS-1368.AWSDNS-43.ORG\nName Server: NS-1869.AWSDNS-41.CO.UK\nName Server: NS-318.AWSDNS-39.COM\nName Server: NS-736.AWSDNS-28.NET\nDNSSEC: unsigned\nURL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;\nFor more information on Whois status codes, please visit https://icann.org/epp\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n</strippedText>\n    <footer/>\n    <audit>\n      <createdDate>2020-04-09 07:17:44.973 UTC</createdDate>\n      <updatedDate>2020-04-09 07:17:44.973 UTC</updatedDate>\n    </audit>\n    <customField1Name>RegistrarContactEmail</customField1Name>\n    <customField1Value>domainabuse@cscglobal.com</customField1Value>\n    <registrarName>CSC Corporate Domains, Inc.</registrarName>\n    <registrarIANAID>299</registrarIANAID>\n    <createdDateNormalized>1996-05-22 04:00:00 UTC</createdDateNormalized>\n    <updatedDateNormalized>2020-04-08 07:06:06 UTC</updatedDateNormalized>\n    <expiresDateNormalized>2021-05-23 04:00:00 UTC</expiresDateNormalized>\n    <customField2Name>RegistrarContactPhone</customField2Name>\n    <customField3Name>RegistrarURL</customField3Name>\n    <customField2Value>8887802723</customField2Value>\n    <customField3Value>http://www.cscglobal.com/global/web/csc/digital-brand-services.html</customField3Value>\n    <whoisServer>whois.corporatedomains.com</whoisServer>\n  </registryData>\n  <contactEmail>Corp.DNS.Domains@disney.com</contactEmail>\n  <domainNameExt>.com</domainNameExt>\n  <estimatedDomainAge>8723</estimatedDomainAge>\n</WhoisRecord>",
                "whoisID": 6653913764397840000,
                "whoisRawID": 0
            },
            "registrant": {
                "address": "New York\n10023-6298\nNY\nUS\n",
                "city": "New York",
                "country": "US",
                "email": "Corp.DNS.Domains@disney.com",
                "fax": "18182384694",
                "id": 0,
                "name": "ABC, Inc.; Domain Administrator",
                "organization": "ABC, Inc.",
                "phone": "18182384694",
                "state": "NY",
                "whoisContactID": 0,
                "zip": "10023-6298"
            },
            "registrarCreatedAt": 832737600,
            "registrarEmail": "domainabuse@cscglobal.com",
            "registrarExpiresAt": 1621742400,
            "registrarIanaID": 299,
            "registrarName": "CSC Corporate Domains, Inc.",
            "registrarParseCode": 3579,
            "registrarPhone": "+1.8887802723",
            "registrarUpdatedAt": 1586329566,
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
                "email": "Corp.DNS.Domains@disney.com",
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
            "updatedAt": 1586416665,
            "whoisID": 6653913764397840000,
            "whoisServer": "whois.corporatedomains.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|admin|auditCreatedAt|auditUpdatedAt|compositeParseCode|contactCountries|contactEmails|contactNames|contactOrganizations|contacts|createdAt|domain|domainAvailable|domainMd5|domainStatus|domainUnicode|expired|id|message|nameservers|noRecord|permalink|rawResponse|registrant|registrarCreatedAt|registrarEmail|registrarExpiresAt|registrarIanaID|registrarName|registrarParseCode|registrarPhone|registrarUpdatedAt|registryParseCode|resource|scan_date|status|task_id|technical|tld|updatedAt|whoisID|whoisServer|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| whoisContactID: 0<br/>email: Corp.DNS.Domains@disney.com<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 1586416665 | 1586416665 | 3579 | US | corp.dns.domains@disney.com | ABC, Inc.; Domain Administrator | ABC, Inc. | {'whoisContactID': 0, 'email': 'Corp.DNS.Domains@disney.com', 'name': 'ABC, Inc.; Domain Administrator', 'organization': 'ABC, Inc.', 'city': 'New York', 'state': 'NY', 'zip': '10023-6298', 'country': 'US', 'phone': '18182384694', 'fax': '18182384694', 'address': 'New York\n10023-6298\nNY\nUS\n', 'id': 0} | 1586416665 | abc.com | false | 929ba26f492f86d4a9d66a080849865a | clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited | abc.com | false | 6653913764397840884 | search success | ns-1368.awsdns-43.org,<br/>ns-1869.awsdns-41.co.uk,<br/>ns-318.awsdns-39.com,<br/>ns-736.awsdns-28.net | false | ["https://cybertotal.cycraft.com/app/intelligence/79ca1bd740564c36a7a4a78df5dc719d"] | whoisRawID: 0<br/>whoisID: 6653913764397840884<br/>domain: abc.com<br/>raw: Domain Name: ABC.COM<br/>   Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>   Registrar WHOIS Server: whois.corporatedomains.com<br/>   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html<br/>   Updated Date: 2020-04-08T07:06:06Z<br/>   Creation Date: 1996-05-22T04:00:00Z<br/>   Registry Expiry Date: 2021-05-23T04:00:00Z<br/>   Registrar: CSC Corporate Domains, Inc.<br/>   Registrar IANA ID: 299<br/>   Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>   Registrar Abuse Contact Phone: 8887802723<br/>   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited<br/>   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited<br/>   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited<br/>   Name Server: NS-1368.AWSDNS-43.ORG<br/>   Name Server: NS-1869.AWSDNS-41.CO.UK<br/>   Name Server: NS-318.AWSDNS-39.COM<br/>   Name Server: NS-736.AWSDNS-28.NET<br/>   DNSSEC: unsigned<br/>   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/<br/>>>> Last update of whois database: 2020-04-09T07:17:38Z <<<<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>NOTICE: The expiration date displayed in this record is the date the<br/>registrar's sponsorship of the domain name registration in the registry is<br/>currently set to expire. This date does not necessarily reflect the expiration<br/>date of the domain name registrant's agreement with the sponsoring<br/>registrar.  Users may consult the sponsoring registrar's Whois database to<br/>view the registrar's reported date of expiration for this registration.<br/><br/>TERMS OF USE: You are not authorized to access or query our Whois<br/>database through the use of electronic processes that are high-volume and<br/>automated except as reasonably necessary to register domain names or<br/>modify existing registrations; the Data in VeriSign Global Registry<br/>Services' ("VeriSign") Whois database is provided by VeriSign for<br/>information purposes only, and to assist persons in obtaining information<br/>about or related to a domain name registration record. VeriSign does not<br/>guarantee its accuracy. By submitting a Whois query, you agree to abide<br/>by the following terms of use: You agree that you may use this Data only<br/>for lawful purposes and that under no circumstances will you use this Data<br/>to: (1) allow, enable, or otherwise support the transmission of mass<br/>unsolicited, commercial advertising or solicitations via e-mail, telephone,<br/>or facsimile; or (2) enable high volume, automated, electronic processes<br/>that apply to VeriSign (or its computer systems). The compilation,<br/>repackaging, dissemination or other use of this Data is expressly<br/>prohibited without the prior written consent of VeriSign. You agree not to<br/>use electronic processes that are automated and high-volume to access or<br/>query the Whois database except as reasonably necessary to register<br/>domain names or modify existing registrations. VeriSign reserves the right<br/>to restrict your access to the Whois database in its sole discretion to ensure<br/>operational stability.  VeriSign may restrict or terminate your access to the<br/>Whois database for failure to abide by these terms of use. VeriSign<br/>reserves the right to modify these terms at any time.<br/><br/>The Registry database contains ONLY .COM, .NET, .EDU domains and<br/>Registrars.<br/><br/>Domain Name: abc.com<br/>Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: www.cscprotectsbrands.com<br/>Updated Date: 2020-04-08T03:06:06Z<br/>Creation Date: 1996-05-22T00:00:00Z<br/>Registrar Registration Expiration Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC CORPORATE DOMAINS, INC.<br/>Sponsoring Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: +1.8887802723<br/>Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited<br/>Registry Registrant ID: <br/>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant Street: <br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Phone Ext: <br/>Registrant Fax: +1.8182384694<br/>Registrant Fax Ext: <br/>Registrant Email: Corp.DNS.Domains@disney.com<br/>Registry Admin ID: <br/>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin Street: <br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Phone Ext: <br/>Admin Fax: +1.8182384694<br/>Admin Fax Ext: <br/>Admin Email: Corp.DNS.Domains@disney.com<br/>Registry Tech ID: <br/>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech Street: <br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Phone Ext: <br/>Tech Fax: +1.8182384694<br/>Tech Fax Ext: <br/>Tech Email: Corp.DNS.Domains@disney.com<br/>Name Server: ns-1869.awsdns-41.co.uk<br/>Name Server: ns-1368.awsdns-43.org<br/>Name Server: ns-736.awsdns-28.net<br/>Name Server: ns-318.awsdns-39.com<br/>DNSSEC: unsigned<br/>URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/<br/>>>> Last update of WHOIS database: 2020-04-08T03:06:06Z <<<<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>Corporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.<br/><br/>Contact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.<br/><br/>NOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.<br/><br/>Register your domain name at http://www.cscglobal.com<br/>unparsed: <?xml version="1.0" encoding="utf-8"?><br/><WhoisRecord><br/>  <createdDate>1996-05-22T00:00:00Z</createdDate><br/>  <updatedDate>2020-04-08T03:06:06Z</updatedDate><br/>  <expiresDate>2021-05-23T04:00:00Z</expiresDate><br/>  <registrant><br/>    <name>ABC, Inc.; Domain Administrator</name><br/>    <organization>ABC, Inc.</organization><br/>    <city>New York</city><br/>    <state>NY</state><br/>    <postalCode>10023-6298</postalCode><br/>    <country>US</country><br/>    <email>Corp.DNS.Domains@disney.com</email><br/>    <telephone>18182384694</telephone><br/>    <fax>18182384694</fax><br/>    <rawText>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Fax: +1.8182384694<br/>Registrant Email: Corp.DNS.Domains@disney.com</rawText><br/>  </registrant><br/>  <administrativeContact><br/>    <name>ABC, Inc.; Domain Administrator</name><br/>    <organization>ABC, Inc.</organization><br/>    <city>New York</city><br/>    <state>NY</state><br/>    <postalCode>10023-6298</postalCode><br/>    <country>US</country><br/>    <email>Corp.DNS.Domains@disney.com</email><br/>    <telephone>18182384694</telephone><br/>    <fax>18182384694</fax><br/>    <rawText>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Fax: +1.8182384694<br/>Admin Email: Corp.DNS.Domains@disney.com</rawText><br/>  </administrativeContact><br/>  <technicalContact><br/>    <name>ABC, Inc.; Domain Administrator</name><br/>    <organization>ABC, Inc.</organization><br/>    <city>New York</city><br/>    <state>NY</state><br/>    <postalCode>10023-6298</postalCode><br/>    <country>US</country><br/>    <email>Corp.DNS.Domains@disney.com</email><br/>    <telephone>18182384694</telephone><br/>    <fax>18182384694</fax><br/>    <rawText>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Fax: +1.8182384694<br/>Tech Email: Corp.DNS.Domains@disney.com</rawText><br/>  </technicalContact><br/>  <domainName>abc.com</domainName><br/>  <nameServers><br/>    <rawText>ns-1869.awsdns-41.co.uk<br/>ns-1368.awsdns-43.org<br/>ns-736.awsdns-28.net<br/>ns-318.awsdns-39.com<br/></rawText><br/>    <hostNames><br/>      <Address>ns-1869.awsdns-41.co.uk</Address><br/>      <Address>ns-1368.awsdns-43.org</Address><br/>      <Address>ns-736.awsdns-28.net</Address><br/>      <Address>ns-318.awsdns-39.com</Address><br/>    </hostNames><br/>    <ips/><br/>  </nameServers><br/>  <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status><br/>  <rawText>Domain Name: abc.com<br/>Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: www.cscprotectsbrands.com<br/>Updated Date: 2020-04-08T03:06:06Z<br/>Creation Date: 1996-05-22T00:00:00Z<br/>Registrar Registration Expiration Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC CORPORATE DOMAINS, INC.<br/>Sponsoring Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: +1.8887802723<br/>Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited<br/>Registry Registrant ID: <br/>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant Street: <br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Phone Ext: <br/>Registrant Fax: +1.8182384694<br/>Registrant Fax Ext: <br/>Registrant Email: Corp.DNS.Domains@disney.com<br/>Registry Admin ID: <br/>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin Street: <br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Phone Ext: <br/>Admin Fax: +1.8182384694<br/>Admin Fax Ext: <br/>Admin Email: Corp.DNS.Domains@disney.com<br/>Registry Tech ID: <br/>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech Street: <br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Phone Ext: <br/>Tech Fax: +1.8182384694<br/>Tech Fax Ext: <br/>Tech Email: Corp.DNS.Domains@disney.com<br/>Name Server: ns-1869.awsdns-41.co.uk<br/>Name Server: ns-1368.awsdns-43.org<br/>Name Server: ns-736.awsdns-28.net<br/>Name Server: ns-318.awsdns-39.com<br/>DNSSEC: unsigned<br/>URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/<br/>&gt;&gt;&gt; Last update of WHOIS database: 2020-04-08T03:06:06Z &lt;&lt;&lt;<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>Corporation Service Company(c) (CSC)  The Trusted Partner of More than 50% of the 100 Best Global Brands.<br/><br/>Contact us to learn more about our enterprise solutions for Global Domain Name Registration and Management, Trademark Research and Watching, Brand, Logo and Auction Monitoring, as well SSL Certificate Services and DNS Hosting.<br/><br/>NOTICE: You are not authorized to access or query our WHOIS database through the use of high-volume, automated, electronic processes or for the purpose or purposes of using the data in any manner that violates these terms of use. The Data in the CSC WHOIS database is provided by CSC for information purposes only, and to assist persons in obtaining information about or related to a domain name registration record. CSC does not guarantee its accuracy. By submitting a WHOIS query, you agree to abide by the following terms of use: you agree that you may use this Data only for lawful purposes and that under no circumstances will you use this Data to: (1) allow, enable, or otherwise support the transmission of mass unsolicited, commercial advertising or solicitations via direct mail, e-mail, telephone, or facsimile; or (2) enable high volume, automated, electronic processes that apply to CSC (or its computer systems). CSC reserves the right to terminate your access to the WHOIS database in its sole discretion for any violations by you of these terms of use. CSC reserves the right to modify these terms at any time.<br/><br/>Register your domain name at http://www.cscglobal.com</rawText><br/>  <parseCode>3579</parseCode><br/>  <header/><br/>  <strippedText>Domain Name: abc.com<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: www.cscprotectsbrands.com<br/>Updated Date: 2020-04-08T03:06:06Z<br/>Creation Date: 1996-05-22T00:00:00Z<br/>Registrar Registration Expiration Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC CORPORATE DOMAINS, INC.<br/>Sponsoring Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: +1.8887802723<br/>Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited<br/>Registrant Name: ABC, Inc.; Domain Administrator<br/>Registrant Organization: ABC, Inc.<br/>Registrant City: New York<br/>Registrant State/Province: NY<br/>Registrant Postal Code: 10023-6298<br/>Registrant Country: US<br/>Registrant Phone: +1.8182384694<br/>Registrant Fax: +1.8182384694<br/>Registrant Email: Corp.DNS.Domains@disney.com<br/>Admin Name: ABC, Inc.; Domain Administrator<br/>Admin Organization: ABC, Inc.<br/>Admin City: New York<br/>Admin State/Province: NY<br/>Admin Postal Code: 10023-6298<br/>Admin Country: US<br/>Admin Phone: +1.8182384694<br/>Admin Fax: +1.8182384694<br/>Admin Email: Corp.DNS.Domains@disney.com<br/>Tech Name: ABC, Inc.; Domain Administrator<br/>Tech Organization: ABC, Inc.<br/>Tech City: New York<br/>Tech State/Province: NY<br/>Tech Postal Code: 10023-6298<br/>Tech Country: US<br/>Tech Phone: +1.8182384694<br/>Tech Fax: +1.8182384694<br/>Tech Email: Corp.DNS.Domains@disney.com<br/>Name Server: ns-1869.awsdns-41.co.uk<br/>Name Server: ns-1368.awsdns-43.org<br/>Name Server: ns-736.awsdns-28.net<br/>Name Server: ns-318.awsdns-39.com<br/></strippedText><br/>  <footer/><br/>  <audit><br/>    <createdDate>2020-04-09 07:17:45.138 UTC</createdDate><br/>    <updatedDate>2020-04-09 07:17:45.138 UTC</updatedDate><br/>  </audit><br/>  <customField1Name>RegistrarContactEmail</customField1Name><br/>  <customField1Value>domainabuse@cscglobal.com</customField1Value><br/>  <registrarName>CSC CORPORATE DOMAINS, INC.</registrarName><br/>  <registrarIANAID>299</registrarIANAID><br/>  <whoisServer>whois.corporatedomains.com</whoisServer><br/>  <customField2Name>RegistrarContactPhone</customField2Name><br/>  <customField3Name>RegistrarURL</customField3Name><br/>  <customField2Value>+1.8887802723</customField2Value><br/>  <customField3Value>www.cscprotectsbrands.com</customField3Value><br/>  <registryData><br/>    <createdDate>1996-05-22T04:00:00Z</createdDate><br/>    <updatedDate>2020-04-08T07:06:06Z</updatedDate><br/>    <expiresDate>2021-05-23T04:00:00Z</expiresDate><br/>    <domainName>abc.com</domainName><br/>    <nameServers><br/>      <rawText>NS-1368.AWSDNS-43.ORG<br/>NS-1869.AWSDNS-41.CO.UK<br/>NS-318.AWSDNS-39.COM<br/>NS-736.AWSDNS-28.NET<br/></rawText><br/>      <hostNames><br/>        <Address>NS-1368.AWSDNS-43.ORG</Address><br/>        <Address>NS-1869.AWSDNS-41.CO.UK</Address><br/>        <Address>NS-318.AWSDNS-39.COM</Address><br/>        <Address>NS-736.AWSDNS-28.NET</Address><br/>      </hostNames><br/>      <ips/><br/>    </nameServers><br/>    <status>clientTransferProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited</status><br/>    <rawText>Domain Name: ABC.COM<br/>   Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>   Registrar WHOIS Server: whois.corporatedomains.com<br/>   Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html<br/>   Updated Date: 2020-04-08T07:06:06Z<br/>   Creation Date: 1996-05-22T04:00:00Z<br/>   Registry Expiry Date: 2021-05-23T04:00:00Z<br/>   Registrar: CSC Corporate Domains, Inc.<br/>   Registrar IANA ID: 299<br/>   Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>   Registrar Abuse Contact Phone: 8887802723<br/>   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited<br/>   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited<br/>   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited<br/>   Name Server: NS-1368.AWSDNS-43.ORG<br/>   Name Server: NS-1869.AWSDNS-41.CO.UK<br/>   Name Server: NS-318.AWSDNS-39.COM<br/>   Name Server: NS-736.AWSDNS-28.NET<br/>   DNSSEC: unsigned<br/>   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/<br/>&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;<br/><br/>For more information on Whois status codes, please visit https://icann.org/epp<br/><br/>NOTICE: The expiration date displayed in this record is the date the<br/>registrar's sponsorship of the domain name registration in the registry is<br/>currently set to expire. This date does not necessarily reflect the expiration<br/>date of the domain name registrant's agreement with the sponsoring<br/>registrar.  Users may consult the sponsoring registrar's Whois database to<br/>view the registrar's reported date of expiration for this registration.<br/><br/>TERMS OF USE: You are not authorized to access or query our Whois<br/>database through the use of electronic processes that are high-volume and<br/>automated except as reasonably necessary to register domain names or<br/>modify existing registrations; the Data in VeriSign Global Registry<br/>Services' ("VeriSign") Whois database is provided by VeriSign for<br/>information purposes only, and to assist persons in obtaining information<br/>about or related to a domain name registration record. VeriSign does not<br/>guarantee its accuracy. By submitting a Whois query, you agree to abide<br/>by the following terms of use: You agree that you may use this Data only<br/>for lawful purposes and that under no circumstances will you use this Data<br/>to: (1) allow, enable, or otherwise support the transmission of mass<br/>unsolicited, commercial advertising or solicitations via e-mail, telephone,<br/>or facsimile; or (2) enable high volume, automated, electronic processes<br/>that apply to VeriSign (or its computer systems). The compilation,<br/>repackaging, dissemination or other use of this Data is expressly<br/>prohibited without the prior written consent of VeriSign. You agree not to<br/>use electronic processes that are automated and high-volume to access or<br/>query the Whois database except as reasonably necessary to register<br/>domain names or modify existing registrations. VeriSign reserves the right<br/>to restrict your access to the Whois database in its sole discretion to ensure<br/>operational stability.  VeriSign may restrict or terminate your access to the<br/>Whois database for failure to abide by these terms of use. VeriSign<br/>reserves the right to modify these terms at any time.<br/><br/>The Registry database contains ONLY .COM, .NET, .EDU domains and<br/>Registrars.</rawText><br/>    <parseCode>251</parseCode><br/>    <header/><br/>    <strippedText>Domain Name: ABC.COM<br/>Registry Domain ID: 893646_DOMAIN_COM-VRSN<br/>Registrar WHOIS Server: whois.corporatedomains.com<br/>Registrar URL: http://www.cscglobal.com/global/web/csc/digital-brand-services.html<br/>Updated Date: 2020-04-08T07:06:06Z<br/>Creation Date: 1996-05-22T04:00:00Z<br/>Registry Expiry Date: 2021-05-23T04:00:00Z<br/>Registrar: CSC Corporate Domains, Inc.<br/>Registrar IANA ID: 299<br/>Registrar Abuse Contact Email: domainabuse@cscglobal.com<br/>Registrar Abuse Contact Phone: 8887802723<br/>Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited<br/>Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited<br/>Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited<br/>Name Server: NS-1368.AWSDNS-43.ORG<br/>Name Server: NS-1869.AWSDNS-41.CO.UK<br/>Name Server: NS-318.AWSDNS-39.COM<br/>Name Server: NS-736.AWSDNS-28.NET<br/>DNSSEC: unsigned<br/>URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/<br/>&gt;&gt;&gt; Last update of whois database: 2020-04-09T07:17:38Z &lt;&lt;&lt;<br/>For more information on Whois status codes, please visit https://icann.org/epp<br/>NOTICE: The expiration date displayed in this record is the date the<br/>registrar's sponsorship of the domain name registration in the registry is<br/>currently set to expire. This date does not necessarily reflect the expiration<br/>date of the domain name registrant's agreement with the sponsoring<br/>registrar.  Users may consult the sponsoring registrar's Whois database to<br/>view the registrar's reported date of expiration for this registration.<br/>TERMS OF USE: You are not authorized to access or query our Whois<br/>database through the use of electronic processes that are high-volume and<br/>automated except as reasonably necessary to register domain names or<br/>modify existing registrations; the Data in VeriSign Global Registry<br/>Services' ("VeriSign") Whois database is provided by VeriSign for<br/>information purposes only, and to assist persons in obtaining information<br/>about or related to a domain name registration record. VeriSign does not<br/>guarantee its accuracy. By submitting a Whois query, you agree to abide<br/>by the following terms of use: You agree that you may use this Data only<br/>for lawful purposes and that under no circumstances will you use this Data<br/>to: (1) allow, enable, or otherwise support the transmission of mass<br/>unsolicited, commercial advertising or solicitations via e-mail, telephone,<br/>or facsimile; or (2) enable high volume, automated, electronic processes<br/>that apply to VeriSign (or its computer systems). The compilation,<br/>repackaging, dissemination or other use of this Data is expressly<br/>prohibited without the prior written consent of VeriSign. You agree not to<br/>use electronic processes that are automated and high-volume to access or<br/>query the Whois database except as reasonably necessary to register<br/>domain names or modify existing registrations. VeriSign reserves the right<br/>to restrict your access to the Whois database in its sole discretion to ensure<br/>operational stability.  VeriSign may restrict or terminate your access to the<br/>Whois database for failure to abide by these terms of use. VeriSign<br/>reserves the right to modify these terms at any time.<br/>The Registry database contains ONLY .COM, .NET, .EDU domains and<br/>Registrars.<br/></strippedText><br/>    <footer/><br/>    <audit><br/>      <createdDate>2020-04-09 07:17:44.973 UTC</createdDate><br/>      <updatedDate>2020-04-09 07:17:44.973 UTC</updatedDate><br/>    </audit><br/>    <customField1Name>RegistrarContactEmail</customField1Name><br/>    <customField1Value>domainabuse@cscglobal.com</customField1Value><br/>    <registrarName>CSC Corporate Domains, Inc.</registrarName><br/>    <registrarIANAID>299</registrarIANAID><br/>    <createdDateNormalized>1996-05-22 04:00:00 UTC</createdDateNormalized><br/>    <updatedDateNormalized>2020-04-08 07:06:06 UTC</updatedDateNormalized><br/>    <expiresDateNormalized>2021-05-23 04:00:00 UTC</expiresDateNormalized><br/>    <customField2Name>RegistrarContactPhone</customField2Name><br/>    <customField3Name>RegistrarURL</customField3Name><br/>    <customField2Value>8887802723</customField2Value><br/>    <customField3Value>http://www.cscglobal.com/global/web/csc/digital-brand-services.html</customField3Value><br/>    <whoisServer>whois.corporatedomains.com</whoisServer><br/>  </registryData><br/>  <contactEmail>Corp.DNS.Domains@disney.com</contactEmail><br/>  <domainNameExt>.com</domainNameExt><br/>  <estimatedDomainAge>8723</estimatedDomainAge><br/></WhoisRecord><br/>source: WHOIS_XML_API | whoisContactID: 0<br/>email: Corp.DNS.Domains@disney.com<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | 832737600 | domainabuse@cscglobal.com | 1621742400 | 299 | CSC Corporate Domains, Inc. | 3579 | +1.8887802723 | 1586329566 | 251 | ["abc.com"] | ["2020-06-18 03:19:48"] | ACTIVE | 79ca1bd740564c36a7a4a78df5dc719d | whoisContactID: 0<br/>email: Corp.DNS.Domains@disney.com<br/>name: ABC, Inc.; Domain Administrator<br/>organization: ABC, Inc.<br/>city: New York<br/>state: NY<br/>zip: 10023-6298<br/>country: US<br/>phone: 18182384694<br/>fax: 18182384694<br/>address: New York<br/>10023-6298<br/>NY<br/>US<br/><br/>id: 0 | com | 1586416665 | 6653913764397840884 | whois.corporatedomains.com |

