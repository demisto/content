This is the RST Threat Feed integration for interacting with API
This integration was integrated and tested with RST Cloud - Threat Feed API v1

Please contact the RST Cloud team via email support@rstcloud.net to obtain a key and ask any questions you have.
Also, the following contact details can be used:

- **URL**: [https://www.rstcloud.net/contact](https://www.rstcloud.net/contact)


Each indicator is ranked from 0 to 100. Indicators are being collected from multiple sources and are cross-verified using multiple criteria. 
Please check indicator tags and malware family fields. An indicator may describe a known malware or a scanning host. Therefore, different actions may be required based on the context.

## Configure RST Cloud - Threat Feed API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. <https://api.rstcloud.net/v1>) |  | True |
| API Key |  | True |
| Score threshold for IP reputation command | Set this to determine the RST Threat Feed score that will determine if an IP is malicious \(0-100\) | True |
| Score threshold for domain reputation command | Set this to determine the RST Threat Feed score that will determine if a domain is malicious \(0-100\) | True |
| Score threshold for url reputation command | Set this to determine the RST Threat Feed score that will determine if a url is malicious \(0-100\) | True |
| Score threshold for file reputation command | Set this to determine the RST Threat Feed score that will determine if a file is malicious \(0-100\) | True |
| IP Indicator Expiration (days) | Mark IP indicators older than indicator_expiration_ip value in days as Suspicious ignoring the last available score | True |
| Domain Indicator Expiration (days) | Mark domain indicators older than indicator_expiration_domain value in days as Suspicious ignoring the last available score | True |
| URL Indicator Expiration (days) | Mark URL indicators older than indicator_expiration_url value in days as Suspicious ignoring the last available score | True |
| Hash Indicator Expiration (days) | Mark Hash indicators older than indicator_expiration_url value in days as Suspicious ignoring the last available score | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Returns IP information and reputation.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 
| threshold | If the IP has reputation above the threshold then the IP defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 45. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | String | IP address. | 
| IP.Geo.Country | String | Country of origin. | 
| IP.Tags | String | The associated tags. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Malicious.Score | String | The score calculated for the indicator by the vendor. | 
| RST.IP.Address | String | The actual IP address. | 
| RST.IP.Geo.Country | String | The country name. | 
| RST.IP.Geo.Region | String | The geo region name. | 
| RST.IP.Geo.City | String | The city name. | 
| RST.IP.ASN | String | The autonomous system name for the IP address. | 
| RST.IP.Organization | String | The organisation name for the autonomous system name for the IP address. | 
| RST.IP.ISP | String | The Internet Service Provider name for the autonomous system name for the IP address. | 
| RST.IP.CloudHosting | String | The Cloud Provider name for the IP address. | 
| RST.IP.NumberOfDomainInASN | String | The number of domain names for the IP address. | 
| RST.IP.FirstSeen | Date | First Seen. | 
| RST.IP.LastSeen | Date | Last Seen. | 
| RST.IP.Tags | String | The associated tags. | 
| RST.IP.Threat | String | The associated Malware Family or threat name. | 
| RST.IP.Score | Number | The total score. | 
| RST.IP.UUID | String | The unique ID for the indicator. | 
| RST.IP.RSTReference | String | The link to the raw JSON indicator. | 
| RST.IP.Related | String | The associated domains. | 
| RST.IP.FalsePositive | String | true if it is likely a False Positive. | 
| RST.IP.FalsePositiveDesc | String | Description why we think it may be a False Positive. | 
| RST.IP.CVE | String | Related CVE \(vulnerabilities\) | 
| RST.IP.Industry | String | Related Industry. | 
| RST.IP.Report | String | Collected from. | 


#### Command Example

```!ip ip=1.2.3.4 threshold=50```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "1.2.3.4",
        "Score": 2,
        "Type": "ip",
        "Vendor": "RST Cloud"
    },
    "IP": {
        "ASN": "4788",
        "Address": "1.2.3.4",
        "Geo": {
            "Country": "Malaysia"
        },
        "Tags": [
            "c2",
            "generic"
        ]
    },
    "RST": {
        "IP": {
            "ASN": "4788",
            "Address": "1.2.3.4",
            "CloudHosting": "",
            "FalsePositive": "false",
            "FalsePositiveDesc": "",
            "FirstSeen": "2019-12-05T00:00:00.000Z",
            "Geo": {
                "city": "Batang Kali",
                "country": "Malaysia",
                "region": "Selangor"
            },
            "ISP": "TMNETASAP",
            "LastSeen": "2021-01-26T00:00:00.000Z",
            "NumberOfDomainInASN": "9615",
            "Organization": "TM Net Internet Service Provider",
            "RSTReference": "https://rstcloud.net/uuid?id=8f10a17d-9931-3329-b97f-db3953c093e2",
            "Related": [],
            "Score": "3",
            "Tags": [
                "c2",
                "generic"
            ],
            "Threat": [
                "emotet"
            ],
            "Type": "IP",
            "UUID": "8f10a17d-9931-3329-b97f-db3953c093e2"
        }
    }
}
```

#### Human Readable Output

>### RST Threat Feed IP Reputation for: 1.2.3.4
>
>|Description|Last Seen|Relevance|Score|Tags|Threat|
>|---|---|---|---|---|---|
>| Ioc with tags: c2, generic. related threats: emotet<br/> | 2021-01-26 | Suspicious | 3 | c2, generic | emotet |


### domain

***
Returns Domain information and reputation.


#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 
| threshold | If the domain has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 45. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.Tags | String | The associated tags | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Malicious.Score | String | The score calculated for the indicator by the vendor. | 
| RST.Domain.Name | String | The domain name. | 
| RST.Domain.WhoisAge | Number | Days since creation. | 
| RST.Domain.WhoisDomainCreationDate | Date | Creation date. Format is ISO8601. | 
| RST.Domain.WhoisDomainUpdateDate | Date | Update date. Format is ISO8601. | 
| RST.Domain.WhoisDomainExpireDate | Date | Expiration date. Format is ISO8601. | 
| RST.Domain.WhoisRegistrar | String | Domain Registrar. | 
| RST.Domain.WhoisRegistrant | String | Domain Registrant. | 
| RST.Domain.FirstSeen | Date | First Seen. | 
| RST.Domain.LastSeen | Date | Last Seen. | 
| RST.Domain.Tags | String | The associated tags. | 
| RST.Domain.Threat | String | The associated Malware Family or threat name. | 
| RST.Domain.Score | Number | The total score. | 
| RST.Domain.UUID | String | The unique ID for the indicator. | 
| RST.Domain.RSTReference | String | The link to the raw JSON indicator. | 
| RST.Domain.Related | String | The associated IP addresses. | 
| RST.Domain.FalsePositive | String | true if it is likely a False Positive. | 
| RST.Domain.FalsePositiveDesc | String | Description why we think it may be a False Positive. | 
| RST.Domain.CVE | String | Related CVE \(vulnerabilities\) | 
| RST.Domain.Industry | String | Related Industry. | 
| RST.Domain.Report | String | Collected from. | 


#### Command Example

```!domain domain="domaintovalidate.local" threshold=40```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "domaintovalidate.local",
        "Score": 2,
        "Type": "domain",
        "Vendor": "RST Cloud"
    },
    "Domain": {
        "Name": "domaintovalidate.local",
        "Tags": [
            "malware"
        ]
    },
    "RST": {
        "Domain": {
            "FalsePositive": "true",
            "FalsePositiveDesc": "Domain not resolved. Whois records not found",
            "FirstSeen": "2020-06-26T00:00:00.000Z",
            "LastSeen": "2021-01-25T00:00:00.000Z",
            "Name": "domaintovalidate.local",
            "RSTReference": "https://rstcloud.net/uuid?id=552fdbe7-7265-3a9d-b364-83426d1c2dbc",
            "Related": {
                "a": [],
                "alias": [],
                "cname": []
            },
            "Score": "10",
            "Tags": [
                "malware"
            ],
            "Threat": [],
            "Type": "Domain",
            "UUID": "552fdbe7-7265-3a9d-b364-83426d1c2dbc",
            "WhoisAge": "",
            "WhoisDomainCreationDate": "",
            "WhoisDomainExpireDate": "",
            "WhoisDomainUpdateDate": "",
            "WhoisRegistrant": "",
            "WhoisRegistrar": ""
        }
    }
}
```

#### Human Readable Output

>### RST Threat Feed Domain Reputation for: domaintovalidate.local
>
>|Description|Last Seen|Relevance:|Score|Tags|
>|---|---|---|---|---|
>| Ioc with tags: malware<br/> | 2021-01-25 | Suspicious | 10 | malware |


### url

***
Returns URL information and reputation.


#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required | 
| threshold | If the URL has reputation above the threshold then the URL defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | String | The URL. | 
| URL.Tags | String | The associated tags. | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | String | A description explaining why the URL was reported as malicious. | 
| URL.Malicious.Score | String | The score calculated for the URL indicator by the vendor. | 
| RST.URL.Data | String | The URL. | 
| RST.URL.Status | String | Last HTTP status code. | 
| RST.URL.FirstSeen | Date | First Seen. | 
| RST.URL.LastSeen | Date | Last Seen. | 
| RST.URL.Tags | String | The associated tags. | 
| RST.URL.Threat | String | The associated Malware Family or threat name. | 
| RST.URL.Score | Number | The total score. | 
| RST.URL.UUID | String | The unique ID for the indicator | 
| RST.URL.Description | String | The associated Description provided by the vendor. | 
| RST.URL.FalsePositive | String | true if it is likely a False Positive. | 
| RST.URL.FalsePositiveDesc | String | Description why we think it may be a False Positive. | 
| RST.URL.Parsed | String | Parsed URL components. | 
| RST.URL.CVE | String | Related CVE \(vulnerabilities\) | 
| RST.URL.Industry | String | Related Industry. | 
| RST.URL.Report | String | Collected from. | 


#### Command Example

```!url url="https://domain.local/testurl" threshold=30```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "https://domain.local/testurl",
        "Score": 2,
        "Type": "url",
        "Vendor": "RST Cloud"
    },
    "RST": {
        "URL": {
            "CVE": [],
            "Data": "https://domain.local/testurl",
            "FalsePositive": "true",
            "FalsePositiveDesc": "Resource unavailable",
            "FirstSeen": "2021-01-05T00:00:00.000Z",
            "LastSeen": "2021-01-26T00:00:00.000Z",
            "Parsed": {
                "anchor": null,
                "domain": "domain.local",
                "params": null,
                "path": "/testurl",
                "port": "443",
                "schema": "https"
            },
            "RSTReference": "https://rstcloud.net/uuid?id=f64f7a99-068b-3fec-b572-598f9d11d4d6",
            "Score": "14",
            "Status": "503",
            "Tags": [
                "malware"
            ],
            "Threat": [
                "emotet"
            ],
            "Type": "URL",
            "UUID": "f64f7a99-068b-3fec-b572-598f9d11d4d6"
        }
    },
    "URL": {
        "Data": "https://domain.local/testurl",
        "Tags": [
            "malware"
        ]
    }
}
```

#### Human Readable Output

>### RST Threat Feed URL Reputation for: `https://domain.local/testurl`
>
>|Description|Last Seen|Relevance|Score|Tags|Threat|
>|---|---|---|---|---|---|
>| Ioc with tags: malware. related threats: emotet<br/> | 2021-01-26 | Suspicious | 14 | malware | emotet |


### file

***
Returns File information and reputation.


#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of Files. | Required | 
| threshold | If the File has reputation above the threshold then the File defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Name | String | The file name. | 
| File.MD5 | String | MD5 for the the file name. | 
| File.SHA1 | String | SHA1 for the the file name. | 
| File.SHA256 | String | The URL. | 
| File.Tags | String | The associated tags. | 
| File.Malicious.Vendor | String | The vendor reporting the File as malicious. | 
| File.Malicious.Description | String | A description explaining why the File was reported as malicious. | 
| File.Malicious.Score | String | The score calculated for the File indicator by the vendor. | 
| RST.File.Name | String | The file name. | 
| RST.File.MD5 | String | MD5 for the the file name. | 
| RST.File.SHA1 | String | SHA1 for the the file name. | 
| RST.File.SHA256 | String | SHA256 for the the file name. | 
| RST.File.FirstSeen | Date | First Seen. | 
| RST.File.LastSeen | Date | Last Seen. | 
| RST.File.Tags | String | The associated tags. | 
| RST.File.Threat | String | The associated Malware Family or threat name. | 
| RST.File.Score | Number | The total score. | 
| RST.File.UUID | String | The unique ID for the indicator. | 
| RST.File.Description | String | The associated Description provided by the vendor. | 
| RST.File.FalsePositive | String | true if it is likely a False Positive. | 
| RST.File.FalsePositiveDesc | String | Description why we think it may be a False Positive. | 
| RST.File.CVE | String | Related CVE \(vulnerabilities\) | 
| RST.File.Industry | String | Related Industry. | 
| RST.File.Report | String | Collected from. | 


#### Command Example

```!file file="fe3d38316dc38a4ec63eac80e34cb157c9d896460f9b7b3bfbd2cec4e2cb8cdc"threshold=5```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "fe3d38316dc38a4ec63eac80e34cb157c9d896460f9b7b3bfbd2cec4e2cb8cdc",
        "Score": 3,
        "Type": "file",
        "Vendor": "RST Cloud"
    },
    "RST": {
        "File": {
            "CVE": [],
            "FalsePositive": "false",
            "FalsePositiveDesc": "",
            "FirstSeen": "2021-05-11T00:00:00.000Z",
            "Industry": [],
            "LastSeen": "2022-03-11T00:00:00.000Z",
            "Name": [],
            "RSTReference": "https://rstcloud.net/uuid?id=c86948e7-eb72-3fe1-96e9-429e885cea3b",
            "Report": [
                "https://www.threatfabric.com/blogs/partners-in-crime-medusa-cabassous.html"
            ],
            "SHA256": "fe3d38316dc38a4ec63eac80e34cb157c9d896460f9b7b3bfbd2cec4e2cb8cdc",
            "Score": "6",
            "Tags": [
                "malware"
            ],
            "Threat": [
                "medusa",
                "flubot"
            ],
            "Type": "File",
            "UUID": "c86948e7-eb72-3fe1-96e9-429e885cea3b"
        }
    },
    "File": {
        "SHA256": "fe3d38316dc38a4ec63eac80e34cb157c9d896460f9b7b3bfbd2cec4e2cb8cdc",
        "Tags": [
            "malware"
        ]
    }
}
```

#### Human Readable Output

>### RST Threat Feed File Reputation for: `https://domain.local/testurl`
>
>|Description|Last Seen|Relevance|Score|Tags|Threat|
>|---|---|---|---|---|---|
>| Ioc with tags: malware. related threats: emotet<br/> | 2021-01-26 | Suspicious | 14 | malware | emotet |


### rst-submit-new

***
Submits an indicator to RST Threat Feed.


#### Base Command

`rst-submit-new`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc | List of IOCs (URLs, domains or IPs). | Required | 
| description | Any context to pass to RST Cloud. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!rst-submit-new ioc="thisisamaliciouswebsite.com" description="a user downloaded a trojan"```

#### Human Readable Output

>Indicator: thisisamaliciouswebsite.com was submitted as a potential threat indicator to RST Cloud


### rst-submit-fp

***
Submits a potential False Positive to RST Threat Feed.


#### Base Command

`rst-submit-fp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc | List of IOCs (URLs, domains or IPs). | Required | 
| description | Any context to pass to RST Cloud. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!rst-submit-fp ioc="thisisnotamaliciousdomain.com" description="a decent website"```

#### Human Readable Output

>Indicator: thisisnotamaliciousdomain.com was submitted as False Positive to RST Cloud
