Query threat crowd for reports.
This integration was integrated and tested with version xx of TheatCrowdv2
## Configure TheatCrowdv2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TheatCrowdv2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Your server URL | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Get a report of an IP.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Get a report of an IP. | Required | 
| resolution_limit | Maximum number of entries under resolution section. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Tags | Unknown | \(List\) Tags of the IP. | 
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP. | 
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP. | 
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP. | 
| IP.MalwareFamily | String | The malware family associated with the IP. | 
| IP.Organization.Name | String | The organization of the IP. | 
| IP.Organization.Type | String | The organization type of the IP. | 


#### Command Example
```!ip ip="1.2.3.5" using="TheatCrowdv2_instance_1" resolution_limit=5```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.2.3.5",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "Threat Crowd"
    },
    "IP": {
        "Address": "1.2.3.5"
    },
    "ThreatCrowd": {
        "IP": {
            "hashes": [],
            "permalink": "https://www.threatcrowd.org/ip.php?ip=1.2.3.5",
            "references": [],
            "resolutions": [
                {
                    "domain": "cname.githubtest.net",
                    "last_resolved": "2018-08-05"
                },
                {
                    "domain": "www.mein-apcoa.de",
                    "last_resolved": "2020-01-11"
                },
                {
                    "domain": "githubtest.net",
                    "last_resolved": "2020-04-27"
                },
                {
                    "domain": "dnsoptimus.com",
                    "last_resolved": "2020-12-04"
                }
            ],
            "response_code": "1",
            "value": "1.2.3.5",
            "votes": 0
        }
    }
}
```

#### Human Readable Output

>Threat crowd report for ip 1.2.3.5: 
>### Resolutions
>|domain|last_resolved|
>|---|---|
>| cname.githubtest.net | 2018-08-05 |
>| www.mein-apcoa.de | 2020-01-11 |
>| githubtest.net | 2020-04-27 |
>| dnsoptimus.com | 2020-12-04 |
>Hashes: 
> [] 
>### References
>**No entries.**


### domain
***
Get a report of a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Get a report of a domain. | Required | 
| resolution_limit | Maximum number of entries under resolution section. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.DomainStatus | Datte | The status of the domain. | 
| Domain.NameServers | Unknown | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | Unknown | \(List&lt;String&gt;\) Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.Tags | Unknown | \(List\) Tags of the domain. | 
| Domain.FeedRelatedIndicators.value | String | Indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the domain. | 
| Domain.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the domain. | 
| Domain.MalwareFamily | String | The malware family associated with the domain. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: 'GoDaddy' | 
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS/History | String | List of Whois objects | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 


#### Command Example
```!domain domain="aoldaily.com" resolution_limit=5 using="TheatCrowdv2_instance_1"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "aoldaily.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Threat Crowd"
    },
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "Threat Crowd"
        },
        "Name": "aoldaily.com"
    },
    "ThreatCrowd": {
        "Domain": {
            "emails": [
                "domains@virustracker.info",
                "william19770319@yahoo.com"
            ],
            "hashes": [],
            "permalink": "https://www.threatcrowd.org/domain.php?domain=aoldaily.com",
            "references": [
                "httpblog.shadowserver.org201302",
                "httpsto-strategy.comsAppendix-D-Digital-FQDNs.pdf"
            ],
            "response_code": "1",
            "subdomains": [
                "media.aoldaily.com",
                "e.aoldaily.com",
                "finance.aoldaily.com",
                "game.aoldaily.com",
                "zone.aoldaily.com",
                "share.aoldaily.com",
                "update.aoldaily.com",
                "flash.aoldaily.com",
                "mail.aoldaily.com",
                "webmail.aoldaily.com",
                "email.aoldaily.com",
                "info.aoldaily.com",
                "auto.aoldaily.com",
                "asdf--auto.aoldaily.com",
                "asdf--\u00c0u0066auto.aoldaily.com",
                "asdf25u0027auto.aoldaily.com",
                "asdfu0027auto.aoldaily.com",
                "asdf--\u00c0auto.aoldaily.com",
                "asdf--\u00c0aaaaaauto.aoldaily.com",
                "asdf--\u00c0fauto.aoldaily.com",
                "asdfauto.aoldaily.com",
                "asdfauto.aoldaily.com",
                "pop.aoldaily.com",
                "ftp.aoldaily.com",
                "smtp.aoldaily.com",
                "ks.aoldaily.com",
                "stratos.aoldaily.com",
                "documents.aoldaily.com",
                "sports.aoldaily.com",
                "news.aoldaily.com",
                "tw.aoldaily.com",
                "www.aoldaily.com",
                "mx.aoldaily.com"
            ],
            "value": "aoldaily.com",
            "votes": -1
        }
    }
}
```

#### Human Readable Output

>Threat crowd report for domain aoldaily.com 
>### Resolutions
>|ip_address|last_resolved|
>|---|---|
>| - | 2017-11-09 |
>| 0.0.0.0 | 2014-04-01 |
>| 167.88.206.88 | 2020-07-22 |
>| 18.189.205.91 | 2021-03-05 |
>| 18.190.95.243 | 2020-10-18 |
>### 
>
>|emails|hashes|permalink|references|response_code|subdomains|value|votes|
>|---|---|---|---|---|---|---|---|
>| domains@virustracker.info,<br/>william19770319@yahoo.com |  | https://www.threatcrowd.org/domain.php?domain=aoldaily.com | httpblog.shadowserver.org201302,<br/>httpsto-strategy.comsAppendix-D-Digital-FQDNs.pdf | 1 | media.aoldaily.com,<br/>e.aoldaily.com,<br/>finance.aoldaily.com,<br/>game.aoldaily.com,<br/>zone.aoldaily.com,<br/>share.aoldaily.com,<br/>update.aoldaily.com,<br/>flash.aoldaily.com,<br/>mail.aoldaily.com,<br/>webmail.aoldaily.com,<br/>email.aoldaily.com,<br/>info.aoldaily.com,<br/>auto.aoldaily.com,<br/>asdf--auto.aoldaily.com,<br/>asdf--Àu0066auto.aoldaily.com,<br/>asdf25u0027auto.aoldaily.com,<br/>asdfu0027auto.aoldaily.com,<br/>asdf--Àauto.aoldaily.com,<br/>asdf--Àaaaaaauto.aoldaily.com,<br/>asdf--Àfauto.aoldaily.com,<br/>asdfauto.aoldaily.com,<br/>asdfauto.aoldaily.com,<br/>pop.aoldaily.com,<br/>ftp.aoldaily.com,<br/>smtp.aoldaily.com,<br/>ks.aoldaily.com,<br/>stratos.aoldaily.com,<br/>documents.aoldaily.com,<br/>sports.aoldaily.com,<br/>news.aoldaily.com,<br/>tw.aoldaily.com,<br/>www.aoldaily.com,<br/>mx.aoldaily.com | aoldaily.com | -1 |


### email
***
Get a report of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Get a report of an email address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCrowd.Account | String | The email address. | 


#### Command Example
```!email email=william19770319@yahoo.com using=TheatCrowdv2_instance_1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "william19770319@yahoo.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "email",
        "Vendor": "Threat Crowd"
    },
    "EMAIL": {
        "Address": "william19770319@yahoo.com"
    },
    "ThreatCrowd": {
        "Account": {
            "domains": [
                "aoldaily.com",
                "aunewsonline.com",
                "cnndaily.com",
                "usnewssite.com"
            ],
            "permalink": "https://www.threatcrowd.org/email.php?email=william19770319@yahoo.com",
            "references": [],
            "response_code": "1",
            "value": "william19770319@yahoo.com"
        }
    }
}
```

#### Human Readable Output

>### Threat crowd report for Email example@example.com
>|domains|permalink|references|response_code|value|
>|---|---|---|---|---|
>| example.com,<br/> | https://www.threatcrowd.org/email.php?email=example@example.com |  | 1 | example@example.com |


### antivirus
***
Get a report of an antivirus.


#### Base Command

`antivirus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| antivirus | Get a report of an antivirus. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!antivirus antivirus="plugx" using="TheatCrowdv2_instance_1"```

#### Context Example
```json
{
    "ThreatCrowd": {
        "AntiVirus": {
            "hashes": [
                "31d0e421894004393c48de1769744687",
                "5cd3f073caac28f915cf501d00030b31",
                "bbd9acdd758ec2316855306e83dba469",
                "ef9d8cd06de03bd5f07b01c1cce9761f",
                "06bd026c77ce6ab8d85b6ae92bb34034"
            ],
            "permalink": "https://www.threatcrowd.org/listMalware.php?antivirus=plugx",
            "references": [],
            "response_code": "1",
            "value": "plugx"
        }
    }
}
```

#### Human Readable Output

>### Threat crowd report for antivirus plugx
>|hashes|permalink|references|response_code|value|
>|---|---|---|---|---|

>| 31d0e421894004393c48de1769744687,<br/>5cd3f073caac28f915cf501d00030b31,<br/>bbd9acdd758ec2316855306e83dba469,<br/>ef9d8cd06de03bd5f07b01c1cce9761f,<br/>06bd026c77ce6ab8d85b6ae92bb34034 | https://www.threatcrowd.org/listMalware.php?antivirus=plugx |  | 1 | plugx |

### file
***
Get a report of a hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Get a report of a hash. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name \(including file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.SSDeep | String | The ssdeep hash of the file \(same as displayed in file entries\). | 
| File.Extension | String | The file extension, for example: 'xls'. | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| File.Hostname | String | The name of the host where the file was found. Should match Path. | 
| File.Path | String | The path where the file is located. | 
| File.Company | String | The name of the company that released a binary. | 
| File.ProductName | String | The name of the product to which this file belongs. | 
| File.DigitalSignature.Publisher | String | The publisher of the digital signature for the file. | 
| File.Actor | String | The actor reference. | 
| File.Tags | Unknown | \(List\) Tags of the file. | 
| File.FeedRelatedIndicators.value | String | Indicators that are associated with the file. | 
| File.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the file. | 
| File.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the file. | 
| File.MalwareFamily | String | The malware family associated with the file. | 
| File.Signature.Authentihash | String | The authentication hash. | 
| File.Signature.Copyright | String | Copyright information. | 
| File.Signature.Description | String | A description of the signature. | 
| File.Signature.FileVersion | String | The file version. | 
| File.Signature.InternalName | String | The internal name of the file. | 
| File.Signature.OriginalName | String | The original name of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 


#### Command Example
```!file file=ec8c89aa5e521572c74e2dd02a4daf78 using=TheatCrowdv2_instance_1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "ec8c89aa5e521572c74e2dd02a4daf78",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "Threat Crowd"
    },
    "File": {
        "MD5": "ec8c89aa5e521572c74e2dd02a4daf78",
        "SHA1": "01f5c3905f2098650f16f50a1b26156586238bfe"
    },
    "ThreatCrowd": {
        "File": {
            "domains": [
                "ks.aoldaily.com"
            ],
            "ips": [
                "0.0.0.0"
            ],
            "md5": "ec8c89aa5e521572c74e2dd02a4daf78",
            "permalink": "https://www.threatcrowd.org/malware.php?md5=ec8c89aa5e521572c74e2dd02a4daf78",
            "references": [],
            "response_code": "1",
            "scans": [
                "",
                "Trojan/W32.Small.34304.EG",
                "Trojan.Win32.Cossta!O",
                "Trojan ( 001922ff1 )",
                "Trojan ( 001922ff1 )",
                "Trojan.Win32.Cossta.cqvyn",
                "APT1.A",
                "TSPY_COSSTA.DH",
                "WIN.Trojan.Cossta-4",
                "Trojan.Win32.Cossta.grt",
                "Trojan.Cossta!dfgiLGS/u08",
                "Trojan.Win32.A.Cossta.34304.A",
                "UnclassifiedMalware",
                "TR/Offend.4596108",
                "TSPY_COSSTA.DH",
                "Mal/Dloadr-BK",
                "Trojan/Cossta.rg",
                "Trojan/Win32.Cossta",
                "Win32.Troj.Cossta.(kcloud)",
                "Backdoor:Win32/Neunut.A",
                "Trojan/Win32.Cossta",
                "Trojan.Cossta",
                "Trojan.Win32.Cossta.abv",
                "W32/Cossta.WQS!tr",
                "Win32/Trojan.734"
            ],
            "sha1": "01f5c3905f2098650f16f50a1b26156586238bfe",
            "value": "ec8c89aa5e521572c74e2dd02a4daf78"
        }
    }
}
```

#### Human Readable Output

>### Threat crowd report for File ec8c89aa5e521572c74e2dd02a4daf78
>|domains|ips|md5|permalink|references|response_code|scans|sha1|value|
>|---|---|---|---|---|---|---|---|---|
>| ks.aoldaily.com | 0.0.0.0 | ec8c89aa5e521572c74e2dd02a4daf78 | https://www.threatcrowd.org/malware.php?md5=ec8c89aa5e521572c74e2dd02a4daf78 |  | 1 | ,<br/>Trojan/W32.Small.34304.EG,<br/>Trojan.Win32.Cossta!O,<br/>Trojan ( 001922ff1 ),<br/>Trojan ( 001922ff1 ),<br/>Trojan.Win32.Cossta.cqvyn,<br/>APT1.A,<br/>TSPY_COSSTA.DH,<br/>WIN.Trojan.Cossta-4,<br/>Trojan.Win32.Cossta.grt,<br/>Trojan.Cossta!dfgiLGS/u08,<br/>Trojan.Win32.A.Cossta.34304.A,<br/>UnclassifiedMalware,<br/>TR/Offend.4596108,<br/>TSPY_COSSTA.DH,<br/>Mal/Dloadr-BK,<br/>Trojan/Cossta.rg,<br/>Trojan/Win32.Cossta,<br/>Win32.Troj.Cossta.(kcloud),<br/>Backdoor:Win32/Neunut.A,<br/>Trojan/Win32.Cossta,<br/>Trojan.Cossta,<br/>Trojan.Win32.Cossta.abv,<br/>W32/Cossta.WQS!tr,<br/>Win32/Trojan.734 | 01f5c3905f2098650f16f50a1b26156586238bfe | ec8c89aa5e521572c74e2dd02a4daf78 |

