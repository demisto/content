Query Threat Crowd for reports.
This integration was integrated and tested with version v2 of TheatCrowdv2
## Configure ThreatCrowd on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatCrowdv2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Use Extended Data | Whether to get full Resolution section. If disabled only 10 most recent entries will be fetched. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Get a report of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | An IP address for which to retrieve a report. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Tags | Unknown | \(List\) Tags of the IP address. | 
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP address. | 
| IP.MalwareFamily | String | The malware family associated with the IP address. | 
| IP.Organization.Name | String | The organization of the IP address. | 
| IP.Organization.Type | String | The organization type of the IP address. | 


#### Command Example
```!ip ip="x.x.x.x"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "x.x.x.x",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "Threat Crowd"
    },
    "IP": {
        "Address": "x.x.x.x"
    },
    "ThreatCrowd": {
        "IP": {
            "hashes": [],
            "permalink": "https://www.threatcrowd.org/ip.php?ip=x.x.x.x",
            "references": [],
            "resolutions": [
                {
                    "domain": "example.example.net",
                    "last_resolved": "2018-08-05"
                },
                {
                    "domain": "www.example.com",
                    "last_resolved": "2020-01-11"
                }
            ],
            "response_code": "1",
            "value": "x.x.x.x",
            "votes": 0
        }
    }
}
```

#### Human Readable Output

>Threat crowd report for ip x.x.x.x: 
>### Resolutions
>|domain|last_resolved|
>|---|---|
>| example.example.net | 2018-08-05 |
>| www.example.com | 2020-01-11 |

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
| domain | The domain for which to retrieve a report. | Required | 


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
| Domain.Tags | String | \(List\) Tags of the domain. | 
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
| Domain.WHOIS/History | String | List of Whois objects. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 


#### Command Example
```!domain domain="example.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.com",
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
        "Name": "example.com"
    },
    "ThreatCrowd": {
        "Domain": {
            "emails": [
                "domains@example.com",
                "example@example.com"
            ],
            "hashes": [],
            "permalink": "https://www.threatcrowd.org/domain.php?domain=example.com",
            "references": [
                "example.example.example"
            ],
            "response_code": "1",
            "subdomains": [
                "media.example.com",
                "e.example.com",
                "finance.example.com"
            ],
            "value": "example.com",
            "votes": -1
        }
    }
}
```

#### Human Readable Output

>Threat crowd report for domain example.com 
>### Resolutions
>|ip_address|last_resolved|
>|---|---|
>| - | 2017-11-09 |
>| x.x.x.x | 2014-04-01 |
>| x.x.x.x | 2020-07-22 |
>| x.x.x.x | 2021-03-05 |
>| x.x.x.x | 2020-10-18 |
>### 
>
>|emails|hashes|permalink|references|response_code|subdomains|value|votes|
>|---|---|---|---|---|---|---|---|
>| domains@example.info,<br/>example@example.com |  | https://www.threatcrowd.org/domain.php?domain=example.com | example.example | 1 | example.example.com,<br/>e.example.com | example.com | -1 |


### email
***
Get a report of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address for which to retrieve a report. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCrowd.Account | String | The email address. | 


#### Command Example
```!email email=example@example.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example@example.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "email",
        "Vendor": "Threat Crowd"
    },
    "EMAIL": {
        "Address": "example@example.com"
    },
    "ThreatCrowd": {
        "Account": {
            "domains": [
                "example.com",
                "example2.com",
                "example3.com",
            ],
            "permalink": "https://www.threatcrowd.org/email.php?email=example@example.com",
            "references": [],
            "response_code": "1",
            "value": "example@example.com"
        }
    }
}
```

#### Human Readable Output

>### Threat crowd report for Email example@example.com
>|domains|permalink|references|response_code|value|
>|---|---|---|---|---|
>| example.com,<br/> | https://www.threatcrowd.org/email.php?email=example@example.com |  | 1 | example@example.com |


### threat-crowd-antivirus
***
Get a report of an antivirus.


#### Base Command

`threat-crowd-antivirus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| antivirus | The antivirus for which to retrieve a report. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threat-crowd-antivirus antivirus="example"```

#### Context Example
```json
{
    "ThreatCrowd": {
        "AntiVirus": {
            "hashes": [
                "hash_example",
                "hash_example_2"
            ],
            "permalink": "https://www.threatcrowd.org/listMalware.php?antivirus=example",
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
| file | The hash for which to retrieve a report. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name \(including file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
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
```!file file=hash_example```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "hash_example",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "Threat Crowd"
    },
    "File": {
        "MD5": "hash_example",
        "SHA1": "hash_example_sha1"
    },
    "ThreatCrowd": {
        "File": {
            "domains": [
                "example.com"
            ],
            "ips": [
                "x.x.x.x"
            ],
            "md5": "hash_example",
            "permalink": "https://www.threatcrowd.org/malware.php?md5=hash_example",
            "references": [],
            "response_code": "1",
            "scans": [
                "",
                "Trojan/W32.Small.34304.EG",
                "Trojan.Win32.Cossta!O"
            ],
            "sha1": "hash_example_sha1",
            "value": "hash_example"
        }
    }
}
```

#### Human Readable Output

>### Threat crowd report for File hash_example
>|domains|ips|md5|permalink|references|response_code|scans|sha1|value|
>|---|---|---|---|---|---|---|---|---|
>| example.com | x.x.x.x | hash_example | https://www.threatcrowd.org/malware.php?md5=hash_example |  | 1 | ,<br/>Trojan/W32.Small.34304.EG,<br/>Trojan.Win32.Cossta!O | hash_example_sha1 | hash_example |
