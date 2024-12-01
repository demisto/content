Query Threat Crowd for reports.
This integration was integrated and tested with version v2 of ThreatCrowd
## Configure ThreatCrowd v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Max Number of Entries | How many entries to fetch. For full data use -1. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| limit | Maximum number of results to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| ThreatCrowd.IP.hashes | String | Hashes related to the ip. | 
| ThreatCrowd.IP.permalink | String | The link to ip in the product. | 
| ThreatCrowd.IP.references | String | References related to the ip. | 
| ThreatCrowd.IP.resolutions | String | Resolutions related to the ip. | 
| ThreatCrowd.IP.value | String | The ip value. | 
| ThreatCrowd.IP.votes | Number | The votes given to the ip. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 


#### Command Example
```!ip ip="x.x.x.x"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "x.x.x.x",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Threat Crowd"
    },
    "IP": {
        "Address": "x.x.x.x",
        "Malicious": {
            "Description": null,
            "Vendor": "Threat Crowd"
        }
    },
    "ThreatCrowd": {
        "IP": {
            "hashes": [
                "06d40abb65ee157ff2574df8d24743f1",
                "16e0a5aa50917ecadc0c2a7726e72ad0",
                "1e77eaba33333c91adfa28e97558677a",
                "210b6e761b4cb7d71e862606c0f28846",
                "226751fb62f99ff5a2c948dea15319df",
                "23ad6fc6ddb25a0974b90d9ec2df7757",
                "2f80660b47db546c6907edd95868b901",
                "36e6f6f725c77e505ccb466069c41c15",
                "3e06f3e3f4da7ea914bbd42bd17c7aef",
                "4d8d5d96caa717c92fea5ac2b1d6ae23"
            ],
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
            "votes": -1
        }
    }
}
```

#### Human Readable Output

>### Threat crowd report for ip x.x.x.x: 
>  ### DBotScore: BAD 
>### Resolutions
>|domain|last_resolved|
>|---|---|
>| example.example.net | 2018-08-05 |
>| www.example.com | 2020-01-11 |
> 
> ### Hashes
>|Hashes|
>|---|
>| 16e0a5aa50917ecadc0c2a7726e72ad0 |
>| 1e77eaba33333c91adfa28e97558677a |
>| 210b6e761b4cb7d71e862606c0f28846 |
>| 226751fb62f99ff5a2c948dea15319df |
>| 23ad6fc6ddb25a0974b90d9ec2df7757 |
>| 2f80660b47db546c6907edd95868b901 |
>| 36e6f6f725c77e505ccb466069c41c15 |
>| 3e06f3e3f4da7ea914bbd42bd17c7aef |
>| 4d8d5d96caa717c92fea5ac2b1d6ae23 |
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
| limit | Maximum number of results to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| ThreatCrowd.Domain.hashes | String | Hashes related to the domain. | 
| ThreatCrowd.Domain.permalink | String | A link to domain search in the product. | 
| ThreatCrowd.Domain.references | String | References related to the domain. | 
| ThreatCrowd.Domain.resolutions | String | Resolutions related to the domain. | 
| ThreatCrowd.Domain.subdomains | String | The subdomains related to the domain. |
| ThreatCrowd.Domain.emails | String | The emails related to the domain. | 
| ThreatCrowd.Domain.value | String | The name of the domain. | 
| ThreatCrowd.Domain.votes | Number | The votes given to the domain. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 


#### Command Example
```!domain domain="example.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
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

>### Threat crowd report for domain example.com 
> ### DBotScore: BAD 
>### Resolutions
>|ip_address|last_resolved|
>|---|---|
>| x.x.x.x | 2014-04-01 |
>| x.x.x.x | 2020-07-22 |
>| x.x.x.x | 2021-03-05 |
>| x.x.x.x | 2020-10-18 |
> 
> ### Subdomains
>|subdomains|
>|---|
>| example.example.com |

> 
>###  
>|emails|permalink|references|response_code|value|votes|
>|---|---|---|---|---|---|
>| domains@example.info,<br/>example@example.com |  | https://www.threatcrowd.org/domain.php?domain=example.com | example.example | 1 | example.com | -1 |


### email
***
Get a report of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address for which to retrieve a report. | Required | 
| limit | Maximum number of results to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCrowd.Account.value | String | The email address. | 
| ThreatCrowd.Account.domains | String | The domains related to the email address. | 
| ThreatCrowd.Account.permalink | String | The Link to the email address in the product. | 
| ThreatCrowd.Account.references | String | The refernces related to the email address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 


#### Command Example
```!email email=example@example.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example@example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "email",
        "Vendor": "Threat Crowd"
    },
    "Email": {
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

>Threat crowd report for Email example@example.com 
> DBotScore: None 
> ### Results
>|domains|permalink|response_code|value|
>|---|---|---|---|
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
| limit | Maximum number of results to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCrowd.AntiVirus.hashes | String | The hashes related to the antivirus | 
| ThreatCrowd.AntiVirus.permalink | String | The link to the antivitrus in the product | 
| ThreatCrowd.AntiVirus.references | Unknown | The references of the antivirus. | 
| ThreatCrowd.AntiVirus.value | String | The name of the antivirus | 


#### Command Example
```!threat-crowd-antivirus antivirus="plugx" using=ThreatCrowdv2_instance_1```

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
                "06bd026c77ce6ab8d85b6ae92bb34034",
                "2af64ba808c79dccd2c1d84f010b22d7",
                "47a311084bffddf6c00b4eb947b4086b",
                "4c5e55c2ce6e9176970aeecf9533cdbf",
                "4f92b6c9c55142ee562e8237ce1436a2",
                "876f24c4102a4e911ab77ee328643dd2"
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
>|hashes|permalink|response_code|value|
>|---|---|---|---|
>| 31d0e421894004393c48de1769744687,<br/>5cd3f073caac28f915cf501d00030b31,<br/>bbd9acdd758ec2316855306e83dba469,<br/>ef9d8cd06de03bd5f07b01c1cce9761f,<br/>06bd026c77ce6ab8d85b6ae92bb34034,<br/>2af64ba808c79dccd2c1d84f010b22d7,<br/>47a311084bffddf6c00b4eb947b4086b,<br/>4c5e55c2ce6e9176970aeecf9533cdbf,<br/>4f92b6c9c55142ee562e8237ce1436a2,<br/>876f24c4102a4e911ab77ee328643dd2 | https://www.threatcrowd.org/listMalware.php?antivirus=plugx | 1 | plugx |


### file
***
Get a report of a hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The hash for which to retrieve a report. | Required | 
| limit | Maximum number of results to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| ThreatCrowd.File.sha1 | String | The SHA1 hash of the file. | 
| ThreatCrowd.File.references | String | The refernces related to the file. | 
| ThreatCrowd.File.permalink | String | The link to the file in the product. | 
| ThreatCrowd.File.ips | String | The ips related to the file. | 
| ThreatCrowd.File.domains | String | The domains related to the file. | 
| ThreatCrowd.File.value | String | The file identifier. | 
| ThreatCrowd.File.scans | String | The scans related to thefile. | 
| ThreatCrowd.File.md5 | String | The MD5 of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 


#### Command Example
```!file file=31d0e421894004393c48de1769744687 using=ThreatCrowdv2_instance_1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "31d0e421894004393c48de1769744687",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "Threat Crowd"
    },
    "File": {
        "MD5": "31d0e421894004393c48de1769744687",
        "SHA1": "4f0eb746d81a616fb9bdff058997ef47a4209a76"
    },
    "ThreatCrowd": {
        "File": {
            "domains": [
                "hpservice.homepc.it",
                "facebook.controlliamo.com"
            ],
            "ips": [
                "8.8.8.8"
            ],
            "md5": "31d0e421894004393c48de1769744687",
            "permalink": "https://www.threatcrowd.org/malware.php?md5=31d0e421894004393c48de1769744687",
            "references": [],
            "response_code": "1",
            "scans": [
                "Error Scanning File",
                "Malware-gen*Win32*Malware-gen",
                "Gen*Variant.Symmi.50061",
                "W32/Trojan.VSQD-1927",
                "BDS/Plugx.266990",
                "Gen*Variant.Symmi.50061",
                "Gen*Variant.Symmi.50061",
                "Win32/Korplug.CF",
                "W32/FakeAV.CX",
                "Generic11_c.CDQL"
            ],
            "sha1": "4f0eb746d81a616fb9bdff058997ef47a4209a76",
            "value": "31d0e421894004393c48de1769744687"
        }
    }
}
```

#### Human Readable Output

>Threat crowd report for File 31d0e421894004393c48de1769744687: 
> ### DBotScore: None 
> ### Results
>|domains|ips|md5|permalink|references|response_code|scans|sha1|value|
>|---|---|---|---|---|---|---|---|---|
>| hpservice.homepc.it,facebook.controlliamo.com | 8.8.8.8 | 31d0e421894004393c48de1769744687 | https://www.threatcrowd.org/malware.php?md5=31d0e421894004393c48de1769744687 |  | 1 | Error Scanning File,Malware-gen*Win32*Malware-gen,Gen*Variant.Symmi.50061,W32/Trojan.VSQD-1927,BDS/Plugx.266990,Gen*Variant.Symmi.50061,Gen*Variant.Symmi.50061,Win32/Korplug.CF,W32/FakeAV.CX,Generic11_c.CDQL | 4f0eb746d81a616fb9bdff058997ef47a4209a76 | 31d0e421894004393c48de1769744687 |