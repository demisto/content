iDefense provides intelligence regarding security threats and vulnerabilities.
This integration was integrated and tested with version v2.58.0 of iDefense
## Configure iDefense v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for iDefense v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| api_token | API Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| use_proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of the given IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address that was checked. | 
| IP.Malicious.Vendor | String | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | String | For malicious IP addresses, the reason the vendor made that decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor that was used to calculate the score. | 
| DBotScore.Score | String | The actual score. | 


#### Command Example
```!ip ip=0.0.0.0```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "0.0.0.0",
        "Score": 2,
        "Type": "ip",
        "Vendor": "iDefense"
    },
    "IP": {
        "Address": "0.0.0.0"
    }
}
```

#### Human Readable Output

>### Results
>|Confidence|DbotReputation|LastPublished|Name|ThreatTypes|TypeOfUse|
>|---|---|---|---|---|---|
>| 0 | 2 | 2018-04-25 14:20:30 | 0.0.0.0 | Cyber Espionage | MALWARE_DOWNLOAD,<br/>MALWARE_C2 |


### domain
***
Checks the reputation of the given domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain that was checked. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason the vendor made that decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!domain domain=example.org```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.org",
        "Score": 2,
        "Type": "domain",
        "Vendor": "iDefense"
    },
    "Domain": {
        "Name": "example.org"
    }
}
```

#### Human Readable Output

>### Results
>|Confidence|DbotReputation|LastPublished|Name|ThreatTypes|TypeOfUse|
>|---|---|---|---|---|---|
>| 50 | 2 | 2019-09-18 15:56:49 | example.org | Cyber Crime | MALWARE_C2 |


### url
***
Checks the reputation of the given URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check (must start with "http://"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL that was checked. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | String | For malicious URLs, the reason the vendor made that decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!url url=http://example.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://example.com",
        "Score": 2,
        "Type": "url",
        "Vendor": "iDefense"
    },
    "URL": {
        "Data": "http://example.com"
    }
}
```

#### Human Readable Output

>### Results
>|Confidence|DbotReputation|LastPublished|Name|ThreatTypes|TypeOfUse|
>|---|---|---|---|---|---|
>| 50 | 2 | 2020-09-16 20:29:35 | http://example.com | Cyber Crime | MALWARE_C2 |


### idefense-get-ioc-by-uuid
***
Get specific indicator reputation


#### Base Command

`idefense-get-ioc-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Unique User ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. | 
| IP.Malicious.Vendor | String | For malicious IPs, the vendor that made the decision. | 
| IP.Malicious.Description | String | For malicious IPs, the reason the vendor made that decision. | 
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason the vendor made that decision. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | String | For malicious URLs, the reason the vendor made that decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!idefense-get-ioc-by-uuid uuid=xxxx```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.org",
        "Score": 2,
        "Type": "domain",
        "Vendor": "iDefense"
    },
    "Domain": {
        "Name": "example.org"
    }
}
```

#### Human Readable Output

>### Results
>|Confidence|DbotReputation|LastPublished|Name|ThreatTypes|TypeOfUse|
>|---|---|---|---|---|---|
>| 0 | 2 | 2017-01-11 20:56:22 | example.org | Cyber Espionage | MALWARE_C2 |

