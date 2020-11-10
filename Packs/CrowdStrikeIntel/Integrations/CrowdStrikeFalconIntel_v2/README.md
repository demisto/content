Threat intelligence service by CrowdStrike focused on delivering a technical feed to help organizations better defend themselves against adversary activity.
This integration was integrated and tested with version xx of CrowdStrike Falcon Intel v2
## Configure CrowdStrike Falcon Intel v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike Falcon Intel v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The server URL to which you want to connect | True |
| credentials | Client ID | True |
| threshold | Indicator Threshold. Minimum malicious confidence from Falcon Intel to consider the indicator malicious.\(low, medium, high\) | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Check file reputation.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of file hashes (MD5/SHA1/SHA256) to check.| Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| FalconIntel.Indicator.ID | String | The indicator ID. | 
| FalconIntel.Indicator.Type | String | The indicator type. | 
| FalconIntel.Indicator.Value | String | The indicator value. | 
| FalconIntel.Indicator.LastUpdate | Date | The last time the indicator was updated. | 
| FalconIntel.Indicator.PublishDate | Date | The time the indicator was published. | 
| FalconIntel.Indicator.MaliciousConfidence | String | The confidence level by which an indicator is considered to be malicious | 
| FalconIntel.Indicator.Reports | String | The report ID that the indicator is associated with | 
| FalconIntel.Indicator.Actors | String | Actors that the indicator is associated | 
| FalconIntel.Indicator.MalwareFamilies | String | A list of malware families that an indicator has been associated. An indicator may be associated with more than one malware family. | 
| FalconIntel.Indicator.KillChains | String | The point in the kill chain at which an indicator is associated | 
| FalconIntel.Indicator.DomainTypes | String | The domain type of domain indicators | 
| FalconIntel.Indicator.IPAddressTypes | String | The address type of ip_address indicators | 
| FalconIntel.Indicator.Relations.Indicator | String | Related Indicators | 
| FalconIntel.Indicator.Type | String | The indicator type | 
| FalconIntel.Indicator.Labels | String | Additional labels | 


#### Command Example
```!file file=sha256_value```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "sha256_value",
        "Score": 3,
        "Type": "file",
        "Vendor": "FalconIntel"
    },
    "FalconIntel": {
        "Indzicator": {
            "Actors": [
                "CIRCUSSPIDER"
            ],
            "ID": "hash_sha256_id",
            "Labels": [
                "CSD/CSA-201011",
                "ThreatType/Criminal",
                "CSD/CSWR-20018",
                "CSD/CSWR-20023",
                "CSD/CSDR-20035",
                "CSD/CSWR-20020",
                "CSD/CSWR-20024",
                "CSD/CSWR-20021",
                "MaliciousConfidence/High",
                "Malware/NetWalker"
            ],
            "MaliciousConfidence": "high",
            "MalwareFamilies": [
                "NetWalker"
            ],
            "Relations": [
                "hash_md5: 0432b62130ca06c04d5a12a5e9841300",
                "hash_sha1: fd2b8fff2c583a1af1b86f150be8f611a2292197"
            ],
            "Reports": [
                "CSA-201011",
                "CSWR-20018",
                "CSWR-20023",
                "CSDR-20035",
                "CSWR-20020",
                "CSWR-20024",
                "CSWR-20021",
                "CSA-200605",
                "CSA-200385",
                "CSDR-20090",
                "CSWR-20017",
                "CSIT-20081",
                "CSWR-20011"
            ],
            "Type": "hash_sha256",
            "Value": "sha256_value"
        }
    },
    "File": {
        "Actors": [
            "CIRCUSSPIDER"
        ],
        "Malicious": {
            "Description": "High confidence",
            "Vendor": "FalconIntel"
        },
        "MalwareFamilies": [
            "NetWalker"
        ],
        "Reports": [
            "CSA-201011",
            "CSWR-20018",
            "CSWR-20023",
            "CSDR-20035",
            "CSWR-20020",
            "CSWR-20024",
            "CSWR-20021",
            "CSA-200605",
            "CSA-200385",
            "CSDR-20090",
            "CSWR-20017",
            "CSIT-20081",
            "CSWR-20011"
        ],
        "SHA256": "sha256_value"
    }
}
```

#### Human Readable Output

>### Falcon Intel file reputation:
>
>|Actors|ID|Labels|Malicious Confidence|Malware Families|Relations|Reports|Type|Value|
>|---|---|---|---|---|---|---|---|---|
>| CIRCUSSPIDER | hash_sha256_sha256_value | CSD/CSA-201011,<br/>ThreatType/Criminal,<br/>CSD/CSWR-20018,<br/>CSD/CSWR-20023,<br/>CSD/CSDR-20035,<br/>CSD/CSWR-20020,<br/>CSD/CSWR-20024,<br/>CSD/CSWR-20021,<br/>MaliciousConfidence/High,<br/>Malware/NetWalker | high | NetWalker | hash_md5: 0432b62130ca06c04d5a12a5e9841300,<br/>hash_sha1: fd2b8fff2c583a1af1b86f150be8f611a2292197 | CSA-201011,<br/>CSWR-20018,<br/>CSWR-20023,<br/>CSDR-20035,<br/>CSWR-20020,<br/>CSWR-20024,<br/>CSWR-20021,<br/>CSA-200605,<br/>CSA-200385,<br/>CSDR-20090,<br/>CSWR-20017,<br/>CSIT-20081,<br/>CSWR-20011 | hash_sha256 | sha256_value |


### url
***
Check the given URL reputation.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to check.| Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| FalconIntel.Indicator.ID | String | The indicator ID. | 
| FalconIntel.Indicator.Type | String | The indicator type. | 
| FalconIntel.Indicator.Value | String | The indicator value. | 
| FalconIntel.Indicator.LastUpdate | Date | The last time the indicator was updated. | 
| FalconIntel.Indicator.PublishDate | Date | The time the indicator was published. | 
| FalconIntel.Indicator.MaliciousConfidence | String | The confidence level by which an indicator is considered to be malicious | 
| FalconIntel.Indicator.Reports | String | The report ID that the indicator is associated with | 
| FalconIntel.Indicator.Actors | String | Actors that the indicator is associated | 
| FalconIntel.Indicator.MalwareFamilies | String | A list of malware families that an indicator has been associated. An indicator may be associated with more than one malware family. | 
| FalconIntel.Indicator.KillChains | String | The point in the kill chain at which an indicator is associated | 
| FalconIntel.Indicator.DomainTypes | String | The domain type of domain indicators | 
| FalconIntel.Indicator.IPAddressTypes | String | The address type of ip_address indicators | 
| FalconIntel.Indicator.Relations.Indicator | String | Related Indicators | 
| FalconIntel.Indicator.Type | String | The indicator type | 
| FalconIntel.Indicator.Labels | String | Additional labels | 


#### Command Example
```!url url=https://withifceale.top/treusparq.php```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "https://withifceale.top/treusparq.php",
        "Score": 3,
        "Type": "url",
        "Vendor": "FalconIntel"
    },
    "FalconIntel": {
        "Indicator": {
            "ID": "url_https://withifceale.top/treusparq.php",
            "KillChains": [
                "C2"
            ],
            "Labels": [
                "CSD/CSA-200342",
                "KillChain/C2",
                "Malware/Zloader",
                "CSD/CSDR-20011",
                "CSD/CSIT-20009",
                "CSD/CSA-191551",
                "MaliciousConfidence/High",
                "ThreatType/Criminal",
                "CSD/CSA-200038",
                "ThreatType/Banking"
            ],
            "MaliciousConfidence": "high",
            "MalwareFamilies": [
                "Zloader"
            ],
            "Relations": [
                "hash_sha256: sha256_value",
                "hash_sha256: sha256_value",
                "hash_sha256: sha256_value",
                "hash_md5: md5_value",
                "hash_md5: md5_value",
                "hash_sha1: sha1_value",
                "hash_sha1: sha1_value",
                "hash_md5: md5_value",
                "hash_sha1: sha1_value",
                "hash_sha1: sha1_value"
            ],
            "Reports": [
                "CSA-200342",
                "CSDR-20011",
                "CSIT-20009",
                "CSA-191551",
                "CSA-200038",
                "CSIT-17112",
                "CSA-200149"
            ],
            "Type": "url",
            "Value": "https://withifceale.top/treusparq.php"
        }
    },
    "URL": {
        "Data": "https://withifceale.top/treusparq.php",
        "KillChains": [
            "C2"
        ],
        "Malicious": {
            "Description": "High confidence",
            "Vendor": "FalconIntel"
        },
        "MalwareFamilies": [
            "Zloader"
        ],
        "Reports": [
            "CSA-200342",
            "CSDR-20011",
            "CSIT-20009",
            "CSA-191551",
            "CSA-200038",
            "CSIT-17112",
            "CSA-200149"
        ]
    }
}
```

#### Human Readable Output

>### Falcon Intel URL reputation:
>
>|ID|Kill Chains|Labels|Malicious Confidence|Malware Families|Relations|Reports|Type|Value|
>|---|---|---|---|---|---|---|---|---|
>| `url_https://withifceale.top/treusparq.php` | C2 | CSD/CSA-200342,<br/>KillChain/C2,<br/>Malware/Zloader,<br/>CSD/CSDR-20011,<br/>CSD/CSIT-20009,<br/>CSD/CSA-191551,<br/>MaliciousConfidence/High,<br/>ThreatType/Criminal,<br/>CSD/CSA-200038,<br/>ThreatType/Banking | high | Zloader | hash_sha256: sha256_value,<br/>hash_sha256: sha256_value,<br/>hash_sha256: sha256_value,<br/>hash_md5: md5_value,<br/>hash_md5: md5_value,<br/>hash_sha1: sha1_value,<br/>hash_sha1: sha1_value,<br/>hash_md5: md5_value,<br/>hash_sha1: sha1_value,<br/>hash_sha1: sha1_value | CSA-200342,<br/>CSDR-20011,<br/>CSIT-20009,<br/>CSA-191551,<br/>CSA-200038,<br/>CSIT-17112,<br/>CSA-200149 | url | `https://withifceale.top/treusparq.php` |


### domain
***
Check the given URL reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-seperated list of domains to check.| Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| FalconIntel.Indicator.ID | String | The indicator ID. | 
| FalconIntel.Indicator.Type | String | The indicator type. | 
| FalconIntel.Indicator.Value | String | The indicator value. | 
| FalconIntel.Indicator.LastUpdate | Date | The last time the indicator was updated. | 
| FalconIntel.Indicator.PublishDate | Date | The time the indicator was published. | 
| FalconIntel.Indicator.MaliciousConfidence | String | The confidence level by which an indicator is considered to be malicious | 
| FalconIntel.Indicator.Reports | String | The report ID that the indicator is associated with | 
| FalconIntel.Indicator.Actors | String | Actors that the indicator is associated | 
| FalconIntel.Indicator.MalwareFamilies | String | A list of malware families that an indicator has been associated. An indicator may be associated with more than one malware family. | 
| FalconIntel.Indicator.KillChains | String | The point in the kill chain at which an indicator is associated | 
| FalconIntel.Indicator.DomainTypes | String | The domain type of domain indicators | 
| FalconIntel.Indicator.IPAddressTypes | String | The address type of ip_address indicators | 
| FalconIntel.Indicator.Relations.Indicator | String | Related Indicators | 
| FalconIntel.Indicator.Type | String | The indicator type | 
| FalconIntel.Indicator.Labels | String | Additional labels | 


#### Command Example
```!domain domain=xeemoquo.top```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "xeemoquo.top",
        "Score": 3,
        "Type": "domain",
        "Vendor": "FalconIntel"
    },
    "Domain": {
        "KillChains": [
            "C2"
        ],
        "Malicious": {
            "Description": "High confidence",
            "Vendor": "FalconIntel"
        },
        "Name": "xeemoquo.top",
        "Reports": [
            "CSA-191551",
            "CSA-200038",
            "CSDR-20011",
            "CSA-200149"
        ]
    },
    "FalconIntel": {
        "Indicator": {
            "ID": "domain_xeemoquo.top",
            "KillChains": [
                "C2"
            ],
            "Labels": [
                "CSD/CSA-191551",
                "CSD/CSA-200038",
                "MaliciousConfidence/High",
                "KillChain/C2",
                "CSD/CSDR-20011",
                "CSD/CSA-200149"
            ],
            "MaliciousConfidence": "high",
            "Relations": [
                "hash_md5: md5_value",
                "hash_sha1: sha1_value",
                "hash_sha1: sha1_value",
                "hash_md5: md5_value",
                "hash_sha1: sha1_value",
                "hash_md5: md5_value",
                "hash_md5: md5_value",
                "hash_sha256: sha256_value",
                "hash_sha256: sha256_value",
                "hash_sha1: sha1_value"
            ],
            "Reports": [
                "CSA-191551",
                "CSA-200038",
                "CSDR-20011",
                "CSA-200149"
            ],
            "Type": "domain",
            "Value": "xeemoquo.top"
        }
    }
}
```

#### Human Readable Output

>### Falcon Intel domain reputation:
>
>|ID|Kill Chains|Labels|Malicious Confidence|Relations|Reports|Type|Value|
>|---|---|---|---|---|---|---|---|
>| domain_xeemoquo.top | C2 | CSD/CSA-191551,<br/>CSD/CSA-200038,<br/>MaliciousConfidence/High,<br/>KillChain/C2,<br/>CSD/CSDR-20011,<br/>CSD/CSA-200149 | high | hash_md5: md5_value,<br/>hash_sha1: sha1_value,<br/>hash_sha1: sha1_value,<br/>hash_md5: md5_value,<br/>hash_sha1: sha1_value,<br/>hash_md5: md5_value,<br/>hash_md5: md5_value,<br/>hash_sha256: sha256_value,<br/>hash_sha256: sha256_value,<br/>hash_sha1: sha1_value | CSA-191551,<br/>CSA-200038,<br/>CSDR-20011,<br/>CSA-200149 | domain | xeemoquo.top |


### ip
***
Check IP reputation.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to check.| Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| FalconIntel.Indicator.ID | String | The indicator ID. | 
| FalconIntel.Indicator.Type | String | The indicator type. | 
| FalconIntel.Indicator.Value | String | The indicator value. | 
| FalconIntel.Indicator.LastUpdate | Date | The last time the indicator was updated. | 
| FalconIntel.Indicator.PublishDate | Date | The time the indicator was published. | 
| FalconIntel.Indicator.MaliciousConfidence | String | The confidence level by which an indicator is considered to be malicious | 
| FalconIntel.Indicator.Reports | String | The report ID that the indicator is associated with | 
| FalconIntel.Indicator.Actors | String | Actors that the indicator is associated | 
| FalconIntel.Indicator.MalwareFamilies | String | A list of malware families that an indicator has been associated. An indicator may be associated with more than one malware family. | 
| FalconIntel.Indicator.KillChains | String | The point in the kill chain at which an indicator is associated | 
| FalconIntel.Indicator.DomainTypes | String | The domain type of domain indicators | 
| FalconIntel.Indicator.IPAddressTypes | String | The address type of ip_address indicators | 
| FalconIntel.Indicator.Relations.Indicator | String | Related Indicators | 
| FalconIntel.Indicator.Type | String | The indicator type | 
| FalconIntel.Indicator.Labels | String | Additional labels | 


#### Command Example
```!ip ip=8.8.8.8```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 3,
        "Type": "ip",
        "Vendor": "FalconIntel"
    },
    "FalconIntel": {
        "Indicator": {
            "Actors": [
                "QUILTEDTIGER"
            ],
            "ID": "ip_address_8.8.8.8",
            "KillChains": [
                "C2"
            ],
            "Labels": [
                "KillChain/C2",
                "Malware/Badnews",
                "Actor/QUILTEDTIGER",
                "ThreatType/Targeted",
                "MitreATTCK/CommandAndControl/StandardApplicationLayerProtocol",
                "MaliciousConfidence/High",
                "MitreATTCK/CommandAndControl/CommonlyUsedPort"
            ],
            "MaliciousConfidence": "high",
            "MalwareFamilies": [
                "Badnews"
            ],
            "Relations": [
                "hash_sha1: sha1_value",
                "hash_sha256: sha256_value",
                "hash_md5: md5_value",
                "hash_md5: md5_value",
                "hash_sha256: sha256_value",
                "hash_sha1: sha1_value",
                "hash_md5: md5_value",
                "hash_sha1: sha1_value",
                "hash_sha256: sha256_value",
                "hash_sha1: sha1_value"
            ],
            "Type": "ip_address",
            "Value": "8.8.8.8"
        }
    },
    "IP": {
        "Actors": [
            "QUILTEDTIGER"
        ],
        "Address": "8.8.8.8",
        "KillChains": [
            "C2"
        ],
        "Malicious": {
            "Description": "High confidence",
            "Vendor": "FalconIntel"
        },
        "MalwareFamilies": [
            "Badnews"
        ]
    }
}
```

#### Human Readable Output

>### Falcon Intel IP reputation:
>
>|Actors|ID|Kill Chains|Labels|Malicious Confidence|Malware Families|Relations|Type|Value|
>|---|---|---|---|---|---|---|---|---|
>| QUILTEDTIGER | ip_address_8.8.8.8 | C2 | KillChain/C2,<br/>Malware/Badnews,<br/>Actor/QUILTEDTIGER,<br/>ThreatType/Targeted,<br/>MitreATTCK/CommandAndControl/StandardApplicationLayerProtocol,<br/>MaliciousConfidence/High,<br/>MitreATTCK/CommandAndControl/CommonlyUsedPort | high | Badnews | hash_sha1: sha1_value,<br/>hash_sha256: sha256_value,<br/>hash_md5: md5_value,<br/>hash_md5: md5_value,<br/>hash_sha256: sha256_value,<br/>hash_sha1: sha1_value,<br/>hash_md5: md5_value,<br/>hash_sha1: sha1_value,<br/>hash_sha256: sha256_value,<br/>hash_sha1: sha1_value | ip_address | 8.8.8.8 |


### cs-actors
***
Search known actors based on the given parameters.


#### Base Command

`cs-actors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search based on a query written in FQL (Falcon Query Language, [See https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql](See https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql) for more information). | Optional | 
| free_search | Search across all fields in an Actor object. | Optional | 
| name | Search based on actor name. | Optional | 
| description | Search based on description. | Optional | 
| created_date | Search range from created date. Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| max_last_modified_date | Search range to modified date. Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| min_last_activity_date | Search range from activity date. Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| max_last_activity_date | Search range to activity date. Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| origins | Search by origins separated by ",". | Optional | 
| target_countries | Search by target countries separated by ",". | Optional | 
| target_industries | Search by target industries separated by ",". | Optional | 
| motivations | Search by motivations separated by ",". | Optional | 
| offset | Which page of the results to retrieve. It is 0 based. | Optional | 
| limit | The maximum number of actors to retrieve. The default is 10. | Optional | 
| sort | Sort by field and direction. | Optional | 
| slug | Search by 'slug' or short descriptive name. Ex: "anchor-panda" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FalconIntel.Actor.ImageURL | String | The URL of the actor image | 
| FalconIntel.Actor.Name | String | The actor name. | 
| FalconIntel.Actor.ID | String | The actor ID. | 
| FalconIntel.Actor.URL | String | The url of the actor | 
| FalconIntel.Actor.Slug | String | Slug name ofactor | 
| FalconIntel.Actor.ShortDescription | String | The actor short description. | 
| FalconIntel.Actor.FirstActivityDate | Date | The actor first activity date. | 
| FalconIntel.Actor.LastActivityDate | Date | The actor last activity date. | 
| FalconIntel.Actor.Active | Boolean | The actor active status. | 
| FalconIntel.Actor.KnowsAs | String | Nicknames the actor is known as. | 
| FalconIntel.Actor.TargetIndustries | String | A list of targeted industries associated with this actor | 
| FalconIntel.Actor.TargetCountries | String | A list of targeted countries associated with this actor | 
| FalconIntel.Actor.Origins | String | The actor's country of origin. Ex: Afghanistan | 
| FalconIntel.Actor.Motivations | String | The actor's motivations. Ex: Criminal | 
| FalconIntel.Actor.Capability | String | The actor's capability. Ex: Average | 
| FalconIntel.Actor.Group | String | The actor's group. Ex: panda gang | 
| FalconIntel.Actor.Region | String | The actor's region. Ex: Eastern Europe | 
| FalconIntel.Actor.KillChains | String | Kill chain fields. | 


#### Command Example
```!cs-actors limit=1 target_industries="Entertainment,Healthcare"```

#### Context Example
```
{
    "FalconIntel": {
        "Actor": {
            "Active": false,
            "Capability": "Average",
            "FirstActivityDate": "2019-05-01T00:00:00.000Z",
            "ID": 76078,
            "KnownAs": "Maze Team",
            "LastActivityDate": "2020-09-01T00:00:00.000Z",
            "Motivations": [
                "Criminal"
            ],
            "Name": "TWISTED SPIDER",
            "Origins": [
                "Eastern Europe",
                "Russian Federation"
            ],
            "ShortDescription": "TWISTED SPIDER is the criminal group behind the development and operation of Maze ransomware. While the ransomware was first observed in May 2019, the group gained notoriety in November 2019 with their brazen attitude toward victims and their willingness to speak with security researchers as they began using Big Game Hunting (BGH) tactics to target organizations and businesses. While other actors ...",
            "Slug": "twisted-spider",
            "TargetCountries": [
                "Algeria",
                "Argentina",
                "Australia",
                "Austria",
                "Belgium",
                "Brazil",
                "Canada",
                "China",
                "Colombia",
                "Costa Rica",
                "Czech Republic",
                "Egypt",
                "France",
                "Germany",
                "Hong Kong",
                "India",
                "Italy",
                "Japan",
                "Luxembourg",
                "Macedonia",
                "Netherlands",
                "Nigeria",
                "North America",
                "Norway",
                "Oman",
                "Puerto Rico",
                "Saudi Arabia",
                "Singapore",
                "South Africa",
                "South Korea",
                "Spain",
                "Sri Lanka",
                "Switzerland",
                "Thailand",
                "United Arab Emirates",
                "United Kingdom",
                "United States",
                "Vietnam"
            ],
            "TargetIndustries": [
                "Academic",
                "Agriculture",
                "Automotive",
                "Aviation",
                "Biomedical",
                "Chemicals",
                "Consulting & Professional Services",
                "Consumer Goods",
                "Energy",
                "Entertainment",
                "Financial Management & Hedge Funds",
                "Financial Services",
                "Food and Beverage",
                "Government",
                "Healthcare",
                "Hospitality",
                "Industrials and Engineering",
                "Insurance",
                "Legal",
                "Logistics",
                "Manufacturing",
                "Media",
                "NGOs and Nonprofits",
                "Oil and Gas",
                "Opportunistic",
                "Pharmaceuticals",
                "Real Estate",
                "Retail",
                "State & Municipal Government",
                "Technology",
                "Telecommunications",
                "Transportation",
                "Travel",
                "Utilities"
            ],
            "URL": "https://falcon.crowdstrike.com/intelligence/actors/twisted-spider/"
        }
    }
}
```

#### Human Readable Output

>### Falcon Intel Actor search:
>|Active|Capability|First Activity Date|ID|Known As|Last Activity Date|Motivations|Name|Origins|Short Description|Slug|Target Countries|Target Industries|URL|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | Average | 2019-05-01T00:00:00.000Z | 76078 | Maze Team | 2020-09-01T00:00:00.000Z | Criminal | TWISTED SPIDER | Eastern Europe,<br/>Russian Federation | TWISTED SPIDER is the criminal group behind the development and operation of Maze ransomware. While the ransomware was first observed in May 2019, the group gained notoriety in November 2019 with their brazen attitude toward victims and their willingness to speak with security researchers as they began using Big Game Hunting (BGH) tactics to target organizations and businesses. While other actors ... | twisted-spider | Algeria,<br/>Argentina,<br/>Australia,<br/>Austria,<br/>Belgium,<br/>Brazil,<br/>Canada,<br/>China,<br/>Colombia,<br/>Costa Rica,<br/>Czech Republic,<br/>Egypt,<br/>France,<br/>Germany,<br/>Hong Kong,<br/>India,<br/>Italy,<br/>Japan,<br/>Luxembourg,<br/>Macedonia,<br/>Netherlands,<br/>Nigeria,<br/>North America,<br/>Norway,<br/>Oman,<br/>Puerto Rico,<br/>Saudi Arabia,<br/>Singapore,<br/>South Africa,<br/>South Korea,<br/>Spain,<br/>Sri Lanka,<br/>Switzerland,<br/>Thailand,<br/>United Arab Emirates,<br/>United Kingdom,<br/>United States,<br/>Vietnam | Academic,<br/>Agriculture,<br/>Automotive,<br/>Aviation,<br/>Biomedical,<br/>Chemicals,<br/>Consulting & Professional Services,<br/>Consumer Goods,<br/>Energy,<br/>Entertainment,<br/>Financial Management & Hedge Funds,<br/>Financial Services,<br/>Food and Beverage,<br/>Government,<br/>Healthcare,<br/>Hospitality,<br/>Industrials and Engineering,<br/>Insurance,<br/>Legal,<br/>Logistics,<br/>Manufacturing,<br/>Media,<br/>NGOs and Nonprofits,<br/>Oil and Gas,<br/>Opportunistic,<br/>Pharmaceuticals,<br/>Real Estate,<br/>Retail,<br/>State & Municipal Government,<br/>Technology,<br/>Telecommunications,<br/>Transportation,<br/>Travel,<br/>Utilities | https://falcon.crowdstrike.com/intelligence/actors/twisted-spider/ |


### cs-indicators
***
Search known indicators based on the given parameters.


#### Base Command

`cs-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search based on a query written in FQL (Falcon Query Language, See [https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql](See https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql) for more information). | Optional | 
| type | The indicator type. | Optional | 
| malicious_confidence | Indicates a confidence level by which an indicator is considered to be malicious. | Optional | 
| offset | Used to paginate the response. You can then use limit to set the number of results for the next page. | Optional | 
| last_updated | The date the indicator was last updated.Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| indicator | The value for the given indicator type. | Optional | 
| sort | Sort by field and direction. | Optional | 
| id | The indicator's ID, in the following format &lt;type&gt;_&lt;indicator&gt;. | Optional | 
| limit | The maximum number of indicators to retrieve. The default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.Reports | String | For malicious files, the associated reports describing the hash | 
| File.Actors | String | For malicious files, the associated actors | 
| File.MalwareFamilies | String | For malicious files, the associated malware family | 
| File.KillChains | String | For malicious files, the associated kill chain | 
| URL.Data | String | The URL | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| URL.Reports | String | For malicious URL, the associated reports describing the URL | 
| URL.Actors | String | For malicious URL, the associated actors | 
| URL.MalwareFamilies | String | For malicious URL, the associated malware family | 
| URL.KillChains | String | For malicious URL, the associated kill chain | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Reports | String | For malicious domain, the associated reports describing the domain | 
| Domain.Actors | String | For malicious domain, the associated actors | 
| Domain.MalwareFamilies | String | For malicious domain, the associated malware family | 
| Domain.KillChains | String | For malicious domain, the associated kill chain | 
| IP.Address | String | IP address | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Reports | String | For malicious IP, the associated reports describing the IP | 
| IP.Actors | String | For malicious IP, the associated actors | 
| IP.MalwareFamilies | String | For malicious IP, the associated malware family | 
| IP.KillChains | String | For malicious IP, the associated kill chain | 
| DBotScore.Indicator | String | The indicator we tested | 
| DBotScore.Type | String | The type of the indicator | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| FalconIntel.Indicator.ID | String | The indicator ID. | 
| FalconIntel.Indicator.Type | String | The indicator type. | 
| FalconIntel.Indicator.Value | String | The indicator value. | 
| FalconIntel.Indicator.LastUpdate | Date | The last time the indicator was updated. | 
| FalconIntel.Indicator.PublishDate | Date | The time the indicator was published. | 
| FalconIntel.Indicator.MaliciousConfidence | String | The confidence level by which an indicator is considered to be malicious | 
| FalconIntel.Indicator.Reports | String | The report ID that the indicator is associated with | 
| FalconIntel.Indicator.Actors | String | Actors that the indicator is associated | 
| FalconIntel.Indicator.MalwareFamilies | String | A list of malware families that an indicator has been associated. An indicator may be associated with more than one malware family. | 
| FalconIntel.Indicator.KillChains | String | The point in the kill chain at which an indicator is associated | 
| FalconIntel.Indicator.DomainTypes | String | The domain type of domain indicators | 
| FalconIntel.Indicator.IPAddressTypes | String | The address type of ip_address indicators | 
| FalconIntel.Indicator.Relations.Indicator | String | Related Indicators | 
| FalconIntel.Indicator.Type | String | The indicator type | 
| FalconIntel.Indicator.Labels | String | Additional labels | 


#### Command Example
```!cs-indicators limit=1 type=ip_address malicious_confidence=high ```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 3,
        "Type": "ip",
        "Vendor": "FalconIntel"
    },
    "FalconIntel": {
        "Indicator": {
            "ID": "ip_address_id",
            "KillChains": [
                "C2"
            ],
            "Labels": [
                "CSD/CSA-191023",
                "CSD/CSA-191350",
                "CSD/CSA-181072",
                "CSD/CSWR-17018",
                "CSD/CSWR-20022",
                "CSD/CSWR-19024",
                "MaliciousConfidence/High",
                "KillChain/C2",
                "CSD/CSIT-16091",
                "ThreatType/Commodity"
            ],
            "MaliciousConfidence": "high",
            "MalwareFamilies": [
                "njRAT"
            ],
            "Reports": [
                "CSA-191023",
                "CSA-191350",
                "CSA-181072",
                "CSWR-17018",
                "CSWR-20022",
                "CSWR-19024",
                "CSIT-16091",
                "CSA-201008",
                "CSWR-20014"
            ],
            "Type": "ip_address",
            "Value": "8.8.8.8"
        }
    },
    "IP": {
        "Address": "8.8.8.8",
        "KillChains": [
            "C2"
        ],
        "Malicious": {
            "Description": "High confidence",
            "Vendor": "FalconIntel"
        },
        "MalwareFamilies": [
            "njRAT"
        ],
        "Reports": [
            "CSA-191023",
            "CSA-191350",
            "CSA-181072",
            "CSWR-17018",
            "CSWR-20022",
            "CSWR-19024",
            "CSIT-16091",
            "CSA-201008",
            "CSWR-20014"
        ]
    }
}
```

#### Human Readable Output

>### Falcon Intel Indicator search:
>|ID|Kill Chains|Labels|Malicious Confidence|Malware Families|Reports|Type|Value|
>|---|---|---|---|---|---|---|---|
>| ip_address_id | C2 | CSD/CSA-191023,<br/>CSD/CSA-191350,<br/>CSD/CSA-181072,<br/>CSD/CSWR-17018,<br/>CSD/CSWR-20022,<br/>CSD/CSWR-19024,<br/>MaliciousConfidence/High,<br/>KillChain/C2,<br/>CSD/CSIT-16091,<br/>ThreatType/Commodity | high | njRAT | CSA-191023,<br/>CSA-191350,<br/>CSA-181072,<br/>CSWR-17018,<br/>CSWR-20022,<br/>CSWR-19024,<br/>CSIT-16091,<br/>CSA-201008,<br/>CSWR-20014 | ip_address | 8.8.8.8 |


### cs-reports
***
The Falcon Intel Reports API allows to query CrowdStrike intelligence publications.


#### Base Command

`cs-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search based on a query written in FQL (Falcon Query Language, See [https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql](See https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql) for more information). | Optional | 
| free_search | Search across all fields in an Report object. | Optional | 
| name | Search for keywords across report names (i.e. the report’s title). | Optional | 
| actors | Search for a report related to a particular actors. Actors should be comma separated. - For example - actor1,actor2,... | Optional | 
| target_countries | Search reports by targeted country/countries | Optional | 
| target_industries | Search reports by targeted industry/industries | Optional | 
| motivations | Search by motivation | Optional | 
| slug | Search by report 'slug' or short descriptive name | Optional | 
| description | Search the body of the report | Optional | 
| type | The type of object to search for. | Optional | 
| sub_type | The sub-type to search for. | Optional | 
| tags | Tags associated with a report (managed internally by CS). | Optional | 
| created_date | Constrain results to those created on a certain date. Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| max_last_modified_date | Constrain results to those modified on or before a certain date. Supported formats: ISO 8601 (for example, 2020-07-28T10:00:00Z) and time period (for example, 24 hours). | Optional | 
| offset | Used to paginate the response. You can then use limit to set the number of results for the next page. | Optional | 
| limit | The maximum number of reports to retrieve. The default is 10. | Optional | 
| sort | Sort by field and direction. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FalconIntel.Report.ID | String | The report ID. | 
| FalconIntel.Report.URL | String | The report URL. | 
| FalconIntel.Report.Name | String | The report name. | 
| FalconIntel.Report.Type | String | The report type. | 
| FalconIntel.Report.SubType | String | The report sub type. | 
| FalconIntel.Report.Slug | String | Slug name of the report | 
| FalconIntel.Report.CreatedDate | Date | The date the report was created. | 
| FalconIntel.Report.LastModifiedSate | Date | The date the report was last modified. | 
| FalconIntel.Report.ShortDescription | String | The report short description. | 
| FalconIntel.Report.TargetIndustries | String | Targeted industries included in the report. Ex: aerospace | 
| FalconIntel.Report.TargetCountries | String | Targeted countries included in the report. Ex: afghanistan | 
| FalconIntel.Report.Motivations | String | Motivations included in the report. Ex: criminal | 
| FalconIntel.Report.Tags | String | The report's tags. Ex: intel_feed | 


#### Command Example
```!cs-reports limit=1 created_date="2016-09-30T19:15:53.000Z"```

#### Context Example
```
{
    "FalconIntel": {
        "Report": {
            "CreatedDate": "2016-09-30T19:15:53.000Z",
            "ID": 7448,
            "LastModifiedSate": "2020-07-24T10:15:02.000Z",
            "Name": "Snort Changelog",
            "ShortDescription": "Added one additional rule to detect Hancitor malware traffic decsribed in CSIT-16107. ",
            "Slug": "slug_value",
            "SubType": "Snort/Suricata",
            "Type": "Feeds",
            "URL": "https://falcon.crowdstrike.com/intelligence/reports/snort-changelog-9-5-2016-6/"
        }
    }
}
```

#### Human Readable Output

>### Falcon Intel Report search:
>|Created Date|ID|Last Modified Sate|Name|Short Description|Slug|Sub Type|Type|URL|
>|---|---|---|---|---|---|---|---|---|
>| 2016-09-30T19:15:53.000Z | 7448 | 2020-07-24T10:15:02.000Z | Snort Changelog | Added one additional rule to detect Hancitor malware traffic decsribed in CSIT-16107.  | snort-changelog-9-5-2016-6 | Snort/Suricata | Feeds | https://falcon.crowdstrike.com/intelligence/reports/snort-changelog-9-5-2016-6/ |

