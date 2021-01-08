Unique threat intel technology that automatically serves up relevant insights in real time.
This integration was integrated and tested with version 1.0 of Recorded Future v2
## Configure Recorded Future v2 on Cortex XSOAR

## Information
A valid API Token for XSOAR from Recorded Future needed to fetch information.
[Get help with Recorded Future for Cortex XSOAR](https://www.recordedfuture.com/support/demisto-integration/).

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Recorded Future v2.
3. Click **Add instance** to create and configure a new integration instance.

---

## Configuration
| Parameter                        | Description                                                       |
|----------------------------------|-------------------------------------------------------------------|
| Server URL                       | The URL to the Recorded Future ConnectAPI                         |
| API Token                        | Valid API Token from Recorded Future                              |
| File/IP/Domain/URL/CVE Threshold | Minimum risk score from Recorded Future needed to mark IOC as malicious when doing reputation or intelligence lookup |
| unsecure                         | Trust any certificate \(unsecure\)                                |
| proxy                            | Use system proxy settings                                         |


4. Click **Test** to validate the URLs, token, and connection.

Several of the outputs below have been reduced in size to improve readability.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Get a quick indicator of the risk associated with a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to get the reputation of | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| Domain.Malicious.Vendor | string | For malicious Domains, the vendor that made the decision | 
| Domain.Malicious.Description | string | For malicious Domains, the reason that the vendor made the decision | 
| Domain.Name | string | Domain name | 
| RecordedFuture.Domain.riskScore | number | Recorded Future Domain Risk Score | 
| RecordedFuture.Domain.riskLevel | string | Recorded Future Domain Risk Level | 
| RecordedFuture.Domain.Evidence.rule | string | Recorded Risk Rule Name | 
| RecordedFuture.Domain.Evidence.mitigation | string | Recorded Risk Rule Mitigation | 
| RecordedFuture.Domain.Evidence.description | string | Recorded Risk Rule description | 
| RecordedFuture.Domain.Evidence.timestamp | date | Recorded Risk Rule timestamp | 
| RecordedFuture.Domain.Evidence.level | number | Recorded Risk Rule Level | 
| RecordedFuture.Domain.Evidence.ruleid | string | Recorded Risk Rule ID | 
| RecordedFuture.Domain.name | string | Domain name | 
| RecordedFuture.Domain.maxRules | number | Maximum count of Recorded Future Domain Risk Rules | 
| RecordedFuture.Domain.ruleCount | number | Number of triggered Recorded Future Domain Risk Rules | 


#### Command Example
```!domain domain="google.com"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Recorded Future"
    },
    "Domain": {
        "Name": "google.com"
    },
    "RecordedFuture": {
        "Domain": {
            "Evidence": [
                {
                    "description": "Previous sightings on 1 source: Recorded Future Analyst Community Trending Indicators. Observed between May 28, 2020, and May 29, 2020.",
                    "level": 1,
                    "rule": "Historically Reported in Threat List",
                    "ruleid": "historicalThreatListMembership",
                    "timestamp": "2020-06-12 16:23:41"
                }
            ],
            "description": "",
            "id": "idn:google.com",
            "maxRules": 40,
            "name": "google.com",
            "riskLevel": 1,
            "riskScore": 24,
            "ruleCount": 4
        }
    }
}
```

#### Human Readable Output

>### Recorded Future Domain reputation for google.com
>Risk score: 24
>Risk Summary: 4 out of 40 Risk Rules currently observed
>Criticality: Informational
>
>[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/idn:google.com)
>
>### Risk Rules Triggered
>|Criticality|Rule|Evidence|Timestamp|
>|---|---|---|---|
>| Informational | Historically Reported in Threat List | Previous sightings on 1 source: Recorded Future Analyst Community Trending Indicators. Observed between May 28, 2020, and May 29, 2020. | 2020-06-12 16:23:41 |


### ip
***
Get a quick indicator of the risk associated with an IP.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to get the reputation of | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision | 
| IP.Malicious.Description | string | For malicious IP addresses, the reason that the vendor made the decision | 
| IP.Address | string | IP address | 
| RecordedFuture.IP.riskScore | number | Recorded Future IP Risk Score | 
| RecordedFuture.IP.riskLevel | string | Recorded Future IP Risk Level | 
| RecordedFuture.IP.Evidence.rule | string | Recorded Risk Rule Name | 
| RecordedFuture.IP.Evidence.mitigation | string | Recorded Risk Rule Mitigation | 
| RecordedFuture.IP.Evidence.description | string | Recorded Risk Rule Description | 
| RecordedFuture.IP.Evidence.timestamp | date | Recorded Risk Rule Timestamp | 
| RecordedFuture.IP.Evidence.level | number | Recorded Risk Rule Level | 
| RecordedFuture.IP.Evidence.ruleid | string | Recorded Risk Rule ID | 
| RecordedFuture.IP.name | string | IP Address | 
| RecordedFuture.IP.maxRules | number | Maximum count of Recorded Future IP Risk Rules | 
| RecordedFuture.IP.ruleCount | number | Number of triggered Recorded Future IP Risk Rules | 


#### Command Example
```!ip ip="8.8.8.8"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Recorded Future"
    },
    "IP": {
        "Address": "8.8.8.8"
    },
    "RecordedFuture": {
        "IP": {
            "Evidence": [],
            "description": "",
            "id": "ip:8.8.8.8",
            "maxRules": 51,
            "name": "8.8.8.8",
            "riskLevel": 0,
            "riskScore": 0,
            "ruleCount": 0
        }
    }
}
```

#### Human Readable Output

>### Recorded Future IP reputation for 8.8.8.8
>Risk score: 0
>Risk Summary: 0 out of 51 Risk Rules currently observed
>Criticality: Unknown
>
>[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/ip:8.8.8.8)


### file
***
Get a quick indicator of the risk associated with a file.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash to check the reputation of (MD5, SHA-1, SHA-256, SHA-512, CRC32, CTPH) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | string | File SHA\-256 | 
| File.SHA512 | string | File SHA\-512 | 
| File.SHA1 | string | File SHA\-1 | 
| File.MD5 | string | File MD5 | 
| File.CRC32 | string | File CRC32 | 
| File.CTPH | string | File CTPH | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision | 
| File.Malicious.Description | string | For malicious files, the reason that the vendor made the decision | 
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| RecordedFuture.File.riskScore | number | Recorded Future Hash Risk Score | 
| RecordedFuture.File.riskLevel | string | Recorded Future Hash Risk Level | 
| RecordedFuture.File.Evidence.rule | string | Recorded Risk Rule Name | 
| RecordedFuture.File.Evidence.mitigation | string | Recorded Risk Rule Mitigation | 
| RecordedFuture.File.Evidence.description | string | Recorded Risk Rule description | 
| RecordedFuture.File.Evidence.timestamp | date | Recorded Risk Rule timestamp | 
| RecordedFuture.File.Evidence.level | number | Recorded Risk Rule Level | 
| RecordedFuture.File.Evidence.ruleid | string | Recorded Risk Rule ID | 
| RecordedFuture.File.name | string | Hash | 
| RecordedFuture.File.maxRules | number | Maximum count of Recorded Future Hash Risk Rules | 
| RecordedFuture.File.ruleCount | number | Number of triggered Recorded Future Hash Risk Rules | 


#### Command Example
```!file file="027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
        "Score": 3,
        "Type": "file",
        "Vendor": "Recorded Future"
    },
    "File": {
        "Malicious": {
            "Description": "Score above 65",
            "Vendor": "Recorded Future"
        },
        "SHA256": "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
    },
    "RecordedFuture": {
        "File": {
            "Evidence": [
                {
                    "description": "20 sightings on 1 source: VirusTotal. 3 related cyber vulnerabilities: CVE-2017-0147, ETERNALBLUE, CWE-200. Most recent link (May 3, 2020): https://www.virustotal.com/gui/file/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                    "level": 2,
                    "rule": "Linked to Vulnerability",
                    "ruleid": "linkedToVuln",
                    "timestamp": "2020-05-03 14:07:48"
                }
            ],
            "description": "",
            "id": "hash:027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
            "maxRules": 12,
            "name": "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
            "riskLevel": 3,
            "riskScore": 89,
            "ruleCount": 6
        }
    }
}
```

#### Human Readable Output

>### Recorded Future File reputation for 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
>Risk score: 89
>Risk Summary: 6 out of 12 Risk Rules currently observed
>Criticality: Malicious
>
>[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/hash:027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745)
>
>### Risk Rules Triggered
>|Criticality|Rule|Evidence|Timestamp|
>|---|---|---|---|
>| Malicious | Positive Malware Verdict | 24 sightings on 4 sources: VirusTotal, Malwr.com, Recorded Future Malware Detonation, ReversingLabs. Most recent link (May 3, 2020): https://www.virustotal.com/gui/file/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745 | 2020-06-11 17:53:54 |


### cve
***
Get a quick indicator of the risk associated with a CVE.


#### Base Command

`cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | CVE to get the reputation of | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | string | Vulnerability name | 
| RecordedFuture.CVE.riskScore | number | Recorded Future Vulnerability Risk Score | 
| RecordedFuture.CVE.riskLevel | string | Recorded Future Vulnerability Risk Level | 
| RecordedFuture.CVE.Evidence.rule | string | Recorded Risk Rule Name | 
| RecordedFuture.CVE.Evidence.mitigation | string | Recorded Risk Rule Mitigation | 
| RecordedFuture.CVE.Evidence.description | string | Recorded Risk Rule description | 
| RecordedFuture.CVE.Evidence.timestamp | date | Recorded Risk Rule timestamp | 
| RecordedFuture.CVE.Evidence.level | number | Recorded Risk Rule Level | 
| RecordedFuture.CVE.Evidence.ruleid | string | Recorded Risk Rule ID | 
| RecordedFuture.CVE.name | string | CVE | 
| RecordedFuture.CVE.maxRules | number | Maximum count of Recorded Future Vulnerability Risk Rules | 
| RecordedFuture.CVE.ruleCount | number | Number of triggered Recorded Future Vulnerability Risk Rules | 


#### Command Example
```!cve cve="CVE-2011-3874"```

#### Context Example
```
{
    "CVE": {
        "Description": "Stack-based buffer overflow in libsysutils in Android 2.2.x through 2.2.2 and 2.3.x through 2.3.6 allows user-assisted remote attackers to execute arbitrary code via an application that calls the FrameworkListener::dispatchCommand method with the wrong number of arguments, as demonstrated by zergRush to trigger a use-after-free error.",
        "ID": "CVE-2011-3874"
    },
    "DBotScore": {
        "Indicator": "CVE-2011-3874",
        "Score": 0,
        "Type": "cve",
        "Vendor": null
    },
    "RecordedFuture": {
        "CVE": {
            "Evidence": [
                {
                    "description": "1 sighting on 1 source: Recorded Future Malware Hunting. Activity seen on 1 out of the last 28 days with 24 all-time daily sightings. Exploited in the wild by 1 malware family: <e id=K4T4te>DroidRt</e>. Last observed on May 23, 2020. Sample hash: <e id=hash:ffd0d7e6ba12ed20bc17f9ea1a1323a04cbf2e03bcaec0fa9ea574d9a7fb4881>ffd0d7e6ba12ed20bc17f9ea1a1323a04cbf2e03bcaec0fa9ea574d9a7fb4881</e>.",
                    "level": 5,
                    "rule": "Exploited in the Wild by Recently Active Malware",
                    "ruleid": "recentMalwareActivity",
                    "timestamp": "2020-05-23 00:00:00"
                }
            ],
            "description": "Stack-based buffer overflow in libsysutils in Android 2.2.x through 2.2.2 and 2.3.x through 2.3.6 allows user-assisted remote attackers to execute arbitrary code via an application that calls the FrameworkListener::dispatchCommand method with the wrong number of arguments, as demonstrated by zergRush to trigger a use-after-free error.",
            "id": "KIHnRI",
            "maxRules": 22,
            "name": "CVE-2011-3874",
            "riskLevel": 5,
            "riskScore": 99,
            "ruleCount": 4
        }
    }
}
```

#### Human Readable Output

>### Recorded Future CVE reputation for CVE-2011-3874
>Risk score: 99
>Risk Summary: 4 out of 22 Risk Rules currently observed
>Criticality: Very Malicious
>
>NVD Vulnerability Description: Stack-based buffer overflow in libsysutils in Android 2.2.x through 2.2.2 and 2.3.x through 2.3.6 allows user-assisted remote attackers to execute arbitrary code via an application that calls the FrameworkListener::dispatchCommand method with the wrong number of arguments, as demonstrated by zergRush to trigger a use-after-free error.
>
>[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/KIHnRI)
>
>### Risk Rules Triggered
>|Criticality|Rule|Evidence|Timestamp|
>|---|---|---|---|
>| Very Malicious | Exploited in the Wild by Recently Active Malware | 1 sighting on 1 source: Recorded Future Malware Hunting. Activity seen on 1 out of the last 28 days with 24 all-time daily sightings. Exploited in the wild by 1 malware family: <e id=K4T4te>DroidRt</e>. Last observed on May 23, 2020. Sample hash: <e id=hash:ffd0d7e6ba12ed20bc17f9ea1a1323a04cbf2e03bcaec0fa9ea574d9a7fb4881>ffd0d7e6ba12ed20bc17f9ea1a1323a04cbf2e03bcaec0fa9ea574d9a7fb4881</e>. | 2020-05-23 00:00:00 |


### url
***
Get a quick indicator of the risk associated with a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to get the reputation of | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | string | For malicious URLs, the reason that the vendor made the decision | 
| URL.Data | string | URL name | 
| RecordedFuture.URL.riskScore | number | Recorded Future URL Risk Score | 
| RecordedFuture.URL.riskLevel | string | Recorded Future URL Risk Level | 
| RecordedFuture.URL.Evidence.rule | string | Recorded Risk Rule Name | 
| RecordedFuture.URL.Evidence.mitigation | string | Recorded Risk Rule Mitigation | 
| RecordedFuture.URL.Evidence.description | string | Recorded Risk Rule description | 
| RecordedFuture.URL.Evidence.timestamp | date | Recorded Risk Rule timestamp | 
| RecordedFuture.URL.Evidence.level | number | Recorded Risk Rule Level | 
| RecordedFuture.URL.Evidence.ruleid | string | Recorded Risk Rule ID | 
| RecordedFuture.URL.name | string | URL | 
| RecordedFuture.URL.maxRules | number | Maximum count of Recorded Future URL Risk Rules | 
| RecordedFuture.URL.ruleCount | number | Number of triggered Recorded Future URL Risk Rules | 


#### Command Example
```!url url="https://google.com"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "https://google.com",
        "Score": 2,
        "Type": "url",
        "Vendor": "Recorded Future"
    },
    "RecordedFuture": {
        "URL": {
            "Evidence": [
                {
                    "description": "13 sightings on 5 sources: Geeks To Go, AbuseIP Database, PasteBin, Malwarebytes Unpacked, PSBDMP Dumps. Most recent link (Dec 16, 2018): https://pastebin.com/2Brry0ZQ",
                    "level": 1,
                    "rule": "Historically Reported as a Defanged URL",
                    "ruleid": "defangedURL",
                    "timestamp": "2018-12-16 22:31:25"
                }
            ],
            "description": "",
            "id": "url:https://google.com",
            "maxRules": 27,
            "name": "https://google.com",
            "riskLevel": 1,
            "riskScore": 24,
            "ruleCount": 1
        }
    },
    "URL": {
        "Data": "https://google.com"
    }
}
```

#### Human Readable Output

>### Recorded Future URL reputation for https://google.com
>Risk score: 24
>Risk Summary: 1 out of 27 Risk Rules currently observed
>Criticality: Informational
>
>[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/url:https://google.com)
>
>### Risk Rules Triggered
>|Criticality|Rule|Evidence|Timestamp|
>|---|---|---|---|
>| Informational | Historically Reported as a Defanged URL | 13 sightings on 5 sources: Geeks To Go, AbuseIP Database, PasteBin, Malwarebytes Unpacked, PSBDMP Dumps. Most recent link (Dec 16, 2018): https://pastebin.com/2Brry0ZQ | 2018-12-16 22:31:25 |


### recordedfuture-threat-assessment
***
Get an indicator of the risk based on context.
This is not affected by the thresholds configured in the app, instead these are controlled by Recorded Future.
The verdict output is determined by algorithms inside the API.

#### Base Command

`recordedfuture-threat-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Context to use for verdict | Required | 
| ip | IPs to check if they are related to the selected context. | Optional |
| domain | Domains to check if they are related to the selected context. | Optional |
| file | File hashes to check if they are related to the selected context. | Optional |
| url | URLs to check if they are related to the selected context. | Optional |
| cve | CVEs to check if they are related to the selected context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested |
| DBotScore.Type | string | Indicator type |
| DBotScore.Vendor | string | Vendor used to calculate the score |
| DBotScore.Score | number | The actual score |
| File.SHA256 | string | File SHA\-256 |
| File.SHA512 | string | File SHA\-512 |
| File.SHA1 | string | File SHA\-1 |
| File.MD5 | string | File MD5 |
| File.CRC32 | string | File CRC32 |
| File.CTPH | string | File CTPH |
| IP.Address | string | IP address |
| Domain.Name | string | Domain name |
| URL.Data | string | URL name |
| CVE.ID | string | Vulnerability name |
| RecordedFuture.verdict | boolean | Recorded Future verdict | 
| RecordedFuture.context | string | Threat Assessment Context | 
| RecordedFuture.riskScore | number | Recorded Future Max Score | 
| RecordedFuture.Entities.id | string | Entity ID | 
| RecordedFuture.Entities.name | string | Entity Name | 
| RecordedFuture.Entities.type | string | Entity Type | 
| RecordedFuture.Entities.score | string | Entity Score | 
| RecordedFuture.Entities.Evidence.ruleid | string | Recorded Future Risk Rule ID | 
| RecordedFuture.Entities.Evidence.timestamp | date | Recorded Future Evidence Timestamp | 
| RecordedFuture.Entities.Evidence.mitigation | string | Recorded Future Evidence Mitigation | 
| RecordedFuture.Entities.Evidence.description | string | Recorded Future Evidence Description | 
| RecordedFuture.Entities.Evidence.rule | string | Recorded Future Risk Rule | 
| RecordedFuture.Entities.Evidence.level | number | Recorded Future Risk Rule Level | 


#### Command Example
```!recordedfuture-threat-assessment context="c2" ip="8.8.8.8"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Recorded Future"
    },
    "IP": {
        "Address": "8.8.8.8"
    },
    "RecordedFuture": {
        "Entities": [
            {
                "Evidence": [],
                "id": "ip:8.8.8.8",
                "name": "8.8.8.8",
                "score": 0,
                "type": "IpAddress"
            }
        ],
        "context": "c2",
        "riskScore": 0,
        "verdict": false
    }
}
```

#### Human Readable Output

>### Recorded Future Threat Assessment with regards to c2
>Verdict: Non-malicious
>Max/Min Score: 0/0
>
>
>### Entities
>Entity: 8.8.8.8
>Score: 0
>Rule count: 0 out of 2
>### Evidence
>**No entries.**


### recordedfuture-alert-rules
***
Search for alert rule IDs.


#### Base Command

`recordedfuture-alert-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | Rule name to search, can be a partial name | Optional | 
| limit | Number of rules to return | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.AlertRule.id | string | Alert rule ID | 
| RecordedFuture.AlertRule.name | string | Alert rule name | 


#### Command Example
```!recordedfuture-alert-rules limit=1```

#### Context Example
```
{
    "RecordedFuture": {
        "AlertRule": {
            "id": "d55BDp",
            "name": "Supplier and Partner Trends, Trending Partners in Watch List"
        }
    }
}
```

#### Human Readable Output

>### Recorded Future Alerting Rules
>|id|name|
>|---|---|
>| d55BDp | Supplier and Partner Trends, Trending Partners in Watch List |


### recordedfuture-alerts
***
Get details on alerts configured and generated by Recorded Future by alert rule ID and/or time range.


#### Base Command

`recordedfuture-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Alert rule ID | Optional | 
| limit | Number of alerts to return | Optional | 
| triggered_time | Alert triggered time, e.g., "1 hour" or "2 days" | Optional | 
| assignee | Alert assignee's email address | Optional | 
| status | Alert review status | Optional | 
| freetext | Free text search | Optional | 
| offset | Alerts from offset | Optional | 
| orderby | Alerts sort order | Optional | 
| direction | Alerts sort direction | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Alert.id | string | Alert ID | 
| RecordedFuture.Alert.name | string | Alert name | 
| RecordedFuture.Alert.type | string | Alert type | 
| RecordedFuture.Alert.triggered | date | Alert triggered time | 
| RecordedFuture.Alert.status | string | Alert status | 
| RecordedFuture.Alert.assignee | string | Alert assignee | 
| RecordedFuture.Alert.rule | string | Alert rule name | 


#### Command Example
```!recordedfuture-alerts limit=1```

#### Context Example
```
{
    "RecordedFuture": {
        "Alert": {
            "Alert Title": "Global Trends, Trending Targets - Spike: Enel SPA, Knoxville and Alabama",
            "assignee": null,
            "email": null,
            "id": "eK8voo",
            "name": "Global Trends, Trending Targets - Spike: Enel SPA, Knoxville and Alabama",
            "rule": "Global Trends, Trending Targets",
            "status": "no-action",
            "triggered": "2020-06-12 14:37:13",
            "type": "ENTITY"
        }
    }
}
```

#### Human Readable Output

>### Recorded Future Alerts
>|Alert Title|
>|---|
>| Global Trends, Trending Targets - Spike: Enel SPA, Knoxville and Alabama |


### recordedfuture-intelligence
***
Get threat intelligence for an IP, Domain, CVE, URL or File.


#### Base Command

`recordedfuture-intelligence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_type | The type of entity to fetch context for. (Should be provided with its value in entityValue argument) | Required | 
| entity | The value of the entity to fetch context for. (Should be provided with its type in entity_type argument, Hash types supported: MD5, SHA-1, SHA-256, SHA-512, CRC32, CTPH). Vulnerability supports CVEs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested | 
| DBotScore.Type | string | Indicator type | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 
| File.SHA256 | string | File SHA\-256 | 
| File.SHA512 | string | File SHA\-512 | 
| File.SHA1 | string | File SHA\-1 | 
| File.MD5 | string | File MD5 | 
| File.CRC32 | string | File CRC32 | 
| File.CTPH | string | File CTPH | 
| IP.Address | string | IP address | 
| IP.ASN | string | ASN | 
| IP.Geo.Country | string | IP Geolocation Country | 
| Domain.Name | string | Domain name | 
| URL.Data | string | URL name | 
| CVE.ID | string | Vulnerability name | 
| RecordedFuture.IP.criticality | number | Risk Criticality | 
| RecordedFuture.IP.criticalityLabel | string | Risk Criticality Label | 
| RecordedFuture.IP.riskString | string | Risk String | 
| RecordedFuture.IP.riskSummary | string | Risk Summary | 
| RecordedFuture.IP.rules | string | Risk Rules | 
| RecordedFuture.IP.score | number | Risk Score | 
| RecordedFuture.IP.firstSeen | date | Evidence First Seen | 
| RecordedFuture.IP.lastSeen | date | Evidence Last Seen | 
| RecordedFuture.IP.intelCard | string | Recorded Future Intelligence Card URL | 
| RecordedFuture.IP.hashAlgorithm | string | Hash Algorithm | 
| RecordedFuture.IP.type | string | Entity Type | 
| RecordedFuture.IP.name | string | Entity | 
| RecordedFuture.IP.id | string | Recorded Future Entity ID | 
| RecordedFuture.IP.location.asn | String | ASN number | 
| RecordedFuture.IP.location.cidr.id | String | Recorded Future CIDR ID | 
| RecordedFuture.IP.location.cidr.name | String | CIDR | 
| RecordedFuture.IP.location.cidr.type | String | CIDR Type | 
| RecordedFuture.IP.location.location.city | String | IP Geolocation City | 
| RecordedFuture.IP.location.location.continent | String | IP Geolocation Continent | 
| RecordedFuture.IP.location.location.country | String | IP Geolocation Country | 
| RecordedFuture.IP.location.organization | String | IP Geolocation Organization | 
| RecordedFuture.IP.metrics.type | String | Recorded Future Metrics Type | 
| RecordedFuture.IP.metrics.value | Number | Recorded Future Metrics Value | 
| RecordedFuture.IP.threatLists.description | String | Recorded Future Threat List Description | 
| RecordedFuture.IP.threatLists.id | String | Recorded Future Threat List ID | 
| RecordedFuture.IP.threatLists.name | String | Recorded Future Threat List Name | 
| RecordedFuture.IP.threatLists.type | String | Recorded Future Threat List Type | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedHash.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedHash.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedHash.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedHash.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.type | String | Recorded Future Related Type | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.count | Number | Recorded Future Related Count | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.id | String | Recorded Future Related ID | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.name | String | Recorded Future Related Name | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.criticality | number | Risk Criticality | 
| RecordedFuture.Domain.criticalityLabel | string | Risk Criticality Label | 
| RecordedFuture.Domain.riskString | string | Risk String | 
| RecordedFuture.Domain.riskSummary | string | Risk Summary | 
| RecordedFuture.Domain.rules | string | Risk Rules | 
| RecordedFuture.Domain.score | number | Risk Score | 
| RecordedFuture.Domain.firstSeen | date | Evidence First Seen | 
| RecordedFuture.Domain.lastSeen | date | Evidence Last Seen | 
| RecordedFuture.Domain.intelCard | string | Recorded Future Intelligence Card URL | 
| RecordedFuture.Domain.hashAlgorithm | string | Hash Algorithm | 
| RecordedFuture.Domain.type | string | Entity Type | 
| RecordedFuture.Domain.name | string | Entity | 
| RecordedFuture.Domain.id | string | Recorded Future Entity ID | 
| RecordedFuture.Domain.location.asn | String | ASN number | 
| RecordedFuture.Domain.location.cidr.id | String | Recorded Future CIDR ID | 
| RecordedFuture.Domain.location.cidr.name | String | CIDR | 
| RecordedFuture.Domain.location.cidr.type | String | CIDR Type | 
| RecordedFuture.Domain.location.location.city | String | IP Geolocation City | 
| RecordedFuture.Domain.location.location.continent | String | IP Geolocation Continent | 
| RecordedFuture.Domain.location.location.country | String | IP Geolocation Country | 
| RecordedFuture.Domain.location.organization | String | IP Geolocation Organization | 
| RecordedFuture.Domain.metrics.type | String | Recorded Future Metrics Type | 
| RecordedFuture.Domain.metrics.value | Number | Recorded Future Metrics Value | 
| RecordedFuture.Domain.threatLists.description | String | Recorded Future Threat List Description | 
| RecordedFuture.Domain.threatLists.id | String | Recorded Future Threat List ID | 
| RecordedFuture.Domain.threatLists.name | String | Recorded Future Threat List Name | 
| RecordedFuture.Domain.threatLists.type | String | Recorded Future Threat List Type | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.type | String | Recorded Future Related Type | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.count | Number | Recorded Future Related Count | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.id | String | Recorded Future Related ID | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.name | String | Recorded Future Related Name | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.criticality | number | Risk Criticality | 
| RecordedFuture.CVE.criticalityLabel | string | Risk Criticality Label | 
| RecordedFuture.CVE.riskString | string | Risk String | 
| RecordedFuture.CVE.riskSummary | string | Risk Summary | 
| RecordedFuture.CVE.rules | string | Risk Rules | 
| RecordedFuture.CVE.score | number | Risk Score | 
| RecordedFuture.CVE.firstSeen | date | Evidence First Seen | 
| RecordedFuture.CVE.lastSeen | date | Evidence Last Seen | 
| RecordedFuture.CVE.intelCard | string | Recorded Future Intelligence Card URL | 
| RecordedFuture.CVE.hashAlgorithm | string | Hash Algorithm | 
| RecordedFuture.CVE.type | string | Entity Type | 
| RecordedFuture.CVE.name | string | Entity | 
| RecordedFuture.CVE.id | string | Recorded Future Entity ID | 
| RecordedFuture.CVE.location.asn | String | ASN number | 
| RecordedFuture.CVE.location.cidr.id | String | Recorded Future CIDR ID | 
| RecordedFuture.CVE.location.cidr.name | String | CIDR | 
| RecordedFuture.CVE.location.cidr.type | String | CIDR Type | 
| RecordedFuture.CVE.location.location.city | String | IP Geolocation City | 
| RecordedFuture.CVE.location.location.continent | String | IP Geolocation Continent | 
| RecordedFuture.CVE.location.location.country | String | IP Geolocation Country | 
| RecordedFuture.CVE.location.organization | String | IP Geolocation Organization | 
| RecordedFuture.CVE.metrics.type | String | Recorded Future Metrics Type | 
| RecordedFuture.CVE.metrics.value | Number | Recorded Future Metrics Value | 
| RecordedFuture.CVE.threatLists.description | String | Recorded Future Threat List Description | 
| RecordedFuture.CVE.threatLists.id | String | Recorded Future Threat List ID | 
| RecordedFuture.CVE.threatLists.name | String | Recorded Future Threat List Name | 
| RecordedFuture.CVE.threatLists.type | String | Recorded Future Threat List Type | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.type | String | Recorded Future Related Type | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.count | Number | Recorded Future Related Count | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.id | String | Recorded Future Related ID | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.name | String | Recorded Future Related Name | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.type | String | Recorded Future Related Type | 
| RecordedFuture.File.criticality | number | Risk Criticality | 
| RecordedFuture.File.criticalityLabel | string | Risk Criticality Label | 
| RecordedFuture.File.riskString | string | Risk String | 
| RecordedFuture.File.riskSummary | string | Risk Summary | 
| RecordedFuture.File.rules | string | Risk Rules | 
| RecordedFuture.File.score | number | Risk Score | 
| RecordedFuture.File.firstSeen | date | Evidence First Seen | 
| RecordedFuture.File.lastSeen | date | Evidence Last Seen | 
| RecordedFuture.File.intelCard | string | Recorded Future Intelligence Card URL | 
| RecordedFuture.File.hashAlgorithm | string | Hash Algorithm | 
| RecordedFuture.File.type | string | Entity Type | 
| RecordedFuture.File.name | string | Entity | 
| RecordedFuture.File.id | string | Recorded Future Entity ID | 
| RecordedFuture.File.metrics.type | String | Recorded Future Metrics Type | 
| RecordedFuture.File.metrics.value | Number | Recorded Future Metrics Value | 
| RecordedFuture.File.threatLists.description | String | Recorded Future Threat List Description | 
| RecordedFuture.File.threatLists.id | String | Recorded Future Threat List ID | 
| RecordedFuture.File.threatLists.name | String | Recorded Future Threat List Name | 
| RecordedFuture.File.threatLists.type | String | Recorded Future Threat List Type | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedTarget.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedTarget.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedTarget.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedTarget.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedMalware.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedMalware.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedMalware.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedMalware.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedProduct.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedProduct.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedProduct.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedProduct.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedCountries.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedCountries.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedCountries.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedCountries.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedHash.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedHash.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedHash.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedHash.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedOperations.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedOperations.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedOperations.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedOperations.type | String | Recorded Future Related Type | 
| RecordedFuture.File.relatedEntities.RelatedCompany.count | Number | Recorded Future Related Count | 
| RecordedFuture.File.relatedEntities.RelatedCompany.id | String | Recorded Future Related ID | 
| RecordedFuture.File.relatedEntities.RelatedCompany.name | String | Recorded Future Related Name | 
| RecordedFuture.File.relatedEntities.RelatedCompany.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.criticality | number | Risk Criticality | 
| RecordedFuture.URL.criticalityLabel | string | Risk Criticality Label | 
| RecordedFuture.URL.riskString | string | Risk String | 
| RecordedFuture.URL.riskSummary | string | Risk Summary | 
| RecordedFuture.URL.rules | string | Risk Rules | 
| RecordedFuture.URL.score | number | Risk Score | 
| RecordedFuture.URL.firstSeen | date | Evidence First Seen | 
| RecordedFuture.URL.lastSeen | date | Evidence Last Seen | 
| RecordedFuture.URL.intelCard | string | Recorded Future Intelligence Card URL | 
| RecordedFuture.URL.hashAlgorithm | string | Hash Algorithm | 
| RecordedFuture.URL.type | string | Entity Type | 
| RecordedFuture.URL.name | string | Entity | 
| RecordedFuture.URL.id | string | Recorded Future Entity ID | 
| RecordedFuture.URL.location.asn | String | ASN number | 
| RecordedFuture.URL.location.cidr.id | String | Recorded Future CIDR ID | 
| RecordedFuture.URL.location.cidr.name | String | CIDR | 
| RecordedFuture.URL.location.cidr.type | String | CIDR Type | 
| RecordedFuture.URL.location.location.city | String | IP Geolocation City | 
| RecordedFuture.URL.location.location.continent | String | IP Geolocation Continent | 
| RecordedFuture.URL.location.location.country | String | IP Geolocation Country | 
| RecordedFuture.URL.location.organization | String | IP Geolocation Organization | 
| RecordedFuture.URL.metrics.type | String | Recorded Future Metrics Type | 
| RecordedFuture.URL.metrics.value | Number | Recorded Future Metrics Value | 
| RecordedFuture.URL.threatLists.description | String | Recorded Future Threat List Description | 
| RecordedFuture.URL.threatLists.id | String | Recorded Future Threat List ID | 
| RecordedFuture.URL.threatLists.name | String | Recorded Future Threat List Name | 
| RecordedFuture.URL.threatLists.type | String | Recorded Future Threat List Type | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedHash.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedHash.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedHash.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedHash.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.type | String | Recorded Future Related Type | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.count | Number | Recorded Future Related Count | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.id | String | Recorded Future Related ID | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.name | String | Recorded Future Related Name | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.type | String | Recorded Future Related Type | 


#### Command Example
```!recordedfuture-intelligence entity_type="ip" entity="8.8.8.8"```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "8.8.8.8",
            "Score": 0,
            "Type": "ip",
            "Vendor": "Recorded Future"
        },
        {
            "Indicator": "8.8.8.4",
            "Score": 2,
            "Type": "ip",
            "Vendor": "Recorded Future"
        },
        {
            "Indicator": "8.8.8.5",
            "Score": 2,
            "Type": "ip",
            "Vendor": "Recorded Future"
        }
    ],
    "IP": [
        {
            "ASN": "AS15169",
            "Address": "8.8.8.8",
            "Geo": {
                "Country": "United States"
            }
        },
        {
            "Address": "8.8.8.4"
        },
        {
            "Address": "8.8.8.5"
        }
    ],
    "RecordedFuture": {
        "IP": {
            "criticality": 0,
            "criticalityLabel": "None",
            "evidenceDetails": [],
            "firstSeen": "2010-04-27T12:46:51.000Z",
            "id": "ip:8.8.8.8",
            "intelCard": "https://app.recordedfuture.com/live/sc/entity/ip%3A8.8.8.8",
            "lastSeen": "2020-06-12T16:25:09.211Z",
            "location": {
                "asn": "AS15169",
                "cidr": {
                    "id": "ip:8.8.8.0/24",
                    "name": "8.8.8.0/24",
                    "type": "IpAddress"
                },
                "location": {
                    "city": "Mountain View",
                    "continent": "North America",
                    "country": "United States"
                },
                "organization": "GOOGLE"
            },
            "metrics": [
                {
                    "type": "pasteHits",
                    "value": 324743
                },
                {
                    "type": "darkWebHits",
                    "value": 53564
                },
                {
                    "type": "criticality",
                    "value": 0
                },
                {
                    "type": "publicSubscore",
                    "value": 0
                },
                {
                    "type": "undergroundForumHits",
                    "value": 1837
                },
                {
                    "type": "maliciousHits",
                    "value": 462511
                },
                {
                    "type": "technicalReportingHits",
                    "value": 9074924
                },
                {
                    "type": "infoSecHits",
                    "value": 9065751
                },
                {
                    "type": "totalHits",
                    "value": 9576010
                },
                {
                    "type": "sixtyDaysHits",
                    "value": 96554
                },
                {
                    "type": "oneDayHits",
                    "value": 169
                },
                {
                    "type": "c2Subscore",
                    "value": 0
                },
                {
                    "type": "phishingSubscore",
                    "value": 0
                },
                {
                    "type": "socialMediaHits",
                    "value": 71547
                },
                {
                    "type": "sevenDaysHits",
                    "value": 5819
                }
            ],
            "name": "8.8.8.8",
            "relatedEntities": [
                {
                    "RelatedMalwareCategory": [
                        {
                            "count": 143770,
                            "id": "0efpT",
                            "name": "Trojan",
                            "type": "MalwareCategory"
                        },
                        {
                            "count": 100993,
                            "id": "J31vQ6",
                            "name": "Banking Trojan",
                            "type": "MalwareCategory"
                        }
                    ]
                },
                {
                    "RelatedCyberVulnerability": [
                        {
                            "count": 11,
                            "id": "LBbHYm",
                            "name": "CWE-78",
                            "type": "CyberVulnerability"
                        },
                        {
                            "count": 11,
                            "id": "LpTCYV",
                            "name": "CVE-2014-6271",
                            "type": "CyberVulnerability"
                        }
                    ]
                },
                {
                    "RelatedHash": [
                        {
                            "count": 573,
                            "id": "hash:00e9fb5ad26e87ce2abc2a7de0789ebb1a38bf0d28ae175662f67d4b16237b67",
                            "name": "00e9fb5ad26e87ce2abc2a7de0789ebb1a38bf0d28ae175662f67d4b16237b67",
                            "type": "Hash"
                        },
                        {
                            "count": 148,
                            "id": "hash:cef615ee419d513c68e67780a08fd52a6e9c23d189cf4b85d3ba5efbee7a48e6",
                            "name": "cef615ee419d513c68e67780a08fd52a6e9c23d189cf4b85d3ba5efbee7a48e6",
                            "type": "Hash"
                        }
                    ]
                },
                {
                    "RelatedIpAddress": [
                        {
                            "count": 1352680,
                            "id": "ip:8.8.4.4",
                            "name": "8.8.4.4",
                            "type": "IpAddress"
                        },
                        {
                            "count": 158918,
                            "id": "ip:66.171.248.178",
                            "name": "66.171.248.178",
                            "type": "IpAddress"
                        }
                    ]
                },
                {
                    "RelatedThreatActor": [
                        {
                            "count": 159,
                            "id": "I2QcS_",
                            "name": "Anonymous",
                            "type": "Organization"
                        }
                    ]
                },
            ],
            "riskString": "0/51",
            "riskSummary": "No Risk Rules are currently observed.",
            "riskyCIDRIPs": [
                {
                    "ip": {
                        "id": "ip:8.8.8.4",
                        "name": "8.8.8.4",
                        "type": "IpAddress"
                    },
                    "score": 24
                },
                {
                    "ip": {
                        "id": "ip:8.8.8.5",
                        "name": "8.8.8.5",
                        "type": "IpAddress"
                    },
                    "score": 24
                }
            ],
            "rules": 0,
            "score": 0,
            "threatLists": [
                {
                    "description": "This list consists of DNS public or open DNS servers and is an absolute white list for Risk Scoring.",
                    "id": "report:Uz6vFG",
                    "name": "DNS Server List (White List)",
                    "type": "EntityList"
                }
            ],
            "type": "IpAddress"
        }
    }
}
```

#### Human Readable Output

>### Recorded Future IP Intelligence for 8.8.8.8
>Risk Score: 0
>Summary: No Risk Rules are currently observed.
>Criticality label: None
>Total references to this entity: 9576010
>ASN and Geolocation
>AS Number: AS15169
>AS Name: GOOGLE
>CIDR: 8.8.8.0/24
>Geolocation (city): Mountain View
>Geolocation (country): United States
>First reference collected on: 2010-04-27 12:46:51
>Latest reference collected on: 2020-06-12 16:25:09
>[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/ip%3A8.8.8.8)
>
>### Triggered Risk Rules
>**No entries.**
>
>### Threat Lists
>|Threat List Name|Description|
>|---|---|
>| DNS Server List (White List) | This list consists of DNS public or open DNS servers and is an absolute white list for Risk Scoring. |

