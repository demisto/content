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
| Parameter                                      | Description                                                                                                                                                                                                                                 |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Server URL                                     | The URL to the Recorded Future ConnectAPI.                                                                                                                                                                                                  |
| API Token                                      | Valid API Token from Recorded Future.                                                                                                                                                                                                       |
| Classifier                                     | Select "Recorded Future - Classifier".                                                                                                                                                                                                      |
| Mapper (Incoming)                              | Select "Recorded Future - Incoming Mapper".                                                                                                                                                                                                 |
| IP/Domain/URL/File/CVE/Vulnerability Threshold | Minimum risk score from Recorded Future needed to mark IOC as malicious when doing reputation or intelligence lookups.                                                                                                                      |
| Trust any certificate (not secure)             | -                                                                                                                                                                                                                                           |
| Use system proxy settings                      | -                                                                                                                                                                                                                                           |
| First fetch time                               | This threshold will be used during first fetch of the incidents.                                                                                                                                                                            |
| Rule names to fetch alerts by                  | Rule names to fetch alerts by, separated by semicolon. If empty, all alerts will be fetched.                                                                                                                                                |
| Alert Statuses to include in the fetch         | Alert Statuses to include in the fetch, separated by a comma. If empty, the default value of 'no-action' will be used. The value should be comma-separated alert statuses (e.g. "unassigned,assigned,pending,actionable,no-action,tuning"). |
| Update alert status on fetch                   | If selected, alerts with a status of 'no-action' will be updated to 'pending' once fetched by the integration.                                                                                                                              |
| Turn on "Incident Sharing"                     | Turning on "Incident Sharing" shares anonymized correlations from playbooks with Recorded Future to improve intelligence quality.                                                                                                           |
| Maximum number of incidents per fetch          | -                                                                                                                                                                                                                                           |
| Incidents Fetch Interval                       | -                                                                                                                                                                                                                                           |
| Indicator Expiration Method                    | -                                                                                                                                                                                                                                           |
| Source Reliability                             | Reliability of the source providing the intelligence data.                                                                                                                                                                                  |


4. Click **Test** to validate the URLs, token, and connection.

Several of the outputs below have been reduced in size to improve readability.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Get a quick indicator of the risk associated with a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description**                 | **Required** |
|-------------------|---------------------------------|--------------|
| domain            | Domain to get the reputation of | Required     |


#### Context Output

| **Path**                                   | **Type** | **Description**                                                     |
|--------------------------------------------|----------|---------------------------------------------------------------------|
| DBotScore.Indicator                        | string   | The indicator that was tested                                       |
| DBotScore.Type                             | string   | Indicator type                                                      |
| DBotScore.Vendor                           | string   | Vendor used to calculate the score                                  |
| DBotScore.Score                            | number   | The actual score                                                    |
| Domain.Malicious.Vendor                    | string   | For malicious Domains, the vendor that made the decision            |
| Domain.Malicious.Description               | string   | For malicious Domains, the reason that the vendor made the decision |
| Domain.Name                                | string   | Domain name                                                         |
| RecordedFuture.Domain.riskScore            | number   | Recorded Future Domain Risk Score                                   |
| RecordedFuture.Domain.riskLevel            | string   | Recorded Future Domain Risk Level                                   |
| RecordedFuture.Domain.Evidence.rule        | string   | Recorded Risk Rule Name                                             |
| RecordedFuture.Domain.Evidence.mitigation  | string   | Recorded Risk Rule Mitigation                                       |
| RecordedFuture.Domain.Evidence.description | string   | Recorded Risk Rule description                                      |
| RecordedFuture.Domain.Evidence.timestamp   | date     | Recorded Risk Rule timestamp                                        |
| RecordedFuture.Domain.Evidence.level       | number   | Recorded Risk Rule Level                                            |
| RecordedFuture.Domain.Evidence.ruleid      | string   | Recorded Risk Rule ID                                               |
| RecordedFuture.Domain.name                 | string   | Domain name                                                         |
| RecordedFuture.Domain.maxRules             | number   | Maximum count of Recorded Future Domain Risk Rules                  |
| RecordedFuture.Domain.ruleCount            | number   | Number of triggered Recorded Future Domain Risk Rules               |
| RecordedFuture.Domain.rules                | string   | All the rules concatenated by comma                                 |


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

| **Argument Name** | **Description**                     | **Required** |
|-------------------|-------------------------------------|--------------|
| ip                | IP address to get the reputation of | Required     |


#### Context Output

| **Path**                               | **Type** | **Description**                                                          |
|----------------------------------------|----------|--------------------------------------------------------------------------|
| DBotScore.Indicator                    | string   | The indicator that was tested                                            |
| DBotScore.Type                         | string   | Indicator type                                                           |
| DBotScore.Vendor                       | string   | Vendor used to calculate the score                                       |
| DBotScore.Score                        | number   | The actual score                                                         |
| IP.Malicious.Vendor                    | string   | For malicious IP addresses, the vendor that made the decision            |
| IP.Malicious.Description               | string   | For malicious IP addresses, the reason that the vendor made the decision |
| IP.Address                             | string   | IP address                                                               |
| RecordedFuture.IP.riskScore            | number   | Recorded Future IP Risk Score                                            |
| RecordedFuture.IP.riskLevel            | string   | Recorded Future IP Risk Level                                            |
| RecordedFuture.IP.Evidence.rule        | string   | Recorded Risk Rule Name                                                  |
| RecordedFuture.IP.Evidence.mitigation  | string   | Recorded Risk Rule Mitigation                                            |
| RecordedFuture.IP.Evidence.description | string   | Recorded Risk Rule Description                                           |
| RecordedFuture.IP.Evidence.timestamp   | date     | Recorded Risk Rule Timestamp                                             |
| RecordedFuture.IP.Evidence.level       | number   | Recorded Risk Rule Level                                                 |
| RecordedFuture.IP.Evidence.ruleid      | string   | Recorded Risk Rule ID                                                    |
| RecordedFuture.IP.name                 | string   | IP Address                                                               |
| RecordedFuture.IP.maxRules             | number   | Maximum count of Recorded Future IP Risk Rules                           |
| RecordedFuture.IP.ruleCount            | number   | Number of triggered Recorded Future IP Risk Rules                        |
| RecordedFuture.IP.rules                | string   | All the rules concatenated by comma                                      |


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

| **Argument Name** | **Description**                                                                  | **Required** |
|-------------------|----------------------------------------------------------------------------------|--------------|
| file              | File hash to check the reputation of (MD5, SHA-1, SHA-256, SHA-512, CRC32, CTPH) | Required     |


#### Context Output

| **Path**                                 | **Type** | **Description**                                                   |
|------------------------------------------|----------|-------------------------------------------------------------------|
| File.SHA256                              | string   | File SHA\-256                                                     |
| File.SHA512                              | string   | File SHA\-512                                                     |
| File.SHA1                                | string   | File SHA\-1                                                       |
| File.MD5                                 | string   | File MD5                                                          |
| File.CRC32                               | string   | File CRC32                                                        |
| File.CTPH                                | string   | File CTPH                                                         |
| File.Malicious.Vendor                    | string   | For malicious files, the vendor that made the decision            |
| File.Malicious.Description               | string   | For malicious files, the reason that the vendor made the decision |
| DBotScore.Indicator                      | string   | The indicator that was tested                                     |
| DBotScore.Type                           | string   | Indicator type                                                    |
| DBotScore.Vendor                         | string   | Vendor used to calculate the score                                |
| DBotScore.Score                          | number   | The actual score                                                  |
| RecordedFuture.File.riskScore            | number   | Recorded Future Hash Risk Score                                   |
| RecordedFuture.File.riskLevel            | string   | Recorded Future Hash Risk Level                                   |
| RecordedFuture.File.Evidence.rule        | string   | Recorded Risk Rule Name                                           |
| RecordedFuture.File.Evidence.mitigation  | string   | Recorded Risk Rule Mitigation                                     |
| RecordedFuture.File.Evidence.description | string   | Recorded Risk Rule description                                    |
| RecordedFuture.File.Evidence.timestamp   | date     | Recorded Risk Rule timestamp                                      |
| RecordedFuture.File.Evidence.level       | number   | Recorded Risk Rule Level                                          |
| RecordedFuture.File.Evidence.ruleid      | string   | Recorded Risk Rule ID                                             |
| RecordedFuture.File.name                 | string   | Hash                                                              |
| RecordedFuture.File.maxRules             | number   | Maximum count of Recorded Future Hash Risk Rules                  |
| RecordedFuture.File.ruleCount            | number   | Number of triggered Recorded Future Hash Risk Rules               |
| RecordedFuture.File.rules                | string   | All the rules concatenated by comma                               |


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

| **Argument Name** | **Description**              | **Required** |
|-------------------|------------------------------|--------------|
| cve               | CVE to get the reputation of | Required     |


#### Context Output

| **Path**                                | **Type** | **Description**                                              |
|-----------------------------------------|----------|--------------------------------------------------------------|
| DBotScore.Indicator                     | string   | The indicator that was tested                                |
| DBotScore.Type                          | string   | Indicator type                                               |
| DBotScore.Vendor                        | string   | Vendor used to calculate the score                           |
| DBotScore.Score                         | number   | The actual score                                             |
| CVE.ID                                  | string   | Vulnerability name                                           |
| RecordedFuture.CVE.riskScore            | number   | Recorded Future Vulnerability Risk Score                     |
| RecordedFuture.CVE.riskLevel            | string   | Recorded Future Vulnerability Risk Level                     |
| RecordedFuture.CVE.Evidence.rule        | string   | Recorded Risk Rule Name                                      |
| RecordedFuture.CVE.Evidence.mitigation  | string   | Recorded Risk Rule Mitigation                                |
| RecordedFuture.CVE.Evidence.description | string   | Recorded Risk Rule description                               |
| RecordedFuture.CVE.Evidence.timestamp   | date     | Recorded Risk Rule timestamp                                 |
| RecordedFuture.CVE.Evidence.level       | number   | Recorded Risk Rule Level                                     |
| RecordedFuture.CVE.Evidence.ruleid      | string   | Recorded Risk Rule ID                                        |
| RecordedFuture.CVE.name                 | string   | CVE                                                          |
| RecordedFuture.CVE.maxRules             | number   | Maximum count of Recorded Future Vulnerability Risk Rules    |
| RecordedFuture.CVE.ruleCount            | number   | Number of triggered Recorded Future Vulnerability Risk Rules |
| RecordedFuture.CVE.rules                | string   | All the rules concatenated by comma                          |


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
                    "description": "1 sighting on 1 source: Recorded Future Malware Hunting. Activity seen on 1 out of the last 28 days with 24 all-time daily sightings. Exploited in the wild by 1 malware family: DroidRt. Last observed on May 23, 2020. Sample hash: ffd0d7e6ba12ed20bc17f9ea1a1323a04cbf2e03bcaec0fa9ea574d9a7fb4881.",
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
>| Very Malicious | Exploited in the Wild by Recently Active Malware | 1 sighting on 1 source: Recorded Future Malware Hunting. Activity seen on 1 out of the last 28 days with 24 all-time daily sightings. Exploited in the wild by 1 malware family: DroidRt. Last observed on May 23, 2020. Sample hash: ffd0d7e6ba12ed20bc17f9ea1a1323a04cbf2e03bcaec0fa9ea574d9a7fb4881. | 2020-05-23 00:00:00 |


### url
***
Get a quick indicator of the risk associated with a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description**              | **Required** |
|-------------------|------------------------------|--------------|
| url               | URL to get the reputation of | Required     |


#### Context Output

| **Path**                                | **Type** | **Description**                                                  |
|-----------------------------------------|----------|------------------------------------------------------------------|
| DBotScore.Indicator                     | string   | The indicator that was tested                                    |
| DBotScore.Type                          | string   | Indicator type                                                   |
| DBotScore.Vendor                        | string   | Vendor used to calculate the score                               |
| DBotScore.Score                         | number   | The actual score                                                 |
| URL.Malicious.Vendor                    | string   | For malicious URLs, the vendor that made the decision            |
| URL.Malicious.Description               | string   | For malicious URLs, the reason that the vendor made the decision |
| URL.Data                                | string   | URL name                                                         |
| RecordedFuture.URL.riskScore            | number   | Recorded Future URL Risk Score                                   |
| RecordedFuture.URL.riskLevel            | string   | Recorded Future URL Risk Level                                   |
| RecordedFuture.URL.Evidence.rule        | string   | Recorded Risk Rule Name                                          |
| RecordedFuture.URL.Evidence.mitigation  | string   | Recorded Risk Rule Mitigation                                    |
| RecordedFuture.URL.Evidence.description | string   | Recorded Risk Rule description                                   |
| RecordedFuture.URL.Evidence.timestamp   | date     | Recorded Risk Rule timestamp                                     |
| RecordedFuture.URL.Evidence.level       | number   | Recorded Risk Rule Level                                         |
| RecordedFuture.URL.Evidence.ruleid      | string   | Recorded Risk Rule ID                                            |
| RecordedFuture.URL.name                 | string   | URL                                                              |
| RecordedFuture.URL.maxRules             | number   | Maximum count of Recorded Future URL Risk Rules                  |
| RecordedFuture.URL.ruleCount            | number   | Number of triggered Recorded Future URL Risk Rules               |
| RecordedFuture.URL.rules                | string   | All the rules concatenated by comma                              |


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

| **Argument Name** | **Description**                                                   | **Required** |
|-------------------|-------------------------------------------------------------------|--------------|
| context           | Context to use for verdict                                        | Required     |
| ip                | IPs to check if they are related to the selected context.         | Optional     |
| domain            | Domains to check if they are related to the selected context.     | Optional     |
| file              | File hashes to check if they are related to the selected context. | Optional     |
| url               | URLs to check if they are related to the selected context.        | Optional     |
| cve               | CVEs to check if they are related to the selected context.        | Optional     |


#### Context Output

| **Path**                                     | **Type** | **Description**                                   |
|----------------------------------------------|----------|---------------------------------------------------|
| DBotScore.Indicator                          | string   | The indicator that was tested                     |
| DBotScore.Type                               | string   | Indicator type                                    |
| DBotScore.Vendor                             | string   | Vendor used to calculate the score                |
| DBotScore.Score                              | number   | The actual score                                  |
| File.SHA256                                  | string   | File SHA\-256                                     |
| File.SHA512                                  | string   | File SHA\-512                                     |
| File.SHA1                                    | string   | File SHA\-1                                       |
| File.MD5                                     | string   | File MD5                                          |
| File.CRC32                                   | string   | File CRC32                                        |
| File.CTPH                                    | string   | File CTPH                                         |
| IP.Address                                   | string   | IP address                                        |
| IP.Geo.Country                               | string   | IP Geolocation Country                            |
| IP.ASN                                       | string   | ASN                                               |
| Domain.Name                                  | string   | Domain name                                       |
| URL.Data                                     | string   | URL name                                          |
| CVE.ID                                       | string   | Vulnerability name                                |
| RecordedFuture.verdict                       | boolean  | Recorded Future verdict                           |
| RecordedFuture.context                       | string   | Threat Assessment Context                         |
| RecordedFuture.riskScore                     | number   | Recorded Future Max Score                         |
| RecordedFuture.Entities.id                   | string   | Entity ID                                         |
| RecordedFuture.Entities.name                 | string   | Entity Name                                       |
| RecordedFuture.Entities.type                 | string   | Entity Type                                       |
| RecordedFuture.Entities.score                | string   | Entity Score                                      |
| RecordedFuture.Entities.context              | string   | Contains the current context if there is evidence |
| RecordedFuture.Entities.Evidence.ruleid      | string   | Recorded Future Risk Rule ID                      |
| RecordedFuture.Entities.Evidence.timestamp   | date     | Recorded Future Evidence Timestamp                |
| RecordedFuture.Entities.Evidence.mitigation  | string   | Recorded Future Evidence Mitigation               |
| RecordedFuture.Entities.Evidence.description | string   | Recorded Future Evidence Description              |
| RecordedFuture.Entities.Evidence.rule        | string   | Recorded Future Risk Rule                         |
| RecordedFuture.Entities.Evidence.level       | number   | Recorded Future Risk Rule Level                   |


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

| **Argument Name** | **Description**                            | **Required** |
|-------------------|--------------------------------------------|--------------|
| rule_name         | Rule name to search, can be a partial name | Optional     |
| limit             | Number of rules to return                  | Optional     |


#### Context Output

| **Path**                      | **Type** | **Description** |
|-------------------------------|----------|-----------------|
| RecordedFuture.AlertRule.id   | string   | Alert rule ID   |
| RecordedFuture.AlertRule.name | string   | Alert rule name |


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




### recordedfuture-single-alert
***
Get single alert by name or ID.


#### Base Command

`recordedfuture-single-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| id                | Alert ID        | Required     |


#### Context Output

| **Path**                                          | **Type** | **Description**                        |
|---------------------------------------------------|----------|----------------------------------------|
| RecordedFuture.SingleAlert.id                     | string   | Recorded Future alert ID               |
| RecordedFuture.SingleAlert.flat_entities.fragment | string   | Recorded Future fragment of the entity |
| RecordedFuture.SingleAlert.flat_entities.name     | string   | Recorded Future name of the entity     |
| RecordedFuture.SingleAlert.flat_entities.type     | string   | Recorded Future type of the entity     |
| RecordedFuture.SingleAlert.flat_entities.id       | string   | Recorded Future the ID of the entity   |


#### Command Example
```!recordedfuture-single-alert id="M101QO"```

#### Context Example
```
{
    'RecordedFuture': {
        'SingleAlert': [
            {
                'review': {
                    'assignee': None,
                    'statusDate': '2022-06-06T03:04:02.980Z',
                    'statusInPortal': 'Pending',
                    'status': 'pending',
                    'noteDate': None,
                    'statusChangeBy': 'mock_user@domain.com',
                    'noteAuthor': None,
                    'note': None
                },
                'entities': [
                    {
                        'trend': {}, 'documents': [],
                        'risk': {
                            'criticalityLabel': 'Medium',
                            'score': None,
                            'documents': [
                                {
                                    'source': {'id': 'MtKtaR', 'name': 'GitHub', 'type': 'Source'},
                                    'url': 'https://github.com/author_name/vuln-list/blob/master/debian/CVE/CVE-2022-1975.json',
                                    'references': [
                                        {
                                            'entities': [
                                                {
                                                    'id': 'm34TIf', 'name': 'CVE-2022-1975',
                                                    'type': 'CyberVulnerability',
                                                    'description': 'There is a sleep-in-atomic bug in /net/nfc/netlink.c that allows an attacker to crash the Linux kernel by simulating a nfc device from user-space.'
                                                },
                                                {
                                                    'id': 'ITQ1tW', 'name': 'NFC',
                                                    'type': 'IndustryTerm'
                                                }
                                            ],
                                            'noteId': None,
                                            'fragment': '<i id=GrT41TAY-MO><e id=m34TIf>CVE-2022-1975</e>.json { "Header": { "Original": "<e id=m34TIf>CVE-2022-1975</e> [<e id=ITQ1tW>NFC</e>: netlink: fix sleep in atomic bug when firmware : fix sleep in atomic bug when firmware download timeout]" }, "Annotations</i>',
                                            'noteLink': None,
                                            'id': 'GrT41TAY-MO',
                                            'language': 'eng'
                                        }
                                    ],
                                    'authors': [
                                        {
                                            'id': 'STbLIH', 'name': 'author_name',
                                            'type': 'Username'
                                        }
                                    ],
                                    'title': 'CVE-2022-1975.json'
                                }
                            ],
                            'evidence': [
                                {
                                    'mitigationString': '',
                                    'rule': 'Web Reporting Prior to NVD Disclosure',
                                    'criticality': 'Medium',
                                    'timestamp': '2022-06-06T00:45:05.743Z',
                                    'evidence': 'Reports involving CVE Vulnerability before vulnerability specifics are disclosed by NVD.'
                                }
                            ],
                            'criticality': 2
                        },
                        'entity': {
                            'id': 'm34TIf',
                            'name': 'CVE-2022-1975',
                            'type': 'CyberVulnerability',
                            'description': 'There is a sleep-in-atomic bug in /net/nfc/netlink.c that allows an attacker to crash the Linux kernel by simulating a nfc device from user-space.'
                        }
                    }
                ],
                'url': 'https://app.recordedfuture.com/live/sc/notification/?id=M101QO',
                'rule': {
                    'name': 'Vulnerability Risk, New Critical or Pre NVD Watch List Vulnerabilities',
                    'url': 'https://app.recordedfuture.com/live/sc/ViewIdkobra_view_report_item_alert_editor?view_opts=%7B%22reportId%22%3A%22jYnLO_%22%2C%22bTitle%22%3Atrue%2C%22title%22%3A%22Vulnerability+Risk%2C+New+Critical+or+Pre+NVD+Watch+List+Vulnerabilities%22%7D',
                    'owner_id': 'uhash:12345',
                    'owner_name': 'RF - mock',
                    'id': 'jtTjt_'
                },
                'triggered': '2022-06-06T03:03:04.993Z',
                'id': 'M101QO',
                'counts': {'references': 1, 'entities': 4, 'documents': 1},
                'triggered_by': [],
                'title': 'Vulnerability Risk, New Critical or Pre NVD Watch List Vulnerabilities - ....',
                'type': 'ENTITY'
            }
        ]
    }
}

```

#### Human Readable Output

>## Vulnerability Risk, New Critical or Pre NVD Watch List Vulnerabilities - .... - 2022-06-06T03:03:04.993Z
>
>#### Status: 
>pending
>
>### Entities for alert
>| name           | type               | description                                                                                                                                                                                                                                   | risk   |
>|----------------|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|
>| CVE-2022-1975  | CyberVulnerability | There is a sleep-in-atomic bug in /net/nfc/netlink.c that allows an attacker to crash the Linux kernel by simulating a nfc device from user-space.                                                                                            | Medium |
>
>### Evidence belonging to CVE-2022-1975
>| rule                                  | criticality | evidence                                                                                 |
>|---------------------------------------|-------------|------------------------------------------------------------------------------------------|
>| Web Reporting Prior to NVD Disclosure | Medium      | Reports involving CVE Vulnerability before vulnerability specifics are disclosed by NVD. |


### recordedfuture-alerts
***
Get details on alerts configured and generated by Recorded Future by alert rule ID and/or time range.


#### Base Command

`recordedfuture-alerts`
#### Input

| **Argument Name** | **Description**                                  | **Required** |
|-------------------|--------------------------------------------------|--------------|
| rule_id           | Alert rule ID                                    | Optional     |
| limit             | Number of alerts to return                       | Optional     |
| triggered_time    | Alert triggered time, e.g., "1 hour" or "2 days" | Optional     |
| assignee          | Alert assignee's email address                   | Optional     |
| status            | Alert review status                              | Optional     |
| freetext          | Free text search                                 | Optional     |
| offset            | Alerts from offset                               | Optional     |
| orderby           | Alerts sort order                                | Optional     |
| direction         | Alerts sort direction                            | Optional     |


#### Context Output

| **Path**                       | **Type** | **Description**      |
|--------------------------------|----------|----------------------|
| RecordedFuture.Alert.id        | string   | Alert ID             |
| RecordedFuture.Alert.name      | string   | Alert name           |
| RecordedFuture.Alert.type      | string   | Alert type           |
| RecordedFuture.Alert.triggered | date     | Alert triggered time |
| RecordedFuture.Alert.status    | string   | Alert status         |
| RecordedFuture.Alert.assignee  | string   | Alert assignee       |
| RecordedFuture.Alert.rule      | string   | Alert rule name      |


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


### recordedfuture-alert-set-status
***
Set status for the alert in Recorded Future


#### Base Command

`recordedfuture-alert-set-status`
#### Input

| **Argument Name** | **Description**                                                                                                                                   | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| alert_id          | The alert id that should be moved in selected status                                                                                              | Required     |
| status            | The status string that represents status of alert in Recorded Future (e.g. unassigned, assigned, pending, dismiss, no-action, actionable, tuning) | Required     |


#### Context Output

| **Path**                          | **Type** | **Description**                      |
|-----------------------------------|----------|--------------------------------------|
| RecordedFuture.Alerts.id          | string   | Recorded Future alert id             |
| RecordedFuture.Alerts.status      | string   | Recorded Future alert status         |
| RecordedFuture.Alerts.note.text   | string   | Recorded Future alert note text      |
| RecordedFuture.Alerts.note.author | string   | Recorded Future alert note author id |
| RecordedFuture.Alerts.note.date   | string   | Recorded Future alert note date      |
| RecordedFuture.Alerts.reviewDate  | string   | Recorded Future alert get date       |



#### Command Example
```!recordedfuture-alert-set-status alert_id="asdy3l" status="no-action"```

#### Context Example
```
{
    "RecordedFuture": {
        "Alerts": [{
            "id": "jrhq5t",
            "note": {
                "author": "NUbI50w62k"
                "date": "2021-08-31T14:04:31Z"
                "text": "testing"
            }
            "reviewDate": "2021-09-01T10:09:32Z"
            "status": "no-action"
        }]
    }
}
```

#### Human Readable Output

>### Status no-action for Alert jrhrfx was successfully set


### recordedfuture-alert-set-note
***
Add note to alert in Recorded Future


#### Base Command

`recordedfuture-alert-set-note`
#### Input

| **Argument Name** | **Description**                                                | **Required** |
|-------------------|----------------------------------------------------------------|--------------|
| alert_id          | The alert id that should be moved in selected status           | Required     |
| note              | The note string that will be added to alert in Recorded Future | Required     |


#### Context Output

| **Path**                          | **Type** | **Description**                      |
|-----------------------------------|----------|--------------------------------------|
| RecordedFuture.Alerts.id          | string   | Recorded Future alert id             |
| RecordedFuture.Alerts.status      | string   | Recorded Future alert status         |
| RecordedFuture.Alerts.note.text   | string   | Recorded Future alert note text      |
| RecordedFuture.Alerts.note.author | string   | Recorded Future alert note author id |
| RecordedFuture.Alerts.note.date   | string   | Recorded Future alert note date      |
| RecordedFuture.Alerts.reviewDate  | string   | Recorded Future alert get date       |



#### Command Example
```!recordedfuture-alert-set-note alert_id="asdy3l" note="This is a note we would like to show you"```

#### Context Example
```
{
    "RecordedFuture": {
        "Alerts": [{
            "id": "jrhq5t",
            "note": {
                "author": "NUbI50w62k"
                "date": "2021-08-31T14:04:31Z"
                "text": "testing"
            }
            "reviewDate": "2021-09-01T10:09:32Z"
            "status": "no-action"
        }]
    }
}
```

#### Human Readable Output

>### Note for Alert jrhrfx was successfully set


### recordedfuture-intelligence
***
Get threat intelligence for an IP, Domain, CVE, URL or File.


#### Base Command

`recordedfuture-intelligence`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                         | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entity_type       | The type of entity to fetch context for. (Should be provided with its value in entityValue argument)                                                                                                    | Required     |
| entity            | The value of the entity to fetch context for. (Should be provided with its type in entity_type argument, Hash types supported: MD5, SHA-1, SHA-256, SHA-512, CRC32, CTPH). Vulnerability supports CVEs. | Required     |


#### Context Output

| **Path**                                                               | **Type** | **Description**                                         |
|------------------------------------------------------------------------|----------|---------------------------------------------------------|
| DBotScore.Indicator                                                    | string   | The indicator that was tested                           |
| DBotScore.Type                                                         | string   | Indicator type                                          |
| DBotScore.Vendor                                                       | string   | Vendor used to calculate the score                      |
| DBotScore.Score                                                        | number   | The actual score                                        |
| File.SHA256                                                            | string   | File SHA\-256                                           |
| File.SHA512                                                            | string   | File SHA\-512                                           |
| File.SHA1                                                              | string   | File SHA\-1                                             |
| File.MD5                                                               | string   | File MD5                                                |
| File.CRC32                                                             | string   | File CRC32                                              |
| File.CTPH                                                              | string   | File CTPH                                               |
| IP.Address                                                             | string   | IP address                                              |
| IP.ASN                                                                 | string   | ASN                                                     |
| IP.Geo.Country                                                         | string   | IP Geolocation Country                                  |
| Domain.Name                                                            | string   | Domain name                                             |
| URL.Data                                                               | string   | URL name                                                |
| CVE.ID                                                                 | string   | Vulnerability name                                      |
| RecordedFuture.IP.criticality                                          | number   | Risk Criticality                                        |
| RecordedFuture.IP.criticalityLabel                                     | string   | Risk Criticality Label                                  |
| RecordedFuture.IP.riskString                                           | string   | Risk string                                             |
| RecordedFuture.IP.riskSummary                                          | string   | Risk Summary                                            |
| RecordedFuture.IP.rules                                                | string   | Risk Rules                                              |
| RecordedFuture.Ip.concatRules                                          | string   | All risk rules concatenated by comma                    |
| RecordedFuture.IP.score                                                | number   | Risk Score                                              |
| RecordedFuture.IP.firstSeen                                            | date     | Evidence First Seen                                     |
| RecordedFuture.IP.lastSeen                                             | date     | Evidence Last Seen                                      |
| RecordedFuture.IP.intelCard                                            | string   | Recorded Future Intelligence Card URL                   |
| RecordedFuture.IP.type                                                 | string   | Entity Type                                             |
| RecordedFuture.IP.name                                                 | string   | Entity                                                  |
| RecordedFuture.IP.id                                                   | string   | Recorded Future Entity ID                               |
| RecordedFuture.IP.location.asn                                         | string   | ASN number                                              |
| RecordedFuture.IP.location.cidr.id                                     | string   | Recorded Future CIDR ID                                 |
| RecordedFuture.IP.location.cidr.name                                   | string   | CIDR                                                    |
| RecordedFuture.IP.location.cidr.type                                   | string   | CIDR Type                                               |
| RecordedFuture.IP.location.location.city                               | string   | IP Geolocation City                                     |
| RecordedFuture.IP.location.location.continent                          | string   | IP Geolocation Continent                                |
| RecordedFuture.IP.location.location.country                            | string   | IP Geolocation Country                                  |
| RecordedFuture.IP.location.organization                                | string   | IP Geolocation Organization                             |
| RecordedFuture.IP.metrics.type                                         | string   | Recorded Future Metrics Type                            |
| RecordedFuture.IP.metrics.value                                        | number   | Recorded Future Metrics Value                           |
| RecordedFuture.IP.threatLists.description                              | string   | Recorded Future Threat List Description                 |
| RecordedFuture.IP.threatLists.id                                       | string   | Recorded Future Threat List ID                          |
| RecordedFuture.IP.threatLists.name                                     | string   | Recorded Future Threat List Name                        |
| RecordedFuture.IP.threatLists.type                                     | string   | Recorded Future Threat List Type                        |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedAttacker.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedTarget.count                  | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedTarget.id                     | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedTarget.name                   | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedTarget.type                   | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedMalware.count                 | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedMalware.id                    | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedMalware.name                  | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedMalware.type                  | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.count      | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.id         | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.name       | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.type       | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.count      | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.id         | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.name       | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.type       | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedProduct.count                 | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedProduct.id                    | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedProduct.name                  | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedProduct.type                  | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedCountries.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedCountries.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedCountries.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedCountries.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedHash.count                    | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedHash.id                       | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedHash.name                     | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedHash.type                     | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedTechnology.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.count         | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.id            | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.name          | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.type          | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedOperations.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedOperations.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedOperations.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedOperations.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.relatedEntities.RelatedCompany.count                 | number   | Recorded Future Related Count                           |
| RecordedFuture.IP.relatedEntities.RelatedCompany.id                    | string   | Recorded Future Related ID                              |
| RecordedFuture.IP.relatedEntities.RelatedCompany.name                  | string   | Recorded Future Related Name                            |
| RecordedFuture.IP.relatedEntities.RelatedCompany.type                  | string   | Recorded Future Related Type                            |
| RecordedFuture.IP.analystNotes.id                                      | string   | Recorded Future analyst note ID                         |
| RecordedFuture.IP.analystNotes.source.id                               | string   | Recorded Future analyst note source ID                  |
| RecordedFuture.IP.analystNotes.source.name                             | string   | Recorded Future analyst note source name                |
| RecordedFuture.IP.analystNotes.source.type                             | string   | Recorded Future analyst note source type                |
| RecordedFuture.IP.analystNotes.attributes.text                         | string   | Recorded Future analyst note content                    |
| RecordedFuture.IP.analystNotes.attributes.title                        | string   | Recorded Future analyst note title                      |
| RecordedFuture.IP.analystNotes.attributes.published                    | string   | Recorded Future analyst note publishing time            |
| RecordedFuture.IP.analystNotes.attributes.validated_on                 | string   | Recorded Future analyst note validation time            |
| RecordedFuture.IP.analystNotes.attributes.validation_urls.type         | string   | Recorded Future analyst note validation URL entity type |
| RecordedFuture.IP.analystNotes.attributes.validation_urls.name         | string   | Recorded Future analyst note validation URL             |
| RecordedFuture.IP.analystNotes.attributes.validation_urls.id           | string   | Recorded Future analyst note validation URL ID          |
| RecordedFuture.IP.analystNotes.attributes.topic.id                     | string   | Recorded Future analyst note topic ID                   |
| RecordedFuture.IP.analystNotes.attributes.topic.name                   | string   | Recorded Future analyst note topic name                 |
| RecordedFuture.IP.analystNotes.attributes.topic.description            | string   | Recorded Future analyst note topic description          |
| RecordedFuture.IP.analystNotes.attributes.topic.type                   | string   | Recorded Future analyst note topic type                 |
| RecordedFuture.IP.analystNotes.attributes.note_entities.id             | string   | Recorded Future analyst note entity ID                  |
| RecordedFuture.IP.analystNotes.attributes.note_entities.name           | string   | Recorded Future analyst note entity name                |
| RecordedFuture.IP.analystNotes.attributes.note_entities.type           | string   | Recorded Future analyst note entity type                |
| RecordedFuture.IP.analystNotes.attributes.context_entities.id          | string   | Recorded Future analyst note context entity ID          |
| RecordedFuture.IP.analystNotes.attributes.context_entities.name        | string   | Recorded Future analyst note context entity name        |
| RecordedFuture.IP.analystNotes.attributes.context_entities.type        | string   | Recorded Future analyst note context entity type        |
| RecordedFuture.Domain.criticality                                      | number   | Risk Criticality                                        |
| RecordedFuture.Domain.criticalityLabel                                 | string   | Risk Criticality Label                                  |
| RecordedFuture.Domain.riskString                                       | string   | Risk string                                             |
| RecordedFuture.Domain.riskSummary                                      | string   | Risk Summary                                            |
| RecordedFuture.Domain.rules                                            | string   | Risk Rules                                              |
| RecordedFuture.Domain.concatRules                                      | string   | All risk rules concatenated by comma                    |
| RecordedFuture.Domain.score                                            | number   | Risk Score                                              |
| RecordedFuture.Domain.firstSeen                                        | date     | Evidence First Seen                                     |
| RecordedFuture.Domain.lastSeen                                         | date     | Evidence Last Seen                                      |
| RecordedFuture.Domain.intelCard                                        | string   | Recorded Future Intelligence Card URL                   |
| RecordedFuture.Domain.type                                             | string   | Entity Type                                             |
| RecordedFuture.Domain.name                                             | string   | Entity                                                  |
| RecordedFuture.Domain.id                                               | string   | Recorded Future Entity ID                               |
| RecordedFuture.Domain.metrics.type                                     | string   | Recorded Future Metrics Type                            |
| RecordedFuture.Domain.metrics.value                                    | number   | Recorded Future Metrics Value                           |
| RecordedFuture.Domain.threatLists.description                          | string   | Recorded Future Threat List Description                 |
| RecordedFuture.Domain.threatLists.id                                   | string   | Recorded Future Threat List ID                          |
| RecordedFuture.Domain.threatLists.name                                 | string   | Recorded Future Threat List Name                        |
| RecordedFuture.Domain.threatLists.type                                 | string   | Recorded Future Threat List Type                        |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedTarget.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.count         | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.id            | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.name          | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.type          | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedMalware.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.count  | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.id     | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.name   | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.type   | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.count  | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.id     | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.name   | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.type   | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedProduct.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedCountries.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedHash.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedHash.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedHash.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedHash.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.count          | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.id             | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.name           | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.type           | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.count        | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.id           | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.name         | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.type         | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.count        | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.id           | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.name         | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.type         | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.count     | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.id        | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.name      | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.type      | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.count          | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.id             | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.name           | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedOperations.type           | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.Domain.relatedEntities.RelatedCompany.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.Domain.analystNotes.id                                  | string   | Recorded Future analyst note ID                         |
| RecordedFuture.Domain.analystNotes.source.id                           | string   | Recorded Future analyst note source ID                  |
| RecordedFuture.Domain.analystNotes.source.name                         | string   | Recorded Future analyst note source name                |
| RecordedFuture.Domain.analystNotes.source.type                         | string   | Recorded Future analyst note source type                |
| RecordedFuture.Domain.analystNotes.attributes.text                     | string   | Recorded Future analyst note content                    |
| RecordedFuture.Domain.analystNotes.attributes.title                    | string   | Recorded Future analyst note title                      |
| RecordedFuture.Domain.analystNotes.attributes.published                | string   | Recorded Future analyst note publishing time            |
| RecordedFuture.Domain.analystNotes.attributes.validated_on             | string   | Recorded Future analyst note validation time            |
| RecordedFuture.Domain.analystNotes.attributes.validation_urls.type     | string   | Recorded Future analyst note validation URL entity type |
| RecordedFuture.Domain.analystNotes.attributes.validation_urls.name     | string   | Recorded Future analyst note validation URL             |
| RecordedFuture.Domain.analystNotes.attributes.validation_urls.id       | string   | Recorded Future analyst note validation URL ID          |
| RecordedFuture.Domain.analystNotes.attributes.topic.id                 | string   | Recorded Future analyst note topic ID                   |
| RecordedFuture.Domain.analystNotes.attributes.topic.name               | string   | Recorded Future analyst note topic name                 |
| RecordedFuture.Domain.analystNotes.attributes.topic.description        | string   | Recorded Future analyst note topic description          |
| RecordedFuture.Domain.analystNotes.attributes.topic.type               | string   | Recorded Future analyst note topic type                 |
| RecordedFuture.Domain.analystNotes.attributes.note_entities.id         | string   | Recorded Future analyst note entity ID                  |
| RecordedFuture.Domain.analystNotes.attributes.note_entities.name       | string   | Recorded Future analyst note entity name                |
| RecordedFuture.Domain.analystNotes.attributes.note_entities.type       | string   | Recorded Future analyst note entity type                |
| RecordedFuture.Domain.analystNotes.attributes.context_entities.id      | string   | Recorded Future analyst note context entity ID          |
| RecordedFuture.Domain.analystNotes.attributes.context_entities.name    | string   | Recorded Future analyst note context entity name        |
| RecordedFuture.Domain.analystNotes.attributes.context_entities.type    | string   | Recorded Future analyst note context entity type        |
| RecordedFuture.CVE.criticality                                         | number   | Risk Criticality                                        |
| RecordedFuture.CVE.criticalityLabel                                    | string   | Risk Criticality Label                                  |
| RecordedFuture.CVE.riskString                                          | string   | Risk string                                             |
| RecordedFuture.CVE.riskSummary                                         | string   | Risk Summary                                            |
| RecordedFuture.CVE.rules                                               | string   | Risk Rules                                              |
| RecordedFuture.CVE.concatRules                                         | string   | All risk rules concatenated by comma                    |
| RecordedFuture.CVE.score                                               | number   | Risk Score                                              |
| RecordedFuture.CVE.firstSeen                                           | date     | Evidence First Seen                                     |
| RecordedFuture.CVE.lastSeen                                            | date     | Evidence Last Seen                                      |
| RecordedFuture.CVE.intelCard                                           | string   | Recorded Future Intelligence Card URL                   |
| RecordedFuture.CVE.type                                                | string   | Entity Type                                             |
| RecordedFuture.CVE.name                                                | string   | Entity                                                  |
| RecordedFuture.CVE.id                                                  | string   | Recorded Future Entity ID                               |
| RecordedFuture.CVE.metrics.type                                        | string   | Recorded Future Metrics Type                            |
| RecordedFuture.CVE.metrics.value                                       | number   | Recorded Future Metrics Value                           |
| RecordedFuture.CVE.threatLists.description                             | string   | Recorded Future Threat List Description                 |
| RecordedFuture.CVE.threatLists.id                                      | string   | Recorded Future Threat List ID                          |
| RecordedFuture.CVE.threatLists.name                                    | string   | Recorded Future Threat List Name                        |
| RecordedFuture.CVE.threatLists.type                                    | string   | Recorded Future Threat List Type                        |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.count                 | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.id                    | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.name                  | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedTarget.type                  | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedMalware.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.count     | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.id        | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.name      | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.type      | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.count     | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.id        | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.name      | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.type      | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedProduct.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedCountries.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedHash.count                   | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedHash.id                      | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedHash.name                    | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedHash.type                    | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.count        | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.id           | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.name         | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.type         | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedOperations.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.CVE.relatedEntities.RelatedCompany.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.CVE.cpe                                                 | string   | Recorded Future  CPE information                        |
| RecordedFuture.CVE.hashAlgorithm                                       | string   | Hash algorithm                                          |
| RecordedFuture.CVE.relatedLinks                                        | string   | Recorded Future CVE Related Links                       |
| RecordedFuture.CVE.analystNotes.id                                     | string   | Recorded Future analyst note ID                         |
| RecordedFuture.CVE.analystNotes.source.id                              | string   | Recorded Future analyst note source ID                  |
| RecordedFuture.CVE.analystNotes.source.name                            | string   | Recorded Future analyst note source name                |
| RecordedFuture.CVE.analystNotes.source.type                            | string   | Recorded Future analyst note source type                |
| RecordedFuture.CVE.analystNotes.attributes.text                        | string   | Recorded Future analyst note content                    |
| RecordedFuture.CVE.analystNotes.attributes.title                       | string   | Recorded Future analyst note title                      |
| RecordedFuture.CVE.analystNotes.attributes.published                   | string   | Recorded Future analyst note publishing time            |
| RecordedFuture.CVE.analystNotes.attributes.validated_on                | string   | Recorded Future analyst note validation time            |
| RecordedFuture.CVE.analystNotes.attributes.validation_urls.type        | string   | Recorded Future analyst note validation URL entity type |
| RecordedFuture.CVE.analystNotes.attributes.validation_urls.name        | string   | Recorded Future analyst note validation URL             |
| RecordedFuture.CVE.analystNotes.attributes.validation_urls.id          | string   | Recorded Future analyst note validation URL ID          |
| RecordedFuture.CVE.analystNotes.attributes.topic.id                    | string   | Recorded Future analyst note topic ID                   |
| RecordedFuture.CVE.analystNotes.attributes.topic.name                  | string   | Recorded Future analyst note topic name                 |
| RecordedFuture.CVE.analystNotes.attributes.topic.description           | string   | Recorded Future analyst note topic description          |
| RecordedFuture.CVE.analystNotes.attributes.topic.type                  | string   | Recorded Future analyst note topic type                 |
| RecordedFuture.CVE.analystNotes.attributes.note_entities.id            | string   | Recorded Future analyst note entity ID                  |
| RecordedFuture.CVE.analystNotes.attributes.note_entities.name          | string   | Recorded Future analyst note entity name                |
| RecordedFuture.CVE.analystNotes.attributes.note_entities.type          | string   | Recorded Future analyst note entity type                |
| RecordedFuture.CVE.analystNotes.attributes.context_entities.id         | string   | Recorded Future analyst note context entity ID          |
| RecordedFuture.CVE.analystNotes.attributes.context_entities.name       | string   | Recorded Future analyst note context entity name        |
| RecordedFuture.CVE.analystNotes.attributes.context_entities.type       | string   | Recorded Future analyst note context entity type        |
| RecordedFuture.File.criticality                                        | number   | Risk Criticality                                        |
| RecordedFuture.File.criticalityLabel                                   | string   | Risk Criticality Label                                  |
| RecordedFuture.File.riskString                                         | string   | Risk string                                             |
| RecordedFuture.File.riskSummary                                        | string   | Risk Summary                                            |
| RecordedFuture.File.rules                                              | string   | Risk Rules                                              |
| RecordedFuture.File.concatRules                                        | string   | All risk rules concatenated by comma                    |
| RecordedFuture.File.score                                              | number   | Risk Score                                              |
| RecordedFuture.File.firstSeen                                          | date     | Evidence First Seen                                     |
| RecordedFuture.File.lastSeen                                           | date     | Evidence Last Seen                                      |
| RecordedFuture.File.intelCard                                          | string   | Recorded Future Intelligence Card URL                   |
| RecordedFuture.File.hashAlgorithm                                      | string   | Hash Algorithm                                          |
| RecordedFuture.File.type                                               | string   | Entity Type                                             |
| RecordedFuture.File.name                                               | string   | Entity                                                  |
| RecordedFuture.File.id                                                 | string   | Recorded Future Entity ID                               |
| RecordedFuture.File.metrics.type                                       | string   | Recorded Future Metrics Type                            |
| RecordedFuture.File.metrics.value                                      | number   | Recorded Future Metrics Value                           |
| RecordedFuture.File.threatLists.description                            | string   | Recorded Future Threat List Description                 |
| RecordedFuture.File.threatLists.id                                     | string   | Recorded Future Threat List ID                          |
| RecordedFuture.File.threatLists.name                                   | string   | Recorded Future Threat List Name                        |
| RecordedFuture.File.threatLists.type                                   | string   | Recorded Future Threat List Type                        |
| RecordedFuture.File.relatedEntities.RelatedAttacker.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedAttacker.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedAttacker.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedAttacker.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedTarget.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedTarget.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedTarget.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedTarget.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedThreatActor.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedMalware.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedMalware.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedMalware.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedMalware.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.count    | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.id       | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.name     | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.type     | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedIpAddress.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.count    | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.id       | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.name     | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.type     | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedProduct.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedProduct.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedProduct.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedProduct.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedCountries.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedCountries.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedCountries.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedCountries.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedHash.count                  | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedHash.id                     | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedHash.name                   | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedHash.type                   | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedTechnology.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedTechnology.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedTechnology.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedTechnology.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.count          | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.id             | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.name           | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.type           | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.count          | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.id             | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.name           | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedAttackVector.type           | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.count       | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.id          | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.name        | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.type        | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedOperations.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedOperations.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedOperations.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedOperations.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.File.relatedEntities.RelatedCompany.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.File.relatedEntities.RelatedCompany.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.File.relatedEntities.RelatedCompany.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.File.relatedEntities.RelatedCompany.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.File.analystNotes.id                                    | string   | Recorded Future analyst note ID                         |
| RecordedFuture.File.analystNotes.source.id                             | string   | Recorded Future analyst note source ID                  |
| RecordedFuture.File.analystNotes.source.name                           | string   | Recorded Future analyst note source name                |
| RecordedFuture.File.analystNotes.source.type                           | string   | Recorded Future analyst note source type                |
| RecordedFuture.File.analystNotes.attributes.text                       | string   | Recorded Future analyst note content                    |
| RecordedFuture.File.analystNotes.attributes.title                      | string   | Recorded Future analyst note title                      |
| RecordedFuture.File.analystNotes.attributes.published                  | string   | Recorded Future analyst note publishing time            |
| RecordedFuture.File.analystNotes.attributes.validated_on               | string   | Recorded Future analyst note validation time            |
| RecordedFuture.File.analystNotes.attributes.validation_urls.type       | string   | Recorded Future analyst note validation URL entity type |
| RecordedFuture.File.analystNotes.attributes.validation_urls.name       | string   | Recorded Future analyst note validation URL             |
| RecordedFuture.File.analystNotes.attributes.validation_urls.id         | string   | Recorded Future analyst note validation URL ID          |
| RecordedFuture.File.analystNotes.attributes.topic.id                   | string   | Recorded Future analyst note topic ID                   |
| RecordedFuture.File.analystNotes.attributes.topic.name                 | string   | Recorded Future analyst note topic name                 |
| RecordedFuture.File.analystNotes.attributes.topic.description          | string   | Recorded Future analyst note topic description          |
| RecordedFuture.File.analystNotes.attributes.topic.type                 | string   | Recorded Future analyst note topic type                 |
| RecordedFuture.File.analystNotes.attributes.note_entities.id           | string   | Recorded Future analyst note entity ID                  |
| RecordedFuture.File.analystNotes.attributes.note_entities.name         | string   | Recorded Future analyst note entity name                |
| RecordedFuture.File.analystNotes.attributes.note_entities.type         | string   | Recorded Future analyst note entity type                |
| RecordedFuture.File.analystNotes.attributes.context_entities.id        | string   | Recorded Future analyst note context entity ID          |
| RecordedFuture.File.analystNotes.attributes.context_entities.name      | string   | Recorded Future analyst note context entity name        |
| RecordedFuture.File.analystNotes.attributes.context_entities.type      | string   | Recorded Future analyst note context entity type        |
| RecordedFuture.URL.criticality                                         | number   | Risk Criticality                                        |
| RecordedFuture.URL.criticalityLabel                                    | string   | Risk Criticality Label                                  |
| RecordedFuture.URL.riskString                                          | string   | Risk string                                             |
| RecordedFuture.URL.riskSummary                                         | string   | Risk Summary                                            |
| RecordedFuture.URL.rules                                               | string   | Risk Rules                                              |
| RecordedFuture.URL.concatRules                                         | string   | All risk rules concatenated by comma                    |
| RecordedFuture.URL.score                                               | number   | Risk Score                                              |
| RecordedFuture.URL.firstSeen                                           | date     | Evidence First Seen                                     |
| RecordedFuture.URL.lastSeen                                            | date     | Evidence Last Seen                                      |
| RecordedFuture.URL.intelCard                                           | string   | Recorded Future Intelligence Card URL                   |
| RecordedFuture.URL.type                                                | string   | Entity Type                                             |
| RecordedFuture.URL.name                                                | string   | Entity                                                  |
| RecordedFuture.URL.id                                                  | string   | Recorded Future Entity ID                               |
| RecordedFuture.URL.metrics.type                                        | string   | Recorded Future Metrics Type                            |
| RecordedFuture.URL.metrics.value                                       | number   | Recorded Future Metrics Value                           |
| RecordedFuture.URL.threatLists.description                             | string   | Recorded Future Threat List Description                 |
| RecordedFuture.URL.threatLists.id                                      | string   | Recorded Future Threat List ID                          |
| RecordedFuture.URL.threatLists.name                                    | string   | Recorded Future Threat List Name                        |
| RecordedFuture.URL.threatLists.type                                    | string   | Recorded Future Threat List Type                        |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedAttacker.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedTarget.count                 | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedTarget.id                    | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedTarget.name                  | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedTarget.type                  | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedMalware.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedMalware.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedMalware.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedMalware.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.count     | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.id        | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.name      | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.type      | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.count     | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.id        | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.name      | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.type      | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedProduct.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedProduct.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedProduct.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedProduct.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedCountries.count              | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedCountries.id                 | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedCountries.name               | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedCountries.type               | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedHash.count                   | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedHash.id                      | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedHash.name                    | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedHash.type                    | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedTechnology.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.count        | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.id           | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.name         | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.type         | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedOperations.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedOperations.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedOperations.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedOperations.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.relatedEntities.RelatedCompany.count                | number   | Recorded Future Related Count                           |
| RecordedFuture.URL.relatedEntities.RelatedCompany.id                   | string   | Recorded Future Related ID                              |
| RecordedFuture.URL.relatedEntities.RelatedCompany.name                 | string   | Recorded Future Related Name                            |
| RecordedFuture.URL.relatedEntities.RelatedCompany.type                 | string   | Recorded Future Related Type                            |
| RecordedFuture.URL.analystNotes.id                                     | string   | Recorded Future analyst note ID                         |
| RecordedFuture.URL.analystNotes.source.id                              | string   | Recorded Future analyst note source ID                  |
| RecordedFuture.URL.analystNotes.source.name                            | string   | Recorded Future analyst note source name                |
| RecordedFuture.URL.analystNotes.source.type                            | string   | Recorded Future analyst note source type                |
| RecordedFuture.URL.analystNotes.attributes.text                        | string   | Recorded Future analyst note content                    |
| RecordedFuture.URL.analystNotes.attributes.title                       | string   | Recorded Future analyst note title                      |
| RecordedFuture.URL.analystNotes.attributes.published                   | string   | Recorded Future analyst note publishing time            |
| RecordedFuture.URL.analystNotes.attributes.validated_on                | string   | Recorded Future analyst note validation time            |
| RecordedFuture.URL.analystNotes.attributes.validation_urls.type        | string   | Recorded Future analyst note validation URL entity type |
| RecordedFuture.URL.analystNotes.attributes.validation_urls.name        | string   | Recorded Future analyst note validation URL             |
| RecordedFuture.URL.analystNotes.attributes.validation_urls.id          | string   | Recorded Future analyst note validation URL ID          |
| RecordedFuture.URL.analystNotes.attributes.topic.id                    | string   | Recorded Future analyst note topic ID                   |
| RecordedFuture.URL.analystNotes.attributes.topic.name                  | string   | Recorded Future analyst note topic name                 |
| RecordedFuture.URL.analystNotes.attributes.topic.description           | string   | Recorded Future analyst note topic description          |
| RecordedFuture.URL.analystNotes.attributes.topic.type                  | string   | Recorded Future analyst note topic type                 |
| RecordedFuture.URL.analystNotes.attributes.note_entities.id            | string   | Recorded Future analyst note entity ID                  |
| RecordedFuture.URL.analystNotes.attributes.note_entities.name          | string   | Recorded Future analyst note entity name                |
| RecordedFuture.URL.analystNotes.attributes.note_entities.type          | string   | Recorded Future analyst note entity type                |
| RecordedFuture.URL.analystNotes.attributes.context_entities.id         | string   | Recorded Future analyst note context entity ID          |
| RecordedFuture.URL.analystNotes.attributes.context_entities.name       | string   | Recorded Future analyst note context entity name        |
| RecordedFuture.URL.analystNotes.attributes.context_entities.type       | string   | Recorded Future analyst note context entity type        |
| RecordedFuture.Malware.id                                              | string   | Recorded Future malware ID                              |
| RecordedFuture.Malware.name                                            | string   | Recorded Future malware entity name                     |
| RecordedFuture.Malware.type                                            | string   | Recorded Future malware entity type                     |
| RecordedFuture.Malware.categories.type                                 | string   | Recorded Future malware category type                   |
| RecordedFuture.Malware.categories.name                                 | string   | Recorded Future malware category name                   |
| RecordedFuture.Malware.categories.id                                   | string   | Recorded Future malware category ID                     |
| RecordedFuture.Malware.intelCard                                       | string   | Recorded Future intelligence card URL                   |
| RecordedFuture.Malware.firstSeen                                       | string   | Recorded Future evidence first seen.                    |
| RecordedFuture.Malware.lastSeen                                        | string   | Recorded Future evidence last seen.                     |
| RecordedFuture.Malware.metrics.type                                    | string   | Recorded Future metrics type                            |
| RecordedFuture.Malware.metrics.value                                   | number   | Recorded Future metrics value                           |
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.count           | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.id              | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.name            | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.type            | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedTarget.count             | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedTarget.id                | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedTarget.name              | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedTarget.type              | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.count        | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.id           | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.name         | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.type         | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedMalware.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedMalware.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedMalware.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedMalware.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.count | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.id    | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.name  | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.type  | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.count          | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.id             | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.name           | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.type           | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.count | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.id    | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.name  | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.type  | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedProduct.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedProduct.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedProduct.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedProduct.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedCountries.count          | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedCountries.id             | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedCountries.name           | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedCountries.type           | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedHash.count               | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedHash.id                  | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedHash.name                | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedHash.type                | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.count         | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.id            | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.name          | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.type          | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.count       | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.id          | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.name        | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.type        | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.count       | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.id          | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.name        | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.type        | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.count    | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.id       | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.name     | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.type     | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedOperations.count         | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedOperations.id            | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedOperations.name          | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedOperations.type          | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.relatedEntities.RelatedCompany.count            | number   | Recorded Future Related Count                           |
| RecordedFuture.Malware.relatedEntities.RelatedCompany.id               | string   | Recorded Future Related ID                              |
| RecordedFuture.Malware.relatedEntities.RelatedCompany.name             | string   | Recorded Future Related Name                            |
| RecordedFuture.Malware.relatedEntities.RelatedCompany.type             | string   | Recorded Future Related Type                            |
| RecordedFuture.Malware.analystNotes.id                                 | string   | Recorded Future analyst note ID                         |
| RecordedFuture.Malware.analystNotes.source.id                          | string   | Recorded Future analyst note source ID                  |
| RecordedFuture.Malware.analystNotes.source.name                        | string   | Recorded Future analyst note source name                |
| RecordedFuture.Malware.analystNotes.source.type                        | string   | Recorded Future analyst note source type                |
| RecordedFuture.Malware.analystNotes.attributes.text                    | string   | Recorded Future analyst note content                    |
| RecordedFuture.Malware.analystNotes.attributes.title                   | string   | Recorded Future analyst note title                      |
| RecordedFuture.Malware.analystNotes.attributes.published               | string   | Recorded Future analyst note publishing time            |
| RecordedFuture.Malware.analystNotes.attributes.validated_on            | string   | Recorded Future analyst note validation time            |
| RecordedFuture.Malware.analystNotes.attributes.validation_urls.type    | string   | Recorded Future analyst note validation URL entity type |
| RecordedFuture.Malware.analystNotes.attributes.validation_urls.name    | string   | Recorded Future analyst note validation URL             |
| RecordedFuture.Malware.analystNotes.attributes.validation_urls.id      | string   | Recorded Future analyst note validation URL ID          |
| RecordedFuture.Malware.analystNotes.attributes.topic.id                | string   | Recorded Future analyst note topic ID                   |
| RecordedFuture.Malware.analystNotes.attributes.topic.name              | string   | Recorded Future analyst note topic name                 |
| RecordedFuture.Malware.analystNotes.attributes.topic.description       | string   | Recorded Future analyst note topic description          |
| RecordedFuture.Malware.analystNotes.attributes.topic.type              | string   | Recorded Future analyst note topic type                 |
| RecordedFuture.Malware.analystNotes.attributes.note_entities.id        | string   | Recorded Future analyst note entity ID                  |
| RecordedFuture.Malware.analystNotes.attributes.note_entities.name      | string   | Recorded Future analyst note entity name                |
| RecordedFuture.Malware.analystNotes.attributes.note_entities.type      | string   | Recorded Future analyst note entity type                |
| RecordedFuture.Malware.analystNotes.attributes.context_entities.id     | string   | Recorded Future analyst note context entity ID          |
| RecordedFuture.Malware.analystNotes.attributes.context_entities.name   | string   | Recorded Future analyst note context entity name        |
| RecordedFuture.Malware.analystNotes.attributes.context_entities.type   | string   | Recorded Future analyst note context entity type        |


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
                    "description": "This list consists of DNS public or open DNS servers and is an absolute allow list for Risk Scoring.",
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
>| DNS Server List (White List) | This list consists of DNS public or open DNS servers and is an absolute allow list for Risk Scoring. |


### recordedfuture-links
***
Get Insikt Group Research Links for an IP, Domain, CVE, URL or File.


#### Base Command

`recordedfuture-links`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                       | **Required** |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entity_type       | The type of entity to fetch links for. (Should be provided with its value in entityValue argument)                                                                                                    | Required     |
| entity            | The value of the entity to fetch links for. (Should be provided with its type in entity_type argument, Hash types supported: MD5, SHA-1, SHA-256, SHA-512, CRC32, CTPH). Vulnerability supports CVEs. | Required     |


#### Context Output

| **Path**                                  | **Type** | **Description**                        |
|-------------------------------------------|----------|----------------------------------------|
| RecordedFuture.Links.category             | string   | Recorded Future Links Category         |
| RecordedFuture.Links.type                 | string   | Recorded Future Links Type             |
| RecordedFuture.Links.lists.entity_type    | string   | Recorded Future Links Entity Type      |
| RecordedFuture.Links.lists.entities.name  | string   | Recorded Future Link Entity Name       |
| RecordedFuture.Links.lists.entities.type  | string   | Recorded Future Link Entity Type       |
| RecordedFuture.Links.lists.entities.score | number   | Recorded Future Link Entity Risk Score |


#### Command Example
```!recordedfuture-links entity="152.169.22.67" entity_type="ip"```

#### Context Example
```
{
    "RecordedFuture": {
        "Links": {
            "Insikt Group Research Links": [
                {
                    "category": "Actors, Tools & TTPs",
                    "lists": [
                        {
                            "entities": [
                                {
                                    "name": "Zero Day Exploit",
                                    "score": null,
                                    "type": "AttackVector",
                                }
                            ]
                            "entity_type": "Attack Vector",

                        }
                    ]
                },
                {
                    "category":"Indicators & Detection Rules",
                    "lists": [
                        {
                            "entity_type":"IP address",
                            "entities": [
                                {
                                    "name": "125.62.192.220",
                                    "score": 69,
                                    "type": "IpAddress",
                                },
                                {
                                    "name": "22.33.66.85",
                                    "score": 33,
                                    "type": "IpAddress",
                                }
                            ]
                        }
                    ]
                }
            ],
            "Technical Links": [
                {
                    "category": "Actors, Tools & TTPs",
                    "lists": [
                        {
                            "entities": [
                                {
                                    "name": "TA0011",
                                    "score": null,
                                    "type": "MitreAttackIdentifier",
                                }
                            ]
                            "entity_type": "MITRE ATT&CK Identifier",

                        },
                    ]
                },
            ]
        }
    }
}
```

#### Human Readable Output

>### Insikt Group Research Links for: 152.169.22.67
>#### Category Actors, Tools & TTPs
>---
>| Attack Vector |
>|---|
>| Zero Day Exploit |
>
>#### Indicators & Detection Rules
>---
>| IP address |
>|---|
>| 125.62.192.220 |
>| 22.33.66.85 |





### recordedfuture-malware-search
***
Search for Malware.


#### Base Command

`recordedfuture-malware-search`
#### Input

| **Argument Name** | **Description**                             | **Required** |
|-------------------|---------------------------------------------|--------------|
| freetext          | Part of malware name or ID to search for    | Not Required |
| limit             | How many records to retrieve (default = 10) | Not Required |


#### Context Output

| **Path**                         | **Type** | **Description**                                  |
|----------------------------------|----------|--------------------------------------------------|
| RecordedFuture.Malware.id        | string   | Recorded Future malware ID                       |
| RecordedFuture.Malware.name      | string   | Recorded Future entity name                      |
| RecordedFuture.Malware.type      | string   | Recorded Future entity type (always = "Malware") |
| RecordedFuture.Malware.intelCard | string   | Recorded Future intelligence card URL            |

#### Command Example
```!recordedfuture-malware-search freetext="Metasplo" limit=50```

#### Context Example
```
{ 
    "RecordedFuture": {
        "Malware":[
            {
                "id": "KtTj13",
                "intelCard": "https://app.recordedfuture.com/live/sc/entity/KtTj13",
                "name": "Metasploit",
                "type": "Malware"
            },
            {
                "id": "dTuv_m",
                "intelCard": "https://app.recordedfuture.com/live/sc/entity/dTuv_m",
                "name": "Metasploit",
                "type": "Malware"
            },
            {
                "id": "FtI1Y",
                "intelCard": "https://app.recordedfuture.com/live/sc/entity/FtI1Y",
                "name": "Metasploit Framework",
                "type": "Malware"
            },
            {
                "id": "VRtY3E",
                "intelCard": "https://app.recordedfuture.com/live/sc/entity/VRtY3E",
                "name": "Metasploit Pro Patcher",
                "type": "Malware"
            },
            {
                "id": "Qtf3ah",
                "intelCard": "https://app.recordedfuture.com/live/sc/entity/Qtf3ah",
                "name": "Meterpreter Metasploit",
                "type": "Malware"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results for malware search
>| **id** | **name**               | **Intelligence card URL**                            |
>|--------|------------------------|------------------------------------------------------|
>| FtI1Y  | Metasploit Framework   | https://app.recordedfuture.com/live/sc/entity/FtI1Y  |
>| KtTj13 | Metasploit             | https://app.recordedfuture.com/live/sc/entity/KtTj13 |
>| VRtY3E | Metasploit Pro Patcher | https://app.recordedfuture.com/live/sc/entity/VRtY3E |
>| dTuv_m | Metasploit             | https://app.recordedfuture.com/live/sc/entity/dTuv_m |
>| Qtf3ah | Meterpreter Metasploit | https://app.recordedfuture.com/live/sc/entity/Qtf3ah |


## Fetch Incidents
You can fetch Recorded Future Alerts and work with them as XSOAR Incidents. When pulling the alert we set it status to pending and we only pull alerts with status no-acction("New" in UI). There are three parameters that you can specify.


| **Argument Name**                          | **Format**                                                       | **Description**                            | **Required** | **Default value** |
|--------------------------------------------|------------------------------------------------------------------|--------------------------------------------|--------------|-------------------|
| First fetch time                           | [number] [time unit], e.g. 12 hours, 7 days, 3 months, 1 year    | First period to fetch alerts from          | Not Required | 24 hours          |
| Max number of incident to pull in one call | Number e.g 1 , 3 , 4                                             | Specify how much alerts to pull in one run | Not Required | 50                |
| Incidents Fetch Interval                   | [number] [time unit][number] [time unit]  e.g. 1 hour 30 minutes | Specify time interval between every pull   | Required     | 1 minute          |


### Fetched Incidents Data
```
"data": {
    "rule": {
      "url": "https://app.recordedfuture.com/live/sc/ViewIdkobra_view_report_item_alert_editor?view_opts=%7B%22reportId%22%3A%22Y8d2JN%22%2C%22bTitle%22%3Atrue%2C%22title%22%3A%22DJIA+Cyber%22%7D&amp;state.bNavbar=false",
      "name": "DJIA Cyber",
      "id": "Y8d2JN"
    },
    "type": "EVENT",
    "entities": [
      {
        "entity": null,
        "risk": {},
        "trend": {},
        "documents": [
          {
            "references": [
              {
                "fragment": "This malware can steal passwords, credit card info in Chrome, Safari.",
                "entities": [
                  {
                    "id": "czhXN",
                    "name": "PT Reliance Securities Tbk",
                    "type": "Company"
                  },
                  {
                    "id": "B_sMd",
                    "name": "Apple Safari",
                    "type": "Product"
                  },
                  {
                    "id": "B_tZO",
                    "name": "Palo Alto Networks",
                    "type": "Company"
                  },
                  {
                    "id": "GARXk",
                    "name": "MSMEs",
                    "type": "Company"
                  },
                  {
                    "id": "B_LyO",
                    "name": "Apple",
                    "type": "Company"
                  },
                  {
                    "id": "B_HE4",
                    "name": "Google",
                    "type": "Company"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "KFGeiP",
              "name": "CanIndia NEWS",
              "type": "Source"
            },
            "url": "http://www.canindia.com/this-malware-can-steal-passwords-credit-card-info-in-chrome-safari/",
            "title": "This malware can steal passwords, credit card info in Chrome, Safari"
          },
          {
            "references": [
              {
                "fragment": "Malicious code hidden in the Windows registry.",
                "entities": [
                  {
                    "id": "B_Hs5",
                    "name": "F5 Networks",
                    "type": "Company"
                  },
                  {
                    "id": "B_E-R",
                    "name": "Twitter",
                    "type": "Company"
                  },
                  {
                    "id": "J0LOpv",
                    "name": "Malicious code",
                    "type": "AttackVector"
                  },
                  {
                    "id": "Y97Q48",
                    "name": "HTML Signature Solutions",
                    "type": "Company"
                  },
                  {
                    "id": "CBJSs",
                    "name": "LinkedIn",
                    "type": "Company"
                  },
                  {
                    "id": "B_HOS",
                    "name": "Microsoft Windows",
                    "type": "Product"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "RrKkHT",
              "name": "F5 Networks",
              "type": "Source"
            },
            "url": "https://www.f5.com/labs/articles/threat-intelligence/gozi-adds-evasion-techniques-to-its-growing-bag-of-tricks",
            "title": null
          },
          {
            "references": [
              {
                "fragment": "The company noted in a blog post the ransomware had infected more than 100 Windows servers by exploiting several web application vulnerabilities, and the number of victims was rising.",
                "entities": [
                  {
                    "id": "Cq3eF",
                    "name": "Web application vulnerabilities",
                    "type": "IndustryTerm"
                  },
                  {
                    "id": "J0Nl-p",
                    "name": "Ransomware",
                    "type": "MalwareCategory"
                  },
                  {
                    "id": "B_HOS",
                    "name": "Microsoft Windows",
                    "type": "Product"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "The company noted in a blog post the ransomware had infected more than 100 Windows servers by exploiting several web application vulnerabilities, and the number of victims was rising.",
                "entities": [
                  {
                    "id": "Cq3eF",
                    "name": "Web application vulnerabilities",
                    "type": "IndustryTerm"
                  },
                  {
                    "id": "J0Nl-p",
                    "name": "Ransomware",
                    "type": "MalwareCategory"
                  },
                  {
                    "id": "B_HOS",
                    "name": "Microsoft Windows",
                    "type": "Product"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "idn:8btc.com",
              "name": "8btc.com",
              "type": "InternetDomainName"
            },
            "url": "https://news.8btc.com/an-upgraded-satan-ransomware-infects-hundreds-of-windows-servers-in-china-demanding-a-ransom-of-1-bitcoin-within-3-days",
            "title": "An Upgraded Satan Ransomware Infects Hundreds of Windows Servers in China, Demanding a Ransom of 1 Bitcoin Within 3 Days | NEWS.8BTC.COM."
          },
          {
            "references": [
              {
                "fragment": "example.gmail.com|1qazse4r",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|snapy573",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|ric290888",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|cumicumi49",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|20may1993",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|04041995",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|lk63864551",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|mememesheryl",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|danubrata45",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|miracles7",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|albert",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|14Oktober1998",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|1234qwer",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|dwitamaalfred",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|oliviaagnes",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|5148520362",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|kucit11",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|n1kuailema",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|limajuli",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|tasyakevinrio",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|747474",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|sanurlovers",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|bologe10101994",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|flymuc12",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|donnie",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|g153ll3",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|kolonel8",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|Na11032009",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|gogle05",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|my9snapy",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|bani2005",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|mala2581998",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|961501",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|april322912",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|dalshabet2012",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|vicha1002",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|0811570188",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|amidala7",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|janand",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|cheptie",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|Dealova33",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|jss231094",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|arschgeil00",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|burlgoat97",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|Ahau7296",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|gilaabis",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|123456",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|Tiffani16694",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              },
              {
                "fragment": "example.gmail.com|4ndr15ukm4v4r094",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "Jv_xrR",
              "name": "PasteBin",
              "type": "Source"
            },
            "url": "https://pastebin.com/20WrvAKf",
            "title": "5K empas Indo + Bonus"
          },
          {
            "references": [
              {
                "fragment": "| [+] E-mail Found: example.gmail.com",
                "entities": [
                  {
                    "id": "email:example.gmail.com",
                    "name": "example.gmail.com",
                    "type": "EmailAddress"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "Jv_xrR",
              "name": "PasteBin",
              "type": "Source"
            },
            "url": "https://pastebin.com/Ntk14mse",
            "title": "Anonymous JTSEC #OpIsis Full Recon #11"
          },
          {
            "references": [
              {
                "fragment": "I remember reading that it was made loose on purpose so cords don't bring your Mac down if they're tripped over.",
                "entities": [
                  {
                    "id": "BBh7yv",
                    "name": "Mac",
                    "type": "Product"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "TiY1wz",
              "name": "Apple devices",
              "type": "Source"
            },
            "url": "https://www.reddit.com/r/apple/comments/aljr4z/apple_testing_iphones_with_usbc_port/efi3j06/",
            "title": "/u/ccrama on Apple testing iPhones with USB-C port"
          },
          {
            "references": [
              {
                "fragment": "App Store, iTunes Store, Apple Music been down for several hours now! @AppleSupport.",
                "entities": [
                  {
                    "id": "JZHhWg",
                    "name": "Apple iTunes",
                    "type": "Product"
                  },
                  {
                    "id": "QGkOLY",
                    "name": "@AppleSupport",
                    "type": "Username"
                  },
                  {
                    "id": "B_LyO",
                    "name": "Apple",
                    "type": "Company"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "BV5",
              "name": "Twitter",
              "type": "Source"
            },
            "url": "https://twitter.com/PRHTH/statuses/1091215388086394880",
            "title": "App Store, iTunes Store , Apple Music down พร้อมกันหมดเลยจ้า หลายชั่วโมงแล้ว \n\nApp Store, iTunes Store, Apple Music been down for several hours now! @AppleSupport"
          },
          {
            "references": [
              {
                "fragment": "An Upgraded Satan Ransomware Infects Hundreds of Windows Servers in China, Demanding a Ransom of 1 Bitcoin Within 3 Days - 8BTC via BTCnews #Bitcoin https://t.co/1YEkzEdO92.",
                "entities": [
                  {
                    "id": "B75KVV",
                    "name": "via",
                    "type": "IndustryTerm"
                  },
                  {
                    "id": "url:https://news.8btc.com/an-upgraded-satan-ransomware-infects-hundreds-of-windows-servers-in-china-demanding-a-ransom-of-1-bitcoin-within-3-days",
                    "name": "https://news.8btc.com/an-upgraded-satan-ransomware-infects-hundreds-of-windows-servers-in-china-demanding-a-ransom-of-1-bitcoin-within-3-days",
                    "type": "URL"
                  },
                  {
                    "id": "IH6pHd",
                    "name": "Bitcoin",
                    "type": "Technology"
                  },
                  {
                    "id": "Kei3LZ",
                    "name": "#Bitcoin",
                    "type": "Hashtag"
                  },
                  {
                    "id": "SePISm",
                    "name": "Satan",
                    "type": "Malware"
                  },
                  {
                    "id": "B_FNa",
                    "name": "China",
                    "type": "Country"
                  },
                  {
                    "id": "J0Nl-p",
                    "name": "Ransomware",
                    "type": "MalwareCategory"
                  },
                  {
                    "id": "B_HOS",
                    "name": "Microsoft Windows",
                    "type": "Product"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "BV5",
              "name": "Twitter",
              "type": "Source"
            },
            "url": "https://twitter.com/btcnewsapp/statuses/1091268383180537856",
            "title": "An Upgraded Satan Ransomware Infects Hundreds of Windows Servers in China, Demanding a Ransom of 1 Bitcoin Within 3 Days - 8BTC via BTCnews #Bitcoin https://t.co/1YEkzEdO92"
          },
          {
            "references": [
              {
                "fragment": "@Apple Flaw that allows hacker to access target mic, camera, location, memory.",
                "entities": [
                  {
                    "id": "P_iscR",
                    "name": "@Apple",
                    "type": "Username"
                  }
                ],
                "language": "eng"
              }
            ],
            "source": {
              "id": "BV5",
              "name": "Twitter",
              "type": "Source"
            },
            "url": "https://twitter.com/ganag92444992/statuses/1091257432662134784",
            "title": "@Apple Flaw that allows hacker to access target mic, camera, location, memory.\nAny remedy for that? Targetted due to that flaw\nSo not  #iOS #Apple #iphone  #hacker #HackerNews #cybersecurity #privacy #HumanRights #surveillance #DataSecurity #DataProtection"
          }
        ]
      }
    ],
    "review": {
      "noteDate": null,
      "note": null,
      "noteAuthor": null,
      "assignee": null,
      "status": "no-action"
    },
    "url": "https://app.recordedfuture.com/live/sc/notification/?id=Y9-jli",
    "triggered": "2019-02-01T09:58:13.564Z",
    "title": "DJIA Cyber - New references in 9 documents",
    "counts": {
      "references": 58,
      "entities": 0,
      "documents": 9
    },
    "id": "Y9-jli"
  }
}
```
