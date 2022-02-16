## Overview
---

Use the Chronicle integration to retrieve Asset alerts or IOC Domain matches as Incidents. Use it to fetch a list of infected assets based on the indicator accessed. This integration also provides reputation and threat enrichment of indicators observed in the enterprise.

**Note:** The `gcb-list-alerts` command would fetch both Asset as well as User alerts depending upon the argument `alert_type`. In this case, the total number of alerts fetched might not match with the value of the page_size argument and this is a known behaviour with respect to the endpoint from which we are fetching the alerts.

**Note:** The `gcb-list-rules` command would filter rules depending upon the argument `live_rule`.In this case, the total number of rules fetched might not match with the value of the page_size argument and this is a known behaviour with respect to the endpoint from which we are fetching the rules.
#### Troubleshoot

##### Problem #1
Cortex XSOAR invokes data pull every minute and looks for alerts/events generated at the last minute. The alert/event has 2 timestamps; the time when the event was generated (event timestamp) on the source product(EDR, Firewall, etc) and the event hit Chronicle(ingestion timestamp).

Considering the latency of the data pipeline usually, the ingestion timestamp can be significantly delayed compared to the event timestamp. Given the fact that Chronicle APIs fetches the alerts/events based on event timestamp, if queried in real-time there are high chances of the alerts getting missed. Considering Cortex XSOAR queries for events in the last 1 minute and if the pipeline latency is greater than a minute, such events are missed in Cortex XSOAR.

##### Solution #1
In order to fetch the missed events, the ingestion should query the historical time range. i.e. the time window to query needs to be increased from the current last minute to a larger window (15 mins, 30 mins, etc). The time window parameter in the integration configuration is provided to achieve the same. Select the time window to query Chronicle with a historical time range. While selecting the time window consider the time delay for an event to appear in Chronicle after generation.

##### Problem #2
Duplication of rule detection incidents when fetched from Chronicle.

##### Solution #2
- The incidents are re-fetched starting from first fetch time window when user resets the last run time stamp. 
- To avoid duplication of incidents with duplicate detection ids and to drop them, XSOAR provides inbuilt features of Pre-process rules. 
- This setting XSOAR platform end users have to set on their own as it's not part of the integration pack.
- Pre-processing rules enable users to perform certain actions on incidents as they are ingested into XSOAR. 
- Using these rules users can choose incoming events on which to perform actions for example drop all the incoming incidents, drop and update incoming incidents if certain conditions are met.
- Please refer for information on Pre-Process rules:
  https://xsoar.pan.dev/docs/incidents/incident-pre-processing#:~:text=Creating%20Rules&text=Navigate%20to%20Settings%20%3E%20Integrations%20%3E%20Pre,viewing%20the%20list%20of%20rules.

## FAQ - Fetch Detections

##### Question #1
If we have 3 rules added in the configuration (R1, R2, R3) and we are getting 429 or 500 errors in R2. Will my integration stop fetching the detections or will it fetch detections of rule R3?

###### Case #1: When HTTP 429 error resumes before 60 retry attempts:

- System will re-attempt to fetch the detection after 1 min for the same R2 rule. The system will re-attempt to get the detections for Rule R2, 60 times.
If 429 error is recovered before 60 attempts, the system will fetch the detections for Rule R2 and then proceed ahead for Rule R3.

###### Case #2: When HTTP 429 error does not resume for 60 retry attempts:

- System will re-attempt after 1 min for the same R2 rule. The system will re-attempt to get the detections for Rule R2 60 times.
If 429 error does not recover for 60 attempts, the system will skip Rule R2 and then proceed ahead for rule R3 to fetch its detections by adding a log.

##### Question #2
What if R1 is an invalid rule id? Would it be able to fetch R2 and R3 detections?

- There will not be any retry attempts for invalid rule ids. The system will skip the invalid rule ids and move to the next rule id. So if R1 is invalid, the system will skip it without any retry attempts and move to R2.

##### Question #3
What if R1 is deleted rule id? Would it be able to fetch R2 and R3 detections?

- There will not be any retry attempts for deleted rule ids. The system will skip the deleted rule ids and move to the next rule id. So if R1 is deleted, the system will skip it without any retry attempts and move to R2.

## Configure Chronicle on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Chronicle.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __User's Service Account JSON__
    * __Region__: Select the region based on the location of the chronicle backstory instance.
    * __Provide comma(',') separated categories (e.g. APT-Activity, Phishing). Indicators belonging to these "categories" would be considered as "malicious" when executing reputation commands.__
    * __Provide comma(',') separated categories (e.g. Unwanted, VirusTotal YARA Rule Match). Indicators belonging to these "categories" would be considered as "suspicious" when executing reputation commands.__
    * __Specify the "severity" of indicator that should be considered as "malicious" irrespective of the category.  If you wish to consider all indicators with High severity as Malicious, set this parameter to 'High'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only.__
    * __Specify the "severity" of indicator that should be considered as "suspicious" irrespective of the category. If you wish to consider all indicators with Medium severity as Suspicious, set this parameter to 'Medium'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only.__
    * __Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "malicious". The value provided should be greater than the suspicious threshold. This configuration is applicable to reputation commands only.__
    * __Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "suspicious". The value provided should be smaller than the malicious threshold. This configuration is applicable to reputation commands only.__
    * __Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "malicious". The confidence level configured should have higher precedence than the suspicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH.__
    * __Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "suspicious". The confidence level configured should have lesser precedence than the malicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH.__
    * __Fetches incidents__
    * __First fetch time interval. The time range to consider for initial data fetch.(&lt;number&gt; &lt;unit&gt;, e.g., 1 day, 7 days, 3 months, 1 year).__
    * __How many incidents to fetch each time__
    * __Chronicle Alert Type (Select the type of data to consider for fetch incidents)__
    * __Time window (in minutes)__
    * __Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection).__
    * __Detections to fetch by Rule ID or Version ID__
    * __Fetch all live rules detections__
    * __Filter detections by alert state__
    * __List Basis__  
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Fetched Incidents Data
---
Fetch-incidents feature can pull events from Google Chronicle which can be converted into actionable incidents for further investigation. It is the function that Cortex XSOAR calls every minute to import new incidents and can be enabled by the "Fetches incidents" parameter in the integration configuration.

#### Configuration Parameters for Fetch-incidents
 - First fetch time interval. The time range to consider for initial data fetch.(&lt;number&gt; &lt;unit&gt;, e.g. 1 day, 7 days, 3 months, 1 year): **Default** 3 days
 - How many incidents to fetch each time: **Default** 10
 - Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection). **Only applicable for asset alerts**.
 - Chronicle Alert Type (Select the type of data to consider for fetch incidents):
   - IOC Domain matches **Default**
   - Assets with alerts
   - Detection alerts
   - User alerts
 - Time window (in minutes): **Not applicable for IOC Domain matches**
    - 15 **Default**
    - 30
    - 45
    - 60
 - Detections to fetch by Rule ID or Version ID **Only applicable for Detection alerts**
 - Fetch all live rules detections **Only applicable for Detection alerts**
 - Filter detections by alert state: **Only applicable for Detection alerts**
   - ALERTING
   - NOT ALERTING
 
| **Name** | **Initial Value** |
| --- | --- |
| First fetch time interval. The time range to consider for initial data fetch.(&lt;number&gt; &lt;unit&gt;, e.g. 1 day, 7 days, 3 months, 1 year). | 3 days |
| How many incidents to fetch each time. | 10 |
| Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection). *Only applicable for asset alerts.* | Default No Selection |
| Chronicle Alert Type (Select the type of data to consider for fetch incidents). | IOC Domain matches (Default), Assets with alerts, Detection alerts and User alerts | 
| Time window (in minutes) | 15 |
| Detections to fetch by Rule ID or Version ID | empty |
| Fetch all live rules detections | Not selected |
| Filter detections by alert state | Not selected |

#### Incident field mapping - Asset Alerts
| **Name** | **Initial Value** |
| --- | --- |
| name | &lt;AlertName&gt; for &lt;Asset&gt; |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |
| severity | Severity of Alert |

#### Incident field mapping - IOC Domain matches
| **Name** | **Initial Value** |
| --- | --- |
| name | IOC Domain Match: &lt;Artifact&gt; |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |

#### Incident field mapping - Detection Alerts
| **Name** | **Initial Value** |
| --- | --- |
| name | &lt;RuleName&gt; |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |

#### Incident field mapping - User Alerts
| **Name** | **Initial Value** |
| --- | --- |
| name | &lt;AlertName&gt; for &lt;User&gt; |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. gcb-list-iocs
2. gcb-assets
3. ip
4. domain
5. gcb-ioc-details
6. gcb-list-alerts
7. gcb-list-events
8. gcb-list-detections
9. gcb-list-rules
### 1. gcb-list-iocs
---
Lists the IOC Domain matches within your enterprise for the specified time interval. The indicator of compromise (IOC) domain matches lists for which the domains that your security infrastructure has flagged as both suspicious and that have been seen recently within your enterprise.

##### Base Command

`gcb-list-iocs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetches IOC Domain matches in the specified time interval. If configured, overrides the start_time argument. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. The default is 10000. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name of the artifact. | 
| GoogleChronicleBackstory.Iocs.Artifact | String | The Indicator artifact. | 
| GoogleChronicleBackstory.Iocs.IocIngestTime | Date | Time(UTC) the IOC was first seen by Chronicle. | 
| GoogleChronicleBackstory.Iocs.FirstAccessedTime | Date | Time(UTC) the artifact was first seen within your enterprise. | 
| GoogleChronicleBackstory.Iocs.LastAccessedTime | Date | Time(UTC) the artifact was most recently seen within your enterprise. | 
| GoogleChronicleBackstory.Iocs.Sources.Category | String | Source Category represents the behavior of the artifact. | 
| GoogleChronicleBackstory.Iocs.Sources.IntRawConfidenceScore | Number | The numeric confidence score of the IOC reported by the source. | 
| GoogleChronicleBackstory.Iocs.Sources.NormalizedConfidenceScore | String | The normalized confidence score of the IOC reported by the source. | 
| GoogleChronicleBackstory.Iocs.Sources.RawSeverity | String | The severity of the IOC as reported by the source. | 
| GoogleChronicleBackstory.Iocs.Sources.Source | String | The source that reported the IOC. | 


##### Command Example
```!gcb-list-iocs page_size=1 preset_time_range="Last 1 day"```

##### Context Example
```
{
    "GoogleChronicleBackstory.Iocs": [
        {
            "FirstAccessedTime": "2018-10-03T02:12:51Z", 
            "Sources": [
                {
                    "Category": "Spyware Reporting Server", 
                    "RawSeverity": "Medium", 
                    "NormalizedConfidenceScore": "Low", 
                    "IntRawConfidenceScore": 0, 
                    "Source": "ET Intelligence Rep List"
                }
            ], 
            "LastAccessedTime": "2020-02-14T05:59:27Z", 
            "Artifact": "anx.tb.ask.com", 
            "IocIngestTime": "2020-02-06T22:00:00Z"
        }
    ], 
    "Domain": [
        {
            "Name": "anx.tb.ask.com"
        }
    ]
}
```

##### Human Readable Output
### IOC Domain Matches
|Domain|Category|Source|Confidence|Severity|IOC ingest time|First seen|Last seen|
|---|---|---|---|---|---|---|---|
| [anx.tb.ask.com]() | Spyware Reporting Server | ET Intelligence Rep List | Low | Medium | 7 days ago | a year ago | 3 hours ago |


### 2. gcb-assets
---
Returns a list of the assets that accessed the input artifact (IP, domain, MD5, SHA1 and SHA256) during the specified time.

##### Base Command

`gcb-assets`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| artifact_value |  The artifact indicator associated with assets. The artifact type can be one of the following: IP, Domain, MD5, SHA1, or SHA256.  | Required | 
| preset_time_range | Fetches assets that accessed the artifact during the interval specified. If configured, overrides the start_time and end_time arguments. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| end_time | The value of the end time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied,  the default is current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. The default is 10000. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Asset.HostName | String | The hostname of the asset that accessed the artifact. | 
| GoogleChronicleBackstory.Asset.IpAddress | String | The IP address of the asset that accessed the artifact. | 
| GoogleChronicleBackstory.Asset.MacAddress | String | The MAC address of the asset that accessed the artifact. | 
| GoogleChronicleBackstory.Asset.ProductId | String | The Product ID of the asset that accessed the artifact. | 
| GoogleChronicleBackstory.Asset.AccessedDomain | String | The domain artifact accessed by the asset. | 
| GoogleChronicleBackstory.Asset.AccessedIP | String | The IP address artifact accessed by the asset. | 
| GoogleChronicleBackstory.Asset.AccessedMD5 | String | The MD5 file hash artifact accessed by the asset. | 
| GoogleChronicleBackstory.Asset.AccessedSHA1 | String | The SHA1 file hash artifact accessed by the asset. | 
| GoogleChronicleBackstory.Asset.AccessedSHA256 | String | The SHA256 file hash artifact accessed by the asset. | 
| GoogleChronicleBackstory.Asset.FirstAccessedTime | Date | The time when the asset first accessed the artifact. | 
| GoogleChronicleBackstory.Asset.LastAccessedTime | Date | The time when the asset last accessed the artifact. | 
| Host.Hostname | String | The hostname of the asset that accessed the artifact. | 
| Host.ID | String | The Product ID of the asset that accessed the artifact. | 
| Host.IP | String | The IP address of the asset that accessed the artifact. | 
| Host.MACAddress | String | The MAC address of the asset that accessed the artifact. | 


##### Command Example
```!gcb-assets artifact_value=bing.com preset_time_range="Last 1 day"```

##### Context Example
```
{
    "GoogleChronicleBackstory.Asset": [
        {
            "FirstAccessedTime": "2018-10-18T04:38:44Z", 
            "AccessedDomain": "bing.com", 
            "HostName": "james-anderson-laptop", 
            "LastAccessedTime": "2020-02-14T07:13:33Z"
        }, 
        {
            "FirstAccessedTime": "2018-10-18T02:01:51Z", 
            "AccessedDomain": "bing.com", 
            "HostName": "roger-buchmann-pc", 
            "LastAccessedTime": "2020-02-13T22:25:27Z"
        }
    ], 
    "Host": [
        {
            "Hostname": "james-anderson-laptop"
        }, 
        {
            "Hostname": "roger-buchmann-pc"
        }
    ]
}
```

##### Human Readable Output
>### Assets related to artifact - bing.com
>|Host Name|Host IP|Host MAC|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|
>| james-anderson-laptop | - | - | 2018-10-18T04:38:44Z | 2020-02-14T07:13:33Z |
>| roger-buchmann-pc | - | - | 2018-10-18T02:01:51Z | 2020-02-13T22:25:27Z |
>
>View assets in Chronicle


### 3. ip
---
Checks the reputation of an IP address.

##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to check. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The reputation score (0: Unknown, 1: Good, 2: Suspicious, 3: Bad) | 
| IP.Address | String | The IP address of the artifact. | 
| IP.Malicious.Vendor | String | For malicious IPs, the vendor that made the decision. | 
| IP.Malicious.Description | String | For malicious IPs, the reason that the vendor made the decision. | 
| GoogleChronicleBackstory.IP.IoCQueried | String | The artifact that was queried. | 
| GoogleChronicleBackstory.IP.Sources.Address.IpAddress | String | The IP address of the artifact. | 
| GoogleChronicleBackstory.IP.Sources.Address.Domain | String | The domain name of the artifact. | 
| GoogleChronicleBackstory.IP.Sources.Address.Port | Number | The port number of the artifact. | 
| GoogleChronicleBackstory.IP.Sources.Category | String | The behavior of the artifact. | 
| GoogleChronicleBackstory.IP.Sources.ConfidenceScore | Number | The confidence score indicating the accuracy and appropriateness of the assigned category. | 
| GoogleChronicleBackstory.IP.Sources.FirstAccessedTime | Date | The time the IOC was first accessed within the enterprise. | 
| GoogleChronicleBackstory.IP.Sources.LastAccessedTime | Date | The time the IOC was most recently seen within your enterprise. | 
| GoogleChronicleBackstory.IP.Sources.Severity | String | Impact of the artifact on the enterprise. | 


##### Command Example
```!ip ip=23.20.239.12```

##### Context Example
```
{
    "IP": {
        "Address": "23.20.239.12"
    }, 
    "DBotScore": {
        "Vendor": "Google Chronicle Backstory", 
        "Indicator": "23.20.239.12", 
        "Score": 0, 
        "Type": "ip"
    }, 
    "GoogleChronicleBackstory.IP": {
        "Sources": [
            {
                "Category": "Known CnC for Mobile specific Family", 
                "FirstAccessedTime": "2018-12-05T00:00:00Z", 
                "Severity": "High", 
                "ConfidenceScore": 70, 
                "Address": [
                    {
                        "IpAddress": "23.20.239.12", 
                        "Port": [
                            80
                        ]
                    }
                ], 
                "LastAccessedTime": "2019-04-10T00:00:00Z"
            }, 
            {
                "Category": "Blocked", 
                "FirstAccessedTime": "1970-01-01T00:00:00Z", 
                "Severity": "High", 
                "ConfidenceScore": "High", 
                "Address": [
                    {
                        "Domain": "mytemplatewebsite.com", 
                        "Port": ""
                    }, 
                    {
                        "IpAddress": "23.20.239.12", 
                        "Port": ""
                    }
                ], 
                "LastAccessedTime": "2020-02-16T08:56:06Z"
            }
        ], 
        "IoCQueried": "23.20.239.12"
    }
}
```

##### Human Readable Output
IP: 23.20.239.12 found with Reputation: Unknown
### Reputation Parameters
|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
|---|---|---|---|---|---|---|
| - | 23.20.239.12 | Known CnC for Mobile specific Family | 70 | High | 2018-12-05T00:00:00Z | 2019-04-10T00:00:00Z |
| mytemplatewebsite.com | 23.20.239.12 | Blocked | High | High | 1970-01-01T00:00:00Z | 2020-02-16T08:56:06Z |

[View IoC details in Chronicle]()


### 4. domain
---
Checks the reputation of a domain.

##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to check. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The reputation score (0: Unknown, 1: Good, 2: Suspicious, 3: Bad) | 
| Domain.Name | String | The domain name of the artifact. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. | 
| GoogleChronicleBackstory.Domain.IoCQueried | String | The domain that queried. | 
| GoogleChronicleBackstory.Domain.Sources.Address.IpAddress | String | The IP address of the artifact. | 
| GoogleChronicleBackstory.Domain.Sources.Address.Domain | String | The domain name of the artifact. | 
| GoogleChronicleBackstory.Domain.Sources.Address.Port | Number | The port number of the artifact. | 
| GoogleChronicleBackstory.Domain.Sources.Category | String | The behavior of the artifact. | 
| GoogleChronicleBackstory.Domain.Sources.ConfidenceScore | Number | The confidence score indicating the accuracy and appropriateness of the assigned category. | 
| GoogleChronicleBackstory.Domain.Sources.FirstAccessedTime | Date | The time the IOC was first accessed within the enterprise. | 
| GoogleChronicleBackstory.Domain.Sources.LastAccessedTime | Date | The time the IOC was most recently seen within your enterprise. | 
| GoogleChronicleBackstory.Domain.Sources.Severity | String | Impact of the artifact on the enterprise. | 


##### Command Example
```!domain domain=bing.com```

##### Context Example
```
{
    "GoogleChronicleBackstory.Domain": {
        "Sources": [
            {
                "Category": "Observed serving executables", 
                "FirstAccessedTime": "2013-08-06T00:00:00Z", 
                "Severity": "Low", 
                "ConfidenceScore": 67, 
                "Address": [
                    {
                        "Domain": "bing.com", 
                        "Port": [
                            80
                        ]
                    }
                ], 
                "LastAccessedTime": "2020-01-14T00:00:00Z"
            }
        ], 
        "IoCQueried": "bing.com"
    }, 
    "Domain": {
        "Name": "bing.com"
    }, 
    "DBotScore": {
        "Vendor": "Google Chronicle Backstory", 
        "Indicator": "bing.com", 
        "Score": 0, 
        "Type": "domain"
    }
}
```

##### Human Readable Output
Domain: bing.com found with Reputation: Unknown
### Reputation Parameters
|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
|---|---|---|---|---|---|---|
| bing.com | - | Observed serving executables | 67 | Low | 2013-08-06T00:00:00Z | 2020-01-14T00:00:00Z |

[View IoC details in Chronicle]()


### 5. gcb-ioc-details
---
Accepts an artifact indicator and returns any threat intelligence associated with the artifact. The threat intelligence information is drawn from your enterprise security systems and from Chronicle's IoC partners (for example, the DHS threat feed).

##### Base Command

`gcb-ioc-details`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| artifact_value | The artifact indicator value. The supported artifact types are IP and domain. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name of the artifact. | 
| IP.Address | String | The IP address of the of the artifact. | 
| GoogleChronicleBackstory.IocDetails.IoCQueried | String | The artifact entered by the user. | 
| GoogleChronicleBackstory.IocDetails.Sources.Address.IpAddress | String | The IP address of the artifact. | 
| GoogleChronicleBackstory.IocDetails.Sources.Address.Domain | String | The domain name of the artifact. | 
| GoogleChronicleBackstory.IocDetails.Sources.Address.Port | Number | The port number of the artifact. | 
| GoogleChronicleBackstory.IocDetails.Sources.Category | String | The behavior of the artifact. | 
| GoogleChronicleBackstory.IocDetails.Sources.ConfidenceScore | Number | The confidence score indicating the accuracy and appropriateness of the assigned category. | 
| GoogleChronicleBackstory.IocDetails.Sources.FirstAccessedTime | Date | The time the IOC was first accessed within the enterprise. | 
| GoogleChronicleBackstory.IocDetails.Sources.LastAccessedTime | Date | The time the IOC was most recently seen within your enterprise. | 
| GoogleChronicleBackstory.IocDetails.Sources.Severity | String | Impact of the artifact on the enterprise. | 


##### Command Example
```!gcb-ioc-details artifact_value=23.20.239.12```
##### Context Example
```
{
    "IP": {
        "Address": "23.20.239.12"
    }, 
    "GoogleChronicleBackstory.IocDetails": {
        "Sources": [
            {
                "Category": "Known CnC for Mobile specific Family", 
                "FirstAccessedTime": "2018-12-05T00:00:00Z", 
                "Severity": "High", 
                "ConfidenceScore": 70, 
                "Address": [
                    {
                        "IpAddress": "23.20.239.12", 
                        "Port": [
                            80
                        ]
                    }
                ], 
                "LastAccessedTime": "2019-04-10T00:00:00Z"
            }, 
            {
                "Category": "Blocked", 
                "FirstAccessedTime": "1970-01-01T00:00:00Z", 
                "Severity": "High", 
                "ConfidenceScore": "High", 
                "Address": [
                    {
                        "Domain": "mytemplatewebsite.com", 
                        "Port": ""
                    }, 
                    {
                        "IpAddress": "23.20.239.12", 
                        "Port": ""
                    }
                ], 
                "LastAccessedTime": "2020-02-16T08:56:06Z"
            }
        ], 
        "IoCQueried": "23.20.239.12"
    }
}
```

##### Human Readable Output
### IoC Details
|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
|---|---|---|---|---|---|---|
| - | 23.20.239.12 | Known CnC for Mobile specific Family | 70 | High | 2018-12-05T00:00:00Z | 2019-04-10T00:00:00Z |
| mytemplatewebsite.com | 23.20.239.12 | Blocked | High | High | 1970-01-01T00:00:00Z | 2020-02-16T08:56:06Z |

[View IoC details in Chronicle]()


### 6. gcb-list-alerts
---
List all the alerts tracked within your enterprise for the specified time range. Both the parsed alerts and their corresponding raw alert logs are returned.

##### Base Command

`gcb-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetch alerts for the specified time range. If preset_time_range is configured, overrides the start_time and end_time arguments. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| end_time | The value of the end time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied,  the default is current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. The default is 10000. | Optional | 
| severity | The severity by which to filter the returned alerts. If not supplied, all alerts are fetched. This is applicable for asset alerts only. The possible values are "High", "Medium", "Low", or "Unspecified". | Optional | 
| alert_type | Specify which type of alerts you want. The possible values are "Asset Alerts" or "User Alerts". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Alert.AssetName | String | The asset identifier. It can be IP Address, MAC Address, Hostname or Product ID. | 
| GoogleChronicleBackstory.Alert.AlertInfo.Name | String | The name of the alert. | 
| GoogleChronicleBackstory.Alert.AlertInfo.Severity | String | The severity of the alert. | 
| GoogleChronicleBackstory.Alert.AlertInfo.SourceProduct | String | The source of the alert. | 
| GoogleChronicleBackstory.Alert.AlertInfo.Timestamp | String | The time of the alert in Chronicle. | 
| GoogleChronicleBackstory.Alert.AlertCounts | Number | The total number of alerts. | 
| GoogleChronicleBackstory.UserAlert.User | String | The user identifier. It can be username or email address. | 
| GoogleChronicleBackstory.UserAlert.AlertInfo.Name | String | The name of the user alert. |  
| GoogleChronicleBackstory.UserAlert.AlertInfo.SourceProduct | String | The source of the user alert. | 
| GoogleChronicleBackstory.UserAlert.AlertInfo.Timestamp | String | The time of the user alert in Chronicle. | 
| GoogleChronicleBackstory.UserAlert.AlertInfo.RawLog | String | The raw log of the user alert. | 
| GoogleChronicleBackstory.UserAlert.AlertCounts | Number | The total number of user alerts. | 


##### Command Example
```!gcb-list-alerts page_size=1 preset_time_range="Last 1 day"```

##### Context Example
```
{
    "GoogleChronicleBackstory.Alert": [
        {
            "AssetName": "rosie-hayes-pc", 
            "AlertInfo": [
                {
                    "Timestamp": "2020-02-14T03:02:36Z", 
                    "SourceProduct": "Internal Alert", 
                    "Name": "Authentication failure [32038]", 
                    "Severity": "Medium"
                }
            ], 
            "AlertCounts": 1
        }
    ]
}
```

##### Human Readable Output
### Security Alert(s)
|Alerts|Asset|Alert Names|First Seen|Last Seen|Severities|Sources|
|---|---|---|---|---|---|---|
| 1 | [rosie-hayes-pc]() | Authentication failure [32038] | 6 hours ago | 6 hours ago | Medium | Internal Alert |


### 7. gcb-list-events
---
List all of the events discovered within your enterprise on a particular device within the specified time range. If you receive the maximum number of events you specified using the page_size parameter (or 100, the default), there might still be more events within your Chronicle account. You can narrow the time range and issue the call again to ensure you have visibility into all possible events. This command returns more than 60 different types of events. Any event would have only specific output context set. Refer the UDM documentation to figure out the output properties specific to the event types.

##### Base Command

`gcb-list-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_identifier_type | Specify the identifier type of the asset you are investigating. The possible values are Host Name, IP Address, MAC Address or Product ID. | Required | 
| asset_identifier | Value of the asset identifier. | Required | 
| preset_time_range | Get events that are discovered during the interval specified. If configured, overrides the start_time and end_time arguments. | Optional | 
| start_time | The value of the start time for your request. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 2 hours earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| end_time | The value of the end time for your request. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| page_size | Specify the maximum number of events to fetch. You can specify between 1 and 1000. The default is 100. | Optional | 
| reference_time | Specify the reference time for the asset you are investigating, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers start time as reference time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Events.eventType | String | Specifies the type of the event. | 
| GoogleChronicleBackstory.Events.eventTimestamp | Date | The GMT timestamp when the event was generated. | 
| GoogleChronicleBackstory.Events.collectedTimestamp | Date | The GMT timestamp when the event was collected by the vendor's local collection infrastructure. | 
| GoogleChronicleBackstory.Events.description | String | Human-readable description of the event. | 
| GoogleChronicleBackstory.Events.productEventType | String | Short, descriptive, human-readable, and product-specific event name or type. | 
| GoogleChronicleBackstory.Events.productLogId | String | A vendor-specific event identifier to uniquely identify the event (a GUID). Users might use this identifier to search the vendor's proprietary console for the event in question. | 
| GoogleChronicleBackstory.Events.productName | String | Specifies the name of the product. | 
| GoogleChronicleBackstory.Events.productVersion | String | Specifies the version of the product. | 
| GoogleChronicleBackstory.Events.urlBackToProduct | String | URL linking to a relevant website where you can view more information about this specific event or the general event category. | 
| GoogleChronicleBackstory.Events.vendorName | String | Specifies the product vendor's name. |
| GoogleChronicleBackstory.Events.principal.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.principal.email | String | Email address. | 
| GoogleChronicleBackstory.Events.principal.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.principal.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.principal.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.principal.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.principal.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.principal.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.principal.mac | String | MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.principal.administrativeDomain | String | Domain which the device belongs to (for example, the Windows domain). | 
| GoogleChronicleBackstory.Events.principal.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.principal.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.principal.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.principal.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.principal.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.principal.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Events.principal.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Events.principal.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Events.principal.process.file | String | Stores the file name of the file in use by the process. |
| GoogleChronicleBackstory.Events.principal.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.principal.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.principal.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.principal.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.principal.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.principal.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.principal.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.principal.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.principal.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.principal.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.principal.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.principal.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.principal.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.principal.user.windowsSid | String | Stores the Microsoft Windows security identifier (SID) associated with a user. | 
| GoogleChronicleBackstory.Events.target.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.target.email | String | Email address. | 
| GoogleChronicleBackstory.Events.target.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.target.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.target.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.target.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.target.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.target.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.target.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.target.administrativeDomain | String | Domain which the device belongs to (for example, the Windows domain). | 
| GoogleChronicleBackstory.Events.target.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.target.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.target.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.target.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.target.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.target.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Events.target.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Events.target.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Events.target.process.file | String | Stores the file name of the file in use by the process. |
| GoogleChronicleBackstory.Events.target.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.target.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.target.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.target.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.target.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.target.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.target.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.target.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.target.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.target.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.target.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.target.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.target.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.target.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.target.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.target.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.target.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.target.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.target.user.windowsSid | String | Stores the Microsoft Windows security identifier (SID) associated with a user. | 
| GoogleChronicleBackstory.Events.intermediary.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.intermediary.email | String | Email address. | 
| GoogleChronicleBackstory.Events.intermediary.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.intermediary.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.intermediary.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.intermediary.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.intermediary.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.intermediary.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.intermediary.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.intermediary.administrativeDomain | String | Domain which the device belongs to (for example, the Windows domain). | 
| GoogleChronicleBackstory.Events.intermediary.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.intermediary.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.intermediary.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Events.intermediary.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Events.intermediary.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Events.intermediary.process.file | String | Stores the file name of the file in use by the process. |
| GoogleChronicleBackstory.Events.intermediary.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.intermediary.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.intermediary.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.intermediary.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.intermediary.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.intermediary.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.intermediary.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.intermediary.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.intermediary.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.intermediary.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.intermediary.user.windowsSid | String | Stores the Microsoft Windows security identifier (SID) associated with a user. | 
| GoogleChronicleBackstory.Events.src.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.src.email | String | Email address. | 
| GoogleChronicleBackstory.Events.src.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.src.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.src.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.src.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.src.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.src.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.src.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.src.administrativeDomain | String | Domain which the device belongs to (for example, the Windows domain). | 
| GoogleChronicleBackstory.Events.src.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.src.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.src.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.src.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.src.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.src.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Events.src.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Events.src.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Events.src.process.file | String | Stores the file name of the file in use by the process. |
| GoogleChronicleBackstory.Events.src.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.src.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.src.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.process.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.src.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.process.file.size | String | Size of the file. |  
| GoogleChronicleBackstory.Events.src.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.src.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.src.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.src.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.src.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.src.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.src.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.src.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.src.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.src.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.src.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.src.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.src.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.src.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.src.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.src.user.windowsSid | String | Stores the Microsoft Windows security identifier (SID) associated with a user. | 
| GoogleChronicleBackstory.Events.observer.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.observer.email | String | Email address. | 
| GoogleChronicleBackstory.Events.observer.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.observer.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.observer.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.observer.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.observer.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.observer.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.observer.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.observer.administrativeDomain | String | Domain which the device belongs to (for example, the Windows domain). | 
| GoogleChronicleBackstory.Events.observer.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.observer.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.observer.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.observer.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.observer.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.observer.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Events.observer.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Events.observer.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Events.observer.process.file | String | Stores the file name of the file in use by the process. |
| GoogleChronicleBackstory.Events.observer.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.observer.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.observer.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.process.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.observer.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.process.file.size | String | Size of the file. |  
| GoogleChronicleBackstory.Events.observer.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.observer.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.observer.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.observer.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.observer.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.observer.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.observer.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.observer.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.observer.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.observer.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.observer.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.observer.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.observer.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.observer.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.observer.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.observer.user.windowsSid | String | Stores the Microsoft Windows security identifier (SID) associated with a user. | 
| GoogleChronicleBackstory.Events.about.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.about.email | String | Email address. | 
| GoogleChronicleBackstory.Events.about.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.about.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.about.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.about.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.about.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.about.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.about.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.about.administrativeDomain | String | Domain which the device belongs to (for example, the Windows domain). | 
| GoogleChronicleBackstory.Events.about.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.about.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.about.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.about.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.about.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.about.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Events.about.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Events.about.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Events.about.process.file | String | Stores the file name of the file in use by the process. |
| GoogleChronicleBackstory.Events.about.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.about.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.about.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.process.file.mimeType | String | Multipurpose Internet Mail Extensions (MIME) type of the file. | 
| GoogleChronicleBackstory.Events.about.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.process.file.size | String | Size of the file. |  
| GoogleChronicleBackstory.Events.about.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.about.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.about.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.about.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.about.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.about.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.about.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.about.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.about.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.about.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.about.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.about.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.about.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.about.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.about.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.about.user.windowsSid | String | Stores the Microsoft Windows security identifier (SID) associated with a user. |  
| GoogleChronicleBackstory.Events.network.applicationProtocol | String | Indicates the network application protocol. | 
| GoogleChronicleBackstory.Events.network.direction | String | Indicates the direction of network traffic. | 
| GoogleChronicleBackstory.Events.network.email | String | Specifies the email address for the sender/recipient. | 
| GoogleChronicleBackstory.Events.network.ipProtocol | String | Indicates the IP protocol. | 
| GoogleChronicleBackstory.Events.network.receivedBytes | String | Specifies the number of bytes received. | 
| GoogleChronicleBackstory.Events.network.sentBytes | String | Specifies the number of bytes sent. | 
| GoogleChronicleBackstory.Events.network.dhcp.clientHostname | String | Hostname for the client. | 
| GoogleChronicleBackstory.Events.network.dhcp.clientIdentifier | String | Client identifier. | 
| GoogleChronicleBackstory.Events.network.dhcp.file | String | Filename for the boot image. | 
| GoogleChronicleBackstory.Events.network.dhcp.flags | String | Value for the DHCP flags field. | 
| GoogleChronicleBackstory.Events.network.dhcp.hlen | String | Hardware address length. | 
| GoogleChronicleBackstory.Events.network.dhcp.hops | String | DHCP hop count. | 
| GoogleChronicleBackstory.Events.network.dhcp.htype | String | Hardware address type. | 
| GoogleChronicleBackstory.Events.network.dhcp.leaseTimeSeconds | String | Client-requested lease time for an IP address in seconds. | 
| GoogleChronicleBackstory.Events.network.dhcp.opcode | String | BOOTP op code. | 
| GoogleChronicleBackstory.Events.network.dhcp.requestedAddress | String | Client identifier. | 
| GoogleChronicleBackstory.Events.network.dhcp.seconds | String | Seconds elapsed since the client began the address acquisition/renewal process. | 
| GoogleChronicleBackstory.Events.network.dhcp.sname | String | Name of the server which the client has requested to boot from. | 
| GoogleChronicleBackstory.Events.network.dhcp.transactionId | String | Client transaction ID. | 
| GoogleChronicleBackstory.Events.network.dhcp.type | String | DHCP message type. | 
| GoogleChronicleBackstory.Events.network.dhcp.chaddr | String | IP address for the client hardware. | 
| GoogleChronicleBackstory.Events.network.dhcp.ciaddr | String | IP address for the client. | 
| GoogleChronicleBackstory.Events.network.dhcp.giaddr | String | IP address for the relay agent. | 
| GoogleChronicleBackstory.Events.network.dhcp.siaddr | String | IP address for the next bootstrap server. | 
| GoogleChronicleBackstory.Events.network.dhcp.yiaddr | String | Your IP address. | 
| GoogleChronicleBackstory.Events.network.dns.authoritative | String | Set to true for authoritative DNS servers. | 
| GoogleChronicleBackstory.Events.network.dns.id | String | Stores the DNS query identifier. | 
| GoogleChronicleBackstory.Events.network.dns.response | String | Set to true if the event is a DNS response. | 
| GoogleChronicleBackstory.Events.network.dns.opcode | String | Stores the DNS OpCode used to specify the type of DNS query (standard, inverse, server status, etc.). | 
| GoogleChronicleBackstory.Events.network.dns.recursionAvailable | String | Set to true if a recursive DNS lookup is available. | 
| GoogleChronicleBackstory.Events.network.dns.recursionDesired | String | Set to true if a recursive DNS lookup is requested. | 
| GoogleChronicleBackstory.Events.network.dns.responseCode | String | Stores the DNS response code as defined by RFC 1035, Domain Names - Implementation and Specification. | 
| GoogleChronicleBackstory.Events.network.dns.truncated | String | Set to true if this is a truncated DNS response. |  
| GoogleChronicleBackstory.Events.network.dns.questions.name | String | Stores the domain name. | 
| GoogleChronicleBackstory.Events.network.dns.questions.class | String | Stores the code specifying the class of the query. | 
| GoogleChronicleBackstory.Events.network.dns.questions.type | String | Stores the code specifying the type of the query. | 
| GoogleChronicleBackstory.Events.network.dns.answers.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.Events.network.dns.answers.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.answers.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.Events.network.dns.answers.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.answers.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.Events.network.dns.answers.type | String | Stores the code specifying the type of the resource record. |
| GoogleChronicleBackstory.Events.network.dns.authority.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.Events.network.dns.authority.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.authority.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.Events.network.dns.authority.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.authority.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.Events.network.dns.authority.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.additional.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.Events.network.dns.additional.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.additional.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.Events.network.dns.additional.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.Events.network.dns.additional.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.Events.network.dns.additional.type | String | Stores the code specifying the type of the resource record. |  
| GoogleChronicleBackstory.Events.network.email.from | String | Stores the from email address. | 
| GoogleChronicleBackstory.Events.network.email.replyTo | String | Stores the reply_to email address. | 
| GoogleChronicleBackstory.Events.network.email.to | String | Stores the to email addresses. | 
| GoogleChronicleBackstory.Events.network.email.cc | String | Stores the cc email addresses. | 
| GoogleChronicleBackstory.Events.network.email.bcc | String | Stores the bcc email addresses. | 
| GoogleChronicleBackstory.Events.network.email.mailId | String | Stores the mail (or message) ID. | 
| GoogleChronicleBackstory.Events.network.email.subject | String | Stores the email subject line. | 
| GoogleChronicleBackstory.Events.network.ftp.command | String | Stores the FTP command. | 
| GoogleChronicleBackstory.Events.network.http.method | String | Stores the HTTP request method. | 
| GoogleChronicleBackstory.Events.network.http.referralUrl | String | Stores the URL for the HTTP referer. | 
| GoogleChronicleBackstory.Events.network.http.responseCode | String | Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. | 
| GoogleChronicleBackstory.Events.network.http.useragent | String | Stores the User-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | 
| GoogleChronicleBackstory.Events.authentication.authType | String | Type of system an authentication event is associated with (Chronicle UDM). | 
| GoogleChronicleBackstory.Events.authentication.mechanism | String | Mechanism(s) used for authentication. | 
| GoogleChronicleBackstory.Events.securityResult.about | String | Provide a description of the security result. | 
| GoogleChronicleBackstory.Events.securityResult.action | String | Specify a security action. | 
| GoogleChronicleBackstory.Events.securityResult.category | String | Specify a security category. | 
| GoogleChronicleBackstory.Events.securityResult.confidence | String | Specify a confidence with regards to a security event as estimated by the product. | 
| GoogleChronicleBackstory.Events.securityResult.confidenceDetails | String | Additional detail with regards to the confidence of a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Events.securityResult.priority | String | Specify a priority with regards to a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Events.securityResult.priorityDetails | String | Vendor-specific information about the security result priority. | 
| GoogleChronicleBackstory.Events.securityResult.ruleId | String | Identifier for the security rule. | 
| GoogleChronicleBackstory.Events.securityResult.ruleName | String | Name of the security rule. | 
| GoogleChronicleBackstory.Events.securityResult.severity | String | Severity of a security event as estimated by the product vendor using values defined by the Chronicle UDM. | 
| GoogleChronicleBackstory.Events.securityResult.severityDetails | String | Severity for a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Events.securityResult.threatName | String | Name of the security threat. | 
| GoogleChronicleBackstory.Events.securityResult.urlBackToProduct | String | URL to direct you to the source product console for this security event. | 


##### Command Example
```!gcb-list-events asset_identifier_type="Host Name" asset_identifier="ray-xxx-laptop" start_time="2020-01-01T00:00:00Z" page_size="1"```

##### Context Example
```
{
    "GoogleChronicleBackstory.Events": [
        {
            "principal": {
                "ip": [
                    "10.0.XX.XX"
                ], 
                "mac": [
                    "88:a6:XX:XX:XX:XX"
                ], 
                "hostname": "ray-xxx-laptop"
            }, 
            "target": {
                "ip": [
                    "8.8.8.8"
                ]
            }, 
            "network": {
                "applicationProtocol": "DNS", 
                "dns": {
                    "questions": [
                        {
                            "type": 1, 
                            "name": "is5-ssl.mzstatic.com"
                        }
                    ], 
                    "answers": [
                        {
                            "type": 1, 
                            "data": "104.118.212.43", 
                            "name": "is5-ssl.mzstatic.com", 
                            "ttl": 11111
                        }
                    ], 
                    "response": true
                }
            }, 
            
            "collectedTimestamp": "2020-01-02T00:00:00Z", 
            "productName": "ExtraHop", 
            "eventTimestamp": "2020-01-01T23:59:38Z", 
            "eventType": "NETWORK_DNS"
        
        }
    ]
}
```

##### Human Readable Output
>### Event(s) Details
>|Event Timestamp|Event Type|Principal Asset Identifier|Target Asset Identifier|Queried Domain|
>|---|---|---|---|---|
>| 2020-01-01T23:59:38Z | NETWORK_DNS | ray-xxx-laptop | 8.8.8.8 | ninthdecimal.com |
>
>View events in Chronicle
>
>Maximum number of events specified in page_size has been returned. There might still be more events in your Chronicle account. >To fetch the next set of events, execute the command with the start time as 2020-01-01T23:59:38Z


### 8. gcb-list-detections
***
Return the detections for the specified version of a rule, the latest version of a rule, all versions of a rule, or all versions of all rules.


##### Base Command

`gcb-list-detections`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique identifier for a rule or specific version of a rule, defined and returned by the server. You can specify exactly one rule identifier. Use the following format to specify the id: ru_{UUID} or {ruleId}@v_{int64}_{int64}. If not specified then detections for all versions of all rules are returned. | Optional | 
| detection_start_time | (Deprecated)Time to begin returning detections, filtering on a detection's detectionTime. If not specified, the start time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| detection_end_time | (Deprecated)Time to stop returning detections, filtering on a detection's detectionTime. If not specified, the end time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| start_time | Time to begin returning detections, filtering by the detection field specified in the listBasis parameter. If not specified, the start time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| end_time | Time to stop returning detections, filtering by the detection field specified by the listBasis parameter. If not specified, the end time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours. | Optional | 
| detection_for_all_versions | Whether the user wants to retrieve detections for all versions of a rule with a given rule identifier.<br/><br/>Note: If this option is set to true, rule id is required. | Optional | 
| list_basis | Sort detections by "DETECTION_TIME" or by "CREATED_TIME". If not specified, it defaults to "DETECTION_TIME". Detections are returned in descending order of the timestamp.<br/><br/>Note: Requires either "start_time" or "end_time" argument. | Optional | 
| alert_state | Filter detections on if they are ALERTING or NOT_ALERTING.<br/>Avoid specifying to return all detections. | Optional | 
| page_size | Specify the limit on the number of detections to display. You can specify between 1 and 1,000. | Optional | 
| page_token | A page token received from a previous call. Provide this to retrieve the subsequent page. If the page token is configured, overrides the detection start and end time arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Detections.id | String | Identifier for the detection. | 
| GoogleChronicleBackstory.Detections.ruleId | String | Identifier for the rule generating the detection. | 
| GoogleChronicleBackstory.Detections.ruleVersion | String | Identifier for the rule version generating the detection. | 
| GoogleChronicleBackstory.Detections.ruleName | String | Name of the rule generating the detection, as parsed from ruleText. | 
| GoogleChronicleBackstory.Detections.timeWindowStartTime | Date | The start time of the window the detection was found in. | 
| GoogleChronicleBackstory.Detections.timeWindowEndTime | Date | The end time of the window the detection was found in. | 
| GoogleChronicleBackstory.Detections.alertState | String | Indicates whether the rule generating this detection currently has alerting enabled or disabled. | 
| GoogleChronicleBackstory.Detections.urlBackToProduct | String | URL pointing to the Chronicle UI for this detection. | 
| GoogleChronicleBackstory.Detections.type | String | Type of detection. | 
| GoogleChronicleBackstory.Detections.createdTime | Date | Time the detection was created. | 
| GoogleChronicleBackstory.Detections.detectionTime | Date | The time period the detection was found in. | 
| GoogleChronicleBackstory.Detections.ruleType | String | Whether the rule generating this detection is a single event or multi-event rule. | 
| GoogleChronicleBackstory.Detections.detectionFields.key | String | The key for a field specified in the rule, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.Detections.detectionFields.value | String | The value for a field specified in the rule, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.Detections.collectionElements.label | String | The variable a given set of UDM events belongs to. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principalAssetIdentifier | String | Specifies the principal asset identifier of the event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.targetAssetIdentifier | String | Specifies the target asset identifier of the event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.eventType | String | Specifies the type of the event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.eventTimestamp | Date | The GMT timestamp when the event was generated. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.ingestedTimestamp | Date | The GMT timestamp when the event was ingested in the vendor's instance. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.description | String | Human-readable description of the event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.productEventType | String | Short, descriptive, human-readable, and product-specific event name or type. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.productLogId | String | A vendor-specific event identifier to uniquely identify the event \(a GUID\). Users might use this identifier to search the vendor's proprietary console for the event in question. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.productName | String | Specifies the name of the product. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.productVersion | String | Specifies the version of the product. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.urlBackToProduct | String | URL linking to a relevant website where you can view more information about this specific event or the general event category. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.vendorName | String | Specifies the product vendor's name. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.email | String | Email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.mac | String | MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.url | String | Standard URL. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.principal.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.email | String | Email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.url | String | Standard URL. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.target.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.email | String | Email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.url | String | Standard URL. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.intermediary.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.email | String | Email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.url | String | Standard URL. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.src.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.email | String | Email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.url | String | Standard URL. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.observer.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.email | String | Email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.url | String | Standard URL. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.about.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.applicationProtocol | String | Indicates the network application protocol. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.direction | String | Indicates the direction of network traffic. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email | String | Specifies the email address for the sender/recipient. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.ipProtocol | String | Indicates the IP protocol. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.receivedBytes | String | Specifies the number of bytes received. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.sentBytes | String | Specifies the number of bytes sent. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.clientHostname | String | Hostname for the client. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.clientIdentifier | String | Client identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.file | String | Filename for the boot image. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.flags | String | Value for the DHCP flags field. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.hlen | String | Hardware address length. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.hops | String | DHCP hop count. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.htype | String | Hardware address type. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.leaseTimeSeconds | String | Client-requested lease time for an IP address in seconds. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.opcode | String | BOOTP op code. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.requestedAddress | String | Client identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.seconds | String | Seconds elapsed since the client began the address acquisition/renewal process. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.sname | String | Name of the server which the client has requested to boot from. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.transactionId | String | Client transaction ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.type | String | DHCP message type. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.chaddr | String | IP address for the client hardware. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.ciaddr | String | IP address for the client. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.giaddr | String | IP address for the relay agent. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.siaddr | String | IP address for the next bootstrap server. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dhcp.yiaddr | String | Your IP address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authoritative | String | Set to true for authoritative DNS servers. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.id | String | Stores the DNS query identifier. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.response | String | Set to true if the event is a DNS response. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.opcode | String | Stores the DNS OpCode used to specify the type of DNS query \(standard, inverse, server status, etc.\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.recursionAvailable | String | Set to true if a recursive DNS lookup is available. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.recursionDesired | String | Set to true if a recursive DNS lookup is requested. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.responseCode | String | Stores the DNS response code as defined by RFC 1035, Domain Names - Implementation and Specification. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.truncated | String | Set to true if this is a truncated DNS response. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.questions.name | String | Stores the domain name. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.questions.class | String | Stores the code specifying the class of the query. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.questions.type | String | Stores the code specifying the type of the query. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.answers.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.answers.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.answers.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.answers.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.answers.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.answers.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authority.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authority.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authority.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authority.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authority.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.authority.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.additional.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.additional.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.additional.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.additional.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.additional.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.dns.additional.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.from | String | Stores the from email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.replyTo | String | Stores the reply_to email address. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.to | String | Stores the to email addresses. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.cc | String | Stores the cc email addresses. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.bcc | String | Stores the bcc email addresses. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.mailId | String | Stores the mail \(or message\) ID. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.email.subject | String | Stores the email subject line. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.ftp.command | String | Stores the FTP command. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.http.method | String | Stores the HTTP request method. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.http.referralUrl | String | Stores the URL for the HTTP referer. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.http.responseCode | String | Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.network.http.useragent | String | Stores the User-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.authentication.authType | String | Type of system an authentication event is associated with \(Chronicle UDM\). | 
| GoogleChronicleBackstory.Detections.collectionElements.references.authentication.mechanism | String | Mechanism\(s\) used for authentication. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.about | String | Provide a description of the security result. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.action | String | Specify a security action. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.category | String | Specify a security category. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.confidence | String | Specify a confidence with regards to a security event as estimated by the product. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.confidenceDetails | String | Additional detail with regards to the confidence of a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.priority | String | Specify a priority with regards to a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.priorityDetails | String | Vendor-specific information about the security result priority. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.ruleId | String | Identifier for the security rule. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.ruleName | String | Name of the security rule. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.severity | String | Severity of a security event as estimated by the product vendor using values defined by the Chronicle UDM. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.severityDetails | String | Severity for a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.threatName | String | Name of the security threat. | 
| GoogleChronicleBackstory.Detections.collectionElements.references.securityResult.urlBackToProduct | String | URL to direct you to the source product console for this security event. | 
| GoogleChronicleBackstory.Token.name | String | The name of the command to which the value of the nextPageToken corresponds. | 
| GoogleChronicleBackstory.Token.nextPageToken | String | A page token that can be provided to the next call to view the next page of detections. Absent if this is the last page. |


##### Command Example
```!gcb-list-detections id=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71 page_size=2```

##### Context Example
```json
{
    "GoogleChronicleBackstory": {
        "Detections": [
            {
                "alertState": "NOT_ALERTING",
                "collectionElements": [
                    {
                        "label": "event",
                        "references": [
                            {
                                "eventTimestamp": "2020-12-24T03:00:02.559Z",
                                "eventType": "NETWORK_DNS",
                                "ingestedTimestamp": "2020-12-24T03:03:17.129868Z",
                                "network": {
                                    "applicationProtocol": "DNS",
                                    "dns": {
                                        "questions": [
                                            {
                                                "name": "is5-ssl.mzstatic.com",
                                                "type": 1
                                            }
                                        ]
                                    }
                                },
                                "principal": {
                                    "hostname": "ray-xxx-laptop",
                                    "ip": [
                                        "10.0.XX.XX"
                                    ],
                                    "mac": [
                                        "88:a6:XX:XX:XX:XX"
                                    ]
                                },
                                "principalAssetIdentifier": "ray-xxx-laptop",
                                "productName": "ExtraHop",
                                "securityResult": [
                                    {
                                        "action": [
                                            "UNKNOWN_ACTION"
                                        ]
                                    }
                                ],
                                "target": {
                                    "ip": [
                                        "10.0.XX.XX"
                                    ]
                                },
                                "targetAssetIdentifier": "10.0.XX.XX"
                            },
                            {
                                "eventTimestamp": "2020-12-24T03:00:40.566Z",
                                "eventType": "NETWORK_DNS",
                                "ingestedTimestamp": "2020-12-24T03:03:17.129868Z",
                                "network": {
                                    "applicationProtocol": "DNS",
                                    "dns": {
                                        "questions": [
                                            {
                                                "name": "is5-ssl.mzstatic.com",
                                                "type": 1
                                            }
                                        ]
                                    }
                                },
                                "principal": {
                                    "hostname": "ray-xxx-laptop",
                                    "ip": [
                                        "10.0.XX.XX"
                                    ],
                                    "mac": [
                                        "88:a6:XX:XX:XX:XX"
                                    ]
                                },
                                "principalAssetIdentifier": "ray-xxx-laptop",
                                "productName": "ExtraHop",
                                "securityResult": [
                                    {
                                        "action": [
                                            "UNKNOWN_ACTION"
                                        ]
                                    }
                                ],
                                "target": {
                                    "ip": [
                                        "10.0.XX.XX"
                                    ]
                                },
                                "targetAssetIdentifier": "10.0.XX.XX"
                            }
                        ]
                    }
                ],
                "createdTime": "2020-12-24T03:13:46.116199Z",
                "detectionFields": [
                    {
                        "key": "client_ip",
                        "value": "10.0.XX.XX"
                    }
                ],
                "detectionTime": "2020-12-24T04:00:00Z",
                "id": "de_bea17243-d3b3-14bf-6b57-74e1a2422c68",
                "ruleId": "ru_746bd6d6-6b84-4007-b74c-ec90c7306a71",
                "ruleName": "SampleRule",
                "ruleType": "MULTI_EVENT",
                "ruleVersion": "ru_746bd6d6-6b84-4007-b74c-ec90c7306a71@v_1604081489_593503000",
                "timeWindowEndTime": "2020-12-24T04:00:00Z",
                "timeWindowStartTime": "2020-12-24T03:00:00Z",
                "type": "RULE_DETECTION",
                "urlBackToProduct": "https://dummy-chronicle/ruleDetections?ruleId=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71&selectedList=RuleDetectionsViewTimeline&selectedDetectionId=de_bea17243-d3b3-14bf-6b57-74e1a2422c68&selectedTimestamp=2020-12-21T03:54:00Z"
            },
            {
                "alertState": "NOT_ALERTING",
                "collectionElements": [
                   {
                        "label": "event",
                        "references": [
                            {
                                "eventTimestamp": "2020-12-24T03:00:11.959Z",
                                "eventType": "NETWORK_DNS",
                                "ingestedTimestamp": "2020-12-24T03:03:17.200062Z",
                                "network": {
                                    "applicationProtocol": "DNS",
                                    "dns": {
                                        "answers": [
                                            {
                                                "data": "10.0.XX.XX",
                                                "name": "is5-ssl.mzstatic.com",
                                                "ttl": 11111,
                                                "type": 1
                                            }
                                        ],
                                        "questions": [
                                            {
                                                "name": "is5-ssl.mzstatic.com",
                                                "type": 1
                                            }
                                        ],
                                        "response": true
                                    }
                                },
                                "principal": {
                                    "hostname": "ray-xxx-laptop",
                                    "ip": [
                                        "10.0.XX.XX"
                                    ],
                                    "mac": [
                                        "88:a6:XX:XX:XX:XX"
                                    ]
                                },
                                "principalAssetIdentifier": "ray-xxx-laptop",
                                "productName": "ExtraHop",
                                "securityResult": [
                                    {
                                        "action": [
                                            "UNKNOWN_ACTION"
                                        ]
                                    }
                                ],
                                "target": {
                                    "ip": [
                                        "10.0.XX.XX"
                                    ]
                                },
                                "targetAssetIdentifier": "10.0.XX.XX"
                            },
                            {
                                "eventTimestamp": "2020-12-24T03:01:43.953Z",
                                "eventType": "NETWORK_DNS",
                                "ingestedTimestamp": "2020-12-24T03:03:17.200062Z",
                                "network": {
                                    "applicationProtocol": "DNS",
                                    "dns": {
                                        "answers": [
                                            {
                                                "data": "10.0.XX.XX",
                                                "name": "is5-ssl.mzstatic.com",
                                                "ttl": 11111,
                                                "type": 1
                                            }
                                        ],
                                        "questions": [
                                            {
                                                "name": "is5-ssl.mzstatic.com",
                                                "type": 1
                                            }
                                        ],
                                        "response": true
                                    }
                                },
                                "principal": {
                                    "hostname": "ray-xxx-laptop",
                                    "ip": [
                                        "10.0.XX.XX"
                                    ],
                                    "mac": [
                                        "88:a6:XX:XX:XX:XX"
                                    ]
                                },
                                "principalAssetIdentifier": "ray-xxx-laptop",
                                "productName": "ExtraHop",
                                "securityResult": [
                                    {
                                        "action": [
                                            "UNKNOWN_ACTION"
                                        ]
                                    }
                                ],
                                "target": {
                                    "ip": [
                                        "10.0.XX.XX"
                                    ]
                                },
                                "targetAssetIdentifier": "10.0.XX.XX"
                            }
                        ]
                   }
                ],
                "createdTime": "2020-12-24T03:13:46.449491Z",
                "detectionFields": [
                    {
                        "key": "client_ip",
                        "value": "10.0.XX.XX"
                    }
                ],
                "detectionTime": "2020-12-24T04:00:00Z",
                "id": "de_d6194710-acd4-c1de-e440-d1c6a7a50fc1",
                "ruleId": "ru_746bd6d6-6b84-4007-b74c-ec90c7306a71",
                "ruleName": "SampleRule",
                "ruleType": "MULTI_EVENT",
                "ruleVersion": "ru_746bd6d6-6b84-4007-b74c-ec90c7306a71@v_1604081489_593503000",
                "timeWindowEndTime": "2020-12-24T04:00:00Z",
                "timeWindowStartTime": "2020-12-24T03:00:00Z",
                "type": "RULE_DETECTION",
                "urlBackToProduct": "https://dummy-chronicle/ruleDetections?ruleId=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71&selectedList=RuleDetectionsViewTimeline&selectedDetectionId=de_d6194710-acd4-c1de-e440-d1c6a7a50fc1&selectedTimestamp=2020-12-21T03:54:00Z"
            }
        ],
        "Token": {
            "name": "gcb-list-detections",
            "nextPageToken": "foobar_page_token"
        }
    }
}
```

##### Human Readable Output

>### Detection(s) Details For Rule: [SampleRule](https://dummy-chronicle/ruleDetections?ruleId=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71&selectedList=RuleDetectionsViewTimeline)
>|Detection ID|Detection Type|Detection Time|Events|Alert State|
>|---|---|---|---|---|
>| [de_bea17243-d3b3-14bf-6b57-74e1a2422c68](https://dummy-chronicle/ruleDetections?ruleId=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71&selectedList=RuleDetectionsViewTimeline&selectedDetectionId=de_bea17243-d3b3-14bf-6b57-74e1a2422c68&selectedTimestamp=2020-12-21T03:54:00Z) | RULE_DETECTION | 2020-12-24T04:00:00Z | **Event Timestamp:** 2020-12-24T03:00:02.559Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com<br/><br/>**Event Timestamp:** 2020-12-24T03:00:40.566Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com | NOT_ALERTING |
>| [de_d6194710-acd4-c1de-e440-d1c6a7a50fc1](https://dummy-chronicle/ruleDetections?ruleId=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71&selectedList=RuleDetectionsViewTimeline&selectedDetectionId=de_d6194710-acd4-c1de-e440-d1c6a7a50fc1&selectedTimestamp=2020-12-21T03:54:00Z) | RULE_DETECTION | 2020-12-24T04:00:00Z | **Event Timestamp:** 2020-12-24T03:00:11.959Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com<br/><br/>**Event Timestamp:** 2020-12-24T03:01:43.953Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com | NOT_ALERTING |
>
>View all detections for this rule in Chronicle by clicking on SampleRule and to view individual detection in Chronicle click on its respective Detection ID.
>
>Note: If a specific version of the rule is provided then detections for that specific version will be fetched.
>Maximum number of detections specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as foobar_page_token.


### 9. gcb-list-rules
***
List the latest versions of all Rules.


##### Base Command

`gcb-list-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| live_rule | To filter live rules. | Optional |
| page_size | Specify the maximum number of Rules to return. You can specify between 1 and 1,000. The default is 100. | Optional |
| page_token | A page token, received from a previous call.  Provide this to retrieve the subsequent page. | Optional |



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Rules.ruleId | String | Unique identifier for a Rule. |
| GoogleChronicleBackstory.Rules.versionId | String | Unique identifier for a specific version of a rule. |
| GoogleChronicleBackstory.Rules.ruleName | String | Name of the rule, as parsed from ruleText. |
| GoogleChronicleBackstory.Rules.ruleText | String | Source code for the rule, as defined by the user. |
| GoogleChronicleBackstory.Rules.liveRuleEnabled | Boolean | Whether the rule is enabled to run as a "Live Rule". |
| GoogleChronicleBackstory.Rules.alertingEnabled | Boolean | Whether the rule is enabled to generate Alerts. |
| GoogleChronicleBackstory.Rules.versionCreateTime | String | A string representing the time in ISO-8601 format. |
| GoogleChronicleBackstory.Rules.compilationState | String | Compilation state of the rule. It can be SUCCEEDED or FAILED. |
| GoogleChronicleBackstory.Rules.compilationError | String | A compilation error if compilationState is FAILED, absent if compilationState is SUCCEEDED. |
| GoogleChronicleBackstory.Rules.Metadata.severity | String | Severity for the rule. |
| GoogleChronicleBackstory.Rules.Metadata.author | String | Name of author for the rule. |
| GoogleChronicleBackstory.Rules.Metadata.description | String | Description of the rule. |
| GoogleChronicleBackstory.Rules.Metadata.reference | String | Reference link for the rule. |
| GoogleChronicleBackstory.Rules.Metadata.created | String | Time at which the rule is created. |
| GoogleChronicleBackstory.Rules.Metadata.updated | String | Time at which the rule is updated. |
| GoogleChronicleBackstory.Token.name | String | The name of the command to which the value of the nextPageToken corresponds. | 
| GoogleChronicleBackstory.Token.nextPageToken | String | A page token that can be provided to the next call to view the next page of Rules. Absent if this is the last page. |


##### Command Example
```!gcb-list-rules page_size=2```

##### Context Example
```json

{
    "GoogleChronicleBackstory": {
       "rules": [
          {
             "ruleId": "ru_c5b129e4-9e20-44ad-ad23-78117bd2a2af",
             "versionId": "ru_c5b129e4-9e20-44ad-ad23-78117bd2a2af@v_1614773287_876527000",
             "ruleName": "malicious_extensions",
             "metadata": {
                "author": "analyst5",
                "description": "Use to detects malicious extentions from email attachments.",
                "severity": "High"
             },
             "ruleText": "rule malicious_extensions {\n  meta:\n    author = \"analyst5\"\n    description = \"Use to detects malicious extentions from email attachments.\"\n    severity = \"High\"\n\n  events:\n    $event.metadata.event_type = \"EMAIL_TRANSACTION\"\n    $event.about.file.mime_type = /^.*\\.(com|exe|bat|cmd|cpl|jar|js|msi|rar|reg)$/\n\n  condition:\n      $event\n    \n}\n",
             "alertingEnabled": true,
             "versionCreateTime": "2021-03-03T12:08:07.876527Z",
             "compilationState": "SUCCEEDED"
          },
          {
             "ruleId": "ru_d63cfaeb-23d7-4e0a-b342-5f880f6129f9",
             "versionId": "ru_d63cfaeb-23d7-4e0a-b342-5f880f6129f9@v_1614369854_162095000",
             "ruleName": "empire_monkey",
             "metadata": {
                "version": "0.01",
                "created": "2019/04/02",
                "category": "process_creation",
                "product": "windows",
                "mitre": "t1086, execution",
                "author": "Markus Neis",
                "description": "Detects EmpireMonkey APT reported Activity  License: https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md.",
                "reference": "https://tdm.socprime.com/tdm/info/jFbYfF51ECXh"
             },
             "ruleText": "rule empire_monkey {\n\tmeta:\n\t\tauthor = \"Markus Neis\"\n\t\tdescription = \"Detects EmpireMonkey APT reported Activity  License: https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md.\"\n\t\treference = \"https://tdm.socprime.com/tdm/info/jFbYfF51ECXh\"\n\t\tversion = \"0.01\"\n\t\tcreated = \"2019/04/02\"\n\t\tcategory = \"process_creation\"\n\t\tproduct = \"windows\"\n\t\tmitre = \"t1086, execution\"\n\n\tevents:\n(re.regex($selection_cutil.target.process.command_line, `.*/i:%APPDATA%\\\\logs\\.txt scrobj\\.dll`) and (re.regex($selection_cutil.target.process.file.full_path, `.*\\\\cutil\\.exe`) or $selection_cutil.metadata.description = \"Microsoft(C) Registerserver\"))\n\n\tcondition:\n\t\t$selection_cutil\n}\n",
             "versionCreateTime": "2021-02-26T20:04:14.162095Z",
             "compilationState": "SUCCEEDED"
          }
       ],
       "nextPageToken": "foobar_page_token"
    }
}
```

##### Human Readable Output

>### Rule(s) Details
>| Rule ID | Rule Name | Compilation State |
>| --- | --- | --- |
>| ru_42f02f52-544c-4b6e-933c-df17648d5831 | email_execution | SUCCEEDED |
>| ru_f13faad1-0041-476c-a05a-40e01c942796 | rule_1616480950177 | SUCCEEDED |
>
> Maximum number of rules specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as foobar_page_token.
