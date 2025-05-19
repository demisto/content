## Overview

---

Use the Chronicle integration to retrieve Asset alerts or IOC Domain matches as Incidents. Use it to fetch a list of infected assets based on the indicator accessed. This integration also provides reputation and threat enrichment of indicators observed in the enterprise.

**Note:** The `gcb-list-alerts` command would fetch both Asset as well as User alerts depending upon the argument `alert_type`. In this case, the total number of alerts fetched might not match with the value of the page_size argument and this is a known behaviour with respect to the endpoint from which we are fetching the alerts.

**Note:** The `gcb-list-rules` command would filter rules depending upon the argument `live_rule`.In this case, the total number of rules fetched might not match with the value of the page_size argument and this is a known behaviour with respect to the endpoint from which we are fetching the rules.

**Note:** The commands and fetch incidents mechanism will do up to 3 internal retries with a gap of 15, 30, and 60 seconds (exponentially) between the retries.

#### Troubleshoot

**Note:** If you are expecting a high volume of alerts from Chronicle, you can reduce the time required to fetch them by increasing the "How many incidents to fetch each time" parameter while decreasing the "Incidents Fetch Interval" parameter in the integration configuration.

##### Problem #1

Duplication of rule detection incidents when fetched from Chronicle.

##### Solution #1

- The incidents are re-fetched starting from first fetch time window when user resets the last run time stamp. 
- To avoid duplication of incidents with duplicate detection ids and to drop them, XSOAR provides inbuilt features of Pre-process rules. 
- This setting XSOAR platform end users have to set on their own as it's not part of the integration pack.
- Pre-processing rules enable users to perform certain actions on incidents as they are ingested into XSOAR. 
- Using these rules users can choose incoming events on which to perform actions for example drop all the incoming incidents, drop and update incoming incidents if certain conditions are met.
- Please refer for information on Pre-Process rules:
  <https://xsoar.pan.dev/docs/incidents/incident-pre-processing#:~:text=Creating%20Rules&text=Navigate%20to%20Settings%20%3E%20Integrations%20%3E%20Pre,viewing%20the%20list%20of%20rules>.

## FAQ - Fetch Detections

##### Question #1

If we have 3 rules added in the configuration (R1, R2, R3) and we are getting 429 or 500 errors in R2. Will my integration stop fetching the detections or will it fetch detections of rule R3?

###### Case #1: When HTTP 429 or 500 error resumes before 60 retry attempts:

- System will re-attempt to fetch the detection after 1 min for the same R2 rule. The system will re-attempt to get the detections for Rule R2, 60 times.
If 429 or 500 error is recovered before 60 attempts, the system will fetch the detections for Rule R2 and then proceed ahead for Rule R3.

###### Case #2: When HTTP 429 or 500 error does not resume for 60 retry attempts:

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

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Chronicle.
3. Click **Add instance** to create and configure a new integration instance.
    - **Name**: a textual name for the integration instance.
    - **User's Service Account JSON**
    - **Region**: Select the region based on the location of the chronicle backstory instance. If region is not listed in the dropdown, choose the "Other" option and specify the region in the "Other Region" text field.
    - **Other Region**: Specify the region based on the location of the chronicle backstory instance. Only applicable if the "Other" option is selected in the Region dropdown.
    - **Provide comma(',') separated categories (e.g. APT-Activity, Phishing). Indicators belonging to these "categories" would be considered as "malicious" when executing reputation commands.**
    - **Provide comma(',') separated categories (e.g. Unwanted, VirusTotal YARA Rule Match). Indicators belonging to these "categories" would be considered as "suspicious" when executing reputation commands.**
    - **Specify the "severity" of indicator that should be considered as "malicious" irrespective of the category.  If you wish to consider all indicators with High severity as Malicious, set this parameter to 'High'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only.**
    - **Specify the "severity" of indicator that should be considered as "suspicious" irrespective of the category. If you wish to consider all indicators with Medium severity as Suspicious, set this parameter to 'Medium'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only.**
    - **Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "malicious". The value provided should be greater than the suspicious threshold. This configuration is applicable to reputation commands only.**
    - **Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "suspicious". The value provided should be smaller than the malicious threshold. This configuration is applicable to reputation commands only.**
    - **Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "malicious". The confidence level configured should have higher precedence than the suspicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH.**
    - **Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "suspicious". The confidence level configured should have lesser precedence than the malicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH.**
    - **Fetches incidents**
    - **First fetch time**
    - **How many incidents to fetch each time**
    - **Chronicle Alert Type (Select the type of data to consider for fetch incidents)**
    - **Time window (in minutes)**
    - **Select the severity of alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (If not selected, fetches all alerts).**
    - **Detections to fetch by Rule ID or Version ID**
    - **Fetch all rules detections**
    - **Filter detections by alert state**
    - **List Basis**  
    - **Trust any certificate (not secure)**
    - **Use system proxy settings**
4. Click **Test** to validate the URLs, token, and connection.

## Fetched Incidents Data

---
Fetch-incidents feature can pull events from Google Chronicle which can be converted into actionable incidents for further investigation. It is the function that Cortex XSOAR calls every minute to import new incidents and can be enabled by the "Fetches incidents" parameter in the integration configuration.

#### Configuration Parameters for Fetch-incidents

- First fetch time interval: **Default** 3 days
- How many incidents to fetch each time: **Default** 100
- Select the severity of alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (If not selected, fetches all alerts). **Only applicable for asset alerts**.
- Chronicle Alert Type (Select the type of data to consider for fetch incidents):
  - IOC Domain matches **Default**
  - Assets with alerts
  - Curated Rule Detection alerts
  - Detection alerts
  - User alerts
- Time window (in minutes): **Not applicable for IOC Domain matches**
  - 15 **Default**
  - 30
  - 45
  - 60
- Detections to fetch by Rule ID or Version ID **Only applicable for Detection alerts and Curated Rule Detection alerts**
- Fetch all rules detections **Only applicable for Detection alerts**
- Filter detections by alert state: **Only applicable for Detection alerts and Curated Rule Detection alerts**
  - ALERTING
  - NOT ALERTING
 
| **Name** | **Initial Value** |
| --- | --- |
| First fetch time interval. The UTC date or relative timestamp from where to start fetching incidents. <br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/> For example: 10 minutes, 5 hours, 8 days, 2 weeks, 8 months, 2021-12-31, 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | 3 days |
| How many incidents to fetch each time. | 100 |
| Select the severity of alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (If not selected, fetches all alerts). *Only applicable for asset alerts.* | Not selected |
| Chronicle Alert Type (Select the type of data to consider for fetch incidents). | IOC Domain matches (Default), Assets with alerts, Curated Rule Detection alerts, Detection alerts and User alerts | 
| Time window (in minutes) | 15 |
| Detections to fetch by Rule ID or Version ID | empty |
| Fetch all rules detections | Not selected |
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

#### Incident field mapping - Curated Rule Detection alerts

| **Name** | **Initial Value** |
| --- | --- |
| name | &lt;RuleName&gt; |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |
| severity | severity |
| Description | description |
| Detection URL | urlBackToProduct |
| Risk Score | riskScore |
| Tags | tags |

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
10. gcb-create-rule
11. gcb-get-rule
12. gcb-delete-rule
13. gcb-create-rule-version
14. gcb-change-rule-alerting-status
15. gcb-change-live-rule-status
16. gcb-start-retrohunt
17. gcb-get-retrohunt
18. gcb-list-retrohunts
19. gcb-cancel-retrohunt
20. gcb-list-reference-list
21. gcb-get-reference-list
22. gcb-create-reference-list
23. gcb-update-reference-list
24. gcb-verify-reference-list
25. gcb-test-rule-stream
26. gcb-list-useraliases
27. gcb-list-assetaliases
28. gcb-list-curatedrules
29. gcb-list-curatedrule-detections
30. gcb-udm-search
31. gcb-verify-value-in-reference-list
32. gcb-verify-rule
33. gcb-get-event

### 1. gcb-list-iocs

---
Lists the IOC Domain matches within your enterprise for the specified time interval. The indicator of compromise (IOC) domain matches lists for which the domains that your security infrastructure has flagged as both suspicious and that have been seen recently within your enterprise.

##### Base Command

`gcb-list-iocs`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetches IOC Domain matches in the specified time interval. If configured, overrides the start_time argument. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. Default is 10000. | Optional | 


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
        },
        {
            "Artifact": "0.0.0.1",
            "IocIngestTime": "2023-11-30T19:26:41.266555Z",
            "FirstAccessedTime": "2023-01-17T09:54:19Z",
            "LastAccessedTime": "2023-01-17T09:54:19Z",
            "Sources": [
                {
                    "Category": "Unwanted",
                    "IntRawConfidenceScore": 0,
                    "NormalizedConfidenceScore": "Medium",
                    "RawSeverity": "Medium",
                    "Source": "Threat Intelligence"
                }
            ]
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

>### IOC Domain Matches

>|Artifact|Category|Source|Confidence|Severity|IOC ingest time|First seen|Last seen|
>|---|---|---|---|---|---|---|---|
>| anx.tb.ask.com | Spyware Reporting Server | ET Intelligence Rep List | Low | Medium | 7 days ago | a year ago | 3 hours ago |
>| [0.0.0.1](https://demo.backstory.chronicle.security/destinationIpResults?ip=0.0.0.1) | Unwanted | Threat Intelligence | Medium | Medium | 3 days ago | 10 months ago | 10 months ago |


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
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| end_time | The value of the end time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied,  the default is current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. Default is 10000. | Optional | 


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
| DBotScore.Score | Number | The actual score. | 
| IP.Address | String | The IP address of the artifact. | 
| IP.Malicious.Vendor | String | For malicious IPs, the vendor that made the decision. | 
| IP.Malicious.Description | String | For malicious IPs, the reason that the vendor made the decision. | 
| GoogleChronicleBackstory.IP.IoCQueried | String | The artifact that was queried. | 
| GoogleChronicleBackstory.IP.Sources.Address.IpAddress | String | The IP address of the artifact. | 
| GoogleChronicleBackstory.IP.Sources.Address.Domain | String | The domain name of the artifact. | 
| GoogleChronicleBackstory.IP.Sources.Address.Port | Unknown | The port numbers of the artifact. | 
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

>IP: 23.20.239.12 found with Reputation: Unknown

>### Reputation Parameters

>|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|---|---|
>| - | 23.20.239.12 | Known CnC for Mobile specific Family | 70 | High | 2018-12-05T00:00:00Z | 2019-04-10T00:00:00Z |
>| mytemplatewebsite.com | 23.20.239.12 | Blocked | High | High | 1970-01-01T00:00:00Z | 2020-02-16T08:56:06Z |
>
>View IoC details in Chronicle


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
| DBotScore.Score | Number | The actual score. | 
| Domain.Name | String | The domain name of the artifact. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. | 
| GoogleChronicleBackstory.Domain.IoCQueried | String | The domain that queried. | 
| GoogleChronicleBackstory.Domain.Sources.Address.IpAddress | String | The IP address of the artifact. | 
| GoogleChronicleBackstory.Domain.Sources.Address.Domain | String | The domain name of the artifact. | 
| GoogleChronicleBackstory.Domain.Sources.Address.Port | Unknown | The port numbers of the artifact. | 
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

>Domain: bing.com found with Reputation: Unknown

>### Reputation Parameters

>|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|---|---|
>| bing.com | - | Observed serving executables | 67 | Low | 2013-08-06T00:00:00Z | 2020-01-14T00:00:00Z |
>
>View IoC details in Chronicle


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
| GoogleChronicleBackstory.IocDetails.Sources.Address.Port | Unknown | The port numbers of the artifact. | 
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

>### IoC Details

>|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|---|---|
>| - | 23.20.239.12 | Known CnC for Mobile specific Family | 70 | High | 2018-12-05T00:00:00Z | 2019-04-10T00:00:00Z |
>| mytemplatewebsite.com | 23.20.239.12 | Blocked | High | High | 1970-01-01T00:00:00Z | 2020-02-16T08:56:06Z |
>
>View IoC details in Chronicle


### 6. gcb-list-alerts

---
List all the alerts tracked within your enterprise for the specified time range. Both the parsed alerts and their corresponding raw alert logs are returned.

##### Base Command

`gcb-list-alerts`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetch alerts for the specified time range. If preset_time_range is configured, overrides the start_time and end_time arguments. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| end_time | The value of the end time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied,  the default is current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 100000. Default is 10000. | Optional | 
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

>### Security Alert(s)

>|Alerts|Asset|Alert Names|First Seen|Last Seen|Severities|Sources|
>|---|---|---|---|---|---|---|
>| 1 | rosie-hayes-pc | Authentication failure [32038] | 6 hours ago | 6 hours ago | Medium | Internal Alert |


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
| start_time | The value of the start time for your request. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 2 hours earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| end_time | The value of the end time for your request. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| page_size | Specify the maximum number of events to fetch. You can specify between 1 and 10000. Default is 10000. | Optional | 
| reference_time | Specify the reference time for the asset you are investigating, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers start time as reference time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |

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
>Maximum number of events specified in page_size has been returned. There might still be more events in your Chronicle account. To fetch the next set of events, execute the command with the start time as 2020-01-01T23:59:38Z


### 8. gcb-list-detections

---
Return the detections for the specified version of a rule, the latest version of a rule, all versions of a rule, or all versions of all rules.


##### Base Command

`gcb-list-detections`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique identifier for a rule or specific version of a rule, defined and returned by the server. You can specify exactly one rule identifier. Use the following format to specify the id: ru_{UUID} or {ruleId}@v_{int64}_{int64}. If not specified then detections for all versions of all rules are returned. | Optional | 
| detection_start_time | (Deprecated)Time to begin returning detections, filtering on a detection's detectionTime. If not specified, the start time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| detection_end_time | (Deprecated)Time to stop returning detections, filtering on a detection's detectionTime. If not specified, the end time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| start_time | Time to begin returning detections, filtering by the detection field specified in the listBasis parameter. If not specified, the start time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| end_time | Time to stop returning detections, filtering by the detection field specified by the listBasis parameter. If not specified, the end time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 
| detection_for_all_versions | Whether the user wants to retrieve detections for all versions of a rule with a given rule identifier.<br/><br/>Note: If this option is set to true, rule id is required. | Optional | 
| list_basis | Sort detections by "DETECTION_TIME" or by "CREATED_TIME". If not specified, it defaults to "DETECTION_TIME". Detections are returned in descending order of the timestamp.<br/><br/>Note: Requires either "start_time" or "end_time" argument. | Optional | 
| alert_state | Filter detections on if they are ALERTING or NOT_ALERTING.<br/>Avoid specifying to return all detections. | Optional | 
| page_size | Specify the limit on the number of detections to display. You can specify between 1 and 1000. | Optional | 
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
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_bea17243-d3b3-14bf-6b57-74e1a2422c68"
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
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_d6194710-acd4-c1de-e440-d1c6a7a50fc1"
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

>### Detection(s) Details For Rule: [SampleRule](https://dummy-chronicle/ruleDetections?ruleId=ru_746bd6d6-6b84-4007-b74c-ec90c7306a71)

>|Detection ID|Detection Type|Detection Time|Events|Alert State|
>|---|---|---|---|---|
>| [de_bea17243-d3b3-14bf-6b57-74e1a2422c68](https://dummy-chronicle/alert?alertId=de_bea17243-d3b3-14bf-6b57-74e1a2422c68) | RULE_DETECTION | 2020-12-24T04:00:00Z | **Event Timestamp:** 2020-12-24T03:00:02.559Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com<br/><br/>**Event Timestamp:** 2020-12-24T03:00:40.566Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com | NOT_ALERTING |
>| [de_d6194710-acd4-c1de-e440-d1c6a7a50fc1](https://dummy-chronicle/alert?alertId=de_d6194710-acd4-c1de-e440-d1c6a7a50fc1) | RULE_DETECTION | 2020-12-24T04:00:00Z | **Event Timestamp:** 2020-12-24T03:00:11.959Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com<br/><br/>**Event Timestamp:** 2020-12-24T03:01:43.953Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** ray-xxx-laptop<br/>**Target Asset Identifier:** 10.0.XX.XX<br/>**Queried Domain:** is5-ssl.mzstatic.com | NOT_ALERTING |
>
>View all detections for this rule in Chronicle by clicking on SampleRule and to view individual detection in Chronicle click on its respective Detection ID.
>
>Note: If a specific version of the rule is provided then detections for that specific version will be fetched.
>Maximum number of detections specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as foobar_page_token.


### 9. gcb-list-rules

---
List the latest versions of all Rules.


##### Base Command

`gcb-list-rules`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| live_rule | To filter live rules. | Optional |
| page_size | Specify the maximum number of Rules to return. You can specify between 1 and 1000. Default is 100. | Optional |
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


### 10. gcb-create-rule

---
Creates a new rule. By default the live rule status will be set to disabled.


#### Base Command

`gcb-create-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_text | Rule text in YARA-L 2.0 format for the rule to be created. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Rules.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.Rules.versionId | String | Unique identifier for a specific version of a rule. | 
| GoogleChronicleBackstory.Rules.ruleName | String | Name of the rule, as parsed from ruleText. | 
| GoogleChronicleBackstory.Rules.ruleText | String | Source code for the rule, as defined by the user. | 
| GoogleChronicleBackstory.Rules.liveRuleEnabled | Boolean | Whether the rule is enabled to run as a Live Rule. | 
| GoogleChronicleBackstory.Rules.alertingEnabled | Boolean | Whether the rule is enabled to generate Alerts. | 
| GoogleChronicleBackstory.Rules.versionCreateTime | String | A string representing the time in ISO-8601 format. | 
| GoogleChronicleBackstory.Rules.compilationState | String | Compilation state of the rule. It can be SUCCEEDED or FAILED. | 
| GoogleChronicleBackstory.Rules.compilationError | String | A compilation error if compilationState is FAILED, absent if compilationState is SUCCEEDED. | 
| GoogleChronicleBackstory.Rules.ruleType | String | Indicates the type of event in rule. It can be SINGLE_EVENT or MULTI_EVENT. | 
| GoogleChronicleBackstory.Rules.metadata.severity | String | Severity for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.author | String | Name of author for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.description | String | Description of the rule. | 
| GoogleChronicleBackstory.Rules.metadata.reference | String | Reference link for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.created | String | Time at which the rule is created. | 
| GoogleChronicleBackstory.Rules.metadata.updated | String | Time at which the rule is updated. | 

#### Command Example

```!gcb-create-rule rule_text="rule demoRuleCreatedFromAPI {meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e}"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": {
            "compilationState": "SUCCEEDED",
            "metadata": {
                "author": "securityuser",
                "description": "single event rule that should generate detections"
            },
            "ruleId": "ru_b28005ec-e027-4300-9dcc-0c6ef5dda8e6",
            "ruleName": "demoRuleCreatedFromAPI",
            "ruleText": "rule demoRuleCreatedFromAPI {meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e}\n",
            "ruleType": "SINGLE_EVENT",
            "versionCreateTime": "2022-06-23T06:21:36.217135Z",
            "versionId": "ru_b28005ec-e027-4300-9dcc-0c6ef5dda8e6@v_1655965296_217135000"
        }
    }
}
```

#### Human Readable Output

>### Rule Detail

>|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|
>|---|---|---|---|---|---|---|---|
>| ru_b28005ec-e027-4300-9dcc-0c6ef5dda8e6 | ru_b28005ec-e027-4300-9dcc-0c6ef5dda8e6@v_1655965296_217135000 | securityuser | demoRuleCreatedFromAPI | single event rule that should generate detections | 2022-06-23T06:21:36.217135Z | SUCCEEDED | rule demoRuleCreatedFromAPI {meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e}<br/> |


### 11. gcb-get-rule

---
Retrieves the rule details of specified Rule ID or Version ID.


#### Base Command

`gcb-get-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule ID or Version ID of the rule to be retrieved. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Rules.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.Rules.versionId | String | Unique identifier for a specific version of a rule. | 
| GoogleChronicleBackstory.Rules.ruleName | String | Name of the rule, as parsed from ruleText. | 
| GoogleChronicleBackstory.Rules.ruleText | String | Source code for the rule, as defined by the user. | 
| GoogleChronicleBackstory.Rules.liveRuleEnabled | Boolean | Whether the rule is enabled to run as a Live Rule. | 
| GoogleChronicleBackstory.Rules.alertingEnabled | Boolean | Whether the rule is enabled to generate Alerts. | 
| GoogleChronicleBackstory.Rules.versionCreateTime | String | A string representing the time in ISO-8601 format. | 
| GoogleChronicleBackstory.Rules.compilationState | String | Compilation state of the rule. It can be SUCCEEDED or FAILED. | 
| GoogleChronicleBackstory.Rules.compilationError | String | A compilation error if compilationState is FAILED, absent if compilationState is SUCCEEDED. | 
| GoogleChronicleBackstory.Rules.ruleType | String | Indicates the type of event in rule. It can be SINGLE_EVENT or MULTI_EVENT. | 
| GoogleChronicleBackstory.Rules.metadata.severity | String | Severity for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.author | String | Name of author for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.description | String | Description of the rule. | 
| GoogleChronicleBackstory.Rules.metadata.reference | String | Reference link for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.created | String | Time at which the rule is created. | 
| GoogleChronicleBackstory.Rules.metadata.updated | String | Time at which the rule is updated. | 

#### Command Example

```!gcb-get-rule id=ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": {
            "compilationState": "SUCCEEDED",
            "metadata": {
                "author": "securityuser",
                "description": "single event rule that should generate detections"
            },
            "ruleId": "ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7",
            "ruleName": "demoRuleCreatedFromAPI",
            "ruleText": "rule demoRuleCreatedFromAPI {meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e}\n",
            "ruleType": "SINGLE_EVENT",
            "versionCreateTime": "2022-06-22T13:28:20.905647Z",
            "versionId": "ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7@v_1655904500_905647000"
        }
    }
}
```

#### Human Readable Output

>### Rule Details

>|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|
>|---|---|---|---|---|---|---|---|
>| ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 | ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7@v_1655904500_905647000 | securityuser | demoRuleCreatedFromAPI | single event rule that should generate detections | 2022-06-22T13:28:20.905647Z | SUCCEEDED | rule demoRuleCreatedFromAPI {meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e}<br/> |


### 12. gcb-delete-rule

---
Deletes the rule specified by Rule ID.


#### Base Command

`gcb-delete-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | ID of the rule to be deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.DeleteRule.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.DeleteRule.actionStatus | String | Whether the rule is successfully deleted or not. | 

#### Command Example

```!gcb-delete-rule rule_id=ru_1e0b123a-5ad8-47d1-94fb-0b874a526f9b```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "DeleteRule": {
            "actionStatus": "SUCCESS",
            "ruleId": "ru_1e0b123a-5ad8-47d1-94fb-0b874a526f9b"
        }
    }
}
```

#### Human Readable Output

>### Rule with ID ru_1e0b123a-5ad8-47d1-94fb-0b874a526f9b deleted successfully.

>|Rule ID|Action Status|
>|---|---|
>| ru_1e0b123a-5ad8-47d1-94fb-0b874a526f9b | SUCCESS |


### 13. gcb-create-rule-version

---
Creates a new version of an existing rule.


#### Base Command

`gcb-create-rule-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID for a Rule for which to create a new version. | Required | 
| rule_text | Rule text in YARA-L 2.0 format for the new version of the rule to be created. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Rules.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.Rules.versionId | String | Unique identifier for a specific version of a rule. | 
| GoogleChronicleBackstory.Rules.ruleName | String | Name of the rule, as parsed from ruleText. | 
| GoogleChronicleBackstory.Rules.ruleText | String | Source code for the rule, as defined by the user. | 
| GoogleChronicleBackstory.Rules.liveRuleEnabled | Boolean | Whether the rule is enabled to run as a Live Rule. | 
| GoogleChronicleBackstory.Rules.alertingEnabled | Boolean | Whether the rule is enabled to generate Alerts. | 
| GoogleChronicleBackstory.Rules.versionCreateTime | String | A string representing the time in ISO-8601 format. | 
| GoogleChronicleBackstory.Rules.compilationState | String | Compilation state of the rule. It can be SUCCEEDED or FAILED. | 
| GoogleChronicleBackstory.Rules.compilationError | String | A compilation error if compilationState is FAILED, absent if compilationState is SUCCEEDED. | 
| GoogleChronicleBackstory.Rules.ruleType | String | Indicates the type of event in rule. It can be SINGLE_EVENT or MULTI_EVENT. | 
| GoogleChronicleBackstory.Rules.metadata.severity | String | Severity for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.author | String | Name of author for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.description | String | Description of the rule. | 
| GoogleChronicleBackstory.Rules.metadata.reference | String | Reference link for the rule. | 
| GoogleChronicleBackstory.Rules.metadata.created | String | Time at which the rule is created. | 
| GoogleChronicleBackstory.Rules.metadata.updated | String | Time at which the rule is updated. | 

#### Command Example

```!gcb-create-rule-version rule_id=ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 rule_text="rule demoRuleCreatedFromAPI {meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e}"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": {
            "compilationState": "SUCCEEDED",
            "metadata": {
                "author": "securityuser",
                "description": "single event rule that should generate detections"
            },
            "ruleId": "ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7",
            "ruleName": "demoRuleCreatedFromAPI",
            "ruleText": "rule demoRuleCreatedFromAPI {meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e}\n",
            "ruleType": "SINGLE_EVENT",
            "versionCreateTime": "2022-06-23T06:22:15.343423Z",
            "versionId": "ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7@v_1655965335_343423000"
        }
    }
}
```

#### Human Readable Output

>### New Rule Version Details

>|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|
>|---|---|---|---|---|---|---|---|
>| ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 | ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7@v_1655965335_343423000 | securityuser | demoRuleCreatedFromAPI | single event rule that should generate detections | 2022-06-23T06:22:15.343423Z | SUCCEEDED | rule demoRuleCreatedFromAPI {meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e}<br/> |


### 14. gcb-change-rule-alerting-status

---
Updates the alerting status for a rule specified by Rule ID.


#### Base Command

`gcb-change-rule-alerting-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | ID of the rule. | Required | 
| alerting_status | New alerting status for the Rule. Possible values are 'enable' or 'disable'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RuleAlertingChange.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.RuleAlertingChange.actionStatus | String | Whether the alerting status for the rule is successfully updated or not. | 
| GoogleChronicleBackstory.RuleAlertingChange.alertingStatus | String | New alerting status for the rule. | 

#### Command Example

```!gcb-change-rule-alerting-status alerting_status=enable rule_id=ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RuleAlertingChange": {
            "actionStatus": "SUCCESS",
            "alertingStatus": "enable",
            "ruleId": "ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7"
        }
    }
}
```

#### Human Readable Output

>### Alerting Status

>Alerting status for the rule with ID ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 has been successfully enabled.
> 
>|Rule ID|Action Status|
>|---|---|
>| ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 | SUCCESS |


### 15. gcb-change-live-rule-status

---
Updates the live rule status for a rule specified by Rule ID.


#### Base Command

`gcb-change-live-rule-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | ID of the rule. | Required | 
| live_rule_status | New live rule status for the Rule. Possible values are 'enable' or 'disable'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.LiveRuleStatusChange.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.LiveRuleStatusChange.actionStatus | String | Whether the live rule status for the rule is successfully updated or not. | 
| GoogleChronicleBackstory.LiveRuleStatusChange.liveRuleStatus | String | New live rule status for the rule. | 

#### Command Example

```!gcb-change-live-rule-status live_rule_status=enable rule_id=ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "LiveRuleStatusChange": {
            "actionStatus": "SUCCESS",
            "liveRuleStatus": "enable",
            "ruleId": "ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7"
        }
    }
}
```

#### Human Readable Output

>### Live Rule Status

>Live rule status for the rule with ID ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 has been successfully enabled.
> 
>|Rule ID|Action Status|
>|---|---|
>| ru_99bfa421-2bf2-4440-9ac8-6b1acab170e7 | SUCCESS |


### 16. gcb-start-retrohunt

---
Initiate a retrohunt for the specified rule.


#### Base Command

`gcb-start-retrohunt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID or Version ID of the rule whose retrohunt is to be started. | Required | 
| start_time | Start time for the time range of logs being processed. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 1 week earlier than current time.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. Default is 1 week. | Optional | 
| end_time | End time for the time range of logs being processed. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 10 minutes earlier than current time.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. Default is 10 min. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RetroHunt.retrohuntId | String | Unique identifier for a retrohunt, defined and returned by the server. | 
| GoogleChronicleBackstory.RetroHunt.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.RetroHunt.versionId | String | Unique identifier for a specific version of a rule. | 
| GoogleChronicleBackstory.RetroHunt.eventStartTime | Date | Start time for the time range of logs being processed. | 
| GoogleChronicleBackstory.RetroHunt.eventEndTime | Date | End time for the time range of logs being processed. | 
| GoogleChronicleBackstory.RetroHunt.retrohuntStartTime | Date | Start time for the retrohunt. | 
| GoogleChronicleBackstory.RetroHunt.state | String | Current state of the retrohunt. It can be STATE_UNSPECIFIED, RUNNING, DONE, or CANCELLED. | 

#### Command Example

```!gcb-start-retrohunt rule_id=ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 start_time="52 weeks"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": {
            "eventEndTime": "2022-06-16T06:58:19.994598Z",
            "eventStartTime": "2021-06-17T07:08:19.991404Z",
            "retrohuntId": "oh_4c02f3a7-fe3c-49a0-82ba-ab255dd87723",
            "retrohuntStartTime": "2022-06-16T07:08:21.958022Z",
            "ruleId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49",
            "state": "RUNNING",
            "versionId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000"
        }
    }
}
```

#### Human Readable Output

>### Retrohunt Details

>|Retrohunt ID|Rule ID|Version ID|Event Start Time|Event End Time|Retrohunt Start Time|State|
>|---|---|---|---|---|---|---|
>| oh_4c02f3a7-fe3c-49a0-82ba-ab255dd87723 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000 | 2021-06-17T07:08:19.991404Z | 2022-06-16T06:58:19.994598Z | 2022-06-16T07:08:21.958022Z | RUNNING |


### 17. gcb-get-retrohunt

---
Get retrohunt for a specific version of rule.


#### Base Command

`gcb-get-retrohunt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule ID or Version ID of the rule whose retrohunt is to be retrieved. | Required |
| retrohunt_id | Unique identifier for a retrohunt, defined and returned by the server. You must specify exactly one retrohunt identifier. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RetroHunt.retrohuntId | String | Unique identifier for a retrohunt, defined and returned by the server. |
| GoogleChronicleBackstory.RetroHunt.ruleId | String | Unique identifier for a Rule. |
| GoogleChronicleBackstory.RetroHunt.versionId | String | Unique identifier for a specific version of a rule. |
| GoogleChronicleBackstory.RetroHunt.eventStartTime | Date | Start time for the time range of logs being processed. |
| GoogleChronicleBackstory.RetroHunt.eventEndTime | Date | End time for the time range of logs being processed. |
| GoogleChronicleBackstory.RetroHunt.retrohuntStartTime | Date | Start time for the retrohunt. |
| GoogleChronicleBackstory.RetroHunt.retrohuntEndTime | Date | End time for the retrohunt. |
| GoogleChronicleBackstory.RetroHunt.state | String | Current state of the retrohunt. It can be STATE_UNSPECIFIED, RUNNING, DONE or CANCELLED. |
| GoogleChronicleBackstory.RetroHunt.progressPercentage | Number | Percentage progress towards retrohunt completion \(0.00 to 100.00\). |

#### Command Example

```!gcb-get-retrohunt id=ru_7ba19ccc-be0d-40d3-91dc-ab3c41251818 retrohunt_id=oh_cbb6b859-5c9d-4af9-8d74-1a58321078ad```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": {
            "eventEndTime": "2022-06-15T13:03:06.834384Z",
            "eventStartTime": "2022-06-08T13:03:04.793333Z",
            "progressPercentage": 100,
            "retrohuntEndTime": "2022-06-15T13:05:46.894926Z",
            "retrohuntId": "oh_cbb6b859-5c9d-4af9-8d74-1a58321078ad",
            "retrohuntStartTime": "2022-06-15T13:05:12.774180Z",
            "ruleId": "ru_7ba19ccc-be0d-40d3-91dc-ab3c41251818",
            "state": "DONE",
            "versionId": "ru_7ba19ccc-be0d-40d3-91dc-ab3c41251818@v_1655291303_302767000"
        }
    }
}
```

#### Human Readable Output

>### Retrohunt Details

>|Retrohunt ID|Rule ID|Version ID|Event Start Time|Event End Time|Retrohunt Start Time|Retrohunt End Time|State|Progress Percentage|
>|---|---|---|---|---|---|---|---|---|
>| oh_cbb6b859-5c9d-4af9-8d74-1a58321078ad | ru_7ba19ccc-be0d-40d3-91dc-ab3c41251818 | ru_7ba19ccc-be0d-40d3-91dc-ab3c41251818@v_1655291303_302767000 | 2022-06-08T13:03:04.793333Z | 2022-06-15T13:03:06.834384Z | 2022-06-15T13:05:12.774180Z | 2022-06-15T13:05:46.894926Z | DONE | 100 |


### 18. gcb-list-retrohunts

---
List retrohunts for a rule.


#### Base Command

`gcb-list-retrohunts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule ID or Version ID of the rule whose retrohunts are to be listed. If not supplied, retohunts for all versions of all rules will be listed. | Optional | 
| retrohunts_for_all_versions | Whether to retrieve retrohunts for all versions of a rule with a given rule identifier.<br/>Note: If this option is set to true, rule id is required. Possible values are: true, false. Default is false. | Optional | 
| state | Filter retrohunts based on their status. The possible values are "RUNNING", "DONE", or "CANCELLED". | Optional | 
| page_size | Specify the maximum number of retohunts to return. You can specify between 1 and 1000. Default is 100. | Optional | 
| page_token | A page token, received from a previous call. Provide this to retrieve the subsequent page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RetroHunt.retrohuntId | String | Unique identifier for a retrohunt, defined and returned by the server. | 
| GoogleChronicleBackstory.RetroHunt.ruleId | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.RetroHunt.versionId | String | Unique identifier for a specific version of a rule. | 
| GoogleChronicleBackstory.RetroHunt.eventStartTime | Date | Start time for the time range of logs being processed. | 
| GoogleChronicleBackstory.RetroHunt.eventEndTime | Date | End time for the time range of logs being processed. | 
| GoogleChronicleBackstory.RetroHunt.retrohuntStartTime | Date | Start time for the retrohunt. | 
| GoogleChronicleBackstory.RetroHunt.retrohuntEndTime | Date | End time for the retrohunt. | 
| GoogleChronicleBackstory.RetroHunt.state | String | Current state of the retrohunt. It can be STATE_UNSPECIFIED, RUNNING, DONE or CANCELLED. | 
| GoogleChronicleBackstory.RetroHunt.progressPercentage | Number | Percentage progress towards retrohunt completion \(0.00 to 100.00\). | 

#### Command Example

```!gcb-list-retrohunts page_size=3```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": [
            {
                "eventEndTime": "2022-06-16T06:58:19.994598Z",
                "eventStartTime": "2021-06-17T07:08:19.991404Z",
                "progressPercentage": 6.59,
                "retrohuntId": "oh_4c02f3a7-fe3c-49a0-82ba-ab255dd87723",
                "retrohuntStartTime": "2022-06-16T07:08:21.958022Z",
                "ruleId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49",
                "state": "RUNNING",
                "versionId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000"
            },
            {
                "eventEndTime": "2022-06-01T11:00:00Z",
                "eventStartTime": "2020-11-25T11:00:00Z",
                "progressPercentage": 6.69,
                "retrohuntEndTime": "2022-06-16T07:08:35.116493Z",
                "retrohuntId": "oh_5fd39b3d-5814-4ce3-ad4f-244aa943d020",
                "retrohuntStartTime": "2022-06-16T07:06:57.738997Z",
                "ruleId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49",
                "state": "CANCELLED",
                "versionId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000"
            },
            {
                "eventEndTime": "2022-06-16T06:47:45.116641Z",
                "eventStartTime": "2021-06-17T06:57:45.113155Z",
                "progressPercentage": 85.44,
                "retrohuntId": "oh_93cedd70-a6b6-480a-8d78-a894aff43e05",
                "retrohuntStartTime": "2022-06-16T06:57:47.233306Z",
                "ruleId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49",
                "state": "RUNNING",
                "versionId": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000"
            }
        ],
        "nextPageToken": "dummy-token"
    }
}
```

#### Human Readable Output

>### Retrohunt Details

>|Retrohunt ID|Rule ID|Version ID|Event Start Time|Event End Time|Retrohunt Start Time|Retrohunt End Time|State|Progress Percentage|
>|---|---|---|---|---|---|---|---|---|
>| oh_4c02f3a7-fe3c-49a0-82ba-ab255dd87723 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000 | 2021-06-17T07:08:19.991404Z | 2022-06-16T06:58:19.994598Z | 2022-06-16T07:08:21.958022Z |  | RUNNING | 6.59 |
>| oh_5fd39b3d-5814-4ce3-ad4f-244aa943d020 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000 | 2020-11-25T11:00:00Z | 2022-06-01T11:00:00Z | 2022-06-16T07:06:57.738997Z | 2022-06-16T07:08:35.116493Z | CANCELLED | 6.69 |
>| oh_93cedd70-a6b6-480a-8d78-a894aff43e05 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 | ru_4bec682c-305a-40a9-bbc6-81fa5487cb49@v_1655362604_042191000 | 2021-06-17T06:57:45.113155Z | 2022-06-16T06:47:45.116641Z | 2022-06-16T06:57:47.233306Z |  | RUNNING | 85.44 |
>
>Maximum number of retrohunts specified in page_size has been returned. To fetch the next set of retrohunts, execute the command with the page token as dummy-token


### 19. gcb-cancel-retrohunt

---
Cancel a retrohunt for a specified rule.


#### Base Command

`gcb-cancel-retrohunt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule ID or Version ID of the rule whose retrohunt is to be cancelled. | Required | 
| retrohunt_id | Unique identifier for a retrohunt, defined and returned by the server. You must specify exactly one retrohunt identifier. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RetroHunt.id | String | Unique identifier for a Rule. | 
| GoogleChronicleBackstory.RetroHunt.retrohuntId | String | Unique identifier for a retrohunt, defined and returned by the server. | 
| GoogleChronicleBackstory.RetroHunt.cancelled | Boolean | Whether the retrohunt is cancelled or not. | 

#### Command Example

```!gcb-cancel-retrohunt id=ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 retrohunt_id=oh_5fd39b3d-5814-4ce3-ad4f-244aa943d020```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": {
            "cancelled": true,
            "id": "ru_4bec682c-305a-40a9-bbc6-81fa5487cb49",
            "retrohuntId": "oh_5fd39b3d-5814-4ce3-ad4f-244aa943d020"
        }
    }
}
```

#### Human Readable Output

>### Cancelled Retrohunt

>Retrohunt for the rule with ID ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 has been successfully cancelled.
>
>|ID|Retrohunt ID|Action Status|
>|---|---|---|
>| ru_4bec682c-305a-40a9-bbc6-81fa5487cb49 | oh_5fd39b3d-5814-4ce3-ad4f-244aa943d020 | SUCCESS |


### 20. gcb-list-reference-list

---
Retrieve all the reference lists.


#### Base Command

`gcb-list-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of results to retrieve in the response. Maximum size allowed is 1000. Default is 100. | Optional | 
| page_token | The next page token to retrieve the next set of results. | Optional | 
| view | Select option to control the returned response. BASIC will return the metadata for the list, but not the full contents. FULL will return everything. Possible values are: BASIC, FULL. Default is BASIC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceLists.name | String | Unique name of the list. | 
| GoogleChronicleBackstory.ReferenceLists.description | String | Description of the list. | 
| GoogleChronicleBackstory.ReferenceLists.createTime | Date | Time when the list was created. | 
| GoogleChronicleBackstory.ReferenceLists.lines | String | List of line items. | 
| GoogleChronicleBackstory.ReferenceLists.contentType | String | Content type of the reference list. | 

#### Command Example

```!gcb-list-reference-list page_size=3```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "ReferenceLists": [
            {
                "createTime": "2022-06-14T06:06:35.787791Z",
                "description": "sample list",
                "contentType": "PLAIN_TEXT",
                "name": "test_1"
            },
            {
                "createTime": "2022-06-15T06:43:45.685951Z",
                "description": "sample list",
                "contentType": "PLAIN_TEXT",
                "name": "Builtin"
            },
            {
                "createTime": "2022-06-14T10:01:23.994415Z",
                "description": "sample",
                "contentType": "PLAIN_TEXT",
                "name": "Certificate_Asset"
            }
        ],
        "nextPageToken": "dummy-token"
    }
}
```

#### Human Readable Output

>### Reference List Details

>|Name|Content Type|Creation Time|Description|
>|---|---|---|---|
>| test_1 | PLAIN_TEXT |2022-06-14T06:06:35.787791Z | sample list |
>| Builtin | PLAIN_TEXT |2022-06-15T06:43:45.685951Z | sample list |
>| Certificate_Asset | PLAIN_TEXT |2022-06-14T10:01:23.994415Z | sample |
>
>Maximum number of reference lists specified in page_size has been returned. To fetch the next set of lists, execute the command with the page token as dummy-token


### 21. gcb-get-reference-list

---
Returns the specified list.


#### Base Command

`gcb-get-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide a unique name of the list to retrieve the result. | Required | 
| view | Select option to control the returned response. BASIC will return the metadata for the list, but not the full contents. FULL will return everything. Possible values are: FULL, BASIC. Default is FULL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | Unique name of the list. | 
| GoogleChronicleBackstory.ReferenceList.description | String | Description of the list. | 
| GoogleChronicleBackstory.ReferenceList.createTime | Date | Time when the list was created. | 
| GoogleChronicleBackstory.ReferenceList.lines | String | List of line items. | 
| GoogleChronicleBackstory.ReferenceList.contentType | String | Content type of the reference list. | 

#### Command Example

```!gcb-get-reference-list name=test1```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "ReferenceList": {
            "createTime": "2022-06-10T08:59:34.885679Z",
            "description": "update",
            "contentType": "PLAIN_TEXT",
            "lines": [
                "line_item_1",
                "// comment",
                "line_item_2"
            ],
            "name": "test1"
        }
    }
}
```

#### Human Readable Output

>### Reference List Details

>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| test1 | PLAIN_TEXT | update | 2022-06-10T08:59:34.885679Z | line_item_1,<br/>// comment,<br/>line_item_2 |


### 22. gcb-create-reference-list

---
Create a new reference list.


#### Base Command

`gcb-create-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide a unique name of the list to create a reference list. | Required | 
| description | Description of the list. | Required | 
| lines | Enter the content to be added into the reference list.<br/>Format accepted is: "Line 1, Line 2, Line 3". | Required | 
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is ,. | Optional | 
| content_type | Select the content type for reference list. Possible values are: PLAIN_TEXT, CIDR, REGEX. Default is PLAIN_TEXT. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | Unique name of the list. | 
| GoogleChronicleBackstory.ReferenceList.description | String | Description of the list. | 
| GoogleChronicleBackstory.ReferenceList.lines | String | List of line items. | 
| GoogleChronicleBackstory.ReferenceList.createTime | Date | Time when the list was created. | 
| GoogleChronicleBackstory.ReferenceList.contentType | String | Content type of the reference list. | 

#### Command Example

```!gcb-create-reference-list description="List created for readme" lines=L1,L2,L3 name=XSOAR_GoogleChronicle_Backstory_README_List_```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "ReferenceList": {
            "createTime": "2022-06-16T07:45:37.285791Z",
            "description": "List created for readme",
            "contentType": "PLAIN_TEXT",
            "lines": [
                "L1",
                "L2",
                "L3"
            ],
            "name": "XSOAR_GoogleChronicle_Backstory_README_List_"
        }
    }
}
```

#### Human Readable Output

>### Reference List Details

>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| XSOAR_GoogleChronicle_Backstory_README_List_ | PLAIN_TEXT |List created for readme | 2022-06-16T07:45:37.285791Z | L1,<br/>L2,<br/>L3 | PLAIN_TEXT |


### 23. gcb-update-reference-list

---
Updates an existing reference list.


#### Base Command

`gcb-update-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide a unique name of the list to update. | Required | 
| lines | Enter the content to be updated into the reference list.<br/>Format accepted is: "Line 1, Line 2, Line 3".<br/><br/>Note: Use gcb-get-reference-list to retrieve the content and description of the list. | Required | 
| description | Description to be updated of the list. | Optional | 
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is ,. | Optional | 
| content_type | Select the content type for reference list. Possible values are: PLAIN_TEXT, CIDR, REGEX. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | Unique name of the list. | 
| GoogleChronicleBackstory.ReferenceList.description | String | Description of the list. | 
| GoogleChronicleBackstory.ReferenceList.lines | String | List of line items. | 
| GoogleChronicleBackstory.ReferenceList.createTime | Date | Time when the list was created. | 
| GoogleChronicleBackstory.ReferenceList.contentType | String | Content type of the reference list. | 

#### Command Example

```!gcb-update-reference-list lines=Line1,Line2,Line3 name=XSOAR_GoogleChronicle_Backstory_README_List```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "ReferenceList": {
            "createTime": "2022-06-16T07:11:11.380991Z",
            "description": "list created for readme",
            "contentType": "PLAIN_TEXT",
            "lines": [
                "Line1",
                "Line2",
                "Line3"
            ],
            "name": "XSOAR_GoogleChronicle_Backstory_README_List"
        }
    }
}
```

#### Human Readable Output

>### Updated Reference List Details

>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| XSOAR_GoogleChronicle_Backstory_README_List | PLAIN_TEXT | list created for readme | 2022-06-16T07:11:11.380991Z | Line1,<br/>Line2,<br/>Line3 | 

### 24. gcb-verify-reference-list

***
Validates list content and returns any errors found for each line.

#### Base Command

`gcb-verify-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lines | Enter the content to be validated in the reference list.<br/>Format accepted is: 'Line 1, Line 2, Line 3'. | Required | 
| content_type | Select the content type for reference list. Possible values are: PLAIN_TEXT, CIDR, REGEX. Default is PLAIN_TEXT. | Optional | 
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is ,. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.VerifyReferenceList.success | Boolean | Whether lines content are valid or not. | 
| GoogleChronicleBackstory.VerifyReferenceList.errors.linenumber | Number | The line number where the error occurred. | 
| GoogleChronicleBackstory.VerifyReferenceList.errors.errorMessage | String | The error message describing the invalid pattern. | 
| GoogleChronicleBackstory.VerifyReferenceList.command_name | String | The name of the command. | 

#### Command example
```!gcb-verify-reference-list lines="1.2.3.4" content_type=CIDR```
#### Context Example
```json
{
    "GoogleChronicleBackstory": {
        "VerifyReferenceList": {
            "command_name": "gcb-verify-reference-list",
            "errors": [
                {
                    "errorMessage": "invalid cidr pattern 1.2.3.4",
                    "lineNumber": 1
                }
            ],
            "success": false
        }
    }
}
```

#### Human Readable Output

>### The following lines contain invalid CIDR pattern.
>|Line Number|Message|
>|---|---|
>| 1 | invalid cidr pattern 1.2.3.4 |


### 25. gcb-test-rule-stream

---
Test a rule over a specified time range. Return any errors and any detections up to the specified maximum.


#### Base Command

`gcb-test-rule-stream`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                           | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| rule_text | Rule text in YARA-L 2.0 format for the rule to stream.                                                                                                                                                                                                                                                                                                                                                                                    | Required | 
| start_time | Start time for the time range of the rule being tested. The format of Date should comply with RFC 3339 (e.g. 2022-10-02T15:00:00Z) or relative time. <br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2022-05-01T00:00:00Z, 2022-05-01, 2 days, 5 hours, 01 Mar 2022, 01 Feb 2022 04:45:33, 15 Jun.<br/><br/><br/>Note: The time window between start_time and end_time cannot be greater than 2 weeks. | Required | 
| end_time | End time for the time range of the rule being tested. The format of Date should comply with RFC 3339 (e.g. 2022-10-02T15:00:00Z) or relative time. <br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2022-05-01T00:00:00Z, 2022-05-01, 2 days, 5 hours, 01 Mar 2022, 01 Feb 2022 04:45:33, 15 Jun.<br/><br/><br/>Note: The time window between start_time and end_time cannot be greater than 2 weeks.   | Required | 
| max_results | Maximum number of results to return. Specify a value between 1 and 10,000.  Default is 1000.                                                                                                                                                                                                                                                                                                                                              | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.StreamRules.list.detection.type | String | Type of detection. | 
| GoogleChronicleBackstory.StreamRules.list.detection.detection.ruleName | String | Name of the rule generating the detection, as parsed from ruleText. | 
| GoogleChronicleBackstory.StreamRules.list.detection.detection.ruleType | String | Whether the rule generating this detection is a single event or multi-event rule. | 
| GoogleChronicleBackstory.StreamRules.list.detection.detection.ruleLabels | Unknown | Information about the rule | 
| GoogleChronicleBackstory.StreamRules.list.detection.id | String | Identifier for the detection. | 
| GoogleChronicleBackstory.StreamRules.list.detection.timeWindow.startTime | Date | The start time of the window the detection was found in. | 
| GoogleChronicleBackstory.StreamRules.list.detection.timeWindow.endTime | Date | The end time of the window the detection was found in. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.productLogId | String | A vendor-specific event identifier to uniquely identify the event \(a GUID\). Users might use this identifier to search the vendor's proprietary console for the event in question. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.eventTimestamp | Date | The GMT timestamp when the event was generated. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.eventType | String | Specifies the type of the event. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.vendorName | String | Specifies the product vendor's name. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.productName | String | Specifies the name of the product. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.productEventType | String | Short, descriptive, human-readable, and product-specific event name or type. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.ingestedTimestamp | Date | The GMT timestamp when the event was ingested in the vendor's instance. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.metadata.id | String | Stores the ID of metadata. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.emailAddresses | Unknown | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.productObjectId | String | Stores the products object ID. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.attribute.labels | Unknown | Stores users session metrics | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.phoneNumbers | Unknown | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.personalAddress.city | String | Stores city of user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.personalAddress.state | String | Stores state of user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.personalAddress.name | String | Stores address name of user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.companyName | String | Stores users company name. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.department | Unknown | Stores users departments | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.officeAddress.name | String | Stores company official address name. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.about | Unknown | Stores event labels. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.securityResult | Unknown | Provide a description of the security result. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.network.applicationProtocol | String | Indicates the network application protocol. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.network.dns.questions | Unknown | Stores the domain name. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.network.dns.answers | Unknown | Stores dns associated data. | 
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.label | String | The variable a given set of UDM events belongs to. | 
| GoogleChronicleBackstory.StreamRules.list.detection.detectionTime | Date | The time period the detection was found in. | 

#### Command example

```!gcb-test-rule-stream rule_text="rule demoRuleCreatedFromAPIVersion2 {meta:author = \"securityuser2\" description = \"double event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition:$e}" start_time="2022-11-24T00:00:00Z" end_time="2022-12-08T00:00:00Z" max_results=1```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "StreamRules": [
            {
                "detection": {
                    "collectionElements": [
                        {
                            "label": "e",
                            "references": [
                                {
                                    "event": {
                                        "about": [
                                            {
                                                "labels": [
                                                    {
                                                        "key": "Category ID",
                                                        "value": "DnsQuery"
                                                    }
                                                ]
                                            }
                                        ],
                                        "metadata": {
                                            "eventTimestamp": "2022-11-24T06:56:59.165381Z",
                                            "eventType": "NETWORK_DNS",
                                            "id": "AAAAABUCUis+2ym6lpWhubmxGDAAAAAAAQAAAN4AAAA=",
                                            "ingestedTimestamp": "2022-11-24T06:57:02.729226Z",
                                            "productEventType": "22",
                                            "productLogId": "278953",
                                            "productName": "Microsoft-Windows-Sysmon",
                                            "vendorName": "Microsoft"
                                        },
                                        "network": {
                                            "applicationProtocol": "DNS",
                                            "dns": {
                                                "answers": [
                                                    {
                                                        "data": "activedir.stackedpads.local",
                                                        "type": 5
                                                    }
                                                ],
                                                "questions": [
                                                    {
                                                        "name": "7121e16d-a937-41b2-b7a4-4f38cf48d65c._msdcs.stackedpads.local"
                                                    }
                                                ]
                                            }
                                        },
                                        "principal": {
                                            "administrativeDomain": "NT AUTHORITY",
                                            "hostname": "activedir.stackedpads.local",
                                            "process": {
                                                "file": {
                                                    "fullPath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe"
                                                },
                                                "pid": "3224",
                                                "productSpecificProcessId": "SYSMON:{3be6fa21-31d0-62c8-5500-000000001100}"
                                            },
                                            "user": {
                                                "userid": "SYSTEM",
                                                "windowsSid": "S-1-5-18"
                                            }
                                        },
                                        "securityResult": [
                                            {
                                                "severity": "INFORMATIONAL",
                                                "summary": "Dns query"
                                            },
                                            {
                                                "ruleName": "EventID: 22",
                                                "summary": "QueryStatus: 0"
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    ],
                    "detection": [
                        {
                            "ruleLabels": [
                                {
                                    "key": "author",
                                    "value": "securityuser2"
                                },
                                {
                                    "key": "description",
                                    "value": "double event rule that should generate detections"
                                }
                            ],
                            "ruleName": "demoRuleCreatedFromAPIVersion2",
                            "ruleType": "SINGLE_EVENT"
                        }
                    ],
                    "detectionTime": "2022-11-24T06:56:59.165381Z",
                    "id": "de_681b4417-27dc-ba3a-7db9-0388a7954c07",
                    "timeWindow": {
                        "endTime": "2022-11-24T06:56:59.165381Z",
                        "startTime": "2022-11-24T06:56:59.165381Z"
                    },
                    "type": "RULE_DETECTION"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Detection(s)

>|Detection ID|Detection Type|Detection Time|Events|
>|---|---|---|---|
>| de_681b4417-27dc-ba3a-7db9-0388a7954c07 | RULE_DETECTION | 2022-11-24T06:56:59.165381Z | **Event Timestamp:** 2022-11-24T06:56:59.165381Z<br/>**Event Type:** NETWORK_DNS<br/>**Principal Asset Identifier:** activedir.stackedpads.local<br/>**Queried Domain:** 7121e16d-a937-41b2-b7a4-4f38cf48d65c._msdcs.stackedpads.local |


### 26. gcb-list-useraliases

***
Lists all the aliases of a user in an enterprise for a specified user identifier and time period.

#### Base Command

`gcb-list-useraliases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The value of the start time for your request.<br/>The date format should comply with RFC 3339 (e.g., 2023-01-02T15:00:00Z) or relative time.<br/>If not supplied, the product considers UTC time corresponding to 3 days earlier than the current time.<br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| end_time | The value of the end time for your request.<br/>The date format should comply with RFC 3339 (e.g., 2023-01-02T15:00:00Z) or relative time.<br/>If not supplied, the product considers the current UTC time.<br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| page_size | Specify the maximum number of users aliases to fetch. You can specify between 1 and 10000. Default is 10000. | Optional | 
| user_identifier_type | Specify the identifier type of the user indicator. Possible values are: Email, Username, Windows SID, Employee ID, Product object ID. | Required | 
| user_identifier | Value of the user identifier. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.UserAliases.user.email | String | Email associated with the user alias. | 
| GoogleChronicleBackstory.UserAliases.user.username | String | Username associated with the user alias. | 
| GoogleChronicleBackstory.UserAliases.user.windows_sid | String | Windows Security Identifier \(SID\) associated with the user alias. | 
| GoogleChronicleBackstory.UserAliases.user.employee_id | String | Employee ID associated with the user alias. | 
| GoogleChronicleBackstory.UserAliases.user.product_object_id | String | Product object ID associated with the user alias. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.collectedTimestamp | Date | Collected timestamp of the user alias metadata. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.vendorName | String | Vendor name associated with the user alias metadata. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.productName | String | Product name associated with the user alias metadata. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.entityType | String | Entity type of the user alias metadata. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.interval.startTime | Date | Start time of the interval from which user aliases are found. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.interval.endTime | Date | End time of the interval from which user aliases are found. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.productObjectId | String | Product object ID associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.hostname | String | Hostname associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.assetId | String | Asset ID associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.ip | String | IP address associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.vulnerabilities.name | String | Name of the vulnerability associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.vulnerabilities.description | String | Description of the vulnerability associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.vulnerabilities.scanStartTime | Date | Start time of the vulnerability scan associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.vulnerabilities.scanEndTime | Date | End time of the vulnerability scan associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.vulnerabilities.firstFound | Date | Timestamp of the first detection of the vulnerability associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.vulnerabilities.lastFound | Date | Timestamp of the last detection of the vulnerability associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.description | String | Description of the user alias metadata. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.platformSoftware | Unknown | Platform software associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.platformSoftware.platformVersion | String | Platform version of the platform software associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.networkDomain | String | Network domain associated with the user alias entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.attribute.labels.key | String | Key of the label associated with the user alias entity asset attribute. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.asset.attribute.labels.value | String | Value of the label associated with the user alias entity asset attribute. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.metadata.productEntityId | String | Product entity ID associated with the user alias metadata. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.user.userid | String | ID of the user. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.user.userDisplayName | String | Display name of the user. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.user.productObjectId | String | Stores the product's object ID. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.user.title | String | Title of the user. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.entity.user.companyName | String | User's company name. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.relations.entity.asset.hostname | String | Hostname associated with the relations entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.relations.entity.asset.hardware | Unknown | Hardware information associated with the relations entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.relations.entity.asset.systemLastUpdateTime | Date | Last update time of the system associated with the relations entity asset. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.relations.entityType | String | Entity type of the relations entity. | 
| GoogleChronicleBackstory.UserAliases.user.aliases.relations.relationship | String | Relationship between entities in the relations. | 

#### Command example

```!gcb-list-useraliases user_identifier_type="Product object ID" user_identifier="test_product_entity_id"```

#### Context Example

```json
{
  "GoogleChronicleBackstory.UserAliases(val.user.email == obj.user.email && val.user.username == obj.user.username && val.user.windows_sid == obj.user.windows_sid && val.user.employee_id == obj.user.employee_id && val.user.product_object_id == obj.user.product_object_id ) ": {
    "user": {
      "email": "xyz@example.com",
      "aliases": [
        {
          "metadata": {
            "productEntityId": "test_product_entity_id",
            "collectedTimestamp": "2022-01-15T07:47:01.666265Z",
            "vendorName": "test_vendor_name",
            "productName": "test_product_name",
            "entityType": "USER",
            "interval": {
              "startTime": "2023-04-26T00:00:00Z",
              "endTime": "2023-01-08T06:47:56.197021Z"
            }
          },
          "entity": {
            "user": {
              "userid": "admin",
              "productObjectId": "test_product_entity_id"
            }
          },
          "relations": [
            {
              "entity": {
                "asset": {
                  "hostname": "Test_data123",
                  "systemLastUpdateTime": "2023-01-14T06:14:06Z"
                }
              },
              "entityType": "ASSET",
              "relationship": "OWNS"
            }
          ]
        },
        {
          "metadata": {
            "productEntityId": "test_product_entity_id_1",
            "collectedTimestamp": "2023-01-08T06:47:56.197021Z",
            "vendorName": "vendor_name",
            "productName": "Configuration Management Database (CMDB)",
            "entityType": "USER",
            "interval": {
              "startTime": "2023-01-08T06:47:56.197021Z",
              "endTime": "2023-06-12T00:00:00Z"
            }
          },
          "entity": {
            "user": {
              "userid": "admin",
              "productObjectId": "test_product_entity_id_1"
            }
          },
          "relations": [
            {
              "entity": {
                "asset": {
                  "hostname": "IP Address",
                  "systemLastUpdateTime": "2023-01-08T06:35:16Z"
                }
              },
              "entityType": "ASSET",
              "relationship": "OWNS"
            }
          ]
        }
      ]
    }
  }
}
```

#### Human Readable Output

>### User Aliases:

>|User ID|Product Object ID|Product Name|Vendor Name|Start Time|End Time|
>|---|---|---|---|---|---|
>| admin | test_product_entity_id | test_product_name | test_vendor_name | 2023-04-26T00:00:00Z | 2023-01-08T06:47:56.197021Z |
>| admin | test_product_entity_id_1 | Configuration Management Database (CMDB) | vendor_name | 2023-01-08T06:47:56.197021Z | 2023-06-12T00:00:00Z |


### 27. gcb-list-assetaliases

***
Lists all the aliases of an asset in an enterprise for the specified asset identifier and time period.

#### Base Command

`gcb-list-assetaliases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The value of the start time for your request.<br/>The date format should comply with RFC 3339 (e.g., 2023-01-02T15:00:00Z) or relative time.<br/>If not supplied, the product considers UTC time corresponding to 3 days earlier than the current time.<br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| end_time | The value of the end time for your request.<br/>The date format should comply with RFC 3339 (e.g., 2023-01-02T15:00:00Z) or relative time.<br/>If not supplied, the product considers the current UTC time.<br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| page_size | Specify the maximum number of assets aliases to fetch. You can specify between 1 and 10000. Default is 10000. | Optional | 
| asset_identifier_type | Specify the identifier type of the asset indicator. Possible values are: Host Name, IP Address, MAC Address, Product ID. | Required | 
| asset_identifier | Value of the asset identifier. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.AssetAliases.asset.product_id | String | Product ID associated with the asset alias. | 
| GoogleChronicleBackstory.AssetAliases.asset.mac | String | MAC address associated with the asset alias. | 
| GoogleChronicleBackstory.AssetAliases.asset.assetIpAddress | String | IP address associated with the asset alias. | 
| GoogleChronicleBackstory.AssetAliases.asset.hostname | String | Hostname associated with the asset alias. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.interval.startTime | Date | Start time of the interval from which asset aliases are found. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.interval.endTime | Date | End time of the interval from which asset aliases are found. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.ip | String | The IP address of the asset. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.collectedTimestamp | Date | The timestamp when the data was collected. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.vendorName | String | The name of the vendor. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.productName | String | The name of the product. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.entityType | String | The type of the entity. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.metadata.description | String | A description of the entity. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.productObjectId | String | The unique identifier of the product. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.hostname | String | The hostname of the asset. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.assetId | String | The identifier of the asset. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.platformSoftware | Unknown | The software running on the asset. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.vulnerabilities.name | String | The name of the vulnerability. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.vulnerabilities.description | String | A description of the vulnerability. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.vulnerabilities.scanStartTime | Date | The start time of the vulnerability scan. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.vulnerabilities.scanEndTime | Date | The end time of the vulnerability scan. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.vulnerabilities.firstFound | Date | The first time the vulnerability was found. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.vulnerabilities.lastFound | Date | The most recent time the vulnerability was found. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.platformSoftware.platformVersion | String | The version of the platform software. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.networkDomain | String | The network domain of the asset. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.attribute.labels.key | String | The key of an attribute label associated with the asset. | 
| GoogleChronicleBackstory.AssetAliases.asset.aliases.entity.asset.attribute.labels.value | String | The value of an attribute label associated with the asset. | 

#### Command example

```!gcb-list-assetaliases asset_identifier_type="Host Name" asset_identifier="windows-endpoint"```

#### Context Example

```json
{
  "GoogleChronicleBackstory.AssetAliases(val.asset.asset_ip_address == obj.asset.asset_ip_address && val.asset.product_id == obj.asset.product_id && val.asset.mac == obj.asset.mac && val.asset.hostname == obj.asset.hostname)": {
    "asset": {
      "hostname": "example.com",
      "aliases": [
        {
          "metadata": {
            "interval": {
              "startTime": "2023-01-01T00:00:00Z",
              "endTime": "2023-01-01T00:00:01Z"
            }
          },
          "entity": {
            "asset": {
              "hostname": "windows-endpoint"
            }
          }
        },
        {
          "metadata": {
            "interval": {
              "startTime": "2023-01-01T00:00:00Z",
              "endTime": "2023-01-01T00:00:01Z"
            }
          },
          "entity": {
            "asset": {
              "hostname": "windows-endpoint",
              "assetId": "test_asset_id"
            }
          }
        }
      ]
    }
  }
}
```

#### Human Readable Output

>### Asset Aliases:

>|Asset ID|Host Name|Start Time|End Time|
>|---|---|---|---|
>|  | windows-endpoint | 2023-01-01T00:00:00Z | 2023-01-01T00:00:01Z |
>| test_asset_id | windows-endpoint | 2023-01-01T00:00:00Z | 2023-01-01T00:00:01Z |


### 28. gcb-list-curatedrules

***
List curated rules.

#### Base Command

`gcb-list-curatedrules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_token | Page token received from a previous call. Use to retrieve the next page. | Optional | 
| page_size | Specify the maximum number of rules to return. You can specify between 1 and 1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.CuratedRules.ruleId | String | Unique identifier for a rule, defined and returned by the server. | 
| GoogleChronicleBackstory.CuratedRules.ruleName | String | Name of the rule. | 
| GoogleChronicleBackstory.CuratedRules.severity | String | Severity of the rule \("Info", "Low", or "High"\). | 
| GoogleChronicleBackstory.CuratedRules.ruleType | String | Type of the rule \("SINGLE_EVENT" or "MULTI_EVENT"\). | 
| GoogleChronicleBackstory.CuratedRules.precision | String | Precision of the rule \("BROAD" or "PRECISE"\). | 
| GoogleChronicleBackstory.CuratedRules.tactics | String | List of MITRE tactic IDs covered by the rule. | 
| GoogleChronicleBackstory.CuratedRules.techniques | String | List of MITRE technique IDs covered by the rule. | 
| GoogleChronicleBackstory.CuratedRules.updateTime | Date | String representing the time the rule was last updated, in RFC 3339 format. | 
| GoogleChronicleBackstory.CuratedRules.ruleSet | String | Unique identifier of the Chronicle rule set containing the rule. | 
| GoogleChronicleBackstory.CuratedRules.description | String | Description of the rule. | 
| GoogleChronicleBackstory.CuratedRules.metadata.false_positives | String | Metadata for the rule. | 
| GoogleChronicleBackstory.CuratedRules.metadata.reference | String | Reference for the rule. | 
| GoogleChronicleBackstory.Token.name | String | The name of the command to which the value of the nextPageToken corresponds. | 
| GoogleChronicleBackstory.Token.nextPageToken | String | A page token that can be provided to the next call to view the next page of Rules. Absent if this is the last page. |

#### Command example

```!gcb-list-curatedrules page_size="2"```

#### Context Example

```json
{
  "GoogleChronicleBackstory": {
    "CuratedRules": [
      {
        "ruleId": "ur_ttp_GCP__Global",
        "ruleName": "GCE SSH Keys",
        "severity": "Low",
        "ruleType": "SINGLE_EVENT",
        "precision": "BROAD",
        "tactics": [
          "TA0000"
        ],
        "techniques": [
          "T0000.000"
        ],
        "updateTime": "2023-05-01T21:56:43.352504Z",
        "ruleSet": "00000000-0000-0000-0000-000000000000",
        "description": "Identifies the addition of project-wide SSH keys where there were previously none."
      },
      {
        "ruleId": "ur_ttp_GCP__Editor",
        "ruleName": "GCP Service Account Editor",
        "severity": "Low",
        "ruleType": "MULTI_EVENT",
        "precision": "BROAD",
        "tactics": [
          "TA0000"
        ],
        "techniques": [
          "T0000.000"
        ],
        "updateTime": "2023-05-01T21:56:43.352504Z",
        "ruleSet": "00000000-0000-0000-0000-000000000000",
        "description": "Identifies a new Service Account created with Editor role within the project."
      }
    ],
    "Token": {
      "name": "gcb-list-curatedrules",
      "nextPageToken": "next_page_token"
    }
  }
}
```

#### Human Readable Output

>### Curated Rules:

>|Rule ID|Rule Name|Severity|Rule Type|Rule Set|Description|
>|---|---|---|---|---|---|
>| ur_ttp_GCP__Global | GCE SSH Keys | Low | SINGLE_EVENT| 00000000-0000-0000-0000-000000000000 | Identifies the addition of project-wide SSH keys where there were previously none. |
>| ur_ttp_GCP__Editor | GCP Service Account Editor | Low | MULTI_EVENT | 00000000-0000-0000-0000-000000000000 | Identifies a new Service Account created with Editor role within the project. |

>Maximum number of curated rules specified in page_size has been returned. To fetch the next set of curated rules, execute the command with the page token as next_page_token.


### 29. gcb-list-curatedrule-detections

***
Return the detections for the specified curated rule identifier.

#### Base Command

`gcb-list-curatedrule-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique identifier for a curated rule, defined and returned by the server. You can specify exactly one curated rule identifier. | Required | 
| alert_state | Filter detections based on whether the alert state is ALERTING or NOT_ALERTING.<br/>Do not specify to return all detections. Possible values are: ALERTING, NOT_ALERTING. | Optional | 
| page_size | Specify the limit on the number of detections to display. You can specify between 1 and 1000. Default is 100. | Optional | 
| page_token | A page token received from a previous call. Provide this to retrieve the subsequent page. If the page token is configured, overrides the detection start and end time arguments. | Optional | 
| list_basis | Sort detections by "DETECTION_TIME" or by "CREATED_TIME". If not specified, it defaults to "DETECTION_TIME". Detections are returned in descending order of the timestamp. Possible values are: DETECTION_TIME, CREATED_TIME. | Optional | 
| start_time | Start time of the time range to return detections for, filtering by the detection field specified in the list_basis parameter. If not specified, the start time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-05-01T00:00:00Z, 2023-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| end_time | End time of the time range to return detections for, filtering by the detection field specified by the list_basis parameter. If not specified, the end time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-05-01T00:00:00Z, 2023-05-01, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2021 04:45:33, 15 Jun. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.CuratedRuleDetections.id | String | Identifier for the detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleId | String | Identifier for the rule generating the detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleName | String | Name of the rule generating the detection, as parsed from ruleText. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleSet | String | The identifier of the Chronicle rule set that generated this detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleSetDisplayName | String | The display name of the Chronicle rule set that generated this detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.tags | Unknown | A list of MITRE tactic and technique IDs covered by the Chronicle rule. | 
| GoogleChronicleBackstory.CuratedRuleDetections.timeWindowStartTime | Date | The start time of the window the detection was found in. | 
| GoogleChronicleBackstory.CuratedRuleDetections.timeWindowEndTime | Date | The end time of the window the detection was found in. | 
| GoogleChronicleBackstory.CuratedRuleDetections.alertState | String | Indicates whether the rule generating this detection currently has alerting enabled or disabled. | 
| GoogleChronicleBackstory.CuratedRuleDetections.description | String | Description of the Chronicle rule that generated the detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.urlBackToProduct | String | URL pointing to the Chronicle UI for this detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.type | String | Type of detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.createdTime | Date | Time the detection was created. | 
| GoogleChronicleBackstory.CuratedRuleDetections.detectionTime | Date | The time period the detection was found in. | 
| GoogleChronicleBackstory.CuratedRuleDetections.lastUpdatedTime | Date | The time period the detection was updated. | 
| GoogleChronicleBackstory.CuratedRuleDetections.riskScore | Number | Risk score of detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.severity | String | Severity of the detection \("INFORMATIONAL" or "LOW" or "HIGH"\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.summary | String | Summary for the generated detection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleType | String | Whether the rule generating this detection is a single event or multi-event rule. | 
| GoogleChronicleBackstory.CuratedRuleDetections.detectionFields.key | String | The key for a field specified in the rule, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.detectionFields.source | String | The source for a field specified in the rule, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.detectionFields.value | String | The value for a field specified in the rule, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.outcomes.key | String | The key for a field specified in the outcomes of detection, for "MULTI_EVENT" rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.outcomes.source | String | The source for a field specified in the outcomes of detection, for "MULTI_EVENT" rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.outcomes.value | String | The value for a field specified in the outcomes of detection, for "MULTI_EVENT" rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleLabels.key | String | The key for a field specified in the Chronicle rule metadata. | 
| GoogleChronicleBackstory.CuratedRuleDetections.ruleLabels.value | String | The value for a field specified in the Chronicle rule metadata. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.label | String | The variable a given set of UDM events belongs to. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principalAssetIdentifier | String | Specifies the principal asset identifier of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.targetAssetIdentifier | String | Specifies the target asset identifier of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.collectedTimestamp | Date | The GMT timestamp when the event was collected. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.eventType | String | Specifies the type of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.eventTimestamp | Date | The GMT timestamp when the event was generated. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.id | String | The event ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.ingestedTimestamp | Date | The GMT timestamp when the event was ingested in the vendor's instance. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.ingestionLabels.key | String | The key for a field specified in the ingestion labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.ingestionLabels.value | String | The value for a field specified in the ingestion labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.logType | String | Type of log. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.description | String | Human-readable description of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.productEventType | String | Short, descriptive, human-readable, and product-specific event name or type. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.productLogId | String | A vendor-specific event identifier to uniquely identify the event \(a GUID\). Users might use this identifier to search the vendor's proprietary console for the event in question. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.productName | String | Specifies the name of the product. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.productVersion | String | Specifies the version of the product. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.urlBackToProduct | String | URL linking to a relevant website where you can view more information about this specific event or the general event category. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.vendorName | String | Specifies the product vendor's name. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.email | String | Email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.ip | String | IP address associated with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.countryOrRegion | String | Associated country or region for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionCoordinates.latitude | Number | Latitude coordinate of the region for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionCoordinates.longitude | Number | Longitude coordinate of the region for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionLatitude | Number | Latitude of the region for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionLongitude | Number | Longitude of the region for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.state | String | Associated state of IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.asn | String | Associated ASN with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.carrierName | String | Associated carrier name with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.dnsDomain | String | Associated DNS domain with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.organizationName | String | Associated organization name with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.countryOrRegion | String | Associated country or region for IP location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionCoordinates.latitude | Number | Latitude coordinate of the region for IP location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionCoordinates.longitude | Number | Longitude coordinate of the region for IP location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionLatitude | Number | Latitude of the region for IP location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionLongitude | Number | Longitude of the region for IP location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.state | String | Associated state of IP location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.labels.key | String | The key for a field specified in the principal labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.labels.value | String | The value for a field specified in the principal labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.countryOrRegion | String | Associated country or region for principal location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionCoordinates.latitude | Number | Latitude coordinate of the region for the principal location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionCoordinates.longitude | Number | Longitude coordinate of the region for the principal location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionLatitude | Number | Latitude of the region for the principal location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionLongitude | Number | Longitude of the region for the principal location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.state | String | Associated state of principal location. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.resource.attribute.cloud.project.name | String | Associated name of the project specified in the principal resource. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.resource.attribute.cloud.project.resourceSubtype | String | Associated resource sub-type of the project specified in the principal resource. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.resource.attribute.labels.key | String | The key for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.resource.attribute.labels.value | String | The value for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.cloud.environment | String | Associated environment specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.cloud.project.id | String | Associated ID of the project specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.permissions.name | String | Associated name of the permission specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.permissions.type | String | Associated type of the permission specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.roles.description | String | Associated description of the role specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.roles.name | String | Associated name of the role specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.attribute.roles.type | String | Associated type of the role specified in the principal user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.mac | String | MAC addresses associated with a device. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.url | String | Standard URL. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.productObjectId | String | Stores the product object ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.email | String | Email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.administrativeDomain | String | Domain for which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.application | String | Application of the target related to the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.cloud.availabilityZone | String | Associated availability zone specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.cloud.environment | String | Associated environment specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.cloud.project.name | String | Associated name of the project specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.cloud.vpc | Unknown | Associated VPC specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.resource.name | String | Associated resource name specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.resource.productObjectId | String | Associated product object ID specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.resource.resourceType | String | Associated resource type specified in the event target. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.resource.attribute.labels.key | String | The key for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.resource.attribute.labels.value | String | The value for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.url | String | Standard URL. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.attribute.cloud.environment | String | Associated environment specified in the target user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.attribute.cloud.project.id | String | Associated ID of the project specified in the target user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.attribute.roles.name | String | Associated name of the role specified in the target user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.attribute.roles.type | String | Associated type of the role specified in the target user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.emailAddresses | Unknown | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.productObjectId | String | Stores the human resources product object ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.target.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.email | String | Email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.url | String | Standard URL. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.email | String | Email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.url | String | Standard URL. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.email | String | Email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.url | String | Standard URL. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.email | String | Email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.url | String | Standard URL. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.commandLine | String | Stores the command line string for the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.productSpecificProcessId | String | Stores the product specific process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.productSpecificParentProcessId | String | Stores the product specific process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file | String | Stores the file name of the file in use by the process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.applicationProtocol | String | Indicates the network application protocol. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.direction | String | Indicates the direction of network traffic. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email | String | Specifies the email address for the sender/recipient. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.ipProtocol | String | Indicates the IP protocol. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.receivedBytes | String | Specifies the number of bytes received. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.sentBytes | String | Specifies the number of bytes sent. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.clientHostname | String | Hostname for the client. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.clientIdentifier | String | Client identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.file | String | Filename for the boot image. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.flags | String | Value for the DHCP flags field. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.hlen | String | Hardware address length. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.hops | String | DHCP hop count. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.htype | String | Hardware address type. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.leaseTimeSeconds | String | Client-requested lease time for an IP address in seconds. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.opcode | String | BOOTP op code. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.requestedAddress | String | Client identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.seconds | String | Seconds elapsed since the client began the address acquisition/renewal process. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.sname | String | Name of the server which the client has requested to boot from. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.transactionId | String | Client transaction ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.type | String | DHCP message type. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.chaddr | String | IP address for the client hardware. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.ciaddr | String | IP address for the client. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.giaddr | String | IP address for the relay agent. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.siaddr | String | IP address for the next bootstrap server. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.yiaddr | String | Your IP address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authoritative | String | Set to true for authoritative DNS servers. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.id | String | Stores the DNS query identifier. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.response | String | Set to true if the event is a DNS response. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.opcode | String | Stores the DNS OpCode used to specify the type of DNS query \(standard, inverse, server status, etc.\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.recursionAvailable | String | Set to true if a recursive DNS lookup is available. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.recursionDesired | String | Set to true if a recursive DNS lookup is requested. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.responseCode | String | Stores the DNS response code as defined by RFC 1035, Domain Names - Implementation and Specification. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.truncated | String | Set to true if this is a truncated DNS response. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.questions.name | String | Stores the domain name. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.questions.class | String | Stores the code specifying the class of the query. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.questions.type | String | Stores the code specifying the type of the query. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.answers.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.answers.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.answers.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.answers.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.answers.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.answers.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authority.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authority.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authority.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authority.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authority.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.authority.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.additional.binaryData | String | Stores the raw bytes of any non-UTF8 strings that might be included as part of a DNS response. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.additional.class | String | Stores the code specifying the class of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.additional.data | String | Stores the payload or response to the DNS question for all responses encoded in UTF-8 format. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.additional.name | String | Stores the name of the owner of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.additional.ttl | String | Stores the time interval for which the resource record can be cached before the source of the information should again be queried. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dns.additional.type | String | Stores the code specifying the type of the resource record. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.from | String | Stores the from email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.replyTo | String | Stores the reply_to email address. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.to | String | Stores the to email addresses. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.cc | String | Stores the cc email addresses. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.bcc | String | Stores the bcc email addresses. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.mailId | String | Stores the mail \(or message\) ID. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.email.subject | String | Stores the email subject line. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.ftp.command | String | Stores the FTP command. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.http.method | String | Stores the HTTP request method. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.http.referralUrl | String | Stores the URL for the HTTP referer. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.http.responseCode | String | Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.http.useragent | String | Stores the User-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.authentication.authType | String | Type of system an authentication event is associated with \(Chronicle UDM\). | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.authentication.mechanism | String | Mechanism\(s\) used for authentication. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.about | String | Provide a description of the security result. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.action | Unknown | Specify a security action. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.category | String | Specify a security category. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.categoryDetails | Unknown | Specify a security category details. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.detectionFields.key | String | The key for a field specified in the security result, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.detectionFields.value | String | The value for a field specified in the security result, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.confidence | String | Specify a confidence with regards to a security event as estimated by the product. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.confidenceDetails | String | Additional details with regards to the confidence of a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.priority | String | Specify a priority with regards to a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.priorityDetails | String | Vendor-specific information about the security result priority. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.ruleId | String | Identifier for the security rule. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.ruleName | String | Name of the security rule. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.severity | String | Severity of a security event as estimated by the product vendor using values defined by the Chronicle UDM. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.severityDetails | String | Severity for a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.threatName | String | Name of the security threat. | 
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.urlBackToProduct | String | URL to direct you to the source product console for this security event. | 
| GoogleChronicleBackstory.Token.name | String | The name of the command to which the value of the nextPageToken corresponds. | 
| GoogleChronicleBackstory.Token.nextPageToken | String | A page token that can be provided to the next call to view the next page of detections. Absent if this is the last page. | 

#### Command example

```!gcb-list-curatedrule-detections page_size="2"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "CuratedRuleDetections": [
            {
                "type": "GCTI_FINDING",
                "createdTime": "2023-06-14T18:38:30.569526Z",
                "lastUpdatedTime": "2023-06-14T18:38:30.569526Z",
                "id": "de_50fd0957-0959-0000-d556-c6f8000016b1",
                "collectionElements": [
                    {
                        "references": [
                            {
                                "eventTimestamp": "2023-06-14T17:27:39.239875241Z",
                                "collectedTimestamp": "2023-06-14T17:27:42.956025244Z",
                                "eventType": "RESOURCE_DELETION",
                                "vendorName": "Google Cloud Platform",
                                "productName": "Google Cloud Platform",
                                "productEventType": "google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret",
                                "urlBackToProduct": "url_0000",
                                "ingestedTimestamp": "2023-06-14T17:27:44.382729Z",
                                "id": "000000000000000000000001",
                                "logType": "GCP_CLOUD_AUDIT",
                                "eventSeverity": "INFORMATIONAL",
                                "principalAssetIdentifier": "0.0.0.1",
                                "principal": {
                                    "user": {
                                        "emailAddresses": [
                                            "secret-migration@test-is-00001.iam.gserviceaccount.com"
                                        ],
                                        "productObjectId": "000000000000000000000001",
                                        "attribute": {
                                            "roles": [
                                                {
                                                    "name": "roles/secretmanager.admin",
                                                    "type": "SERVICE_ACCOUNT"
                                                }
                                            ],
                                            "permissions": [
                                                {
                                                    "name": "secretmanager.secrets.delete",
                                                    "type": "ADMIN_WRITE"
                                                }
                                            ]
                                        }
                                    },
                                    "ip": [
                                        "0.0.0.1"
                                    ],
                                    "location": {
                                        "state": "State",
                                        "countryOrRegion": "Country",
                                        "regionLatitude": 10.0,
                                        "regionLongitude": 10.0,
                                        "regionCoordinates": {
                                            "latitude": 10.0,
                                            "longitude": 10.0
                                        }
                                    },
                                    "resource": {
                                        "attribute": {
                                            "cloud": {
                                                "project": {
                                                    "name": "projects/0000000/secrets/gsm_secret_1",
                                                    "resourceSubtype": "secretmanager.googleapis.com/Secret"
                                                }
                                            },
                                            "labels": [
                                                {
                                                    "key": "request_type",
                                                    "value": "type.googleapis.com/google.cloud.secretmanager.v1.DeleteSecretRequest"
                                                }
                                            ]
                                        }
                                    },
                                    "labels": [
                                        {
                                            "key": "request_attributes_time",
                                            "value": "2023-06-14T17:27:39.245079752Z"
                                        }
                                    ],
                                    "ipGeoArtifact": [
                                        {
                                            "ip": "0.0.0.1",
                                            "location": {
                                                "state": "State",
                                                "countryOrRegion": "India",
                                                "regionLatitude": 10.0,
                                                "regionLongitude": 10.0,
                                                "regionCoordinates": {
                                                    "latitude": 10.0,
                                                    "longitude": 10.0
                                                }
                                            },
                                            "network": {
                                                "asn": "00001",
                                                "dnsDomain": "broad_band.in",
                                                "carrierName": "broad band.",
                                                "organizationName": "broad band services limited"
                                            }
                                        }
                                    ]
                                },
                                "target": {
                                    "application": "secretmanager.googleapis.com",
                                    "resource": {
                                        "name": "gsm_secret_1",
                                        "attribute": {
                                            "labels": [
                                                {
                                                    "key": "request_name",
                                                    "value": "projects/test-is-00001/secrets/gsm_secret_1"
                                                }
                                            ]
                                        }
                                    },
                                    "cloud": {
                                        "environment": "GOOGLE_CLOUD_PLATFORM",
                                        "project": {
                                            "name": "test-is-00001"
                                        }
                                    }
                                },
                                "securityResult": [
                                    {
                                        "categoryDetails": [
                                            "projects/test-is-00001/logs/cloudaudit.googleapis.com"
                                        ],
                                        "action": [
                                            "ALLOW"
                                        ],
                                        "severity": "INFORMATIONAL",
                                        "detectionFields": [
                                            {
                                                "key": "resource_name",
                                                "value": "projects/0000001/secrets/gsm_secret_1"
                                            },
                                            {
                                                "key": "key_id",
                                                "value": "000000000000000000000001"
                                            }
                                        ]
                                    }
                                ],
                                "network": {
                                    "http": {
                                        "userAgent": "grpc-python-asyncio/1.51.3 grpc-c/29.0.0 (windows; chttp2),gzip(gfe)"
                                    }
                                }
                            }
                        ],
                        "label": "e"
                    }
                ],
                "detectionTime": "2023-06-14T17:28:00Z",
                "tags": [
                    "TA0040",
                    "T1485"
                ],
                "ruleName": "GCP Secret Manager Mass Deletion",
                "summary": "Rule Detection",
                "description": "Identifies mass deletion of secrets in GCP Secret Manager.",
                "severity": "LOW",
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_50fd0957-0959-0000-d556-c6f8000016b1",
                "ruleId": "ur_ttp_GCP__MassSecretDeletion",
                "alertState": "ALERTING",
                "ruleType": "MULTI_EVENT",
                "detectionFields": [
                    {
                        "key": "resource",
                        "value": "secretmanager.googleapis.com"
                    },
                    {
                        "key": "principaluser",
                        "value": "secret@google.com",
                        "source": "udm.principal.user.email_addresses"
                    }
                ],
                "ruleLabels": [
                    {
                        "key": "rule_name",
                        "value": "GCP Secret Manager Mass Deletion"
                    },
                    {
                        "key": "false_positives",
                        "value": "This may be common behavior in dev, testing, or deprecated projects."
                    }
                ],
                "outcomes": [
                    {
                        "key": "risk_score",
                        "value": "35"
                    },
                    {
                        "key": "resource_name",
                        "value": "gsm_secret_1, gsm_secret_10",
                        "source": "udm.target.resource.name"
                    },
                    {
                        "key": "ip",
                        "value": "0.0.0.1",
                        "source": "udm.principal.ip"
                    }
                ],
                "ruleSet": "9d7537ae-0ae2-0000-b5e2-507c00008ae9",
                "ruleSetDisplayName": "Service Disruption",
                "riskScore": 35,
                "timeWindowStartTime": "2023-06-14T17:18:00Z",
                "timeWindowEndTime": "2023-06-14T17:28:00Z"
            },
            {
                "type": "GCTI_FINDING",
                "createdTime": "2023-06-14T18:38:30.569526Z",
                "lastUpdatedTime": "2023-06-14T18:38:30.569526Z",
                "id": "de_662d8ff5-8eea-deb8-274e-f3410c7b935a",
                "collectionElements": [
                    {
                        "references": [
                            {
                                "eventTimestamp": "2023-06-14T17:27:39.239875241Z",
                                "collectedTimestamp": "2023-06-14T17:27:42.956025244Z",
                                "eventType": "RESOURCE_DELETION",
                                "vendorName": "Google Cloud Platform",
                                "productName": "Google Cloud Platform",
                                "productEventType": "google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret",
                                "urlBackToProduct": "url_0000",
                                "ingestedTimestamp": "2023-06-14T17:27:44.382729Z",
                                "id": "000000000000000000000001",
                                "logType": "GCP_CLOUD_AUDIT",
                                "eventSeverity": "INFORMATIONAL",
                                "principalAssetIdentifier": "0.0.0.1",
                                "principal": {
                                    "user": {
                                        "emailAddresses": [
                                            "secret-migration@test-is-00001.iam.gserviceaccount.com"
                                        ],
                                        "productObjectId": "000000000000000000000001",
                                        "attribute": {
                                            "roles": [
                                                {
                                                    "name": "roles/secretmanager.admin",
                                                    "type": "SERVICE_ACCOUNT"
                                                }
                                            ],
                                            "permissions": [
                                                {
                                                    "name": "secretmanager.secrets.delete",
                                                    "type": "ADMIN_WRITE"
                                                }
                                            ]
                                        }
                                    },
                                    "ip": [
                                        "0.0.0.1"
                                    ],
                                    "location": {
                                        "state": "State",
                                        "countryOrRegion": "Country",
                                        "regionLatitude": 10.0,
                                        "regionLongitude": 10.0,
                                        "regionCoordinates": {
                                            "latitude": 10.0,
                                            "longitude": 10.0
                                        }
                                    },
                                    "resource": {
                                        "attribute": {
                                            "cloud": {
                                                "project": {
                                                    "name": "projects/0000000/secrets/gsm_secret_1",
                                                    "resourceSubtype": "secretmanager.googleapis.com/Secret"
                                                }
                                            },
                                            "labels": [
                                                {
                                                    "key": "request_type",
                                                    "value": "type.googleapis.com/google.cloud.secretmanager.v1.DeleteSecretRequest"
                                                }
                                            ]
                                        }
                                    },
                                    "labels": [
                                        {
                                            "key": "request_attributes_time",
                                            "value": "2023-06-14T17:27:39.245079752Z"
                                        }
                                    ],
                                    "ipGeoArtifact": [
                                        {
                                            "ip": "0.0.0.1",
                                            "location": {
                                                "state": "State",
                                                "countryOrRegion": "India",
                                                "regionLatitude": 10.0,
                                                "regionLongitude": 10.0,
                                                "regionCoordinates": {
                                                    "latitude": 10.0,
                                                    "longitude": 10.0
                                                }
                                            },
                                            "network": {
                                                "asn": "00001",
                                                "dnsDomain": "broad_band.in",
                                                "carrierName": "broad band.",
                                                "organizationName": "broad band services limited"
                                            }
                                        }
                                    ]
                                },
                                "target": {
                                    "application": "secretmanager.googleapis.com",
                                    "resource": {
                                        "name": "gsm_secret_1",
                                        "attribute": {
                                            "labels": [
                                                {
                                                    "key": "request_name",
                                                    "value": "projects/test-is-00001/secrets/gsm_secret_1"
                                                }
                                            ]
                                        }
                                    },
                                    "cloud": {
                                        "environment": "GOOGLE_CLOUD_PLATFORM",
                                        "project": {
                                            "name": "test-is-00001"
                                        }
                                    }
                                },
                                "securityResult": [
                                    {
                                        "categoryDetails": [
                                            "projects/test-is-00001/logs/cloudaudit.googleapis.com"
                                        ],
                                        "action": [
                                            "ALLOW"
                                        ],
                                        "severity": "INFORMATIONAL",
                                        "detectionFields": [
                                            {
                                                "key": "resource_name",
                                                "value": "projects/0000001/secrets/gsm_secret_1"
                                            },
                                            {
                                                "key": "key_id",
                                                "value": "000000000000000000000001"
                                            }
                                        ]
                                    }
                                ],
                                "network": {
                                    "http": {
                                        "userAgent": "grpc-python-asyncio/1.51.3 grpc-c/29.0.0 (windows; chttp2),gzip(gfe)"
                                    }
                                }
                            }
                        ],
                        "label": "e"
                    }
                ],
                "detectionTime": "2023-06-14T17:28:00Z",
                "tags": [
                    "TA0040",
                    "T1485"
                ],
                "ruleName": "GCP Secret Manager Mass Deletion",
                "summary": "Rule Detection",
                "description": "Identifies mass deletion of secrets in GCP Secret Manager.",
                "severity": "LOW",
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_662d8ff5-8eea-deb8-274e-f3410c7b935a",
                "ruleId": "ur_ttp_GCP__MassSecretDeletion",
                "alertState": "ALERTING",
                "ruleType": "MULTI_EVENT",
                "detectionFields": [
                    {
                        "key": "resource",
                        "value": "secretmanager.googleapis.com"
                    },
                    {
                        "key": "principaluser",
                        "value": "secret@google.com",
                        "source": "udm.principal.user.email_addresses"
                    }
                ],
                "ruleLabels": [
                    {
                        "key": "rule_name",
                        "value": "GCP Secret Manager Mass Deletion"
                    },
                    {
                        "key": "false_positives",
                        "value": "This may be common behavior in dev, testing, or deprecated projects."
                    }
                ],
                "outcomes": [
                    {
                        "key": "risk_score",
                        "value": "35"
                    },
                    {
                        "key": "resource_name",
                        "value": "gsm_secret_1, gsm_secret_10",
                        "source": "udm.target.resource.name"
                    },
                    {
                        "key": "ip",
                        "value": "0.0.0.1",
                        "source": "udm.principal.ip"
                    }
                ],
                "ruleSet": "9d7537ae-0ae2-0000-b5e2-507c00008ae9",
                "ruleSetDisplayName": "Service Disruption",
                "riskScore": 35,
                "timeWindowStartTime": "2023-06-14T17:18:00Z",
                "timeWindowEndTime": "2023-06-14T17:28:00Z"
            }
        ],
        "Token": {
            "name": "gcb-list-curatedrule-detections",
            "nextPageToken": "next_page_token"
        }
    }
}
```

#### Human Readable Output

>### Curated Detection(s) Details For Rule: [GCP Secret Manager Mass Deletion](<https://dummy-chronicle/ruleDetections?ruleId=ur_ttp_GCP__MassSecretDeletion>

>|Detection ID|Description|Detection Type|Detection Time|Events|Alert State|Detection Severity|Detection Risk-Score|
>|---|---|---|---|---|---|---|---|
>| [de_50fd0957-0959-0000-d556-c6f8000016b1](https://dummy-chronicle/alert?alertId=de_50fd0957-0959-0000-d556-c6f8000016b1) | Identifies mass deletion of secrets in GCP Secret Manager. | GCTI_FINDING | 2023-06-14T17:28:00Z | **Event Timestamp:** 2023-06-14T17:27:39.239875241Z<br>**Event Type:** RESOURCE_DELETION<br>**Principal Asset Identifier:** 0.0.0.1 | ALERTING | LOW | 35 |
>| [de_662d8ff5-8eea-deb8-274e-f3410c7b935a](https://dummy-chronicle/alert?alertId=de_662d8ff5-8eea-deb8-274e-f3410c7b935a) | Identifies mass deletion of secrets in GCP Secret Manager. | GCTI_FINDING | 2023-06-14T17:28:00Z | **Event Timestamp:** 2023-06-14T17:27:39.239875241Z<br>**Event Type:** RESOURCE_DELETION<br>**Principal Asset Identifier:** 0.0.0.1 | ALERTING | LOW | 35 |

>View all Curated Detections for this rule in Chronicle by clicking on GCP Secret Manager Mass Deletion and to view individual detection in Chronicle click on its respective Detection ID.
>Maximum number of detections specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as next_page_token.


### 30. gcb-udm-search

***
Lists the events for the specified UDM Search query.
Note: The underlying API has the rate limit of 120 queries per hour.

#### Base Command

`gcb-udm-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The value of the start time for your request. The date format should comply with RFC 3339 (e.g., 2023-01-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 3 days earlier than the current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. If the date is supplied in duration, it will be calculated as time.now() - duration. Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| end_time | The value of the end time for your request. The date format should comply with RFC 3339 (e.g., 2023-01-02T15:00:00Z) or relative time. If not supplied, the product considers current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. If the date is supplied in duration, it will be calculated as time.now() - duration. Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional | 
| limit | Specify the maximum number of matched events to return. You can specify between 1 and 1000. Default is 200. | Optional | 
| query | UDM search query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Events.eventType | String | Specifies the type of the event. | 
| GoogleChronicleBackstory.Events.eventTimestamp | Date | The GMT timestamp when the event was generated. | 
| GoogleChronicleBackstory.Events.id | String | The event ID. | 
| GoogleChronicleBackstory.Events.ingestedTimestamp | Date | The GMT timestamp when the event was ingested in the vendor's instance. | 
| GoogleChronicleBackstory.Events.ingestionLabels.key | String | The key for a field specified in the ingestion labels of the event. | 
| GoogleChronicleBackstory.Events.ingestionLabels.value | String | The value for a field specified in the ingestion labels of the event. | 
| GoogleChronicleBackstory.Events.collectedTimestamp | Date | The GMT timestamp when the event was collected by the vendor's local collection infrastructure. | 
| GoogleChronicleBackstory.Events.logType | String | Type of log. | 
| GoogleChronicleBackstory.Events.description | String | Human-readable description of the event. | 
| GoogleChronicleBackstory.Events.productEventType | String | Short, descriptive, human-readable, and product-specific event name or type. | 
| GoogleChronicleBackstory.Events.productLogId | String | A vendor-specific event identifier to uniquely identify the event \(a GUID\). Users might use this identifier to search the vendor's proprietary console for the event in question. | 
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
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.ip | String | IP address associated with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.countryOrRegion | String | Associated country or region for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionCoordinates.latitude | Number | Latitude coordinate of the region for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionCoordinates.longitude | Number | Longitude coordinate of the region for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionLatitude | Number | Latitude of the region for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionLongitude | Number | Longitude of the region for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.state | String | Associated state of IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.asn | String | Associated ASN with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.carrierName | String | Associated carrier name with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.dnsDomain | String | Associated DNS domain with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.organizationName | String | Associated organization name with a network connection for IP Geolocation. | 
| GoogleChronicleBackstory.Events.principal.ipLocation.countryOrRegion | String | Associated country or region for IP location. | 
| GoogleChronicleBackstory.Events.principal.ipLocation.regionCoordinates.latitude | Number | Latitude coordinate of the region for IP location. | 
| GoogleChronicleBackstory.Events.principal.ipLocation.regionCoordinates.longitude | Number | Longitude coordinate of the region for IP location. | 
| GoogleChronicleBackstory.Events.principal.ipLocation.regionLatitude | Number | Latitude of the region for IP location. | 
| GoogleChronicleBackstory.Events.principal.ipLocation.regionLongitude | Number | Longitude of the region for IP location. | 
| GoogleChronicleBackstory.Events.principal.ipLocation.state | String | Associated state of IP location. | 
| GoogleChronicleBackstory.Events.principal.labels.key | String | The key for a field specified in the principal labels of the event. | 
| GoogleChronicleBackstory.Events.principal.labels.value | String | The value for a field specified in the principal labels of the event. | 
| GoogleChronicleBackstory.Events.principal.location.countryOrRegion | String | Associated country or region for the principal location. | 
| GoogleChronicleBackstory.Events.principal.location.regionCoordinates.latitude | Number | Latitude coordinate of the region for the principal location. | 
| GoogleChronicleBackstory.Events.principal.location.regionCoordinates.longitude | Number | Longitude coordinate of the region for the principal location. | 
| GoogleChronicleBackstory.Events.principal.location.regionLatitude | Number | Latitude of the region for the principal location. | 
| GoogleChronicleBackstory.Events.principal.location.regionLongitude | Number | Longitude of the region for the principal location. | 
| GoogleChronicleBackstory.Events.principal.location.state | String | Associated state of the principal location. | 
| GoogleChronicleBackstory.Events.principal.resource.attribute.cloud.project.name | String | Associated name of the project specified in the principal resource. | 
| GoogleChronicleBackstory.Events.principal.resource.attribute.cloud.project.resourceSubtype | String | Associated resource sub-type of the project specified in the principal resource. | 
| GoogleChronicleBackstory.Events.principal.resource.attribute.labels.key | String | The key for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.Events.principal.resource.attribute.labels.value | String | The value for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.cloud.environment | String | Associated environment specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.cloud.project.id | String | Associated ID of the project specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.permissions.name | String | Associated name of the permission specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.permissions.type | String | Associated type of the permission specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.roles.description | String | Associated description of the role specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.roles.name | String | Associated name of the role specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.user.attribute.roles.type | String | Associated type of the role specified in the principal user. | 
| GoogleChronicleBackstory.Events.principal.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.principal.mac | String | MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.principal.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.principal.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.principal.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.principal.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.principal.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.principal.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.principal.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.principal.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.principal.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.principal.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.principal.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.principal.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.principal.user.employeeId | String | Stores the product object ID for the user. | 
| GoogleChronicleBackstory.Events.principal.user.productObjectId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.principal.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.principal.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.principal.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.principal.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.principal.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.principal.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.target.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.target.email | String | Email address. | 
| GoogleChronicleBackstory.Events.target.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.target.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.target.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.target.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.target.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.target.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.target.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.target.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.target.application | String | Application of the target related to the event. | 
| GoogleChronicleBackstory.Events.target.cloud.availabilityZone | String | Associated availability zone specified in the event target. | 
| GoogleChronicleBackstory.Events.target.cloud.environment | String | Associated environment specified in the event target. | 
| GoogleChronicleBackstory.Events.target.cloud.project.name | String | Associated name of the project specified in the event target. | 
| GoogleChronicleBackstory.Events.target.cloud.vpc | Unknown | Associated VPC specified in the event target. | 
| GoogleChronicleBackstory.Events.target.resource.name | String | Associated resource name specified in the event target. | 
| GoogleChronicleBackstory.Events.target.resource.productObjectId | String | Associated product object ID specified in the event target. | 
| GoogleChronicleBackstory.Events.target.resource.resourceType | String | Associated resource type specified in the event target. | 
| GoogleChronicleBackstory.Events.target.resource.attribute.labels.key | String | The key for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.Events.target.resource.attribute.labels.value | String | The value for a field specified in the principal resource labels of the event. | 
| GoogleChronicleBackstory.Events.target.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.target.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.target.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.target.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.target.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.sha1 | String | SHA-1 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.sha256 | String | SHA-256 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.process.file.size | String | Size of the file. | 
| GoogleChronicleBackstory.Events.target.process.parentPid | String | Stores the process ID for the parent process. | 
| GoogleChronicleBackstory.Events.target.process.pid | String | Stores the process ID. | 
| GoogleChronicleBackstory.Events.target.registry.registryKey | String | Stores the registry key associated with an application or system component. | 
| GoogleChronicleBackstory.Events.target.registry.registryValueName | String | Stores the name of the registry value associated with an application or system component. | 
| GoogleChronicleBackstory.Events.target.registry.registryValueData | String | Stores the data associated with a registry value. | 
| GoogleChronicleBackstory.Events.target.user.attribute.cloud.environment | String | Associated environment specified in the target user. | 
| GoogleChronicleBackstory.Events.target.user.attribute.cloud.project.id | String | Associated ID of the project specified in the target user. | 
| GoogleChronicleBackstory.Events.target.user.attribute.roles.name | String | Associated name of the role specified in the target user. | 
| GoogleChronicleBackstory.Events.target.user.attribute.roles.type | String | Associated type of the role specified in the target user. | 
| GoogleChronicleBackstory.Events.target.user.emailAddresses | String | Stores the email addresses for the user. | 
| GoogleChronicleBackstory.Events.target.user.productObjectId | String | Stores the human resources product object ID for the user. | 
| GoogleChronicleBackstory.Events.target.user.employeeId | String | Stores the human resources employee ID for the user. | 
| GoogleChronicleBackstory.Events.target.user.firstName | String | Stores the first name for the user. | 
| GoogleChronicleBackstory.Events.target.user.middleName | String | Stores the middle name for the user. | 
| GoogleChronicleBackstory.Events.target.user.lastName | String | Stores the last name for the user. | 
| GoogleChronicleBackstory.Events.target.user.groupid | String | Stores the group ID associated with a user. | 
| GoogleChronicleBackstory.Events.target.user.phoneNumbers | String | Stores the phone numbers for the user. | 
| GoogleChronicleBackstory.Events.target.user.title | String | Stores the job title for the user. | 
| GoogleChronicleBackstory.Events.target.user.userDisplayName | String | Stores the display name for the user. | 
| GoogleChronicleBackstory.Events.target.user.userid | String | Stores the user ID. | 
| GoogleChronicleBackstory.Events.target.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.intermediary.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.intermediary.email | String | Email address. | 
| GoogleChronicleBackstory.Events.intermediary.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.intermediary.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.intermediary.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.intermediary.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.intermediary.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.intermediary.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.intermediary.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.intermediary.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.intermediary.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.intermediary.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.intermediary.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.intermediary.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.intermediary.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.src.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.src.email | String | Email address. | 
| GoogleChronicleBackstory.Events.src.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.src.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.src.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.src.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.src.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.src.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.src.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.src.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.src.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.src.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.src.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.src.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.src.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.src.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.observer.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.observer.email | String | Email address. | 
| GoogleChronicleBackstory.Events.observer.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.observer.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.observer.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.observer.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.observer.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.observer.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.observer.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.observer.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.observer.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.observer.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.observer.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.observer.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.observer.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.observer.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.about.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.about.email | String | Email address. | 
| GoogleChronicleBackstory.Events.about.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.about.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.about.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.about.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.about.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.about.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.about.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.about.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.about.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.about.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.about.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.about.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.about.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.about.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
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
| GoogleChronicleBackstory.Events.network.dns.opcode | String | Stores the DNS OpCode used to specify the type of DNS query \(standard, inverse, server status, etc.\). | 
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
| GoogleChronicleBackstory.Events.network.email.mailId | String | Stores the mail \(or message\) ID. | 
| GoogleChronicleBackstory.Events.network.email.subject | String | Stores the email subject line. | 
| GoogleChronicleBackstory.Events.network.ftp.command | String | Stores the FTP command. | 
| GoogleChronicleBackstory.Events.network.http.method | String | Stores the HTTP request method. | 
| GoogleChronicleBackstory.Events.network.http.referralUrl | String | Stores the URL for the HTTP referer. | 
| GoogleChronicleBackstory.Events.network.http.responseCode | String | Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. | 
| GoogleChronicleBackstory.Events.network.http.useragent | String | Stores the User-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | 
| GoogleChronicleBackstory.Events.authentication.authType | String | Type of system an authentication event is associated with \(Chronicle UDM\). | 
| GoogleChronicleBackstory.Events.authentication.mechanism | String | Mechanism\(s\) used for authentication. | 
| GoogleChronicleBackstory.Events.securityResult.about | String | Provide a description of the security result. | 
| GoogleChronicleBackstory.Events.securityResult.action | String | Specify a security action. | 
| GoogleChronicleBackstory.Events.securityResult.category | String | Specify a security category. | 
| GoogleChronicleBackstory.Events.securityResult.categoryDetails | Unknown | Specify a security category details. | 
| GoogleChronicleBackstory.Events.securityResult.detectionFields.key | String | The key for a field specified in the security result, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.Events.securityResult.detectionFields.value | String | The value for a field specified in the security result, for MULTI_EVENT rules. | 
| GoogleChronicleBackstory.Events.securityResult.confidence | String | Specify a confidence with regards to a security event as estimated by the product. | 
| GoogleChronicleBackstory.Events.securityResult.confidenceDetails | String | Additional details with regards to the confidence of a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Events.securityResult.priority | String | Specify a priority with regards to a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Events.securityResult.priorityDetails | String | Vendor-specific information about the security result priority. | 
| GoogleChronicleBackstory.Events.securityResult.ruleId | String | Identifier for the security rule. | 
| GoogleChronicleBackstory.Events.securityResult.ruleName | String | Name of the security rule. | 
| GoogleChronicleBackstory.Events.securityResult.severity | String | Severity of a security event as estimated by the product vendor using values defined by the Chronicle UDM. | 
| GoogleChronicleBackstory.Events.securityResult.severityDetails | String | Severity for a security event as estimated by the product vendor. | 
| GoogleChronicleBackstory.Events.securityResult.threatName | String | Name of the security threat. | 
| GoogleChronicleBackstory.Events.securityResult.urlBackToProduct | String | URL to direct you to the source product console for this security event. | 

#### Command example

```!gcb-udm-search query="ip=\"0.0.0.1\"" limit="2"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Events": [
            {
                "metadata": {
                    "productLogId": "010000",
                    "eventTimestamp": "2023-01-14T00:59:52.110Z",
                    "eventType": "REGISTRY_MODIFICATION",
                    "vendorName": "Microsoft",
                    "productName": "Microsoft-Windows-Sysmon",
                    "productEventType": "13",
                    "ingestedTimestamp": "2023-01-14T13:14:24.377988Z",
                    "id": "010000=",
                    "enrichmentState": "ENRICHED"
                },
                "principal": {
                    "hostname": "active.stack.local",
                    "assetId": "ACTIVE",
                    "user": {
                        "userid": "LOCAL SERVICE",
                        "windowsSid": "S-1-1-10"
                    },
                    "process": {
                        "pid": "1000",
                        "file": {
                            "fullPath": "C:\\Windows\\host.exe"
                        },
                        "productSpecificProcessId": "SYSMON:{00000000-0000-0000-0000-000000000f00}"
                    },
                    "ip": [
                        "0.0.0.1"
                    ],
                    "administrativeDomain": "AUTHORITY",
                    "asset": {
                        "productObjectId": "0000-0000-0000-0000-000000001000",
                        "hostname": "active.stack.local",
                        "assetId": "ACTIVE",
                        "ip": [
                            "0.0.0.1"
                        ],
                        "platformSoftware": {
                            "platform": "WINDOWS",
                            "platformVersion": "Windows"
                        },
                        "location": {
                            "countryOrRegion": "0"
                        },
                        "category": "Computer",
                        "attribute": {
                            "labels": [
                                {
                                    "key": "Bad password count",
                                    "value": "0"
                                },
                                {
                                    "key": "Password Expired",
                                    "value": "false"
                                }
                            ],
                            "creationTime": "2023-01-14T00:00:10Z",
                            "lastUpdateTime": "2023-01-14T00:00:10Z"
                        }
                    }
                },
                "target": {
                    "registry": {
                        "registryKey": "System\\LastKnownGoodTime",
                        "registryValueData": "WORD"
                    },
                    "ip": [
                        "0.0.0.1"
                    ]
                },
                "about": [
                    {
                        "labels": [
                            {
                                "key": "Category ID",
                                "value": "RegistryEvent"
                            }
                        ]
                    }
                ],
                "securityResult": [
                    {
                        "ruleName": "technique_id=T0000,technique_name=Service Creation",
                        "summary": "Registry value set",
                        "severity": "INFORMATIONAL"
                    },
                    {
                        "ruleName": "EventID: 10",
                       "action": [
                          "ALLOW"
                        ]
                    }
                ]
            },
            {
                "name": "0000000020000",
                "udm": {
                    "metadata": {
                        "productLogId": "0001",
                        "eventTimestamp": "2023-01-14T00:56:57.372Z",
                        "eventType": "NETWORK_DNS",
                        "vendorName": "Microsoft",
                        "productName": "Microsoft",
                        "productEventType": "22",
                        "ingestedTimestamp": "2023-01-14T10:07:42.183563Z",
                        "id": "0000000020000=",
                        "enrichmentState": "ENRICHED"
                    },
                    "principal": {
                        "hostname": "DESKTOP",
                        "user": {
                            "userid": "SYSTEM",
                            "windowsSid": "S-1-1-11"
                        },
                        "process": {
                            "pid": "2000",
                            "file": {
                                "sha256": "0000000000000000000000000000000000000000000000000000000000000001",
                                "md5": "00000000000000000000000000000001",
                                "sha1": "0000000000000000000000000000000000000001",
                                "fullPath": "C:\\Scripts.exe",
                                "fileMetadata": {
                                    "pe": {
                                        "importHash": "00000000000000000000000000000001"
                                    }
                                }
                            },
                            "commandLine": "\"C:\\Scripts.exe\"  \"shutdown\"",
                            "productSpecificProcessId": "SYSMON"
                        },
                        "administrativeDomain": "AUTHORITY"
                    },
                    "target": {
                        "mac": [
                            "0.0.0.1"
                        ]
                    },
                    "about": [
                        {
                            "labels": [
                                {
                                    "key": "Category ID",
                                    "value": "DnsQuery"
                                }
                            ]
                        }
                    ],
                    "securityResult": [
                        {
                            "summary": "Dns query",
                            "severity": "INFORMATIONAL"
                        },
                        {
                            "ruleName": "EventID: 22",
                            "summary": "QueryStatus: 0"
                        }
                    ],
                    "network": {
                        "applicationProtocol": "DNS",
                        "dns": {
                            "questions": [
                                {
                                    "name": "logging.googleapis.com"
                                }
                            ],
                            "answers": [
                                {
                                    "type": 5,
                                    "data": "logging.googleapis.com"
                                }
                            ]
                        }
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Event(s) Details

>|Event ID|Event Timestamp|Event Type|Security Results|Principal Asset Identifier|Target Asset Identifier|Product Name|Vendor Name|Queried Domain|
>|---|---|---|---|---|---|---|---|---|
>| 010000= | 2023-01-14T00:59:52.110Z | REGISTRY_MODIFICATION | **Severity:** INFORMATIONAL<br>**Summary:** Registry value set<br>**Rule Name:** technique_id=T0000,technique_name=Service Creation<br><br>**Actions:** ALLOW<br>**Rule Name:** EventID: 10 | active.stack.local | 0.0.0.1 | Microsoft-Windows-Sysmon | Microsoft |  |
>| 0000000020000= | 2023-01-14T00:56:57.372Z | NETWORK_DNS | **Severity:** INFORMATIONAL<br>**Summary:** Dns query<br><br>**Summary:** QueryStatus: 0<br>**Rule Name:** EventID: 22 | DESKTOP | 0.0.0.1 | Microsoft | Microsoft | logging.googleapis.com<br> |


>Maximum number of events specified in limit has been returned. There might still be more events in your Chronicle account. To fetch the next set of events, execute the command with the end time as 2023-01-14T00:56:57.372Z.


### 31. gcb-verify-value-in-reference-list

***
Check if provided values are found in the reference lists in Google Chronicle.

#### Base Command

`gcb-verify-value-in-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values | Specify the values to search in reference lists.<br/>Format accepted is: "value 1, value 2, value 3". | Required | 
| reference_list_names | Specify the reference list names to search through. Supports comma separated values. | Required | 
| case_insensitive_search | If set to true, the command performs case insensitive matching. Possible values are: True, False. Default is False. | Optional | 
| delimiter | Delimiter by which the content of the values list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is ",". | Optional | 
| add_not_found_reference_lists | If set to true, the command will add the not found reference list names to the HR and the context. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.VerifyValueInReferenceList.value | String | The item value to search in the reference list. | 
| GoogleChronicleBackstory.VerifyValueInReferenceList.found_in_lists | String | List of Reference list names, where item was found. | 
| GoogleChronicleBackstory.VerifyValueInReferenceList.not_found_in_lists | String | List of Reference list names, where item not was found. | 
| GoogleChronicleBackstory.VerifyValueInReferenceList.overall_status | String | Whether value found in any reference list. | 

#### Command example
```!gcb-verify-value-in-reference-list reference_list_names="list1,list2" values="value1;value2;value4" delimiter=; case_insensitive_search=True add_not_found_reference_lists=True```

#### Context Example
```json
{
    "GoogleChronicleBackstory": {
        "VerifyValueInReferenceList": [
            {
                "case_insensitive": true,
                "value": "value1",
                "found_in_lists": [
                    "list1"
                ],
                "not_found_in_lists": [
                    "list2"
                ],
                "overall_status": "Found"
            },
            {
                "case_insensitive": true,
                "value": "value2",
                "found_in_lists": [
                    "list1"
                ],
                "not_found_in_lists": [
                    "list2"
                ],
                "overall_status": "Found"
            },
            {
                "case_insensitive": true,
                "value": "value4",
                "found_in_lists": [],
                "not_found_in_lists": [
                    "list1",
                    "list2"
                ],
                "overall_status": "Not Found"
            }
        ]
    }
}
```


#### Human Readable Output

>### Successfully searched provided values in the reference lists in Google Chronicle.
>|Value|Found In Lists|Not Found In Lists|Overall Status|
>|---|---|---|---|
>| value1 | list1 | list2 | Found |
>| value2 | list1 | list2 | Found |
>| value4 |  | list1, list2 | Not Found |



### 32. gcb-verify-rule

***
Verifies that a rule is a valid YARA-L 2.0 rule without creating a new rule or evaluating it over data.

#### Base Command

`gcb-verify-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_text | Specify the Rule text in YARA-L 2.0 format to verify. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.VerifyRule.success | Boolean | Whether rule_text has a valid YARA-L 2.0 format. | 
| GoogleChronicleBackstory.VerifyRule.context | String | Contains the success message or the compilation error if the verification fails. | 
| GoogleChronicleBackstory.VerifyRule.command_name | String | The command name. | 

#### Command example
```!gcb-verify-rule rule_text="rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }"```
#### Context Example
```json
{
    "GoogleChronicleBackstory": {
        "VerifyRule": {
            "command_name": "gcb-verify-rule",
            "context": "identified no known errors",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Identified no known errors

### 33. gcb-get-event

***
Get the specific event with the given ID from Chronicle. <br/><br/>Note: This command returns more than 60 different types of events. Any event would have only specific output context set. Refer the UDM documentation to figure out the output properties specific to the event types.

#### Base Command

`gcb-get-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Specify the ID of the event. <br/><br/>Note: The event_id can be retrieved from the output context path (<span>GoogleChronicleBackstory.Events.id</span>) of the gcb-list-events command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Events.eventType | String | Specifies the type of the event. | 
| GoogleChronicleBackstory.Events.eventTimestamp | Date | The GMT timestamp when the event was generated. | 
| GoogleChronicleBackstory.Events.collectedTimestamp | Date | The GMT timestamp when the event was collected by the vendor's local collection infrastructure. | 
| GoogleChronicleBackstory.Events.description | String | Human-readable description of the event. | 
| GoogleChronicleBackstory.Events.productEventType | String | Short, descriptive, human-readable, and product-specific event name or type. | 
| GoogleChronicleBackstory.Events.productLogId | String | A vendor-specific event identifier to uniquely identify the event \(a GUID\). Users might use this identifier to search the vendor's proprietary console for the event in question. | 
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
| GoogleChronicleBackstory.Events.principal.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.principal.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.principal.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.principal.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.principal.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.principal.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.principal.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.principal.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.target.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.target.email | String | Email address. | 
| GoogleChronicleBackstory.Events.target.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.target.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.target.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.target.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.target.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.target.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.target.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.target.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.target.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.target.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.target.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.target.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.target.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.target.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.target.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.intermediary.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.intermediary.email | String | Email address. | 
| GoogleChronicleBackstory.Events.intermediary.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.intermediary.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.intermediary.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.intermediary.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.intermediary.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.intermediary.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.intermediary.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.intermediary.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.intermediary.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.intermediary.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.intermediary.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.intermediary.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.intermediary.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.intermediary.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.src.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.src.email | String | Email address. | 
| GoogleChronicleBackstory.Events.src.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.src.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.src.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.src.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.src.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.src.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.src.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.src.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.src.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.src.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.src.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.src.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.src.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.src.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.src.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.observer.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.observer.email | String | Email address. | 
| GoogleChronicleBackstory.Events.observer.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.observer.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.observer.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.observer.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.observer.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.observer.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.observer.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.observer.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.observer.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.observer.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.observer.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.observer.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.observer.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.observer.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.observer.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
| GoogleChronicleBackstory.Events.about.assetId | String | Vendor-specific unique device identifier. | 
| GoogleChronicleBackstory.Events.about.email | String | Email address. | 
| GoogleChronicleBackstory.Events.about.hostname | String | Client hostname or domain name field. | 
| GoogleChronicleBackstory.Events.about.platform | String | Platform operating system. | 
| GoogleChronicleBackstory.Events.about.platformPatchLevel | String | Platform operating system patch level. | 
| GoogleChronicleBackstory.Events.about.platformVersion | String | Platform operating system version. | 
| GoogleChronicleBackstory.Events.about.ip | String | IP address associated with a network connection. | 
| GoogleChronicleBackstory.Events.about.port | String | Source or destination network port number when a specific network connection is described within an event. | 
| GoogleChronicleBackstory.Events.about.mac | String | One or more MAC addresses associated with a device. | 
| GoogleChronicleBackstory.Events.about.administrativeDomain | String | Domain which the device belongs to \(for example, the Windows domain\). | 
| GoogleChronicleBackstory.Events.about.url | String | Standard URL. | 
| GoogleChronicleBackstory.Events.about.file.fileMetadata | String | Metadata associated with the file. | 
| GoogleChronicleBackstory.Events.about.file.fullPath | String | Full path identifying the location of the file on the system. | 
| GoogleChronicleBackstory.Events.about.file.md5 | String | MD5 hash value of the file. | 
| GoogleChronicleBackstory.Events.about.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.about.process.file.mimeType | String | Multipurpose Internet Mail Extensions \(MIME\) type of the file. | 
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
| GoogleChronicleBackstory.Events.about.user.windowsSid | String | Stores the Microsoft Windows security identifier \(SID\) associated with a user. | 
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
| GoogleChronicleBackstory.Events.network.dns.opcode | String | Stores the DNS OpCode used to specify the type of DNS query \(standard, inverse, server status, etc.\). | 
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
| GoogleChronicleBackstory.Events.network.email.mailId | String | Stores the mail \(or message\) ID. | 
| GoogleChronicleBackstory.Events.network.email.subject | String | Stores the email subject line. | 
| GoogleChronicleBackstory.Events.network.ftp.command | String | Stores the FTP command. | 
| GoogleChronicleBackstory.Events.network.http.method | String | Stores the HTTP request method. | 
| GoogleChronicleBackstory.Events.network.http.referralUrl | String | Stores the URL for the HTTP referer. | 
| GoogleChronicleBackstory.Events.network.http.responseCode | String | Stores the HTTP response status code, which indicates whether a specific HTTP request has been successfully completed. | 
| GoogleChronicleBackstory.Events.network.http.useragent | String | Stores the User-Agent request header which includes the application type, operating system, software vendor or software version of the requesting software user agent. | 
| GoogleChronicleBackstory.Events.authentication.authType | String | Type of system an authentication event is associated with \(Chronicle UDM\). | 
| GoogleChronicleBackstory.Events.authentication.mechanism | String | Mechanism\(s\) used for authentication. | 
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

#### Command Example

```!gcb-get-event event_id="dummy_id"```

#### Context Example

```json
{
    "GoogleChronicleBackstory.Events(val.id == obj.id)": [
      {
        "eventTimestamp": "2024-11-12T12:19:59Z",
        "eventType": "GENERIC_EVENT",
        "vendorName": "NewClient",
        "productName": "Private Access",
        "productEventType": "APP_NOT_REACHABLE",
        "description": "0",
        "ingestedTimestamp": "2024-11-12T12:20:03.217859Z",
        "id": "dummy_id",
        "logType": "NEW_XYZ",
        "baseLabels": {
          "logTypes": [
            "NEW_XYZ"
          ],
          "allowScopedAccess": true
        },
        "additional": {
          "policy_processing_time": "0",
          "idp": "0",
          "server_setup_time": "0",
          "connector": "0",
          "client_to_client": "0",
          "app_micro_tenant_id": "0",
          "micro_tenant_id": "0",
          "pra_capability_policy_id": "0",
          "client_zen": "EU-DE-9490",
          "customer": "New Demo Center",
          "pra_credential_policy_id": "0",
          "connector_zen": "0",
          "pra_approval_id": "0",
          "double_encryption": "Off",
          "timestamp_connection_end": "2024-11-12T12:19:59.961Z",
          "connection_id": "dummy_connection_id"
        },
        "principal": {
          "user": {
            "userDisplayName": "New LSS Client"
          },
          "port": 11522,
          "location": {
            "city": "New City",
            "countryOrRegion": "US",
            "regionCoordinates": {
              "latitude": 0,
              "longitude": 0
            }
          },
          "natIp": [
            "0.0.0.0"
          ]
        },
        "target": {
          "hostname": "0.0.0.0",
          "user": {
            "groupIdentifiers": [
              "New Enterprise Server - User Status"
            ]
          },
          "port": 11522,
          "application": "New Enterprise Server - User Status"
        },
        "intermediary": [
          {
            "application": "0",
            "resource": {
              "attribute": {
                "labels": [
                  {
                    "key": "new_total_bytes_tx_connector",
                    "value": "0"
                  }
                ]
              }
            }
          }
        ],
        "securityResult": [
          {
            "about": {
              "labels": [
                {
                  "key": "connection_status",
                  "value": "close"
                }
              ]
            },
            "ruleName": "0",
            "description": "None of the App Connectors configured.",
            "detectionFields": [
              {
                "key": "server",
                "value": "0"
              }
            ]
          }
        ],
        "network": {
          "ipProtocol": "TCP",
          "sessionId": "dummy"
        }
      }
    ]
  }
```

#### Human Readable Output

>### General Information for the given event with ID: dummy_id
>|Base Labels|Description|Event Timestamp|Event Type|Id|Ingested Timestamp|Log Type|Product Event Type|Product Name|Vendor Name|
>|---|---|---|---|---|---|---|---|---|---|
>| **logTypes**:<br>	***values***: NEW_XYZ<br>***allowScopedAccess***: True | 0 | 2024-11-12T12:19:59Z | GENERIC_EVENT | dummy_id | 2024-11-12T12:20:03.217859Z | NEW_XYZ | APP_NOT_REACHABLE | Private Access | NewClient |
>
>### Principal Information
>|Location|Nat Ip|Port|User|
>|---|---|---|---|
>| ***city***: New City<br>***countryOrRegion***: US<br>**regionCoordinates**:<br>	***latitude***: 0.0<br>	***longitude***: 0.0 | ***values***: 0.0.0.0 | 11522 | ***userDisplayName***: New LSS Client |
>
>### Target Information
>|Application|Hostname|Port|User|
>|---|---|---|---|
>| New Enterprise Server - User Status | 0.0.0.0 | 11522 | **groupIdentifiers**:<br>	***values***: New Enterprise Server - User Status |
>
>### Security Result Information
>|About|Description|Detection Fields|Rule Name|
>|---|---|---|---|
>| **labels**:<br>	**-**	***key***: connection_status<br>		***value***: close | None of the App Connectors configured. | **-**	***key***: server<br>	***value***: 0 | 0 |
>
>### Network Information
>|Ip Protocol|Session Id|
>|---|---|
>| TCP | dummy |
