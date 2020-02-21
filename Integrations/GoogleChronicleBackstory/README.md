## Overview
---

Use the Google Chronicle Backstory integration to retrieve Asset alerts or IOC Domain matches as Incidents. Use it to fetch a list of infected assets based on the indicator accessed. This integration also provides reputation and threat enrichment of indicators observed in the enterprise.

## Configure Google Chronicle Backstory on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Google Chronicle Backstory.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __User's Service Account JSON__
    * __Provide comma(',') separated categories (e.g. APT-Activity, Phishing). Indicators belonging to these "categories" would be considered as "malicious" when executing reputation commands.__
    * __Provide comma(',') separated categories (e.g. Unwanted, VirusTotal YARA Rule Match). Indicators belonging to these "categories" would be considered as "suspicious" when executing reputation commands.__
    * __Specify the "severity" of indicator that should be considered as "malicious" irrespective of the category.  If you wish to consider all indicators with High severity as Malicious, set this parameter to 'High'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only.__
    * __Specify the "severity" of indicator that should be considered as "suspicious" irrespective of the category. If you wish to consider all indicators with Medium severity as Suspicious, set this parameter to 'Medium'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only.__
    * __Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "malicious". The value provided should be greater than the suspicious threshold. This configuration is applicable to reputation commands only.__
    * __Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "suspicious". The value provided should be smaller than the malicious threshold. This configuration is applicable to reputation commands only.__
    * __Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "malicious". The confidence level configured should have higher precedence than the suspicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH.__
    * __Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "suspicious". The confidence level configured should have lesser precedence than the malicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH.__
    * __Fetches incidents__
    * __First fetch time interval. The time range to consider for initial data fetch.(<number> <unit>, e.g., 1 day, 7 days, 3 months, 1 year).__
    * __How many incidents to fetch each time__
    * __Backstory Alert Type (Select the type of data to consider for fetch incidents).__
    * __Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection).__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Fetched Incidents Data
---
Fetch-incidents feature can pull events from Google Chronicle which can be converted into actionable incidents for further investigation. It is the function that Demisto calls every minute to import new incidents and can be enabled by the "Fetches incidents" parameter in the integration configuration.

The list of alerts (gcb-list-alerts) or IOC domain matches (gcb-list-iocs) are the two choices that can be configured.
#### Configuration Parameters for Fetch-incidents
 - First fetch time interval. The time range to consider for initial data fetch.(\<number> \<unit>, e.g. 1 day, 7 days, 3 months, 1 year): **Default** 3 days
 - How many incidents to fetch each time: **Default** 10
 - Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection). **Only applicable for asset alerts**.
 - Backstory Alert Type (Select the type of data to consider for fetch incidents):
   - IOC Domain matches **Default**
   - Assets with alerts
 
| **Name** | **Initial Value** |
| --- | --- |
| First fetch time interval. The time range to consider for initial data fetch.(\<number> \<unit>, e.g. 1 day, 7 days, 3 months, 1 year). | 3 days |
| How many incidents to fetch each time. | 10 |
| Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection). *Only applicable for asset alerts.* | Default No Selection |
| Backstory Alert Type (Select the type of data to consider for fetch incidents). | IOC Domain matches (Default), Assets with alerts | 

#### Incident field mapping - Asset Alerts
| **Name** | **Initial Value** |
| --- | --- |
| name | \<AlertName> for \<Asset> |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |
| severity | Severity of Alert |

#### Incident field mapping - IOC Domain matches
| **Name** | **Initial Value** |
| --- | --- |
| name | IOC Domain Match: \<Artifact> |
| rawJSON | Single Raw JSON |
| details | Single Raw JSON |


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. gcb-list-iocs
2. gcb-assets
3. ip
4. domain
5. gcb-ioc-details
6. gcb-list-alerts
### 1. gcb-list-iocs
---
Lists the IOC Domain matches within your enterprise for the specified time interval. The indicator of compromise (IOC) domain matches lists for which the domains that your security infrastructure has flagged as both suspicious and that have been seen recently within your enterprise.

##### Base Command

`gcb-list-iocs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetches IOC Domain matches in the specified time interval. If configured, overrides the start_time argument. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z). If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. | Optional | 
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
| anx.tb.ask.com | Spyware Reporting Server | ET Intelligence Rep List | Low | Medium | 7 days ago | a year ago | 3 hours ago |


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
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z). If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. | Optional | 
| end_time | The value of the end time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z). If not supplied,  the default is current UTC time. | Optional | 
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
### Assets related to artifact - bing.com
|Host Name|Host IP|Host MAC|First Accessed Time|Last Accessed Time|
|---|---|---|---|---|
| james-anderson-laptop | - | - | 2018-10-18T04:38:44Z | 2020-02-14T07:13:33Z |
| roger-buchmann-pc | - | - | 2018-10-18T02:01:51Z | 2020-02-13T22:25:27Z |


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


### 6. gcb-list-alerts
---
List all the alerts tracked within your enterprise for the specified time range. Both the parsed alerts and their corresponding raw alert logs are returned.

##### Base Command

`gcb-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetch alerts for the specified time range. If preset_time_range is configured, overrides the start_time and end_time arguments. | Optional | 
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z). If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. | Optional | 
| end_time | The value of the end time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z). If not supplied,  the default is current UTC time. | Optional | 
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. The default is 10000. | Optional | 
| severity | The severity by which to filter the returned alerts. If not supplied, all alerts are fetched. The possible values are "High", "Medium", "Low", or "Unspecified". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Alert.AssetName | String | The asset identifier. It can be IP Address, MAC Address, Hostname or Product ID. | 
| GoogleChronicleBackstory.Alert.AlertInfo.Name | String | The name of the alert. | 
| GoogleChronicleBackstory.Alert.AlertInfo.Severity | String | The severity of the alert. | 
| GoogleChronicleBackstory.Alert.AlertInfo.SourceProduct | String | The source of the alert. | 
| GoogleChronicleBackstory.Alert.AlertInfo.Timestamp | String | The time of the alert in Backstory. | 
| GoogleChronicleBackstory.Alert.AlertCounts | Number | The total number of alerts. | 


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
| 1 | rosie-hayes-pc | Authentication failure [32038] | 6 hours ago | 6 hours ago | Medium | Internal Alert |
