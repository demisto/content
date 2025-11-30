Use the Google SecOps integration to retrieve IOC Domain matches as Incidents. This integration also provides reputation and threat enrichment of indicators observed in the enterprise.
This integration was integrated and tested with version v1 Alpha of GoogleSecOps.

**Note:** The commands will do up to 3 internal retries with a gap of 15, 30, and 60 seconds (exponentially) between the retries.

If you are upgrading from a Google Chronicle Backstory integration, please refer to the [Migration Guide](#migration-guide) for guidance.

## Configure Google SecOps v1 Alpha on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google SecOps v1 Alpha.
3. Click **Add instance** to create and configure a new integration instance.
4. To fetch IOC Domain matches, refer to the section ["Configuration for fetching IOC Domain Matches as a Cortex XSOAR Incident"](#configuration-for-fetching-ioc-domain-matches-as-a-cortex-xsoar-incident).

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| User's Service Account JSON |  | True |
| Google SecOps Project Instance ID | Provide the Project Instance ID of the Google SecOps.<br/><br/>Note: User can retrieve the Customer ID\(Project Instance ID\) in the Profile section of the Google SecOps page. | True |
| Region | Select the region based on the location of the Google SecOps instance. If the region is not listed in the dropdown, choose the "Other" option and specify the region in the "Other Region" text field. | True |
| Other Region | Specify the region based on the location of the Google SecOps instance. Only applicable if the "Other" option is selected in the Region dropdown. | False |
| Provide comma(',') separated categories (e.g. APT-Activity, Phishing). | Indicators belonging to these "categories" would be considered as "malicious" when executing reputation commands. | False |
| Provide comma(',') separated categories (e.g. Unwanted, VirusTotal YARA Rule Match). | Indicators belonging to these "categories" would be considered as "suspicious" when executing reputation commands. | False |
| Specify the "severity" of indicator that should be considered as "malicious" irrespective of the category. | If you wish to consider all indicators with High severity as Malicious, set this parameter to 'High'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only. | False |
| Specify the "severity" of indicator that should be considered as "suspicious" irrespective of the category. | If you wish to consider all indicators with Medium severity as Suspicious, set this parameter to 'Medium'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable to reputation commands only. | False |
| Specify the numeric value of "confidence score". | If the indicator's confidence score is equal or above the configured threshold, it would be considered as "malicious". The value provided should be greater than the suspicious threshold. This configuration is applicable to reputation commands only. | False |
| Specify the numeric value of "confidence score". | If the indicator's confidence score is equal or above the configured threshold, it would be considered as "suspicious". The value provided should be smaller than the malicious threshold. This configuration is applicable to reputation commands only. | False |
| Select the confidence score level. | If the indicator's confidence score level is equal or above the configured level, it would be considered as "malicious". The confidence level configured should have higher precedence than the suspicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN SEVERITY &lt; INFORMATIONAL &lt; LOW &lt; MEDIUM &lt; HIGH. | False |
| Select the confidence score level.  | If the indicator's confidence score level is equal or above the configured level, it would be considered as "suspicious".<br/>The confidence level configured should have lesser precedence than the malicious level. This configuration is applicable to reputation commands only. Refer the "confidence score" level precedence UNKNOWN SEVERITY &lt; INFORMATIONAL &lt; LOW &lt; MEDIUM &lt; HIGH. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch time | The UTC date or relative timestamp from where to start fetching incidents.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 10 minutes, 5 hours, 8 days, 2 weeks, 8 months, 2021-12-31, 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. Default value is 3 days. | False |
| How many incidents to fetch each time | The maximum number of incidents to fetch in each time. The maximum value is 10,000. Default value is 100. | False |
| Time window (in minutes) | Select the time window to query Google SecOps. While selecting the time window consider the time delay for an event to appear in Google SecOps after generation. Available options are 60\(Default\), 120, 240, 360, 480, 600, 720, 1440. |  |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

5. Click **Test** to validate the URLs, token, and connection.

## Configuration for fetching IOC Domain Matches as a Cortex XSOAR Incident

1. Select **Fetches incidents**.
2. Under Classifier, select "Chronicle - Classifier".
3. Under Incident type, select "N/A".
4. Under Mapper (incoming), select "Chronicle - Incoming Mapper" for default mapping.
5. Enter the connection parameters (Service Account JSON, Google SecOps Project Instance ID, Region).
6. Update "First fetch time" and "Max Fetch Count" based on your requirements.
7. Update the "Time window" based on the time delay for an event to appear in Google SecOps after generation.
8. Click **Save**.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. gcb-list-iocs
2. ip
3. domain
4. gcb-ioc-details
5. gcb-list-events
6. gcb-list-detections
7. gcb-list-rules
8. gcb-create-rule
9. gcb-get-rule
10. gcb-delete-rule
11. gcb-create-rule-version
12. gcb-change-rule-alerting-status
13. gcb-change-live-rule-status
14. gcb-start-retrohunt
15. gcb-get-retrohunt
16. gcb-list-retrohunts
17. gcb-cancel-retrohunt
18. gcb-list-reference-list
19. gcb-get-reference-list
20. gcb-create-reference-list
21. gcb-update-reference-list
22. gcb-verify-reference-list
23. gcb-test-rule-stream
24. gcb-list-curatedrules
25. gcb-list-curatedrule-detections
26. gcb-udm-search
27. gcb-verify-value-in-reference-list
28. gcb-verify-rule
29. gcb-get-event
30. gcb-reference-list-append-content
31. gcb-reference-list-remove-content
32. gcb-list-data-tables
33. gcb-create-data-table
34. gcb-get-data-table
35. gcb-verify-value-in-data-table
36. gcb-data-table-add-row
37. gcb-data-table-remove-row
38. gcb-get-detection

### 1. gcb-list-iocs

***
Lists the IOC Domain matches within your enterprise for the specified time interval. The indicator of compromise (IOC) domain matches lists for which the domains that your security infrastructure has flagged as both suspicious and that have been seen recently within your enterprise.

#### Base Command

`gcb-list-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| preset_time_range | Fetches IOC Domain matches in the specified time interval. If configured, overrides the start_time argument. | Optional |
| start_time | The value of the start time for your request, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the default is the UTC time corresponding to 3 days earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |
| page_size | The maximum number of IOCs to return. You can specify between 1 and 10000. Default is 10000. | Optional |

#### Context Output

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

#### Command Example

```!gcb-list-iocs page_size=1 preset_time_range="Last 1 day"```

#### Context Example

```json
{
    "Domain": {
        "Name": "test.com"
    },
    "GoogleChronicleBackstory": {
        "Iocs": [
            {
                "Artifact": "test.com",
                "FirstAccessedTime": "2025-06-19T05:48:21Z",
                "IocIngestTime": "2025-06-16T04:22:03.276821Z",
                "LastAccessedTime": "2025-07-10T14:13:30Z",
                "Sources": [
                    {
                        "Category": "Unwanted",
                        "IntRawConfidenceScore": 70,
                        "NormalizedConfidenceScore": "Medium",
                        "RawSeverity": "Medium",
                        "Source": "3rd Party"
                    }
                ]
            },
            {
                "Artifact": "0.0.0.1",
                "FirstAccessedTime": "2025-06-19T05:48:21Z",
                "IocIngestTime": "2025-06-16T04:22:03.276821Z",
                "LastAccessedTime": "2025-07-10T14:13:30Z",
                "Sources": [
                    {
                        "Category": "Unwanted",
                        "IntRawConfidenceScore": 100,
                        "NormalizedConfidenceScore": "High",
                        "RawSeverity": "Medium",
                        "Source": "3rd Party"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### IOC Domain Matches
>
>|Artifact|Category|Source|Confidence|Severity|IOC ingest time|First seen|Last seen|
>|---|---|---|---|---|---|---|---|
>| test.com | Unwanted | 3rd Party | Medium | Medium | 2 months ago | 2 months ago | a month ago |
>| 0.0.0.1 | Unwanted | 3rd Party | High | Medium | 2 months ago | 2 months ago | a month ago |

### 2. ip

***
Checks the reputation of an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to check. | Required |

#### Context Output

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

#### Command example

```!ip ip="0.0.0.1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "0.0.0.1",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Google SecOps"
    },
    "GoogleChronicleBackstory": {
        "IP": {
            "IoCQueried": "0.0.0.1",
            "Sources": [
                {
                    "Address": [
                        {
                            "IpAddress": "0.0.0.1"
                        }
                    ],
                    "Category": "Indicator was published in publicly available sources",
                    "ConfidenceScore": 64,
                    "FirstAccessedTime": "1970-01-01T00:00:01Z",
                    "LastAccessedTime": "9999-12-31T23:59:59Z",
                    "Severity": "High"
                }
            ]
        }
    },
    "IP": {
        "Address": "0.0.0.1",
        "Malicious": {
            "Description": "Found in malicious data set",
            "Vendor": "Google SecOps"
        }
    }
}
```

#### Human Readable Output

>IP: 0.0.0.1 found with Reputation: Malicious
>
>### Reputation Parameters
>
>|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|---|---|
>| - | 0.0.0.1 | Indicator was published in publicly available sources | 64 | High | 1970-01-01T00:00:01Z | 9999-12-31T23:59:59Z |

### 3. domain

***
Checks the reputation of a domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to check. | Required |

#### Context Output

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

#### Command example

```!domain domain="test.com"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "test.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Google SecOps"
    },
    "Domain": {
        "Name": "test.com"
    },
    "GoogleChronicleBackstory": {
        "Domain": {
            "IoCQueried": "test.com",
            "Sources": [
                {
                    "Address": [
                        {
                            "Domain": "test.com"
                        }
                    ],
                    "Category": "Indicator was published in publicly available sources",
                    "ConfidenceScore": 77,
                    "FirstAccessedTime": "1970-01-01T00:00:01Z",
                    "LastAccessedTime": "9999-12-31T23:59:59Z",
                    "Severity": "Medium"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>Domain: test.com found with Reputation: Unknown
>
>### Reputation Parameters
>
>|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|---|---|
>| test.com | - | Indicator was published in publicly available sources | 77 | Medium | 1970-01-01T00:00:01Z | 9999-12-31T23:59:59Z |

### 4. gcb-ioc-details

***
Accepts an artifact indicator and returns any threat intelligence associated with the artifact. The threat intelligence information is drawn from your enterprise security systems and from Chronicle's IoC partners (for example, the DHS threat feed).

#### Base Command

`gcb-ioc-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| artifact_value | The artifact indicator value. The supported artifact types are IP and domain. | Required |

#### Context Output

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

#### Command Example

```!gcb-ioc-details artifact_value=0.0.0.1```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "IocDetails": {
            "IoCQueried": "0.0.0.1",
            "Sources": [
                {
                    "Address": [
                        {
                            "IpAddress": "0.0.0.1",
                            "Port": [
                                80
                            ]
                        }
                    ],
                    "Category": "Blocked",
                    "ConfidenceScore": "High",
                    "FirstAccessedTime": "1970-01-01T00:00:00Z",
                    "LastAccessedTime": "9999-12-31T23:59:59Z",
                    "Severity": "High"
                },
                {
                    "Address": [
                        {
                            "Domain": "test.com",
                            "Port": [
                                44902,
                                65178
                            ]
                        },
                        {
                            "IpAddress": "0.0.0.1",
                            "Port": [
                                80
                            ]
                        }
                    ],
                    "Category": "Blocked",
                    "ConfidenceScore": 70,
                    "FirstAccessedTime": "1970-01-01T00:00:00Z",
                    "LastAccessedTime": "2025-02-18T15:35:11Z",
                    "Severity": "Low"
                }
            ]
        }
    },
    "IP": {
        "Address": "0.0.0.1"
    }
}
```

#### Human Readable Output

>### IoC Details
>
>|Domain|IP Address|Category|Confidence Score|Severity|First Accessed Time|Last Accessed Time|
>|---|---|---|---|---|---|---|
>| - | 0.0.0.1 | Blocked | High | High | 1970-01-01T00:00:00Z | 9999-12-31T23:59:59Z |
>| test.com | 0.0.0.1 | Blocked | 70 | Low | 1970-01-01T00:00:00Z | 2025-02-18T15:35:11Z |

### 5. gcb-list-events

***
List all of the events discovered within your enterprise on a particular device within the specified time range. If you receive the maximum number of events you specified using the page_size parameter (or 100, the default), there might still be more events within your Google SecOps account. You can narrow the time range and issue the call again to ensure you have visibility into all possible events. This command returns more than 60 different types of events. Any event would have only specific output context set. Refer the UDM documentation to figure out the output properties specific to the event types.

#### Base Command

`gcb-list-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_identifier_type | Specify the identifier type of the asset you are investigating. The possible values are Host Name, IP Address, MAC Address or Product ID. Possible values are: Host Name, IP Address, MAC Address, Product ID. | Required |
| asset_identifier | Value of the asset identifier. | Required |
| preset_time_range | Get events that are discovered during the interval specified. If configured, overrides the start_time and end_time arguments. Possible values are: Last 1 day, Last 7 days, Last 15 days, Last 30 days. | Optional |
| start_time | The value of the start time for your request. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 2 hours earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |
| end_time | The value of the end time for your request. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers current UTC time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |
| page_size | Specify the maximum number of events to fetch. You can specify between 1 and 10000. Default is 10000. | Optional |
| reference_time | Specify the reference time for the asset you are investigating, in RFC 3339 format (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers start time as reference time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |

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

#### Command example

```!gcb-list-events asset_identifier=1.2.3.4 asset_identifier_type="IP Address" page_size=1 start_time="10 days"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Events": {
            "eventTimestamp": "2025-07-10T00:01:00Z",
            "collectedTimestamp": "2025-07-10T00:01:00Z",
            "eventType": "NETWORK_DNS",
            "productName": "ExtraHop",
            "principal": {
                "hostname": "dummy-host",
                "ip": [
                    "1.2.3.4"
                ]
            },
            "target": {
                "ip": [
                    "5.6.7.8"
                ]
            },
            "network": {
                "applicationProtocol": "DNS",
                "dns": {
                    "questions": [
                        {
                            "name": "www.test.com",
                            "type": 1
                        }
                    ],
                    "answers": [
                        {
                            "name": "www.test.com",
                            "type": 1,
                            "ttl": 1111,
                            "data": "4.3.2.1"
                        }
                    ]
                }
            }
        }
    }
}
```

>### Event(s) Details
>
>|Event Timestamp|Event Type|Principal Asset Identifier|Target Asset Identifier|Queried Domain|
>|---|---|---|---|---|
>| 2025-07-10T00:01:00Z | NETWORK_DNS | 1.2.3.4 | 5.6.7.8 | www.test.com<br> |
>
>
>Maximum number of events specified in page_size has been returned. There might still be more events in your Google SecOps account. To fetch the next set of events, execute the command with the start time as 2025-07-10T00:01:00Z.

### 6. gcb-list-detections

***
Return the detections for the specified version of a rule, the latest version of a rule, all versions of a rule, or all versions of all rules.

#### Base Command

`gcb-list-detections`

#### Input

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

```!gcb-list-detections id=ru_dummy_rule_id page_size=1```

##### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Detections": [
            {
                "alertState": "ALERTING",
                "collectionElements": [
                    {
                        "label": "event",
                        "references": [
                            {
                                "eventTimestamp": "2020-12-21T02:58:06.804Z",
                                "eventType": "NETWORK_DNS",
                                "ingestedTimestamp": "2020-12-21T03:02:46.559472Z",
                                "network": {
                                    "applicationProtocol": "DNS",
                                    "dns": {
                                        "answers": [
                                            {
                                                "data": "4.3.2.1",
                                                "name": "test1.com",
                                                "ttl": 11111,
                                                "type": 1
                                            }
                                        ],
                                        "questions": [
                                            {
                                                "name": "test.com",
                                                "type": 1
                                            }
                                        ],
                                        "response": true
                                    }
                                },
                                "principal": {
                                    "hostname": "ray-xxx-laptop",
                                    "ip": [
                                        "0.0.0.0"
                                    ],
                                    "mac": [
                                        "00:00:00:00:00:00"
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
                                        "0.0.0.1"
                                    ]
                                },
                                "targetAssetIdentifier": "0.0.0.1"
                            }
                        ]
                    }
                ],
                "createdTime": "2020-12-21T03:12:50.128428Z",
                "detectionFields": [
                    {
                        "key": "client_ip",
                        "value": "0.0.0.0"
                    }
                ],
                "detectionTime": "2020-12-21T03:54:00Z",
                "id": "de_dummy_detection_id",
                "ruleId": "ru_dummy_rule_id",
                "ruleName": "SampleRule",
                "ruleType": "MULTI_EVENT",
                "ruleVersion": "ru_dummy_rule_id@v_version_id",
                "timeWindowEndTime": "2020-12-21T03:54:00Z",
                "timeWindowStartTime": "2020-12-21T02:54:00Z",
                "type": "RULE_DETECTION",
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_dummy_detection_id"
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

>### Detection(s) Details For Rule: [SampleRule](https://dummy-chronicle/ruleDetections?ruleId=dummy_rule_id)
>
>|Detection ID|Detection Type|Detection Time|Events|Alert State|
>|---|---|---|---|---|
>| [de_dummy_detection_id](https://dummy-chronicle/alert?alertId=de_dummy_detection_id) | RULE_DETECTION | 2020-12-21T03:54:00Z | **Event Timestamp:** 2020-12-21T02:58:06.804Z<br>**Event Type:** NETWORK_DNS<br>**Principal Asset Identifier:** ray-xxx-laptop<br>**Target Asset Identifier:** 0.0.0.1<br>**Queried Domain:** test.com | ALERTING |
>
>View all detections for this rule in Google SecOps by clicking on SampleRule and to view individual detection in Google SecOps click on its respective Detection ID.
>
>Note: If a specific version of the rule is provided then detections for that specific version will be fetched.
>Maximum number of detections specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as `foobar_page_token`.

### 7. gcb-list-rules

***
List the latest versions of all Rules.

#### Base Command

`gcb-list-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Specify the maximum number of Rules to return. You can specify between 1 and 1000. Default is 100. | Optional |
| page_token | A page token, received from a previous call.  Provide this to retrieve the subsequent page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.Rules.ruleId | String | Unique identifier for a Rule. |
| GoogleChronicleBackstory.Rules.versionId | String | Unique identifier for a specific version of a rule. |
| GoogleChronicleBackstory.Rules.ruleName | String | Name of the rule, as parsed from ruleText. |
| GoogleChronicleBackstory.Rules.ruleText | String | Source code for the rule, as defined by the user. |
| GoogleChronicleBackstory.Rules.versionCreateTime | String | A string representing the time in ISO-8601 format. |
| GoogleChronicleBackstory.Rules.compilationState | String | Compilation state of the rule. It can be SUCCEEDED or FAILED. |
| GoogleChronicleBackstory.Rules.compilationError | String | A compilation error if compilationState is FAILED, absent if compilationState is SUCCEEDED. |
| GoogleChronicleBackstory.Rules.Metadata.severity | String | Severity for the rule. |
| GoogleChronicleBackstory.Rules.Metadata.author | String | Name of author for the rule. |
| GoogleChronicleBackstory.Rules.Metadata.description | String | Description of the rule. |
| GoogleChronicleBackstory.Rules.Metadata.reference | String | Reference link for the rule. |
| GoogleChronicleBackstory.Rules.Metadata.created | String | Time at which the rule is created. |
| GoogleChronicleBackstory.Rules.Metadata.updated | String | Time at which the rule is updated. |
| GoogleChronicleBackstory.Rules.referenceLists | String | Resource names of the reference lists used in this rule. |
| GoogleChronicleBackstory.Rules.allowedRunFrequencies | String | The run frequencies that are allowed for the rule. |
| GoogleChronicleBackstory.Token.name | String | The name of the command to which the value of the nextPageToken corresponds. |
| GoogleChronicleBackstory.Token.nextPageToken | String | A page token that can be provided to the next call to view the next page of Rules. Absent if this is the last page. |

#### Command Example

```!gcb-list-rules page_size=2```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": [
            {
                "ruleId": "dummy_rule_id",
                "versionId": "dummy_rule_id@dummy_revicion_id",
                "ruleName": "singleEventRule2",
                "ruleText": "rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }\n",
                "ruleType": "SINGLE_EVENT",
                "versionCreateTime": "2025-01-02T00:00:00.000000z",
                "metadata": {
                    "author": "securityuser",
                    "created": "2025-01-01T00:00:00.000000z",
                    "severity": "",
                    "description": "single event rule that should generate detections"
                },
                "compilationState": "SUCCEEDED",
                "inputsUsed": {
                    "usesUdm": true
                },
                "allowedRunFrequencies": [
                    "LIVE",
                    "HOURLY",
                    "DAILY"
                ]
            },
            {
                "ruleId": "dummy_rule_id_2",
                "versionId": "dummy_rule_id_2@dummy_revicion_id_2",
                "ruleName": "singleEventRule2",
                "ruleText": "rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }\n",
                "ruleType": "SINGLE_EVENT",
                "versionCreateTime": "2025-01-02T00:00:00.000000z",
                "metadata": {
                    "author": "securityuser",
                    "created": "2025-01-01T00:00:00.000000z",
                    "severity": "",
                    "description": "single event rule that should generate detections on platform"
                },
                "compilationState": "SUCCEEDED",
                "inputsUsed": {
                    "usesUdm": true
                },
                "allowedRunFrequencies": [
                    "LIVE",
                    "HOURLY",
                    "DAILY"
                ]
            }
        ],
    },
    "GoogleChronicleBackstory": {
        "Token": {
            "name": "gcb-list-rules",
            "nextPageToken": "test_page_token"
        }
    }
}
```

#### Human Readable Output

>### Rule(s) Details
>
>|Rule ID|Rule Name|Compilation State|
>| --- | --- | --- |
>| dummy_rule_id | singleEventRule2 | SUCCEEDED |
>| dummy_rule_id_2 | singleEventRule2 | SUCCEEDED |
>
> Maximum number of rules specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as `test_page_token`.

### 8. gcb-create-rule

***
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
| GoogleChronicleBackstory.Rules.referenceLists | String | Resource names of the reference lists used in this rule. |
| GoogleChronicleBackstory.Rules.allowedRunFrequencies | String | The run frequencies that are allowed for the rule. |

#### Command Example

```!gcb-create-rule rule_text="rule demoRuleCreatedFromAPI {meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e}"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": {
            "ruleId": "dummy_rule_id",
            "versionId": "dummy_rule_id@dummy_revicion_id",
            "ruleName": "singleEventRule2",
            "ruleText": "rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }\n",
            "ruleType": "SINGLE_EVENT",
            "versionCreateTime": "2025-01-02T00:00:00.000000z",
            "metadata": {
                "author": "securityuser",
                "created": "2025-01-01T00:00:00.000000z",
                "severity": "Medium",
                "description": "single event rule that should generate detections"
            },
            "compilationState": "SUCCEEDED",
            "inputsUsed": {
                "usesUdm": true
            },
            "allowedRunFrequencies": [
                "LIVE",
                "HOURLY",
                "DAILY"
            ]
        }
    }
}
```

#### Human Readable Output

>### Rule Details
>
>|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|Allowed Run Frequencies|
>|---|---|---|---|---|---|---|---|---|
>| dummy_rule_id | dummy_rule_id@dummy_revicion_id | securityuser | singleEventRule2 | single event rule that should generate detections | 2025-01-02T00:00:00.000000z | SUCCEEDED | rule singleEventRule2 { meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e }<br> | LIVE,<br>HOURLY,<br>DAILY |

### 9. gcb-get-rule

***
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
| GoogleChronicleBackstory.Rules.referenceLists | String | Resource names of the reference lists used in this rule. |
| GoogleChronicleBackstory.Rules.allowedRunFrequencies | String | The run frequencies that are allowed for the rule. |

#### Command Example

```!gcb-get-rule id=dummy_rule_id```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": [
            {
                "ruleId": "dummy_rule_id",
                "versionId": "dummy_rule_id@dummy_revision_id",
                "ruleName": "singleEventRule2",
                "ruleText": "rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }\n",
                "ruleType": "SINGLE_EVENT",
                "versionCreateTime": "2025-01-02T00:00:00.000000z",
                "metadata": {
                    "description": "single event rule that should generate detections",
                    "author": "securityuser",
                    "created": "2025-01-01T00:00:00.000000z",
                    "severity": "Medium"
                },
                "compilationState": "SUCCEEDED",
                "inputsUsed": {
                    "usesUdm": true
                },
                "allowedRunFrequencies": [
                    "LIVE",
                    "HOURLY",
                    "DAILY"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Rule Details
>
>|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|Allowed Run Frequencies|
>|---|---|---|---|---|---|---|---|---|
>| dummy_rule_id | dummy_rule_id@dummy_revision_id | securityuser | singleEventRule2 | single event rule that should generate detections | 2025-01-02T00:00:00.000000z | SUCCEEDED | rule singleEventRule2 { meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e }<br> | LIVE,<br>HOURLY,<br>DAILY |

### 10. gcb-delete-rule

***
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

```!gcb-delete-rule rule_id=dummy_rule_id```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "DeleteRule": {
            "actionStatus": "SUCCESS",
            "ruleId": "dummy_rule_id"
        }
    }
}
```

#### Human Readable Output

>### Rule with ID test_rule_id deleted successfully
>
>|Rule ID|Action Status|
>|---|---|
>| test_rule_id | SUCCESS |

### 11. gcb-create-rule-version

***
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
| GoogleChronicleBackstory.Rules.referenceLists | String | Resource names of the reference lists used in this rule. |
| GoogleChronicleBackstory.Rules.allowedRunFrequencies | String | The run frequencies that are allowed for the rule. |

#### Command Example

```!gcb-create-rule-version rule_id="dummy_rule_id" rule_text="rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }\n"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Rules": {
            "ruleId": "dummy_rule_id",
            "versionId": "dummy_rule_id@dummy_revicion_id",
            "ruleName": "singleEventRule2",
            "ruleText": "rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }\n",
            "ruleType": "SINGLE_EVENT",
            "versionCreateTime": "2025-01-02T00:00:00.000000z",
            "metadata": {
                "author": "securityuser",
                "created": "2025-01-01T00:00:00.000000z",
                "severity": "Medium",
                "description": "single event rule that should generate detections"
            },
            "compilationState": "SUCCEEDED",
            "inputsUsed": {
                "usesUdm": true
            },
            "allowedRunFrequencies": [
                "LIVE",
                "HOURLY",
                "DAILY"
            ]
        }
    }
}
```

#### Human Readable Output

>### Rule Details
>
>|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|Allowed Run Frequencies|
>|---|---|---|---|---|---|---|---|---|
>| dummy_rule_id | dummy_rule_id@dummy_revicion_id | securityuser | singleEventRule2 | single event rule that should generate detections | 2025-01-02T00:00:00.000000z | SUCCEEDED | rule singleEventRule2 { meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e }<br> | LIVE,<br>HOURLY,<br>DAILY |

### 12. gcb-change-rule-alerting-status

***
Updates the alerting status for a rule specified by Rule ID.

#### Base Command

`gcb-change-rule-alerting-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | ID of the rule. | Required |
| alerting_status | New alerting status for the Rule.<br/><br/>Possible values are: "enable" or "disable". | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RuleAlertingChange.ruleId | String | Unique identifier for a Rule. |
| GoogleChronicleBackstory.RuleAlertingChange.actionStatus | String | Whether the alerting status for the rule is successfully updated or not. |
| GoogleChronicleBackstory.RuleAlertingChange.alertingStatus | String | New alerting status for the rule. |

#### Command Example

```!gcb-change-rule-alerting-status alerting_status=enable rule_id=dummy_rule_id```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RuleAlertingChange": {
            "actionStatus": "SUCCESS",
            "alertingStatus": "enable",
            "ruleId": "dummy_rule_id"
        }
    }
}
```

#### Human Readable Output

>### Alerting Status
>
>Alerting status for the rule with ID dummy_rule_id has been successfully enabled.
>
>|Rule ID|Action Status|
>|---|---|
>| dummy_rule_id | SUCCESS |

### 13. gcb-change-live-rule-status

***
Updates the live rule status for a rule specified by Rule ID.

#### Base Command

`gcb-change-live-rule-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | ID of the rule. | Required |
| live_rule_status | New live rule status for the Rule.<br/><br/>Possible values are: "enable" or "disable". | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.LiveRuleStatusChange.ruleId | String | Unique identifier for a Rule. |
| GoogleChronicleBackstory.LiveRuleStatusChange.actionStatus | String | Whether the live rule status for the rule is successfully updated or not. |
| GoogleChronicleBackstory.LiveRuleStatusChange.liveRuleStatus | String | New live rule status for the rule. |

#### Command Example

```!gcb-change-live-rule-status live_rule_status=enable rule_id=ru_abcd```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "LiveRuleStatusChange": {
            "actionStatus": "SUCCESS",
            "liveRuleStatus": "enable",
            "ruleId": "ru_abcd"
        }
    }
}
```

#### Human Readable Output

>### Live Rule Status
>
>Live rule status for the rule with ID ru_abcd has been successfully enabled.
>
>|Rule ID|Action Status|
>|---|---|
>| ru_abcd | SUCCESS |

### 14. gcb-start-retrohunt

***
Initiate a retrohunt for the specified rule.

#### Base Command

`gcb-start-retrohunt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID or Version ID of the rule whose retrohunt is to be started. | Required |
| start_time | Start time for the time range of logs being processed. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 1 week earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |
| end_time | End time for the time range of logs being processed. The format of Date should comply with RFC 3339 (e.g. 2002-10-02T15:00:00Z) or relative time. If not supplied, the product considers UTC time corresponding to 10 minutes earlier than current time. Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours. Example: 2020-05-01T00:00:00Z, 2020-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2021 04:45:33, 15 Jun. | Optional |

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

```!gcb-start-retrohunt rule_id=ru_dummy_rule_id start_time="1 day"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": {
            "retrohuntId": "oh_dummy_retrohunt_id",
            "ruleId": "ru_dummy_rule_id",
            "versionId": "ru_dummy_rule_id@v_dummy_revision_id",
            "eventStartTime": "2025-07-01T10:00:00Z",
            "eventEndTime": "2025-07-08T10:00:00Z",
            "retrohuntStartTime": "2025-07-08T12:00:00.000000Z",
            "state": "RUNNING",
            "progressPercentage": 0
        }
    }
}
```

#### Human Readable Output

>### Retrohunt Details
>
>|Retrohunt ID|Rule ID|Version ID|Event Start Time|Event End Time|Retrohunt Start Time|State|Progress Percentage|
>|---|---|---|---|---|---|---|---|
>| oh_dummy_retrohunt_id | ru_dummy_rule_id | ru_dummy_rule_id@v_dummy_revision_id | 2025-07-01T10:00:00Z | 2025-07-08T10:00:00Z | 2025-07-08T12:00:00.000000Z | RUNNING | 0 |

### 15. gcb-get-retrohunt

***
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

```!gcb-get-retrohunt id=ru_dummy_rule_id retrohunt_id=oh_dummy_retrohunt_id```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": {
            "retrohuntId": "oh_dummy_retrohunt_id",
            "ruleId": "ru_dummy_rule_id",
            "versionId": "ru_dummy_rule_id@v_dummy_revision_id",
            "eventStartTime": "2025-07-01T10:00:00Z",
            "eventEndTime": "2025-07-08T10:00:00Z",
            "retrohuntStartTime": "2025-07-08T12:00:00.000000Z",
            "retrohuntEndTime": "2025-07-08T12:15:00.000000Z",
            "state": "DONE",
            "progressPercentage": 100
        }
    }
}
```

#### Human Readable Output

>### Retrohunt Details
>
>|Retrohunt ID|Rule ID|Version ID|Event Start Time|Event End Time|Retrohunt Start Time|Retrohunt End Time|State|Progress Percentage|
>|---|---|---|---|---|---|---|---|---|
>| oh_dummy_retrohunt_id | ru_dummy_rule_id | ru_dummy_rule_id@v_dummy_revision_id | 2025-07-01T10:00:00Z | 2025-07-08T10:00:00Z | 2025-07-08T12:00:00.000000Z | 2025-07-08T12:15:00.000000Z | DONE | 100 |

### 16. gcb-list-retrohunts

***
List retrohunts for a rule.

#### Base Command

`gcb-list-retrohunts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Rule ID or Version ID of the rule whose retrohunts are to be listed. If not supplied, retohunts for all versions of all rules will be listed. | Optional |
| retrohunts_for_all_versions | Whether to retrieve retrohunts for all versions of a rule with a given rule identifier.<br/>Note: If this option is set to true, rule id is required. Possible values are: True, False. Default is False. | Optional |
| state | Filter retrohunts based on their status. Possible values are: RUNNING, DONE, CANCELLED. | Optional |
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

#### Command example

```!gcb-list-retrohunts id=ru_dummy_rule_id retrohunts_for_all_versions=true```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": [
            {
                "retrohuntId": "oh_dummy_retrohunt_id",
                "ruleId": "ru_dummy_rule_id",
                "versionId": "ru_dummy_rule_id@v_dummy_revision_id",
                "eventStartTime": "2025-07-01T10:00:00Z",
                "eventEndTime": "2025-07-08T10:00:00Z",
                "retrohuntStartTime": "2025-07-08T12:00:00.000000Z",
                "retrohuntEndTime": "2025-07-08T12:15:00.000000Z",
                "state": "DONE",
                "progressPercentage": 100
            }
        ]
    }
}
```

#### Human Readable Output

>### Retrohunt Details
>
>|Retrohunt ID|Rule ID|Version ID|Event Start Time|Event End Time|Retrohunt Start Time|Retrohunt End Time|State|Progress Percentage|
>|---|---|---|---|---|---|---|---|---|
>| oh_dummy_retrohunt_id | ru_dummy_rule_id | ru_dummy_rule_id@v_dummy_revision_id | 2025-07-01T10:00:00Z | 2025-07-08T10:00:00Z | 2025-07-08T12:00:00.000000Z | 2025-07-08T12:15:00.000000Z | DONE | 100 |
>
>Maximum number of retrohunts specified in page_size has been returned. To fetch the next set of retrohunts, execute the command with the page token as `dummy_page_token`

### 17. gcb-cancel-retrohunt

***
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

```!gcb-cancel-retrohunt id=dummy_rule_or_version_id retrohunt_id=dummy_retrohunt_id```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RetroHunt": {
            "cancelled": true,
            "id": "dummy_rule_or_version_id",
            "retrohuntId": "dummy_retrohunt_id"
        }
    }
}
```

#### Human Readable Output

>### Cancelled Retrohunt
>
>Retrohunt for the rule with ID dummy_rule_or_version_id has been successfully cancelled.
>
>|ID|Retrohunt ID|Action Status|
>|---|---|---|
>| dummy_rule_or_version_id | dummy_retrohunt_id | SUCCESS |

### 18. gcb-list-reference-list

***
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
                "contentType": "PLAIN_TEXT",
                "createTime": "2025-08-08T06:41:45.744591Z",
                "description": "monitoring domain",
                "lines": [
                    "lines2"
                ],
                "name": "reference_list_1"
            },
            {
                "contentType": "CIDR",
                "createTime": "2025-07-22T07:22:19.247551Z",
                "description": "Description",
                "lines": [
                    "0.0.0.1/24"
                ],
                "name": "reference_list_2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Reference List Details
>
>|Name|Content Type|Creation Time|Description|Content|
>|---|---|---|---|---|
>| reference_list_1 | PLAIN_TEXT | 2025-07-14T07:50:45.350943Z | monitoring domain | lines2 |
>| reference_list_2 | CIDR | 2025-07-22T07:22:19.247551Z | Description | 0.0.0.1/24 |

Maximum number of reference lists specified in page_size has been returned. To fetch the next set of lists, execute the command with the page token as `dummy_token`

### 19. gcb-get-reference-list

***
Returns the specified list.

#### Base Command

`gcb-get-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the list to retrieve the result. | Required |
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
                "line_item_2"
            ],
            "name": "test1"
        }
    }
}
```

#### Human Readable Output

>### Reference List Details
>
>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| test1 | PLAIN_TEXT | update | 2022-06-10T08:59:34.885679Z | line_item_1,<br/>line_item_2 |

### 20. gcb-create-reference-list

***
Create a new reference list.

#### Base Command

`gcb-create-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide a unique name of the list to create a reference list. | Required |
| description | Description of the list. | Required |
| lines | Enter the content to be added into the reference list.<br/>Format accepted is: "Line 1, Line 2, Line 3". | Optional |
| entry_id | Provide a unique file id consisting of lines to add.<br/><br/>Note: Please provide either one of "lines" or "entry_id". You can get the entry_id from the context path(File.EntryID). | Optional |
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is " , ". | Optional |
| content_type | Select the content type for reference list. Possible values are: PLAIN_TEXT, CIDR, REGEX. Default is PLAIN_TEXT. | Optional |
| use_delimiter_for_file | Flag to control how the file content is split. If set to True, it uses the provided delimiter; otherwise it splits by new lines (\n). Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | Unique name of the list. |
| GoogleChronicleBackstory.ReferenceList.description | String | Description of the list. |
| GoogleChronicleBackstory.ReferenceList.lines | String | List of line items. |
| GoogleChronicleBackstory.ReferenceList.createTime | Date | Time when the list was created. |
| GoogleChronicleBackstory.ReferenceList.contentType | String | Content type of the reference list. |

#### Command Example

```!gcb-create-reference-list description="List created for readme" lines=L1,L2,L3 name=reference_list_name```

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
            "name": "reference_list_name"
        }
    }
}
```

#### Human Readable Output

>### Reference List Details
>
>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| reference_list_name | PLAIN_TEXT |List created for readme | 2022-06-16T07:45:37.285791Z | L1,<br/>L2,<br/>L3 |

### 21. gcb-update-reference-list

***
Updates an existing reference list.

#### Base Command

`gcb-update-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the list to update. | Required |
| lines | Enter the content to be updated into the reference list.<br/>Format accepted is: "Line 1, Line 2, Line 3".<br/><br/>Note: Use gcb-get-reference-list to retrieve the content and description of the list. | Optional |
| entry_id | Provide a unique file id consisting of lines to update.<br/><br/>Note: Please provide either one of "lines" or "entry_id". You can get the entry_id from the context path(File.EntryID). | Optional |
| description | Description to be updated of the list. | Optional |
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is " , ". | Optional |
| content_type | Select the content type for reference list. Possible values are: PLAIN_TEXT, CIDR, REGEX. | Optional |
| use_delimiter_for_file | Flag to control how the file content is split. If set to True, it uses the provided delimiter; otherwise it splits by new lines (\n). Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | Unique name of the list. |
| GoogleChronicleBackstory.ReferenceList.description | String | Description of the list. |
| GoogleChronicleBackstory.ReferenceList.lines | String | List of line items. |
| GoogleChronicleBackstory.ReferenceList.createTime | Date | Time when the list was created. |
| GoogleChronicleBackstory.ReferenceList.contentType | String | Content type of the reference list. |

#### Command Example

```!gcb-update-reference-list lines=Line1,Line2,Line3 name=reference_list_name```

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
            "name": "reference_list_name"
        }
    }
}
```

#### Human Readable Output

>### Updated Reference List Details
>
>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| reference_list_name | PLAIN_TEXT | list created for readme | 2022-06-16T07:11:11.380991Z | Line1,<br/>Line2,<br/>Line3 |

### 22. gcb-verify-reference-list

***
Validates list content and returns any errors found for each line.

#### Base Command

`gcb-verify-reference-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lines | Enter the content to be validated in the reference list.<br/>Format accepted is: 'Line 1, Line 2, Line 3'. | Required |
| content_type | Select the content type for reference list. Possible values are: PLAIN_TEXT, CIDR, REGEX. Default is PLAIN_TEXT. | Optional |
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is " , ". | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.VerifyReferenceList.success | Boolean | Whether lines content are valid or not. |
| GoogleChronicleBackstory.VerifyReferenceList.errors.linenumber | Number | The line number where the error occurred. |
| GoogleChronicleBackstory.VerifyReferenceList.errors.errorMessage | String | The error message describing the invalid pattern. |
| GoogleChronicleBackstory.VerifyReferenceList.command_name | String | The name of the command. |

#### Command example

```!gcb-verify-reference-list lines="0.0.0.1" content_type="CIDR" delimiter=","```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "VerifyReferenceList": {
            "command_name": "gcb-verify-reference-list",
            "errors": [
                {
                    "errorMessage": "invalid cidr pattern 0.0.0.1",
                    "lineNumber": 1
                }
            ],
            "success": false
        }
    }
}
```

#### Human Readable Output

>### The following lines contain invalid CIDR pattern
>
>|Line Number|Message|
>|---|---|
>| 1 | invalid cidr pattern 0.0.0.1 |

### 23. gcb-test-rule-stream

***
Test a rule over a specified time range. Return any errors and any detections up to the specified maximum.

#### Base Command

`gcb-test-rule-stream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_text | Rule text in YARA-L 2.0 format for the rule to stream. | Required |
| start_time | Start time for the time range of the rule being tested. The format of Date should comply with RFC 3339 (e.g. 2022-10-02T15:00:00Z) or relative time. <br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2022-05-01T00:00:00Z, 2022-05-01, 2 days, 5 hours, 01 Mar 2022, 01 Feb 2022 04:45:33, 15 Jun.<br/><br/><br/>Note: The time window between start_time and end_time cannot be greater than 2 weeks. | Required |
| end_time | End time for the time range of the rule being tested. The format of Date should comply with RFC 3339 (e.g. 2022-10-02T15:00:00Z) or relative time. <br/><br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2022-05-01T00:00:00Z, 2022-05-01, 2 days, 5 hours, 01 Mar 2022, 01 Feb 2022 04:45:33, 15 Jun.<br/><br/>Note: The time window between start_time and end_time cannot be greater than 2 weeks. | Required |
| max_results | Maximum number of results to return. Specify a value between 1 and 10,000. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.StreamRules.list.detection.type | String | Type of detection. |
| GoogleChronicleBackstory.StreamRules.list.detection.detection.ruleName | String | Name of the rule generating the detection, as parsed from ruleText. |
| GoogleChronicleBackstory.StreamRules.list.detection.detection.ruleType | String | Whether the rule generating this detection is a single event or multi-event rule. |
| GoogleChronicleBackstory.StreamRules.list.detection.detection.ruleLabels | Unknown | Information about the rule. |
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
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.attribute.labels | Unknown | Stores users session metrics. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.firstName | String | Stores the first name for the user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.lastName | String | Stores the last name for the user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.phoneNumbers | Unknown | Stores the phone numbers for the user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.personalAddress.city | String | Stores city of user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.personalAddress.state | String | Stores state of user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.personalAddress.name | String | Stores address name of user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.title | String | Stores the job title for the user. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.companyName | String | Stores users company name. |
| GoogleChronicleBackstory.StreamRules.list.detection.collectionElements.references.event.principal.user.department | Unknown | Stores users departments. |
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

```!gcb-test-rule-stream rule_text="rule singleEventRule2 { meta: author = \"securityuser\" description = \"single event rule that should generate detections\" events: $e.metadata.event_type = \"NETWORK_DNS\" condition: $e }" start_time="3 days" end_time="1 hour" max_results="2"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "StreamRules": {
            "list": [
                {
                    "detection": {
                        "type": "RULE_DETECTION",
                        "detection": [
                            {
                                "ruleName": "singleEventRule1",
                                "description": "single event rule that should generate detections",
                                "ruleType": "SINGLE_EVENT",
                                "ruleLabels": [
                                    {
                                        "key": "author",
                                        "value": "securityuser"
                                    },
                                    {
                                        "key": "description",
                                        "value": "single event rule that should generate detections"
                                    }
                                ]
                            }
                        ],
                        "id": "de_dummy_detection_id_1",
                        "timeWindow": {
                            "startTime": "2025-07-28T19:31:37Z",
                            "endTime": "2025-07-28T19:31:37Z"
                        },
                        "collectionElements": [
                            {
                                "references": [
                                    {
                                        "event": {
                                            "metadata": {
                                                "eventTimestamp": "2025-07-28T19:31:37Z",
                                                "eventType": "dummy_event_type",
                                                "vendorName": "dummy_vendor_name",
                                                "productName": "dummy_product_name",
                                                "ingestedTimestamp": "2025-07-28T08:05:40.391043Z",
                                                "id": "dummy_event_id",
                                                "logType": "WINDOWS_DNS",
                                                "baseLabels": {
                                                    "logTypes": [
                                                        "WINDOWS_DNS"
                                                    ],
                                                    "allowScopedAccess": true
                                                },
                                                "enrichmentLabels": {
                                                    "allowScopedAccess": true
                                                }
                                            },
                                            "additional": {
                                                "Internal Packet Identifier": "0000000000000001",
                                                "dns_record_type": "A"
                                            },
                                            "principal": {
                                                "ip": [
                                                    "0.0.0.1"
                                                ],
                                                "location": {
                                                    "state": "state",
                                                    "countryOrRegion": "country",
                                                    "regionLatitude": 0,
                                                    "regionLongitude": 0,
                                                    "regionCoordinates": {
                                                        "latitude": 0,
                                                        "longitude": 0
                                                    }
                                                },
                                                "asset": {
                                                    "ip": [
                                                        "0.0.0.1"
                                                    ]
                                                },
                                                "ipGeoArtifact": [
                                                    {
                                                        "ip": "0.0.0.1",
                                                        "location": {
                                                            "state": "state",
                                                            "countryOrRegion": "country",
                                                            "regionLatitude": 0,
                                                            "regionLongitude": 0,
                                                            "regionCoordinates": {
                                                                "latitude": 0,
                                                                "longitude": 0
                                                            }
                                                        },
                                                        "network": {
                                                            "carrierName": "carrier",
                                                            "organizationName": "organization"
                                                        }
                                                    }
                                                ]
                                            },
                                            "target": {
                                                "hostname": "test.com",
                                                "asset": {
                                                    "hostname": "test.com"
                                                }
                                            },
                                            "intermediary": [
                                                {
                                                    "hostname": "AAAA-AA-AA01",
                                                    "asset": {
                                                        "platformSoftware": {
                                                            "platform": "WINDOWS"
                                                        }
                                                    }
                                                }
                                            ],
                                            "about": [
                                                {
                                                    "labels": [
                                                        {
                                                            "key": "Internal Packet Identifier",
                                                            "value": "0000000000000001"
                                                        }
                                                    ]
                                                }
                                            ],
                                            "network": {
                                                "ipProtocol": "UDP",
                                                "applicationProtocol": "DNS",
                                                "dns": {
                                                    "questions": [
                                                        {
                                                            "name": "test.com",
                                                            "type": 1
                                                        }
                                                    ],
                                                    "id": 64395,
                                                    "recursionDesired": true
                                                },
                                                "direction": "OUTBOUND"
                                            },
                                            "extracted": {
                                                "resource_attributes.host.name": "AAAA-AA-AA01",
                                                "resource_attributes.os.type": "windows",
                                                "attributes.log.file.name": "test.txt",
                                                "attributes.log_type": "WINDOWS_DNS",
                                                "body": "7/28/2025 7:31:37 PM PACKET"
                                            }
                                        }
                                    }
                                ],
                                "label": "e"
                            }
                        ],
                        "detectionTime": "2025-07-28T19:31:37Z"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Detection(s)
>
>|Detection ID|Detection Type|Detection Time|Events|
>|---|---|---|---|
>| de_dummy_detection_id_1 | RULE_DETECTION | 2025-07-28T19:31:37Z | **Event Timestamp:** 2025-07-28T19:31:37Z<br>**Event Type:** dummy_event_type<br>**Principal Asset Identifier:** 0.0.0.1<br>**Target Asset Identifier:** test.com |

### 24. gcb-list-curatedrules

***
List curated rules.

#### Base Command

`gcb-list-curatedrules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_token | Page token received from a previous call. Use to retrieve the next page. | Optional |
| page_size | Specify the maximum number of rules to return. You can specify between 1 and 1000. Default is 100. | Optional |

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
| GoogleChronicleBackstory.Token.nextPageToken | String | A page token that can be provided to the next call to view the next page of rules. Absent if this is the last page. |

#### Command example

```!gcb-list-curatedrules page_size=1```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "CuratedRules": {
            "description": "Detects mass deletion of firewall rules by non-service accounts.",
            "metadata": {
                "false_positives": "Deleting many firewall rules is not necessarily malicious, but could be used to disrupt operations."
            },
            "precision": "BROAD",
            "ruleId": "ur_dummy_curated_rule_id",
            "ruleName": "Test Rule 1",
            "ruleSet": "dummy_curated_rule_set_id",
            "ruleType": "SINGLE_EVENT",
            "severity": "High",
            "tactics": [
                "TA0040"
            ],
            "techniques": [
                "T1489"
            ],
            "updateTime": "2025-05-29T18:36:10.155175Z"
        },
        "Token": {
            "name": "gcb-list-curatedrules",
            "nextPageToken": "next_page_token"
        }
    }
}
```

#### Human Readable Output

>### Curated Rules
>
>|Rule ID|Rule Name|Severity|Rule Type|Rule Set|Description|
>|---|---|---|---|---|---|
>| ur_dummy_curated_rule_id | Test Rule 1 | High | SINGLE_EVENT | dummy_curated_rule_set_id | Detects mass deletion of firewall rules by non-service accounts. |
>
>Maximum number of curated rules specified in page_size has been returned. To fetch the next set of curated rules, execute the command with the page token as `next_page_token`.

### 25. gcb-list-curatedrule-detections

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
| start_time | Start time of the time range to return detections for, filtered by the detection field specified in the list_basis parameter. If not specified, the start time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-05-01T00:00:00Z, 2023-05-01, 2 days, 5 hours, 01 Mar 2021, 01 Feb 2023 04:45:33, 15 Jun. | Optional |
| end_time | End time of the time range to return detections for, filtered by the detection field specified by the list_basis parameter. If not specified, the end time is treated as open-ended.<br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-05-01T00:00:00Z, 2023-05-01, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2021 04:45:33, 15 Jun. | Optional |

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
| GoogleChronicleBackstory.CuratedRuleDetections.lastUpdatedTime | Date | The time period of when the detection was last updated. |
| GoogleChronicleBackstory.CuratedRuleDetections.riskScore | Number | Risk score of the detection. |
| GoogleChronicleBackstory.CuratedRuleDetections.severity | String | Severity of the detection \("INFORMATIONAL" or "LOW" or "HIGH"\). |
| GoogleChronicleBackstory.CuratedRuleDetections.summary | String | Summary for the generated detection. |
| GoogleChronicleBackstory.CuratedRuleDetections.ruleType | String | Whether the rule generating this detection is a single event or multi-event rule. |
| GoogleChronicleBackstory.CuratedRuleDetections.detectionFields.key | String | The key for a field specified in the rule, for MULTI_EVENT rules. |
| GoogleChronicleBackstory.CuratedRuleDetections.detectionFields.source | String | The source for a field specified in the rule, for MULTI_EVENT rules. |
| GoogleChronicleBackstory.CuratedRuleDetections.detectionFields.value | String | The value for a field specified in the rule, for MULTI_EVENT rules. |
| GoogleChronicleBackstory.CuratedRuleDetections.outcomes.key | String | The key for a field specified in the outcomes of the detection, for "MULTI_EVENT" rules. |
| GoogleChronicleBackstory.CuratedRuleDetections.outcomes.source | String | The source for a field specified in the outcomes of the detection, for "MULTI_EVENT" rules. |
| GoogleChronicleBackstory.CuratedRuleDetections.outcomes.value | String | The value for a field specified in the outcomes of the detection, for "MULTI_EVENT" rules. |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionCoordinates.latitude | Number | Latitude coordinates of the region for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionCoordinates.longitude | Number | Longitude coordinates of the region for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionLatitude | Number | Latitude of the region for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.regionLongitude | Number | Longitude of the region for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.location.state | String | Associated state of IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.asn | String | Associated ASN with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.carrierName | String | Associated carrier name with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.dnsDomain | String | Associated DNS domain with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipGeoArtifact.network.organizationName | String | Associated organization name with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.countryOrRegion | String | Associated country or region for the IP location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionCoordinates.latitude | Number | Latitude coordinates of the region for the IP location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionCoordinates.longitude | Number | Longitude coordinates of the region for IP location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionLatitude | Number | Latitude of the region for the IP location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.regionLongitude | Number | Longitude of the region for the IP location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.ipLocation.state | String | Associated state of the IP location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.labels.key | String | The key for a field specified in the principal labels of the event. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.labels.value | String | The value for a field specified in the principal labels of the event. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.countryOrRegion | String | Associated country or region for the principal location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionCoordinates.latitude | Number | Latitude coordinates of the region for the principal location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionCoordinates.longitude | Number | Longitude coordinates of the region for the principal location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionLatitude | Number | Latitude of the region for the principal location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.regionLongitude | Number | Longitude of the region for the principal location. |
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.location.state | String | Associated state of the principal location. |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.principal.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.intermediary.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.src.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.observer.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.about.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.network.dhcp.sname | String | Name of the server that the client has requested to boot from. |
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
| GoogleChronicleBackstory.CuratedRuleDetections.collectionElements.references.securityResult.categoryDetails | Unknown | Specify the security category details. |
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

```!gcb-list-curatedrule-detections id="ur_dummy_curatedrule_id" page_size="2"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "CuratedRuleDetections": [
            {
                "alertState": "ALERTING",
                "createdTime": "2023-06-14T18:38:30.569526Z",
                "description": "Identifies mass deletion of secrets in GCP Secret Manager.",
                "detectionFields": [
                    {
                        "key": "field1",
                        "value": "value1"
                    }
                ],
                "detectionTime": "2023-06-14T17:28:00Z",
                "id": "de_dummy_detection_id_1",
                "lastUpdatedTime": "2023-06-14T18:38:30.569526Z",
                "outcomes": [
                    {
                        "key": "risk_score",
                        "value": "35"
                    },
                    {
                        "key": "resource_name",
                        "value": "dummy_secret_1, dummy_secret_2"
                    },
                    {
                        "key": "ip",
                        "value": "0.0.0.0"
                    }
                ],
                "riskScore": 35,
                "ruleId": "ur_dummy_rule_id",
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
                "ruleName": "GCP Secret Manager Mass Deletion",
                "ruleSet": "dummy_ruleset_id",
                "ruleSetDisplayName": "Service Disruption",
                "ruleType": "MULTI_EVENT",
                "severity": "LOW",
                "summary": "Rule Detection",
                "timeWindowEndTime": "2023-06-14T17:28:00Z",
                "timeWindowStartTime": "2023-06-14T17:18:00Z",
                "type": "GCTI_FINDING",
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_dummy_detection_id_1"
            },
            {
                "alertState": "ALERTING",
                "createdTime": "2023-06-14T18:38:30.569526Z",
                "description": "Identifies mass deletion of secrets in GCP Secret Manager.",
                "detectionFields": [
                    {
                        "key": "field1",
                        "value": "value1"
                    },
                    {
                        "key": "field2",
                        "value": "value2"
                    }
                ],
                "detectionTime": "2023-06-14T17:28:00Z",
                "id": "de_dummy_detection_id_2",
                "lastUpdatedTime": "2023-06-14T18:38:30.569526Z",
                "outcomes": [
                    {
                        "key": "risk_score",
                        "value": "35"
                    },
                    {
                        "key": "resource_name",
                        "value": "dummy_secret_1, dummy_secret_2"
                    },
                    {
                        "key": "ip",
                        "value": "0.0.0.0"
                    }
                ],
                "riskScore": 35,
                "ruleId": "ur_dummy_rule_id",
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
                "ruleName": "GCP Secret Manager Mass Deletion",
                "ruleSet": "dummy_ruleset_id",
                "ruleSetDisplayName": "Service Disruption",
                "ruleType": "MULTI_EVENT",
                "severity": "LOW",
                "summary": "Rule Detection",
                "timeWindowEndTime": "2023-06-14T17:28:00Z",
                "timeWindowStartTime": "2023-06-14T17:18:00Z",
                "type": "GCTI_FINDING",
                "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_dummy_detection_id_2"
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

>### Curated Detection(s) Details For Rule: [GCP Secret Manager Mass Deletion](https://dummy-chronicle/ruleDetections?ruleId=ur_dummy_curatedrule_id)
>
>|Detection ID|Description|Detection Type|Detection Time|Alert State|Detection Severity|Detection Risk-Score|
>|---|---|---|---|---|---|---|
>| [de_dummy_detection_id_1](https://dummy-chronicle/alert?alertId=de_dummy_detection_id_1) | Identifies mass deletion of secrets in GCP Secret Manager. | GCTI_FINDING | 2023-06-14T17:28:00Z | ALERTING | LOW | 35 |
>| [de_dummy_detection_id_2](https://dummy-chronicle/alert?alertId=de_dummy_detection_id_2) | Identifies mass deletion of secrets in GCP Secret Manager. | GCTI_FINDING | 2023-06-14T17:28:00Z | ALERTING | LOW | 35 |
>
>View all Curated Detections for this rule in Google SecOps by clicking on GCP Secret Manager Mass Deletion and to view individual detection in Google SecOps click on its respective Detection ID.
>Maximum number of detections specified in page_size has been returned. To fetch the next set of detections, execute the command with the page token as `next_page_token`.

### 26. gcb-udm-search

***
Lists the events for the specified UDM Search query.
Note: The underlying API has the rate limit of 360 queries per hour.

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
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionCoordinates.latitude | Number | Latitude coordinates of the region for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionCoordinates.longitude | Number | Longitude coordinates of the region for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionLatitude | Number | Latitude of the region for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.regionLongitude | Number | Longitude of the region for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.location.state | String | Associated state of IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.asn | String | Associated ASN with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.carrierName | String | Associated carrier name with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.dnsDomain | String | Associated DNS domain with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipGeoArtifact.network.organizationName | String | Associated organization name with a network connection for IP Geolocation. |
| GoogleChronicleBackstory.Events.principal.ipLocation.countryOrRegion | String | Associated country or region for the IP location. |
| GoogleChronicleBackstory.Events.principal.ipLocation.regionCoordinates.latitude | Number | Latitude coordinates of the region for the IP location. |
| GoogleChronicleBackstory.Events.principal.ipLocation.regionCoordinates.longitude | Number | Longitude coordinates of the region for the IP location. |
| GoogleChronicleBackstory.Events.principal.ipLocation.regionLatitude | Number | Latitude of the region for the IP location. |
| GoogleChronicleBackstory.Events.principal.ipLocation.regionLongitude | Number | Longitude of the region for the IP location. |
| GoogleChronicleBackstory.Events.principal.ipLocation.state | String | Associated state of the IP location. |
| GoogleChronicleBackstory.Events.principal.labels.key | String | The key for a field specified in the principal labels of the event. |
| GoogleChronicleBackstory.Events.principal.labels.value | String | The value for a field specified in the principal labels of the event. |
| GoogleChronicleBackstory.Events.principal.location.countryOrRegion | String | Associated country or region for the principal location. |
| GoogleChronicleBackstory.Events.principal.location.regionCoordinates.latitude | Number | Latitude coordinates of the region for the principal location. |
| GoogleChronicleBackstory.Events.principal.location.regionCoordinates.longitude | Number | Longitude coordinates of the region for the principal location. |
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
| GoogleChronicleBackstory.Events.principal.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.Events.target.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.Events.intermediary.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.Events.src.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.Events.observer.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.Events.about.administrativeDomain | String | Domain that the device belongs to \(for example, the Windows domain\). |
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
| GoogleChronicleBackstory.Events.network.dhcp.sname | String | Name of the server that  the client has requested to boot from. |
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
| GoogleChronicleBackstory.Events.securityResult.categoryDetails | Unknown | Specify the security category details. |
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
                    "eventTimestamp": "2025-07-14T00:59:52.110Z",
                    "eventType": "REGISTRY_MODIFICATION",
                    "vendorName": "Microsoft",
                    "productName": "Microsoft-Windows-Sysmon",
                    "productEventType": "13",
                    "ingestedTimestamp": "2025-07-14T13:14:24.377988Z",
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
                            "creationTime": "2025-07-14T00:00:10Z",
                            "lastUpdateTime": "2025-07-14T00:00:10Z"
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
                        "eventTimestamp": "2025-07-14T00:56:57.372Z",
                        "eventType": "NETWORK_DNS",
                        "vendorName": "Microsoft",
                        "productName": "Microsoft",
                        "productEventType": "22",
                        "ingestedTimestamp": "2025-07-14T10:07:42.183563Z",
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
>
>|Event ID|Event Timestamp|Event Type|Security Results|Principal Asset Identifier|Target Asset Identifier|Product Name|Vendor Name|Queried Domain|
>|---|---|---|---|---|---|---|---|---|
>| 010000= | 2025-07-14T00:59:52.110Z | REGISTRY_MODIFICATION | **Severity:** INFORMATIONAL<br>**Summary:** Registry value set<br>**Rule Name:** technique_id=T0000,technique_name=Service Creation<br><br>**Actions:** ALLOW<br>**Rule Name:** EventID: 10 | active.stack.local | 0.0.0.1 | Microsoft-Windows-Sysmon | Microsoft |  |
>| 0000000020000= | 2025-07-14T00:56:57.372Z | NETWORK_DNS | **Severity:** INFORMATIONAL<br>**Summary:** Dns query<br><br>**Summary:** QueryStatus: 0<br>**Rule Name:** EventID: 22 | DESKTOP | 0.0.0.1 | Microsoft | Microsoft | logging.googleapis.com<br> |
>
>Maximum number of events specified in limit has been returned. There might still be more events in your Google SecOps account. To fetch the next set of events, execute the command with the start time as 2025-07-14T00:59:52.110Z.

### 27. gcb-verify-value-in-reference-list

***
Check if provided values are found in the reference lists in Google SecOps.

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

>### Successfully searched provided values in the reference lists in Google SecOps
>
>|Value|Found In Lists|Not Found In Lists|Overall Status|
>|---|---|---|---|
>| value1 | list1 | list2 | Found |
>| value2 | list1 | list2 | Found |
>| value4 |  | list1, list2 | Not Found |

### 28. gcb-verify-rule

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

### 29. gcb-get-event

***
Get the specific event with the given ID from Google SecOps.

Note: This command returns more than 60 different types of events. Any event would have only specific output context set. Refer the UDM documentation to figure out the output properties specific to the event types.

#### Base Command

`gcb-get-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Specify the ID of the event.<br/><br/>Note: The event_id can be retrieved from the output context path (GoogleChronicleBackstory.Events.id) of the gcb-list-events command. | Required |

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

#### Command example

```!gcb-get-event event_id="dummy_id"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Events": {
            "additional": {
                "app_micro_tenant_id": "0",
                "client_to_client": "0",
                "client_zen": "EU-DE-9490",
                "connection_id": "dummy_connection_id",
                "connector": "0",
                "connector_zen": "0",
                "customer": "New Demo Center",
                "double_encryption": "Off",
                "idp": "0",
                "micro_tenant_id": "0",
                "policy_processing_time": "0",
                "pra_approval_id": "0",
                "pra_capability_policy_id": "0",
                "pra_credential_policy_id": "0",
                "server_setup_time": "0",
                "timestamp_connection_end": "2024-11-12T12:19:59.961Z"
            },
            "baseLabels": {
                "allowScopedAccess": true,
                "logTypes": [
                    "NEW_XYZ"
                ]
            },
            "description": "0",
            "eventTimestamp": "2024-11-12T12:19:59Z",
            "eventType": "GENERIC_EVENT",
            "id": "dummy_id",
            "ingestedTimestamp": "2024-11-12T12:20:03.217859Z",
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
            "logType": "NEW_XYZ",
            "network": {
                "ipProtocol": "TCP",
                "sessionId": "dummy"
            },
            "principal": {
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
                ],
                "port": 11522,
                "user": {
                    "userDisplayName": "New LSS Client"
                }
            },
            "productEventType": "APP_NOT_REACHABLE",
            "productName": "Private Access",
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
                    "description": "None of the App Connectors configured.",
                    "detectionFields": [
                        {
                            "key": "server",
                            "value": "0"
                        }
                    ],
                    "ruleName": "0"
                }
            ],
            "target": {
                "application": "New Enterprise Server - User Status",
                "hostname": "0.0.0.0",
                "port": 11522,
                "user": {
                    "groupIdentifiers": [
                        "New Enterprise Server - User Status"
                    ]
                }
            },
            "vendorName": "NewClient"
        }
    }
}
```

#### Human Readable Output

>### General Information for the given event with ID: dummy_id
>
>|Base Labels|Description|Event Timestamp|Event Type|Id|Ingested Timestamp|Log Type|Product Event Type|Product Name|Vendor Name|
>|---|---|---|---|---|---|---|---|---|---|
>| **logTypes**:<br> ***values***: NEW_XYZ<br>***allowScopedAccess***: True | 0 | 2024-11-12T12:19:59Z | GENERIC_EVENT | dummy_id | 2024-11-12T12:20:03.217859Z | NEW_XYZ | APP_NOT_REACHABLE | Private Access | NewClient |
>
>### Principal Information
>
>|Location|Nat Ip|Port|User|
>|---|---|---|---|
>| ***city***: New City<br>***countryOrRegion***: US<br>**regionCoordinates**:<br> ***latitude***: 0.0<br> ***longitude***: 0.0 | ***values***: 0.0.0.0 | 11522 | ***userDisplayName***: New LSS Client |
>
>### Target Information
>
>|Application|Hostname|Port|User|
>|---|---|---|---|
>| New Enterprise Server - User Status | 0.0.0.0 | 11522 | **groupIdentifiers**:<br> ***values***: New Enterprise Server - User Status |
>
>### Security Result Information
>
>|About|Description|Detection Fields|Rule Name|
>|---|---|---|---|
>| **labels**:<br> **-** ***key***: connection_status<br>  ***value***: close | None of the App Connectors configured. | **-** ***key***: server<br> ***value***: 0 | 0 |
>
>### Network Information
>
>|Ip Protocol|Session Id|
>|---|---|
>| TCP | dummy |

### 30. gcb-reference-list-append-content

***
Appends lines into an existing reference list.

#### Base Command

`gcb-reference-list-append-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the list to append content. | Required |
| lines | Enter the content to be appended into the reference list.<br/>Format accepted is: "Line 1, Line 2, Line 3".<br/><br/>Note: Use "gcb-get-reference-list" to retrieve the content of the list. | Optional |
| entry_id | Provide a unique file id consisting of lines to append.<br/><br/>Note: Please provide either one of "lines" or "entry_id". You can get the entry_id from the context path(File.EntryID). | Optional |
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is " , ". | Optional |
| use_delimiter_for_file | Flag to control how the file content is split. If set to True, it uses the provided delimiter; otherwise it splits by new lines (\n). Possible values are: True, False. Default is False. | Optional |
| append_unique | A flag to determine whether to apply deduplication logic over new lines. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | The unique name of the list. |
| GoogleChronicleBackstory.ReferenceList.description | String | The description of the list. |
| GoogleChronicleBackstory.ReferenceList.lines | String | The list of line items. |
| GoogleChronicleBackstory.ReferenceList.createTime | Date | The time when the list was created. |
| GoogleChronicleBackstory.ReferenceList.contentType | String | The content type of the reference list. |

#### Command Example

```!gcb-reference-list-append-content name="readme_list_name" lines="Line3"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "ReferenceList": {
            "createTime": "2025-06-16T07:11:11.380991Z",
            "description": "list created for readme",
            "contentType": "PLAIN_TEXT",
            "lines": [
                "Line1",
                "Line2",
                "Line3"
            ],
            "name": "readme_list_name"
        }
    }
}
```

#### Human Readable Output

>### Updated Reference List Details
>
>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| readme_list_name | PLAIN_TEXT | list created for readme | 2025-06-16T07:11:11.380991Z | Line1,<br/>Line2,<br/>Line3 |

### 31. gcb-reference-list-remove-content

***
Removes lines from an existing reference list.

#### Base Command

`gcb-reference-list-remove-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the list to remove content. | Required |
| lines | Enter the content to be removed from the reference list.<br/>Format accepted is: "Line 1, Line 2, Line 3".<br/><br/>Note: Use "gcb-get-reference-list" to retrieve the content of the list. | Optional |
| entry_id | Provide a unique file id consisting of lines to remove.<br/><br/>Note: Please provide either one of "lines" or "entry_id". You can get the entry_id from the context path(File.EntryID). | Optional |
| delimiter | Delimiter by which the content of the list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is " , ". | Optional |
| use_delimiter_for_file | Flag to control how the file content is split. If set to True, it uses the provided delimiter; otherwise it splits by new lines (\n). Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.ReferenceList.name | String | The unique name of the list. |
| GoogleChronicleBackstory.ReferenceList.description | String | The description of the list. |
| GoogleChronicleBackstory.ReferenceList.lines | String | The list of line items. |
| GoogleChronicleBackstory.ReferenceList.createTime | Date | The time when the list was created. |
| GoogleChronicleBackstory.ReferenceList.contentType | String | The content type of the reference list. |

#### Command Example

```!gcb-reference-list-remove-content name="reference_list_name" lines="Line3"```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "ReferenceList": {
            "createTime": "2025-06-16T07:11:11.380991Z",
            "description": "list created for readme",
            "contentType": "PLAIN_TEXT",
            "lines": [
                "Line1",
                "Line2",
            ],
            "name": "reference_list_name"
        }
    }
}
```

#### Human Readable Output

>### Updated Reference List Details
>
>|Name|Content Type|Description|Creation Time|Content|
>|---|---|---|---|---|
>| reference_list_name | PLAIN_TEXT | list created for readme | 2025-06-16T07:11:11.380991Z | Line1,<br/>Line2 |

### 32. gcb-list-data-tables

***
Returns a list of data tables.

#### Base Command

`gcb-list-data-tables`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Specify the maximum number of data tables to return. You can specify between 1 and 1000. The maximum value is 1000, values above 1000 will be corrected to 1000. Default is 100. | Optional |
| page_token | Specify the page token to use for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.DataTable.name | String | The identifier of the data table. |
| GoogleChronicleBackstory.DataTable.displayName | String | The name of the data table. |
| GoogleChronicleBackstory.DataTable.description | String | The description of the data table. |
| GoogleChronicleBackstory.DataTable.createTime | Date | The time when the data table was created. |
| GoogleChronicleBackstory.DataTable.updateTime | Date | The time when the data table was updated. |
| GoogleChronicleBackstory.DataTable.columnInfo.originalColumn | String | The original column name. |
| GoogleChronicleBackstory.DataTable.columnInfo.columnType | String | The type of the column. |
| GoogleChronicleBackstory.DataTable.columnInfo.columnIndex | Number | The index of the column. |
| GoogleChronicleBackstory.DataTable.dataTableUuid | String | The UUID of the data table. |
| GoogleChronicleBackstory.DataTable.approximateRowCount | Number | The approximate count of rows of the data table. |

#### Command example

```!gcb-list-data-tables```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "DataTable": [
            {
                "columnInfo": [
                    {
                        "columnType": "REGEX",
                        "originalColumn": "column_1"
                    },
                    {
                        "columnIndex": 1,
                        "columnType": "STRING",
                        "originalColumn": "column_2"
                    }
                ],
                "createTime": "2025-08-18T05:45:04.624866Z",
                "dataTableUuid": "00000000000000000000000000000001",
                "description": "test description",
                "displayName": "test_1",
                "name": "projects/sample-001/locations/us/instances/00000000-0000-0000-0000-000000000001/dataTables/test_1",
                "updateTime": "2025-08-18T05:45:04.624866Z"
            },
            {
                "approximateRowCount": "1055",
                "columnInfo": [
                    {
                        "columnType": "STRING",
                        "originalColumn": "A"
                    },
                    {
                        "columnIndex": 1,
                        "columnType": "REGEX",
                        "originalColumn": "B"
                    }
                ],
                "createTime": "2025-08-13T05:01:47.031912Z",
                "dataTableUuid": "00000000000000000000000000000000",
                "description": "test description",
                "displayName": "test",
                "name": "projects/sample-001/locations/us/instances/00000000-0000-0000-0000-000000000001/dataTables/test",
                "updateTime": "2025-08-22T08:03:03.395766Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Data Tables
>
>|Display Name|Description|Column Info|Create Time|Update Time|Approximate Row Count|
>|---|---|---|---|---|---|
>| test_1 | test description | **-** ***Column Name***: column_1<br> ***Column Type***: REGEX<br>**-** ***Column Name***: column_2<br> ***Column Type***: STRING | 2025-08-18T05:45:04.624866Z | 2025-08-18T05:45:04.624866Z |  |
>| test | test description | **-** ***Column Name***: A<br> ***Column Type***: STRING<br>**-** ***Column Name***: B<br> ***Column Type***: REGEX | 2025-08-13T05:01:47.031912Z | 2025-08-22T08:03:03.395766Z | 1055 |
>
>Maximum number of data tables specified in page_size has been returned. To fetch the next set of data tables, execute the command with the page token as `dummy_page_token`.

### 33. gcb-create-data-table

***
Creates a new data table schema.

#### Base Command

`gcb-create-data-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide a unique name for the data table. | Required |
| description | Provide a description for the data table. | Optional |
| columns | Provide the columns of the data table.<br/>Format accepted is:<br/>{"column_name_1": "column_1_type", "column_name_2": "column_2_type"}.<br/><br/>Expected values for column_type are: String, REGEX, CIDR, Number and Entity key field map path.<br/><br/>Note: If the same column name is provided multiple times, only the last value will be considered. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.DataTable.name | String | The identifier of the data table. |
| GoogleChronicleBackstory.DataTable.displayName | String | The name of the data table. |
| GoogleChronicleBackstory.DataTable.description | String | The description of the data table. |
| GoogleChronicleBackstory.DataTable.createTime | Date | The time when the data table was created. |
| GoogleChronicleBackstory.DataTable.updateTime | Date | The time when the data table was updated. |
| GoogleChronicleBackstory.DataTable.columnInfo.originalColumn | String | The original column name. |
| GoogleChronicleBackstory.DataTable.columnInfo.columnType | String | The type of the column. |
| GoogleChronicleBackstory.DataTable.columnInfo.columnIndex | Number | The index of the column. |
| GoogleChronicleBackstory.DataTable.dataTableUuid | String | The UUID of the data table. |

#### Command Example

```!gcb-create-data-table name=data_table_name description=data_table_description columns={"column_1":"regex", "column_2":"String","column_3":"CIDR"}```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "DataTable": {
            "columnInfo": [
                {
                    "columnType": "REGEX",
                    "originalColumn": "column_1"
                },
                {
                    "columnIndex": 1,
                    "columnType": "STRING",
                    "originalColumn": "column_2"
                },
                {
                    "columnIndex": 2,
                    "columnType": "CIDR",
                    "originalColumn": "column_3"
                }
            ],
            "createTime": "2025-08-18T09:54:50.841579275Z",
            "dataTableUuid": "00000000000000000000000000000001",
            "description": "data_table_description",
            "displayName": "data_table_name",
            "name": "projects/dummy_project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/data_table_name",
            "updateTime": "1970-01-01T00:00:00Z"
        }
    }
}
```

#### Human Readable Output

>### Data Table Details
>
>|Display Name|Description|Columns Info|Create Time|Update Time|
>|---|---|---|---|---|
>| data_table_name | data_table_description | **-** ***Column Name***: column_1<br/> ***Column Type***: REGEX<br/>**-** ***Column Name***: column_2<br/> ***Column Type***: STRING<br/>**-** ***Column Name***: column_3<br/> ***Column Type***: CIDR | 2025-08-18T09:54:50.841579275Z | 1970-01-01T00:00:00Z |

### 34. gcb-get-data-table

***
Retrieves the data table details of specified data table name.

#### Base Command

`gcb-get-data-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the data table. | Required |
| view | Select option to control the returned response. BASIC will return the metadata for the data table, but not the data table rows contents. FULL will return everything. Possible values are: FULL, BASIC. Default is BASIC. | Optional |
| max_rows_to_return | Specify how many data table rows to return.<br/><br/>Note: this parameter is only applied if “view” is FULL. The maximum value is 1000; values above 1000 will be coerced to 1000. Default is 100. | Optional |
| page_token | The page token to retrieve the next set of data table rows.<br/><br/>Note: this parameter is only applied if “view” is FULL. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.DataTable.name | String | The identifier of the data table. |
| GoogleChronicleBackstory.DataTable.displayName | String | The name of the data table. |
| GoogleChronicleBackstory.DataTable.description | String | The description of the data table. |
| GoogleChronicleBackstory.DataTable.createTime | Date | The time when the data table was created. |
| GoogleChronicleBackstory.DataTable.updateTime | Date | The time when the data table was updated. |
| GoogleChronicleBackstory.DataTable.columnInfo.originalColumn | String | The original column name. |
| GoogleChronicleBackstory.DataTable.columnInfo.columnType | String | The type of the column. |
| GoogleChronicleBackstory.DataTable.columnInfo.columnIndex | Number | The index of the column. |
| GoogleChronicleBackstory.DataTable.dataTableUuid | String | The UUID of the data table. |
| GoogleChronicleBackstory.DataTable.rows.name | String | The identifier of the row. |
| GoogleChronicleBackstory.DataTable.rows.values | String | The values of the row. |
| GoogleChronicleBackstory.DataTable.rows.createTime | Date | The time when the row was created. |
| GoogleChronicleBackstory.DataTable.rows.updateTime | Date | The time when the row was updated. |

#### Command Example

```!gcb-get-data-table name=data_table_name view=FULL max_rows_to_return=1```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "DataTable": {
            "approximateRowCount": "1",
            "columnInfo": [
                {
                    "columnType": "STRING",
                    "originalColumn": "column_1"
                },
                {
                    "columnIndex": 1,
                    "columnType": "STRING",
                    "originalColumn": "column_2"
                },
                {
                    "columnIndex": 2,
                    "columnType": "CIDR",
                    "originalColumn": "column_3"
                }
            ],
            "createTime": "2025-08-13T05:01:47.031912Z",
            "dataTableUuid": "665c88d4a5bc4a6faa006152e1adeccd",
            "description": "data_table_description",
            "displayName": "data_table_name",
            "name": "projects/project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/data_table_name",
            "rows": [
                {
                    "createTime": "2025-08-13T05:04:11.212111Z",
                    "name": "projects/project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/data_table_name/dataTableRows/data_table_row_id",
                    "updateTime": "2025-08-13T05:04:11.212111Z",
                    "values": {
                        "column_1": "value_1",
                        "column_2": "value_2",
                        "column_3": "0.0.0.1/24"
                    }
                }
            ],
            "updateTime": "2025-08-13T05:09:11.288412Z"
        }
    }
}
```

#### Human Readable Output

>### Data Table Details
>
>|Display Name|Description|Columns Info|Create Time|Update Time|Approximate Row Count|
>|---|---|---|---|---|---|
>| data_table_name | data_table_description | **-** ***Column Name***: column_1<br/> ***Column Type***: STRING<br/>**-** ***Column Name***: column_2<br/> ***Column Type***: STRING<br/>**-** ***Column Name***: column_3<br/> ***Column Type***: CIDR | 2025-08-13T05:01:47.031912Z | 2025-08-13T05:09:11.288412Z | 1 |
>
>### Data Table Rows Content
>
>|column_1|column_2|column_3|
>|---|---|---|
>| value_1 | value_2 | 0.0.0.1/24 |
>
>Maximum number of data table rows specified in max_rows_to_return has been returned. To fetch the next set of data table rows, execute the command with the page token as `dummy_page_token`.

### 35. gcb-verify-value-in-data-table

***
Check if provided values are found in the data table.

Note: This command only searches in the first 1000 data table rows. To search next set of rows, use the page_token argument.

#### Base Command

`gcb-verify-value-in-data-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values | Provide the values to search in the data table.<br/>Format accepted is: "value 1, value 2, value 3". | Required |
| name | Provide a data table name to search through. | Required |
| columns | Provide the columns that need to be searched within the data table.<br/>Format accepted is: "column 1, column 2, column 3".<br/><br/>Note: Use "gcb-get-data-table" to retrieve the column names of the data table. If nothing is provided, the command will search within all columns. | Optional |
| case_insensitive_search | If set to true, the command performs case insensitive matching. Possible values are: True, False. Default is False. | Optional |
| delimiter | Delimiter by which the content of the values list is separated.<br/>Eg:  " , " , " : ", " ; ". Default is ",". | Optional |
| add_not_found_columns | If set to true, the command will add the not found column names to the HR and the context. Possible values are: True, False. Default is False. | Optional |
| page_token | The page token to search the next set of data table rows. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.VerifyValueInDataTable.value | String | The value that was searched. |
| GoogleChronicleBackstory.VerifyValueInDataTable.found_in_columns | String | The columns in which the value was found. |
| GoogleChronicleBackstory.VerifyValueInDataTable.not_found_in_columns | String | The columns in which the value was not found. |
| GoogleChronicleBackstory.VerifyValueInDataTable.overall_status | String | The overall status of the search. |

#### Command example

```!gcb-verify-value-in-data-table column_names="column_name_1,column_name_2" data_table_name=data_table_name values="value1,value2,value3" case_insensitive_search=True add_not_found_columns=True```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "VerifyValueInDataTable": [
            {
                "case_insensitive": true,
                "found_in_columns": [
                    "column_name_1"
                ],
                "not_found_in_columns": [
                    "column_name_2"
                ],
                "overall_status": "Found",
                "value": "value1"
            },
            {
                "case_insensitive": true,
                "found_in_columns": [
                    "column_name_1",
                    "column_name_2"
                ],
                "overall_status": "Found",
                "value": "value2"
            },
            {
                "case_insensitive": true,
                "not_found_in_columns": [
                    "column_name_1",
                    "column_name_2"
                ],
                "overall_status": "Not Found",
                "value": "value3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Successfully searched provided values in the data_table_name data table
>
>|Value|Found In Columns|Not Found In Columns|Overall Status|
>|---|---|---|---|
>| value1 | column_name_1 | column_name_2 | Found |
>| value2 | column_name_1,column_name_2 |  | Found |
>| value3 |  | column_name_1,column_name_2 | Not Found |
>
>The command can search the up to 1000 rows in single execution. To search the next set of data table rows, execute the command with the page token as `dummy_page_token`.

### 36. gcb-data-table-add-row

***
Adds rows to a data table.

#### Base Command

`gcb-data-table-add-row`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the data table. | Required |
| rows | Provide the list of rows data that need to be added in the data table.<br/>Format accepted is: <br/>[{"columnName1": "value1","columnName2": "value2"},{"columnName1": "value3","columnName2": "value4"}]<br/><br/>Note: Use "gcb-get-data-table" to retrieve the column names of the data table. | Optional |
| entry_id | Provide a unique file id of comma separated CSV file consisting of rows to add.<br/><br/>Note: Please provide either one of "rows" or "entry_id". A maximum of 1000 rows can be added in a single execution. You can get the entry_id from the context path(File.EntryID). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.DataTableRows.name | String | The identifier of the data table row. |
| GoogleChronicleBackstory.DataTableRows.values | String | The values of the data table row. |

#### Command Example

```!gcb-data-table-add-row name=data_table_name rows=`[{"column1":"value1","column2":"value2"},{"column1":"value3","column2":"value4"}]````

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "DataTableRows": [
            {
                "name": "projects/dummy_project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/test_table/dataTableRows/row1",
                "values": {
                    "column1": "value1",
                    "column2": "value2"
                }
            },
            {
                "name": "projects/dummy_project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/test_table/dataTableRows/row2",
                "values": {
                    "column1": "value3",
                    "column2": "value4"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Successfully added rows to the data_table_name data table
>
>|column1|column2|
>|---|---|
>| value1 | value2 |
>| value3 | value4 |

### 37. gcb-data-table-remove-row

***
Removes rows from a data table based on specified row data.

Note: This command only removes the first 1000 data table rows. To remove the next set of rows, use the page_token argument.

#### Base Command

`gcb-data-table-remove-row`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Provide the name of the data table. | Required |
| rows | Provide the list of rows data that need to be removed from the data table.<br/>Format accepted is: <br/>[{"columnName1": "value1","columnName2": "value2"},{"columnName1": "value3","columnName2": "value4"}]<br/><br/>Example:<br/>If you provide [{"columnName1": "value1"}] then it will remove all the rows from the data table where column1 has value1.<br/>If you provide [{"columnName1": "value1", "columnName2": "value2"}] then it will remove all the rows from the data table where column1 has value1 and column2 has value2.<br/><br/>Note: Use "gcb-get-data-table" to retrieve the column names of the data table. | Optional |
| entry_id | Provide a unique file id of comma separated CSV file consisting of row data for removal.<br/><br/>Note: Please provide either one of "rows" or "entry_id". You can get the entry_id from the context path(File.EntryID). | Optional |
| page_token | The page token to search and remove the next set of data table rows. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChronicleBackstory.RemovedDataTableRows.name | String | The identifier of the row. |
| GoogleChronicleBackstory.RemovedDataTableRows.values | String | The values of the row. |
| GoogleChronicleBackstory.RemovedDataTableRows.createTime | Date | The time when the row was created. |
| GoogleChronicleBackstory.RemovedDataTableRows.updateTime | Date | The time when the row was updated. |

#### Command Example

```!gcb-data-table-remove-row name=data_table_name rows=`[{"column_1":"value1","column_2":"value2"},{"column_1":"value3","column_2":"value4"}]```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "RemovedDataTableRows": [
            {
                "createTime": "2025-08-22T07:29:18.504543Z",
                "name": "projects/project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/data_table_name/dataTableRows/data_table_row_id",
                "updateTime": "2025-08-22T07:29:18.504543Z",
                "values": {
                    "column_1": "value1",
                    "column_2": "value2"
                }
            },
            {
                "createTime": "2025-08-22T07:29:18.482255Z",
                "name": "projects/project_id/locations/dummy_location/instances/dummy_instance_id/dataTables/data_table_name/dataTableRows/data_table_row_id",
                "updateTime": "2025-08-22T07:29:18.482255Z",
                "values": {
                    "column_1": "value3",
                    "column_2": "value4"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Successfully removed rows from the data_table_name data table
>
>|column_1|column_2|
>|---|---|
>| value1 | value2 |
>| value3 | value4 |
>
>The command can search and remove the up to 1000 rows in single execution. To remove the next set of data table rows, execute the command with the page token as `dummy_page_token`.

### 38. gcb-get-detection

***
Retrieves the detection details of specified detection ID.

#### Base Command

`gcb-get-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Specify the ID or version ID of the rule. You can specify exactly one rule identifier. Use the following format to specify the ID: ru_{UUID} or {ruleId}@v_{int64}_{int64}.<br/><br/>Note: Use gcb-list-rules command to retrieve rule ID. | Required |
| detection_id | Specify the ID of the detection.<br/><br/>Note: Use gcb-list-detections command to retrieve detection ID. | Required |

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

#### Command example

```!gcb-get-detection rule_id=ru_dummy_rule_id detection_id=de_dummy_detection_id```

#### Context Example

```json
{
    "GoogleChronicleBackstory": {
        "Detections": {
            "alertState": "ALERTING",
            "collectionElements": [
                {
                    "label": "event",
                    "references": [
                        {
                            "eventTimestamp": "2025-08-21T02:58:06.804Z",
                            "eventType": "NETWORK_DNS",
                            "ingestedTimestamp": "2025-08-21T03:02:46.559472Z",
                            "network": {
                                "applicationProtocol": "DNS",
                                "dns": {
                                    "answers": [
                                        {
                                            "data": "4.3.2.1",
                                            "name": "test1.com",
                                            "ttl": 11111,
                                            "type": 1
                                        }
                                    ],
                                    "questions": [
                                        {
                                            "name": "test.com",
                                            "type": 1
                                        }
                                    ],
                                    "response": true
                                }
                            },
                            "principal": {
                                "hostname": "ray-xxx-laptop",
                                "ip": [
                                    "0.0.0.0"
                                ],
                                "mac": [
                                    "00:00:00:00:00:00"
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
                                    "0.0.0.1"
                                ]
                            },
                            "targetAssetIdentifier": "0.0.0.1"
                        }
                    ]
                }
            ],
            "createdTime": "2025-08-21T03:12:50.128428Z",
            "description": "description",
            "detectionFields": [
                {
                    "key": "client_ip",
                    "value": "0.0.0.0"
                }
            ],
            "detectionTime": "2025-08-21T03:54:00Z",
            "id": "de_dummy_detection_id",
            "riskScore": 40,
            "ruleId": "ru_dummy_rule_id",
            "ruleLabels": [
                {
                    "key": "author",
                    "value": "user1"
                },
                {
                    "key": "description",
                    "value": "description"
                },
                {
                    "key": "severity",
                    "value": "Medium"
                }
            ],
            "ruleName": "SampleRule",
            "ruleType": "MULTI_EVENT",
            "ruleVersion": "ru_dummy_rule_id@v_version_id",
            "timeWindowEndTime": "2025-08-21T03:54:00Z",
            "timeWindowStartTime": "2025-08-21T02:54:00Z",
            "type": "RULE_DETECTION",
            "urlBackToProduct": "https://dummy-chronicle/alert?alertId=de_dummy_detection_id"
        }
    }
}
```

#### Human Readable Output

>### Detection Details for de_dummy_detection_id
>
>|Detection ID|Detection Type|Rule Name|Rule ID|Rule Type|Severity|Risk Score|Alert State|Description|Events|Created Time|Detection Time|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| [de_dummy_detection_id](https://dummy-chronicle/alert?alertId=de_dummy_detection_id) | RULE_DETECTION | SampleRule | ru_dummy_rule_id | MULTI_EVENT | Medium | 40 | ALERTING | description | **Event Timestamp:** 2025-08-21T02:58:06.804Z<br>**Event Type:** NETWORK_DNS<br>**Principal Asset Identifier:** ray-xxx-laptop<br>**Target Asset Identifier:** 0.0.0.1<br>**Queried Domain:** test.com | 2025-08-21T03:12:50.128428Z | 2025-08-21T03:54:00Z |

## Migration Guide

**Note:**

- For **fetching incidents**, set the **First Fetch** parameter to the **start time** from previous integration's last run. This might create duplicate alerts, but it will ensure that no alert data is lost.
- This integration only supports fetching IOC domain matches. If you need to fetch user defined Rule Detection and Curated Rule Detection Alerts, please use the Streaming API integration.
- Assert Alerts and User Alerts options are no longer available in this integration as these APIs have been deprecated.

### Migrated Commands

Below is the table showing the commands that have been migrated from "Chronicle" to "Google SecOps" integration.

| **Command Name** |
| --- |
| gcb-list-iocs |
| ip |
| domain |
| gcb-ioc-details |
| gcb-list-events |
| gcb-list-detections |
| gcb-list-rules |
| gcb-create-rule |
| gcb-get-rule |
| gcb-delete-rule |
| gcb-create-rule-version |
| gcb-change-rule-alerting-status |
| gcb-change-live-rule-status |
| gcb-start-retrohunt |
| gcb-get-retrohunt |
| gcb-list-retrohunts |
| gcb-cancel-retrohunt |
| gcb-list-reference-list |
| gcb-get-reference-list |
| gcb-create-reference-list |
| gcb-update-reference-list |
| gcb-verify-reference-list |
| gcb-test-rule-stream |
| gcb-list-curatedrules |
| gcb-list-curatedrule-detections |
| gcb-udm-search |
| gcb-verify-value-in-reference-list |
| gcb-verify-rule |
| gcb-get-event |
| gcb-reference-list-append-content |
| gcb-reference-list-remove-content |

### Deprecated Commands

Some commands from the previous integration have been deprecated from Google API side. Below is the table showing the commands that have been deprecated with no replacement.

| **Deprecated Command** |
| --- |
| gcb-assets |
| gcb-list-alerts |
| gcb-list-useraliases |
| gcb-list-assetaliases |
