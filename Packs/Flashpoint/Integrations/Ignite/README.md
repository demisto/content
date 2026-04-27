Use the Flashpoint Ignite integration to reduce business risk. Ignite allows users to ingest alerts and compromised credentials as incident alerts and executes commands such as search intelligence report, ip, url, get events, and more.
This integration was integrated and tested with API v1 of Ignite.

### Auto Extract Indicator

Both incident types **Ignite Alert** and **Flashpoint Compromised Credentials** support the auto extraction feature by default. This feature extracts indicators and enriches their reputations using commands and scripts defined for the indicator type (Refer to [Indicator extraction (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Indicator-Extraction) or [Indicator extraction (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Indicator-extraction) or [Indicator extraction (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Indicator-extraction) for more details).

If you are upgrading from a Flashpoint integration, please refer to the [Migration Guide](#migration-guide) for guidance.

## Configure Flashpoint Ignite on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Flashpoint Ignite.
3. Click **Add instance** to create and configure a new integration instance.
4. To fetch Ignite alerts, refer to the section ["Configuration for fetching Ignite Alerts as a Cortex XSOAR Incident"](#configuration-for-fetching-ignite-alerts-as-a-cortex-xsoar-incident).
5. To fetch Ignite compromised credentials, refer to the section ["Configuration for fetching Ignite Compromised Credentials as a Cortex XSOAR Incident"](#configuration-for-fetching-ignite-compromised-credentials-as-a-cortex-xsoar-incident).

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Server URL | Server URL to connect to Ignite. | True |
    | API Key | API key used for secure communication with the Ignite platform. | True |
    | Maximum number of incidents per fetch | The maximum limit is 200 for alerts and compromised credentials. | False |
    | First fetch time | Date or relative timestamp to start fetching the incidents from. \(Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.\). | False |
    | Fetch Type | Whether to fetch the Ignite alerts or the compromised credentials. Defaults to "Compromised Credentials" if nothing selected. | False |
    | Severity for Incidents | Set the default severity for the incidents using this instance. | False |
    | Alert Status | Filters the incoming alerts with the provided alert status. | False |
    | Alert Origin | Filters the incoming alerts with the origin of the alert. | False |
    | Alert Sources | Filters the incoming alerts with the source of the alert. | False |
    | Fetch fresh compromised credentials alerts | Adds the 'is_fresh' flag to compromised credential queries so it only ingests username/password combinations if they haven't been seen before. | False |
    | Fetch compromised credentials alerts having lowercase in password | Filters the incoming compromised credentials alerts with passwords having lowercase letters. | False |
    | Fetch compromised credentials alerts having uppercase in password | Filters the incoming compromised credentials alerts with passwords having uppercase letters. | False |
    | Fetch compromised credentials alerts having numbers in password | Filters the incoming compromised credentials alerts with passwords having numbers. | False |
    | Fetch compromised credentials alerts having symbol in password | Filters the incoming compromised credentials alerts with passwords having symbols. | False |
    | Fetch compromised credentials alerts having minimum length of password | Filters the incoming compromised credentials alerts with passwords has minimum length. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Create relationships | Create relationships between indicators as part of enrichment. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

6. Click **Test** to validate the URLs, token, and connection.

## Configuration for fetching Ignite Alerts as a Cortex XSOAR Incident

1. Select **Fetches incidents**.
2. Under Classifier, select "N/A".
3. Under Incident type, select "Ignite Alert".
4. Under Mapper (incoming), select "Ignite Alert - Incoming Mapper" for default mapping.
5. Enter the connection parameters (Server URL, API key).
6. Under the Fetch Type, select "Alerts".
7. Select "Alert Status" based on your requirement to filter the alerts. By default, it will fetch all status of alerts.
8. Select "Alert Origin" based on your requirement to filter the alerts. By default, it will fetch all origins of alerts.
9. Select "Alert Sources" based on your requirement to filter the alerts. By default, it will fetch all sources of alerts.
10. Select "Severity for Incidents" based on your requirement to set the default severity for the incidents. By default, it will set the Unknown severity for all incidents.
11. Update "First fetch time" and "Max Fetch Count" based on your requirements.

## Configuration for fetching Ignite Compromised Credentials as a Cortex XSOAR Incident

1. Select **Fetches incidents**.
2. Under Classifier, select "N/A".
3. Under Incident type, select "Flashpoint Compromised Credentials".
4. Under Mapper (incoming), select "Flashpoint Compromised Credentials - Incoming Mapper" for default mapping.
5. Enter the connection parameters (Server URL, API key).
6. Under the Fetch Type, select "Compromised Credentials".
7. Select "Fetch fresh compromised credentials alerts" so that it only ingests username/password combinations if they haven't been seen before.
8. Select "Fetch compromised credentials alerts having lowercase in password" so that it filters the incoming compromised credentials alerts with passwords having lowercase letters.
9. Select "Fetch compromised credentials alerts having uppercase in password" so that it filters the incoming compromised credentials alerts with passwords having uppercase letters.
10. Select "Fetch compromised credentials alerts having numbers in password" so that it filters the incoming compromised credentials alerts with passwords having numbers.
11. Select "Fetch compromised credentials alerts having symbol in password" so that it filters the incoming compromised credentials alerts with passwords having symbols.
12. Select "Fetch compromised credentials alerts having minimum length of password" so that it filters the incoming compromised credentials alerts with passwords has minimum length.
13. Update "First fetch time" and "Max Fetch Count" based on your requirements.

## Troubleshooting

### Error: The maximum records to fetch for the given first fetch can not exceed 10,000

- The maximum number of records that can be fetched using the first fetch time is limited to 10,000 by the API.
- To resolve this issue, you can reduce the first fetch time to a shorter time period, ensuring that the total number of records fetched during the specified time falls within the 10,000 limit.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### flashpoint-ignite-intelligence-report-search

***
Search for the Intelligence Reports using a keyword.

#### Base Command

`flashpoint-ignite-intelligence-report-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_search | Search report using keyword or text. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Report.NotifiedAt | string | Notify date of report. |
| Ignite.Report.PlatformUrl | string | Platform URL of the report. Used to help redirect the Ignite platform. |
| Ignite.Report.PostedAt | number | Posted date of the report. |
| Ignite.Report.Summary | string | Summary of the report. |
| Ignite.Report.Title | string | Title of the report. |
| Ignite.Report.UpdatedAt | string | Last updated date of the report. |
| Ignite.Report.ReportId | string | Unique ID of the report. |

#### Command example

```!flashpoint-ignite-intelligence-report-search report_search=ChatGpt```

#### Context Example

```json
{
    "Ignite": {
        "Report": [
            {
                "NotifiedAt": "2024-04-17T19:23:51.870+00:00",
                "PlatformUrl": "https://app.flashpoint.io/cti/intelligence/report/00000000000000000001",
                "PostedAt": "2024-04-17T19:23:51.870+00:00",
                "ReportId": "00000000000000000001",
                "Summary": "This report covers evolving events that impact the advancement of AI technology and highlights notable developments that impact safety for users and organizations.",
                "Title": "Artificial Intelligence Threat Landscape",
                "UpdatedAt": "2024-04-17T19:23:51.870+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Ignite Intelligence reports related to search: ChatGpt
>
>Top 5 reports:
>
>1) [Artificial Intelligence Threat Landscape](https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000001)
> Summary: This report covers evolving events that impact the advancement of AI technology and highlights notable developments that impact safety for users and organizations.
>
>
>
>Link to Report-search on Ignite platform: [https:<span>//</span>app.flashpoint.io/cti/intelligence/search?query=ChatGpt](https:<span>//</span>app.flashpoint.io/cti/intelligence/search)

### flashpoint-ignite-compromised-credentials-list

***
Retrieves the compromised credentials based on the filter values provided in the command arguments.

#### Base Command

`flashpoint-ignite-compromised-credentials-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Filters the data based on the start date of the breach (UTC). Note: Will consider current time as default for end_date if start_date is initialized.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc. | Optional |
| end_date | Filters the data based on the end date of the breach (UTC). Note: Requires start_date along with the given argument.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc. | Optional |
| filter_date | Filters the compromised credential's breach data by either created or first observed date.<br/>Note: Requires the argument value for at least 'start_date' and 'end_date'. Possible values are: created_at, first_observed_at. | Optional |
| page_size | The maximum number of result objects to return per page. Note: The maximum value is 1,000. Default is 50. | Optional |
| page_number | Specify a page number to retrieve the compromised credentials. Note: The multiplication of page_size and page_number parameters cannot exceed 10,000. Default is 1. | Optional |
| sort_date | Sort the compromised credential's breach data by either created or first observed date. Note: Will consider ascending as default for sort_order if sort_date is initialized. Possible values are: created_at, first_observed_at. | Optional |
| sort_order | Specify the order to sort the data in. Note: Requires sort_date along with the given argument. Possible values are: asc, desc. | Optional |
| is_fresh | Whether to fetch the fresh compromised credentials or not. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.CompromisedCredential._id | String | ID of the IoC. |
| Ignite.CompromisedCredential._source.affected_domain | String | Affected domain of the IoC. |
| Ignite.CompromisedCredential._source.basetypes | Unknown | The array contains the underlying type of the credentials object, in this case  \["credential-sighting"\]. |
| Ignite.CompromisedCredential._source.body.raw | String | This is the raw content captured from the breach Flashpoint discovered. |
| Ignite.CompromisedCredential._source.breach._header | String | This is the breach header object. |
| Ignite.CompromisedCredential._source.breach.basetypes | Unknown | Array containing the underlying base type of the breach object, i.e., \["breach"\]. |
| Ignite.CompromisedCredential._source.breach.breach_type | String | Constant for future use. |
| Ignite.CompromisedCredential._source.breach.created_at.date-time | Date | The datetime when the source breach was created, formatted as YYYY-mm-ddTHH:MM:SSZ. |
| Ignite.CompromisedCredential._source.breach.created_at.timestamp | Number | The UNIX timestamp when the source breach was created. |
| Ignite.CompromisedCredential._source.breach.first_observed_at.date-time | Date | Datetime when the source breach was first observed, formatted as YYYY-mm-ddTHH:MM:SSZ. |
| Ignite.CompromisedCredential._source.breach.first_observed_at.timestamp | Number | The UNIX timestamp when the source breach was first observed. |
| Ignite.CompromisedCredential._source.breach.fpid | String | Flashpoint ID of the breach. |
| Ignite.CompromisedCredential._source.breach.source | String | Data source of breach \(i.e., Analyst Research, CredentialStealer, etc.\). |
| Ignite.CompromisedCredential._source.breach.source_type | String | Type of source of the breach. |
| Ignite.CompromisedCredential._source.breach.title | String | Title of the breach. |
| Ignite.CompromisedCredential._source.breach.victim | String | Victim of the breach. |
| Ignite.CompromisedCredential._source.credential_record_fpid | String | The Flashpoint ID of the associated record object. Used to retrieve sightings for a credential. |
| Ignite.CompromisedCredential._source.customer_id | String | Customer ID of the IoC. |
| Ignite.CompromisedCredential._source.domain | String | The domain object extracted off of the email address. |
| Ignite.CompromisedCredential._source.email | String | The email address for the compromised credential. |
| Ignite.CompromisedCredential._source.username | String | The username for the compromised credential. |
| Ignite.CompromisedCredential._source.extraction_id | String | Extraction ID of the IoC. |
| Ignite.CompromisedCredential._source.extraction_record_id | String | Extraction record ID of the IoC. |
| Ignite.CompromisedCredential._source.fpid | String | The Flashpoint ID of this credentials object. |
| Ignite.CompromisedCredential._source.header_.indexed_at | String | Timestamp for when this document was indexed into the Flashpoint database. |
| Ignite.CompromisedCredential._source.header_.pipeline_duration | String | Pipeline duration header information of the IoC. |
| Ignite.CompromisedCredential._source.is_fresh | Boolean | "true" if the credential has not been seen before, and it hasn't been marked "not fresh" by an analyst. \(Historical breaches are not "fresh".\). |
| Ignite.CompromisedCredential._source.last_observed_at.date-time | Date | If exists, time object for when the credential was previously observed. Datetime object formatted as YYYY-mm-ddTHH:MM:SSZ. |
| Ignite.CompromisedCredential._source.last_observed_at.timestamp | Number | The UNIX timestamp when the source breach was first observed. |
| Ignite.CompromisedCredential._source.password | String | The password for the credential \(in plain text, if possible\). |
| Ignite.CompromisedCredential._source.password_complexity.has_lowercase | Boolean | Whether lowercase letters are present. |
| Ignite.CompromisedCredential._source.password_complexity.has_number | Boolean | Whether numbers are present. |
| Ignite.CompromisedCredential._source.password_complexity.has_symbol | Boolean | Whether symbols are present. |
| Ignite.CompromisedCredential._source.password_complexity.has_uppercase | Boolean | Whether uppercase letters are present. |
| Ignite.CompromisedCredential._source.password_complexity.length | Number | Integer value that represents the number of characters in the password. |
| Ignite.CompromisedCredential._source.password_complexity.probable_hash_algorithms | Unknown | List of possible hash algorithms suspected based on the text pattern of the password. \(May include values like "MD5", "SHA-1", "SHA-256", "bcrypt", etc.\) |
| Ignite.CompromisedCredential._source.times_seen | Number | Integer representing the number of times the credential has been seen at Flashpoint. |
| Ignite.CompromisedCredential._type | String | Type of the IoC. |
| Ignite.CompromisedCredential.matched_queries | Unknown | Matching queries of the IoC. |
| Ignite.CompromisedCredential.sort | Unknown | Sort value of the IoC. |

#### Command example

```!flashpoint-ignite-compromised-credentials-list start_date="2 weeks" end_date="1 days" filter_date=created_at is_fresh=true page_number=2 page_size=1 sort_date=created_at sort_order=asc```

#### Context Example

```json
{
    "Ignite": {
        "CompromisedCredential": {
            "_id": "sample_id",
            "_source": {
                "affected_domain": "example",
                "affected_url": "https://dummy_url",
                "basetypes": [
                    "credential-sighting"
                ],
                "body": {
                    "raw": "URL: https://dummy_url\r\nUsername: someone@example.com\r\nPassword: pass_123\r\nApplication: Microsoft_[Edge]_Default"
                },
                "breach": {
                    "basetypes": [
                        "breach"
                    ],
                    "breach_type": "credential",
                    "created_at": {
                        "date-time": "2024-05-10T16:13:33Z",
                        "timestamp": 1715789613
                    },
                    "first_observed_at": {
                        "date-time": "2024-05-10T16:13:34Z",
                        "timestamp": 1715789614
                    },
                    "fpid": "sample_fpid",
                    "source": "Analyst Research",
                    "source_type": "Credential Stealer",
                    "title": "Compromised Users from Redline Stealer Malware \"logs_05_10_2024-160709.zip\" May152024"
                },
                "credential_record_fpid": "sample_credential_record_fpid",
                "customer_id": "sample_customer_id",
                "domain": "example.com",
                "email": "someone@example.com",
                "extraction_id": "sample_extraction_id",
                "extraction_record_id": "sample_extraction_record_id",
                "fpid": "sample_fpid",
                "header_": {
                    "indexed_at": 1715793565,
                    "pipeline_duration": 63883012765
                },
                "is_fresh": true,
                "last_observed_at": {
                    "date-time": "2024-05-10T16:13:34Z",
                    "timestamp": 1715789614
                },
                "password": "pass_123",
                "password_complexity": {
                    "has_lowercase": true,
                    "has_number": true,
                    "has_symbol": true,
                    "has_uppercase": true,
                    "length": 9
                },
                "times_seen": 1,
                "username": "someone@example.com"
            },
            "_type": "_doc",
            "matched_queries": [
                "data.example"
            ],
            "sort": [
                1715789613000
            ]
        }
    }
}
```

#### Human Readable Output

>#### Total number of records found: 150
>
>### Compromised Credential(s)
>
>|FPID|Email|Username|Breach Source|Breach Source Type|Password|Created Date (UTC)|First Observed Date (UTC)|
>|---|---|---|---|---|---|---|---|
>| sample_fpid | someone@example.com | someone@example.com | Analyst Research | Credential Stealer | pass_123 | May 10, 2024  16:13 | May 10, 2024  16:13 |

### flashpoint-ignite-event-list

***
Searches for events within the specified time period, the Flashpoint report ID, or attack IDs.

#### Base Command

`flashpoint-ignite-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_period | The time period for the search. | Optional |
| report_fpid | The Flashpoint report ID. To retrieve the Flashpoint report ID, run the flashpoint-ignite-intelligence-related-report-list command. | Optional |
| limit | The maximum number of records. Default is 10. | Optional |
| attack_ids | A comma-separated list of attack IDs for which to search. Attack IDs can be found in event information or on the Ignite platform by filtering events by attack IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Event.EventCreatorEmail | string | The email of the event creator. |
| Ignite.Event.EventId | string | The ID of the event. |
| Ignite.Event.UUID | string | The UUID of the event. |
| Ignite.Event.Href | string | The hyperlink of the event. |
| Ignite.Event.MalwareDescription | string | The description of the malware. |
| Ignite.Event.Name | string | The name of the event. |
| Ignite.Event.ObservedTime | string | The date that the event was triggered. |
| Ignite.Event.Tags | string | The tags of the event. |

#### Command example

```!flashpoint-ignite-event-list limit="2" attack_ids=T1001```

#### Context Example

```json
{
    "Ignite": {
        "Event": [
            {
                "Name": "Observation: strike \"0000000000000000000000000000000000000000000000000000000000000001\" [2024-05-31 03:49:12]",
                "Tags": "mitre:T1001",
                "EventCreatorEmail": "info@flashpoint-intel.com",
                "EventId": "0000000000000000000001",
                "UUID": "00000000-0000-0000-0000-0001",
                "Href": "https://api.flashpoint.io/technical-intelligence/v1/event/0000000000000000000001",
                "ObservedTime": "May 31, 2024  04:03",
                "MalwareDescription": "This malicious adoption has caused difficulties in determining whether observed activity is related to an ongoing criminal attack."
            },
            {
                "Name": "Observation: strike \"0000000000000000000000000000000000000000000000000000000000000002\" [2024-05-31 00:01:14]",
                "Tags": "mitre:T1001",
                "EventCreatorEmail": "info@flashpoint-intel.com",
                "EventId": "0000000000000000000002",
                "UUID": "00000000-0000-0000-0000-0002",
                "Href": "https://api.flashpoint.io/technical-intelligence/v1/event/0000000000000000000002",
                "ObservedTime": "May 31, 2024  01:00",
                "MalwareDescription": "Strike became popular among threat actors as an initial access payload, as well as a second-stage tool threat actors use once access is achieved."
            }
        ]
    }
}
```

#### Human Readable Output

>### Ignite Events
>
>### Below are the detail found
>
>|Observed time (UTC)|Name|Tags|Malware Description|
>|---|---|---|---|
>| May 31, 2024  04:03 | [Observation: strike "0000000000000000000000000000000000000000000000000000000000000001" [2024-05-31 03:49:12]](https://mock_dummy.com/cti/malware/iocs?query=00000000-0000-0000-0000-0001&sort_date=All+Time) | mitre:T1001 | This malicious adoption has caused difficulties in determining whether observed activity is related to an ongoing criminal attack. |
>| May 31, 2024  01:00 | [Observation: strike "0000000000000000000000000000000000000000000000000000000000000002" [2024-05-31 00:01:14]](https://mock_dummy.com/cti/malware/iocs?query=00000000-0000-0000-0000-0002&sort_date=All+Time) | mitre:T1001 | Strike became popular among threat actors as an initial access payload, as well as a second-stage tool threat actors use once access is achieved. |
>
>All events and details (ignite): [https://mock_dummy.com/cti/malware/iocs](https://mock_dummy.com/cti/malware/iocs)

### flashpoint-ignite-event-get

***
Retrieves the details of a single event using event FPID or UUID.

#### Base Command

`flashpoint-ignite-event-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The FPID or UUID that identifies a particular event. The event ID can be fetched from the output context path (Ignite.Event.EventId) of the flashpoint-ignite-event-list command, or the indicator reputation command response or some other investigation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Event.EventCreatorEmail | string | The email of the event creator. |
| Ignite.Event.EventId | string | The ID of the event. |
| Ignite.Event.UUID | string | The UUID of the event. |
| Ignite.Event.Href | string | The hyperlink of the event. |
| Ignite.Event.MalwareDescription | string | The description of the malware. |
| Ignite.Event.Name | string | The name of the event. |
| Ignite.Event.ObservedTime | string | The date that the event was triggered. |
| Ignite.Event.Tags | string | The tags of the event. |

#### Command example

```!flashpoint-ignite-event-get event_id=0000000000000000000001```

#### Context Example

```json
{
    "Ignite": {
        "Event": {
            "Name": "Observation: strike \"0000000000000000000000000000000000000000000000000000000000000001\" [2024-05-31 03:49:12]",
            "Tags": "mitre:T1001",
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "0000000000000000000001",
            "UUID": "00000000-0000-0000-0000-0001",
            "Href": "https://api.flashpoint.io/technical-intelligence/v1/event/0000000000000000000001",
            "ObservedTime": "May 31, 2024  04:03",
            "MalwareDescription": "This malicious adoption has caused difficulties in determining whether observed activity is related to an ongoing criminal attack."
        }
    }
}
```

#### Human Readable Output

>### Ignite Event details
>
>### Below are the detail found
>
>|Observed time (UTC)|Name|Tags|Malware Description|
>|---|---|---|---|
>| May 31, 2024  04:03 | [Observation: strike "0000000000000000000000000000000000000000000000000000000000000001" [2024-05-31 03:49:12]](https://mock_dummy.com/cti/malware/iocs?query=00000000-0000-0000-0000-0001&sort_date=All+Time) | mitre:T1001 | This malicious adoption has caused difficulties in determining whether observed activity is related to an ongoing criminal attack. |

### flashpoint-ignite-intelligence-report-get

***
Get single report details using the report id.

#### Base Command

`flashpoint-ignite-intelligence-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The ID of the report for which the details are to be fetched. The report ID can be retrieved from the output context path (Ignite.Report.ReportId) of the flashpoint-ignite-intelligence-report-search command or some other investigation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Report.NotifiedAt | string | Notify date of the report. |
| Ignite.Report.PlatformUrl | string | Platform URL of the report. Used to help redirect the Ignite platform. |
| Ignite.Report.PostedAt | number | Posted date of the report. |
| Ignite.Report.Summary | string | Summary of the report. |
| Ignite.Report.Title | string | Title of the report. |
| Ignite.Report.UpdatedAt | string | Last updated date of the report. |
| Ignite.Report.ReportId | string | Unique ID of the report. |
| Ignite.Report.Tags | string | Tags of the report. |

#### Command example

```!flashpoint-ignite-intelligence-report-get report_id=00000000000000000001```

#### Context Example

```json
{
    "Ignite": {
        "Report": {
            "NotifiedAt": "2022-02-10T22:25:51.190+00:00",
            "PlatformUrl": "https://app.flashpoint.io/cti/intelligence/report/00000000000000000001",
            "PostedAt": "2022-02-10T22:25:51.190+00:00",
            "ReportId": "00000000000000000001",
            "Summary": "A weekly update on major developments in XYZ.",
            "Title": "Key Developments: XYZ (February 3-10, 2022)",
            "UpdatedAt": "2022-02-10T22:25:51.190+00:00",
            "Tags": "Energy, Government & Policymakers, XYZ, Law Enforcement & Military, Intelligence Report, Technology & Internet, Right-Wing Extremist, Media & Telecom, Protests, Cyber Threats, Physical Threats, Government, Technology, Right-wing extremism, Media, Direct action and protests, Key Developments: XYZ "
        }
    }
}
```

#### Human Readable Output

>### Ignite Intelligence Report details
>
>### Below are the details found
>
>|Title|Date Published (UTC)|Summary|Tags|
>|---|---|---|---|
>| [Key Developments: XYZ (February 3-10, 2022)](https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000001) | Feb 10, 2022  22:25 | A weekly update on major developments in XYZ. | Energy, Government & Policymakers, XYZ, Law Enforcement & Military, Intelligence Report, Technology & Internet, Right-Wing Extremist, Media & Telecom, Protests, Cyber Threats, Physical Threats, Government, Technology, Right-wing extremism, Media, Direct action and protests, Key Developments: XYZ |
>

### flashpoint-ignite-intelligence-related-report-list

***
List related reports for a particular report using the report ID.

#### Base Command

`flashpoint-ignite-intelligence-related-report-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report-id of the report of which the related reports are to be fetched. The report id can be known from output context path (Ignite.Report.ReportId) of flashpoint-ignite-intelligence-report-search command or some other investigation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Report.NotifiedAt | string | Notify date of report. |
| Ignite.Report.PlatformUrl | string | Platform URL of the report. Used to help redirect the Ignite platform. |
| Ignite.Report.PostedAt | number | Posted date of the report. |
| Ignite.Report.Summary | string | Summary of the report. |
| Ignite.Report.Title | string | Title of the report. |
| Ignite.Report.UpdatedAt | string | Last updated date of the report. |
| Ignite.Report.ReportId | string | Unique ID of the report. |

#### Command example

```!flashpoint-ignite-intelligence-related-report-list report_id=00000000000000000003```

#### Context Example

```json
{
    "Ignite": {
        "Report": [
            {
                "NotifiedAt": "2023-04-13T21:18:35.557+00:00",
                "PlatformUrl": "https://app.flashpoint.io/cti/intelligence/report/00000000000000000003",
                "PostedAt": "2023-04-13T21:18:35.557+00:00",
                "ReportId": "00000000000000000003",
                "Summary": "A weekly report on the major developments in XYZ.              ",
                "Title": "Key Developments: XYZ (April 7-13, 2023)",
                "UpdatedAt": "2023-04-13T21:18:35.557+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Ignite Intelligence related reports
>
>Top 5 related reports:
>
>1) [Key Developments: XYZ (April 7-13, 2023)](https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000003)
> Summary: A weekly report on the major developments in XYZ.
>
>
>Link to the given Report on Ignite platform: [https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000001#detail](https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000001#detail)

### flashpoint-ignite-alert-list

***
Retrieves a list of alerts based on the filter values provided in the command arguments.

#### Base Command

`flashpoint-ignite-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| size | The number of alerts to return. Default is 10. | Optional |
| created_after | Returns alerts that occurred after the specified date. (Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc). | Optional |
| created_before | Returns alerts that occurred before the specified date. (Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc). | Optional |
| cursor | The cursor to retrieve next page data. Used for pagination only. The value of the cursor can be found from the output context path (Ignite.PageToken.Alert.cursor) or the HR output of the flashpoint-ignite-alert-list command. | Optional |
| status | Filter alerts by status. Possible values are: Archived, Starred, Sent, None. | Optional |
| origin | Filter alerts by origin. Possible values are: Searches, Assets. | Optional |
| sources | Filter alerts by source. Possible values are: Github, Gitlab, Bitbucket, Communities, Images, Marketplaces. | Optional |
| tags | A comma-separated list of alerts filtered by tags. | Optional |
| asset_type | Filter alerts by asset type. | Optional |
| asset_ip | Filter alerts by asset IP. | Optional |
| asset_ids | A comma-separated list of alerts filtered by asset IDs. | Optional |
| query_ids | A comma-separated list of alerts filtered by search IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Alert.id | String | The unique identifier for the alert. |
| Ignite.Alert.resource.id | String | The identifier for the resource associated with the alert. |
| Ignite.Alert.resource.basetypes | String | Base types of the resource related to the alert. |
| Ignite.Alert.resource.container.container.name | String | The name of the nested container within the resource that holds the alert. |
| Ignite.Alert.resource.container.container.native_id | String | The native identifier for the nested container within the resource. |
| Ignite.Alert.resource.container.container.title | String | The title of the nested container within the resource. |
| Ignite.Alert.resource.container.name | String | The name of the container that holds the resource associated with the alert. |
| Ignite.Alert.resource.container.native_id | String | The native identifier for the container that holds the resource. |
| Ignite.Alert.resource.container.title | String | The title of the container that holds the resource associated with the alert. |
| Ignite.Alert.resource.created_at.date-time | String | The date and time when the resource associated with the alert was created in ISO 8601 format. |
| Ignite.Alert.resource.created_at.raw | Date | The raw timestamp or other date-time representation when the resource was created. |
| Ignite.Alert.resource.created_at.timestamp | Number | The UNIX timestamp representing when the resource associated with the alert was created. |
| Ignite.Alert.resource.media_v2.sha1 | String | The SHA1 hash of the media file related to the alert. |
| Ignite.Alert.resource.media_v2.phash | String | The perceptual hash \(pHash\) of the media file, used to find visually similar images. |
| Ignite.Alert.resource.media_v2.media_type | String | The type of media \(e.g., image, video\) associated with the alert. |
| Ignite.Alert.resource.media_v2.mime_type | String | The MIME type of the media file associated with the alert. |
| Ignite.Alert.resource.media_v2.storage_uri | String | The storage URI where the media file related to the alert is located. |
| Ignite.Alert.resource.media_v2.image_enrichment.enrichments.v1.image-analysis.safe_search.racy | Number | A score indicating the likelihood that the image contains racy content. |
| Ignite.Alert.resource.media_v2.image_enrichment.enrichments.v1.image-analysis.safe_search.spoof | Number | A score indicating the likelihood that the image contains spoofed content. |
| Ignite.Alert.resource.media_v2.image_enrichment.enrichments.v1.image-analysis.safe_search.medical | Number | A score indicating the likelihood that the image contains medical content. |
| Ignite.Alert.resource.media_v2.image_enrichment.enrichments.v1.image-analysis.safe_search.adult | Number | A score indicating the likelihood that the image contains sexual content. |
| Ignite.Alert.resource.media_v2.image_enrichment.enrichments.v1.image-analysis.safe_search.adult | Number | A score indicating the likelihood that the image contains adult content. |
| Ignite.Alert.resource.media_v2.image_enrichment.enrichments.v1.image-analysis.safe_search.violence | Number | A score indicating the likelihood that the image contains violent content. |
| Ignite.Alert.resource.title | String | The title of the resource associated with the alert. |
| Ignite.Alert.resource.section | String | The section of the platform or service where the resource is categorized or located. |
| Ignite.Alert.resource.repo | String | Repository of the resource related to the alert. |
| Ignite.Alert.resource.snippet | String | Snippet of the resource related to the alert. |
| Ignite.Alert.resource.source | String | Source of the resource related to the alert. |
| Ignite.Alert.resource.url | String | URL of the resource related to the alert. |
| Ignite.Alert.resource.owner | String | Owner of the resource related to the alert. |
| Ignite.Alert.resource.file | String | File associated with the resource related to the alert. |
| Ignite.Alert.resource.parent_basetypes | String | The parent base types that categorize the resource. |
| Ignite.Alert.resource.site_actor.names.handle | String | The username or handle of the site actor related to the resource. |
| Ignite.Alert.resource.site_actor.native_id | String | The native identifier for the site actor associated with the resource. |
| Ignite.Alert.resource.sort_date | Date | The date and time used for sorting the resource, typically the creation or publication date. |
| Ignite.Alert.resource.site.title | String | The title of the site or platform associated with the resource. |
| Ignite.Alert.resource.shodan_host.asn | String | The ASN \(Autonomous System Number\) of the Shodan host. |
| Ignite.Alert.resource.shodan_host.country | String | The country of the Shodan host. |
| Ignite.Alert.resource.shodan_host.org | String | The organization of the Shodan host. |
| Ignite.Alert.resource.shodan_host.shodan_url | String | The Shodan URL of the Shodan host. |
| Ignite.Alert.resource.shodan_host.vulns | Unknown | The vulnerabilities related to the Shodan host. |
| Ignite.Alert.reason.id | String | ID of the reason for the alert. |
| Ignite.Alert.reason.name | String | Name of the reason for the alert. |
| Ignite.Alert.reason.text | String | Text related to the reason for the alert. |
| Ignite.Alert.reason.origin | String | Origin of the reason for the alert. |
| Ignite.Alert.reason.details.sources | String | Sources related to the reason for the alert. |
| Ignite.Alert.reason.details.params | Unknown | Parameters related to the reason for the alert. |
| Ignite.Alert.reason.details.params.include.date.end | String | The end date for the included date range in the alert's reason details. |
| Ignite.Alert.reason.details.params.include.date.label | String | The label describing the included date range in the alert's reason details. |
| Ignite.Alert.reason.details.params.include.date.start | String | The start date for the included date range in the alert's reason details. |
| Ignite.Alert.reason.details.type | String | The type of details related to the reason for the alert. |
| Ignite.Alert.reason.entity.id | String | ID of the entity related to the reason for the alert. |
| Ignite.Alert.reason.entity.name | String | Name of the entity related to the reason for the alert. |
| Ignite.Alert.reason.entity.type | String | Type of the entity related to the reason for the alert. |
| Ignite.Alert.status | String | Status of the alert. |
| Ignite.Alert.generated_at | Date | Date when the alert was generated. |
| Ignite.Alert.created_at | Date | Date when the alert was created. |
| Ignite.Alert.tags | Unknown | Tags associated with the alert. |
| Ignite.Alert.highlights.media_v2.image_enrichment.enrichments.v1.image-analysis.text.value | String | The text value extracted from the image analysis in the alert's highlights. |
| Ignite.Alert.highlights.ports | String | The highlighted ports related to the alert. |
| Ignite.Alert.highlights.services | String | The highlighted services related to the alert. |
| Ignite.Alert.highlight_text | String | The highlighted text associated with the alert. |
| Ignite.Alert.data_type | String | Data type of the alert. |
| Ignite.Alert.parent_data_type | String | Parent data type of the alert. |
| Ignite.Alert.source | String | Source of the alert. |
| Ignite.Alert.is_read | Boolean | Indicates if the alert has been read. |
| Ignite.Alert.highlights.body.text/plain | String | The plain text extracted from the body of the content highlighted in the alert. |
| Ignite.Alert.reason.details.params.include.ships_from | String | The shipping origin included in the alert's reason details. |
| Ignite.Alert.highlights.snippet | String | A snippet or excerpt highlighted in the alert. |
| Ignite.PageToken.Alert.created_after | Date | Date for filtering alerts created after a specific time. |
| Ignite.PageToken.Alert.created_before | Date | Date for filtering alerts created before a specific time. |
| Ignite.PageToken.Alert.size | String | Size of the page for pagination. |
| Ignite.PageToken.Alert.cursor | Date | Cursor for pagination to retrieve the next set of alerts. |
| Ignite.PageToken.Alert.name | String | The name of the command. |

#### Command example

```!flashpoint-ignite-alert-list created_after="2024-06-11T05:54:25Z" created_before="2024-06-12T05:54:27Z" size=1```

#### Context Example

```json
{
    "Ignite": {
        "Alert": {
            "id": "00000000-0000-0000-0000-000000000001",
            "resource": {
                "id": "00000000-0000-0000-0000-000000000001",
                "basetypes": [
                    "code",
                    "file",
                    "github",
                    "repository"
                ],
                "file": "2024/06/17/My First Blog/index.html",
                "url": "https://dummyurl.com/naive-gabrie-white",
                "owner": "naive-gabrie-white",
                "source": "github",
                "repo": "naive-gabrie-white.github.io",
                "snippet": "data-image=\"https://i.dummyurl.net/2021/02/24/000000000000001.png\" data-sites=\"facebook,twitter,wechat,weibo,qq\"></div><link rel=\"stylesheet\" href=\"https:..."
            },
            "reason": {
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "fb",
                "text": "facebook",
                "origin": "searches",
                "details": {
                    "sources": [
                        "data_exposure__github",
                        "data_exposure__gitlab",
                        "data_exposure__bitbucket"
                    ]
                },
                "entity": {
                    "id": "000000000000000001",
                    "name": "Crest Data Systems",
                    "type": "organization"
                }
            },
            "generated_at": "2024-06-17T05:54:19Z",
            "created_at": "2024-06-17T05:54:22.158905Z",
            "highlights": {
                "snippet": [
                    "data-image=\"https://i.dummyurl.net/2021/02/24/000000000000001.png\" data-sites=\"<x-fp-highlight>facebook</x-fp-highlight>,twitter,wechat,weibo,qq\"></div><link rel=\"stylesheet\" href=\"https:..."
                ]
            },
            "highlight_text": "data-image=\"https://i.dummyurl.net/2021/02/24/000000000000001.png\" data-sites=\"<x-fp-highlight>facebook</x-fp-highlight>,twitter,wechat,weibo,qq\"></div><link rel=\"stylesheet\" href=\"https:...",
            "data_type": "github",
            "source": "data_exposure__github",
            "is_read": false
        },
        {
            "id": "00000000-0000-0000-0000-000000000005",
            "resource": {
                "id": "00000000000000000005",
                "basetypes": [
                    "infrastructure",
                    "internet",
                    "shodan"
                ],
                "source": "shodan",
                "shodan_host": {
                    "asn": "AS0001",
                    "country": "United States",
                    "org": "Company LLC",
                    "shodan_url": "https://www.shodan.io/host/0.0.0.1"
                }
            },
            "reason": {
                "id": "00000000000000000005",
                "name": "Company IP",
                "text": "0.0.0.1",
                "origin": "assets",
                "details": {
                    "type": "ipv4s"
                },
                "entity": {
                    "id": "000000000000000001",
                    "name": "Crest Data Systems",
                    "type": "organization"
                }
            },
            "generated_at": "2024-07-02T16:43:17Z",
            "created_at": "2024-07-02T16:43:37.476237Z",
            "highlights": {
                "ports": [
                    "<x-fp-highlight>53</x-fp-highlight>",
                    "<x-fp-highlight>443</x-fp-highlight>"
                ],
                "services": [
                    "<x-fp-highlight>Unknown Service (Port 01)</x-fp-highlight>",
                    "<x-fp-highlight>Unknown Service (Port 02)</x-fp-highlight>"
                ]
            },
            "highlight_text": "<x-fp-highlight>53</x-fp-highlight>",
            "data_type": "unknown",
            "is_read": false
        },
        "PageToken": {
            "Alert": {
                "created_after": "2024-06-14T05:54:25Z",
                "created_before": "2024-06-17T05:54:25Z",
                "cursor": "1718603662.158905",
                "name": "flashpoint-ignite-alert-list",
                "size": "1"
            }
        }
    }
}
```

#### Human Readable Output

>### Alerts
>
>|ID|Created at (UTC)|Query|Source|Resource URL|Site Title|Shodan Host|Repository|Owner|Origin|Ports|Services|Highlight Text|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000001 | Jun 17, 2024  05:54 | facebook | data_exposure__github | [https://dummyurl.com/naive-gabrie-white](https://dummyurl.com/naive-gabrie-white) |  |  | naive-gabrie-white.github.io | naive-gabrie-white | searches |  |  | data\-image="https://i.dummyurl.net/2021/02/24/000000000000001.png" data\-sites="<x\-fp\-highlight>facebook</x\-fp\-highlight>,twitter,wechat,weibo,qq"><link rel="stylesheet" href="https:...> |
>| 00000000-0000-0000-0000-000000000005 | Jul 02, 2024  16:43 | 0.0.0.1 |  |  |  | _**asn**_: AS0001<br>_**country**_: United States<br>_**org**_: Company LLC<br>_**shodan_url**_: [https://www.shodan.io/host/0.0.0.1](https://www.shodan.io/host/0.0.0.1) |  |  | assets | 53, 443 | Unknown Service (Port 01), Unknown Service (Port 02) | <x\-fp\-highlight>53</x\-fp\-highlight> |
>
>#### To retrieve the next set of result use
>
>created_after = 2024-06-14T05:54:25Z
>created_before = 2024-06-17T05:54:25Z
>size = 1
>cursor = 1718603662.158905

### email

***
Looks up the "Email" type indicator details. The reputation of Email is considered malicious if there's at least one IoC event in the Ignite database matching the Email indicator.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | A comma-separated list of emails. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.Email.Event.Href | string | A list of reference links of the indicator. |
| Ignite.Email.Event.EventDetails | string | The event details in which the indicator was observed. |
| Ignite.Email.Event.Category | string | The category of the indicator. |
| Ignite.Email.Event.Fpid | string | The Flashpoint ID of the indicator. |
| Ignite.Email.Event.Timestamp | string | The time and date that the indicator was observed. |
| Ignite.Email.Event.Type | string | The indicator type. |
| Ignite.Email.Event.Uuid | string | The UUID of the indicator. |
| Ignite.Email.Event.Comment | string | The comment that was provided when the indicator was observed. |
| Account.Description | string | The description of the indicator. |
| Account.Email.Name | string | Name of indicator. |

#### Command Example

```
!email email="dummy@dummy.com"
```

#### Context Example

``` json
{
  "DBotScore": {
    "Indicator": "dummy@dummy.com",
    "Type": "email",
    "Vendor": "Ignite",
    "Score": 3
  },
  "Account": {
    "Description": "Found in malicious indicators dataset"
    "Email": {
        "Address": "dummy@dummy.com"
    },
  },
  "Ignite.Email.Event": [
    {
      "EventDetails": {
        "RelatedEvent": [],
        "Tags": ["sample_tags"],
        "attack_ids": [],
        "event_uuid": "dummy_uuid",
        "fpid": "dummy_fpid",
        "href": "https://mock_dummy.com/technical-intelligence/v1/event/00000001",
        "info": "sample info", "reports": [], "timestamp": "00001"
      },
      "Category": "sample_category",
      "Fpid": "dummy_fpid",
      "Href": "https://mock_dummy.com/technical-intelligence/v1/attribute/0000001",
      "Timestamp": "00001",
      "Type": "email",
      "Uuid": "dummy_uuid",
      "Comment": "sample comment"
    }
  ]
}
```

#### Human Readable Output

>##### Ignite Email reputation for dummy@dummy.com
>
>Reputation: Malicious
>
>##### Events in which this IOC observed
>
>|Date Observed (UTC)|Name|Tags|
>|---|---|---|
>| Jan 01, 1970  00:00 | sample info | sample_tags |
>
>All events and details (ignite): [https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=email-dst,email-src,email-src-display-name,email-subject,email&query=%22dummy%40dummy.com%22](https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=email-dst,email-src,email-src-display-name,email-subject,email&query=%22dummy%40dummy.com%22)

### filename

***
Looks up the "Filename" type indicator details. The reputation of Filename is considered malicious if there's at least one IoC event in the Ignite database matching the Filename indicator.

#### Base Command

`filename`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | A comma-separated list of filenames. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.Filename.Event.Href | string | A list of reference links of the indicator. |
| Ignite.Filename.Event.Filename | string | Filename of the indicator. |
| Ignite.Filename.Event.EventDetails | string | The event details in which the indicator was observed. |
| Ignite.Filename.Event.Category | string | The category of the indicator. |
| Ignite.Filename.Event.Fpid | string | The Ignite ID of the indicator. |
| Ignite.Filename.Event.Timestamp | string | The time and date that the indicator was observed. |
| Ignite.Filename.Event.Type | string | The indicator type. |
| Ignite.Filename.Event.Uuid | string | The UUID of the indicator. |
| Ignite.Filename.Event.Comment | string | The comment that was provided when the indicator was observed. |
| Filename.Malicious.Description | string | The description of the malicious indicator. |
| Filename.Malicious.Vendor | string | Vendor of the malicious filename. |
| Filename.Name | string | The filename. |
| Filename.Description | string | The description of the indicator. |

#### Command Example

```
!filename filename="dummy.log"
```

#### Context Example

```json
{
  "DBotScore": {
    "Indicator": "dummy.log",
    "Type": "filename",
    "Vendor": "Ignite",
    "Score": 3
  },
  "Filename": {
    "Name": "dummy.log",
    "Malicious": {
      "Vendor": "Ignite",
      "Description": "Found in malicious indicators dataset"
    }
  },
  "Ignite.Filename.Event": [
    {
      "Filename": "dummy.log",
      "Category": "test category",
      "Fpid": "dummy_fpid",
      "Href": "https://mock_dummy.com/technical-intelligence/v1/attribute/00001",
      "Timestamp": "0000000001",
      "Type": "filename",
      "Uuid": "dummy_uuid",
      "EventDetails": {
        "RelatedEvent": [],
        "Tags": [
          "sample_tags"
        ],
        "attack_ids": [],
        "event_uuid": "dummy_uuid",
        "fpid": "dummy_fpid",
        "href": "https://mock_dummy.com/technical-intelligence/v1/event/0001",
        "info": "test info",
        "reports": [],
        "timestamp": "0000000001"
      },
      "Comment": ""
    }
  ]
}
```

#### Human Readable Output

>##### Ignite Filename reputation for dummy.log
>
>Reputation: Malicious
>
>##### Events in which this IOC observed
>
>|Date Observed (UTC)|Name|Tags|
>|---|---|---|
>| Jan 01, 1970  00:00 | test info | sample_tags |
>
>All events and details (ignite): [https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=filename&query=%22dummy.log%22](https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=filename&query=%22dummy.log%22)

### ip

***
Looks up the "IP" type indicator details. The reputation of the IP address is decided from the indicator score if it is found in the Ignite IOC database. Alternatively, the IP address is considered suspicious if it matches any one of the community's peer IP addresses.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses. | Required |
| exact_match | Whether to perform an exact match on the IP address value. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| IP.Address | string | The IP address. |
| IP.Malicious.Description | string | The description of the malicious indicator. |
| IP.Malicious.Vendor | string | The vendor used to calculate the severity of the IP address. |
| IP.Description | string | The description of the indicator. |
| Ignite.IP.Event.Href | string | A list of reference links of the indicator. |
| Ignite.IP.Event.Address | string | The IP address of the indicator. |
| Ignite.IP.Event.EventDetails | string | The event details in which the indicator was observed. |
| Ignite.IP.Event.Category | string | The category of the indicator. |
| Ignite.IP.Event.Fpid | string | The Ignite ID of the indicator. |
| Ignite.IP.Event.Timestamp | string | The time and date that the indicator was observed. |
| Ignite.IP.Event.Type | string | The indicator type. |
| Ignite.IP.Event.Uuid | string | The UUID of the indicator. |
| Ignite.IP.Event.Comment | string | The comment that was provided when the indicator was observed. |
| IP.Relationships.EntityA | string | The source of the relationship. |
| IP.Relationships.EntityB | string | The destination of the relationship. |
| IP.Relationships.Relationship | string | The name of the relationship. |
| IP.Relationships.EntityAType | string | The type of the source of the relationship. |
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Ignite.IP.id | String | Unique identifier for the document. |
| Ignite.IP.author | String | The author of the document. |
| Ignite.IP.author_id | String | The ID of the author of the document. |
| Ignite.IP.date | Date | The date associated with the document. |
| Ignite.IP.container_id | String | Unique identifier of the container. |
| Ignite.IP.container_title | String | Title of the container. |
| Ignite.IP.enrichments.bins | Number | Number of bins associated with the document. |
| Ignite.IP.enrichments.bitcoin_addresses | String | Bitcoin addresses associated with the document. |
| Ignite.IP.enrichments.cve_ids | String | CVE IDs associated with the document. |
| Ignite.IP.enrichments.email_addresses | String | Email addresses associated with the document. |
| Ignite.IP.enrichments.ethereum_addresses | String | Ethereum addresses associated with the document. |
| Ignite.IP.enrichments.ip_addresses | String | IP addresses associated with the document. |
| Ignite.IP.enrichments.location.country_code | String | Country code of the location associated with the document. |
| Ignite.IP.enrichments.location.name | String | Name of the location associated with the document. |
| Ignite.IP.enrichments.location.lat | Number | Latitude of the location associated with the document. |
| Ignite.IP.enrichments.location.long | Number | Longitude of the location associated with the document. |
| Ignite.IP.enrichments.monero_addresses | String | Monero addresses associated with the document. |
| Ignite.IP.enrichments.social_media_handles | String | Social media handles associated with the document. |
| Ignite.IP.enrichments.social_media_sites | String | Social media sites associated with the document. |
| Ignite.IP.enrichments.translation.language | String | Language of the translation associated with the document. |
| Ignite.IP.enrichments.translation.message | String | Translation message associated with the document. |
| Ignite.IP.enrichments.url_domains | String | URL domains associated with the document. |
| Ignite.IP.first_observed_at | Date | The first observed date of the document. |
| Ignite.IP.last_observed_at | Date | The last observed date of the document. |
| Ignite.IP.media.id | String | Unique identifier of the media. |
| Ignite.IP.media.file_name | String | File name of the media. |
| Ignite.IP.media.mime_type | String | MIME type of the media. |
| Ignite.IP.media.phash | String | Perceptual hash of the media. |
| Ignite.IP.media.safe_search | String | Safe search value of the media. |
| Ignite.IP.media.size | Number | Size of the media. |
| Ignite.IP.media.sort_date | Date | Date used for sorting the media. |
| Ignite.IP.media.storage_uri | String | Storage URI of the media. |
| Ignite.IP.media.type | String | Type of the media. |
| Ignite.IP.message | String | Message associated with the document. |
| Ignite.IP.message_id | String | ID of the message associated with the document. |
| Ignite.IP.native_id | String | Native ID of the document. |
| Ignite.IP.message_hash | String | Hash of the message associated with the document. |
| Ignite.IP.parent_container_title | String | Title of the parent container. |
| Ignite.IP.section | String | Section of the document. |
| Ignite.IP.section_id | String | ID of the section. |
| Ignite.IP.site | String | The site associated with the document. |
| Ignite.IP.site_actor_handle | String | Actor handle of the site associated with the document. |
| Ignite.IP.site_actor_alias | String | Actor alias of the site associated with the document. |
| Ignite.IP.site_actor_url | String | Actor URL of the site associated with the document. |
| Ignite.IP.site_actor_username | String | Actor username of the site associated with the document. |
| Ignite.IP.site_source_uri | String | Source URI of the site associated with the document. |
| Ignite.IP.site_title | String | Title of the site associated with the document. |
| Ignite.IP.sort_date | Date | Date used for sorting the document. |
| Ignite.IP.source_uri | String | Source URI of the document. |
| Ignite.IP.title | String | Title of the document. |
| Ignite.IP.title_id | String | ID of the title. |
| Ignite.IP.type | String | Type of the indicator. |
| Ignite.IP.value | string | The value of IP. |
| Ignite.IP.href | string | The href of IP. |
| Ignite.IP.entity_type | string | The entity type of IP. |
| Ignite.IP.score.value | string | The score value of IP. |
| Ignite.IP.score.last_scored_at | string | The last scored at of IP. |
| Ignite.IP.score.raw_score | number | The raw score of IP. |
| Ignite.IP.modified_at | string | The modified at of IP. |
| Ignite.IP.created_at | string | The created at of IP. |
| Ignite.IP.last_seen_at | string | The last seen at of IP. |
| Ignite.IP.platform_urls.ignite | string | The ignite platform url of IP. |
| Ignite.IP.apt_description | string | The apt description of IP. |
| Ignite.IP.external_references.source_name | string | The source name of external reference. |
| Ignite.IP.external_references.url | string | The url of external reference. |
| Ignite.IP.hashes.md5 | string | The md5 hash of IP. |
| Ignite.IP.hashes.sha1 | string | The sha1 hash of IP. |
| Ignite.IP.hashes.sha256 | string | The sha256 hash of IP. |
| Ignite.IP.malware_description | string | The malware description of IP. |
| Ignite.IP.mitre_attack_ids.id | string | The mitre attack id of IP. |
| Ignite.IP.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.IP.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.IP.relationships.iocs.id | string | The id of ioc. |
| Ignite.IP.relationships.iocs.type | string | The type of ioc. |
| Ignite.IP.relationships.iocs.value | string | The value of ioc. |
| Ignite.IP.relationships.iocs.href | string | The href of ioc. |
| Ignite.IP.sightings.source | string | The source of IP sighting. |
| Ignite.IP.sightings.sighted_at | string | The sighted at of IP. |
| Ignite.IP.sightings.tags | array | The tags of IP sighting. |
| Ignite.IP.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.IP.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.IP.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.IP.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.IP.latest_sighting.source | string | The source of IP latest sighting. |
| Ignite.IP.latest_sighting.sighted_at | string | The sighted at of IP latest sighting. |
| Ignite.IP.latest_sighting.tags | array | The tags of IP latest sighting. |
| Ignite.IP.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.IP.total_sightings | integer | The total sightings of IP. |

#### Command example

```!ip ip=0.0.0.1```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "0.0.0.1",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Ignite"
    },
    "IP": {
        "Address": "0.0.0.1",
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Ignite"
        },
        "Relationships": [
            {
                "Relationship": "related-to",
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "dummy_latest_sighting_related_ioc_value_1",
                "EntityBType": "File"
            },
            {
                "Relationship": "related-to",
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "dummy_related_ioc_value_1.com",
                "EntityBType": "Domain"
            }
        ]
    },
    "Ignite": {
        "IP": {
            "id": " dummy_id_123",
            "type": "ipv4",
            "value": "0.0.0.1",
            "href": "https://dummy.href.com",
            "entity_type": "indicator",
            "score": {
                "value": "malicious",
                "last_scored_at": "2025-04-21T06:44:37.633000",
                "raw_score": null
            },
            "modified_at": "2025-04-21T06:44:37.633000",
            "created_at": "2025-04-14T15:28:26.371000",
            "last_seen_at": "2025-04-21T06:34:55.617000",
            "sort_date": "2025-04-21T06:34:55.617000",
            "platform_urls": {
                "ignite": "https://dummy.ignite.com"
            },
            "apt_description": "N/A",
            "external_references": [],
            "hashes": null,
            "malware_description": "dummy_malware_description",
            "mitre_attack_ids": [
                {
                    "id": "dummy_attack_id_123",
                    "name": "dummy_attack_name",
                    "tactics": [
                        "Discovery"
                    ]
                }
            ],
            "relationships": {
                "iocs": [
                    {
                        "id": "dummy_ioc_id_1",
                        "type": "dummy_ioc_type_1",
                        "value": "dummy_ioc_value_1",
                        "href": "https://dummy.ioc.href.com/1"
                    }
                ]
            },
            "sightings": [
                {
                    "source": "dummy_source",
                    "sighted_at": "2025-04-21T06:34:55.617000",
                    "tags": [
                        "dummy_tag_1",
                        "dummy_tag_2",
                        "dummy_tag_3"
                    ],
                    "related_iocs": [
                        {
                            "id": "dummy_related_ioc_id_1",
                            "type": "domain",
                            "value": "dummy_related_ioc_value_1.com",
                            "href": "https://dummy.related_ioc.href.com/1"
                        }
                    ]
                }
            ],
            "latest_sighting": {
                "source": "dummy_latest_sighting_source",
                "sighted_at": "2025-04-21T06:34:55.617000",
                "tags": [
                    "dummy_latest_sighting_tag_1",
                    "dummy_latest_sighting_tag_2",
                    "dummy_latest_sighting_tag_3"
                ],
                "related_iocs": [
                    {
                        "id": "dummy_latest_sighting_related_ioc_id_1",
                        "type": "file",
                        "value": "dummy_latest_sighting_related_ioc_value_1",
                        "href": "https://dummy.latest_sighting.related_ioc.href.com/1"
                    }
                ]
            },
            "total_sightings": 11
        }
    }
}
```

#### Human Readable Output

>### Ignite IP Address reputation for 0.0.0.1
>
>Reputation: Malicious
>
>|ID|IP|Type|Malware Description|Tags|Related IOCs|Mitre Attack IDs|Created At|Modified At|Last Seen At|
>|---|---|---|---|---|---|---|---|---|---|
>|  dummy_id_123 | 0.0.0.1 | ipv4 | dummy_malware_description | dummy_latest_sighting_tag_1,<br>dummy_latest_sighting_tag_2,<br>dummy_latest_sighting_tag_3,<br>dummy_tag_1,<br>dummy_tag_2,<br>dummy_tag_3 | **-** _**type**_: file<br> _**value**_: dummy_latest_sighting_related_ioc_value_1<br>**-** _**type**_: domain<br> _**value**_: dummy_related_ioc_value_1.com | **-** _**id**_: dummy_attack_id_123<br> _**name**_: dummy_attack_name<br> **tactics**:<br>  _**values**_: Discovery | Apr 14, 2025  15:28 | Apr 21, 2025  06:44 | Apr 21, 2025  06:34 |
>
>Platform Link(ignite): [https://dummy.ignite.com](https://dummy.ignite.com)

### flashpoint-ignite-common-lookup

***
Looks up details for indicators of types: "URL", "Domain", "File Hash", and "IP". The reputation of the indicator is decided from the indicator score if it is found in the Ignite IOC database.

#### Base Command

`flashpoint-ignite-common-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | List of indicators. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.File.id | string | The ID of file. |
| Ignite.File.type | String | Type of the indicator. |
| Ignite.File.value | string | The value of file. |
| Ignite.File.href | string | The href of file. |
| Ignite.File.entity_type | string | The entity type of file. |
| Ignite.File.score.value | string | The score value of file. |
| Ignite.File.score.last_scored_at | string | The last scored time of file. |
| Ignite.File.score.raw_score | number | The raw score of file. |
| Ignite.File.modified_at | string | Last time when file was modified. |
| Ignite.File.created_at | string | The creation time of file. |
| Ignite.File.last_seen_at | string | The last seen time of file. |
| Ignite.File.sort_date | string | The sort date of file. |
| Ignite.File.platform_urls.ignite | string | The ignite platform url of file. |
| Ignite.File.apt_description | string | The apt description of file. |
| Ignite.File.external_references.source_name | string | The source name of external reference. |
| Ignite.File.external_references.url | string | The url of external reference. |
| Ignite.File.hashes.md5 | string | The md5 hash of file. |
| Ignite.File.hashes.sha1 | string | The sha1 hash of file. |
| Ignite.File.hashes.sha256 | string | The sha256 hash of file. |
| Ignite.File.malware_description | string | The malware description of file. |
| Ignite.File.mitre_attack_ids.id | string | The mitre attack id of file. |
| Ignite.File.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.File.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.File.relationships.iocs.id | string | The id of ioc. |
| Ignite.File.relationships.iocs.type | string | The type of ioc. |
| Ignite.File.relationships.iocs.value | string | The value of ioc. |
| Ignite.File.relationships.iocs.href | string | The href of ioc. |
| Ignite.File.sightings.source | string | The source of file sighting. |
| Ignite.File.sightings.sighted_at | string | The sighted at time of file. |
| Ignite.File.sightings.tags | array | The tags of file sighting. |
| Ignite.File.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.File.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.File.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.File.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.File.latest_sighting.source | string | The source of file latest sighting. |
| Ignite.File.latest_sighting.sighted_at | string | The sighted at time of latest sighting of file. |
| Ignite.File.latest_sighting.tags | array | The tags of file latest sighting. |
| Ignite.File.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.File.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.File.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.File.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.File.total_sightings | integer | The total sightings of file. |
| File.Malicious.Description | string | The description of the malicious indicator. |
| File.Malicious.Vendor | string | Vendor of the malicious file. |
| File.MD5 | string | MD5 type file. |
| File.SHA1 | string | SHA1 type file. |
| File.SHA512 | string | SHA512 type file. |
| File.Relationships.EntityA | string | The source of the relationship. |
| File.Relationships.EntityB | string | The destination of the relationship. |
| File.Relationships.Relationship | string | The name of the relationship. |
| File.Relationships.EntityAType | string | The type of the source of the relationship. |
| File.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Ignite.Domain.id | string | The ID of domain. |
| Ignite.Domain.type | String | Type of the indicator. |
| Ignite.Domain.value | string | The value of domain. |
| Ignite.Domain.href | string | The href of domain. |
| Ignite.Domain.entity_type | string | The entity type of domain. |
| Ignite.Domain.score.value | string | The score value of domain. |
| Ignite.Domain.score.last_scored_at | string | The last scored time of domain. |
| Ignite.Domain.score.raw_score | number | The raw score of domain. |
| Ignite.Domain.modified_at | string | Last time when domain was modified. |
| Ignite.Domain.created_at | string | The creation time of domain. |
| Ignite.Domain.last_seen_at | string | The last seen time of domain. |
| Ignite.Domain.sort_date | string | The sort date of domain. |
| Ignite.Domain.platform_urls.ignite | string | The ignite platform url of domain. |
| Ignite.Domain.apt_description | string | The apt description of domain. |
| Ignite.Domain.external_references.source_name | string | The source name of external reference. |
| Ignite.Domain.external_references.url | string | The url of external reference. |
| Ignite.Domain.hashes.md5 | string | The md5 hash of domain. |
| Ignite.Domain.hashes.sha1 | string | The sha1 hash of domain. |
| Ignite.Domain.hashes.sha256 | string | The sha256 hash of domain. |
| Ignite.Domain.malware_description | string | The malware description of domain. |
| Ignite.Domain.mitre_attack_ids.id | string | The mitre attack id of domain. |
| Ignite.Domain.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.Domain.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.Domain.relationships.iocs.id | string | The id of ioc. |
| Ignite.Domain.relationships.iocs.type | string | The type of ioc. |
| Ignite.Domain.relationships.iocs.value | string | The value of ioc. |
| Ignite.Domain.relationships.iocs.href | string | The href of ioc. |
| Ignite.Domain.sightings.source | string | The source of domain sighting. |
| Ignite.Domain.sightings.sighted_at | string | The sighted at of domain. |
| Ignite.Domain.sightings.tags | array | The tags of domain sighting. |
| Ignite.Domain.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.Domain.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.Domain.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.Domain.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.Domain.latest_sighting.source | string | The source of domain latest sighting. |
| Ignite.Domain.latest_sighting.sighted_at | string | The sighted at of domain latest sighting. |
| Ignite.Domain.latest_sighting.tags | array | The tags of domain latest sighting. |
| Ignite.Domain.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.Domain.total_sightings | integer | The total sightings of domain. |
| Domain.Malicious.Description | string | The description of the malicious indicator. |
| Domain.Malicious.Vendor | string | Vendor of the malicious indicator. |
| Domain.Name | string | Name of the domain. |
| Domain.Description | string | The description of the indicator. |
| Domain.Relationships.EntityA | string | The source of the relationship. |
| Domain.Relationships.EntityB | string | The destination of the relationship. |
| Domain.Relationships.Relationship | string | The name of the relationship. |
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. |
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. |
| URL.Malicious.Description | string | The description of the malicious indicator. |
| URL.Malicious.Vendor | string | Vendor of the malicious URL. |
| URL.Data | string | The URL. |
| URL.Relationships.EntityA | string | The source of the relationship. |
| URL.Relationships.EntityB | string | The destination of the relationship. |
| URL.Relationships.Relationship | string | The name of the relationship. |
| URL.Relationships.EntityAType | string | The type of the source of the relationship. |
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. |
| URL.Description | string | The description of the indicator. |
| Ignite.URL.id | string | The ID of URL. |
| Ignite.URL.type | String | Type of the indicator. |
| Ignite.URL.value | string | The value of URL. |
| Ignite.URL.href | string | The href of URL. |
| Ignite.URL.entity_type | string | The entity type of URL. |
| Ignite.URL.score.value | string | The score value of URL. |
| Ignite.URL.score.last_scored_at | string | The last scored time of URL. |
| Ignite.URL.score.raw_score | number | The raw score of URL. |
| Ignite.URL.modified_at | string | Last time when URL was modified. |
| Ignite.URL.created_at | string | The creation time of URL. |
| Ignite.URL.last_seen_at | string | The last seen time of URL. |
| Ignite.URL.sort_date | string | The sort date of URL. |
| Ignite.URL.platform_urls.ignite | string | The ignite platform url of URL. |
| Ignite.URL.apt_description | string | The apt description of URL. |
| Ignite.URL.external_references.source_name | string | The source name of external reference. |
| Ignite.URL.external_references.url | string | The url of external reference. |
| Ignite.URL.hashes.md5 | string | The md5 hash of URL. |
| Ignite.URL.hashes.sha1 | string | The sha1 hash of URL. |
| Ignite.URL.hashes.sha256 | string | The sha256 hash of URL. |
| Ignite.URL.malware_description | string | The malware description of URL. |
| Ignite.URL.mitre_attack_ids.id | string | The mitre attack id of URL. |
| Ignite.URL.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.URL.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.URL.relationships.iocs.id | string | The id of ioc. |
| Ignite.URL.relationships.iocs.type | string | The type of ioc. |
| Ignite.URL.relationships.iocs.value | string | The value of ioc. |
| Ignite.URL.relationships.iocs.href | string | The href of ioc. |
| Ignite.URL.sightings.source | string | The source of URL sighting. |
| Ignite.URL.sightings.sighted_at | string | The sighted at time of URL. |
| Ignite.URL.sightings.tags | array | The tags of URL sighting. |
| Ignite.URL.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.URL.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.URL.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.URL.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.URL.latest_sighting.source | string | The source of URL latest sighting. |
| Ignite.URL.latest_sighting.sighted_at | string | The sighted at time of latest sighting of URL. |
| Ignite.URL.latest_sighting.tags | array | The tags of URL latest sighting. |
| Ignite.URL.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.URL.total_sightings | integer | The total sightings of URL. |
| IP.Address | string | The IP address. |
| IP.Malicious.Description | string | The description of the malicious indicator. |
| IP.Malicious.Vendor | string | The vendor used to calculate the severity of the IP address. |
| IP.Description | string | The description of the indicator. |
| IP.Relationships.EntityA | string | The source of the relationship. |
| IP.Relationships.EntityB | string | The destination of the relationship. |
| IP.Relationships.Relationship | string | The name of the relationship. |
| IP.Relationships.EntityAType | string | The type of the source of the relationship. |
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Ignite.IP.id | String | Unique identifier for the document. |
| Ignite.IP.type | String | Type of the indicator. |
| Ignite.IP.value | string | The value of IP. |
| Ignite.IP.href | string | The href of IP. |
| Ignite.IP.entity_type | string | The entity type of IP. |
| Ignite.IP.score.value | string | The score value of IP. |
| Ignite.IP.score.last_scored_at | string | The last scored time of IP. |
| Ignite.IP.score.raw_score | number | The raw score of IP. |
| Ignite.IP.modified_at | string | Last time when IP was modified. |
| Ignite.IP.created_at | string | The creation time of IP. |
| Ignite.IP.last_seen_at | string | The last seen time of IP. |
| Ignite.IP.platform_urls.ignite | string | The ignite platform url of IP. |
| Ignite.IP.apt_description | string | The apt description of IP. |
| Ignite.IP.external_references.source_name | string | The source name of external reference. |
| Ignite.IP.external_references.url | string | The url of external reference. |
| Ignite.IP.hashes.md5 | string | The md5 hash of IP. |
| Ignite.IP.hashes.sha1 | string | The sha1 hash of IP. |
| Ignite.IP.hashes.sha256 | string | The sha256 hash of IP. |
| Ignite.IP.malware_description | string | The malware description of IP. |
| Ignite.IP.mitre_attack_ids.id | string | The mitre attack id of IP. |
| Ignite.IP.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.IP.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.IP.relationships.iocs.id | string | The id of ioc. |
| Ignite.IP.relationships.iocs.type | string | The type of ioc. |
| Ignite.IP.relationships.iocs.value | string | The value of ioc. |
| Ignite.IP.relationships.iocs.href | string | The href of ioc. |
| Ignite.IP.sightings.source | string | The source of IP sighting. |
| Ignite.IP.sightings.sighted_at | string | The sighted at time of IP. |
| Ignite.IP.sightings.tags | array | The tags of IP sighting. |
| Ignite.IP.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.IP.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.IP.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.IP.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.IP.latest_sighting.source | string | The source of IP latest sighting. |
| Ignite.IP.latest_sighting.sighted_at | string | The sighted at time of latest sighting of IP. |
| Ignite.IP.latest_sighting.tags | array | The tags of IP latest sighting. |
| Ignite.IP.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.IP.total_sightings | integer | The total sightings of IP. |

#### Command example

```!flashpoint-ignite-common-lookup indicator="00000000000000000000000000000001"```

#### Context Example

```json
{
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "00000000000000000000000000000001"
                },
                {
                    "type": "SHA1",
                    "value": "0000000000000000000000000000000000000001"
                },
                {
                    "type": "SHA256",
                    "value": "0000000000000000000000000000000000000000000000000000000000000001"
                }
            ],
            "MD5": "00000000000000000000000000000001",
            "SHA1": "0000000000000000000000000000000000000001",
            "SHA256": "0000000000000000000000000000000000000000000000000000000000000001",
            "Malicious": {
                "Vendor": "Ignite",
                "Description": "Found in malicious indicators dataset"
            },
            "Relationships": [
                {
                    "Relationship": "related-to",
                    "EntityA": "00000000000000000000000000000001",
                    "EntityAType": "File",
                    "EntityB": "00000000000000000000000000000002",
                    "EntityBType": "File"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "00000000000000000000000000000001",
            "Type": "file",
            "Vendor": "Ignite",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "Ignite.File": {
        "id": "dummy_id",
        "type": "file",
        "value": "00000000000000000000000000000001",
        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id",
        "entity_type": "indicator",
        "score": {
            "value": "malicious",
            "last_scored_at": "2025-01-02T01:00:00.000001"
        },
        "modified_at": "2025-01-02T01:00:00.000001",
        "created_at": "2025-01-01T01:00:00.000000",
        "last_seen_at": "2025-01-02T01:00:00.000001",
        "sort_date": "2025-01-02T01:00:00.000001",
        "platform_urls": {
            "ignite": "https://mock_dummy.com/cti/malware/iocs/dummy_id"
        },
        "apt_description": "N/A",
        "hashes": {
            "md5": "00000000000000000000000000000001",
            "sha1": "0000000000000000000000000000000000000001",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000001"
        },
        "malware_description": "dummy description.",
        "mitre_attack_ids": [
            {
                "id": "dummy_mitre_id",
                "name": "dummy name",
                "tactics": [
                    "Defense Evasion"
                ]
            }
        ],
        "sightings": [
            {
                "source": "flashpoint_detection",
                "sighted_at": "2025-01-02T01:00:00.000000",
                "tags": [
                    "malware:pony",
                    "os:windows",
                    "source:flashpoint_detection",
                    "type:stealer"
                ],
                "related_iocs": [
                    {
                        "id": "dummy_id",
                        "type": "file",
                        "value": "00000000000000000000000000000001",
                        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id"
                    }
                ]
            }
        ],
        "latest_sighting": {
            "source": "flashpoint_detection",
            "sighted_at": "2025-01-02T01:00:00.000000",
            "tags": [
                "malware:pony",
                "os:windows",
                "source:flashpoint_detection",
                "type:stealer"
            ],
            "related_iocs": [
                {
                    "id": "dummy_id",
                    "type": "file",
                    "value": "00000000000000000000000000000002",
                    "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id"
                }
            ]
        },
        "total_sightings": 1
    }
}
```

#### Human Readable Output

>### Ignite File reputation for  00000000000000000000000000000001
>
>Reputation: Malicious
>
>
>|ID|Type|Hashes|Malware Description|Tags|Related IOCs|Mitre Attack IDs|Created At|Modified At|Last Seen At|
>|---|---|---|---|---|---|---|---|---|---|
>| dummy_id | file | _**md5**_: 00000000000000000000000000000001<br>_**sha1**_: 0000000000000000000000000000000000000001<br>_**sha256**_: 0000000000000000000000000000000000000000000000000000000000000001 | dummy description. | malware:pony,<br>os:windows,<br>source:flashpoint_detection,<br>type:stealer | **-** _**type**_: file<br> _**value**_: 00000000000000000000000000000002 | **-** _**id**_: dummy_mitre_id<br> _**name**_: dummy name<br> **tactics**:<br>  _**values**_: Defense Evasion | Jan 01, 2025  01:00 | Jan 02, 2025  01:00 | Jan 02, 2025  01:00 |
>
>Platform Link(ignite): [https://mock_dummy.com/cti/malware/iocs/dummy_id](https://mock_dummy.com/cti/malware/iocs/dummy_id)

### flashpoint-ignite-indicator-get

***
Looks up details for indicators of types "URL", "Domain", "File Hash", and "IP" using their ID. The reputation of the indicator is decided from the indicator score if it is found in the Ignite IOC database.

#### Base Command

`flashpoint-ignite-indicator-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | ID of the indicator. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.File.id | string | The ID of file. |
| Ignite.File.type | String | Type of the indicator. |
| Ignite.File.value | string | The value of file. |
| Ignite.File.href | string | The href of file. |
| Ignite.File.entity_type | string | The entity type of file. |
| Ignite.File.score.value | string | The score value of file. |
| Ignite.File.score.last_scored_at | string | The last scored time of file. |
| Ignite.File.score.raw_score | number | The raw score of file. |
| Ignite.File.modified_at | string | Last time when file was modified. |
| Ignite.File.created_at | string | The creation time of file. |
| Ignite.File.last_seen_at | string | The last seen time of file. |
| Ignite.File.sort_date | string | The sort date of file. |
| Ignite.File.platform_urls.ignite | string | The ignite platform url of file. |
| Ignite.File.apt_description | string | The apt description of file. |
| Ignite.File.external_references.source_name | string | The source name of external reference. |
| Ignite.File.external_references.url | string | The url of external reference. |
| Ignite.File.hashes.md5 | string | The md5 hash of file. |
| Ignite.File.hashes.sha1 | string | The sha1 hash of file. |
| Ignite.File.hashes.sha256 | string | The sha256 hash of file. |
| Ignite.File.malware_description | string | The malware description of file. |
| Ignite.File.mitre_attack_ids.id | string | The mitre attack id of file. |
| Ignite.File.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.File.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.File.relationships.iocs.id | string | The id of ioc. |
| Ignite.File.relationships.iocs.type | string | The type of ioc. |
| Ignite.File.relationships.iocs.value | string | The value of ioc. |
| Ignite.File.relationships.iocs.href | string | The href of ioc. |
| Ignite.File.sightings.source | string | The source of file sighting. |
| Ignite.File.sightings.sighted_at | string | The sighted at time of file. |
| Ignite.File.sightings.tags | array | The tags of file sighting. |
| Ignite.File.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.File.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.File.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.File.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.File.latest_sighting.source | string | The source of file latest sighting. |
| Ignite.File.latest_sighting.sighted_at | string | The sighted at time of latest sighting of file. |
| Ignite.File.latest_sighting.tags | array | The tags of file latest sighting. |
| Ignite.File.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.File.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.File.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.File.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.File.total_sightings | integer | The total sightings of file. |
| File.Malicious.Description | string | The description of the malicious indicator. |
| File.Malicious.Vendor | string | Vendor of the malicious file. |
| File.MD5 | string | MD5 type file. |
| File.SHA1 | string | SHA1 type file. |
| File.SHA512 | string | SHA512 type file. |
| File.Relationships.EntityA | string | The source of the relationship. |
| File.Relationships.EntityB | string | The destination of the relationship. |
| File.Relationships.Relationship | string | The name of the relationship. |
| File.Relationships.EntityAType | string | The type of the source of the relationship. |
| File.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Ignite.File.historical_tags | string | The tags of File. |
| Ignite.File.reports.html | string | Platform url to access the report of the indicator. |
| Ignite.File.reports.json | string | API url of the report of the indicator. |
| Ignite.Domain.id | string | The ID of domain. |
| Ignite.Domain.type | String | Type of the indicator. |
| Ignite.Domain.value | string | The value of domain. |
| Ignite.Domain.href | string | The href of domain. |
| Ignite.Domain.entity_type | string | The entity type of domain. |
| Ignite.Domain.score.value | string | The score value of domain. |
| Ignite.Domain.score.last_scored_at | string | The last scored time of domain. |
| Ignite.Domain.score.raw_score | number | The raw score of domain. |
| Ignite.Domain.modified_at | string | Last time when domain was modified. |
| Ignite.Domain.created_at | string | The creation time of domain. |
| Ignite.Domain.last_seen_at | string | The last seen time of domain. |
| Ignite.Domain.sort_date | string | The sort date of domain. |
| Ignite.Domain.platform_urls.ignite | string | The ignite platform url of domain. |
| Ignite.Domain.apt_description | string | The apt description of domain. |
| Ignite.Domain.external_references.source_name | string | The source name of external reference. |
| Ignite.Domain.external_references.url | string | The url of external reference. |
| Ignite.Domain.hashes.md5 | string | The md5 hash of domain. |
| Ignite.Domain.hashes.sha1 | string | The sha1 hash of domain. |
| Ignite.Domain.hashes.sha256 | string | The sha256 hash of domain. |
| Ignite.Domain.malware_description | string | The malware description of domain. |
| Ignite.Domain.mitre_attack_ids.id | string | The mitre attack id of domain. |
| Ignite.Domain.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.Domain.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.Domain.relationships.iocs.id | string | The id of ioc. |
| Ignite.Domain.relationships.iocs.type | string | The type of ioc. |
| Ignite.Domain.relationships.iocs.value | string | The value of ioc. |
| Ignite.Domain.relationships.iocs.href | string | The href of ioc. |
| Ignite.Domain.sightings.source | string | The source of domain sighting. |
| Ignite.Domain.sightings.sighted_at | string | The sighted at of domain. |
| Ignite.Domain.sightings.tags | array | The tags of domain sighting. |
| Ignite.Domain.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.Domain.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.Domain.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.Domain.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.Domain.latest_sighting.source | string | The source of domain latest sighting. |
| Ignite.Domain.latest_sighting.sighted_at | string | The sighted at of domain latest sighting. |
| Ignite.Domain.latest_sighting.tags | array | The tags of domain latest sighting. |
| Ignite.Domain.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.Domain.total_sightings | integer | The total sightings of domain. |
| Domain.Malicious.Description | string | The description of the malicious indicator. |
| Domain.Malicious.Vendor | string | Vendor of the malicious indicator. |
| Domain.Name | string | Name of the domain. |
| Domain.Description | string | The description of the indicator. |
| Domain.Relationships.EntityA | string | The source of the relationship. |
| Domain.Relationships.EntityB | string | The destination of the relationship. |
| Domain.Relationships.Relationship | string | The name of the relationship. |
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. |
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Ignite.Domain.historical_tags | string | The tags of Domain. |
| Ignite.Domain.reports.html | string | Platform url to access the report of the indicator. |
| Ignite.Domain.reports.json | string | API url of the report of the indicator. |
| URL.Malicious.Description | string | The description of the malicious indicator. |
| URL.Malicious.Vendor | string | Vendor of the malicious URL. |
| URL.Data | string | The URL. |
| URL.Relationships.EntityA | string | The source of the relationship. |
| URL.Relationships.EntityB | string | The destination of the relationship. |
| URL.Relationships.Relationship | string | The name of the relationship. |
| URL.Relationships.EntityAType | string | The type of the source of the relationship. |
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. |
| URL.Description | string | The description of the indicator. |
| Ignite.URL.id | string | The ID of URL. |
| Ignite.URL.type | String | Type of the indicator. |
| Ignite.URL.value | string | The value of URL. |
| Ignite.URL.href | string | The href of URL. |
| Ignite.URL.entity_type | string | The entity type of URL. |
| Ignite.URL.score.value | string | The score value of URL. |
| Ignite.URL.score.last_scored_at | string | The last scored time of URL. |
| Ignite.URL.score.raw_score | number | The raw score of URL. |
| Ignite.URL.modified_at | string | Last time when URL was modified. |
| Ignite.URL.created_at | string | The creation time of URL. |
| Ignite.URL.last_seen_at | string | The last seen time of URL. |
| Ignite.URL.sort_date | string | The sort date of URL. |
| Ignite.URL.platform_urls.ignite | string | The ignite platform url of URL. |
| Ignite.URL.apt_description | string | The apt description of URL. |
| Ignite.URL.external_references.source_name | string | The source name of external reference. |
| Ignite.URL.external_references.url | string | The url of external reference. |
| Ignite.URL.hashes.md5 | string | The md5 hash of URL. |
| Ignite.URL.hashes.sha1 | string | The sha1 hash of URL. |
| Ignite.URL.hashes.sha256 | string | The sha256 hash of URL. |
| Ignite.URL.malware_description | string | The malware description of URL. |
| Ignite.URL.mitre_attack_ids.id | string | The mitre attack id of URL. |
| Ignite.URL.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.URL.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.URL.relationships.iocs.id | string | The id of ioc. |
| Ignite.URL.relationships.iocs.type | string | The type of ioc. |
| Ignite.URL.relationships.iocs.value | string | The value of ioc. |
| Ignite.URL.relationships.iocs.href | string | The href of ioc. |
| Ignite.URL.sightings.source | string | The source of URL sighting. |
| Ignite.URL.sightings.sighted_at | string | The sighted at time of URL. |
| Ignite.URL.sightings.tags | array | The tags of URL sighting. |
| Ignite.URL.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.URL.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.URL.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.URL.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.URL.latest_sighting.source | string | The source of URL latest sighting. |
| Ignite.URL.latest_sighting.sighted_at | string | The sighted at time of latest sighting of URL. |
| Ignite.URL.latest_sighting.tags | array | The tags of URL latest sighting. |
| Ignite.URL.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.URL.total_sightings | integer | The total sightings of URL. |
| Ignite.URL.historical_tags | string | The tags of URL. |
| Ignite.URL.reports.html | string | Platform url to access the report of the indicator. |
| Ignite.URL.reports.json | string | API url of the report of the indicator. |
| IP.Address | string | The IP address. |
| IP.Malicious.Description | string | The description of the malicious indicator. |
| IP.Malicious.Vendor | string | The vendor used to calculate the severity of the IP address. |
| IP.Description | string | The description of the indicator. |
| IP.Relationships.EntityA | string | The source of the relationship. |
| IP.Relationships.EntityB | string | The destination of the relationship. |
| IP.Relationships.Relationship | string | The name of the relationship. |
| IP.Relationships.EntityAType | string | The type of the source of the relationship. |
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Ignite.IP.id | String | Unique identifier for the document. |
| Ignite.IP.type | String | Type of the indicator. |
| Ignite.IP.value | string | The value of IP. |
| Ignite.IP.href | string | The href of IP. |
| Ignite.IP.entity_type | string | The entity type of IP. |
| Ignite.IP.score.value | string | The score value of IP. |
| Ignite.IP.score.last_scored_at | string | The last scored time of IP. |
| Ignite.IP.score.raw_score | number | The raw score of IP. |
| Ignite.IP.modified_at | string | Last time when IP was modified. |
| Ignite.IP.created_at | string | The creation time of IP. |
| Ignite.IP.last_seen_at | string | The last seen time of IP. |
| Ignite.IP.platform_urls.ignite | string | The ignite platform url of IP. |
| Ignite.IP.apt_description | string | The apt description of IP. |
| Ignite.IP.external_references.source_name | string | The source name of external reference. |
| Ignite.IP.external_references.url | string | The url of external reference. |
| Ignite.IP.hashes.md5 | string | The md5 hash of IP. |
| Ignite.IP.hashes.sha1 | string | The sha1 hash of IP. |
| Ignite.IP.hashes.sha256 | string | The sha256 hash of IP. |
| Ignite.IP.malware_description | string | The malware description of IP. |
| Ignite.IP.mitre_attack_ids.id | string | The mitre attack id of IP. |
| Ignite.IP.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.IP.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.IP.relationships.iocs.id | string | The id of ioc. |
| Ignite.IP.relationships.iocs.type | string | The type of ioc. |
| Ignite.IP.relationships.iocs.value | string | The value of ioc. |
| Ignite.IP.relationships.iocs.href | string | The href of ioc. |
| Ignite.IP.sightings.source | string | The source of IP sighting. |
| Ignite.IP.sightings.sighted_at | string | The sighted at time of IP. |
| Ignite.IP.sightings.tags | array | The tags of IP sighting. |
| Ignite.IP.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.IP.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.IP.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.IP.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.IP.latest_sighting.source | string | The source of IP latest sighting. |
| Ignite.IP.latest_sighting.sighted_at | string | The sighted at time of latest sighting of IP. |
| Ignite.IP.latest_sighting.tags | array | The tags of IP latest sighting. |
| Ignite.IP.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.IP.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.IP.total_sightings | integer | The total sightings of IP. |
| Ignite.IP.historical_tags | string | The tags of IP. |
| Ignite.IP.reports.html | string | Platform url to access the report of the indicator. |
| Ignite.IP.reports.json | string | API url of the report of the indicator. |

#### Command example

```!flashpoint-ignite-indicator-get indicator_id=dummy_id```

#### Context Example

```json
{
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "00000000000000000000000000000001"
                },
                {
                    "type": "SHA1",
                    "value": "0000000000000000000000000000000000000001"
                },
                {
                    "type": "SHA256",
                    "value": "0000000000000000000000000000000000000000000000000000000000000001"
                }
            ],
            "MD5": "00000000000000000000000000000001",
            "SHA1": "0000000000000000000000000000000000000001",
            "SHA256": "0000000000000000000000000000000000000000000000000000000000000001",
            "Malicious": {
                "Vendor": "Ignite",
                "Description": "Found in malicious indicators dataset"
            },
            "Relationships": [
                {
                    "Relationship": "related-to",
                    "EntityA": "dummy_id",
                    "EntityAType": "File",
                    "EntityB": "00000000000000000000000000000002",
                    "EntityBType": "File"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "00000000000000000000000000000001",
            "Type": "file",
            "Vendor": "Ignite",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "Ignite.File": {
        "id": "dummy_id",
        "type": "file",
        "value": "00000000000000000000000000000001",
        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id",
        "entity_type": "indicator",
        "score": {
            "value": "malicious",
            "last_scored_at": "2025-01-02T01:00:00.000001"
        },
        "modified_at": "2025-01-02T01:00:00.000001",
        "created_at": "2025-01-01T01:00:00.000000",
        "last_seen_at": "2025-01-02T01:00:00.000001",
        "sort_date": "2025-01-02T01:00:00.000001",
        "platform_urls": {
            "ignite": "https://mock_dummy.com/cti/malware/iocs/dummy_id"
        },
        "apt_description": "N/A",
        "hashes": {
            "md5": "00000000000000000000000000000001",
            "sha1": "0000000000000000000000000000000000000001",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000001"
        },
        "malware_description": "dummy description.",
        "mitre_attack_ids": [
            {
                "id": "dummy_mitre_id",
                "name": "dummy name",
                "tactics": [
                    "Defense Evasion"
                ]
            }
        ],
        "sightings": [
            {
                "source": "flashpoint_detection",
                "sighted_at": "2025-01-02T01:00:00.000000",
                "tags": [
                    "malware:pony",
                    "os:windows",
                    "source:flashpoint_detection",
                    "type:stealer"
                ],
                "related_iocs": [
                    {
                        "id": "dummy_id",
                        "type": "file",
                        "value": "00000000000000000000000000000002",
                        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id"
                    }
                ]
            },
            {
                "source": "flashpoint_detection",
                "sighted_at": "2025-01-02T01:00:00.000000",
                "tags": [
                    "malware:pony",
                    "os:windows",
                    "source:flashpoint_detection",
                    "type:stealer"
                ],
                "related_iocs": [
                    {
                        "id": "dummy_id",
                        "type": "file",
                        "value": "00000000000000000000000000000001",
                        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id"
                    }
                ]
            }
        ],
        "historical_tags": [
            "malware:pony",
            "os:windows",
            "source:flashpoint_detection",
            "type:stealer"
        ],
        "reports": [
            {
                "html": "https://mock_dummy.com/cti/intelligence/report/report_1",
                "json": "https://mock_dummy.com/finished-intelligence/v1/reports/report_1"
            },
            {
                "html": "https://mock_dummy.com/cti/intelligence/report/report_2",
                "json": "https://mock_dummy.com/finished-intelligence/v1/reports/report_2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Ignite File reputation for  00000000000000000000000000000001
>
>Reputation: Malicious
>
>
>|ID|Type|Hashes|Malware Description|Tags|Related IOCs|Hashes|Mitre Attack IDs|Reports|Created At|Modified At|Last Seen At|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| dummy_id | file | _**md5**_: 00000000000000000000000000000001<br>_**sha1**_: 0000000000000000000000000000000000000001<br>_**sha256**_: 0000000000000000000000000000000000000000000000000000000000000001 | dummy description. | malware:pony,<br>os:windows,<br>source:flashpoint_detection,<br>type:stealer | **-** _**type**_: file<br> _**value**_: 00000000000000000000000000000002 | **-** _**id**_: dummy_mitre_id<br> _**name**_: dummy name<br> **tactics**:<br>  _**values**_: Defense Evasion | **-** _**html**_: https://mock_dummy.com/cti/intelligence/report/report_1<br> _**json**_: https://mock_dummy.com/finished-intelligence/v1/reports/report_1<br>**-** _**html**_: https://mock_dummy.com/cti/intelligence/report/report_2<br> _**json**_: https://mock_dummy.com/finished-intelligence/v1/reports/report_2 | Jan 01, 2025  01:00 | Jan 02, 2025  01:00 | Jan 02, 2025  01:00 |
>
>Platform Link(ignite): [https://mock_dummy.com/cti/malware/iocs/dummy_id](https://mock_dummy.com/cti/malware/iocs/dummy_id)

### url

***
Looks up the "URL" type indicator details. The reputation of the URL is decided from the indicator score if it is found in the Ignite IOC database.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs. | Required |
| exact_match | Whether to perform an exact match on the URL value. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.Url.Event.Href | string | A list of reference links of the indicator. |
| Ignite.Url.Event.Url | string | URL of the indicator. |
| Ignite.Url.Event.EventDetails | string | The event details in which the indicator was observed. |
| Ignite.Url.Event.Category | string | The category of the indicator. |
| Ignite.Url.Event.Fpid | string | The Flashpoint ID of the indicator. |
| Ignite.Url.Event.Timestamp | string | The time and date that the indicator was observed. |
| Ignite.Url.Event.Type | string | The indicator type. |
| Ignite.Url.Event.Uuid | string | The UUID of the indicator. |
| Ignite.Url.Event.Comment | string | The comment that was provided when the indicator was observed. |
| URL.Malicious.Description | string | The description of the malicious indicator. |
| URL.Malicious.Vendor | string | Vendor of the malicious URL. |
| URL.Data | string | The URL. |
| URL.Relationships.EntityA | string | The source of the relationship. |
| URL.Relationships.EntityB | string | The destination of the relationship. |
| URL.Relationships.Relationship | string | The name of the relationship. |
| URL.Relationships.EntityAType | string | The type of the source of the relationship. |
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. |
| URL.Description | string | The description of the indicator. |
| Ignite.URL.id | string | The ID of URL. |
| Ignite.URL.type | string | Type of the indicator. |
| Ignite.URL.value | string | The value of URL. |
| Ignite.URL.href | string | The href of URL. |
| Ignite.URL.entity_type | string | The entity type of URL. |
| Ignite.URL.score.value | string | The score value of URL. |
| Ignite.URL.score.last_scored_at | string | The last scored time of URL. |
| Ignite.URL.score.raw_score | number | The raw score of URL. |
| Ignite.URL.modified_at | string | Last time when URL was modified. |
| Ignite.URL.created_at | string | The creation time of URL. |
| Ignite.URL.last_seen_at | string | The last seen time of URL. |
| Ignite.URL.sort_date | string | The sort date of URL. |
| Ignite.URL.platform_urls.ignite | string | The ignite platform url of URL. |
| Ignite.URL.apt_description | string | The apt description of URL. |
| Ignite.URL.external_references.source_name | string | The source name of external reference. |
| Ignite.URL.external_references.url | string | The url of external reference. |
| Ignite.URL.hashes.md5 | string | The md5 hash of URL. |
| Ignite.URL.hashes.sha1 | string | The sha1 hash of URL. |
| Ignite.URL.hashes.sha256 | string | The sha256 hash of URL. |
| Ignite.URL.malware_description | string | The malware description of URL. |
| Ignite.URL.mitre_attack_ids.id | string | The mitre attack id of URL. |
| Ignite.URL.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.URL.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.URL.relationships.iocs.id | string | The id of ioc. |
| Ignite.URL.relationships.iocs.type | string | The type of ioc. |
| Ignite.URL.relationships.iocs.value | string | The value of ioc. |
| Ignite.URL.relationships.iocs.href | string | The href of ioc. |
| Ignite.URL.sightings.source | string | The source of URL sighting. |
| Ignite.URL.sightings.sighted_at | string | The sighted at time of URL. |
| Ignite.URL.sightings.tags | array | The tags of URL sighting. |
| Ignite.URL.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.URL.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.URL.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.URL.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.URL.latest_sighting.source | string | The source of URL latest sighting. |
| Ignite.URL.latest_sighting.sighted_at | string | The sighted at time of latest sighting of URL. |
| Ignite.URL.latest_sighting.tags | array | The tags of URL latest sighting. |
| Ignite.URL.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.URL.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.URL.total_sightings | integer | The total sightings of URL. |

#### Command Example

```
!url url="http://dummy.com"
```

#### Context Example

``` json
{
    "URL": [
        {
            "Data": "http://dummy.com",
            "Relationships": [
                {
                    "Relationship": "related-to",
                    "EntityA": "http://dummy.com",
                    "EntityAType": "URL",
                    "EntityB": "http://dummyurl.com",
                    "EntityBType": "URL"
                },
                {
                    "Relationship": "related-to",
                    "EntityA": "http://dummy.com",
                    "EntityAType": "URL",
                    "EntityB": "0.0.0.1",
                    "EntityBType": "IP"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "http://dummy.com",
            "Reliability": "B - Usually reliable",
            "Type": "url",
            "Vendor": "Ignite",
            "Score": 2
        }
    ],
    "Ignite.URL": {
        "id": " dummy-id-123",
        "type": "url",
        "value": "http://dummy.com",
        "href": "https://dummy-api.com/dummy-endpoint",
        "entity_type": "indicator",
        "score": {
            "value": "suspicious",
            "last_scored_at": "2025-04-01T00:00:00"
        },
        "modified_at": "2025-04-01T00:00:00",
        "created_at": "2025-04-01T00:00:00",
        "last_seen_at": "2025-04-01T00:00:00",
        "sort_date": "2025-04-01T00:00:00",
        "platform_urls": {
            "ignite": "https://dummy-platform.com/dummy-url"
        },
        "apt_description": "Dummy APT description",
        "malware_description": "Dummy malware description",
        "sightings": [
            {
                "source": "dummy-source",
                "sighted_at": "2025-04-01T00:00:00",
                "tags": [
                    "dummy-tag-1",
                    "dummy-tag-2"
                ],
                "related_iocs": [
                    {
                        "id": "dummy-id-1",
                        "type": "ipv4",
                        "value": "0.0.0.1",
                        "href": "https://dummy-api.com/dummy-endpoint-1"
                    }
                ]
            }
        ],
        "latest_sighting": {
            "source": "dummy-source",
            "sighted_at": "2025-04-01T00:00:00",
            "tags": [
                "dummy_latest_sighting_tag_1",
                "dummy_latest_sighting_tag_2"
            ],
            "related_iocs": [
                {
                    "id": "dummy-id-1",
                    "type": "url",
                    "value": "http://dummyurl.com",
                    "href": "https://dummy-api.com/dummy-endpoint-2"
                }
            ]
        },
        "total_sightings": 1
    }
}
```

#### Human Readable Output

>### Ignite URL reputation for http://dummy.com
>
>Reputation: Suspicious
>
>|ID|URL|Malware Description|Tags|Related IOCs|Created At|Modified At|Last Seen At|
>|---|---|---|---|---|---|---|---|
>|  dummy-id-123 | http://dummy.com | Dummy malware description | dummy_latest_sighting_tag_1,<br>dummy_latest_sighting_tag_2,<br>dummy-tag-1,<br>dummy-tag-2 | **-** _**type**_: url<br> _**value**_: http://dummyurl.com<br>**-** _**type**_: ipv4<br> _**value**_: 0.0.0.1 | Apr 01, 2025  00:00 | Apr 01, 2025  00:00 | Apr 01, 2025  00:00 |
>
>Platform Link(ignite): [https://dummy-platform.com/dummy-url](https://dummy-platform.com/dummy-url)

### domain

***
Looks up the "Domain" type indicator details. The reputation of the domain is decided from the indicator score if it is found in the Ignite IOC database.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains. | Required |
| exact_match | Whether to perform an exact match on the domain value. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.Domain.Event.Href | string | A list of reference links of the indicator. |
| Ignite.Domain.Event.Domain | string | The domain of the indicator. |
| Ignite.Domain.Event.EventDetails | string | The event details in which the indicator was observed. |
| Ignite.Domain.Event.Category | string | The category of the indicator. |
| Ignite.Domain.Event.Fpid | string | The Ignite ID of the indicator. |
| Ignite.Domain.Event.Timestamp | string | The time and date that the indicator was observed. |
| Ignite.Domain.Event.Type | string | The indicator type. |
| Ignite.Domain.Event.Uuid | string | The UUID of the indicator. |
| Ignite.Domain.Event.Comment | string | The comment that was provided when the indicator was observed. |
| Ignite.Domain.id | string | The ID of domain. |
| Ignite.Domain.type | string | Type of the indicator. |
| Ignite.Domain.value | string | The value of domain. |
| Ignite.Domain.href | string | The href of domain. |
| Ignite.Domain.entity_type | string | The entity type of domain. |
| Ignite.Domain.score.value | string | The score value of domain. |
| Ignite.Domain.score.last_scored_at | string | The last scored time of domain. |
| Ignite.Domain.score.raw_score | number | The raw score of domain. |
| Ignite.Domain.modified_at | string | Last time when domain was modified. |
| Ignite.Domain.created_at | string | The creation time of domain. |
| Ignite.Domain.last_seen_at | string | The last seen time of domain. |
| Ignite.Domain.sort_date | string | The sort date of domain. |
| Ignite.Domain.platform_urls.ignite | string | The ignite platform url of domain. |
| Ignite.Domain.apt_description | string | The apt description of domain. |
| Ignite.Domain.external_references.source_name | string | The source name of external reference. |
| Ignite.Domain.external_references.url | string | The url of external reference. |
| Ignite.Domain.hashes.md5 | string | The md5 hash of domain. |
| Ignite.Domain.hashes.sha1 | string | The sha1 hash of domain. |
| Ignite.Domain.hashes.sha256 | string | The sha256 hash of domain. |
| Ignite.Domain.malware_description | string | The malware description of domain. |
| Ignite.Domain.mitre_attack_ids.id | string | The mitre attack id of domain. |
| Ignite.Domain.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.Domain.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.Domain.relationships.iocs.id | string | The id of ioc. |
| Ignite.Domain.relationships.iocs.type | string | The type of ioc. |
| Ignite.Domain.relationships.iocs.value | string | The value of ioc. |
| Ignite.Domain.relationships.iocs.href | string | The href of ioc. |
| Ignite.Domain.sightings.source | string | The source of domain sighting. |
| Ignite.Domain.sightings.sighted_at | string | The sighted at of domain. |
| Ignite.Domain.sightings.tags | array | The tags of domain sighting. |
| Ignite.Domain.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.Domain.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.Domain.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.Domain.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.Domain.latest_sighting.source | string | The source of domain latest sighting. |
| Ignite.Domain.latest_sighting.sighted_at | string | The sighted at of domain latest sighting. |
| Ignite.Domain.latest_sighting.tags | array | The tags of domain latest sighting. |
| Ignite.Domain.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.Domain.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.Domain.total_sightings | integer | The total sightings of domain. |
| Domain.Malicious.Description | string | The description of the malicious indicator. |
| Domain.Malicious.Vendor | string | Vendor of the malicious indicator. |
| Domain.Name | string | Name of the domain. |
| Domain.Description | string | The description of the indicator. |
| Domain.Relationships.EntityA | string | The source of the relationship. |
| Domain.Relationships.EntityB | string | The destination of the relationship. |
| Domain.Relationships.Relationship | string | The name of the relationship. |
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. |
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. |

#### Command example

```!domain domain="dummy_domain.com"```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "dummy.com",
            "Type": "domain",
            "Vendor": "Ignite",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "Domain": [
        {
            "Name": "dummy.com",
            "Malicious": {
                "Vendor": "Ignite",
                "Description": "Found in malicious indicators dataset"
            },
            "Relationships": [
                {
                    "Relationship": "related-to",
                    "EntityA": "dummy.com",
                    "EntityAType": "IP",
                    "EntityB": "dummy_value",
                    "EntityBType": "File"
                }
            ]
        }
    ],
    "Ignite.Domain": {
        "apt_description": "N/A",
        "created_at": "2025-01-01T01:00:00.000000",
        "entity_type": "indicator",
        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id",
        "id": "dummy_id",
        "last_seen_at": "2025-04-22T11:17:37.981000",
        "latest_sighting": {
            "related_iocs": [
                {
                    "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id_2",
                    "id": "dummy_id_2",
                    "type": "file",
                    "value": "dummy_value"
                }
            ],
            "sighted_at": "2025-01-01T01:00:00.000000",
            "source": "flashpoint_extraction",
            "tags": [
                "extracted_config:true",
                "malware:xworm",
                "source:flashpoint_extraction"
            ]
        },
        "malware_description": "<p>This is dummy description.</p>",
        "modified_at": "2025-01-02T01:00:00.000000",
        "platform_urls": {
            "ignite": "https://mock_dummy.com/cti/malware/iocs/dummy_id"
        },
        "score": {
            "last_scored_at": "2025-04-22T11:23:21.569000",
            "value": "malicious"
        },
        "sightings": [
            {
                "related_iocs": [
                    {
                        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id_3",
                        "id": "dummy_id_3",
                        "type": "file",
                        "value": "dummy_value"
                    }
                ],
                "sighted_at": "2025-04-22T11:17:37.981000",
                "source": "flashpoint_extraction",
                "tags": [
                    "extracted_config:true",
                    "malware:xworm",
                    "source:flashpoint_extraction"
                ]
            }
        ],
        "sort_date": "2025-01-01T01:00:00.000000",
        "total_sightings": 1,
        "type": "domain",
        "value": "dummy_domain.com"
    }
}
```

#### Human Readable Output

>### Ignite Domain reputation for dummy_domain.com
>
>Reputation: Malicious
>
>
>|ID|Domain|Malware Description|Tags|Related IOCs|Created At|Modified At|Last Seen At|
>|---|---|---|---|---|---|---|---|
>| dummy_id | dummy_domain.com | This is dummy description. | extracted_config:true,<br>malware:xworm,<br>source:flashpoint_extraction | **-** _**type**_: file<br> _**value**_: dummy_value | Jan 01, 2025  01:00 | Jan 02, 2025  01:00 | Jan 02, 2025  01:00 |
>
>Platform Link(ignite): [https://mock_dummy.com/cti/malware/iocs/dummy_id](https://mock_dummy.com/cti/malware/iocs/dummy_id)

### file

***
Looks up the "File" type indicator details. The reputation of the file is decided from the indicator score if it is found in the Ignite IOC database.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. | Required |
| exact_match | Whether to perform an exact match on the file hash value. Possible values are: True, False. Default is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.File.Event.Href | string | A list of reference links of the indicator. |
| Ignite.File.Event.MD5 | string | MD5 file hash of the indicator. |
| Ignite.File.Event.SHA1 | string | SHA1 file hash of the indicator. |
| Ignite.File.Event.SHA256 | string | SHA256 file hash of the indicator. |
| Ignite.File.Event.SHA512 | string | SHA512 file hash of the indicator. |
| Ignite.File.Event.SSDeep | string | SSDeep file hash of the indicator. |
| Ignite.File.Event.EventDetails | string | The event details in which the indicator was observed. |
| Ignite.File.Event.Category | string | The category of the indicator. |
| Ignite.File.Event.Fpid | string | The Ignite ID of the indicator. |
| Ignite.File.Event.Timestamp | string | The time and date that the indicator was observed. |
| Ignite.File.Event.Type | string | The indicator type. |
| Ignite.File.Event.Uuid | string | The UUID of the indicator. |
| Ignite.File.Event.Comment | string | The comment that was provided when the indicator was observed. |
| Ignite.File.id | string | The ID of file. |
| Ignite.File.type | string | Type of the indicator. |
| Ignite.File.value | string | The value of file. |
| Ignite.File.href | string | The href of file. |
| Ignite.File.entity_type | string | The entity type of file. |
| Ignite.File.score.value | string | The score value of file. |
| Ignite.File.score.last_scored_at | string | The last scored time of file. |
| Ignite.File.score.raw_score | number | The raw score of file. |
| Ignite.File.modified_at | string | Last time when file was modified. |
| Ignite.File.created_at | string | The creation time of file. |
| Ignite.File.last_seen_at | string | The last seen time of file. |
| Ignite.File.sort_date | string | The sort date of file. |
| Ignite.File.platform_urls.ignite | string | The ignite platform url of file. |
| Ignite.File.apt_description | string | The apt description of file. |
| Ignite.File.external_references.source_name | string | The source name of external reference. |
| Ignite.File.external_references.url | string | The url of external reference. |
| Ignite.File.hashes.md5 | string | The md5 hash of file. |
| Ignite.File.hashes.sha1 | string | The sha1 hash of file. |
| Ignite.File.hashes.sha256 | string | The sha256 hash of file. |
| Ignite.File.malware_description | string | The malware description of file. |
| Ignite.File.mitre_attack_ids.id | string | The mitre attack id of file. |
| Ignite.File.mitre_attack_ids.name | string | The name of mitre attack id. |
| Ignite.File.mitre_attack_ids.tactics | unknown | A list of tactics associated with mitre attack id. |
| Ignite.File.relationships.iocs.id | string | The id of ioc. |
| Ignite.File.relationships.iocs.type | string | The type of ioc. |
| Ignite.File.relationships.iocs.value | string | The value of ioc. |
| Ignite.File.relationships.iocs.href | string | The href of ioc. |
| Ignite.File.sightings.source | string | The source of file sighting. |
| Ignite.File.sightings.sighted_at | string | The sighted at time of file. |
| Ignite.File.sightings.tags | array | The tags of file sighting. |
| Ignite.File.sightings.related_iocs.id | string | The ID of related IOC. |
| Ignite.File.sightings.related_iocs.type | string | The type of related IOC. |
| Ignite.File.sightings.related_iocs.value | string | The value of related IOC. |
| Ignite.File.sightings.related_iocs.href | string | The href of related IOC. |
| Ignite.File.latest_sighting.source | string | The source of file latest sighting. |
| Ignite.File.latest_sighting.sighted_at | string | The sighted at time of latest sighting of file. |
| Ignite.File.latest_sighting.tags | array | The tags of file latest sighting. |
| Ignite.File.latest_sighting.related_iocs.id | string | The ID of related IOC. |
| Ignite.File.latest_sighting.related_iocs.type | string | The type of related IOC. |
| Ignite.File.latest_sighting.related_iocs.value | string | The value of related IOC. |
| Ignite.File.latest_sighting.related_iocs.href | string | The href of related IOC. |
| Ignite.File.total_sightings | integer | The total sightings of file. |
| File.Malicious.Description | string | The description of the malicious indicator. |
| File.Malicious.Vendor | string | Vendor of the malicious file. |
| File.MD5 | string | MD5 type file. |
| File.SHA1 | string | SHA1 type file. |
| File.SHA256 | string | SHA256 type file. |
| File.SHA512 | string | SHA512 type file. |
| File.SSDeep | string | SSDeep type file. |
| File.Relationships.EntityA | string | The source of the relationship. |
| File.Relationships.EntityB | string | The destination of the relationship. |
| File.Relationships.Relationship | string | The name of the relationship. |
| File.Relationships.EntityAType | string | The type of the source of the relationship. |
| File.Relationships.EntityBType | string | The type of the destination of the relationship. |

#### Command Example

```
!file file="00000000000000000000000000000001"
```

#### Context Example

``` json
{
    "File": [
        {
            "Hashes": [
                {
                    "type": "MD5",
                    "value": "00000000000000000000000000000001"
                },
                {
                    "type": "SHA1",
                    "value": "0000000000000000000000000000000000000001"
                },
                {
                    "type": "SHA256",
                    "value": "0000000000000000000000000000000000000000000000000000000000000001"
                }
            ],
            "MD5": "00000000000000000000000000000001",
            "SHA1": "0000000000000000000000000000000000000001",
            "SHA256": "0000000000000000000000000000000000000000000000000000000000000001",
            "Malicious": {
                "Vendor": "Ignite",
                "Description": "Found in malicious indicators dataset"
            },
            "Relationships": [
                {
                    "Relationship": "related-to",
                    "EntityA": "00000000000000000000000000000001",
                    "EntityAType": "File",
                    "EntityB": "00000000000000000000000000000002",
                    "EntityBType": "File"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "00000000000000000000000000000001",
            "Type": "file",
            "Vendor": "Ignite",
            "Score": 3,
            "Reliability": "B - Usually reliable"
        }
    ],
    "Ignite.File": {
        "id": "dummy_id",
        "type": "file",
        "value": "00000000000000000000000000000001",
        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id",
        "entity_type": "indicator",
        "score": {
            "value": "malicious",
            "last_scored_at": "2025-01-02T01:00:00.000001"
        },
        "modified_at": "2025-01-02T01:00:00.000001",
        "created_at": "2025-01-01T01:00:00.000000",
        "last_seen_at": "2025-01-02T01:00:00.000001",
        "sort_date": "2025-01-02T01:00:00.000001",
        "platform_urls": {
            "ignite": "https://mock_dummy.com/cti/malware/iocs/dummy_id"
        },
        "apt_description": "N/A",
        "hashes": {
            "md5": "00000000000000000000000000000001",
            "sha1": "0000000000000000000000000000000000000001",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000001"
        },
        "malware_description": "dummy description.",
        "mitre_attack_ids": [
            {
                "id": "dummy_mitre_id",
                "name": "dummy name",
                "tactics": [
                    "Defense Evasion"
                ]
            }
        ],
        "sightings": [
            {
                "source": "flashpoint_detection",
                "sighted_at": "2025-01-02T01:00:00.000000",
                "tags": [
                    "malware:pony",
                    "os:windows",
                    "source:flashpoint_detection",
                    "type:stealer"
                ],
                "related_iocs": [
                    {
                        "id": "dummy_id",
                        "type": "file",
                        "value": "00000000000000000000000000000001",
                        "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id"
                    }
                ]
            }
        ],
        "latest_sighting": {
            "source": "flashpoint_detection",
            "sighted_at": "2025-01-02T01:00:00.000000",
            "tags": [
                "malware:pony",
                "os:windows",
                "source:flashpoint_detection",
                "type:stealer"
            ],
            "related_iocs": [
                {
                    "id": "dummy_id",
                    "type": "file",
                    "value": "00000000000000000000000000000001",
                    "href": "https://mock_dummy.com/technical-intelligence/v2/indicators/dummy_id"
                }
            ]
        },
        "total_sightings": 1
    }
}
```

#### Human Readable Output

>### Ignite File reputation for 00000000000000000000000000000001
>
>Reputation: Malicious
>
>
>|ID|Hash Type|Hashes|Malware Description|Tags|Related IOCs|Mitre Attack IDs|Created At|Modified At|Last Seen At|
>|---|---|---|---|---|---|---|---|---|---|
>| dummy_id | md5 | _**md5**_: 00000000000000000000000000000001<br>_**sha1**_: 0000000000000000000000000000000000000001<br>_**sha256**_: 0000000000000000000000000000000000000000000000000000000000000001 | dummy description. | malware:pony,<br>os:windows,<br>source:flashpoint_detection,<br>type:stealer | **-** _**type**_: file<br> _**value**_: 00000000000000000000000000000002 | **-** _**id**_: dummy_mitre_id<br> _**name**_: dummy name<br> **tactics**:<br>  _**values**_: Defense Evasion | Jan 01, 2025  01:00 | Jan 02, 2025  01:00 | Jan 02, 2025  01:00 |
>
>Platform Link(ignite): [https://mock_dummy.com/cti/malware/iocs/dummy_id](https://mock_dummy.com/cti/malware/iocs/dummy_id)

### flashpoint-ignite-vulnerability-get

***
Retrieves detailed information about a specific vulnerability by its Flashpoint ID.

#### Base Command

`flashpoint-ignite-vulnerability-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Flashpoint ID of the vulnerability to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE, for example: CVE-2015-1653. |
| CVE.CVSS | String | The CVSS of the CVE, for example: 10.0. |
| CVE.Version | String | The version of the CVE, for example: 3.0. |
| CVE.Vector | String | The vector of the CVE, for example: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N. |
| CVE.Table | String | The table of the CVE. |
| CVE.Published | Date | The timestamp of when the CVE was published. |
| CVE.Modified | Date | The timestamp of when the CVE was last modified. |
| CVE.Description | String | A description of the CVE. |
| CVE.Tags | String | The tags of the CVE. |
| CVE.VulnerableProducts | String | The vulnerable products of the CVE. |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.Vulnerability.id | Number | The unique identifier of the vulnerability. |
| Ignite.Vulnerability.cve_ids | Unknown | A list of CVE IDs associated with the vulnerability. |
| Ignite.Vulnerability.title | String | The title of the vulnerability. |
| Ignite.Vulnerability.keywords | String | A list of keywords associated with the vulnerability. |
| Ignite.Vulnerability.description | String | The description of the vulnerability. |
| Ignite.Vulnerability.solution | String | The solution or remediation steps for the vulnerability. |
| Ignite.Vulnerability.technical_description | String | The technical description of the vulnerability. |
| Ignite.Vulnerability.timelines.published_at | Date | The date when the vulnerability was published. |
| Ignite.Vulnerability.timelines.last_modified_at | Date | The date when the vulnerability was last modified. |
| Ignite.Vulnerability.timelines.exploit_published_at | Date | The date when the exploit was published. |
| Ignite.Vulnerability.timelines.discovered_at | Date | The date when the vulnerability was discovered. |
| Ignite.Vulnerability.timelines.disclosed_at | Date | The date when the vulnerability was disclosed. |
| Ignite.Vulnerability.timelines.vendor_informed_at | Date | The date when the vendor was informed. |
| Ignite.Vulnerability.timelines.vendor_acknowledged_at | Date | The date when the vendor acknowledged the vulnerability. |
| Ignite.Vulnerability.timelines.third_party_solution_provided_at | Date | The date when a third-party solution was provided. |
| Ignite.Vulnerability.timelines.solution_provided_at | Date | The date when a solution was provided. |
| Ignite.Vulnerability.timelines.exploited_in_the_wild_at | Date | The date when the vulnerability was exploited in the wild. |
| Ignite.Vulnerability.timelines.vendor_response_time | String | The time taken for vendor response. |
| Ignite.Vulnerability.timelines.time_to_patch | String | The time taken to patch the vulnerability. |
| Ignite.Vulnerability.timelines.total_time_to_patch | String | The total time taken to patch the vulnerability. |
| Ignite.Vulnerability.timelines.time_unpatched | String | The time the vulnerability remained unpatched. |
| Ignite.Vulnerability.timelines.time_to_exploit | String | The time taken to exploit the vulnerability. |
| Ignite.Vulnerability.timelines.total_time_to_exploit | String | The total time taken to exploit the vulnerability. |
| Ignite.Vulnerability.scores.epss_score | Number | An EPSS \(Exploit Prediction Scoring System\) score. |
| Ignite.Vulnerability.scores.epss_v1_score | Number | An EPSS version 1 score. |
| Ignite.Vulnerability.scores.ransomware_score | Number | A ransomware score. |
| Ignite.Vulnerability.scores.severity | String | The severity level of the vulnerability. |
| Ignite.Vulnerability.scores.social_risk_scores.cve_id | String | The CVE ID associated with the social risk score. |
| Ignite.Vulnerability.scores.social_risk_scores.numeric_score | Number | A numeric social risk score. |
| Ignite.Vulnerability.scores.social_risk_scores.categorical_score | String | A categorical social risk score. |
| Ignite.Vulnerability.scores.social_risk_scores.score_date | Date | The date when the social risk score was calculated. |
| Ignite.Vulnerability.scores.social_risk_scores.todays_tweets | Number | The number of tweets today about the vulnerability. |
| Ignite.Vulnerability.scores.social_risk_scores.total_tweets | Number | The total number of tweets about the vulnerability. |
| Ignite.Vulnerability.scores.social_risk_scores.unique_users | Number | The number of unique users discussing the vulnerability. |
| Ignite.Vulnerability.vuln_status | String | The status of the vulnerability. |
| Ignite.Vulnerability.alternate_vulndb_id | String | An alternate VulnDB ID. |
| Ignite.Vulnerability.changelog.created_at | Date | The date when the changelog entry was created. |
| Ignite.Vulnerability.changelog.description | String | The description of the changelog entry. |
| Ignite.Vulnerability.cwes.cwe_id | String | The CWE identifier. |
| Ignite.Vulnerability.cwes.name | String | The name of the CWE. |
| Ignite.Vulnerability.exploits.value | String | An exploit URL or identifier. |
| Ignite.Vulnerability.exploits.type | String | The type of exploit \(e.g., Exploit Database\). |
| Ignite.Vulnerability.exploits_count | Number | The count of exploits associated with the vulnerability. |
| Ignite.Vulnerability.ext_references.value | String | A value of the external reference. |
| Ignite.Vulnerability.ext_references.type | String | The type of external reference. |
| Ignite.Vulnerability.ext_references.created_at | Date | The date when the external reference was created. |
| Ignite.Vulnerability.ext_references.description | String | The description of the external reference. |
| Ignite.Vulnerability.ext_references.url | String | The URL of the external reference. |
| Ignite.Vulnerability.nvd_additional_information.cve_id | String | The CVE ID from NVD. |
| Ignite.Vulnerability.nvd_additional_information.summary | String | The summary from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cwes.cwe_id | String | The CWE identifier from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cwes.name | String | The name of the CWE from NVD. |
| Ignite.Vulnerability.nvd_additional_information.references.name | String | The name of the NVD reference. |
| Ignite.Vulnerability.nvd_additional_information.references.url | String | The URL of the NVD reference. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.access_vector | String | The CVSS v2 access vector from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.access_complexity | String | The CVSS v2 access complexity from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.authentication | String | The CVSS v2 authentication from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.confidentiality_impact | String | The CVSS v2 confidentiality impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.integrity_impact | String | The CVSS v2 integrity impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.availability_impact | Number | The CVSS v2 availability impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.attack_vector | String | The CVSS v3 attack vector from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.attack_complexity | String | The CVSS v3 attack complexity from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.privileges_required | String | The CVSS v3 privileges required from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.user_interaction | String | The CVSS v3 user interaction from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.scope | String | The CVSS v3 scope from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.confidentiality_impact | String | The CVSS v3 confidentiality impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.integrity_impact | String | The CVSS v3 integrity impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.availability_impact | String | The CVSS v3 availability impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.score | Number | The CVSS v3 score from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.vector_string | String | The CVSS v3 vector string from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.version | String | The CVSS v3 version from NVD. |
| Ignite.Vulnerability.classifications.name | String | The name of the classification. |
| Ignite.Vulnerability.classifications.longname | String | The long name of the classification. |
| Ignite.Vulnerability.classifications.description | String | The description of the classification. |
| Ignite.Vulnerability.creditees.name | String | The name of the individual or organization credited. |
| Ignite.Vulnerability.cvss_v2s.access_vector | String | The CVSS v2 access vector. |
| Ignite.Vulnerability.cvss_v2s.access_complexity | String | The CVSS v2 access complexity. |
| Ignite.Vulnerability.cvss_v2s.authentication | String | The CVSS v2 authentication. |
| Ignite.Vulnerability.cvss_v2s.confidentiality_impact | String | The CVSS v2 confidentiality impact. |
| Ignite.Vulnerability.cvss_v2s.integrity_impact | String | The CVSS v2 integrity impact. |
| Ignite.Vulnerability.cvss_v2s.availability_impact | String | The CVSS v2 availability impact. |
| Ignite.Vulnerability.cvss_v2s.source | String | The source of the CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.generated_at | Date | The date when the CVSS v2 score was generated. |
| Ignite.Vulnerability.cvss_v2s.cve_id | String | The CVE ID associated with the CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.score | Number | The CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.calculated_cvss_base_score | Number | A calculated CVSS v2 base score. |
| Ignite.Vulnerability.cvss_v3s.attack_vector | String | The CVSS v3 attack vector. |
| Ignite.Vulnerability.cvss_v3s.attack_complexity | String | The CVSS v3 attack complexity. |
| Ignite.Vulnerability.cvss_v3s.privileges_required | String | The CVSS v3 privileges required. |
| Ignite.Vulnerability.cvss_v3s.user_interaction | String | The CVSS v3 user interaction. |
| Ignite.Vulnerability.cvss_v3s.scope | String | The CVSS v3 scope. |
| Ignite.Vulnerability.cvss_v3s.confidentiality_impact | String | The CVSS v3 confidentiality impact. |
| Ignite.Vulnerability.cvss_v3s.integrity_impact | String | The CVSS v3 integrity impact. |
| Ignite.Vulnerability.cvss_v3s.availability_impact | String | The CVSS v3 availability impact. |
| Ignite.Vulnerability.cvss_v3s.source | String | The source of the CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.generated_at | Date | The date when the CVSS v3 score was generated. |
| Ignite.Vulnerability.cvss_v3s.cve_id | String | The CVE ID associated with the CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.score | Number | The CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.vector_string | String | The CVSS v3 vector string. |
| Ignite.Vulnerability.cvss_v3s.version | String | The CVSS v3 version. |
| Ignite.Vulnerability.cvss_v3s.remediation_level | String | The CVSS v3 remediation level. |
| Ignite.Vulnerability.cvss_v3s.report_confidence | String | The CVSS v3 report confidence. |
| Ignite.Vulnerability.cvss_v3s.exploit_code_maturity | String | The CVSS v3 exploit code maturity. |
| Ignite.Vulnerability.cvss_v3s.temporal_score | String | The CVSS v3 temporal score. |
| Ignite.Vulnerability.cvss_v3s.updated_at | Date | The date when the CVSS v3 score was updated. |
| Ignite.Vulnerability.cvss_v4s.score | Number | The CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.threat_score | Number | The CVSS v4 threat score. |
| Ignite.Vulnerability.cvss_v4s.source | String | The source of the CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.generated_at | Date | The date when the CVSS v4 score was generated. |
| Ignite.Vulnerability.cvss_v4s.updated_at | Date | The date when the CVSS v4 score was updated. |
| Ignite.Vulnerability.cvss_v4s.cve_id | String | The CVE ID associated with the CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.vector_string | String | The CVSS v4 vector string. |
| Ignite.Vulnerability.cvss_v4s.version | String | The CVSS v4 version. |
| Ignite.Vulnerability.cvss_v4s.attack_vector | String | The CVSS v4 attack vector. |
| Ignite.Vulnerability.cvss_v4s.attack_complexity | String | The CVSS v4 attack complexity. |
| Ignite.Vulnerability.cvss_v4s.attack_requirements | String | The CVSS v4 attack requirements. |
| Ignite.Vulnerability.cvss_v4s.privileges_required | String | The CVSS v4 privileges required. |
| Ignite.Vulnerability.cvss_v4s.user_interaction | String | The CVSS v4 user interaction. |
| Ignite.Vulnerability.cvss_v4s.exploit_maturity | String | The CVSS v4 exploit maturity. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_confidentiality_impact | String | The CVSS v4 vulnerable system confidentiality impact. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_integrity_impact | String | The CVSS v4 vulnerable system integrity impact. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_availability_impact | String | The CVSS v4 vulnerable system availability impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_confidentiality_impact | String | The CVSS v4 subsequent system confidentiality impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_integrity_impact | String | The CVSS v4 subsequent system integrity impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_availability_impact | String | The CVSS v4 subsequent system availability impact. |
| Ignite.Vulnerability.tags | String | The tags associated with the vulnerability. |
| Ignite.Vulnerability.products.id | Number | The ID of the affected product. |
| Ignite.Vulnerability.products.name | String | The name of the affected product. |
| Ignite.Vulnerability.products.vendor_id | Number | The vendor ID of the affected product. |
| Ignite.Vulnerability.products.vendor | String | The vendor name of the affected product. |
| Ignite.Vulnerability.products.versions.id | Number | The ID of the product version. |
| Ignite.Vulnerability.products.versions.vulndb_version_id | Number | The VulnDB version ID. |
| Ignite.Vulnerability.products.versions.name | String | The name of the product version. |
| Ignite.Vulnerability.products.versions.affected | String | A string indicating whether the product version is affected. |
| Ignite.Vulnerability.products.versions.all_prior_versions_affected | Boolean | A boolean indicating whether all prior versions are affected. |
| Ignite.Vulnerability.products.versions.cpes.name | String | The CPE \(Common Platform Enumeration\) name. |
| Ignite.Vulnerability.products.versions.cpes.source | String | The source of the CPE. |

#### Command Example

```
!flashpoint-ignite-vulnerability-get id="123456"
```

#### Context Example

``` json
{
    "CVE": [
        {
            "CVSS": {
                "Score": 9.2,
                "Table": [
                    {
                        "metrics": "score",
                        "value": 9.2
                    },
                    {
                        "metrics": "threat_score",
                        "value": 8.5
                    },
                    {
                        "metrics": "source",
                        "value": "http://nvd.nist.gov"
                    },
                    {
                        "metrics": "generated_at",
                        "value": "2024-01-15T00:00:00Z"
                    },
                    {
                        "metrics": "updated_at",
                        "value": "2024-06-15T10:30:00Z"
                    },
                    {
                        "metrics": "cve_id",
                        "value": "CVE-2024-0001"
                    },
                    {
                        "metrics": "vector_string",
                        "value": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    },
                    {
                        "metrics": "version",
                        "value": "4.0"
                    },
                    {
                        "metrics": "attack_vector",
                        "value": "NETWORK"
                    },
                    {
                        "metrics": "attack_complexity",
                        "value": "LOW"
                    },
                    {
                        "metrics": "attack_requirements",
                        "value": "NONE"
                    },
                    {
                        "metrics": "privileges_required",
                        "value": "NONE"
                    },
                    {
                        "metrics": "user_interaction",
                        "value": "NONE"
                    },
                    {
                        "metrics": "exploit_maturity",
                        "value": "PROOF_OF_CONCEPT"
                    },
                    {
                        "metrics": "vulnerable_system_confidentiality_impact",
                        "value": "HIGH"
                    },
                    {
                        "metrics": "vulnerable_system_integrity_impact",
                        "value": "HIGH"
                    },
                    {
                        "metrics": "vulnerable_system_availability_impact",
                        "value": "HIGH"
                    },
                    {
                        "metrics": "subsequent_system_confidentiality_impact",
                        "value": "NONE"
                    },
                    {
                        "metrics": "subsequent_system_integrity_impact",
                        "value": "NONE"
                    },
                    {
                        "metrics": "subsequent_system_availability_impact",
                        "value": "NONE"
                    }
                ],
                "Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Version": "4.0"
            },
            "Description": "This is a dummy vulnerability description for testing purposes. It describes a hypothetical security flaw in a test application.",
            "ID": "CVE-2024-0002",
            "Modified": "2024-06-15T10:30:00Z",
            "Published": "2024-01-01T00:00:00Z",
            "Tags": [
                "test",
                "dummy",
                "critical"
            ],
            "VulnerableProducts": [
                {
                    "CPE": "cpe:2.3:a:testvendor:dummyapp:1.0:*:*:*:*:*:*:*"
                },
                {
                    "CPE": "cpe:2.3:a:testvendor:dummyapp:1.5:*:*:*:*:*:*:*"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "CVE-2024-0002",
            "Score": 0,
            "Type": "cve",
            "Vendor": "Ignite"
        }
    ],
    "Ignite": {
        "Vulnerability": {
            "id": 123456,
            "cve_ids": [
                "CVE-2024-0001",
                "CVE-2024-0002"
            ],
            "title": "Dummy Vulnerability Title for Testing",
            "keywords": "test, dummy, vulnerability",
            "description": "This is a dummy vulnerability description for testing purposes. It describes a hypothetical security flaw in a test application.",
            "solution": "Apply the latest security patch or upgrade to version 2.0 or higher.",
            "technical_description": "Technical details about the dummy vulnerability for testing.",
            "timelines": {
                "published_at": "2024-01-01T00:00:00Z",
                "last_modified_at": "2024-06-15T10:30:00Z",
                "exploit_published_at": "2024-02-10T00:00:00Z",
                "discovered_at": "2023-12-15T00:00:00Z",
                "disclosed_at": "2024-01-05T00:00:00Z",
                "vendor_informed_at": "2023-12-20T00:00:00Z",
                "vendor_acknowledged_at": "2023-12-22T00:00:00Z",
                "solution_provided_at": "2024-01-30T00:00:00Z",
                "exploited_in_the_wild_at": "2024-03-01T00:00:00Z",
                "vendor_response_time": "2 days",
                "time_to_patch": "25 days",
                "total_time_to_patch": "46 days",
                "time_unpatched": "30 days, 0:00:00",
                "time_to_exploit": "40 days, 0:00:00",
                "total_time_to_exploit": "75 days"
            },
            "scores": {
                "epss_score": 0.75,
                "epss_v1_score": 0.68,
                "ransomware_score": 0.45,
                "severity": "Critical",
                "social_risk_scores": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "numeric_score": 8.5,
                        "categorical_score": "High",
                        "score_date": "2024-06-15T10:30:00Z",
                        "todays_tweets": 25,
                        "total_tweets": 150,
                        "unique_users": 75
                    }
                ]
            },
            "vuln_status": "Active",
            "changelog": [
                {
                    "created_at": "2024-06-15T10:30:00Z",
                    "description": "Dummy Product Application version 1.5.0 by Test Vendor: Affected Status set to \"Affected\""
                },
                {
                    "created_at": "2024-05-20T14:20:00Z",
                    "description": "Initial vulnerability entry created"
                }
            ],
            "cwes": [
                {
                    "cwe_id": "CWE-79",
                    "name": "Improper Neutralization of Input During Web Page Generation"
                },
                {
                    "cwe_id": "CWE-89",
                    "name": "SQL Injection"
                }
            ],
            "exploits": [
                {
                    "value": "http://www.exploit-db.com/exploits/99999",
                    "type": "Exploit Database"
                },
                {
                    "value": "http://packetstormsecurity.com/files/dummy-exploit",
                    "type": "Packet Storm"
                }
            ],
            "exploits_count": 2,
            "ext_references": [
                {
                    "value": "12345",
                    "type": "Snort Signature ID",
                    "created_at": "2024-01-15T00:00:00Z",
                    "description": "Dummy Snort signature for testing",
                    "url": "http://www.snort.org/sid/12345"
                },
                {
                    "value": "TEST-2024-001",
                    "type": "Security Advisory",
                    "created_at": "2024-01-10T00:00:00Z",
                    "description": "Test security advisory reference",
                    "url": "http://security.example.com/advisory/TEST-2024-001"
                }
            ],
            "nvd_additional_information": [
                {
                    "cve_id": "CVE-2024-0001",
                    "summary": "Dummy vulnerability summary from NVD for testing purposes. This describes a hypothetical security issue in a test application.",
                    "cwes": [
                        {
                            "cwe_id": "CWE-79",
                            "name": "Cross-site Scripting"
                        }
                    ],
                    "references": [
                        {
                            "name": "99999",
                            "url": "http://www.securityfocus.com/bid/99999"
                        },
                        {
                            "name": "TEST-ADV-2024",
                            "url": "http://security.example.com/advisory/test"
                        }
                    ],
                    "cvss_v2s": [
                        {
                            "access_vector": "NETWORK",
                            "access_complexity": "LOW",
                            "authentication": "NONE",
                            "confidentiality_impact": "PARTIAL",
                            "integrity_impact": "PARTIAL",
                            "availability_impact": "PARTIAL",
                            "score": 7.5
                        }
                    ],
                    "cvss_v3s": [
                        {
                            "attack_vector": "NETWORK",
                            "attack_complexity": "LOW",
                            "privileges_required": "NONE",
                            "user_interaction": "PARTIAL",
                            "scope": "PARTIAL",
                            "confidentiality_impact": "PARTIAL",
                            "integrity_impact": "PARTIAL",
                            "availability_impact": "PARTIAL",
                            "score": 7.5,
                            "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                            "version": "3.1"
                        }
                    ]
                }
            ],
            "classifications": [
                {
                    "name": "location_remote",
                    "longname": "Remote / Network Access",
                    "description": "This vulnerability can be exploited remotely over a network."
                },
                {
                    "name": "access_complexity_low",
                    "longname": "Low Access Complexity",
                    "description": "Exploitation requires minimal specialized access or circumstances."
                }
            ],
            "creditees": [
                {
                    "name": "Test Security Researcher"
                },
                {
                    "name": "Dummy Research Team"
                }
            ],
            "cvss_v2s": [
                {
                    "access_vector": "NETWORK",
                    "access_complexity": "LOW",
                    "authentication": "NONE",
                    "confidentiality_impact": "COMPLETE",
                    "integrity_impact": "COMPLETE",
                    "availability_impact": "COMPLETE",
                    "source": "http://nvd.nist.gov",
                    "generated_at": "2024-01-15T00:00:00Z",
                    "cve_id": "CVE-2024-0001",
                    "score": 10.0,
                    "calculated_cvss_base_score": 10.0
                }
            ],
            "cvss_v3s": [
                {
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "CHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                    "source": "http://nvd.nist.gov",
                    "generated_at": "2024-01-15T00:00:00Z",
                    "cve_id": "CVE-2024-0001",
                    "score": 9.8,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "version": "3.1",
                    "remediation_level": "Official Fix",
                    "report_confidence": "Confirmed",
                    "exploit_code_maturity": "Proof-of-Concept",
                    "temporal_score": "8.9",
                    "updated_at": "2024-06-15T10:30:00Z"
                }
            ],
            "cvss_v4s": [
                {
                    "score": 9.2,
                    "threat_score": 8.5,
                    "source": "http://nvd.nist.gov",
                    "generated_at": "2024-01-15T00:00:00Z",
                    "updated_at": "2024-06-15T10:30:00Z",
                    "cve_id": "CVE-2024-0001",
                    "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "version": "4.0",
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "attack_requirements": "NONE",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "exploit_maturity": "PROOF_OF_CONCEPT",
                    "vulnerable_system_confidentiality_impact": "HIGH",
                    "vulnerable_system_integrity_impact": "HIGH",
                    "vulnerable_system_availability_impact": "HIGH",
                    "subsequent_system_confidentiality_impact": "NONE",
                    "subsequent_system_integrity_impact": "NONE",
                    "subsequent_system_availability_impact": "NONE"
                }
            ],
            "tags": [
                "test",
                "dummy",
                "critical"
            ],
            "products": [
                {
                    "id": 99999,
                    "name": "Dummy Test Application",
                    "versions": [
                        {
                            "id": 88888,
                            "vulndb_version_id": 77777,
                            "name": "1.0",
                            "affected": "Affected",
                            "all_prior_versions_affected": true,
                            "cpes": [
                                {
                                    "name": "cpe:2.3:a:testvendor:dummyapp:1.0:*:*:*:*:*:*:*",
                                    "source": "Official"
                                }
                            ]
                        },
                        {
                            "id": 88889,
                            "vulndb_version_id": 77778,
                            "name": "1.5",
                            "affected": "Affected",
                            "all_prior_versions_affected": false,
                            "cpes": [
                                {
                                    "name": "cpe:2.3:a:testvendor:dummyapp:1.5:*:*:*:*:*:*:*",
                                    "source": "Official"
                                }
                            ]
                        }
                    ],
                    "vendor_id": 12345,
                    "vendor": "Test Vendor Corporation"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Ignite FP-VULN-123456 Vulnerability Details for: CVE-2024-0001, CVE-2024-0002
>
>### Vulnerability Information
>
>|ID|Title|Status|Keywords|Description|Solution|Technical Description|Exploits Count|Tags|Creditees|
>|---|---|---|---|---|---|---|---|---|---|
>| [123456](https://app.flashpoint.io/vuln/vulnerabilities/123456) | Dummy Vulnerability Title for Testing | Active | test, dummy, vulnerability | This is a dummy vulnerability description for testing purposes. It describes a hypothetical security flaw in a test application. | Apply the latest security patch or upgrade to version 2.0 or higher. | Technical details about the dummy vulnerability for testing. | 2 | test, dummy, critical | **-** _**name**_: Test Security Researcher<br>**-** _**name**_: Dummy Research Team |
>
>### Score Information
>
>|EPSS Score|EPSS v1 Score|Ransomware Score|Severity|Social Risk Scores|
>|---|---|---|---|---|
>| 0.75 | 0.68 | 0.45 | Critical | **-** _**cve_id**_: CVE-2024-0001<br> _**numeric_score**_: 8.5<br> _**categorical_score**_: High<br> _**score_date**_: 2024-06-15T10:30:00Z<br> _**todays_tweets**_: 25<br> _**total_tweets**_: 150<br> _**unique_users**_: 75 |
>
>### Timeline Information
>
>|Published At|Last Modified At|Discovered At|Disclosed At|Vendor Informed At|Vendor Acknowledged At|Solution Provided At|Exploited In The Wild At|Vendor Response Time|Time To Patch|Total Time To Patch|Time Unpatched|Time To Exploit|Total Time To Exploit|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2024-01-01T00:00:00Z | 2024-06-15T10:30:00Z | 2023-12-15T00:00:00Z | 2024-01-05T00:00:00Z | 2023-12-20T00:00:00Z | 2023-12-22T00:00:00Z | 2024-01-30T00:00:00Z | 2024-03-01T00:00:00Z | 2 days | 25 days | 46 days | 30 days, 0:00:00 | 40 days, 0:00:00 | 75 days |
>
>### CVSS v2 Scores
>
>|Score|Source|Generated At|CVE ID|Calculated CVSS Base Score|Access Vector|Access Complexity|Authentication|Confidentiality Impact|Integrity Impact|Availability Impact|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 10.0 | <http://nvd.nist.gov> | 2024-01-15T00:00:00Z | CVE-2024-0001 | 10.0 | NETWORK | LOW | NONE | COMPLETE | COMPLETE | COMPLETE |
>
>### CVSS v3 Scores
>
>|Score|Vector String|Source|Version|Updated At|Generated At|CVE ID|Temporal Score|Calculated CVSS Base Score|Attack Vector|Attack Complexity|Privileges Required|User Interaction|Scope|Confidentiality Impact|Integrity Impact|Availability Impact|Remediation Level|Report Confidence|Exploit Code Maturity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | <http://nvd.nist.gov> | 3.1 | 2024-06-15T10:30:00Z | 2024-01-15T00:00:00Z | CVE-2024-0001 | 8.9 | N/A | NETWORK | LOW | NONE | NONE | CHANGED | HIGH | HIGH | HIGH | Official Fix | Confirmed | Proof-of-Concept |
>
>### CVSS v4 Score
>
>|Score|Vector String|Threat Score|Source|Version|Generated At|Updated At|CVE ID|Attack Vector|Attack Complexity|Attack Requirements|Privileges Required|User Interaction|Exploit Maturity|Vulnerable System Confidentiality Impact|Vulnerable System Integrity Impact|Vulnerable System Availability Impact|Subsequent System Confidentiality Impact|Subsequent System Integrity Impact|Subsequent System Availability Impact|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 9.2 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 8.5 | <http://nvd.nist.gov> | 4.0 | 2024-01-15T00:00:00Z | 2024-06-15T10:30:00Z | CVE-2024-0001 | NETWORK | LOW | NONE | NONE | NONE | PROOF_OF_CONCEPT | HIGH | HIGH | HIGH | NONE | NONE | NONE |
>
>### Affected Products
>
>|Product ID|Product|Vendor ID|Vendor|Versions|
>|---|---|---|---|---|
>| 99999 | Dummy Test Application | 12345 | Test Vendor Corporation | **-** _**id**_: 88888<br> _**vulndb_version_id**_: 77777<br> _**name**_: 1.0<br> _**affected**_: Affected<br> _**all_prior_versions_affected**_: true<br> **cpes**:<br>  **-** _**name**_: cpe:2.3:a:testvendor:dummyapp:1.0:_:_:_:_:_:_:_<br>   _**source**_: Official<br>**-** _**id**_: 88889<br> _**vulndb_version_id**_: 77778<br> _**name**_: 1.5<br> _**affected**_: Affected<br> _**all_prior_versions_affected**_: false<br> **cpes**:<br>  **-** _**name**_: cpe:2.3:a:testvendor:dummyapp:1.5:_:_:_:_:_:_:_<br>   _**source**_: Official |
>
>### External References
>
>|Value|Type|URL|Description|Created At|
>|---|---|---|---|---|
>| 12345 | Snort Signature ID | [http://www.snort.org/sid/12345](http://www.snort.org/sid/12345) | Dummy Snort signature for testing | 2024-01-15T00:00:00Z |
>| TEST-2024-001 | Security Advisory | [http://security.example.com/advisory/TEST-2024-001](http://security.example.com/advisory/TEST-2024-001) | Test security advisory reference | 2024-01-10T00:00:00Z |
>
>### CWES
>
>|CWE ID|Name|Source|CVE IDs|
>|---|---|---|---|
>| CWE-79 | Improper Neutralization of Input During Web Page Generation | N/A | N/A |
>| CWE-89 | SQL Injection | N/A | N/A |
>
>### Exploits
>
>|Value|Type|
>|---|---|
>| <http://www.exploit-db.com/exploits/99999> | Exploit Database |
>| <http://packetstormsecurity.com/files/dummy-exploit> | Packet Storm |
>
>### Changelog
>
>|Created At|Description|
>|---|---|
>| 2024-06-15T10:30:00Z | Dummy Product Application version 1.5.0 by Test Vendor: Affected Status set to "Affected" |
>| 2024-05-20T14:20:00Z | Initial vulnerability entry created |

### cve

***
Retrieves detailed information about a specific CVE by its CVE ID.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | List of CVEs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE, for example: CVE-2015-1653. |
| CVE.CVSS | String | The CVSS of the CVE, for example: 10.0. |
| CVE.Version | String | The version of the CVE, for example: 3.0. |
| CVE.Vector | String | The vector of the CVE, for example: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N. |
| CVE.Table | String | The table of the CVE. |
| CVE.Published | Date | The timestamp of when the CVE was published. |
| CVE.Modified | Date | The timestamp of when the CVE was last modified. |
| CVE.Description | String | A description of the CVE. |
| CVE.Tags | String | The tags of the CVE. |
| CVE.VulnerableProducts | String | The vulnerable products of the CVE. |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Reliability | string | The reliability of the vendor. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Ignite.Vulnerability.id | Number | The unique identifier of the vulnerability. |
| Ignite.Vulnerability.cve_ids | Unknown | A list of CVE IDs associated with the vulnerability. |
| Ignite.Vulnerability.title | String | The title of the vulnerability. |
| Ignite.Vulnerability.keywords | String | A list of keywords associated with the vulnerability. |
| Ignite.Vulnerability.description | String | The description of the vulnerability. |
| Ignite.Vulnerability.solution | String | The solution or remediation steps for the vulnerability. |
| Ignite.Vulnerability.technical_description | String | The technical description of the vulnerability. |
| Ignite.Vulnerability.timelines.published_at | Date | The date when the vulnerability was published. |
| Ignite.Vulnerability.timelines.last_modified_at | Date | The date when the vulnerability was last modified. |
| Ignite.Vulnerability.timelines.exploit_published_at | Date | The date when the exploit was published. |
| Ignite.Vulnerability.timelines.discovered_at | Date | The date when the vulnerability was discovered. |
| Ignite.Vulnerability.timelines.disclosed_at | Date | The date when the vulnerability was disclosed. |
| Ignite.Vulnerability.timelines.vendor_informed_at | Date | The date when the vendor was informed. |
| Ignite.Vulnerability.timelines.vendor_acknowledged_at | Date | The date when the vendor acknowledged the vulnerability. |
| Ignite.Vulnerability.timelines.third_party_solution_provided_at | Date | The date when a third-party solution was provided. |
| Ignite.Vulnerability.timelines.solution_provided_at | Date | The date when a solution was provided. |
| Ignite.Vulnerability.timelines.exploited_in_the_wild_at | Date | The date when the vulnerability was exploited in the wild. |
| Ignite.Vulnerability.timelines.vendor_response_time | String | The time taken for vendor response. |
| Ignite.Vulnerability.timelines.time_to_patch | String | The time taken to patch the vulnerability. |
| Ignite.Vulnerability.timelines.total_time_to_patch | String | The total time taken to patch the vulnerability. |
| Ignite.Vulnerability.timelines.time_unpatched | String | The time the vulnerability remained unpatched. |
| Ignite.Vulnerability.timelines.time_to_exploit | String | The time taken to exploit the vulnerability. |
| Ignite.Vulnerability.timelines.total_time_to_exploit | String | The total time taken to exploit the vulnerability. |
| Ignite.Vulnerability.scores.epss_score | Number | An EPSS \(Exploit Prediction Scoring System\) score. |
| Ignite.Vulnerability.scores.epss_v1_score | Number | An EPSS version 1 score. |
| Ignite.Vulnerability.scores.ransomware_score | Number | A ransomware score. |
| Ignite.Vulnerability.scores.severity | String | The severity level of the vulnerability. |
| Ignite.Vulnerability.scores.social_risk_scores.cve_id | String | The CVE ID associated with the social risk score. |
| Ignite.Vulnerability.scores.social_risk_scores.numeric_score | Number | A numeric social risk score. |
| Ignite.Vulnerability.scores.social_risk_scores.categorical_score | String | A categorical social risk score. |
| Ignite.Vulnerability.scores.social_risk_scores.score_date | Date | The date when the social risk score was calculated. |
| Ignite.Vulnerability.scores.social_risk_scores.todays_tweets | Number | The number of tweets today about the vulnerability. |
| Ignite.Vulnerability.scores.social_risk_scores.total_tweets | Number | The total number of tweets about the vulnerability. |
| Ignite.Vulnerability.scores.social_risk_scores.unique_users | Number | The number of unique users discussing the vulnerability. |
| Ignite.Vulnerability.vuln_status | String | The status of the vulnerability. |
| Ignite.Vulnerability.alternate_vulndb_id | String | An alternate VulnDB ID. |
| Ignite.Vulnerability.changelog.created_at | Date | The date when the changelog entry was created. |
| Ignite.Vulnerability.changelog.description | String | The description of the changelog entry. |
| Ignite.Vulnerability.cwes.cwe_id | String | The CWE identifier. |
| Ignite.Vulnerability.cwes.name | String | The name of the CWE. |
| Ignite.Vulnerability.exploits.value | String | An exploit URL or identifier. |
| Ignite.Vulnerability.exploits.type | String | The type of exploit \(e.g., Exploit Database\). |
| Ignite.Vulnerability.exploits_count | Number | The count of exploits associated with the vulnerability. |
| Ignite.Vulnerability.ext_references.value | String | A value of the external reference. |
| Ignite.Vulnerability.ext_references.type | String | The type of external reference. |
| Ignite.Vulnerability.ext_references.created_at | Date | The date when the external reference was created. |
| Ignite.Vulnerability.ext_references.description | String | The description of the external reference. |
| Ignite.Vulnerability.ext_references.url | String | The URL of the external reference. |
| Ignite.Vulnerability.nvd_additional_information.cve_id | String | The CVE ID from NVD. |
| Ignite.Vulnerability.nvd_additional_information.summary | String | The summary from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cwes.cwe_id | String | The CWE identifier from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cwes.name | String | The name of the CWE from NVD. |
| Ignite.Vulnerability.nvd_additional_information.references.name | String | The name of the NVD reference. |
| Ignite.Vulnerability.nvd_additional_information.references.url | String | The URL of the NVD reference. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.access_vector | String | The CVSS v2 access vector from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.access_complexity | String | The CVSS v2 access complexity from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.authentication | String | The CVSS v2 authentication from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.confidentiality_impact | String | The CVSS v2 confidentiality impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.integrity_impact | String | The CVSS v2 integrity impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v2s.availability_impact | Number | The CVSS v2 availability impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.attack_vector | String | The CVSS v3 attack vector from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.attack_complexity | String | The CVSS v3 attack complexity from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.privileges_required | String | The CVSS v3 privileges required from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.user_interaction | String | The CVSS v3 user interaction from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.scope | String | The CVSS v3 scope from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.confidentiality_impact | String | The CVSS v3 confidentiality impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.integrity_impact | String | The CVSS v3 integrity impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.availability_impact | String | The CVSS v3 availability impact from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.score | Number | The CVSS v3 score from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.vector_string | String | The CVSS v3 vector string from NVD. |
| Ignite.Vulnerability.nvd_additional_information.cvss_v3s.version | String | The CVSS v3 version from NVD. |
| Ignite.Vulnerability.classifications.name | String | The name of the classification. |
| Ignite.Vulnerability.classifications.longname | String | The long name of the classification. |
| Ignite.Vulnerability.classifications.description | String | The description of the classification. |
| Ignite.Vulnerability.creditees.name | String | The name of the individual or organization credited. |
| Ignite.Vulnerability.cvss_v2s.access_vector | String | The CVSS v2 access vector. |
| Ignite.Vulnerability.cvss_v2s.access_complexity | String | The CVSS v2 access complexity. |
| Ignite.Vulnerability.cvss_v2s.authentication | String | The CVSS v2 authentication. |
| Ignite.Vulnerability.cvss_v2s.confidentiality_impact | String | The CVSS v2 confidentiality impact. |
| Ignite.Vulnerability.cvss_v2s.integrity_impact | String | The CVSS v2 integrity impact. |
| Ignite.Vulnerability.cvss_v2s.availability_impact | String | The CVSS v2 availability impact. |
| Ignite.Vulnerability.cvss_v2s.source | String | The source of the CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.generated_at | Date | The date when the CVSS v2 score was generated. |
| Ignite.Vulnerability.cvss_v2s.cve_id | String | The CVE ID associated with the CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.score | Number | The CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.calculated_cvss_base_score | Number | A calculated CVSS v2 base score. |
| Ignite.Vulnerability.cvss_v3s.attack_vector | String | The CVSS v3 attack vector. |
| Ignite.Vulnerability.cvss_v3s.attack_complexity | String | The CVSS v3 attack complexity. |
| Ignite.Vulnerability.cvss_v3s.privileges_required | String | The CVSS v3 privileges required. |
| Ignite.Vulnerability.cvss_v3s.user_interaction | String | The CVSS v3 user interaction. |
| Ignite.Vulnerability.cvss_v3s.scope | String | The CVSS v3 scope. |
| Ignite.Vulnerability.cvss_v3s.confidentiality_impact | String | The CVSS v3 confidentiality impact. |
| Ignite.Vulnerability.cvss_v3s.integrity_impact | String | The CVSS v3 integrity impact. |
| Ignite.Vulnerability.cvss_v3s.availability_impact | String | The CVSS v3 availability impact. |
| Ignite.Vulnerability.cvss_v3s.source | String | The source of the CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.generated_at | Date | The date when the CVSS v3 score was generated. |
| Ignite.Vulnerability.cvss_v3s.cve_id | String | The CVE ID associated with the CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.score | Number | The CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.vector_string | String | The CVSS v3 vector string. |
| Ignite.Vulnerability.cvss_v3s.version | String | The CVSS v3 version. |
| Ignite.Vulnerability.cvss_v3s.remediation_level | String | The CVSS v3 remediation level. |
| Ignite.Vulnerability.cvss_v3s.report_confidence | String | The CVSS v3 report confidence. |
| Ignite.Vulnerability.cvss_v3s.exploit_code_maturity | String | The CVSS v3 exploit code maturity. |
| Ignite.Vulnerability.cvss_v3s.temporal_score | String | The CVSS v3 temporal score. |
| Ignite.Vulnerability.cvss_v3s.updated_at | Date | The date when the CVSS v3 score was updated. |
| Ignite.Vulnerability.cvss_v4s.score | Number | The CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.threat_score | Number | The CVSS v4 threat score. |
| Ignite.Vulnerability.cvss_v4s.source | String | The source of the CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.generated_at | Date | The date when the CVSS v4 score was generated. |
| Ignite.Vulnerability.cvss_v4s.updated_at | Date | The date when the CVSS v4 score was updated. |
| Ignite.Vulnerability.cvss_v4s.cve_id | String | The CVE ID associated with the CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.vector_string | String | The CVSS v4 vector string. |
| Ignite.Vulnerability.cvss_v4s.version | String | The CVSS v4 version. |
| Ignite.Vulnerability.cvss_v4s.attack_vector | String | The CVSS v4 attack vector. |
| Ignite.Vulnerability.cvss_v4s.attack_complexity | String | The CVSS v4 attack complexity. |
| Ignite.Vulnerability.cvss_v4s.attack_requirements | String | The CVSS v4 attack requirements. |
| Ignite.Vulnerability.cvss_v4s.privileges_required | String | The CVSS v4 privileges required. |
| Ignite.Vulnerability.cvss_v4s.user_interaction | String | The CVSS v4 user interaction. |
| Ignite.Vulnerability.cvss_v4s.exploit_maturity | String | The CVSS v4 exploit maturity. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_confidentiality_impact | String | The CVSS v4 vulnerable system confidentiality impact. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_integrity_impact | String | The CVSS v4 vulnerable system integrity impact. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_availability_impact | String | The CVSS v4 vulnerable system availability impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_confidentiality_impact | String | The CVSS v4 subsequent system confidentiality impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_integrity_impact | String | The CVSS v4 subsequent system integrity impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_availability_impact | String | The CVSS v4 subsequent system availability impact. |
| Ignite.Vulnerability.tags | String | The tags associated with the vulnerability. |
| Ignite.Vulnerability.products.id | Number | The ID of the affected product. |
| Ignite.Vulnerability.products.name | String | The name of the affected product. |
| Ignite.Vulnerability.products.vendor_id | Number | The vendor ID of the affected product. |
| Ignite.Vulnerability.products.vendor | String | The vendor name of the affected product. |
| Ignite.Vulnerability.products.versions.id | Number | The ID of the product version. |
| Ignite.Vulnerability.products.versions.vulndb_version_id | Number | The VulnDB version ID. |
| Ignite.Vulnerability.products.versions.name | String | The name of the product version. |
| Ignite.Vulnerability.products.versions.affected | String | A string indicating whether the product version is affected. |
| Ignite.Vulnerability.products.versions.all_prior_versions_affected | Boolean | A boolean indicating whether all prior versions are affected. |
| Ignite.Vulnerability.products.versions.cpes.name | String | The CPE \(Common Platform Enumeration\) name. |
| Ignite.Vulnerability.products.versions.cpes.source | String | The source of the CPE. |

#### Command Example

```
!cve cve="CVE-2024-0002"
```

#### Context Example

``` json
{
    "CVE": [
        {
            "CVSS": {
                "Score": 9.2,
                "Table": [
                    {
                        "metrics": "score",
                        "value": 9.2
                    },
                    {
                        "metrics": "threat_score",
                        "value": 8.5
                    },
                    {
                        "metrics": "source",
                        "value": "http://nvd.nist.gov"
                    },
                    {
                        "metrics": "generated_at",
                        "value": "2024-01-15T00:00:00Z"
                    },
                    {
                        "metrics": "updated_at",
                        "value": "2024-06-15T10:30:00Z"
                    },
                    {
                        "metrics": "cve_id",
                        "value": "CVE-2024-0001"
                    },
                    {
                        "metrics": "vector_string",
                        "value": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    },
                    {
                        "metrics": "version",
                        "value": "4.0"
                    },
                    {
                        "metrics": "attack_vector",
                        "value": "NETWORK"
                    },
                    {
                        "metrics": "attack_complexity",
                        "value": "LOW"
                    },
                    {
                        "metrics": "attack_requirements",
                        "value": "NONE"
                    },
                    {
                        "metrics": "privileges_required",
                        "value": "NONE"
                    },
                    {
                        "metrics": "user_interaction",
                        "value": "NONE"
                    },
                    {
                        "metrics": "exploit_maturity",
                        "value": "PROOF_OF_CONCEPT"
                    },
                    {
                        "metrics": "vulnerable_system_confidentiality_impact",
                        "value": "HIGH"
                    },
                    {
                        "metrics": "vulnerable_system_integrity_impact",
                        "value": "HIGH"
                    },
                    {
                        "metrics": "vulnerable_system_availability_impact",
                        "value": "HIGH"
                    },
                    {
                        "metrics": "subsequent_system_confidentiality_impact",
                        "value": "NONE"
                    },
                    {
                        "metrics": "subsequent_system_integrity_impact",
                        "value": "NONE"
                    },
                    {
                        "metrics": "subsequent_system_availability_impact",
                        "value": "NONE"
                    }
                ],
                "Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Version": "4.0"
            },
            "Description": "This is a dummy vulnerability description for testing purposes. It describes a hypothetical security flaw in a test application.",
            "ID": "CVE-2024-0002",
            "Modified": "2024-06-15T10:30:00Z",
            "Published": "2024-01-01T00:00:00Z",
            "Tags": [
                "test",
                "dummy",
                "critical"
            ],
            "VulnerableProducts": [
                {
                    "CPE": "cpe:2.3:a:testvendor:dummyapp:1.0:*:*:*:*:*:*:*"
                },
                {
                    "CPE": "cpe:2.3:a:testvendor:dummyapp:1.5:*:*:*:*:*:*:*"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "CVE-2024-0002",
            "Score": 0,
            "Type": "cve",
            "Vendor": "Ignite"
        }
    ],
    "Ignite": {
        "Vulnerability": {
            "id": 123456,
            "cve_ids": [
                "CVE-2024-0001",
                "CVE-2024-0002"
            ],
            "title": "Dummy Vulnerability Title for Testing",
            "keywords": "test, dummy, vulnerability",
            "description": "This is a dummy vulnerability description for testing purposes. It describes a hypothetical security flaw in a test application.",
            "solution": "Apply the latest security patch or upgrade to version 2.0 or higher.",
            "technical_description": "Technical details about the dummy vulnerability for testing.",
            "timelines": {
                "published_at": "2024-01-01T00:00:00Z",
                "last_modified_at": "2024-06-15T10:30:00Z",
                "exploit_published_at": "2024-02-10T00:00:00Z",
                "discovered_at": "2023-12-15T00:00:00Z",
                "disclosed_at": "2024-01-05T00:00:00Z",
                "vendor_informed_at": "2023-12-20T00:00:00Z",
                "vendor_acknowledged_at": "2023-12-22T00:00:00Z",
                "solution_provided_at": "2024-01-30T00:00:00Z",
                "exploited_in_the_wild_at": "2024-03-01T00:00:00Z",
                "vendor_response_time": "2 days",
                "time_to_patch": "25 days",
                "total_time_to_patch": "46 days",
                "time_unpatched": "30 days, 0:00:00",
                "time_to_exploit": "40 days, 0:00:00",
                "total_time_to_exploit": "75 days"
            },
            "scores": {
                "epss_score": 0.75,
                "epss_v1_score": 0.68,
                "ransomware_score": 0.45,
                "severity": "Critical",
                "social_risk_scores": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "numeric_score": 8.5,
                        "categorical_score": "High",
                        "score_date": "2024-06-15T10:30:00Z",
                        "todays_tweets": 25,
                        "total_tweets": 150,
                        "unique_users": 75
                    }
                ]
            },
            "vuln_status": "Active",
            "changelog": [
                {
                    "created_at": "2024-06-15T10:30:00Z",
                    "description": "Dummy Product Application version 1.5.0 by Test Vendor: Affected Status set to \"Affected\""
                },
                {
                    "created_at": "2024-05-20T14:20:00Z",
                    "description": "Initial vulnerability entry created"
                }
            ],
            "cwes": [
                {
                    "cwe_id": "CWE-79",
                    "name": "Improper Neutralization of Input During Web Page Generation"
                },
                {
                    "cwe_id": "CWE-89",
                    "name": "SQL Injection"
                }
            ],
            "exploits": [
                {
                    "value": "http://www.exploit-db.com/exploits/99999",
                    "type": "Exploit Database"
                },
                {
                    "value": "http://packetstormsecurity.com/files/dummy-exploit",
                    "type": "Packet Storm"
                }
            ],
            "exploits_count": 2,
            "ext_references": [
                {
                    "value": "12345",
                    "type": "Snort Signature ID",
                    "created_at": "2024-01-15T00:00:00Z",
                    "description": "Dummy Snort signature for testing",
                    "url": "http://www.snort.org/sid/12345"
                },
                {
                    "value": "TEST-2024-001",
                    "type": "Security Advisory",
                    "created_at": "2024-01-10T00:00:00Z",
                    "description": "Test security advisory reference",
                    "url": "http://security.example.com/advisory/TEST-2024-001"
                }
            ],
            "nvd_additional_information": [
                {
                    "cve_id": "CVE-2024-0001",
                    "summary": "Dummy vulnerability summary from NVD for testing purposes. This describes a hypothetical security issue in a test application.",
                    "cwes": [
                        {
                            "cwe_id": "CWE-79",
                            "name": "Cross-site Scripting"
                        }
                    ],
                    "references": [
                        {
                            "name": "99999",
                            "url": "http://www.securityfocus.com/bid/99999"
                        },
                        {
                            "name": "TEST-ADV-2024",
                            "url": "http://security.example.com/advisory/test"
                        }
                    ],
                    "cvss_v2s": [
                        {
                            "access_vector": "NETWORK",
                            "access_complexity": "LOW",
                            "authentication": "NONE",
                            "confidentiality_impact": "PARTIAL",
                            "integrity_impact": "PARTIAL",
                            "availability_impact": "PARTIAL",
                            "score": 7.5
                        }
                    ],
                    "cvss_v3s": [
                        {
                            "attack_vector": "NETWORK",
                            "attack_complexity": "LOW",
                            "privileges_required": "NONE",
                            "user_interaction": "PARTIAL",
                            "scope": "PARTIAL",
                            "confidentiality_impact": "PARTIAL",
                            "integrity_impact": "PARTIAL",
                            "availability_impact": "PARTIAL",
                            "score": 7.5,
                            "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                            "version": "3.1"
                        }
                    ]
                }
            ],
            "classifications": [
                {
                    "name": "location_remote",
                    "longname": "Remote / Network Access",
                    "description": "This vulnerability can be exploited remotely over a network."
                },
                {
                    "name": "access_complexity_low",
                    "longname": "Low Access Complexity",
                    "description": "Exploitation requires minimal specialized access or circumstances."
                }
            ],
            "creditees": [
                {
                    "name": "Test Security Researcher"
                },
                {
                    "name": "Dummy Research Team"
                }
            ],
            "cvss_v2s": [
                {
                    "access_vector": "NETWORK",
                    "access_complexity": "LOW",
                    "authentication": "NONE",
                    "confidentiality_impact": "COMPLETE",
                    "integrity_impact": "COMPLETE",
                    "availability_impact": "COMPLETE",
                    "source": "http://nvd.nist.gov",
                    "generated_at": "2024-01-15T00:00:00Z",
                    "cve_id": "CVE-2024-0001",
                    "score": 10.0,
                    "calculated_cvss_base_score": 10.0
                }
            ],
            "cvss_v3s": [
                {
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "CHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                    "source": "http://nvd.nist.gov",
                    "generated_at": "2024-01-15T00:00:00Z",
                    "cve_id": "CVE-2024-0001",
                    "score": 9.8,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "version": "3.1",
                    "remediation_level": "Official Fix",
                    "report_confidence": "Confirmed",
                    "exploit_code_maturity": "Proof-of-Concept",
                    "temporal_score": "8.9",
                    "updated_at": "2024-06-15T10:30:00Z"
                }
            ],
            "cvss_v4s": [
                {
                    "score": 9.2,
                    "threat_score": 8.5,
                    "source": "http://nvd.nist.gov",
                    "generated_at": "2024-01-15T00:00:00Z",
                    "updated_at": "2024-06-15T10:30:00Z",
                    "cve_id": "CVE-2024-0001",
                    "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "version": "4.0",
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "attack_requirements": "NONE",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "exploit_maturity": "PROOF_OF_CONCEPT",
                    "vulnerable_system_confidentiality_impact": "HIGH",
                    "vulnerable_system_integrity_impact": "HIGH",
                    "vulnerable_system_availability_impact": "HIGH",
                    "subsequent_system_confidentiality_impact": "NONE",
                    "subsequent_system_integrity_impact": "NONE",
                    "subsequent_system_availability_impact": "NONE"
                }
            ],
            "tags": [
                "test",
                "dummy",
                "critical"
            ],
            "products": [
                {
                    "id": 99999,
                    "name": "Dummy Test Application",
                    "versions": [
                        {
                            "id": 88888,
                            "vulndb_version_id": 77777,
                            "name": "1.0",
                            "affected": "Affected",
                            "all_prior_versions_affected": true,
                            "cpes": [
                                {
                                    "name": "cpe:2.3:a:testvendor:dummyapp:1.0:*:*:*:*:*:*:*",
                                    "source": "Official"
                                }
                            ]
                        },
                        {
                            "id": 88889,
                            "vulndb_version_id": 77778,
                            "name": "1.5",
                            "affected": "Affected",
                            "all_prior_versions_affected": false,
                            "cpes": [
                                {
                                    "name": "cpe:2.3:a:testvendor:dummyapp:1.5:*:*:*:*:*:*:*",
                                    "source": "Official"
                                }
                            ]
                        }
                    ],
                    "vendor_id": 12345,
                    "vendor": "Test Vendor Corporation"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Ignite CVE Details for: CVE-2024-0001, CVE-2024-0002
>
>### Vulnerability Information
>
>|ID|Title|Status|Keywords|Description|Solution|Technical Description|Exploits Count|Tags|Creditees|
>|---|---|---|---|---|---|---|---|---|---|
>| [123456](https://app.flashpoint.io/vuln/vulnerabilities/123456) | Dummy Vulnerability Title for Testing | Active | test, dummy, vulnerability | This is a dummy vulnerability description for testing purposes. It describes a hypothetical security flaw in a test application. | Apply the latest security patch or upgrade to version 2.0 or higher. | Technical details about the dummy vulnerability for testing. | 2 | test, dummy, critical | **-** _**name**_: Test Security Researcher<br>**-** _**name**_: Dummy Research Team |
>
>### Score Information
>
>|EPSS Score|EPSS v1 Score|Ransomware Score|Severity|Social Risk Scores|
>|---|---|---|---|---|
>| 0.75 | 0.68 | 0.45 | Critical | **-** _**cve_id**_: CVE-2024-0001<br> _**numeric_score**_: 8.5<br> _**categorical_score**_: High<br> _**score_date**_: 2024-06-15T10:30:00Z<br> _**todays_tweets**_: 25<br> _**total_tweets**_: 150<br> _**unique_users**_: 75 |
>
>### Timeline Information
>
>|Published At|Last Modified At|Discovered At|Disclosed At|Vendor Informed At|Vendor Acknowledged At|Solution Provided At|Exploited In The Wild At|Vendor Response Time|Time To Patch|Total Time To Patch|Time Unpatched|Time To Exploit|Total Time To Exploit|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2024-01-01T00:00:00Z | 2024-06-15T10:30:00Z | 2023-12-15T00:00:00Z | 2024-01-05T00:00:00Z | 2023-12-20T00:00:00Z | 2023-12-22T00:00:00Z | 2024-01-30T00:00:00Z | 2024-03-01T00:00:00Z | 2 days | 25 days | 46 days | 30 days, 0:00:00 | 40 days, 0:00:00 | 75 days |
>
>### CVSS v2 Scores
>
>|Score|Source|Generated At|CVE ID|Calculated CVSS Base Score|Access Vector|Access Complexity|Authentication|Confidentiality Impact|Integrity Impact|Availability Impact|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 10.0 | <http://nvd.nist.gov> | 2024-01-15T00:00:00Z | CVE-2024-0001 | 10.0 | NETWORK | LOW | NONE | COMPLETE | COMPLETE | COMPLETE |
>
>### CVSS v3 Scores
>
>|Score|Vector String|Source|Version|Updated At|Generated At|CVE ID|Temporal Score|Calculated CVSS Base Score|Attack Vector|Attack Complexity|Privileges Required|User Interaction|Scope|Confidentiality Impact|Integrity Impact|Availability Impact|Remediation Level|Report Confidence|Exploit Code Maturity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | <http://nvd.nist.gov> | 3.1 | 2024-06-15T10:30:00Z | 2024-01-15T00:00:00Z | CVE-2024-0001 | 8.9 | N/A | NETWORK | LOW | NONE | NONE | CHANGED | HIGH | HIGH | HIGH | Official Fix | Confirmed | Proof-of-Concept |
>
>### CVSS v4 Score
>
>|Score|Vector String|Threat Score|Source|Version|Generated At|Updated At|CVE ID|Attack Vector|Attack Complexity|Attack Requirements|Privileges Required|User Interaction|Exploit Maturity|Vulnerable System Confidentiality Impact|Vulnerable System Integrity Impact|Vulnerable System Availability Impact|Subsequent System Confidentiality Impact|Subsequent System Integrity Impact|Subsequent System Availability Impact|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 9.2 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 8.5 | <http://nvd.nist.gov> | 4.0 | 2024-01-15T00:00:00Z | 2024-06-15T10:30:00Z | CVE-2024-0001 | NETWORK | LOW | NONE | NONE | NONE | PROOF_OF_CONCEPT | HIGH | HIGH | HIGH | NONE | NONE | NONE |
>
>### Affected Products
>
>|Product ID|Product|Vendor ID|Vendor|Versions|
>|---|---|---|---|---|
>| 99999 | Dummy Test Application | 12345 | Test Vendor Corporation | **-** _**id**_: 88888<br> _**vulndb_version_id**_: 77777<br> _**name**_: 1.0<br> _**affected**_: Affected<br> _**all_prior_versions_affected**_: true<br> **cpes**:<br>  **-** _**name**_: cpe:2.3:a:testvendor:dummyapp:1.0:_:_:_:_:_:_:_<br>   _**source**_: Official<br>**-** _**id**_: 88889<br> _**vulndb_version_id**_: 77778<br> _**name**_: 1.5<br> _**affected**_: Affected<br> _**all_prior_versions_affected**_: false<br> **cpes**:<br>  **-** _**name**_: cpe:2.3:a:testvendor:dummyapp:1.5:_:_:_:_:_:_:_<br>   _**source**_: Official |
>
>### External References
>
>|Value|Type|URL|Description|Created At|
>|---|---|---|---|---|
>| 12345 | Snort Signature ID | [http://www.snort.org/sid/12345](http://www.snort.org/sid/12345) | Dummy Snort signature for testing | 2024-01-15T00:00:00Z |
>| TEST-2024-001 | Security Advisory | [http://security.example.com/advisory/TEST-2024-001](http://security.example.com/advisory/TEST-2024-001) | Test security advisory reference | 2024-01-10T00:00:00Z |
>
>### CWES
>
>|CWE ID|Name|Source|CVE IDs|
>|---|---|---|---|
>| CWE-79 | Improper Neutralization of Input During Web Page Generation | N/A | N/A |
>| CWE-89 | SQL Injection | N/A | N/A |
>
>### Exploits
>
>|Value|Type|
>|---|---|
>| <http://www.exploit-db.com/exploits/99999> | Exploit Database |
>| <http://packetstormsecurity.com/files/dummy-exploit> | Packet Storm |
>
>### Changelog
>
>|Created At|Description|
>|---|---|
>| 2024-06-15T10:30:00Z | Dummy Product Application version 1.5.0 by Test Vendor: Affected Status set to "Affected" |
>| 2024-05-20T14:20:00Z | Initial vulnerability entry created |

### flashpoint-ignite-vulnerability-list

***
List Vulnerabilities using provided filters.

#### Base Command

`flashpoint-ignite-vulnerability-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| updated_after | Get vulnerabilities that were updated after the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| updated_before | Get vulnerabilities that were updated before the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| disclosed_after | Get vulnerabilities that were disclosed after the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| disclosed_before | Get vulnerabilities that were disclosed before the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| published_after | Get vulnerabilities that were published after the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| published_before | Get vulnerabilities that were published before the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| last_touched_after | Get vulnerabilities that were last touched after the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| last_touched_before | Get vulnerabilities that were last touched before the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| ransomware_scores | Filter by Ransomware score. Possible values are: Critical, High, Medium, Low. | Optional |
| attack_types | Filter by Attack type classification. Possible values are: Authentication Management, Cryptographic, Infrastructure, Input Manipulation, Misconfiguration, Man-In-The-Middle (MITM), Other, Race Condition, Attack Type Unknown. | Optional |
| severities | Filter by severity, which is calculated based on CVSS values. Possible values are: Critical, High, Medium, Low, Informational. | Optional |
| products | Filter by associated product names \(case-insensitive\). | Optional |
| vendors | Filter by associated vendor names \(case-insensitive\). | Optional |
| cwe_ids | Filter by CWE IDs assigned by Mitre. | Optional |
| min_cvssv2_score | Filter by lower limit of the CVSSv2 score. Prioritizes Flashpoint generated scores when possible. Example value 7.0<br/><br/>Note: Value must be a float between 0 and 10. | Optional |
| max_cvssv2_score | Filter by upper limit of the CVSSv2 score. Prioritizes Flashpoint generated scores when possible. Example value 10.0<br/><br/>Note: Value must be a float between 0 and 10. | Optional |
| min_cvssv3_score | Filter by lower limit of the CVSSv3 score. Prioritizes Flashpoint generated scores when possible. Example value 7.0<br/><br/>Note: Value must be a float between 0 and 10. | Optional |
| max_cvssv3_score | Filter by upper limit of the CVSSv3 score. Prioritizes Flashpoint generated scores when possible. Example value 10.0<br/><br/>Note: Value must be a float between 0 and 10. | Optional |
| min_cvssv4_score | Filter by lower limit of the CVSSv4 score. Prioritizes Flashpoint generated scores when possible. Example value 7.0<br/><br/>Note: Value must be a float between 0 and 10. | Optional |
| max_cvssv4_score | Filter by upper limit of the CVSSv4 score. Prioritizes Flashpoint generated scores when possible. Example value 10.0<br/><br/>Note: Value must be a float between 0 and 10. | Optional |
| ref_types | Filter by reference types. Possible values are: Bug Tracker, Bugtraq ID, CERT, CERT VU, CIAC Advisory, CVE ID, D2 Elliot, DISA IAVA, Exploit Activity, Exploit Database, Flashpoint, Generic Exploit URL, Generic Informational URL, Immunity CANVAS, Immunity CANVAS (D2ExploitPack), Immunity CANVAS (White Phosphorus), ISS X-Force ID, Japan Vulnerability Notes, Keyword, Mail List Post, Metasploit URL, Microsoft Knowledge Base Article, Microsoft Security Bulletin, Nessus Script ID, News Article, Nikto Item ID, Other Advisory URL, Other Solution URL, OVAL ID, Packet Storm, RedHat RHSA, Related VulnDB ID, SCIP VulDB ID, Secunia Advisory ID, Security Tracker, Snort Signature ID, Tenable PVS, US-CERT Cyber Security Alert, Vendor Specific Advisory URL, Vendor Specific Solution URL, Vendor URL, Vendor Specific News/Changelog Entry, VUPEN Advisory. | Optional |
| ref_values | Filter by reference values. Use with Reference Types to filter by specific reference type. | Optional |
| locations | Filter by location type classification. Possible values are: Context Dependent, Dial-up Access Required, Local Access Required, Legacy: Local / Remote, Mobile Phone / Hand-held Device, Physical Access Required, Remote / Network Access, Location Unknown, Wireless Vector. | Optional |
| min_epss_score | Filter by lower limit of the EPSS v3 score. Example value 0.5<br/><br/>Note: Value must be a float between 0 and 1. | Optional |
| max_epss_score | Filter by upper limit of the EPSS v3 score. Example value 1.0<br/><br/>Note: Value must be a float between 0 and 1. | Optional |
| tags | Filter vulnerabilities by tags. | Optional |
| size | Number of vulnerabilities to return per page. Maximum value: 1000. Default is 10. | Optional |
| from | The offset to retrieve next page data. Used for pagination only. Default is 0. | Optional |
| sort_by | Specify the field used to sort the vulnerabilities. Possible values are: ID, Severity, Title, CVSSv3 Score, Published At. Default is Published At. | Optional |
| sort_order | Specify the order used to sort the vulnerabilities. Possible values are: Asc, Desc. Default is Desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Vulnerability.id | Number | The unique identifier of the vulnerability. |
| Ignite.Vulnerability.cve_ids | Unknown | A list of CVE IDs associated with the vulnerability. |
| Ignite.Vulnerability.title | String | The title of the vulnerability. |
| Ignite.Vulnerability.keywords | String | A list of keywords associated with the vulnerability. |
| Ignite.Vulnerability.description | String | The description of the vulnerability. |
| Ignite.Vulnerability.solution | String | The solution or remediation steps for the vulnerability. |
| Ignite.Vulnerability.technical_description | String | The technical description of the vulnerability. |
| Ignite.Vulnerability.timelines.published_at | Date | The date when the vulnerability was published. |
| Ignite.Vulnerability.timelines.last_modified_at | Date | The date when the vulnerability was last modified. |
| Ignite.Vulnerability.timelines.exploit_published_at | Date | The date when the exploit was published. |
| Ignite.Vulnerability.timelines.discovered_at | Date | The date when the vulnerability was discovered. |
| Ignite.Vulnerability.timelines.disclosed_at | Date | The date when the vulnerability was disclosed. |
| Ignite.Vulnerability.timelines.vendor_informed_at | Date | The date when the vendor was informed. |
| Ignite.Vulnerability.timelines.vendor_acknowledged_at | Date | The date when the vendor acknowledged the vulnerability. |
| Ignite.Vulnerability.timelines.third_party_solution_provided_at | Date | The date when a third-party solution was provided. |
| Ignite.Vulnerability.timelines.solution_provided_at | Date | The date when a solution was provided. |
| Ignite.Vulnerability.timelines.exploited_in_the_wild_at | Date | The date when the vulnerability was exploited in the wild. |
| Ignite.Vulnerability.scores.epss_score | Number | An EPSS \(Exploit Prediction Scoring System\) score. |
| Ignite.Vulnerability.scores.cvssv3_score | Number | A CVSS v3 score. |
| Ignite.Vulnerability.scores.epss_v1_score | Number | An EPSS version 1 score. |
| Ignite.Vulnerability.scores.ransomware_score | Number | A ransomware score. |
| Ignite.Vulnerability.scores.severity | String | The severity level of the vulnerability. |
| Ignite.Vulnerability.vuln_status | String | The status of the vulnerability. |
| Ignite.Vulnerability.cwes.cwe_id | String | The CWE identifier. |
| Ignite.Vulnerability.cwes.name | String | The name of the CWE. |
| Ignite.Vulnerability.ext_references.value | String | A value of the external reference. |
| Ignite.Vulnerability.ext_references.type | String | The type of external reference. |
| Ignite.Vulnerability.ext_references.created_at | Date | The date when the external reference was created. |
| Ignite.Vulnerability.ext_references.description | String | The description of the external reference. |
| Ignite.Vulnerability.ext_references.url | String | The URL of the external reference. |
| Ignite.Vulnerability.classifications.name | String | The name of the classification. |
| Ignite.Vulnerability.classifications.longname | String | The long name of the classification. |
| Ignite.Vulnerability.classifications.description | String | The description of the classification. |
| Ignite.Vulnerability.exploits.value | String | An exploit URL or identifier. |
| Ignite.Vulnerability.exploits.type | String | The type of exploit \(e.g., Exploit Database\). |
| Ignite.Vulnerability.exploits_count | Number | The count of exploits associated with the vulnerability. |
| Ignite.Vulnerability.cvss_v2s.access_vector | String | The CVSS v2 access vector. |
| Ignite.Vulnerability.cvss_v2s.access_complexity | String | The CVSS v2 access complexity. |
| Ignite.Vulnerability.cvss_v2s.authentication | String | The CVSS v2 authentication. |
| Ignite.Vulnerability.cvss_v2s.confidentiality_impact | String | The CVSS v2 confidentiality impact. |
| Ignite.Vulnerability.cvss_v2s.integrity_impact | String | The CVSS v2 integrity impact. |
| Ignite.Vulnerability.cvss_v2s.availability_impact | String | The CVSS v2 availability impact. |
| Ignite.Vulnerability.cvss_v2s.source | String | The source of the CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.generated_at | Date | The date when the CVSS v2 score was generated. |
| Ignite.Vulnerability.cvss_v2s.cve_id | String | The CVE ID associated with the CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.score | Number | The CVSS v2 score. |
| Ignite.Vulnerability.cvss_v2s.calculated_cvss_base_score | Number | A calculated CVSS v2 base score. |
| Ignite.Vulnerability.cvss_v3s.attack_vector | String | The CVSS v3 attack vector. |
| Ignite.Vulnerability.cvss_v3s.attack_complexity | String | The CVSS v3 attack complexity. |
| Ignite.Vulnerability.cvss_v3s.privileges_required | String | The CVSS v3 privileges required. |
| Ignite.Vulnerability.cvss_v3s.user_interaction | String | The CVSS v3 user interaction. |
| Ignite.Vulnerability.cvss_v3s.scope | String | The CVSS v3 scope. |
| Ignite.Vulnerability.cvss_v3s.confidentiality_impact | String | The CVSS v3 confidentiality impact. |
| Ignite.Vulnerability.cvss_v3s.integrity_impact | String | The CVSS v3 integrity impact. |
| Ignite.Vulnerability.cvss_v3s.availability_impact | String | The CVSS v3 availability impact. |
| Ignite.Vulnerability.cvss_v3s.source | String | The source of the CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.generated_at | Date | The date when the CVSS v3 score was generated. |
| Ignite.Vulnerability.cvss_v3s.cve_id | String | The CVE ID associated with the CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.score | Number | The CVSS v3 score. |
| Ignite.Vulnerability.cvss_v3s.calculated_cvss_base_score | Number | A calculated CVSS v3 base score. |
| Ignite.Vulnerability.cvss_v3s.vector_string | String | The CVSS v3 vector string. |
| Ignite.Vulnerability.cvss_v3s.version | String | The CVSS v3 version. |
| Ignite.Vulnerability.cvss_v3s.remediation_level | String | The CVSS v3 remediation level. |
| Ignite.Vulnerability.cvss_v3s.report_confidence | String | The CVSS v3 report confidence. |
| Ignite.Vulnerability.cvss_v3s.exploit_code_maturity | String | The CVSS v3 exploit code maturity. |
| Ignite.Vulnerability.cvss_v3s.temporal_score | Number | The CVSS v3 temporal score. |
| Ignite.Vulnerability.cvss_v3s.updated_at | Date | The date when the CVSS v3 score was updated. |
| Ignite.Vulnerability.cvss_v4s.score | Number | The CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.threat_score | Number | The CVSS v4 threat score. |
| Ignite.Vulnerability.cvss_v4s.source | String | The source of the CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.generated_at | Date | The date when the CVSS v4 score was generated. |
| Ignite.Vulnerability.cvss_v4s.updated_at | Date | The date when the CVSS v4 score was updated. |
| Ignite.Vulnerability.cvss_v4s.cve_id | String | The CVE ID associated with the CVSS v4 score. |
| Ignite.Vulnerability.cvss_v4s.vector_string | String | The CVSS v4 vector string. |
| Ignite.Vulnerability.cvss_v4s.version | String | The CVSS v4 version. |
| Ignite.Vulnerability.cvss_v4s.attack_vector | String | The CVSS v4 attack vector. |
| Ignite.Vulnerability.cvss_v4s.attack_complexity | String | The CVSS v4 attack complexity. |
| Ignite.Vulnerability.cvss_v4s.attack_requirements | String | The CVSS v4 attack requirements. |
| Ignite.Vulnerability.cvss_v4s.privileges_required | String | The CVSS v4 privileges required. |
| Ignite.Vulnerability.cvss_v4s.user_interaction | String | The CVSS v4 user interaction. |
| Ignite.Vulnerability.cvss_v4s.exploit_maturity | String | The CVSS v4 exploit maturity. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_confidentiality_impact | String | The CVSS v4 vulnerable system confidentiality impact. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_integrity_impact | String | The CVSS v4 vulnerable system integrity impact. |
| Ignite.Vulnerability.cvss_v4s.vulnerable_system_availability_impact | String | The CVSS v4 vulnerable system availability impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_confidentiality_impact | String | The CVSS v4 subsequent system confidentiality impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_integrity_impact | String | The CVSS v4 subsequent system integrity impact. |
| Ignite.Vulnerability.cvss_v4s.subsequent_system_availability_impact | String | The CVSS v4 subsequent system availability impact. |
| Ignite.Vulnerability.products.id | Number | The unique numeric identifier assigned by Flashpoint for a single product. |
| Ignite.Vulnerability.products.name | String | The product name. |
| Ignite.Vulnerability.vendors.id | Number | The unique numeric identifier assigned by Flashpoint for a single vendor. |
| Ignite.Vulnerability.vendors.name | String | The vendor name. |
| Ignite.Vulnerability.tags | String | The tags associated with the vulnerability. |

#### Command Example

!flashpoint-ignite-vulnerability-list attack_types="Attack Type Unknown" from=2 locations="Context Dependent" min_cvssv2_score=9 products="Squid" ransomware_scores=Critical ref_types="D2 Elliot" sort_order=Asc sort_by="ID" severities=Informational

#### Context Example

```json
[
    {
        "id": 1,
        "cve_ids": [
            "CVE-2020-101010"
        ],
        "title": "Dummy Vulnerability Title for Testing",
        "keywords": "",
        "description": "Dummy Vulnerability Description for Testing",
        "solution": "Dummy Solution for Testing",
        "technical_description": "Dummy Technical Description for Testing",
        "timelines": {
            "published_at": "2026-02-28T01:07:11Z",
            "last_modified_at": "2026-02-28T01:17:13Z",
            "exploit_published_at": "2025-12-21T00:00:00Z",
            "disclosed_at": "2025-12-21T00:00:00Z",
            "solution_provided_at": "2025-12-21T00:00:00Z"
        },
        "scores": {
            "severity": "Medium",
            "cvssv3_score": 5.4,
            "epss_score": 0.00039,
            "epss_v1_score": 0.0166211,
            "ransomware_score": "High"
        },
        "vuln_status": "Active",
        "cwes": [
            {
                "cwe_id": 79,
                "name": "Dummy CWE Name for Testing",
                "source": "nvd",
                "cve_ids": "CVE-2025-70091"
            }
        ],
        "exploits_count": 0,
        "ext_references": [
            {
                "value": "https://github.com/opensourcepos/opensourcepos/commit/01010101",
                "type": "Vendor Specific Solution URL",
                "url": "https://github.com/opensourcepos/opensourcepos/commit/01010101",
                "created_at": "2026-01-13T21:40:34Z"
            }
        ],
        "cvss_v2s": [
            {
                "access_vector": "NETWORK",
                "access_complexity": "LOW",
                "authentication": "SINGLE_INSTANCE",
                "confidentiality_impact": "NONE",
                "integrity_impact": "PARTIAL",
                "availability_impact": "NONE",
                "source": "Flashpoint",
                "generated_at": "2026-02-25T22:31:54Z",
                "score": 4.0
            }
        ],
        "cvss_v3s": [
            {
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "LOW",
                "user_interaction": "REQUIRED",
                "scope": "CHANGED",
                "confidentiality_impact": "LOW",
                "integrity_impact": "LOW",
                "availability_impact": "NONE",
                "source": "Flashpoint",
                "generated_at": "2026-02-25T22:31:54Z",
                "score": 5.4,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/:U/RC:C",
                "version": "3.1",
                "remediation_level": "UNAVAILABLE",
                "report_confidence": "CONFIRMED",
                "exploit_code_maturity": "FUNCTIONAL",
                "temporal_score": 5.3,
                "updated_at": "2026-02-28T01:07:11Z"
            }
        ],
        "cvss_v4s": [
            {
                "score": 5.1,
                "threat_score": 5.1,
                "source": "Flashpoint",
                "generated_at": "2026-02-25T22:31:54.998000Z",
                "updated_at": "2026-02-25T22:31:55.195000Z",
                "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A",
                "version": "4.0",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "attack_requirements": "NONE",
                "privileges_required": "LOW",
                "user_interaction": "PASSIVE",
                "exploit_maturity": "ATTACKED",
                "vulnerable_system_confidentiality_impact": "LOW",
                "vulnerable_system_integrity_impact": "LOW",
                "vulnerable_system_availability_impact": "NONE",
                "subsequent_system_confidentiality_impact": "LOW",
                "subsequent_system_integrity_impact": "LOW",
                "subsequent_system_availability_impact": "NONE"
            }
        ],
        "tags": [
            "oss"
        ],
        "products": [
            {
                "id": 1903500,
                "name": "dummy product"
            }
        ],
        "vendors": [
            {
                "id": 1884569,
                "name": "dummy vendor"
            }
        ]
    },
    {
        "id": 2,
        "cve_ids": [
            "CVE-2025-101010"
        ],
        "title": "Dummy Title for Testing2",
        "keywords": "",
        "description": "Dummy Description for Testing2",
        "solution": "Dummy Solution for Testing2",
        "technical_description": "Dummy Technical Description for Testing2",
        "timelines": {
            "published_at": "2026-02-28T01:02:30Z",
            "last_modified_at": "2026-02-28T01:12:33Z",
            "exploit_published_at": "2026-01-04T00:00:00Z",
            "disclosed_at": "2026-01-04T00:00:00Z",
            "vendor_informed_at": "2025-11-01T00:00:00Z",
            "solution_provided_at": "2026-01-04T00:00:00Z"
        },
        "scores": {
            "severity": "High",
            "cvssv3_score": 7.5,
            "epss_score": 0.00128,
            "epss_v1_score": 0.0226512,
            "ransomware_score": "Low"
        },
        "vuln_status": "Active",
        "cwes": [
            {
                "cwe_id": 1,
                "name": "dummy cwe name",
                "source": "flashpoint"
            }
        ],
        "exploits_count": 0,
        "ext_references": [
            {
                "value": "https://github.com/issue/1xxx",
                "type": "Bug Tracker",
                "url": "https://github.com/issue/2xxx",
                "created_at": "2026-02-12T15:45:49Z"
            }
        ],
        "classifications": [
            {
                "name": "dummy classifications",
                "longname": "dummy longname",
                "description": "dummy description"
            }
        ],
        "cvss_v2s": [
            {
                "access_vector": "NETWORK",
                "access_complexity": "LOW",
                "authentication": "NONE",
                "confidentiality_impact": "NONE",
                "integrity_impact": "NONE",
                "availability_impact": "COMPLETE",
                "source": "Flashpoint",
                "generated_at": "2026-02-27T18:40:31Z",
                "score": 7.8
            }
        ],
        "cvss_v3s": [
            {
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "NONE",
                "integrity_impact": "NONE",
                "availability_impact": "HIGH",
                "source": "Flashpoint",
                "generated_at": "2026-02-27T18:40:31Z",
                "score": 7.5,
                "vector_string": "CVSS:3.1/AV:N/AC:L/E:F/RL:O/RC:C",
                "version": "3.1",
                "remediation_level": "OFFICIAL_FIX",
                "report_confidence": "CONFIRMED",
                "exploit_code_maturity": "FUNCTIONAL",
                "temporal_score": 7.0,
                "updated_at": "2026-02-28T01:02:30Z"
            }
        ],
        "cvss_v4s": [
            {
                "score": 8.7,
                "threat_score": 8.7,
                "source": "Flashpoint",
                "generated_at": "2026-02-28T01:02:25.362000Z",
                "updated_at": "2026-02-28T01:02:25.392000Z",
                "vector_string": "CVSS:4.0/AV:N/AC:L/SA:N/E:A",
                "version": "4.0",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "attack_requirements": "NONE",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "exploit_maturity": "ATTACKED",
                "vulnerable_system_confidentiality_impact": "NONE",
                "vulnerable_system_integrity_impact": "NONE",
                "vulnerable_system_availability_impact": "HIGH",
                "subsequent_system_confidentiality_impact": "NONE",
                "subsequent_system_integrity_impact": "NONE",
                "subsequent_system_availability_impact": "NONE"
            }
        ],
        "tags": [
            "oss"
        ],
        "products": [
            {
                "id": 7483660,
                "name": "dummy product2"
            }
        ],
        "vendors": [
            {
                "id": 7441495,
                "name": "dummy vendor2"
            }
        ]
    }
]
```

#### Human Readable Output

>#### Total number of vulnerabilities found: 4
>
>### Vulnerability List
>
>|ID|CVE IDs|Title|Description|Solution|Vulnerability Status|Severity|EPSS Score|Ransomware Score|Published At|Last Modified At|Tags|CVSS v2|CVSS v3|CVSS v4|Products|CWEs|Exploits Count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| FP-VULN-1, [link](https://mock_dummy.com/vuln/vulnerabilities/1) | CVE-2020-101010 | Dummy Vulnerability Title for Testing | Dummy Vulnerability Description for Testing | Dummy Solution for Testing | Active | Medium | 0.00039 | High | 2026-02-28T01:07:11Z | 2026-02-28T01:17:13Z | oss | **-** _**access_vector**_: NETWORK<br> _**access_complexity**_: LOW<br> _**authentication**_: SINGLE_INSTANCE<br> _**confidentiality_impact**_: NONE<br> _**integrity_impact**_: PARTIAL<br> _**availability_impact**_: NONE<br> _**source**_: Flashpoint<br> _**generated_at**_: 2026-02-25T22:31:54Z<br> _**cve_id**_: null<br> _**score**_: 4.0<br> _**calculated_cvss_base_score**_: null | **-** _**attack_vector**_: NETWORK<br> _**attack_complexity**_: LOW<br> _**privileges_required**_: LOW<br> _**user_interaction**_: REQUIRED<br> _**scope**_: CHANGED<br> _**confidentiality_impact**_: LOW<br> _**integrity_impact**_: LOW<br> _**availability_impact**_: NONE<br> _**source**_: Flashpoint<br> _**generated_at**_: 2026-02-25T22:31:54Z<br> _**cve_id**_: null<br> _**score**_: 5.4<br> _**calculated_cvss_base_score**_: null<br> _**vector_string**_: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/:U/RC:C<br> _**version**_: 3.1<br> _**remediation_level**_: UNAVAILABLE<br> _**report_confidence**_: CONFIRMED<br> _**exploit_code_maturity**_: FUNCTIONAL<br> _**temporal_score**_: 5.3<br> _**updated_at**_: 2026-02-28T01:07:11Z | **-** _**score**_: 5.1<br> _**threat_score**_: 5.1<br> _**source**_: Flashpoint<br> _**generated_at**_: 2026-02-25T22:31:54.998000Z<br> _**updated_at**_: 2026-02-25T22:31:55.195000Z<br> _**cve_id**_: null<br> _**vector_string**_: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A<br> _**version**_: 4.0<br> _**attack_vector**_: NETWORK<br> _**attack_complexity**_: LOW<br> _**attack_requirements**_: NONE<br> _**privileges_required**_: LOW<br> _**user_interaction**_: PASSIVE<br> _**exploit_maturity**_: ATTACKED<br> _**vulnerable_system_confidentiality_impact**_: LOW<br> _**vulnerable_system_integrity_impact**_: LOW<br> _**vulnerable_system_availability_impact**_: NONE<br> _**subsequent_system_confidentiality_impact**_: LOW<br> _**subsequent_system_integrity_impact**_: LOW<br> _**subsequent_system_availability_impact**_: NONE | **-** _**id**_: 1903500<br> _**name**_: dummy product | **-** _**cwe_id**_: 79<br> _**name**_: Dummy CWE Name for Testing<br> _**source**_: nvd<br> _**cve_ids**_: CVE-2025-70091 | 0 |
>| FP-VULN-2, [link](https://mock_dummy.com/vuln/vulnerabilities/2) | CVE-2025-101010 | Dummy Title for Testing2 | Dummy Description for Testing2 | Dummy Solution for Testing2 | Active | High | 0.00128 | Low | 2026-02-28T01:02:30Z | 2026-02-28T01:12:33Z | oss | **-** _**access_vector**_: NETWORK<br> _**access_complexity**_: LOW<br> _**authentication**_: NONE<br> _**confidentiality_impact**_: NONE<br> _**integrity_impact**_: NONE<br> _**availability_impact**_: COMPLETE<br> _**source**_: Flashpoint<br> _**generated_at**_: 2026-02-27T18:40:31Z<br> _**cve_id**_: null<br> _**score**_: 7.8<br> _**calculated_cvss_base_score**_: null | **-** _**attack_vector**_: NETWORK<br> _**attack_complexity**_: LOW<br> _**privileges_required**_: NONE<br> _**user_interaction**_: NONE<br> _**scope**_: UNCHANGED<br> _**confidentiality_impact**_: NONE<br> _**integrity_impact**_: NONE<br> _**availability_impact**_: HIGH<br> _**source**_: Flashpoint<br> _**generated_at**_: 2026-02-27T18:40:31Z<br> _**cve_id**_: null<br> _**score**_: 7.5<br> _**calculated_cvss_base_score**_: null<br> _**vector_string**_: CVSS:3.1/AV:N/AC:L/E:F/RL:O/RC:C<br> _**version**_: 3.1<br> _**remediation_level**_: OFFICIAL_FIX<br> _**report_confidence**_: CONFIRMED<br> _**exploit_code_maturity**_: FUNCTIONAL<br> _**temporal_score**_: 7.0<br> _**updated_at**_: 2026-02-28T01:02:30Z | **-** _**score**_: 8.7<br> _**threat_score**_: 8.7<br> _**source**_: Flashpoint<br> _**generated_at**_: 2026-02-28T01:02:25.362000Z<br> _**updated_at**_: 2026-02-28T01:02:25.392000Z<br> _**cve_id**_: null<br> _**vector_string**_: CVSS:4.0/AV:N/AC:L/SA:N/E:A<br> _**version**_: 4.0<br> _**attack_vector**_: NETWORK<br> _**attack_complexity**_: LOW<br> _**attack_requirements**_: NONE<br> _**privileges_required**_: NONE<br> _**user_interaction**_: NONE<br> _**exploit_maturity**_: ATTACKED<br> _**vulnerable_system_confidentiality_impact**_: NONE<br> _**vulnerable_system_integrity_impact**_: NONE<br> _**vulnerable_system_availability_impact**_: HIGH<br> _**subsequent_system_confidentiality_impact**_: NONE<br> _**subsequent_system_integrity_impact**_: NONE<br> _**subsequent_system_availability_impact**_: NONE | **-** _**id**_: 7483660<br> _**name**_: dummy product2 | **-** _**cwe_id**_: 1<br> _**name**_: dummy cwe name<br> _**source**_: flashpoint<br> _**cve_ids**_: null | 0 |
>
>
>#### To retrieve the next set of result use, from = 2, size = 2

### flashpoint-ignite-vulnerability-library-list

***
Retrieves a list of libraries that are affected by a particular vulnerability.

#### Base Command

`flashpoint-ignite-vulnerability-library-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The Flashpoint vulnerability ID. | Required |
| from | The offset to retrieve next page data. Used for pagination only. Default is 0. | Optional |
| size | Number of libraries to return per page. Maximum value: 1000. Default is 10. | Optional |
| sort_by | Specify the field used to sort the libraries. Possible values are: ID, Name. Default is ID. | Optional |
| sort_order | Specify the order to sort the libraries. Possible values are: Asc, Desc. Default is Asc. | Optional |
| library_ids | Flashpoint library ID(s) to filter by. Supports a comma-separated values. | Optional |
| library_name | The library name to filter by \(case-insensitive\). | Optional |
| query | Search libraries by namespace, name, version, type, etc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Library.id | Number | The unique identifier of the library. |
| Ignite.Library.namespace | String | The namespace of the library. |
| Ignite.Library.name | String | The name of the library. |
| Ignite.Library.version | String | The version of the library. |
| Ignite.Library.qualifiers | String | The qualifiers of the library. |
| Ignite.Library.subpath | String | The subpath of the library. |
| Ignite.Library.type | String | The type of the library \(e.g., pypi, npm, maven\). |
| Ignite.Library.purl | String | The package URL of the library. |
| Ignite.Library.affected | Boolean | Whether the library is affected by the vulnerability. |
| Ignite.Library.constructed_purl | String | The constructed package URL of the library including name and version. |

#### Command Example

```
!flashpoint-ignite-vulnerability-library-list vulnerability_id=101010 sort=id sort_order=asc from=2 name="dummy_name" query="1.11" size=2
```

#### Context Example

```json
{
    "Ignite": {
        "Library": [
            {
                "id": 1010,
                "namespace": "-",
                "name": "dummy_name",
                "version": "1.11.112",
                "qualifiers": "-",
                "subpath": "-",
                "type": "pypi",
                "purl": "pkg:pypi",
                "affected": true,
                "constructed_purl": "pkg:pypi/dummy_name@1.11.112"
            },
            {
                "id": 101010,
                "namespace": "-",
                "name": "dummy_name",
                "version": "1.111.123",
                "qualifiers": "-",
                "subpath": "-",
                "type": "pypi",
                "purl": "pkg:pypi",
                "affected": true,
                "constructed_purl": "pkg:pypi/dummy_name@1.111.123"
            }
        ]
    }
}
```

#### Human Readable Output

>#### Total number of libraries found: 2
>
>### Vulnerability Libraries
>
>|ID|Name|Version|Type|Namespace|Package URL|Affected|
>|---|---|---|---|---|---|---|
>| 1010 | dummy_name | 1.11.112 | pypi | - | pkg:pypi/dummy_name@1.11.112 | true |
>| 101010 | dummy_name | 1.111.123 | pypi | - | pkg:pypi/dummy_name@1.111.123 | true |

### flashpoint-ignite-vulnerability-package-list

***
Retrieves a list of packages that are affected by a particular vulnerability.

#### Base Command

`flashpoint-ignite-vulnerability-package-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The Flashpoint vulnerability ID. | Required |
| from | The offset to retrieve next page data. Used for pagination only. Default is 0. | Optional |
| size | Number of packages to return per page. Maximum value: 1000. Default is 10. | Optional |
| sort_by | Specify the field used to sort the packages. Possible values are: ID, Name. Default is ID. | Optional |
| sort_order | Specify the order to sort the packages. Possible values are: Asc, Desc. Default is Asc. | Optional |
| package_ids | Flashpoint package ID(s) to filter by. Supports comma-separated integer values. | Optional |
| package_name | The package name to filter by \(case-insensitive\). | Optional |
| query | Search packages by name, version, operating system, etc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Package.id | Number | The unique identifier of the package. |
| Ignite.Package.name | String | The name of the package. |
| Ignite.Package.version | String | The version of the package. |
| Ignite.Package.filename | String | The filename of the package. |
| Ignite.Package.os | String | The operating system associated with the package. |
| Ignite.Package.os_version | String | The version of the operating system. |
| Ignite.Package.os_arch | String | The architecture of the operating system. |
| Ignite.Package.purl | String | The Package URL \(purl\) of the package. |
| Ignite.Package.operator | String | The operator indicating the version constraint relationship. |
| Ignite.Package.affected | Boolean | Whether the package is affected by the vulnerability. |

#### Command Example

```
!flashpoint-ignite-vulnerability-package-list vulnerability_id=101010 sort_by=id sort_order=asc query="Debian GNU/Linux" size=2
```

#### Context Example

```json
{
    "Ignite": {
        "Package": [
            {
                "id": 10000,
                "name": "dummy_package_1",
                "version": "1.0.0",
                "filename": "dummy_file_name_1",
                "os": "Debian GNU/Linux",
                "os_version": "10.1",
                "os_arch": "all",
                "purl": "pkg:deb/debian/dummy_package_1@1.0.0?distro=10.1",
                "operator": "=",
                "affected": true
            },
            {
                "id": 10001,
                "name": "dummy_package_2",
                "version": "2.0.0",
                "filename": "dummy_file_name_2",
                "os": "Debian GNU/Linux",
                "os_version": "10.1",
                "os_arch": "all",
                "purl": "pkg:deb/debian/dummy_package_2@2.0.0?distro=10.1",
                "operator": "<",
                "affected": false
            }
        ]
    }
}
```

#### Human Readable Output

>#### Total number of packages found: 4
>
>### Vulnerability Packages
>
>|ID|Package|Version|Filename|OS|OS Version|OS Architecture|Package URL|Affected|
>|---|---|---|---|---|---|---|---|---|
>| 10000 | dummy_package_1 | 1.0.0 | dummy_file_name_1 | Debian GNU/Linux | 10.1 | all | pkg:deb/debian/dummy_package_1@1.0.0?distro=10.1 | true |
>| 10001 | dummy_package_2 | 2.0.0 | dummy_file_name_2 | Debian GNU/Linux | 10.1 | all | pkg:deb/debian/dummy_package_2@2.0.0?distro=10.1 | false |
>
>#### To retrieve the next set of result use, from = 2, size = 2

### flashpoint-ignite-vendor-list

***
List vendors using provided filters.

#### Base Command

`flashpoint-ignite-vendor-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | The offset to retrieve next page data. Used for pagination only. Default is 0. | Optional |
| size | Number of packages to return per page. Maximum value: 1000. Default is 10. | Optional |
| vendor_ids | Flashpoint vendor ID(s) to filter by. Supports comma-separated integer values. | Optional |
| vendor_name | The vendor name to filter by \(case-insensitive\). | Optional |
| updated_after | Get vendors that were updated after the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| updated_before | Get vendors that were updated before the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Vendor.id | Number | The unique identifier of the vendor. |
| Ignite.Vendor.name | String | The name of the vendor. |

#### Command Example

```
!flashpoint-ignite-vendor-list size=2
```

#### Context Example

``` json
{
    "Ignite": {
        "Vendor": [
            {
                "id": 1001,
                "name": "Vendor Alpha"
            },
            {
                "id": 1002,
                "name": "Vendor Beta"
            }
        ]
    }
}
```

#### Human Readable Output

>#### Total number of vendors found: 4
>
>### Vendor List
>
>|ID|Name|
>|---|---|
>| [1001](https://app.flashpoint.io/vuln/vendors/1001) | Vendor Alpha |
>| [1002](https://app.flashpoint.io/vuln/vendors/1002) | Vendor Beta |
>
>#### To retrieve the next set of result use, from = 2, size = 2

### flashpoint-ignite-product-list

***
List products using provided filters.

#### Base Command

`flashpoint-ignite-product-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | The offset to retrieve next page data. Used for pagination only. Default is 0. | Optional |
| size | Number of products to return per page. Maximum value: 1000. Default is 10. | Optional |
| product_ids | Flashpoint product ID(s) to filter by. Supports comma-separated integer values. | Optional |
| product_name | The product name to filter by \(case-insensitive\). | Optional |
| vendor_ids | Flashpoint vendor ID(s) to filter by. Supports comma-separated integer values. | Optional |
| updated_after | Get products that were updated after the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |
| updated_before | Get products that were updated before the specified date or relative timestamp.<br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ignite.Product.id | Number | The unique identifier of the product. |
| Ignite.Product.name | String | The name of the product. |
| Ignite.Product.vendor.id | Number | The unique identifier of the vendor associated with the product. |
| Ignite.Product.vendor.name | String | The name of the vendor associated with the product. |
| Ignite.Product.versions | List | List of versions associated with the product. |

#### Command example

```
!flashpoint-ignite-product-list size=2
```

#### Context Example

``` json
{
    "Ignite": {
        "Product": [
            {
                "id": 10001,
                "name": "dummy product1",
                "vendor": {
                    "id": 1,
                    "name": "dummy vendor1"
                },
                "versions": [
                    {
                        "id": 1641849,
                        "vulndb_version_id": 11704,
                        "name": "1.1.4"
                    }
                ]
            },
            {
                "id": 10002,
                "name": "dummy product2",
                "vendor": {
                    "id": 2,
                    "name": "dummy vendor2"
                },
                "versions": [
                    {
                        "id": 1824886,
                        "vulndb_version_id": 11921,
                        "name": "1.6.6"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

#### Total number of products found: 5

### Product List

|Product ID|Product Name|Vendor ID|Vendor Name|
|---|---|---|---|
| [10001](https://app.flashpoint.io/vuln/products/10001) | dummy product1 | 1 | dummy vendor1 |
| [10002](https://app.flashpoint.io/vuln/products/10002) | dummy product2 | 2 | dummy vendor2 |

#### To retrieve the next set of result use, from = 2, size = 2

## Migration Guide

**Note:**  
For **fetching incidents**, set the **First Fetch** time to the previous integration's **Incidents Fetch Interval** time. This might create duplicate alerts, but it will ensure that no alert data is lost.

### Migrated Commands

Some of the previous integration's commands have been migrated to new commands. Below is the table showing the commands that have been migrated to the new ones.

| **Flashpoint Command** | **Migrated Ignite Command** |
| --- | --- |
| ip | ip |
| domain | domain |
| url | url |
| file | file |
| flashpoint-search-intelligence-reports | flashpoint-ignite-intelligence-report-search |
| flashpoint-get-single-intelligence-report | flashpoint-ignite-intelligence-report-get |
| flashpoint-get-related-reports | flashpoint-ignite-intelligence-related-report-list |
| flashpoint-get-single-event | flashpoint-ignite-event-get |
| flashpoint-get-events | flashpoint-ignite-event-list |
| flashpoint-common-lookup | flashpoint-ignite-common-lookup |
| flashpoint-alert-list | flashpoint-ignite-alert-list |
| flashpoint-compromised-credentials-list | flashpoint-ignite-compromised-credentials-list |

### Deprecated Commands

Some of the previous integration's commands have been deprecated from the Flashpoint API side. Below is the table showing the commands that have been deprecated for which, there is no replacement available.

| **Deprecated Command** |
| --- |
|flashpoint-get-forum-details|
|flashpoint-get-forum-room-details|
|flashpoint-get-forum-user-details|
|flashpoint-get-forum-post-details|
|flashpoint-search-forum-sites|
|flashpoint-search-forum-posts|
|filename|
|email|
