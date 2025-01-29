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
8. Update "First fetch time" and "Max Fetch Count" based on your requirements.

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
>Top 5 reports:
>1) [Artificial Intelligence Threat Landscape](https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000001)
>   Summary: This report covers evolving events that impact the advancement of AI technology and highlights notable developments that impact safety for users and organizations. 
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
>### Below are the detail found:
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
>### Below are the detail found:
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
>### Below are the details found:
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

>### Ignite Intelligence related reports:
>Top 5 related reports:
>
>1) [Key Developments: XYZ (April 7-13, 2023)](https:<span>//</span>app.flashpoint.io/cti/intelligence/report/00000000000000000003)
>   Summary: A weekly report on the major developments in XYZ.              
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
>|ID|Created at (UTC)|Query|Source|Resource URL|Site Title|Shodan Host|Repository|Owner|Origin|Ports|Services|Highlight Text|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000001 | Jun 17, 2024  05:54 | facebook | data_exposure__github | [https://dummyurl.com/naive-gabrie-white](https://dummyurl.com/naive-gabrie-white) |  |  | naive-gabrie-white.github.io | naive-gabrie-white | searches |  |  | data\-image="https://i.dummyurl.net/2021/02/24/000000000000001.png" data\-sites="<x\-fp\-highlight>facebook</x\-fp\-highlight>,twitter,wechat,weibo,qq"><link rel="stylesheet" href="https:...> |
>| 00000000-0000-0000-0000-000000000005 | Jul 02, 2024  16:43 | 0.0.0.1 |  |  |  | ***asn***: AS0001<br>***country***: United States<br>***org***: Company LLC<br>***shodan_url***: [https://www.shodan.io/host/0.0.0.1](https://www.shodan.io/host/0.0.0.1) |  |  | assets | 53, 443 | Unknown Service (Port 01), Unknown Service (Port 02) | <x\-fp\-highlight>53</x\-fp\-highlight> |
>
>#### To retrieve the next set of result use,
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
>Reputation: Malicious
>
>##### Events in which this IOC observed
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
>Reputation: Malicious
>
>##### Events in which this IOC observed
>|Date Observed (UTC)|Name|Tags|
>|---|---|---|
>| Jan 01, 1970  00:00 | test info | sample_tags |
>
>All events and details (ignite): [https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=filename&query=%22dummy.log%22](https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=filename&query=%22dummy.log%22)


### ip

***
Looks up details of an IP indicator. The reputation of the IP address is considered malicious if there's at least one IoC event in the Ignite database that matches the IP indicator. Alternatively, the IP address is considered suspicious if it matches any one of the community's peer IP addresses.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses. | Required | 

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
| Ignite.IP.type | String | Type of the document. | 

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
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "T1071",
                "EntityBType": "Attack Pattern",
                "Relationship": "indicator-of"
            }
        ]
    },
    "Ignite": {
        "IP": {
            "Event": [
                {
                    "Address": "0.0.0.1",
                    "Category": "Network activity",
                    "Comment": "",
                    "EventDetails": {
                        "RelatedEvent": [],
                        "Tags": [
                            "asn:as11878",
                            "infrastructure:c2",
                            "mitre:T1071",
                            "source:masscan",
                            "tool:cobaltstrike"
                        ],
                        "attack_ids": [
                            "T1071"
                        ],
                        "event_uuid": "00000000-0000-0000-0000-000000000001",
                        "fpid": "0000000000000000000001",
                        "href": "https://api.flashpoint.io/technical-intelligence/v1/event/0000000000000000000001",
                        "info": "Observation: CobaltStrikeVariant [2024-06-09 14:08:21]",
                        "reports": [],
                        "timestamp": "1717964206"
                    },
                    "Fpid": "0000000000000000000001",
                    "Href": "https://api.flashpoint.io/technical-intelligence/v1/attribute/0000000000000000000001",
                    "Timestamp": "1717950039",
                    "Type": "ip-dst",
                    "Uuid": "00000000-0000-0000-0000-000000000001"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Ignite IP Address reputation for 0.0.0.1
>Reputation: Malicious
>
>### Events in which this IOC observed
>|Date Observed (UTC)|Name|Tags|
>|---|---|---
>| Jun 09, 2024  20:16 | Observation: CobaltStrikeVariant [2024-06-09 14:08:21] | asn:as11878, infrastructure:c2, mitre:T1071, source:masscan, tool:cobaltstrike |
>
>All events and details (ignite): [https:<span>//</span>app.flashpoint.io/cti/malware/iocs?query=%220.0.0.1%22&sort_date=All%20Time&types=ip-dst,ip-src,ip-dst|port](https:<span>//</span>app.flashpoint.io/cti/malware/iocs?query=%220.0.0.1%22&sort_date=All%20Time&types=ip-dst,ip-src,ip-dst|port)


### flashpoint-ignite-common-lookup

***
Looks up any type of indicator.

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

#### Command example
```!flashpoint-ignite-common-lookup indicator="dummy@dummy.com"```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "dummy@dummy.com",
            "Reliability": "B - Usually reliable",
            "Score": 3,
            "Type": "email",
            "Vendor": "Ignite"
        }
    ]
}
```

#### Human Readable Output

>### Ignite reputation for dummy@dummy.com
>Reputation: Malicious
>
>### Events in which this IOC observed
>|Date Observed (UTC)|Name|Tags|
>|---|---|---|
>| Feb 06, 2021  01:29 | Observation: reported BazarLoader iocs [2021-02-05 15:30:30] | event:observation, malware:bazar, source:osint, type:64bit, misp-galaxy:mitre-enterprise-attack-attack-pattern="Exfiltration Over Command and Control Channel - 00001" |
>
>All events and details (ignite): [https:<span>//</span>app.flashpoint.io/cti/malware/iocs?sort_date=All%20Time&query=%22dummy%40dummy.com%22](https:<span>//</span>app.flashpoint.io/cti/malware/iocs?sort_date=All%20Time&query=%22dummy%40dummy.com%22)


### url

***
Looks up the "URL" type indicator details. The reputation of the URL is considered malicious if there's at least one IoC event in the Ignite database matching the URL indicator.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs. | Required | 

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
            "Malicious": {
                "Vendor": "Ignite",
                "Description": "Found in malicious indicators dataset"
            },
            "Relationships": [
                {
                    "Relationship": "indicator-of",
                    "EntityA": "http://dummy.com",
                    "EntityAType": "URL",
                    "EntityB": "T1016",
                    "EntityBType": "Attack Pattern"
                },
                {
                    "Relationship": "indicator-of",
                    "EntityA": "http://dummy.com",
                    "EntityAType": "URL",
                    "EntityB": "T1027",
                    "EntityBType": "Attack Pattern"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "http://dummy.com",
            "Type": "url",
            "Vendor": "Ignite",
            "Score": 3
        }
    ],
    "Ignite.URL.Event": [
        {
            "Fpid": "sample_fpid",
            "EventDetails": {
                "RelatedEvent": [],
                "Tags": [
                    "sample_tags"
                ],
                "attack_ids": [
                    "T1016",
                    "T1027"
                ],
                "event_uuid": "sample_uuid",
                "fpid": "sample_fpid",
                "href": "https://api.flashpoint.io/technical-intelligence/v1/event/sample_fpid",
                "info": "Sample info",
                "reports": [],
                "timestamp": "1000000001"
            },
            "Category": "Network activity",
            "Href": "https://api.flashpoint.io/technical-intelligence/v1/attribute/sample_fpid",
            "Timestamp": "1000000001",
            "Type": "url",
            "Uuid": "sample_uuid",
            "Comment": "",
            "Url": "http://dummy.com"
        }
    ]
}
```

#### Human Readable Output

>##### Ignite URL reputation for http://dummy.com
>Reputation: Malicious
>
>##### Events in which this IOC observed
>| Date Observed (UTC) |Name|Tags|
>|---------------------|---|---|
>| Jan 01, 2001  12:00 | Sample info | sample_tags |
>
>All events and details (ignite): [https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=url&query=%22http%3A//dummy.com%22](https://mock_dummy.com/cti/malware/iocs?sort_date=All%20Time&types=url&query=%22http%3A//dummy.com%22)


### domain

***
Looks up the "Domain" type indicator details. The reputation of Domain is considered malicious if there's at least one IoC event in the Ignite database matching the Domain indicator.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains. | Required | 

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
```!domain domain="dummy.com"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "dummy.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Ignite"
    },
    "Domain": {
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Ignite"
        },
        "Name": "dummy.com"
    },
    "Ignite": {
        "Domain": {
            "Event": {
                "Category": "Network activity",
                "Comment": "",
                "Domain": "dummy.com",
                "EventDetails": {
                    "RelatedEvent": [],
                    "Tags": [
                        "actor:APT",
                        "actor:Lazarus",
                        "event:observation",
                        "source:osint"
                    ],
                    "attack_ids": [],
                    "event_uuid": "00000000-0000-0000-0000-000000000001",
                    "fpid": "0000000000000000000001",
                    "href": "https://api.flashpoint.io/technical-intelligence/v1/event/0000000000000000000001",
                    "info": "Observation: APT Lazarus Reported IOCs [2021-07-28 21:10:34]",
                    "reports": [],
                    "timestamp": "1627527286"
                },
                "Fpid": "0000000000000000000001",
                "Href": "https://api.flashpoint.io/technical-intelligence/v1/attribute/0000000000000000000001",
                "Timestamp": "1569436997",
                "Type": "domain",
                "Uuid": "00000000-0000-0000-0000-000000000001"
            }
        }
    }
}
```

#### Human Readable Output

>### Ignite Domain reputation for dummy.com
>Reputation: Malicious
>
>### Events in which this IOC observed
>|Date Observed (UTC)|Name|Tags|
>|---|---|---|
>| Sep 25, 2019  19:51 | Observation: APT Lazarus Reported IOCs [2021-07-28 21:10:34] | actor:APT, actor:Lazarus, event:observation, source:osint |
>
>All events and details (ignite): [https:<span>//</span>app.flashpoint.io/cti/malware/iocs?sort_date=All%20Time&types=domain&query=%22dummy.com%22](https:<span>//</span>app.flashpoint.io/cti/malware/iocs?sort_date=All%20Time&types=domain&query=%22dummy.com%22)

### file

***
Looks up the "File" type indicator details. The reputation of File hash is considered malicious if there's at least one IoC event in the Ignite database matching the File hash indicator.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. | Required | 

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
                }
            ],
            "MD5": "00000000000000000000000000000001",
            "Malicious": {
                "Vendor": "Ignite",
                "Description": "Found in malicious indicators dataset"
            },
            "Relationships": [
                {
                    "Relationship": "indicator-of",
                    "EntityA": "00000000000000000000000000000001",
                    "EntityAType": "file",
                    "EntityB": "T1010",
                    "EntityBType": "Attack Pattern"
                },
                {
                    "Relationship": "indicator-of",
                    "EntityA": "00000000000000000000000000000001",
                    "EntityAType": "file",
                    "EntityB": "T1027",
                    "EntityBType": "Attack Pattern"
                }
            ]
        }
    ],
    "DBotScore": [
        {
            "Indicator": "00000000000000000000000000000001",
            "Type": "file",
            "Vendor": "Ignite",
            "Score": 3
        }
    ],
    "Ignite.File.Event": [
        {
            "MD5": "00000000000000000000000000000001",
            "EventDetails": {
                "RelatedEvent": [],
                "Tags": [
                    "sample_tags"
                ],
                "attack_ids": [
                    "T1010",
                    "T1027"
                ],
                "event_uuid": "sample_uuid",
                "fpid": "sample_fpid",
                "href": "https://api.flashpoint.io/technical-intelligence/v1/event/sample_fpid",
                "info": "Observation: test_info [\"00000000000000000000000000000001\"]",
                "reports": [],
                "timestamp": "0000000001"
            },
            "Category": "sample category",
            "Fpid": "sample_fpid",
            "Href": "https://api.flashpoint.io/technical-intelligence/v1/attribute/sample_fpid",
            "Timestamp": "0000000001",
            "Type": "md5",
            "Uuid": "sample_uuid",
            "Comment": ""
        }
    ]
}
```

#### Human Readable Output

>##### Ignite File reputation for 00000000000000000000000000000001
>Reputation: Malicious
>
>##### Events in which this IOC observed
>|Date Observed (UTC)|Name|Tags|
>|---|---|---|
>| Jan 01, 1970  00:00 | Observation: test_info ["00000000000000000000000000000001"] | sample_tags |
>
>All events and details (ignite): [https://mock_dummy.com/cti/malware/iocs?sort_date=All%20time&types=md5,sha1,sha256,sha512,ssdeep&query=%2200000000000000000000000000000001%22](https://mock_dummy.com/cti/malware/iocs?sort_date=All%20time&types=md5,sha1,sha256,sha512,ssdeep&query=%2200000000000000000000000000000001%22)


## Migration Guide

**Note:**  
For **fetching incidents**, set the **First Fetch** time to the previous integration's **Incidents Fetch Interval** time. This might create duplicate alerts, but it will ensure that no alert data is lost.

### Migrated Commands

Some of the previous integration's commands have been migrated to new commands. Below is the table showing the commands that have been migrated to the new ones.

| **Flashpoint Command** | **Migrated Ignite Command** |
| --- | --- |
| ip | ip |
| domain | domain |
| filename | filename |
| url | url |
| file | file |
| email | email |
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
