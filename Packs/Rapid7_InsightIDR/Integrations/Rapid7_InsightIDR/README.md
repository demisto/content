Rapid7’s InsightIDR is your security center for incident detection and response, authentication monitoring, and endpoint visibility. Together, these form Extended Detection and Response (XDR). InsightIDR identifies unauthorized access from external and internal threats and highlights suspicious activity so you don’t have to weed through thousands of data streams.
This integration was integrated and tested with cloud version of Rapid7 InsightIDR.

## Configure Rapid7 InsightIDR in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Insight cloud server region |  | True |
| InsightIDR API key |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Fetch Limit | Max number of alerts per fetch. Default is 50. | False |
| Multi customer | Indicates whether the requester has multi-customer access. | False |
| Use API Version 2 by default | Whether to use API version 2 by default for investigation commands (Can be overriden by passing the api_version argument). | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### rapid7-insight-idr-list-investigations

***
List all investigations. Retrieve a list of investigations matching the given request parameters. The investigations are sorted by investigation created_time in descending order. Investigations are an aggregate of the applicable alert data in a single place and are closely tied to Alerts and Detection Rules.

#### Base Command

`rapid7-insight-idr-list-investigations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- |--------------|
| api_version | The InsightIDR API version to request to. Possible values are: V1, V2, Default. Default is Default. | Optional     |
| index | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional     |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional     |
| limit | The maximum number of records to retrieve. Default is 50. | Optional     |
| statuses | A comma-separated list of investigation statuses to include in the result. For example, Open,Closed. Possible values are: open, investigating, closed. | Optional     |
| sources | A comma-separated list of investigation sources to include in the result. For example, User,Alert. Relevant when api_version is V2 only. Possible values are: User, Alert. | Optional     |
| priorities | A comma-separated list of investigation priorities to include in the result. For example, Low,Medium. Relevant when api_version is V2 only. Possible values are: Unspecified, Low, Medium, High, Critical. | Optional     |
| assignee_email | A user's email address. Only investigations assigned to that user will be included. For example, test@test.com. | Optional     |
| time_range | An optional time range string (i.e., 1 week, 1 day). | Optional     |
| start_time | The time an investigation is opened. Only investigations whose created_time is after this date will be returned by the API. Must be an ISO-formatted timestamp. For example, 2018-07-01T00:00:00Z. Default is 28 days prior. Relevant when api_version is V2 only. | Optional     |
| end_time | The time an investigation is closed. Only investigations whose created_time is before this date will be returned by the API. Must be an ISO-formatted timestamp. For example, 2018-07-28T23:59:00Z. Default is the current time. Relevant when api_version is V2 only. | Optional     |
| sort_field | A field for investigations to be sorted by. Relevant when api_version is V2 only. Possible values are: Created time, Priority, RRN Last Created Alert, Last Detection Alert. Default is Created time. | Optional     |
| sort_direction | The sorting direction. Relevant when api_version is V2 only. Possible values are: ASC, DESC. Default is DESC. | Optional     |
| tags | A comma-separated list of tags to include in the result. Only investigations who have all specified tags will be included. For example, my_teg,test_tag. Relevant when api_version is V2 only. | Optional     |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.responsibility | String | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. |
| Rapid7InsightIDR.Investigation.first_alert_time | String | The create time of the first alert belonging to this investigation \(if any\). Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.latest_alert_time | Date | The create time of the most recent alert belonging to this investigation \(if any\). Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.assignee.email | String | The email of the assigned user \(if any\). |
| Rapid7InsightIDR.Investigation.assignee.name | String | The name of the assigned user \(if any\). |
| Rapid7InsightIDR.Investigation.disposition | String | The disposition of this investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.created_time | Date | The time this investigation was created. |
| Rapid7InsightIDR.Investigation.last_accessed | Date | The time this investigation was last viewed or modified. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.priority | String | The priority of the investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.status | String | The status of the investigation. |
| Rapid7InsightIDR.Investigation.source | String | How this investigation was generated. |
| Rapid7InsightIDR.Investigation.title | String | The name of the investigation. |
| Rapid7InsightIDR.Investigation.organization_id | String | The ID of the organization that owns this investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.rrn | String | The Rapid7 Resource Names of the investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.id | String | The ID of the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.type | String | Type of alert in the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.type_description | String | The description of the type of alert in the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | First event time of the alert in the investigation. Relevant when api_version is V1 only. |

#### Command example
```!rapid7-insight-idr-list-investigations api_version=V2 limit=1```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": {
                "email": "test@test.com",
                "name": "test"
            },
            "created_time": "2024-03-05T12:53:02.722Z",
            "disposition": "NOT_APPLICABLE",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T16:18:19.186Z",
            "latest_alert_time": null,
            "organization_id": "123-123-123",
            "priority": "HIGH",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:123-123-123:investigation:SF6PGC3DEOLJ",
            "source": "USER",
            "status": "CLOSED",
            "title": "demo2025"
        }
    }
}
```

#### Human Readable Output

>### Investigations
>|Title|Rrn|Status|Created Time|Source|Assignee|Priority|
>|---|---|---|---|---|---|---|
>| demo2025 | rrn:investigation:eu:123-123-123:investigation:SF6PGC3DEOLJ | CLOSED | 2024-03-05T12:53:02.722Z | USER | name: test<br/>email: test@test.com | HIGH |


### rapid7-insight-idr-get-investigation

***
Get a specific investigation. This investigation is specified by either ID or Rapid7 Resource Names (RRN). (If multi-customer is set to true, the investigation_id must be in the RRN format).

#### Base Command

`rapid7-insight-idr-get-investigation`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                   | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| api_version | The InsightIDR API version to request to. Possible values are: V1, V2, Default. Default is Default.                                                                                                                               | Optional |
| investigation_id | The ID or Rapid7 Resource Names (RRN) of the investigation to retrieve. (If api_version=V2, the ID of the investigation must be in the RRN format). Use rapid7-insight-idr-list-investigations to retrieve all investigation IDs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.responsibility | String | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. |
| Rapid7InsightIDR.Investigation.first_alert_time | String | The create time of the first alert belonging to this investigation \(if any\). Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.latest_alert_time | Date | The create time of the most recent alert belonging to this investigation \(if any\). Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.assignee.email | String | The email of the assigned user \(if any\). |
| Rapid7InsightIDR.Investigation.assignee.name | String | The name of the assigned user \(if any\). |
| Rapid7InsightIDR.Investigation.disposition | String | The disposition of this investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.created_time | Date | The time this investigation was created. |
| Rapid7InsightIDR.Investigation.last_accessed | Date | The time this investigation was last viewed or modified. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.priority | String | The priority of the investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.status | String | The status of the investigation. |
| Rapid7InsightIDR.Investigation.source | String | How this investigation was generated. |
| Rapid7InsightIDR.Investigation.title | String | The name of the investigation. |
| Rapid7InsightIDR.Investigation.organization_id | String | The ID of the organization that owns this investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.rrn | String | The Rapid7 Resource Names of the investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.id | String | The ID of the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.type | String | Type of alert in the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.type_description | String | The description of the alert type in the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | First event time of alert in the investigation. Relevant when api_version is V1 only. |

#### Command example
```!rapid7-insight-idr-get-investigation investigation_id=3793645a-6484-4a7e-9228-7aeb4ba97472 api_version=V2```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": {
                "email": "test@test.com",
                "name": "test"
            },
            "created_time": "2024-03-05T19:02:28.419Z",
            "disposition": "UNDECIDED",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T19:07:07.790Z",
            "latest_alert_time": null,
            "organization_id": "123-123-123",
            "priority": "UNSPECIFIED",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2",
            "source": "USER",
            "status": "OPEN",
            "title": "test1"
        }
    }
}
```

#### Human Readable Output

>### Investigation "3793645a-6484-4a7e-9228-7aeb4ba97472" Information
>|Title|Rrn|Status|Created Time|Source|Assignee|Priority|
>|---|---|---|---|---|---|---|
>| test1 | rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2 | OPEN | 2024-03-05T19:02:28.419Z | USER | name: test<br/>email: test@test.com | UNSPECIFIED |


### rapid7-insight-idr-close-investigations

***
Close all investigations that match the provided request parameters. If there are any investigations found associated with Threat Command alerts within the given request parameters, they will be closed in Threat Command with the close reason, "Other".

#### Base Command

`rapid7-insight-idr-close-investigations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | The name of an investigation source. Only investigations from this source will be closed. If the source is ALERT, an alert type or a detection rule RRN must be specified as well. Possible values are: ALERT, MANUAL, HUNT. | Required |
| end_time | An ISO formatted timestamp. Only investigations whose createTime is before this date will be returned by the API. For example, 2018-07-28T23:59:00Z. Default is the current time. | Required |
| start_time | An ISO formatted timestamp. Only investigations whose createTime is after this date will be returned by the API. For example, 2018-07-01T00:00:00Z. | Required |
| alert_type | The category of types of alerts that should be closed. Use rapid7-insight-idr-list-investigations or rapid7-insight-idr-list-investigation-alerts to get the alert types. Required when sourceis ALERT. | Optional |
| disposition | A disposition to set the investigation to. Possible values are: Undecided, Benign, Malicious, Not Applicable. Default is Not Applicable. | Optional |
| detection_rule_rrn | The Rapid7 Resource Names (RRN) of the detection rule. Only investigations that are associated with this detection rule will be closed. If a detection rule RRN is given, thealert_typeis required to be 'Attacker Behavior Detected'.  Userapid7-insight-idr-get-investigationto retrieve the investigationdetection_rule_rrn. | Optional |
| max_investigations_to_close | The maximum number of alerts to close. If this parameter is not specified then there is no maximum. The minimum description is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.id | String | The ID of the investigation. |
| Rapid7InsightIDR.Investigation.status | String | The new status (Closed) of the investigation. |

#### Command example
```!rapid7-insight-idr-close-investigations source=HUNT start_time=2020-12-04T10:00:00.515Z end_time=2020-12-29T10:00:00.526Z```
#### Human Readable Output

>### Investigation '[]' (0) was successfully closed.
>**No entries.**


### rapid7-insight-idr-assign-user

***
Assign a user by email to an investigation. Users will receive an email whenever they are assigned to a new investigation

#### Base Command

`rapid7-insight-idr-assign-user`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                     | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| api_version | The InsightIDR API version to request to. Possible values are: V1, V2, Default. Default is Default.                                                                                                                                                                 | Optional |
| investigation_id | Comma-separated list of the ID or Rapid7 Resource Names (RRN) of the investigation to assign the user to. (If api_version=V2, the ID of the investigation must be in the RRN format). Use rapid7-insight-idr-list-investigations to retrieve all investigation IDs. | Required |
| user_email_address | The email address of the user to assign to this investigation. This is the same email used to log into the insight platform. For example, test@test.com. Use rapid7-insight-idr-list-users to retrieve the user email list. Relevant when api_version is V2 only.   | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.responsibility | String | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.latest_alert_time | String | The create time of the most recent alert belonging to this investigation \(if any\). Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.assignee.email | String | The email of the assigned user. |
| Rapid7InsightIDR.Investigation.assignee.name | String | The name of the assigned user. |
| Rapid7InsightIDR.Investigation.disposition | String | The disposition of this investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.created_time | String | The time this investigation was created. |
| Rapid7InsightIDR.Investigation.last_accessed | String | The time this investigation was last viewed or modified. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.priority | String | The investigations priority. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.status | String | The status of the investigation. |
| Rapid7InsightIDR.Investigation.source | String | How this investigation was generated. |
| Rapid7InsightIDR.Investigation.title | String | The name of the investigation. |
| Rapid7InsightIDR.Investigation.organization_id | String | The ID of the organization that owns this investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.rrn | String | The Rapid7 Resource Names of the investigation. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.id | String | The ID of the investigation. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.type_description | String | The description of this type of alert \(if any\). Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.type | String | The alert's type. Relevant when api_version is V1 only. |
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | The create time of the first alert belonging to this investigation \(if any\). Relevant when api_version is V1 only. |

#### Command example
```!rapid7-insight-idr-assign-user investigation_id=3793645a-6484-4a7e-9228-7aeb4ba97472 user_email_address=test@test.com api_version=V2```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": {
                "email": "test@test.com",
                "name": "test"
            },
            "created_time": "2024-03-05T19:02:28.419Z",
            "disposition": "UNDECIDED",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T19:07:30.382Z",
            "latest_alert_time": null,
            "organization_id": "123-123-123",
            "priority": "UNSPECIFIED",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2",
            "source": "USER",
            "status": "OPEN",
            "title": "test1"
        }
    }
}
```

#### Human Readable Output

>### Investigation '3793645a-6484-4a7e-9228-7aeb4ba97472' was successfully assigned to test@test.com.
>|Title|Rrn|Status|Created Time|Source|Assignee|Priority|
>|---|---|---|---|---|---|---|
>| test1 | rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2 | OPEN | 2024-03-05T19:02:28.419Z | USER | name: test<br/>email: test@test.com | UNSPECIFIED |


### rapid7-insight-idr-set-status

***
Set the status of the investigation, which is specified by ID or Rapid7 Resource Names (RRN).

#### Base Command

`rapid7-insight-idr-set-status`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                       | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| api_version | The InsightIDR API version to request to. Possible values are: V1, V2, Default. Default is Default.                                                                                                                                                                                                                                                                                                                                                                   | Optional |
| investigation_id | Comma-separated list of the ID or Rapid7 Resource Names (RRN) of the investigation to be changed.  (If api_version=V2, the ID of the investigation must be in the RRN format). Use rapid7-insight-idr-list-investigations to retrieve all investigation IDs.                                                                                                                                                                                                          | Required |
| status | The new status for the investigation.  Open - The default status for all new investigations. Investigating - The investigation is in progress. Waiting - Progress on the investigation has paused while more information is gathered. Closed - The investigation has ended. A disposition must be selected to set this status. Possible values are: open, closed, investigating, waiting.                                                                             | Required |
| threat_command_free_text | Additional information provided by the user when closing a Threat Command alert. Relevant when status=closed and api_version is V2 only.                                                                                                                                                                                                                                                                                                                              | Optional |
| threat_command_close_reason | The Threat Command reason for closing, applicable only if the investigation being closed has an associated alert in Threat Command. The Close Reason description depends on the Threat Command alert type. Relevant when status=closed and api_version is V2 only. Possible values are: Problem Solved, Informational Only, Problem We Are Already Aware Of, Not Related To My Company, False Positive, Legitimate Application/ Profile, Company Owned Domain, Other. | Optional |
| disposition | A disposition to set the investigation to. Relevant when status=closed and api_version is V2 only. Possible values are: benign, malicious, not_applicable.                                                                                                                                                                                                                                                                                                            | Optional |

#### Context Output

| **Path**                                              | **Type** | **Description**                                                                                                                                                                                                               |
|-------------------------------------------------------| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Rapid7InsightIDR.Investigation.responsibility         | String | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. Relevant when api_version is V2 only. |
| Rapid7InsightIDR.Investigation.latest_alert_time      | String | The create time of the most recent alert belonging to this investigation \(if any\). Relevant when api_version is V2 only.                                                                                                    |
| Rapid7InsightIDR.Investigation.assignee.email         | String | The email of the assigned user Relevant when api_version is V2 only.                                                                                                                                                          |
| Rapid7InsightIDR.Investigation.assignee_email         | String | The email of the assigned user. Relevant when api_version is V2 only.                                                                                                                                                         |
| Rapid7InsightIDR.Investigation.assignee_name          | String | The name of the assigned user. Relevant when api_version is V1 only.                                                                                                                                                          |
| Rapid7InsightIDR.Investigation.alert.type | String | The alert's type. Relevant when api_version is V1 only.                                                                                                                                                                       |
| Rapid7InsightIDR.Investigation.assignee.name          | String | The name of the assigned user. Relevant when api_version is V2 only.                                                                                                                                                          |
| Rapid7InsightIDR.Investigation.disposition            | String | The disposition of this investigation. Relevant when api_version is V2 only.                                                                                                                                                  |
| Rapid7InsightIDR.Investigation.created_time           | String | The time this investigation was created.                                                                                                                                                                                      |
| Rapid7InsightIDR.Investigation.last_accessed          | String | The time this investigation was last viewed or modified. Relevant when api_version is V2 only.                                                                                                                                |
| Rapid7InsightIDR.Investigation.priority               | String | The investigations priority. Relevant when api_version is V2 only.                                                                                                                                                            |
| Rapid7InsightIDR.Investigation.status                 | String | The status of the investigation.                                                                                                                                                                                              |
| Rapid7InsightIDR.Investigation.source                 | String | How this investigation was generated.                                                                                                                                                                                         |
| Rapid7InsightIDR.Investigation.title                  | String | The name of the investigation.                                                                                                                                                                                                |
| Rapid7InsightIDR.Investigation.organization_id        | String | The ID of the organization that owns this investigation. Relevant when api_version is V2 only.                                                                                                                                |
| Rapid7InsightIDR.Investigation.rrn                    | String | The Rapid7 Resource Names of the investigation. Relevant when api_version is V2 only.                                                                                                                                         |
| Rapid7InsightIDR.Investigation.id                     | String | The ID of the investigation. Relevant when api_version is V1 only.                                                                                                                                                            |
| Rapid7InsightIDR.Investigation.alert.type_description | String | The description of this type of alert \(if any\). Relevant when api_version is V1 only.                                                                                                                                       |
| Rapid7InsightIDR.Investigation.alert.type             | String | The alert's type. Relevant when api_version is V2 only.                                                                                                                                                                       |
| Rapid7InsightIDR.Investigation.alert_type             | String | The alert's type. Relevant when api_version is V1 only.                                                                                                                                                                       |
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | The create time of the first alert belonging to this investigation \(if any\). Relevant when api_version is V1 only.                                                                                                          |

#### Command example
```!rapid7-insight-idr-set-status status=open investigation_id=3793645a-6484-4a7e-9228-7aeb4ba97472 api_version=V2```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": {
                "email": "test@test.com",
                "name": "test"
            },
            "created_time": "2024-03-05T19:02:28.419Z",
            "disposition": "UNDECIDED",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T19:07:33.509Z",
            "latest_alert_time": null,
            "organization_id": "123-123-123",
            "priority": "UNSPECIFIED",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2",
            "source": "USER",
            "status": "OPEN",
            "title": "test1"
        }
    }
}
```

#### Human Readable Output

>### Investigation '3793645a-6484-4a7e-9228-7aeb4ba97472' status was successfully updated to open.
>|Title|Rrn|Status|Created Time|Source|Assignee|Priority|
>|---|---|---|---|---|---|---|
>| test1 | rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2 | OPEN | 2024-03-05T19:02:28.419Z | USER | name: test<br/>email: test@test.com | UNSPECIFIED |


### rapid7-insight-idr-add-threat-indicators

***
Adds new indicators to a threat (IP addresses, hashes, domains, and URLs).

#### Base Command

`rapid7-insight-idr-add-threat-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Key of the threat (or threats) to add indicators to. | Required |
| ip_addresses | IP address indicators to add. | Optional |
| hashes | Hash indicators to add. | Optional |
| domain_names | Domain indicators to add. | Optional |
| url | URL indicators to add. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Threat.name | String | Name of the threat. |
| Rapid7InsightIDR.Threat.note | String | Notes for the threat. |
| Rapid7InsightIDR.Threat.indicator_count | Number | How many indicators the threat has. |
| Rapid7InsightIDR.Threat.published | Boolean | Whether or not the threat is published. |

#### Command example
```!rapid7-insight-idr-add-threat-indicators key=76b06783-83cb-4018-b828-82a917278940 ip_addresses=20.20.20.20```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Threat": {
            "indicator_count": 2,
            "name": "test",
            "note": "",
            "published": true
        }
    }
}
```

#### Human Readable Output

>### Threat Information (key: 76b06783-83cb-4018-b828-82a917278940)
>|name|indicator_count|published|
>|---|---|---|
>| test | 2 | true |


### rapid7-insight-idr-replace-threat-indicators

***
Deletes existing indicators from a threat and adds new indicators to the threat.

#### Base Command

`rapid7-insight-idr-replace-threat-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Key of the threat (or threats) to replace indicators for. | Required |
| ip_addresses | IP address indicators to add. | Optional |
| hashes | Hash indicators to add. | Optional |
| domain_names | Domain indicators to add. | Optional |
| url | URL indicators to add. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Threat.name | String | Name of the threat. |
| Rapid7InsightIDR.Threat.note | String | Notes for the threat. |
| Rapid7InsightIDR.Threat.indicator_count | Number | How many indicators the threat has. |
| Rapid7InsightIDR.Threat.published | Boolean | Whether or not the threat is published. |

#### Command example
```!rapid7-insight-idr-replace-threat-indicators key=76b06783-83cb-4018-b828-82a917278940 ip_addresses=30.30.30.30```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Threat": {
            "indicator_count": 1,
            "name": "test",
            "note": "",
            "published": true
        }
    }
}
```

#### Human Readable Output

>### Threat Information (key: 76b06783-83cb-4018-b828-82a917278940)
>|name|indicator_count|published|
>|---|---|---|
>| test | 1 | true |


### rapid7-insight-idr-list-logs

***
Lists all existing logs for an account.

#### Base Command

`rapid7-insight-idr-list-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Log.name | String | Log name. |
| Rapid7InsightIDR.Log.id | String | Log ID. |

#### Command example
```!rapid7-insight-idr-list-logs```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Log": [
            {
                "id": "ee919c89-22c7-490e-be3e-db8994ee21cb",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/ee919c89-22c7-490e-be3e-db8994ee21cb/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "ef427412-18cb-4f23-af30-a36e8efb4efb",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/ef427412-18cb-4f23-af30-a36e8efb4efb",
                                "rel": "Self"
                            }
                        ],
                        "name": "Audit Logs",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:ef427412-18cb-4f23-af30-a36e8efb4efb"
                    }
                ],
                "name": "InsightIDR Investigations",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:ee919c89-22c7-490e-be3e-db8994ee21cb",
                "source_type": "internal",
                "structures": [
                    "fa6a4440-4579-4a03-be08-c259a84db062"
                ],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            },
            {
                "id": "17803c57-9124-43d1-a5d1-1e974042b481",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/17803c57-9124-43d1-a5d1-1e974042b481/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                                "rel": "Self"
                            }
                        ],
                        "name": "Internal Logs",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:e4f0787b-ff40-4587-986f-42ee27e7ffc0"
                    }
                ],
                "name": "Web Access Log",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:17803c57-9124-43d1-a5d1-1e974042b481",
                "source_type": "internal",
                "structures": [],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            },
            {
                "id": "fdf33f7b-edf9-4e2c-98f3-527ab62e124c",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/fdf33f7b-edf9-4e2c-98f3-527ab62e124c/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                                "rel": "Self"
                            }
                        ],
                        "name": "Internal Logs",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:e4f0787b-ff40-4587-986f-42ee27e7ffc0"
                    }
                ],
                "name": "Alert Audit Log",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:fdf33f7b-edf9-4e2c-98f3-527ab62e124c",
                "source_type": "internal",
                "structures": [
                    "fa6a4440-4579-4a03-be08-c259a84db062"
                ],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            },
            {
                "id": "3a813f0d-a3a8-47f8-b69e-67ff327f4383",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/3a813f0d-a3a8-47f8-b69e-67ff327f4383/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Activity",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:86484c1c-7aa8-4316-bb0d-bdb8e479e65b"
                    }
                ],
                "name": "Netbios Poisoning",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:3a813f0d-a3a8-47f8-b69e-67ff327f4383",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "6db7d337-b7ca-435b-babf-63efb6f8a9c3"
                ],
                "user_data": {
                    "le_expire_backup": "false",
                    "le_log_type": "eet",
                    "platform_managed": "true"
                }
            },
            {
                "id": "f1242448-a2ae-436a-925e-adebd71cbce5",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/f1242448-a2ae-436a-925e-adebd71cbce5/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "27bf96d8-4ec0-49ad-a3a7-4f6cdfb24354",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/27bf96d8-4ec0-49ad-a3a7-4f6cdfb24354",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Health",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:27bf96d8-4ec0-49ad-a3a7-4f6cdfb24354"
                    }
                ],
                "name": "Job Status",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:f1242448-a2ae-436a-925e-adebd71cbce5",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "9a9d3e69-44f2-4233-beae-ecc766c93b90"
                ],
                "user_data": {
                    "le_expire_backup": "false",
                    "le_log_type": "eet",
                    "platform_managed": "true"
                }
            },
            {
                "id": "676e5e4e-638e-4df5-b6a5-3a92a5c858ac",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/676e5e4e-638e-4df5-b6a5-3a92a5c858ac/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "0d1b319d-d2ca-4427-945c-5af8fc9c9f59",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/0d1b319d-d2ca-4427-945c-5af8fc9c9f59",
                                "rel": "Self"
                            }
                        ],
                        "name": "Unparsed Data",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:0d1b319d-d2ca-4427-945c-5af8fc9c9f59"
                    }
                ],
                "name": "Windows Defender",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:676e5e4e-638e-4df5-b6a5-3a92a5c858ac",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "b8566a56-d0f6-4898-ab33-0edeeb223941"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "8b780f32-a897-42e9-a0ef-d48278e7ea89",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/8b780f32-a897-42e9-a0ef-d48278e7ea89/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Activity",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:86484c1c-7aa8-4316-bb0d-bdb8e479e65b"
                    }
                ],
                "name": "Local Service Creation",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:8b780f32-a897-42e9-a0ef-d48278e7ea89",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "e6ef532f-47cb-42f6-be41-e8f767768279"
                ],
                "user_data": {
                    "le_expire_backup": "false",
                    "le_log_type": "eet",
                    "platform_managed": "true"
                }
            },
            {
                "id": "196d3f6e-d92c-40df-88b0-5c622da6396b",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/196d3f6e-d92c-40df-88b0-5c622da6396b/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                                "rel": "Self"
                            }
                        ],
                        "name": "Internal Logs",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:e4f0787b-ff40-4587-986f-42ee27e7ffc0"
                    }
                ],
                "name": "Log Updates",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:196d3f6e-d92c-40df-88b0-5c622da6396b",
                "source_type": "internal",
                "structures": [
                    "fa6a4440-4579-4a03-be08-c259a84db062"
                ],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            },
            {
                "id": "ed3599b4-a857-47ed-bde5-4e9baf9c6864",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/ed3599b4-a857-47ed-bde5-4e9baf9c6864/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "0122d7b5-6632-47c0-abf0-68c8545a6fd4",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/0122d7b5-6632-47c0-abf0-68c8545a6fd4",
                                "rel": "Self"
                            }
                        ],
                        "name": "Virus Alert",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:0122d7b5-6632-47c0-abf0-68c8545a6fd4"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:ed3599b4-a857-47ed-bde5-4e9baf9c6864",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "3ddf97fb-d590-4b9f-a312-1ca8aebbba76"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "d04903f1-a710-4c6c-ac16-0bf2e39f411d",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/d04903f1-a710-4c6c-ac16-0bf2e39f411d/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Activity",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:86484c1c-7aa8-4316-bb0d-bdb8e479e65b"
                    }
                ],
                "name": "Process Start Events",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:d04903f1-a710-4c6c-ac16-0bf2e39f411d",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "ba013edf-2877-4a80-819c-006b5e8c06de"
                ],
                "user_data": {
                    "le_expire_backup": "false",
                    "le_log_type": "eet",
                    "platform_managed": "true"
                }
            },
            {
                "id": "7bd5dbe6-9745-4386-8ff9-44c3cc2d5883",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/7bd5dbe6-9745-4386-8ff9-44c3cc2d5883/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "e4a59aa9-d8ef-45ee-af04-eb6fc929c1cf",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/e4a59aa9-d8ef-45ee-af04-eb6fc929c1cf",
                                "rel": "Self"
                            }
                        ],
                        "name": "Active Directory Admin Activity",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:e4a59aa9-d8ef-45ee-af04-eb6fc929c1cf"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:7bd5dbe6-9745-4386-8ff9-44c3cc2d5883",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "a84f5643-f816-47bb-9133-fc8c3add4359"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "b4d09423-9d8f-4eb3-9638-657a3b6824d5",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/b4d09423-9d8f-4eb3-9638-657a3b6824d5/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "78677867-e594-462a-aaad-923fe45d6efe",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/78677867-e594-462a-aaad-923fe45d6efe",
                                "rel": "Self"
                            }
                        ],
                        "name": "Host To IP Observations",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:78677867-e594-462a-aaad-923fe45d6efe"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:b4d09423-9d8f-4eb3-9638-657a3b6824d5",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "3e99ac75-0c5d-4472-83a6-ace858ebbba4"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "0a6a2612-e8c8-454a-a1bf-62e4d3f17304",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/0a6a2612-e8c8-454a-a1bf-62e4d3f17304/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "91de4b59-8324-45ed-8994-4604d918eb8d",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/91de4b59-8324-45ed-8994-4604d918eb8d",
                                "rel": "Self"
                            }
                        ],
                        "name": "Asset Authentication",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:91de4b59-8324-45ed-8994-4604d918eb8d"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:0a6a2612-e8c8-454a-a1bf-62e4d3f17304",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "c596d84d-9e56-4d98-9b2b-7fcb347376ef"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "1dc31fad-20e9-4946-856e-7da6ddf8910e",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/1dc31fad-20e9-4946-856e-7da6ddf8910e/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "0122d7b5-6632-47c0-abf0-68c8545a6fd4",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/0122d7b5-6632-47c0-abf0-68c8545a6fd4",
                                "rel": "Self"
                            }
                        ],
                        "name": "Virus Alert",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:0122d7b5-6632-47c0-abf0-68c8545a6fd4"
                    }
                ],
                "name": "Carbon",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:1dc31fad-20e9-4946-856e-7da6ddf8910e",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "4581d7af-ea5b-40fc-b119-c57bf473b44f"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "9355519b-cbc7-4e78-82aa-70e468ee2599",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/9355519b-cbc7-4e78-82aa-70e468ee2599/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "665aa34b-e489-4b78-a020-76203dbb2eea",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/665aa34b-e489-4b78-a020-76203dbb2eea",
                                "rel": "Self"
                            }
                        ],
                        "name": "File Access Activity",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:665aa34b-e489-4b78-a020-76203dbb2eea"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:9355519b-cbc7-4e78-82aa-70e468ee2599",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "69106621-037b-4040-91f2-8a6d2d074f9b"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "a679d822-bd3c-4807-a16d-4efd8ca248ab",
                "links": [
                    {
                        "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/a679d822-bd3c-4807-a16d-4efd8ca248ab/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "02f12c43-91b8-44d4-969e-8a5216781a5c",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logsets/02f12c43-91b8-44d4-969e-8a5216781a5c",
                                "rel": "Self"
                            }
                        ],
                        "name": "File Modification Activity",
                        "rrn": "rrn:logsearch:eu:123-123-123:logset:02f12c43-91b8-44d4-969e-8a5216781a5c"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:eu:123-123-123:log:a679d822-bd3c-4807-a16d-4efd8ca248ab",
                "source_type": "token",
                "structures": [
                    "9bceaf29-b72b-4259-94e4-0300e170157d",
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "91e38fb4-3e44-4c42-80d2-ba50a73944be"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List Logs
>|name|id|
>|---|---|
>| InsightIDR Investigations | ee919c89-22c7-490e-be3e-db8994ee21cb |
>| Web Access Log | 17803c57-9124-43d1-a5d1-1e974042b481 |
>| Alert Audit Log | fdf33f7b-edf9-4e2c-98f3-527ab62e124c |
>| Netbios Poisoning | 3a813f0d-a3a8-47f8-b69e-67ff327f4383 |
>| Job Status | f1242448-a2ae-436a-925e-adebd71cbce5 |
>| Windows Defender | 676e5e4e-638e-4df5-b6a5-3a92a5c858ac |
>| Local Service Creation | 8b780f32-a897-42e9-a0ef-d48278e7ea89 |
>| Log Updates | 196d3f6e-d92c-40df-88b0-5c622da6396b |
>| Endpoint Agents | ed3599b4-a857-47ed-bde5-4e9baf9c6864 |
>| Process Start Events | d04903f1-a710-4c6c-ac16-0bf2e39f411d |
>| Endpoint Agents | 7bd5dbe6-9745-4386-8ff9-44c3cc2d5883 |
>| Endpoint Agents | b4d09423-9d8f-4eb3-9638-657a3b6824d5 |
>| Endpoint Agents | 0a6a2612-e8c8-454a-a1bf-62e4d3f17304 |
>| Carbon | 1dc31fad-20e9-4946-856e-7da6ddf8910e |
>| Endpoint Agents | 9355519b-cbc7-4e78-82aa-70e468ee2599 |
>| Endpoint Agents | a679d822-bd3c-4807-a16d-4efd8ca248ab |


### rapid7-insight-idr-list-log-sets

***
Lists all existing log sets for your InsightsIDR instance.

#### Base Command

`rapid7-insight-idr-list-log-sets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.LogSet.name | String | Log name. |
| Rapid7InsightIDR.LogSet.id | String | Log ID. |

#### Command example
```!rapid7-insight-idr-list-log-sets```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "LogSet": [
            {
                "description": null,
                "id": "665aa34b-e489-4b78-a020-76203dbb2eea",
                "logs_info": [
                    {
                        "id": "9355519b-cbc7-4e78-82aa-70e468ee2599",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/9355519b-cbc7-4e78-82aa-70e468ee2599",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:9355519b-cbc7-4e78-82aa-70e468ee2599"
                    }
                ],
                "name": "File Access Activity",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:665aa34b-e489-4b78-a020-76203dbb2eea",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "ef427412-18cb-4f23-af30-a36e8efb4efb",
                "logs_info": [
                    {
                        "id": "ee919c89-22c7-490e-be3e-db8994ee21cb",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/ee919c89-22c7-490e-be3e-db8994ee21cb",
                                "rel": "Self"
                            }
                        ],
                        "name": "InsightIDR Investigations",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:ee919c89-22c7-490e-be3e-db8994ee21cb"
                    }
                ],
                "name": "Audit Logs",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:ef427412-18cb-4f23-af30-a36e8efb4efb",
                "user_data": {}
            },
            {
                "description": null,
                "id": "27bf96d8-4ec0-49ad-a3a7-4f6cdfb24354",
                "logs_info": [
                    {
                        "id": "f1242448-a2ae-436a-925e-adebd71cbce5",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/f1242448-a2ae-436a-925e-adebd71cbce5",
                                "rel": "Self"
                            }
                        ],
                        "name": "Job Status",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:f1242448-a2ae-436a-925e-adebd71cbce5"
                    }
                ],
                "name": "Endpoint Health",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:27bf96d8-4ec0-49ad-a3a7-4f6cdfb24354",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "0122d7b5-6632-47c0-abf0-68c8545a6fd4",
                "logs_info": [
                    {
                        "id": "1dc31fad-20e9-4946-856e-7da6ddf8910e",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/1dc31fad-20e9-4946-856e-7da6ddf8910e",
                                "rel": "Self"
                            }
                        ],
                        "name": "Carbon",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:1dc31fad-20e9-4946-856e-7da6ddf8910e"
                    },
                    {
                        "id": "ed3599b4-a857-47ed-bde5-4e9baf9c6864",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/ed3599b4-a857-47ed-bde5-4e9baf9c6864",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:ed3599b4-a857-47ed-bde5-4e9baf9c6864"
                    }
                ],
                "name": "Virus Alert",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:0122d7b5-6632-47c0-abf0-68c8545a6fd4",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "02f12c43-91b8-44d4-969e-8a5216781a5c",
                "logs_info": [
                    {
                        "id": "a679d822-bd3c-4807-a16d-4efd8ca248ab",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/a679d822-bd3c-4807-a16d-4efd8ca248ab",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:a679d822-bd3c-4807-a16d-4efd8ca248ab"
                    }
                ],
                "name": "File Modification Activity",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:02f12c43-91b8-44d4-969e-8a5216781a5c",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "91de4b59-8324-45ed-8994-4604d918eb8d",
                "logs_info": [
                    {
                        "id": "0a6a2612-e8c8-454a-a1bf-62e4d3f17304",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/0a6a2612-e8c8-454a-a1bf-62e4d3f17304",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:0a6a2612-e8c8-454a-a1bf-62e4d3f17304"
                    }
                ],
                "name": "Asset Authentication",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:91de4b59-8324-45ed-8994-4604d918eb8d",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "0d1b319d-d2ca-4427-945c-5af8fc9c9f59",
                "logs_info": [
                    {
                        "id": "676e5e4e-638e-4df5-b6a5-3a92a5c858ac",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/676e5e4e-638e-4df5-b6a5-3a92a5c858ac",
                                "rel": "Self"
                            }
                        ],
                        "name": "Windows Defender",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:676e5e4e-638e-4df5-b6a5-3a92a5c858ac"
                    }
                ],
                "name": "Unparsed Data",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:0d1b319d-d2ca-4427-945c-5af8fc9c9f59",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                "logs_info": [
                    {
                        "id": "17803c57-9124-43d1-a5d1-1e974042b481",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/17803c57-9124-43d1-a5d1-1e974042b481",
                                "rel": "Self"
                            }
                        ],
                        "name": "Web Access Log",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:17803c57-9124-43d1-a5d1-1e974042b481"
                    },
                    {
                        "id": "196d3f6e-d92c-40df-88b0-5c622da6396b",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/196d3f6e-d92c-40df-88b0-5c622da6396b",
                                "rel": "Self"
                            }
                        ],
                        "name": "Log Updates",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:196d3f6e-d92c-40df-88b0-5c622da6396b"
                    },
                    {
                        "id": "fdf33f7b-edf9-4e2c-98f3-527ab62e124c",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/fdf33f7b-edf9-4e2c-98f3-527ab62e124c",
                                "rel": "Self"
                            }
                        ],
                        "name": "Alert Audit Log",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:fdf33f7b-edf9-4e2c-98f3-527ab62e124c"
                    }
                ],
                "name": "Internal Logs",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:e4f0787b-ff40-4587-986f-42ee27e7ffc0",
                "user_data": {}
            },
            {
                "description": null,
                "id": "e4a59aa9-d8ef-45ee-af04-eb6fc929c1cf",
                "logs_info": [
                    {
                        "id": "7bd5dbe6-9745-4386-8ff9-44c3cc2d5883",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/7bd5dbe6-9745-4386-8ff9-44c3cc2d5883",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:7bd5dbe6-9745-4386-8ff9-44c3cc2d5883"
                    }
                ],
                "name": "Active Directory Admin Activity",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:e4a59aa9-d8ef-45ee-af04-eb6fc929c1cf",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                "logs_info": [
                    {
                        "id": "3a813f0d-a3a8-47f8-b69e-67ff327f4383",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/3a813f0d-a3a8-47f8-b69e-67ff327f4383",
                                "rel": "Self"
                            }
                        ],
                        "name": "Netbios Poisoning",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:3a813f0d-a3a8-47f8-b69e-67ff327f4383"
                    },
                    {
                        "id": "8b780f32-a897-42e9-a0ef-d48278e7ea89",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/8b780f32-a897-42e9-a0ef-d48278e7ea89",
                                "rel": "Self"
                            }
                        ],
                        "name": "Local Service Creation",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:8b780f32-a897-42e9-a0ef-d48278e7ea89"
                    },
                    {
                        "id": "d04903f1-a710-4c6c-ac16-0bf2e39f411d",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/d04903f1-a710-4c6c-ac16-0bf2e39f411d",
                                "rel": "Self"
                            }
                        ],
                        "name": "Process Start Events",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:d04903f1-a710-4c6c-ac16-0bf2e39f411d"
                    }
                ],
                "name": "Endpoint Activity",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:86484c1c-7aa8-4316-bb0d-bdb8e479e65b",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "78677867-e594-462a-aaad-923fe45d6efe",
                "logs_info": [
                    {
                        "id": "b4d09423-9d8f-4eb3-9638-657a3b6824d5",
                        "links": [
                            {
                                "href": "https://eu.api.insight.rapid7.com/log_search/management/logs/b4d09423-9d8f-4eb3-9638-657a3b6824d5",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:eu:123-123-123:log:b4d09423-9d8f-4eb3-9638-657a3b6824d5"
                    }
                ],
                "name": "Host To IP Observations",
                "rrn": "rrn:logsearch:eu:123-123-123:logset:78677867-e594-462a-aaad-923fe45d6efe",
                "user_data": {
                    "platform_managed": "true"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List Log Sets
>|name|id|
>|---|---|
>| File Access Activity | 665aa34b-e489-4b78-a020-76203dbb2eea |
>| Audit Logs | ef427412-18cb-4f23-af30-a36e8efb4efb |
>| Endpoint Health | 27bf96d8-4ec0-49ad-a3a7-4f6cdfb24354 |
>| Virus Alert | 0122d7b5-6632-47c0-abf0-68c8545a6fd4 |
>| File Modification Activity | 02f12c43-91b8-44d4-969e-8a5216781a5c |
>| Asset Authentication | 91de4b59-8324-45ed-8994-4604d918eb8d |
>| Unparsed Data | 0d1b319d-d2ca-4427-945c-5af8fc9c9f59 |
>| Internal Logs | e4f0787b-ff40-4587-986f-42ee27e7ffc0 |
>| Active Directory Admin Activity | e4a59aa9-d8ef-45ee-af04-eb6fc929c1cf |
>| Endpoint Activity | 86484c1c-7aa8-4316-bb0d-bdb8e479e65b |
>| Host To IP Observations | 78677867-e594-462a-aaad-923fe45d6efe |


### rapid7-insight-idr-download-logs

***
Downloads logs from your InsightsIDR instance. The maximum number of logs per call is 10.

#### Base Command

`rapid7-insight-idr-download-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_ids | IDs of the logs to download - up to 10 logs allowed. | Required |
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. This is optional if time_range is supplied. | Optional |
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. | Optional |
| time_range | The relative time range in a readable format. Optional if "from" \ is supplied. For example: Last 4 Days. Note that if start_time, end_time and\ \ time_range is not provided the default will be Last 3 days. | Optional |
| query | The LEQL query to match desired log events. Do not use a calculation. For more information: https://docs.rapid7.com/insightidr/build-a-query/. | Optional |
| limit | The maximum number of log events to download; cannot exceed 20 million. The default is 20 million. The argument value should be written like this: "10 thousand" or "2 million"). | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!rapid7-insight-idr-download-logs log_ids=ee919c89-22c7-490e-be3e-db8994ee21cb time_range="last 7 days"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "692@3eb6b0b2-d80d-4c3a-8c97-1d191f5a42fe",
        "Extension": "log",
        "Info": "text/x-log; charset=utf-8",
        "Name": "InsightIDRInvestigations_2024-02-27_190751_2024-03-05_190751.log",
        "Size": 70908,
        "Type": "ASCII text, with very long lines"
    }
}
```

#### Human Readable Output



### rapid7-insight-idr-query-log

***
Queries within a log for certain values.

#### Base Command

`rapid7-insight-idr-query-log`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_id | Log entries log key. | Required |
| query | A valid LEQL query to run against the log. For more information: https://docs.rapid7.com/insightidr/build-a-query/. | Required |
| time_range | A time range string (i.e., 1 week, 1 day). When using this parameter, start_time and end_time isn't needed. | Optional |
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1450557004000. | Optional |
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1460557604000. | Optional |
| logs_per_page | The maximum number of log entries to return per page. Default of 50. | Optional |
| sequence_number | The earlier sequence number of a log entry to start searching from. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Event.log_id | String | ID of the log the event appears in. |
| Rapid7InsightIDR.Event.message | String | Event message. |
| Rapid7InsightIDR.Event.timestamp | Number | Time when the event was triggered. |

### rapid7-insight-idr-query-log-set

***
Queries within a log set for certain values.

#### Base Command

`rapid7-insight-idr-query-log-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_set_id | ID of the log set. | Required |
| query | A valid LEQL query to run against the log. For more information: https://docs.rapid7.com/insightidr/build-a-query/. | Required |
| time_range | A time range string (e.g., 1 week, 1 day). When using this parameter, start_time and end_time isn't needed. | Optional |
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1450557004000. | Optional |
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1460557604000. | Optional |
| logs_per_page | The maximum number of log entries to return per page. Default of 50. | Optional |
| sequence_number | The earlier sequence number of a log entry to start searching from. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Event.log_id | String | ID of the log the event appears in. |
| Rapid7InsightIDR.Event.message | String | Event message. |
| Rapid7InsightIDR.Event.timestamp | Number | Time when the event was triggered. |

### rapid7-insight-idr-create-investigation

***
Create a new investigation manually.

#### Base Command

`rapid7-insight-idr-create-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The name of the investigation. | Required |
| status | The status of the investigation. Open - The default status for all new investigations. Investigating - The investigation is in progress. Closed - The investigation has ended. A disposition must be selected to set this status. Possible values are: Open, Investigating, Closed. Default is Open. | Optional |
| priority | The priority for the investigation. Investigation priority is the scale given to an investigation based on the impact and urgency of the detections and assets associated with it. Possible values are: Unspecified, Low, Medium, High, Critical. Default is Unspecified. | Optional |
| disposition | The disposition for the investigation. Select a disposition to indicate whether the investigation represented a legitimate threat. Possible values are: Undecided, Benign, Malicious, Not Applicable. Default is Undecided. | Optional |
| user_email_address | The email address of the user to assign to this investigation. This is the same email used to log into the insight platform. Use rapid7-insight-idr-list-users to retrieve the user email list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.responsibility | String | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. |
| Rapid7InsightIDR.Investigation.latest_alert_time | String | The create time of the most recent alert belonging to this investigation \(if any\). |
| Rapid7InsightIDR.Investigation.first_alert_time | String | The create time of the first alert belonging to this investigation \(if any\). |
| Rapid7InsightIDR.Investigation.assignee.email | String | The email of the assigned user \(if any\). |
| Rapid7InsightIDR.Investigation.assignee.name | String | The name of the assigned user \(if any\). |
| Rapid7InsightIDR.Investigation.disposition | String | The disposition of this investigation. |
| Rapid7InsightIDR.Investigation.created_time | Date | The time this investigation was created. |
| Rapid7InsightIDR.Investigation.last_accessed | Date | The time this investigation was last viewed or modified. |
| Rapid7InsightIDR.Investigation.priority | String | The priority of the investigation. |
| Rapid7InsightIDR.Investigation.status | String | The status of the investigation. |
| Rapid7InsightIDR.Investigation.source | String | How this investigation was generated. |
| Rapid7InsightIDR.Investigation.title | String | The name of the investigation. |
| Rapid7InsightIDR.Investigation.organization_id | String | The ID of the organization that owns this investigation. |
| Rapid7InsightIDR.Investigation.rrn | String | The Rapid7 Resource Names of the investigation. |

#### Command example
```!rapid7-insight-idr-create-investigation title=test limit=1```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": null,
            "created_time": "2024-03-05T19:07:04.610Z",
            "disposition": "UNDECIDED",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T19:07:04.610Z",
            "latest_alert_time": null,
            "organization_id": "123-123-123",
            "priority": "UNSPECIFIED",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:123-123-123:investigation:U92BZEYO124T",
            "source": "USER",
            "status": "OPEN",
            "title": "test"
        }
    }
}
```

#### Human Readable Output

>### Investigation 'rrn:investigation:eu:123-123-123:investigation:U92BZEYO124T' was successfuly created.
>|Title|Rrn|Status|Created Time|Source|Priority|
>|---|---|---|---|---|---|
>| test | rrn:investigation:eu:123-123-123:investigation:U92BZEYO124T | OPEN | 2024-03-05T19:07:04.610Z | USER | UNSPECIFIED |


### rapid7-insight-idr-update-investigation

***
Updates multiple fields in a single operation for an investigation, specified by ID or Rapid7 Resource Names (RRN). (If multi-customer set to true, the investigation_id must be in the RRN format). Use rapid7-insight-idr-list-investigations to retrieve all investigation IDs

#### Base Command

`rapid7-insight-idr-update-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | The ID or Rapid7 Resource Names (RRN) of the investigation to to update. (If api_version=V2, the ID of the investigation must be in the RRN format). | Required |
| title | The name of the investigation. | Optional |
| status | The status of the investigation.  Open - The default status for all new investigations. Investigating - The investigation is in progress. Closed - The investigation has ended. A disposition must be selected to set this status. Possible values are: Open, Investigating, Closed. | Optional |
| priority | The priority for the investigation. Investigation priority is the scale given to an investigation based on the impact and urgency of the detections and assets associated with it. Possible values are: Unspecified, Low, Medium, High, Critical. | Optional |
| disposition | The disposition for the investigation. Select a disposition to indicate whether the investigation represented a legitimate threat. Possible values are: Undecided, Benign, Malicious, Not Applicable. | Optional |
| user_email_address | The email address of the user to assign to this investigation. This is the same email used to log into the insight platform. | Optional |
| threat_command_free_text | Additional information provided by the user when closing a Threat Command alert. Relevant when status=Closed. | Optional |
| threat_command_close_reason | The Threat Command reason for closing, applicable only if the investigation being closed has an associated alert in Threat Command. The Close Reason description depends on the Threat Command alert type.  Relevant when status=Closed. Possible values are: Problem Solved, Informational Only, Problem We Are Already Aware Of, Not Related To My Company, False Positive, Legitimate Application/ Profile, Company Owned Domain, Other. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.responsibility | String | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. |
| Rapid7InsightIDR.Investigation.latest_alert_time | String | The create time of the most recent alert belonging to this investigation \(if any\). |
| Rapid7InsightIDR.Investigation.first_alert_time | String | The create time of the first alert belonging to this investigation \(if any\). |
| Rapid7InsightIDR.Investigation.assignee_email | String | The email of the assigned user. |
| Rapid7InsightIDR.Investigation.assignee_name | String | The name of the assigned user. |
| Rapid7InsightIDR.Investigation.disposition | String | The disposition of this investigation. |
| Rapid7InsightIDR.Investigation.created_time | Date | The time this investigation was created. |
| Rapid7InsightIDR.Investigation.last_accessed | Date | The time this investigation was last viewed or modified. |
| Rapid7InsightIDR.Investigation.priority | String | The priority of the investigation. |
| Rapid7InsightIDR.Investigation.status | String | The status of the investigation. |
| Rapid7InsightIDR.Investigation.source | String | How this investigation was generated. |
| Rapid7InsightIDR.Investigation.title | String | The name of the investigation. |
| Rapid7InsightIDR.Investigation.organization_id | String | The ID of the organization that owns this investigation. |
| Rapid7InsightIDR.Investigation.rrn | String | The Rapid7 Resource Names of the investigation. |

#### Command example
```!rapid7-insight-idr-update-investigation investigation_id=3793645a-6484-4a7e-9228-7aeb4ba97472 title=test1```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": {
                "email": "test@test.com",
                "name": "test"
            },
            "created_time": "2024-03-05T19:02:28.419Z",
            "disposition": "UNDECIDED",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T19:07:07.790Z",
            "latest_alert_time": null,
            "organization_id": "123-123-123",
            "priority": "UNSPECIFIED",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2",
            "source": "USER",
            "status": "OPEN",
            "title": "test1"
        }
    }
}
```

#### Human Readable Output

>### Investigation '3793645a-6484-4a7e-9228-7aeb4ba97472' was successfuly updated.
>|Title|Rrn|Status|Created Time|Source|Assignee|Priority|
>|---|---|---|---|---|---|---|
>| test1 | rrn:investigation:eu:123-123-123:investigation:UFBFNSRZG4N2 | OPEN | 2024-03-05T19:02:28.419Z | USER | name: test<br/>email: test@test.com | UNSPECIFIED |


### rapid7-insight-idr-search-investigation

***
Search for investigations matching the given search/sort criteria.

#### Base Command

`rapid7-insight-idr-search-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | An optional ISO formatted timestamp for the start of the time period to search for matching investigations. Only investigations whose created_time is after this date will be returned. For example, 2018-07-01T00:00:00Z. Default is 28 days ago. | Optional |
| end_time | An optional ISO formatted timestamp for the end of the time period to search for matching investigations. Only investigations whose created_time is before this date will be returned. For example,2018-07-28T23:59:00Z. Default is the current time. | Optional |
| actor_asset_hostname | A comma-separated list of hostnames. | Optional |
| actor_user_name | A comma-separated list of user names. | Optional |
| alert_mitre_t_codes | A comma-separated list of mitre_t_codes. | Optional |
| alert_rule_rrn | A comma-separated list of Rapid7 Resource Names. | Optional |
| assignee_id | A comma-separated list of assignee IDs. | Optional |
| organization_id | A comma-separated list of organization IDs. | Optional |
| priority | A comma-separated list of priorities. | Optional |
| rrn | A comma-separated list of Rapid7 Resource Names. | Optional |
| source | A comma-separated list of sources. | Optional |
| status | A comma-separated list of statuses. | Optional |
| title | A comma-separated list of titles. | Optional |
| sort | Comma-separated list of fields to sort by. Possible values are: Created time, Priority, RRN, Alert created time, Alert detection created time. | Optional |
| sort_direction | The sorting direction. Relevant when sort is chosen. Possible values are: asc, desc, asc,desc. Default is asc. | Optional |
| index | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.responsibility | Unknown | The responsibility of the investigation, which denotes who is responsible for performing the investigation. This field will only appear for Managed Detection &amp; Response customers. |
| Rapid7InsightIDR.Investigation.latest_alert_time | Date | The create time of the most recent alert belonging to this investigation \(if any\). |
| Rapid7InsightIDR.Investigation.first_alert_time | Date | The create time of the first alert belonging to this investigation \(if any\). |
| Rapid7InsightIDR.Investigation.assignee.email | Unknown | The email of the assigned user. |
| Rapid7InsightIDR.Investigation.assignee.name | String | The name of the assigned user. |
| Rapid7InsightIDR.Investigation.disposition | String | The disposition of this investigation. |
| Rapid7InsightIDR.Investigation.created_time | Date | The time this investigation was created. |
| Rapid7InsightIDR.Investigation.last_accessed | Date | The time this investigation was last viewed or modified. |
| Rapid7InsightIDR.Investigation.priority | String | The priority of the investigation. |
| Rapid7InsightIDR.Investigation.status | String | The status of the investigation. |
| Rapid7InsightIDR.Investigation.source | String | How this investigation was generated. |
| Rapid7InsightIDR.Investigation.title | String | The name of the investigation. |
| Rapid7InsightIDR.Investigation.organization_id | String | The ID of the organization that owns this investigation. |
| Rapid7InsightIDR.Investigation.rrn | String | The Rapid7 Resource Names of the investigation. |

#### Command example
```!rapid7-insight-idr-search-investigation limit=1```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "assignee": null,
            "created_time": "2024-03-05T19:07:04.61Z",
            "disposition": "UNDECIDED",
            "first_alert_time": null,
            "last_accessed": "2024-03-05T19:07:04.61Z",
            "latest_alert_time": null,
            "organization_id": "244e0f2e-2e23-43de-9910-da818cdf9ef8",
            "priority": "UNMAPPED",
            "responsibility": null,
            "rrn": "rrn:investigation:eu:244e0f2e-2e23-43de-9910-da818cdf9ef8:investigation:U92BZEYO124T",
            "source": "USER",
            "status": "OPEN",
            "title": "test"
        }
    }
}
```

#### Human Readable Output

>### Investigations
>|Title|Rrn|Status|Created Time|Source|Priority|
>|---|---|---|---|---|---|
>| test | rrn:investigation:eu:244e0f2e-2e23-43de-9910-da818cdf9ef8:investigation:U92BZEYO124T | OPEN | 2024-03-05T19:07:04.61Z | USER | UNMAPPED |



### rapid7-insight-idr-list-investigation-alerts

***
Retrieve and list all alerts associated with an investigation, with the given ID or Rapid7 Resource Names (RRN). The listed alerts are sorted in descending order by alert create time. Use rapid7-insight-idr-list-investigations to retrieve all investigation IDs.

#### Base Command

`rapid7-insight-idr-list-investigation-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | The ID of the investigation (If api_version=V2, the ID of the investigation must be in the RRN format). | Required |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.alert.rule_rrn | String | The Rapid7 Resource Names of the investigation. |
| Rapid7InsightIDR.Investigation.alert.rule_name | String | The name of the detection rule. |
| Rapid7InsightIDR.Investigation.alert.alert_source | String | The source of the alert. |
| Rapid7InsightIDR.Investigation.alert.latest_event_time | String | The time the most recent event involved in this alert occurred. |
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | The time the first event involved in this alert occurred. |
| Rapid7InsightIDR.Investigation.alert.created_time | String | The time the alert was created. |
| Rapid7InsightIDR.Investigation.alert.alert_type_description | String | A description of this type of alert. |
| Rapid7InsightIDR.Investigation.alert.alert_type | String | The alert's type. |
| Rapid7InsightIDR.Investigation.alert.title | String | The alert's title. |
| Rapid7InsightIDR.Investigation.alert.id | String | The alert's ID. |
| Rapid7InsightIDR.Investigation.rrn | String | The ID of the investigation. |

#### Command example
```!rapid7-insight-idr-list-investigation-alerts investigation_id=3793645a-6484-4a7e-9228-7aeb4ba97472```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "alert": [],
            "rrn": "3793645a-6484-4a7e-9228-7aeb4ba97472"
        }
    }
}
```

#### Human Readable Output

>### Investigation "3793645a-6484-4a7e-9228-7aeb4ba97472" alerts
>**No entries.**


### rapid7-insight-idr-list-investigation-product-alerts

***
Retrieve and list all Rapid7 product alerts associated with an investigation, with the given ID or the Rapid7 Resource Names. These alerts are generated by Rapid7 products other than InsightIDR that you have an active license for.

#### Base Command

`rapid7-insight-idr-list-investigation-product-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | The ID of the investigation (If api_version=V2, the ID of the investigation must be in the Rapid7 Resource Names format). Use rapid7-insight-idr-list-investigations to retrieve all investigation IDs. | Required |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.rrn | String | The ID of the investigation. |
| Rapid7InsightIDR.Investigation.ProductAlert.name | String | The investigation product name |
| Rapid7InsightIDR.Investigation.ProductAlert.Alert.name | String | The investigation product alert name. |
| Rapid7InsightIDR.Investigation.ProductAlert.Alert.alert_id | String | The investigation product alert ID. |
| Rapid7InsightIDR.Investigation.ProductAlert.Alert.alert_type | String | The investigation product alert type. |

#### Command example
```!rapid7-insight-idr-list-investigation-product-alerts investigation_id=3793645a-6484-4a7e-9228-7aeb4ba97472```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "ProductAlert": [
                {
                    "agent_action_taken": "Block",
                    "alert_id": "972bef1b-72c9-48d2-9e33-ca9056cfe086",
                    "alert_type": "Endpoint Prevention",
                    "name": "THREAT_COMMAND"
                },
                {
                    "alert_id": "620ba5123b2aff3303ed65f3",
                    "alert_type": "Phishing",
                    "applicable_close_reasons": [
                        "ProblemSolved",
                        "InformationalOnly",
                        "Other"
                    ],
                    "name": "THREAT_COMMAND"
                }
            ],
            "rrn": "3793645a-6484-4a7e-9228-7aeb4ba97472"
        }
    }
}
```

#### Human Readable Output

>### Investigation "3793645a-6484-4a7e-9228-7aeb4ba97472" product alerts
>|Name|Alert Type|Alert Id|
>|---|---|---|
>| THREAT_COMMAND | Endpoint Prevention | 972bef1b-72c9-48d2-9e33-ca9056cfe086 |
>| THREAT_COMMAND | Phishing | 620ba5123b2aff3303ed65f3 |


### rapid7-insight-idr-list-users

***
List all users matching the given search/sort criteria or retrieve a user with the given RRN.

#### Base Command

`rapid7-insight-idr-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rrn | The Rapid7 Resource Names (unique identifier for user.) of the user to retrieve. When using this argument, all the other irrelevant. | Optional |
| first_name | A comma-separated list of first names. Choose search operator to define the operator type. | Optional |
| last_name | A comma-separated list of last names. Choose search operator to define the operator type. | Optional |
| name | A comma-separated list of names. Choose search operator to define the operator type. | Optional |
| search_operator | The filtering operator. Relevant when first_name / last_name / is name / domain chosen. Possible values are: contains, equals. | Optional |
| sort | Comma-separated list of fields to sort by. Possible values are: first_name, last_name, name. | Optional |
| sort_direction | The sorting direction. Relevant when sort is chosen. Possible values are: asc, desc, asc & desc. Default is asc. | Optional |
| index | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.User.domain | String | The domain this user is associated with. |
| Rapid7InsightIDR.User.name | String | The name of this user. |
| Rapid7InsightIDR.User.first_name | String | The first name of this user, if known. |
| Rapid7InsightIDR.User.last_name | String | The last name of this user, if known. |
| Rapid7InsightIDR.User.rrn | String | The unique identifier for this user. |

#### Command example
```!rapid7-insight-idr-list-users limit=1```
#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "User": {
            "domain": "azuread",
            "name": "nirvaron",
            "rrn": "rrn:uba:eu:244e0f2e-2e23-43de-9910-da818cdf9ef8:user:15N2NECIYNFB"
        }
    }
}
```

#### Human Readable Output

>### Users
>|Rrn|Name|Domain|
>|---|---|---|
>| rrn:uba:eu:244e0f2e-2e23-43de-9910-da818cdf9ef8:user:15N2NECIYNFB | nirvaron | azuread |



### rapid7-insight-idr-query-log
***
Query inside a log for certain values.


#### Base Command

`rapid7-insight-idr-query-log`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_id | Logentries log key | Required |
| query | A valid LEQL query to run against the log. For more information: https://docs.rapid7.com/insightidr/build-a-query/ | Required |
| time_range | An optional time range string (i.e., 1 week, 1 day). When using this parameter, start_time and end_time isn't needed | Optional |
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1450557004000 | Optional |
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1460557604000 | Optional |
| logs_per_page | The number of log entries to return per page. Default of 50 | Optional |
| sequence_number | The earlier sequence number of a log entry to start searching from. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Event.log_id | String | Event message. |
| Rapid7InsightIDR.Event.message | String | ID of the log the event appears in. |
| Rapid7InsightIDR.Event.timestamp | Number | Time when the event fired. |


#### Command Example
```!rapid7-insight-idr-query-log log_id=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c query=where(destination_asset=\"jenkinsnode.someorganiztion.co\") start_time=0 end_time=3000557004000```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Event": [
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429120512?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.067Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755448,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237201778429120500,
                "sequence_number_str": "3237201778429120512",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429128704?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:57.509Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755429,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237201778429128700,
                "sequence_number_str": "3237201778429128704",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429132800?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.554Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755452,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"89715ccf32b3f36cc769952cf203bb177ba5ad8d775fc8794d6dd613d371d2f0\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429133000,
                "sequence_number_str": "3237201778429132800",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429136896?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:59.683Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755430,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429137000,
                "sequence_number_str": "3237201778429136896",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429140992?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:07.343Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755445,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237201778429141000,
                "sequence_number_str": "3237201778429140992",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429145088?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:08.986Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755446,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429145000,
                "sequence_number_str": "3237201778429145088",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177084416?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:36.743Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853390,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237199644177084400,
                "sequence_number_str": "3237199644177084416",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177088512?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.194Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853387,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237199644177088500,
                "sequence_number_str": "3237199644177088512",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177092608?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:39.212Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853394,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"fe326b6ee65a983946f2847f66f735ba41d20d096a13ea9fa7f8341ad5e7da61\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177092600,
                "sequence_number_str": "3237199644177092608",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177096704?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.872Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853388,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177096700,
                "sequence_number_str": "3237199644177096704",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879106560?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.401Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853508,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237134439879106600,
                "sequence_number_str": "3237134439879106560",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879110656?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.406Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853512,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237134439879110700,
                "sequence_number_str": "3237134439879110656",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570530304?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.538Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854639,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127759570530300,
                "sequence_number_str": "3237127759570530304",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570534400?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:04.843Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854655,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127759570534400,
                "sequence_number_str": "3237127759570534400",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570538496?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.841Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854640,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570538500,
                "sequence_number_str": "3237127759570538496",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570542592?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:07.557Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854659,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser@pts/2    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ddd669c2a201339a549a5d9bab79c8a61dfd6ff2b4b0ed846fa9798f5bf2cc9c\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570542600,
                "sequence_number_str": "3237127759570542592",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554612224?per_page=50&timestamp=1605541577601&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:13.083Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914355,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237202737554612000,
                "sequence_number_str": "3237202737554612224",
                "timestamp": 1605541577601
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554616320?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.886Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914725,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237202737554616300,
                "sequence_number_str": "3237202737554616320",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554620416?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:17.123Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914407,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554620400,
                "sequence_number_str": "3237202737554620416",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554624512?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.903Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914729,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554624500,
                "sequence_number_str": "3237202737554624512",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292884480?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:40.506Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969724,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127416292884500,
                "sequence_number_str": "3237127416292884480",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292888576?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:33.182Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969721,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127416292888600,
                "sequence_number_str": "3237127416292888576",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292892672?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:40.511Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969728,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127416292892700,
                "sequence_number_str": "3237127416292892672",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292896768?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:34.880Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969722,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127416292897000,
                "sequence_number_str": "3237127416292896768",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102485504?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:23.114Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969772,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237130189102485500,
                "sequence_number_str": "3237130189102485504",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102489600?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:31.957Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969775,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237130189102489600,
                "sequence_number_str": "3237130189102489600",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102493696?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:25.008Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969773,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237130189102493700,
                "sequence_number_str": "3237130189102493696",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102497792?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:31.962Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969779,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237130189102498000,
                "sequence_number_str": "3237130189102497792",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203842254422016?per_page=50&timestamp=1605630674347&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:30:28.652Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969891,\"pid\":5937,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630620500,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"3102d83225143e6bb4289a37b7bf75cdb923986cd1f742d25aa5754bb64371e1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237203842254422000,
                "sequence_number_str": "3237203842254422016",
                "timestamp": 1605630674347
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203842254426112?per_page=50&timestamp=1605630674347&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:30:28.657Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969895,\"pid\":5937,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630620500,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"3102d83225143e6bb4289a37b7bf75cdb923986cd1f742d25aa5754bb64371e1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237203842254426000,
                "sequence_number_str": "3237203842254426112",
                "timestamp": 1605630674347
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237198110196469760?per_page=50&timestamp=1605635851797&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T17:57:16.286Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971131,\"pid\":11113,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605635829560,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"80c8ca7211c3811e3f8771bbcd4a8ef96966c38c576baf1bed692ebb0f23c7cb\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237198110196470000,
                "sequence_number_str": "3237198110196469760",
                "timestamp": 1605635851797
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237198110196473856?per_page=50&timestamp=1605635851797&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T17:57:16.291Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971135,\"pid\":11113,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605635829560,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"80c8ca7211c3811e3f8771bbcd4a8ef96966c38c576baf1bed692ebb0f23c7cb\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237198110196474000,
                "sequence_number_str": "3237198110196473856",
                "timestamp": 1605635851797
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130286714318848?per_page=50&timestamp=1605636173197&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T18:02:22.639Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971269,\"pid\":11470,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605636137010,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"478a45813ee339a561058b995683e2b8046f7dec5980388d380b9aac9e86bd20\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237130286714319000,
                "sequence_number_str": "3237130286714318848",
                "timestamp": 1605636173197
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130286714322944?per_page=50&timestamp=1605636173197&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T18:02:22.644Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971273,\"pid\":11470,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605636137010,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"478a45813ee339a561058b995683e2b8046f7dec5980388d380b9aac9e86bd20\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237130286714323000,
                "sequence_number_str": "3237130286714322944",
                "timestamp": 1605636173197
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203267267010560?per_page=50&timestamp=1605648541800&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T21:28:33.116Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":974128,\"pid\":23906,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605648507610,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"41def18612308c2052a04f92b5c9cc782642d35bd9f1cccba842a563a08a460b\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237203267267010600,
                "sequence_number_str": "3237203267267010560",
                "timestamp": 1605648541800
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203267267014656?per_page=50&timestamp=1605648541800&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T21:28:33.118Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":974132,\"pid\":23906,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605648507610,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"41def18612308c2052a04f92b5c9cc782642d35bd9f1cccba842a563a08a460b\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237203267267014700,
                "sequence_number_str": "3237203267267014656",
                "timestamp": 1605648541800
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271236096?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:57.920Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002860,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237131626271236000,
                "sequence_number_str": "3237131626271236096",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271240192?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:42.482Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002854,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237131626271240000,
                "sequence_number_str": "3237131626271240192",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271244288?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:57.924Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002864,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237131626271244300,
                "sequence_number_str": "3237131626271244288",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271248384?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:45.493Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002855,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237131626271248400,
                "sequence_number_str": "3237131626271248384",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271252480?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:47.880Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002857,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237131626271252500,
                "sequence_number_str": "3237131626271252480",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271256576?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:50.403Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002858,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237131626271256600,
                "sequence_number_str": "3237131626271256576",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237170866055852032?per_page=50&timestamp=1605779255422&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T09:47:15.802Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1003669,\"pid\":27013,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605779227890,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d2c61c1e0d53ccdb81a8884c992121920d20d819948586559efe6ff5b9de0c12\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237170866055852000,
                "sequence_number_str": "3237170866055852032",
                "timestamp": 1605779255422
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237170866055856128?per_page=50&timestamp=1605779255422&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T09:47:15.805Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1003673,\"pid\":27013,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605779227890,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d2c61c1e0d53ccdb81a8884c992121920d20d819948586559efe6ff5b9de0c12\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237170866055856000,
                "sequence_number_str": "3237170866055856128",
                "timestamp": 1605779255422
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Results
>|log_id|message|timestamp|
>|---|---|---|
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.067Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755448,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:57.509Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755429,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.554Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":755452,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:59.683Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755430,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:07.343Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755445,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:08.986Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755446,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:36.743Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853390,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.194Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853387,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:39.212Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853394,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.872Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853388,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.401Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853508,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.406Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853512,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.538Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854639,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:04.843Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854655,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.841Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854640,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:07.557Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854659,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser@pts/2    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:13.083Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914355,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605541577601 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.886Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914725,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:17.123Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914407,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.903Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914729,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:40.506Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969724,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:33.182Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969721,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:40.511Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969728,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:34.880Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969722,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:23.114Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969772,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:31.957Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969775,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:25.008Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969773,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:31.962Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969779,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:30:28.652Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969891,"pid":5937,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630620500,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630674347 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:30:28.657Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969895,"pid":5937,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630620500,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630674347 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T17:57:16.286Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971131,"pid":11113,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605635829560,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605635851797 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T17:57:16.291Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971135,"pid":11113,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605635829560,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605635851797 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T18:02:22.639Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971269,"pid":11470,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605636137010,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605636173197 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T18:02:22.644Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971273,"pid":11470,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605636137010,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605636173197 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T21:28:33.116Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":974128,"pid":23906,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605648507610,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605648541800 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T21:28:33.118Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":974132,"pid":23906,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605648507610,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605648541800 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:57.920Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002860,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:42.482Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002854,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:57.924Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002864,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:45.493Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002855,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:47.880Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002857,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:50.403Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002858,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T09:47:15.802Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1003669,"pid":27013,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605779227890,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605779255422 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T09:47:15.805Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1003673,"pid":27013,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605779227890,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605779255422 |


### rapid7-insight-idr-query-log-set
***
Query inside a log set for certain values.


#### Base Command

`rapid7-insight-idr-query-log-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_set_id | log set ID | Required |
| query | A valid LEQL query to run against the log. For more information: https://docs.rapid7.com/insightidr/build-a-query/ | Required |
| time_range | An optional time range string (i.e., 1 week, 1 day). When using this parameter, start_time and end_time isn't needed | Optional |
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1450557004000 | Optional |
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1460557604000 | Optional |
| logs_per_page | The number of log entries to return per page. Default of 50 | Optional |
| sequence_number | The earlier sequence number of a log entry to start searching from. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Event.log_id | String | Event message. |
| Rapid7InsightIDR.Event.message | String | ID of the log the event appears in. |
| Rapid7InsightIDR.Event.timestamp | Number | Time when the event fired. |


#### Command Example
```!rapid7-insight-idr-query-log-set log_set_id=74c4af9d-2673-4bc2-b8e8-afe3d1354987 query=where(destination_asset=\"jenkinsnode.someorganiztion.co\") start_time=0 end_time=3000557004000```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Event": [
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429120512?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.067Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755448,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237201778429120500,
                "sequence_number_str": "3237201778429120512",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429128704?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:57.509Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755429,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237201778429128700,
                "sequence_number_str": "3237201778429128704",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429132800?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.554Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755452,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"89715ccf32b3f36cc769952cf203bb177ba5ad8d775fc8794d6dd613d371d2f0\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429133000,
                "sequence_number_str": "3237201778429132800",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429136896?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:59.683Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755430,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429137000,
                "sequence_number_str": "3237201778429136896",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429140992?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:07.343Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755445,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237201778429141000,
                "sequence_number_str": "3237201778429140992",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429145088?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:08.986Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755446,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429145000,
                "sequence_number_str": "3237201778429145088",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177084416?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:36.743Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853390,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237199644177084400,
                "sequence_number_str": "3237199644177084416",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177088512?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.194Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853387,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237199644177088500,
                "sequence_number_str": "3237199644177088512",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177092608?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:39.212Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853394,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"fe326b6ee65a983946f2847f66f735ba41d20d096a13ea9fa7f8341ad5e7da61\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177092600,
                "sequence_number_str": "3237199644177092608",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177096704?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.872Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853388,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177096700,
                "sequence_number_str": "3237199644177096704",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879106560?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.401Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853508,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237134439879106600,
                "sequence_number_str": "3237134439879106560",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879110656?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.406Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853512,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237134439879110700,
                "sequence_number_str": "3237134439879110656",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570530304?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.538Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854639,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127759570530300,
                "sequence_number_str": "3237127759570530304",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570534400?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:04.843Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854655,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127759570534400,
                "sequence_number_str": "3237127759570534400",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570538496?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.841Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854640,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570538500,
                "sequence_number_str": "3237127759570538496",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570542592?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:07.557Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854659,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: someuser@pts/2    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ddd669c2a201339a549a5d9bab79c8a61dfd6ff2b4b0ed846fa9798f5bf2cc9c\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570542600,
                "sequence_number_str": "3237127759570542592",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554612224?per_page=50&timestamp=1605541577601&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:13.083Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914355,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237202737554612000,
                "sequence_number_str": "3237202737554612224",
                "timestamp": 1605541577601
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554616320?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.886Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914725,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237202737554616300,
                "sequence_number_str": "3237202737554616320",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554620416?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:17.123Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914407,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554620400,
                "sequence_number_str": "3237202737554620416",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554624512?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.903Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914729,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554624500,
                "sequence_number_str": "3237202737554624512",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292884480?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:40.506Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969724,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127416292884500,
                "sequence_number_str": "3237127416292884480",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292888576?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:33.182Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969721,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237127416292888600,
                "sequence_number_str": "3237127416292888576",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292892672?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:40.511Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969728,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127416292892700,
                "sequence_number_str": "3237127416292892672",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127416292896768?per_page=50&timestamp=1605630543983&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:28:34.880Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969722,\"pid\":5715,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630502030,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ea37db9287ae773a36408bac9370614fde7f254b3e49a572d6788ce69340d234\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127416292897000,
                "sequence_number_str": "3237127416292896768",
                "timestamp": 1605630543983
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102485504?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:23.114Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969772,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237130189102485500,
                "sequence_number_str": "3237130189102485504",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102489600?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:31.957Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969775,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237130189102489600,
                "sequence_number_str": "3237130189102489600",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102493696?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:25.008Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969773,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237130189102493700,
                "sequence_number_str": "3237130189102493696",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130189102497792?per_page=50&timestamp=1605630611317&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:29:31.962Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969779,\"pid\":5773,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630548740,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a24a9a05594179b0f8fed7ec73cd097e3c58e3720dc654f38566a1f78504c219\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237130189102498000,
                "sequence_number_str": "3237130189102497792",
                "timestamp": 1605630611317
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203842254422016?per_page=50&timestamp=1605630674347&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:30:28.652Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969891,\"pid\":5937,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630620500,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"3102d83225143e6bb4289a37b7bf75cdb923986cd1f742d25aa5754bb64371e1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237203842254422000,
                "sequence_number_str": "3237203842254422016",
                "timestamp": 1605630674347
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203842254426112?per_page=50&timestamp=1605630674347&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T16:30:28.657Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":969895,\"pid\":5937,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605630620500,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"3102d83225143e6bb4289a37b7bf75cdb923986cd1f742d25aa5754bb64371e1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237203842254426000,
                "sequence_number_str": "3237203842254426112",
                "timestamp": 1605630674347
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237198110196469760?per_page=50&timestamp=1605635851797&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T17:57:16.286Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971131,\"pid\":11113,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605635829560,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"80c8ca7211c3811e3f8771bbcd4a8ef96966c38c576baf1bed692ebb0f23c7cb\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237198110196470000,
                "sequence_number_str": "3237198110196469760",
                "timestamp": 1605635851797
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237198110196473856?per_page=50&timestamp=1605635851797&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T17:57:16.291Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971135,\"pid\":11113,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605635829560,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"80c8ca7211c3811e3f8771bbcd4a8ef96966c38c576baf1bed692ebb0f23c7cb\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237198110196474000,
                "sequence_number_str": "3237198110196473856",
                "timestamp": 1605635851797
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130286714318848?per_page=50&timestamp=1605636173197&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T18:02:22.639Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971269,\"pid\":11470,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605636137010,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"478a45813ee339a561058b995683e2b8046f7dec5980388d380b9aac9e86bd20\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237130286714319000,
                "sequence_number_str": "3237130286714318848",
                "timestamp": 1605636173197
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237130286714322944?per_page=50&timestamp=1605636173197&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T18:02:22.644Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":971273,\"pid\":11470,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605636137010,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"478a45813ee339a561058b995683e2b8046f7dec5980388d380b9aac9e86bd20\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237130286714323000,
                "sequence_number_str": "3237130286714322944",
                "timestamp": 1605636173197
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203267267010560?per_page=50&timestamp=1605648541800&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T21:28:33.116Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":974128,\"pid\":23906,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605648507610,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"41def18612308c2052a04f92b5c9cc782642d35bd9f1cccba842a563a08a460b\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237203267267010600,
                "sequence_number_str": "3237203267267010560",
                "timestamp": 1605648541800
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237203267267014656?per_page=50&timestamp=1605648541800&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-17T21:28:33.118Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":974132,\"pid\":23906,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605648507610,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"41def18612308c2052a04f92b5c9cc782642d35bd9f1cccba842a563a08a460b\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237203267267014700,
                "sequence_number_str": "3237203267267014656",
                "timestamp": 1605648541800
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271236096?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:57.920Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002860,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237131626271236000,
                "sequence_number_str": "3237131626271236096",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271240192?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:42.482Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002854,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237131626271240000,
                "sequence_number_str": "3237131626271240192",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271244288?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:57.924Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002864,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237131626271244300,
                "sequence_number_str": "3237131626271244288",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271248384?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:45.493Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002855,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237131626271248400,
                "sequence_number_str": "3237131626271248384",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271252480?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:47.880Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002857,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237131626271252500,
                "sequence_number_str": "3237131626271252480",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237131626271256576?per_page=50&timestamp=1605775912448&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T08:50:50.403Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1002858,\"pid\":23548,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605775839850,\"cmdLine\":\"sshd: someuser [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d95fde1d186923f4810692d7e52a85301b54fce1d3e189b8ceea0cb3c76d4068\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237131626271256600,
                "sequence_number_str": "3237131626271256576",
                "timestamp": 1605775912448
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237170866055852032?per_page=50&timestamp=1605779255422&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T09:47:15.802Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1003669,\"pid\":27013,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"someuser\",\"hostname\":\"x.x.x.x\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605779227890,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d2c61c1e0d53ccdb81a8884c992121920d20d819948586559efe6ff5b9de0c12\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\"}}",
                "sequence_number": 3237170866055852000,
                "sequence_number_str": "3237170866055852032",
                "timestamp": 1605779255422
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237170866055856128?per_page=50&timestamp=1605779255422&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-19T09:47:15.805Z\",\"destination_asset\":\"jenkinsnode.someorganiztion.co\",\"source_asset_address\":\"x.x.x.x\",\"destination_asset_address\":\"jenkinsnode.someorganiztion.co\",\"destination_local_account\":\"someuser\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":1003673,\"pid\":27013,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"someuser\",\"addr\":\"x.x.x.x\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605779227890,\"cmdLine\":\"sshd: someuser@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d2c61c1e0d53ccdb81a8884c992121920d20d819948586559efe6ff5b9de0c12\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"someuser\",\"gidName\":\"someuser\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"someuser\",\"egidName\":\"someuser\",\"auidName\":null,\"domain\":\"someorganiztion.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237170866055856000,
                "sequence_number_str": "3237170866055856128",
                "timestamp": 1605779255422
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Results
>|log_id|message|timestamp|
>|---|---|---|
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.067Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755448,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:57.509Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755429,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.554Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":755452,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:59.683Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755430,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:07.343Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755445,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:08.986Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755446,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:36.743Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853390,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.194Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853387,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:39.212Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853394,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.872Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853388,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.401Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853508,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.406Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853512,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.538Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854639,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:04.843Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854655,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.841Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854640,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:07.557Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854659,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: someuser@pts/2    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:13.083Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914355,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605541577601 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.886Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914725,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:17.123Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914407,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.903Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914729,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:40.506Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969724,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:33.182Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969721,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:40.511Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969728,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:28:34.880Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969722,"pid":5715,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630502030,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630543983 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:23.114Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969772,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:31.957Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969775,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:25.008Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969773,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:29:31.962Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969779,"pid":5773,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630548740,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630611317 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:30:28.652Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969891,"pid":5937,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630620500,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605630674347 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T16:30:28.657Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":969895,"pid":5937,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605630620500,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605630674347 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T17:57:16.286Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971131,"pid":11113,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605635829560,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605635851797 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T17:57:16.291Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971135,"pid":11113,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605635829560,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605635851797 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T18:02:22.639Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971269,"pid":11470,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605636137010,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605636173197 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T18:02:22.644Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":971273,"pid":11470,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605636137010,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605636173197 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T21:28:33.116Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":974128,"pid":23906,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605648507610,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605648541800 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-17T21:28:33.118Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":974132,"pid":23906,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605648507610,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605648541800 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:57.920Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002860,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:42.482Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002854,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:57.924Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002864,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:45.493Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002855,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:47.880Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002857,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T08:50:50.403Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1002858,"pid":23548,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"failed","type":1100,"startTime":1605775839850,"cmdLine":"sshd: someuser [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605775912448 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T09:47:15.802Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1003669,"pid":27013,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"someuser","hostname":"x.x.x.x","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605779227890,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co"}} | 1605779255422 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-19T09:47:15.805Z","destination_asset":"jenkinsnode.someorganiztion.co","source_asset_address":"x.x.x.x","destination_asset_address":"jenkinsnode.someorganiztion.co","destination_local_account":"someuser","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":1003673,"pid":27013,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"someuser","addr":"x.x.x.x","terminal":"ssh","res":"success","type":1100,"startTime":1605779227890,"cmdLine":"sshd: someuser@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"hashes":{"sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"someuser","gidName":"someuser"},"euid":0,"egid":0,"uidName":null,"euidName":"someuser","egidName":"someuser","auidName":null,"domain":"someorganiztion.co","hostname":"jenkinsnode"}} | 1605779255422 |