Triggers by triaged alerts from endpoint, cloud, and network security monitoring. Contains event details and easy-to-follow mitigation steps.
This integration was integrated and tested with version 1.1.10 of Covalence Managed Security.

## Configure Covalence Managed Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Covalence Managed Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Credentials |  | True |
    | Password |  | True |
    | Use system proxy settings |  | False |
    | First run time range | When fetching incidents for the first time, this parameter specifies in days how far the integration looks for incidents. For instance if set to "2", it will pull all alerts in Covalence for the last 2 days and will create corresponding incidents. | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Fetch Limit | the maximum number of incidents to fetch | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cov-mgsec-get-aro

***
Query FES Portal for ARO.

#### Base Command

`cov-mgsec-get-aro`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| details | if details=true, will return the complete response from Covalence API. | Optional | 
| query | Portal query, for example: "resolution=Unresolved&amp;type=Recommendation"<br/>Available Keys to filter on:<br/>- id; eg: "id=&lt;ARO_id&gt;<br/>- status; eg: "status=In Triage" or "status=Open" or "status=Closed"<br/>- resolution; eg: "resolution=Unresolved" or "resolution=Resolved" or "resolution=Help Requested" or "resolution=Dismissed"<br/>- type; eg: "type=Action" or "type=Recommendation" or "type=Observation"<br/>- org; eg: "org=&lt;organization_name&gt;"<br/>- since; eg: "since=2021-01-31 14:00:00"<br/>- until; eg: "until=2021-01-31 14:00:00". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESPortal.Aro.ID | String | ID. | 
| FESPortal.Aro.alert_key | String | Alert_key. | 
| FESPortal.Aro.analyst_notes | String | Analyst_notes. | 
| FESPortal.Aro.count | Number | Count. | 
| FESPortal.Aro.creation_time | Date | Creation_time. | 
| FESPortal.Aro.details | String | Details. | 
| FESPortal.Aro.details_markdown | String | Details_markdown. | 
| FESPortal.Aro.display_url | String | Display_url. | 
| FESPortal.Aro.external_bug_id | String | External_bug_id. | 
| FESPortal.Aro.last_updated_time | Date | Last_updated_time. | 
| FESPortal.Aro.notes | String | Notes. | 
| FESPortal.Aro.organization.ID | String | ID. | 
| FESPortal.Aro.organization.email | String | Email. | 
| FESPortal.Aro.organization.name | String | Name. | 
| FESPortal.Aro.resolution | String | Resolution. | 
| FESPortal.Aro.serial_id | String | Serial_id. | 
| FESPortal.Aro.severity | String | Severity. | 
| FESPortal.Aro.status | String | Status. | 
| FESPortal.Aro.steps.ID | String | ID. | 
| FESPortal.Aro.steps.completed | Boolean | Completed. | 
| FESPortal.Aro.steps.label | String | Label. | 
| FESPortal.Aro.steps.last_updated_time | Date | Last_updated_time. | 
| FESPortal.Aro.template_id | String | Template_id. | 
| FESPortal.Aro.title | String | Title. | 
| FESPortal.Aro.triage_id | String | Triage_id. | 
| FESPortal.Aro.type | String | Type. | 

#### Command example
```!cov-mgsec-get-aro query="since=2023-11-30 18:00:00"```
#### Context Example
```json
{
    "FESPortal": {
        "ARO": [
            {
                "organization": {
                    "ID": "9d4297ea-089e-42bd-884d-51744e31a471",
                    "email": "foo@bar.com",
                    "name": "Acme"
                },
                "resolution": "Unresolved",
                "severity": "Critical",
                "status": "Open",
                "title": "test2",
                "type": "Action"
            },
            {
                "organization": {
                    "ID": "e0e04c8b-d50c-4379-bfd6-5e0f2b1037cd",
                    "email": "foo@bar.com",
                    "name": "Capsule Corp"
                },
                "resolution": "Unresolved",
                "severity": "High",
                "status": "Open",
                "title": "Vulnerable Software Detected",
                "type": "Recommendation"
            }
        ]
    }
}
```

#### Human Readable Output

>### AROs
>|Organization|Resolution|Severity|Status|Title|Type|
>|---|---|---|---|---|---|
>| ID: 9d4297ea-089e-42bd-884d-51744e31a471<br/>email: foo@bar.com<br/>name: Acme | Unresolved | Critical | Open | test2 | Action |
>| ID: e0e04c8b-d50c-4379-bfd6-5e0f2b1037cd<br/>email: foo@bar.com<br/>name: Capsule Corp | Unresolved | High | Open | Vulnerable Software Detected | Recommendation |


### cov-mgsec-list-org

***
List organizations.

#### Base Command

`cov-mgsec-list-org`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESPortal.Org.ID | String | ID. | 
| FESPortal.Org.email | String | Email. | 
| FESPortal.Org.email_aro_details | Boolean | Email_aro_details. | 
| FESPortal.Org.name | String | Name. | 

#### Command example
```!cov-mgsec-list-org```
#### Context Example
```json
{
    "FESPortal": {
        "Org": [
            {
                "ID": "9d4297ea-089e-42bd-884d-51744e31a471",
                "email": "foo@bar.com",
                "email_aro_details": false,
                "name": "Acme"
            },
            {
                "ID": "e0e04c8b-d50c-4379-bfd6-5e0f2b1037cd",
                "email": "foo@bar.com",
                "email_aro_details": false,
                "name": "Capsule Corp"
            }
        ]
    }
}
```

#### Human Readable Output

>### Organizations
>|Id|Email|Email Aro Details|Name|
>|---|---|---|---|
>| 9d4297ea-089e-42bd-884d-51744e31a471 | foo@bar.com | false | Acme |
>| e0e04c8b-d50c-4379-bfd6-5e0f2b1037cd | foo@bar.com | false | Capsule Corp |


### cov-mgsec-transition-aro

***
Transition an ARO.

#### Base Command

`cov-mgsec-transition-aro`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| aro_id | This ARO ID to transition. | Required | 
| resolution | Resolution to transition the ARO to.  Options include: Unresolved, Help Requested, Resolved, or Dismissed. | Required | 
| comment | Optional comment to leave on the ARO. | Optional | 
| is_comment_sensitive | Optionally mark the comment as sensitive. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESPortal.Aro.ID | String | ID. | 
| FESPortal.Aro.alert_key | String | Alert_key. | 
| FESPortal.Aro.analyst_notes | String | Analyst_notes. | 
| FESPortal.Aro.count | Number | Count. | 
| FESPortal.Aro.creation_time | Date | Creation_time. | 
| FESPortal.Aro.details | String | Details. | 
| FESPortal.Aro.details_markdown | String | Details_markdown. | 
| FESPortal.Aro.display_url | String | Display_url. | 
| FESPortal.Aro.external_bug_id | String | External_bug_id. | 
| FESPortal.Aro.last_updated_time | Date | Last_updated_time. | 
| FESPortal.Aro.notes | String | Notes. | 
| FESPortal.Aro.organization.ID | String | ID. | 
| FESPortal.Aro.organization.email | String | Email. | 
| FESPortal.Aro.organization.name | String | Name. | 
| FESPortal.Aro.resolution | String | Resolution. | 
| FESPortal.Aro.serial_id | String | Serial_id. | 
| FESPortal.Aro.severity | String | Severity. | 
| FESPortal.Aro.status | String | Status. | 
| FESPortal.Aro.steps.ID | String | ID. | 
| FESPortal.Aro.steps.completed | Boolean | Completed. | 
| FESPortal.Aro.steps.label | String | Label. | 
| FESPortal.Aro.steps.last_updated_time | Date | Last_updated_time. | 
| FESPortal.Aro.template_id | String | Template_id. | 
| FESPortal.Aro.title | String | Title. | 
| FESPortal.Aro.triage_id | String | Triage_id. | 
| FESPortal.Aro.type | String | Type. | 

#### Command example
```!cov-mgsec-transition-aro aro_id="7ea9b17d-7529-4b17-b0e7-92334d6c674b" resolution="Resolved" comment="Risk mitigated."```
#### Context Example
```json
{
    "FESPortal": {
        "Org": {
            "ID": "7ea9b17d-7529-4b17-b0e7-92334d6c674b",
            "alert_key": "test_alert_key",
            "attachments": [],
            "count": 1,
            "creation_time": "2023-08-16 19:48:02",
            "data": null,
            "details": "ARO Details",
            "details_markdown": null,
            "display_url": "test_url",
            "external_ticket": null,
            "frameworks": [],
            "insights": {},
            "last_updated_time": "2023-11-30 19:01:59",
            "organization": {
                "ID": "test_ID",
                "email": null,
                "name": "test_org_id"
            },
            "references": [],
            "resolution": "Resolved",
            "resolution_duration_seconds": 9155637,
            "resolution_time": "2023-11-30 19:01:59",
            "serial_id": "15",
            "severity": "Low",
            "status": "Open",
            "steps": [
                {
                    "ID": "test_id",
                    "completed": true,
                    "label": "test_resolution_step",
                    "last_updated_time": "2023-10-24 20:53:45"
                }
            ],
            "template_id": null,
            "title": "test_aro_title",
            "triage_id": null,
            "type": "Observation"
        }
    }
}
```

#### Human Readable Output

>### ARO
>|Id|Alert Key|Count|Creation Time|Details|Display Url|Last Updated Time|Organization|Resolution|Resolution Duration Seconds|Resolution Time|Serial Id|Severity|Status| Steps|Title|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 7ea9b17d-7529-4b17-b0e7-92334d6c674b | test_alert_key | 1 | 2023-08-16 19:48:02 | ARO Details | test_url | 2023-11-30 19:01:59 | ID: test_ID<br/>email: null<br/>name: test_org_id | Resolved | 9155637 | 2023-11-30 19:01:59 | 15 | Low | Open | {'ID': 'test_id', 'completed': True, 'label': 'test_resolution_step', 'last_updated_time': '2023-10-24 20:53:45'} | test_aro_title | Observation |

