Triggers by triaged alerts from endpoint, cloud, and network security monitoring. Contains event details and easy-to-follow mitigation steps.
This integration was integrated and tested with version 3.0 of Covalence Managed Security

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
    | None |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cov-mgsec-get-aro
***
Query FES Portal for ARO


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
| FESPortal.Aro.ID | String | ID | 
| FESPortal.Aro.alert_key | String | Alert_key | 
| FESPortal.Aro.analyst_notes | String | Analyst_notes | 
| FESPortal.Aro.count | Number | Count | 
| FESPortal.Aro.creation_time | Date | Creation_time | 
| FESPortal.Aro.details | String | Details | 
| FESPortal.Aro.details_markdown | String | Details_markdown | 
| FESPortal.Aro.display_url | String | Display_url | 
| FESPortal.Aro.external_bug_id | String | External_bug_id | 
| FESPortal.Aro.last_updated_time | Date | Last_updated_time | 
| FESPortal.Aro.notes | String | Notes | 
| FESPortal.Aro.organization.ID | String | ID | 
| FESPortal.Aro.organization.email | String | Email | 
| FESPortal.Aro.organization.name | String | Name | 
| FESPortal.Aro.resolution | String | Resolution | 
| FESPortal.Aro.serial_id | String | Serial_id | 
| FESPortal.Aro.severity | String | Severity | 
| FESPortal.Aro.status | String | Status | 
| FESPortal.Aro.steps.ID | String | ID | 
| FESPortal.Aro.steps.completed | Boolean | Completed | 
| FESPortal.Aro.steps.label | String | Label | 
| FESPortal.Aro.steps.last_updated_time | Date | Last_updated_time | 
| FESPortal.Aro.template_id | String | Template_id | 
| FESPortal.Aro.title | String | Title | 
| FESPortal.Aro.triage_id | String | Triage_id | 
| FESPortal.Aro.type | String | Type | 


#### Command Example
```!cov-mgsec-get-aro query="resolution=Unresolved"```

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
List organizations


#### Base Command

`cov-mgsec-list-org`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESPortal.Org.ID | String | ID | 
| FESPortal.Org.email | String | Email | 
| FESPortal.Org.email_aro_details | Boolean | Email_aro_details | 
| FESPortal.Org.name | String | Name | 


#### Command Example
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

