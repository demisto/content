Triggers by triaged alerts from endpoint, cloud, and network security monitoring. Contains event details and easy-to-follow mitigation steps.
This integration was integrated and tested with version 1.1.10 of Covalence Managed Security.

## Configure Covalence Managed Security in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Credentials |  | True |
| Password |  | True |
| Use system proxy settings |  | False |
| First run time range | When fetching incidents for the first time, this parameter specifies in days how far the integration looks for incidents. For instance if set to "2", it will pull all alerts in Covalence for the last 2 days and will create corresponding incidents. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Fetch Limit | The maximum number of incidents to fetch | False |
| Broker Server URL | Broker Server URL (Optional).  Required to use Broker commands. | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| resolution | Resolution to transition the ARO to. Possible values are: Unresolved, Help Requested, Resolved, Dismissed. | Required | 
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
### cov-mgsec-broker-cloud-action-by-aro

***
Broker - Cloud Action By ARO.

#### Base Command

`cov-mgsec-broker-cloud-action-by-aro`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | Action to perform. Possible values are: DISABLE_USER, ENABLE_USER, REVOKE_SESSIONS. | Required | 
| aro_id | ARO ID (eg. "00000000-1111-2222-3333-444444444444"). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESBroker.action_id | String | Action ID | 
| FESBroker.action_type | String | Action Type | 
| FESBroker.action_params | Unknown | Action Parameters | 
| FESBroker.created_time | String | Created Time | 
| FESBroker.status | String | Status | 
| FESBroker.result | String | Result | 

#### Command example
```!cov-mgsec-broker-cloud-action-by-aro action_type=DISABLE_USER aro_id=00000000-1111-2222-3333-444444444444```
#### Context Example
```json
{
    "FESBroker": {
        "Action": {
            "action_id": "00000000-1111-2222-3333-444444444444",
            "action_params": {
                "user": "azure credential configuration endpoint service"
            },
            "action_type": "disable_user",
            "created_time": "2024-02-22T01:27:04.344179Z",
            "result": "SUCCESS",
            "status": "COMPLETE"
        }
    }
}
```

#### Human Readable Output

>### Command Result
>|action_id|action_params|action_type|created_time|result|status|
>|---|---|---|---|---|---|
>| 00000000-1111-2222-3333-444444444444 | user: azure credential configuration endpoint service | disable_user | 2024-02-22T01:27:04.344179Z | SUCCESS | COMPLETE |


### cov-mgsec-broker-endpoint-action-by-aro

***
Broker - Endpoint Action By ARO.

#### Base Command

`cov-mgsec-broker-endpoint-action-by-aro`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | Action to send to Host. Possible values are: ISOLATE, UNISOLATE, SHUTDOWN, RESTART, DEFENDER_QUICK_SCAN, DEFENDER_FULL_SCAN, DEFENDER_SIGNATURE_UPDATE. | Required | 
| aro_id | ARO ID (eg. "00000000-1111-2222-3333-444444444444"). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESBroker.host_identifier | String | Host Identifier | 
| FESBroker.agent_uuid | String | Agent UUID | 
| FESBroker.covalence_appliance | String | Covalence Appliance ID | 
| FESBroker.task_id | Number | Endpoint Action Task ID | 

#### Command example
```!cov-mgsec-broker-endpoint-action-by-aro action_type=DEFENDER_QUICK_SCAN aro_id=00000000-1111-2222-3333-444444444444```
#### Context Example
```json
{
    "FESBroker": {
        "Action": {
            "agent_uuid": "00000000-1111-2222-3333-444444444444",
            "covalence_appliance": "2000-001-XX-0",
            "host_identifier": "00000000-1111-2222-3333-444444444444",
            "task_id": 26876
        }
    }
}
```

#### Human Readable Output

>### Command Result - Success
>|agent_uuid|covalence_appliance|host_identifier|task_id|
>|---|---|---|---|
>| 00000000-1111-2222-3333-444444444444 | 2000-001-XX-0 | 00000000-1111-2222-3333-444444444444 | 26876 |


### cov-mgsec-broker-ping

***
Broker - Ping.

#### Base Command

`cov-mgsec-broker-ping`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESBroker.APIStatus | String | API Status | 

#### Command example
```!cov-mgsec-broker-ping```
#### Context Example
```json
{
    "FESBroker": {
        "APIStatus": "pong"
    }
}
```

#### Human Readable Output

>## Success

### cov-mgsec-broker-endpoint-action-by-host

***
Broker - Endpoint Action By Host.

#### Base Command

`cov-mgsec-broker-endpoint-action-by-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | Action to send to Host. Possible values are: ISOLATE, UNISOLATE, SHUTDOWN, RESTART, DEFENDER_QUICK_SCAN, DEFENDER_FULL_SCAN, DEFENDER_SIGNATURE_UPDATE. | Required | 
| org_id | Organization ID (eg. "00000000-1111-2222-3333-444444444444"). | Required | 
| host_identifier | Hostname. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESBroker.host_identifier | String | Host Identifier | 
| FESBroker.agent_uuid | String | Agent UUID | 
| FESBroker.covalence_appliance | String | Covalence Appliance ID | 
| FESBroker.task_id | Number | Endpoint Action Task ID | 

#### Command example
```!cov-mgsec-broker-endpoint-action-by-host action_type=DEFENDER_QUICK_SCAN host_identifier=test-hostname org_id=00000000-1111-2222-3333-444444444444```
#### Context Example
```json
{
    "FESBroker": {
        "Action": {
            "agent_uuid": "00000000-1111-2222-3333-444444444444",
            "covalence_appliance": "2000-001-XX-0",
            "host_identifier": "test-hostname",
            "task_id": 24773
        }
    }
}
```

#### Human Readable Output

>### Command Result - Success
>|agent_uuid|covalence_appliance|host_identifier|task_id|
>|---|---|---|---|
>| 00000000-1111-2222-3333-444444444444 | 2000-001-XX-0 | test-hostname | 24773 |


### cov-mgsec-broker-list-org

***
Broker - List organizations.

#### Base Command

`cov-mgsec-broker-list-org`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESBroker.ID | String | Organization ID | 
| FESBroker.name | String | Organization Name | 
| FESBroker.client_id | String | Client ID | 

#### Command example
```!cov-mgsec-broker-list-org```
#### Context Example
```json
{
    "FESBroker": {
        "Org": [
            {
                "ID": "00000000-1111-2222-3333-444444444444",
                "client_id": "2000-001-XX-0",
                "name": "Test Company"
            }
        ]
    }
}
```

#### Human Readable Output

>### Organizations
>|ID|client_id|name|
>|---|---|---|
>| 00000000-1111-2222-3333-444444444444 | 2024-1384-SAN | 110 Sand Company |



### cov-mgsec-comment-aro

***
Comment on an ARO.

#### Base Command

`cov-mgsec-comment-aro`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| aro_id | This ARO ID to transition. | Required | 
| comment | Comment to leave on the ARO. | Required | 
| is_comment_sensitive | Optionally mark the comment as sensitive. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FESPortal.Aro.ID | String | ID. | 
| FESPortal.Aro.acknowledged | Boolean | Acknowledged | 
| FESPortal.Aro.acknowledged_by.ID | String | Acknowledged By ID | 
| FESPortal.Aro.acknowledged_by.avatar_file_url | String | Acknowledged By | 
| FESPortal.Aro.acknowledged_by.email | String | Acknowledged By Email | 
| FESPortal.Aro.acknowledged_by.first_name | String | Acknowledged By First Name | 
| FESPortal.Aro.acknowledged_by.last_name | String | Acknowledged By Last Name | 
| FESPortal.Aro.acknowledged_time | Date | Acknowledged Time | 
| FESPortal.Aro.aro_id | String | ARO ID | 
| FESPortal.Aro.author.ID | String | Author ID | 
| FESPortal.Aro.author.avatar_file_url | String | Author Avatar File URL | 
| FESPortal.Aro.author.email | String | Author Email | 
| FESPortal.Aro.author.first_name | String | Author First Name | 
| FESPortal.Aro.author.last_name | String | Author Last Name | 
| FESPortal.Aro.author_organization.ID | String | Author Organization ID | 
| FESPortal.Aro.author_organization.email | String | Author Organization Email | 
| FESPortal.Aro.author_organization.name | String | Author Organization Name | 
| FESPortal.Aro.author_organization_type | String | Author Organization Type | 
| FESPortal.Aro.available_only_to_organization_id | String | ARO Comment Available Only to Organization ID | 
| FESPortal.Aro.available_only_to_provider_id | String | ARO Comment Available Only to Provider ID | 
| FESPortal.Aro.created_time | Date | ARO Created Time | 
| FESPortal.Aro.id | String | ARO Comment ID | 
| FESPortal.Aro.last_updated_time | Date | ARO Comment Last Updated Time | 
| FESPortal.Aro.sensitive | Boolean | ARO Comment Sensitive | 
| FESPortal.Aro.source | String | ARO Comment Source | 
| FESPortal.Aro.text | String | ARO Comment Text | 
| FESPortal.Aro.type | String | ARO Comment Type | 
| FESPortal.Aro.visible_to.ID | String | ARO Comment Visible to ID | 
| FESPortal.Aro.visible_to.email | String | ARO Comment Visible to Email | 
| FESPortal.Aro.visible_to.name | String | ARO Comment Visible to Name | 

#### Command example
```!cov-mgsec-comment-aro aro_id="b25e461e-75e9-415b-a631-6d0f4516f33a" comment="Risk mitigated."```
#### Context Example
```json
{
    "FESPortal": {
        "Org": {
            "acknowledged": true,
            "acknowledged_by": {
                "ID": "abcdefghijklmnopqrstuvwxyzabd1",
                "avatar_file_url": null,
                "email": "foo@bar.com",
                "first_name": "John",
                "last_name": "Smith"
            },
            "acknowledged_time": "2024-04-12 17:01:25",
            "aro_id": "b25e461e-75e9-415b-a631-6d0f4516f33a",
            "author": {
                "ID": "abcdefghijklmnopqrstuvwxyzabd1",
                "avatar_file_url": null,
                "email": "foo@bar.com",
                "first_name": "John",
                "last_name": "Smith"
            },
            "author_organization": {
                "ID": "00000000-1111-2222-3333-444444444444",
                "email": "foo@bar.com",
                "name": "Field Effect"
            },
            "author_organization_type": "Field Effect",
            "available_only_to_organization_id": null,
            "available_only_to_provider_id": null,
            "created_time": "2024-04-12 17:01:25",
            "id": "b14a53a4-23ac-488d-b992-dbc1d5ef5361",
            "last_updated_time": "2024-04-12 17:01:25",
            "sensitive": false,
            "source": "Portal",
            "text": "Risk mitigated.",
            "type": "Comment",
            "visible_to": [
                {
                    "ID": "00000000-1111-2222-3333-444444444444",
                    "email": null,
                    "name": "Tradecraft Test & Development (Do Not Delete)"
                },
                {
                    "ID": "00000000-1111-2222-3333-444444444444",
                    "email": "foo@bar.com",
                    "name": "Field Effect"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ARO
>|Acknowledged|Acknowledged By|Acknowledged Time|Aro Id|Author|Author Organization|Author Organization Type|Created Time|Id|Last Updated Time|Sensitive|Source|Text|Type|Visible To|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | ID: abcdefghijklmnopqrstuvwxyzabd1<br/>avatar_file_url: null<br/>email: foo@bar.com<br/>first_name: John<br/>last_name: Smith | 2024-04-12 17:01:25 | b25e461e-75e9-415b-a631-6d0f4516f33a | ID: abcdefghijklmnopqrstuvwxyzabd1<br/>avatar_file_url: null<br/>email: foo@bar.com<br/>first_name: John<br/>last_name: Smith | ID: 00000000-1111-2222-3333-444444444444<br/>email: foo@bar.com<br/>name: Field Effect | Field Effect | 2024-04-12 17:01:25 | b14a53a4-23ac-488d-b992-dbc1d5ef5361 | 2024-04-12 17:01:25 | false | Portal | Risk mitigated. | Comment | {'ID': '00000000-1111-2222-3333-444444444444', 'email': None, 'name': 'Tradecraft Test & Development (Do Not Delete)'},<br/>{'ID': '00000000-1111-2222-3333-444444444444', 'email': 'foo@bar.com', 'name': 'Field Effect'} |
