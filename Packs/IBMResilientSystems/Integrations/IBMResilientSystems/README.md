Case management that enables visibility across your tools for continual IR improvement.

## Configure IBM Resilient Systems on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IBM Resilient Systems.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. 192.168.0.1) | True |
    | Credentials | False |
    | Password | False |
    | Organization name | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | First fetch timestamp (YYYY-MM-DDTHH:MM:SSZ). For example: 2020-02-02T19:00:00Z | False |
    | API key ID | False |
    | API key secret | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rs-search-incidents
***
Query for incidents


#### Base Command

`rs-search-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Comma-separated list of incident severity, e.g., Low,Medium,High. | Optional | 
| date-created-before | Created date of the incident before the given date in the formatYYYY-MM-DDTHH:MM:SSZ, e.g., 2018-05-07T10:59:07Z. | Optional | 
| date-created-after | Created date of the incident after the given date in the format YYYY-MM-DDTHH:MM:SSZ, e.g., 2018-05-07T10:59:07Z. | Optional | 
| date-created-within-the-last | Created date of the incident within the last time frame (days/hours/minutes). Should be given a number, along with with the timeframe argument. | Optional | 
| timeframe | Time frame to search within for incident. Should be given with within-the-last/due-in argument. Possible values: "days", "hours", "minutes". Possible values are: days, hours, minutes. | Optional | 
| date-occurred-within-the-last | Occurred date of the incident within the last time frame (days/hours/minutes). Should be given a number, along with the timeframe argument. | Optional | 
| date-occurred-before | Occurred date of the incident before the given date in the format YYYY-MM-DDTHH:MM:SSZ, e.g., 2018-05-07T10:59:07Z. | Optional | 
| date-occurred-after | Occurred date of the incident after the given date in the format YYYY-MM-DDTHH:MM:SSZ, e.g., 2018-05-07T10:59:07Z. | Optional | 
| incident-type | Incident type. Possible values are: CommunicationError, DenialOfService, ImproperDisposal:DigitalAsset, ImproperDisposal:documents/files, LostDocuments/files/records, LostPC/laptop/tablet, LostPDA/smartphone, LostStorageDevice/media, Malware, NotAnIssue, Other, Phishing, StolenDocuments/files/records, StolenPC/laptop/tablet, StolenPDA/Smartphone, StolenStorageDevice/media, SystemIntrusion, TBD/Unknown, Vendor/3rdPartyError. | Optional | 
| nist | NIST Attack Vectors. Possible values: "Attrition", "E-mail", "External/RemovableMedia", "Impersonation", "ImproperUsage", "Loss/TheftOfEquipment", "Other", "Web". Possible values are: Attrition, E-mail, External/RemovableMedia, Impersonation, ImproperUsage, Loss/TheftOfEquipment, Other, Web. | Optional | 
| status | Incident status. Possible values: "Active" and "Closed". Possible values are: Active, Closed. | Optional | 
| due-in | Due date of the incident in given time frame (days/hours/minutes). Should be given a number, along with the timeframe argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.CreateDate | string | Created date of the incident. | 
| Resilient.Incidents.Name | string | Incident name. | 
| Resilient.Incidents.DiscoveredDate | string | Discovered date of the incident. | 
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Phase | string | Incident Phase. | 
| Resilient.Incidents.Severity | string | Incident severity. | 
| Resilient.Incidents.Description | string | Incident description. | 


#### Command Example
```!rs-search-incidents```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": [
            {
                "CreatedDate": "2000-01-01T00:00:00Z",
                "DiscoveredDate": "1970-01-01T00:00:00Z",
                "Id": "1234",
                "Name": "example",
                "Owner": "example example",
                "Phase": "Respond",
                "SequenceCode": "E123-45"
            },
            {
                "CreatedDate": "2000-01-01T00:00:00Z",
                "DiscoveredDate": "1970-01-01T00:00:00Z",
                "Id": "5678",
                "Name": "example",
                "Owner": "example example",
                "Phase": "Respond",
                "SequenceCode": "E678-90"
            }
        ]
    }
}
```

#### Human Readable Output

>### Resilient Systems Incidents
>|Id|Name|CreatedDate|DiscoveredDate|Owner|Phase|
>|---|---|---|---|---|---|
>| 1234 | example | 2000-01-01T00:00:00Z | 1970-01-01T00:00:00Z | example example | Respond |
>| 5678 | example | 2000-01-01T00:00:00Z | 1970-01-01T00:00:00Z | example example | Respond |


### rs-update-incident
***
Updates incidents.


#### Base Command

`rs-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | Incident ID to update. | Required | 
| severity | Severity to update. Possible value: "Low", "Medium", and "High". Possible values are: Low, Medium, High. | Optional | 
| owner | User full name to set as incident owner, e.g., Steve Jobs. | Optional | 
| incident-type | Incident type (added to the current incident types list). Possible values are: CommunicationError, DenialOfService, ImproperDisposal:DigitalAsset, ImproperDisposal:documents/files, LostDocuments/files/records, LostPC/laptop/tablet, LostPDA/smartphone, LostStorageDevice/media, Malware, NotAnIssue, Other, Phishing, StolenDocuments/files/records, StolenPC/laptop/tablet, StolenPDA/Smartphone, StolenStorageDevice/media, SystemIntrusion, TBD/Unknown, Vendor/3rdPartyError. | Optional | 
| resolution | Incident resolution. Possible value: "Unresolved", "Duplicate", "NotAnIssue", and "Resolved". Possible values are: Unresolved, Duplicate, NotAnIssue, Resolved. | Optional | 
| resolution-summary | Incident resolution summary. | Optional | 
| description | Incident description. | Optional | 
| name | Incident name. | Optional | 
| nist | NIST Attack Vectors (added to the current list of NIST attack vectors). Possible values: "Attrition", "E-mail", "External/RemovableMedia", "Impersonation", "ImproperUsage", "Loss/TheftOfEquipment", "Other", "Web". Possible values are: Attrition, E-mail, External/RemovableMedia, Impersonation, ImproperUsage, Loss/TheftOfEquipment, Other, Web. | Optional | 
| other-fields | A JSON object of the form: {field_name: new_field_value}. For example: `{"description": {"textarea": {"format": "html", "content": "The new description"}}, "name": {"text": "The new name"}}`. The name should be the path to it in the incident separated by "." For example: `{"properties.incident_summary": {"text": "The new name"}}". Because of API limitations we currently support only fields of the following types: ID, list of IDS, Number, Boolean, Text, Data, Textarea. For more information, refer to https://xsoar.pan.dev/docs/reference/integrations/ibm-resilient-systems. In case of conflicts between the other-fields argument and the regular fields arguments, the other-fields value will be used. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rs-update-incident incident-id=1234 severity=High incident-type=Malware```

#### Human Readable Output

>Incident 1234 was updated successfully.

### rs-incidents-get-members
***
Gets members of the incident.


#### Base Command

`rs-incidents-get-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | Incident ID to get members of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.ID | string | Incident ID. | 
| Resilient.Incidents.Members.FirstName | string | Member's first name. | 
| Resilient.Incidents.Members.LastName | string | Member's last name. | 
| Resilient.Incidents.Members.ID | number | Member's ID. | 
| Resilient.Incidents.Members.Email | string | Member's email address. | 


#### Command Example
```!rs-incidents-get-members incident-id=1234```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Id": "1234",
            "Members": [
                {
                    "Email": "example@example.com",
                    "FirstName": "example",
                    "ID": 1,
                    "LastName": "example"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Members of incident 1234
>|ID|LastName|FirstName|Email|
>|---|---|---|---|
>| 1 | example | example | example@example.com |


### rs-get-incident
***
Gets an individual incident by ID.


#### Base Command

`rs-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | ID of incident to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.CreateDate | string | Created date of the incident. | 
| Resilient.Incidents.Name | string | Incident name. | 
| Resilient.Incidents.Resolution | string | Incident resolution. | 
| Resilient.Incidents.DiscoveredDate | string | Discovered date of the incident. | 
| Resilient.Incidents.ResolutionSummary | string | Incident resolution summary. | 
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Phase | string | Incident phase. | 
| Resilient.Incidents.Severity | string | Incident severity. | 
| Resilient.Incidents.Description | string | Incident description. | 
| Resilient.Incidents.Confirmed | boolean | Incident confirmation. | 
| Resilient.Incidents.NegativePr | boolean | Whether negative PR is likely. | 
| Resilient.Incidents.DateOccurred | string | Date incident occurred. | 
| Resilient.Incidents.Reporter | string | Name of reporting individual. | 
| Resilient.Incidents.NistAttackVectors | Unknown | Incident NIST attack vectors. | 


#### Command Example
```!rs-get-incident incident-id=1234```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Confirmed": true,
            "CreatedDate": "2000-01-01T00:00:00Z",
            "DateOccurred": "2000-01-01T00:00:00Z",
            "Description": "example",
            "DiscoveredDate": "2000-01-01T00:00:00Z",
            "ExposureType": "Unknown",
            "Id": "1234",
            "Name": "example",
            "NistAttackVectors": "E-mail\n",
            "Owner": "example example",
            "Phase": "Engage",
            "Reporter": "example example",
            "Severity": "High"
        }
    }
}
```

#### Human Readable Output

>### IBM Resilient Systems incident ID 1234
>|Id|Name|Description|NistAttackVectors|Phase|Resolution|ResolutionSummary|Owner|CreatedDate|DateOccurred|DiscoveredDate|DueDate|NegativePr|Confirmed|ExposureType|Severity|Reporter|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1234 | example | example | E-mail<br/> | Engage |  |  | example example | 2000-01-01T00:00:00Z | 2000-01-01T00:00:00Z | 2000-01-01T00:00:00Z |  |  | true | Unknown | High | example example |


### rs-incidents-update-member
***
Updates the incident's members.


#### Base Command

`rs-incidents-update-member`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | ID of the incident for which to update its members. | Required | 
| members | A comma-separated list of members to add, e.g. 1,2,3. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rs-incidents-update-member incident-id=1234 members=2```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Id": "1234",
            "Members": {
                "Email": "example@exampe.com",
                "FirstName": "example",
                "ID": 2,
                "LastName": "example",
                "members": [],
                "vers": 10
            }
        }
    }
}
```

#### Human Readable Output

>### Members of incident 1234
>|Email|FirstName|ID|LastName|members|vers|
>|---|---|---|---|---|---|
>| example@example.com | example | 2 | example |  | 10 |


### rs-get-users
***
Gets a list of all users in the system.


#### Base Command

`rs-get-users`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!rs-get-users```

#### Human Readable Output

>### IBM Resilient Systems Users
>|ID|LastName|FirstName|Email|
>|---|---|---|---|
>| 1 | example | example | example@example.com |
>| 2 | example1 | example1 | example1@example.com |


### rs-close-incident
***
Closes an incident.


#### Base Command

`rs-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | ID of the incident to close. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rs-close-incident incident-id=1234```

#### Human Readable Output

>Incident 1234 was closed.

### rs-create-incident
***
Creates an incident.


#### Base Command

`rs-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Incident name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Name | string | Incident name. | 


#### Command Example
```!rs-create-incident name=IncidentName```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Id": "1235",
            "Name": "IncidentName"
        }
    }
}
```

#### Human Readable Output

>### Incident IncidentName was created
>|ID|Name|
>|---|---|
>| 1235 | IncidentName |


### rs-incident-artifacts
***
Gets incident artifacts.


#### Base Command

`rs-incident-artifacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | Incident ID to get artifacts of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Name | string | Incident name. | 
| Resilient.Incidents.Artifacts.CreatedDate | string | Artifact created date. | 
| Resilient.Incidents.Artifacts.Creator | string | Artifact creator. | 
| Resilient.Incidents.Artifacts.Description | string | Artifact description. | 
| Resilient.Incidents.Artifacts.ID | number | Artifact ID. | 
| Resilient.Incidents.Artifacts.Type | string | Artifact type. | 
| Resilient.Incidents.Artifacts.Value | string | Artifact value. | 
| Resilient.Incidents.Artifacts.Attachments.ContentType | string | Attachment content type. | 
| Resilient.Incidents.Artifacts.Attachments.CreatedDate | string | Attachment created date. | 
| Resilient.Incidents.Artifacts.Attachments.Creator | string | Attachment creator. | 
| Resilient.Incidents.Artifacts.Attachments.ID | number | Attachment ID. | 
| Resilient.Incidents.Artifacts.Attachments.Name | string | Attachment name. | 
| Resilient.Incidents.Artifacts.Attachments.Size | number | Attachment size. | 


#### Command Example
```!rs-incident-artifacts incident-id=1234```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Artifacts": [
                {
                    "CreatedDate": "2000-00-00T00:00:00Z",
                    "Creator": "example example",
                    "Description": "example",
                    "ID": 1,
                    "Type": "IP Address",
                    "Value": "1.1.1.1"
                },
                {
                    "CreatedDate": "2000-00-00T00:00:00Z",
                    "Creator": "example example",
                    "Description": "example",
                    "ID": 2,
                    "Type": "IP Address",
                    "Value": "2.2.2.2"
                }
             ],
            "Id": "1234",
            "Name": "example"
        }
    }
}
```

#### Human Readable Output

>### Incident 1234 artifacts
>|ID|Value|Description|CreatedDate|Creator|
>|---|---|---|---|---|
>| 1 | 1.1.1.1 | example | 2000-00-00T00:00:00Z | example example |
>| 2 | 2.2.2.2 | example | 2000-00-00T00:00:00Z | example example |


### rs-incident-attachments
***
Gets incident attachments.


#### Base Command

`rs-incident-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | Incident ID to get attachments from. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Name | string | Incident name. | 
| Resilient.Incidents.Owner | string | Incident owner. | 
| Resilient.Incidents.Attachments.ContentType | string | Attachment content type. | 
| Resilient.Incidents.Attachments.CreatedDate | string | Attachment created date. | 
| Resilient.Incidents.Attachments.Creator | string | Attachment creator. | 
| Resilient.Incidents.Attachments.ID | number | Attachment ID. | 
| Resilient.Incidents.Attachments.Name | string | Attachment name. | 
| Resilient.Incidents.Attachments.Size | number | Attachment size. | 


#### Command Example
```!rs-incident-attachments incident-id=1234```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Attachments": [
                {
                    "ContentType": "example",
                    "CreatedDate": "2000-00-00T00:00:00Z",
                    "Creator": "example example",
                    "ID": 1,
                    "Name": "example",
                    "Size": 10
                }
            ],
            "Id": "1234",
            "Name": "example",
            "Owner": "example example"
        }
    }
}
```

#### Human Readable Output

>### Incident 1234 attachments
>|ContentType|CreatedDate|Creator|ID|Name|Size|
>|---|---|---|---|---|---|
>| example | 2000-00-00T00:00:00Z | example example | 1 | example | 10 |


### rs-related-incidents
***
Gets related incidents.


#### Base Command

`rs-related-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | Incident ID to get related incidents of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Related.CreatedDate | string | Created date of the related incident. | 
| Resilient.Incidents.Related.Name | string | Name of the related incident. | 
| Resilient.Incidents.Related.ID | number | ID of the related incident. | 
| Resilient.Incidents.Related.Status | string | Status \(Active/Closed\) of the related incident. | 
| Resilient.Incidents.Related.Artifacts.CreatedDate | string | Created date of the artifact. | 
| Resilient.Incidents.Related.Artifacts.ID | number | ID of the artifact. | 
| Resilient.Incidents.Related.Artifacts.Creator | string | Creator of the artifact. | 


#### Command Example
```!rs-related-incidents incident-id=1234```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Id": "1234",
            "Related": [
                {
                    "Artifacts": [
                        {
                            "CreatedDate": "2000-00-00T00:00:00Z",
                            "Creator": "example example",
                            "ID": 1
                        },
                        {
                            "CreatedDate": "2000-00-00T00:00:00Z",
                            "Creator": "example example",
                            "Description": "example",
                            "ID": 2
                        }
                    ],
                    "CreatedDate": "2000-00-00T00:00:00Z",
                    "ID": 1235,
                    "Name": "example",
                    "Status": "Closed"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incident 1234 related incidents
>|Artifacts|CreatedDate|ID|Name|Status|
>|---|---|---|---|---|
>| ID: 1<br/>Created Date: 2000-00-00T00:00:00Z<br/>Creator: example example<br/>ID: 2<br/>Created Date: 2000-00-00T00:00:00Z<br/>Description: example<br/><br/>Creator: example example<br/> | 2000-00-00T00:00:00Z | 1234 | example | Closed |


### rs-incidents-get-tasks
***
Gets tasks of incidents.


#### Base Command

`rs-incidents-get-tasks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | Incident ID to get tasks of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.Incidents.Id | string | Incident ID. | 
| Resilient.Incidents.Name | string | Incident name. | 
| Resilient.Incidents.Tasks.Category | string | Task category. | 
| Resilient.Incidents.Tasks.Creator | string | Task creator. | 
| Resilient.Incidents.Tasks.DueDate | string | Task due date. | 
| Resilient.Incidents.Tasks.Form | string | Task form. | 
| Resilient.Incidents.Tasks.ID | string | Task ID. | 
| Resilient.Incidents.Tasks.Name | string | Task name. | 
| Resilient.Incidents.Tasks.Required | boolean | Whether the task is required. | 
| Resilient.Incidents.Tasks.Status | string | Task status \(Open/Closed\). | 


#### Command Example
```!rs-incidents-get-tasks incident-id=1234```

#### Context Example
```json
{
    "Resilient": {
        "Incidents": {
            "Id": "1234",
            "Name": "example",
            "Tasks": [
                {
                    "Category": "Respond",
                    "Creator": "example example",
                    "Form": "data_compromised, determined_date",
                    "ID": 1,
                    "Name": "example",
                    "Required": true,
                    "Status": "Open"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Incident 1234 tasks
>|ID|Name|Category|Form|Status|DueDate|Instructions|UserNotes|Required|Creator|
>|---|---|---|---|---|---|---|---|---|---|
>| 1 | example | Respond | data_compromised, determined_date | Open |  |  |  | true | example example |


### rs-add-note
***
Add a note to an incident.


#### Base Command

`rs-add-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | The ID of the incident. | Required | 
| note | The text of the note. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.IncidentNote.type | String | The type of the note \(incident or task\). | 
| Resilient.IncidentNote.id | Number | The note's ID. | 
| Resilient.IncidentNote.parent_id | Number | The ID of the parent note \(null for top-level note\).. | 
| Resilient.IncidentNote.user_id | Number | The ID of the user who created the note. | 
| Resilient.IncidentNote.user_fname | String | The user's first name. | 
| Resilient.IncidentNote.user_lname | String | The user's last name. | 
| Resilient.IncidentNote.text | String | The note text. | 
| Resilient.IncidentNote.create_date | Date | The date the note was created. | 
| Resilient.IncidentNote.modify_date | Date | The date the note was modified. | 
| Resilient.IncidentNote.is_deleted | Boolean | The flag indicating if the note is deleted. Generally, note objects are removed from the database when the user deletes them. However, if the user deletes a parent note, the parent is just marked as deleted \(and its text is cleared\). | 
| Resilient.IncidentNote.modify_user.id | Number | The ID of the user who last modified the note. | 
| Resilient.IncidentNote.modify_user.first_name | String | The first name of the user who last modified the note. | 
| Resilient.IncidentNote.modify_user.last_name | String | The last name of the user who last modified the note. | 
| Resilient.IncidentNote.inc_id | Number | The ID of the incident to which this note belongs. | 
| Resilient.IncidentNote.inc_name | String | The name of the incident to which this note belongs. | 
| Resilient.IncidentNote.task_id | Number | The ID of the task to which this note belongs. Will be null on incident notes. | 
| Resilient.IncidentNote.task_name | String | The name of the task to which this note belongs. Will be null on incident notes. | 
| Resilient.IncidentNote.task_custom | Booolean | For a task note, whether that task is a custom task. Null for incident notes. | 
| Resilient.IncidentNote.task_members | Unknown | For a task note, the list of that task's members, if any. Null for incident notes. | 
| Resilient.IncidentNote.task_at_id | Unknown | For a task note, whether that task is an automatic task. Null for incident notes and task notes that are not automatically generated. | 
| Resilient.IncidentNote.inc_owner | Number | The owner of the incident to which this note belongs. | 
| Resilient.IncidentNote.user_name | String | The name of the owner of the incident to which this note belongs. | 
| Resilient.IncidentNote.modify_principal.id | Number | The ID of the principal. | 
| Resilient.IncidentNote.modify_principal.type | String | The type of the principal. Currently only user or group. | 
| Resilient.IncidentNote.modify_principal.name | String | The name of the principal. | 
| Resilient.IncidentNote.modify_principal.display_name | String | The display name of the principal. | 
| Resilient.IncidentNote.comment_perms.update | Boolean | Whether the current user has permission to update this note. | 
| Resilient.IncidentNote.comment_perms.delete | Boolean | Whether the current user has permission to delete this note. | 


#### Command Example
```!rs-add-note incident-id=1234 note="This is a note"```

#### Context Example
```json
{
    "Resilient": {
        "incidentNote": {
            "actions": [],
            "children": [],
            "comment_perms": {
                "delete": true,
                "update": true
            },
            "create_date": 1600000000000,
            "id": 10,
            "inc_id": 1234,
            "inc_name": "example",
            "inc_owner": 1,
            "is_deleted": false,
            "mentioned_users": [],
            "modify_date": 1600000000000,
            "modify_principal": {
                "display_name": "example example",
                "id": 1,
                "name": "example@example.com",
                "type": "user"
            },
            "modify_user": {
                "first_name": "example",
                "id": 1,
                "last_name": "example"
            },
            "parent_id": null,
            "task_at_id": null,
            "task_custom": null,
            "task_id": null,
            "task_members": null,
            "task_name": null,
            "text": "<div>This is a note</div>",
            "type": "incident",
            "user_fname": "example",
            "user_id": 1,
            "user_lname": "example",
            "user_name": "example example"
        }
    }
}
```

#### Human Readable Output

>The note was added successfully to incident 1234

### rs-add-artifact
***
Add an artifact to an incident.


#### Base Command

`rs-add-artifact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident-id | The ID of the incident. | Required | 
| artifact-type | The type of the artifact. Possible values are: DNS Name, Email Attachment, Email Attachment Name, Email Body, Email Recipient, Email Sender, Email Sender Name, Email Subject, File Name, File Path, HTTP Request Header, HTTP Response Header, IP Address, Log File, MAC Address, Malware Family/Variant, Malware MD5 Hash, Malware Sample, Malware Sample Fuzzy Hash, Malware SHA-1 Hash, Malware SHA-256 Hash, Mutex, Network CIDR Range, Observed Data, Other File, Password, Port, Process Name, Registry Key, RFC 822 Email Message File, Service, String, System Name, Threat CVE ID, URI Path, URL, URL Referer, User Account, User Agent, X509 Certificate File. | Required | 
| artifact-value | The value of the artifact. | Required | 
| artifact-description | The description of the artifact. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resilient.IncidentArtifact.id | Number | The ID of the artifact. | 
| Resilient.IncidentArtifact.type | Number | The type of the artifact. | 
| Resilient.IncidentArtifact.value | String | The value of the artifact. For example, the IP address for an IP address artifact. | 
| Resilient.IncidentArtifact.description | String | The description of the artifact. | 
| Resilient.IncidentArtifact.attachment | Unknown | The files attached to the artifact. | 
| Resilient.IncidentArtifact.parent_id | Number | The parent artifact ID. | 
| Resilient.IncidentArtifact.creator.id | Number | The ID of the artifact creator. | 
| Resilient.IncidentArtifact.creator.fname | String | The first name of the artifact creator. | 
| Resilient.IncidentArtifact.creator.lname | String | The last name of the artifact creator. | 
| Resilient.IncidentArtifact.creator.display_name | String | The display name of the artifact creator. | 
| Resilient.IncidentArtifact.creator.status | String | The status of the artifact creator. | 
| Resilient.IncidentArtifact.creator.email | String | The email of the artifact creator. | 
| Resilient.IncidentArtifact.creator.phone | String | The phone number of the artifact creator. | 
| Resilient.IncidentArtifact.creator.cell | String | The cellphone number of the artifact creator. | 
| Resilient.IncidentArtifact.creator.title | String | The user's job title \(e.g., Incident Response Manager\). | 
| Resilient.IncidentArtifact.creator.locked | Boolean | The status of the creator's account. \(True if locked. false otherwise\). | 
| Resilient.IncidentArtifact.creator.password_changed | Boolean | Whether the user's password has changed. \(True if changed, false otherwise\). | 
| Resilient.IncidentArtifact.creator.is_external | Boolean | Whether the user's account is authenticated externally. | 
| Resilient.IncidentArtifact.creator.ui_theme | String | The UI theme the user has selected. The Resilient UI recognizes the following values \(darkmode, lightmode, verydarkmode\). | 
| Resilient.IncidentArtifact.inc_id | Number | The incident ID. | 
| Resilient.IncidentArtifact.inc_name | String | The incident name. | 
| Resilient.IncidentArtifact.inc_owner | Number | The incident owner. | 
| Resilient.IncidentArtifact.created | Date | The date when the artifact is created. | 
| Resilient.IncidentArtifact.last_modified_time | Date | The last date on which the artifact changed. | 
| Resilient.IncidentArtifact.last_modified_by.id | Number | The ID of the user who last changed the artifact. | 
| Resilient.IncidentArtifact.last_modified_by.type | String | The type of user who last changed the artifact. | 
| Resilient.IncidentArtifact.last_modified_by.name | String | The name of the user who last changed the artifact. | 
| Resilient.IncidentArtifact.last_modified_by.display_name | String | The display name of the user who last changed the artifact. | 
| Resilient.IncidentArtifact.perms.read | Boolean | Whether the current user has permission to read this artifact. | 
| Resilient.IncidentArtifact.perms.write | Boolean | Whether the current user has permission to write to this artifact. | 
| Resilient.IncidentArtifact.perms.delete | Boolean | Whether the current user has permission to delete this artifact. | 
| Resilient.IncidentArtifact.properties | Unknown | The additional artifact properties. | 
| Resilient.IncidentArtifact.hash | String | The hash of the incident. | 
| Resilient.IncidentArtifact.relating | Boolean | Whether this artifact should be used for relating to other incidents. Null means use the default specified by the type. True means to always relate. False means to never relate. | 
| Resilient.IncidentArtifact.creator_principal.id | Number | The ID of the principal. | 
| Resilient.IncidentArtifact.creator_principal.type | String | The type of the principal. Currently only user or group. | 
| Resilient.IncidentArtifact.creator_principal.name | String | The API name of the principal. | 
| Resilient.IncidentArtifact.creator_principal.display_name | String | The display name of the principal. | 
| Resilient.IncidentArtifact.ip.source | Boolean | Whether the IP address is a source. | 
| Resilient.IncidentArtifact.ip.destination | Boolean | Whether the IP address is a destination. | 


#### Command Example
```!rs-add-artifact artifact-type="IP Address" artifact-value=1.1.1.1 incident-id=1234 artifact-description="This is a description"```

#### Context Example
```json
{
    "Resilient": {
        "incidentArtifact": {
            "actions": [],
            "attachment": null,
            "created": 1600000000000,
            "creator": {
                "cell": "",
                "display_name": "example example",
                "email": "example@example.com",
                "fname": "example",
                "id": 9,
                "is_external": false,
                "lname": "example",
                "locked": false,
                "password_changed": false,
                "phone": "",
                "status": "A",
                "title": "",
                "ui_theme": "darkmode"
            },
            "creator_principal": {
                "display_name": "example example",
                "id": 1,
                "name": "example@example.com",
                "type": "user"
            },
            "description": "example",
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hits": [],
            "id": 1,
            "inc_id": 1234,
            "inc_name": "example",
            "inc_owner": 1,
            "ip": {
                "destination": null,
                "source": null
            },
            "last_modified_by": {
                "display_name": "example example",
                "id": 1,
                "name": "example@example.com",
                "type": "user"
            },
            "last_modified_time": 1600000000000,
            "parent_id": null,
            "pending_sources": [],
            "perms": {
                "delete": true,
                "read": true,
                "write": true
            },
            "properties": null,
            "relating": null,
            "type": 1,
            "value": "1.1.1.1"
        }
    }
}
```

#### Human Readable Output

>The artifact was added successfully to incident 1234
