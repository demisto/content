Cloud-based IT service management solution
This integration was integrated and tested with version 10.1.1 of Cherwell

## Configure Cherwell in Cortex


| **Parameter** | **Required** |
| --- | --- |
| URL (example: https://my.domain.com) | True |
| Username | True |
| Password | True |
| Client id | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| CSV list of objects to fetch. The default is incident, for example: incident,problem,service) | False |
| Max results to fetch (defualt is 30) | False |
| Advanced Query to fetch (see integration detailed instructions) | False |
| Fetch attachments (include attachements in fetch process) | False |
| Fetch incidents | False |
| Incident type | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cherwell-create-business-object
***
Creates a business object.


#### Base Command

`cherwell-create-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| json | Data JSON containing the relevant fields and their values, for example:<br/>{"title": "some value"}). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.BusinessObjects.RecordId | String | Business object record ID.  | 
| Cherwell.BusinessObjects.PublicId | String | Business object public ID.  | 


#### Command Example
```!cherwell-create-business-object type=incident json={"Priority": "3", "CustomerDisplayName": "demisto admin", "Description": "This incident was created by Cherwell test playbook","Service":"Enterprise Apps","Category":"PeopleSoft","Subcategory":"Submit Incident"}```

#### Context Example
```json
{
    "Cherwell": {
        "BusinessObjects": {
            "PublicId": "102384",
            "RecordId": "947571cec8a5b5f03850c940c2bf6ca2bf116ffce9"
        }
    }
}
```

#### Human Readable Output

>### New Incident was created
>|Public Id|Record Id|
>|---|---|
>| 102384 | 947571cec8a5b5f03850c940c2bf6ca2bf116ffce9 |


### cherwell-update-business-object
***
Update a business object with the specified fields.


#### Base Command

`cherwell-update-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| json | Data JSON containing the relevant fields and their values. | Required | 
| id_value | Public ID or record ID. | Required | 
| id_type | Type of ID. Possible values are: public_id, record_id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.BusinessObjects.RecordId | String | Business object record ID.  | 
| Cherwell.BusinessObjects.PublicId | Unknown | Business object public ID.  | 


#### Command Example
```!cherwell-update-business-object type=incident id_type=public_id id_value=102383 json={"Priority": "1"}```

#### Context Example
```json
{
    "Cherwell": {
        "BusinessObjects": {
            "PublicId": "102383",
            "RecordId": "94757184cce46253b3ab694ae58289b64d0cd867ce"
        }
    }
}
```

#### Human Readable Output

>### Incident 102383 was updated
>|Public Id|Record Id|
>|---|---|
>| 102383 | 94757184cce46253b3ab694ae58289b64d0cd867ce |


### cherwell-delete-business-object
***
Deletes a given business object.


#### Base Command

`cherwell-delete-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| id_value | Public ID or record ID. | Required | 
| id_type | Type of ID. Possible values are: public_id, record_id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cherwell-delete-business-object id_type=record_id id_value=94757184cce46253b3ab694ae58289b64d0cd867ce type=incident```

#### Human Readable Output

>### Record 94757184cce46253b3ab694ae58289b64d0cd867ce of type incident was deleted.

### cherwell-get-business-object
***
Gets a business object by an ID.


#### Base Command

`cherwell-get-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| id_value | Public ID or record ID. | Required | 
| id_type | Type of ID. Possible values are: record_id, public_id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cherwell-get-business-object type=incident id_type=public_id id_value=102383```

#### Context Example
```json
{
    "Cherwell": {
        "BusinessObjects": {
            "ApprovalBlockID": "",
            "AssignedTeam": "1st Level Support",
            "AssignedTeamID": "9365b4e90592c81e3b7a024555a6c0094ba77e8773",
            "AssignedTo": "",
            "AssignedToID": "",
            "AssignedToManager": "",
            "Barcode": "",
            "BreachNotes": "",
            "CIDownEndDateTime": "",
            "CIDownStartDateTime": "",
            "CIDowntimeInMinutes": "0",
            "CallSource": "Phone",
            "CartItemID": "",
            "Category": "PeopleSoft",
            "Cause": "",
            "ChangeID": "",
            "ClonedIncident": "False",
            "ClonedIncidentID": "",
            "CloseDescription": "",
            "ClosedBy": "",
            "ClosedByID": "",
            "ClosedDateTime": "",
            "ClosedOn1stCall": "False",
            "CombinedKB": "",
            "Comments": "",
            "ConfigItemDisplayName": "",
            "ConfigItemRecID": "",
            "ConfigItemType": "",
            "ConfigItemTypeID": "",
            "Cost": "0",
            "CreatedBy": "demisto admin",
            "CreatedByEmail": "user1@mail.com",
            "CreatedByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
            "CreatedDateTime": "7/22/2021 12:22 PM",
            "CreatedDuring": "8 to 5 Monday thru Friday",
            "CustomerDepartment": "Accounting",
            "CustomerDisplayName": "demisto admin",
            "CustomerRecID": "9365da817530b0bfee892a48fb8815654c6071af03",
            "CustomerSubscriptionLevel": "",
            "CustomerTypeID": "",
            "DefaultTeam": "1st Level Support",
            "Description": "This incident was created by Cherwell test playbook-\r\n-\r\nThis is from the REST API-\r\n-\r\nThis is from the REST API",
            "DescriptionSentimentValue": "2",
            "EmailNotifications": "",
            "ISMSAuditsID": "",
            "Impact": "",
            "IncidentDurationInDays": "0.02",
            "IncidentDurationInHours": "0.53",
            "IncidentID": "102383",
            "IncidentType": "Service Request",
            "IncidentchildID": "",
            "IncidentchildRecID": "",
            "KnowledgeArticleID": "",
            "LastModBy": "demisto admin",
            "LastModByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
            "LastModTimeStamp": "",
            "LastModifiedDateTime": "7/22/2021 12:53 PM",
            "Level2EscalationComplete": "False",
            "Level2EscalationTeam": "2nd Level Support",
            "Level3EscalationComplete": "False",
            "Level3EscalationTeam": "3rd Level Support",
            "LinkedProblem": "",
            "LinkedSLAs": "93838607346b42be7074af487d9171ea9f948b7204 ,  , ",
            "LinkedToProblem": "False",
            "Location": "",
            "MajorIncident": "False",
            "MajorIncidentID": "",
            "MajorIncidentRecID": "",
            "NetworkEventID": "",
            "NextStatus": "In Progress",
            "NextStatusOneStep": "ActionInfoDef ID=\"93d9abdb6242",
            "NextStatusText": "Begin Work",
            "OnBehalfOf": "False",
            "PendingEndDateTime": "",
            "PendingPreviousStatus": "",
            "PendingReason": "",
            "PendingStartDateTime": "",
            "PickedUpDateTime": "",
            "PortalAffectsMultipleUsers": "False",
            "PortalAffectsPrimaryFunction": "False",
            "PortalAltContactInfo": "",
            "Priority": "3",
            "PublicId": "102383",
            "RecID": "94757184cce46253b3ab694ae58289b64d0cd867ce",
            "RecordId": "94757184cce46253b3ab694ae58289b64d0cd867ce",
            "RecurringIncident": "False",
            "Reopened": "False",
            "Requester": "",
            "RequesterDepartment": "Accounting",
            "RequesterEmail": "",
            "RequesterID": "",
            "ReviewByDeadline": "",
            "SCTFired": "False",
            "SCTRecID": "",
            "SLAID": "93838607346b42be7074af487d9171ea9f948b7204",
            "SLAIDForCI": "",
            "SLAIDForCustomer": "93838607346b42be7074af487d9171ea9f948b7204",
            "SLAIDForService": "",
            "SLAName": "Platinum",
            "SLANameForCI": "",
            "SLANameForCustomer": "Platinum",
            "SLANameForService": "",
            "SLAResolutionWarning": "7/26/2021 12:07 PM",
            "SLAResolveByDeadline": "7/26/2021 12:22 PM",
            "SLARespondByDeadline": "7/22/2021 4:22 PM",
            "SLAResponseWarning": "7/22/2021 4:07 PM",
            "SLATargetTimeID": "",
            "SLA_Key": "Platinum_Service Request",
            "STCTimeInMinutes": "0",
            "SecurityEventID": "",
            "Service": "Enterprise Apps",
            "ServiceCartID": "",
            "ServiceCatalogTemplateName": "",
            "ServiceCustomerIsEntitled": "True",
            "ServiceEntitlements": "Platinum, Gold, Silver, Corporate",
            "ServiceID": "9389f689ed2a47e91de7954ecb8f2fe733af0ecb06",
            "ShowAllServices": "False",
            "ShowContactInformation": "False",
            "SkillID": "9454f50880a42d63b93ce142d58fbbe97de1b3d672",
            "SmartClassifySearchString": "Submit Incident",
            "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00",
            "Stat_24x7ElapsedTime": "0",
            "Stat_DateTimeAssigned": "",
            "Stat_DateTimeClosed": "",
            "Stat_DateTimeInProgress": "",
            "Stat_DateTimeReOpened": "",
            "Stat_DateTimeResolved": "",
            "Stat_DateTimeResponded": "",
            "Stat_FirstCallResolution": "False",
            "Stat_IncidentEscalated": "False",
            "Stat_IncidentReopened": "False",
            "Stat_NumberOfEscalations": "0",
            "Stat_NumberOfTouches": "4",
            "Stat_ResponseTime": "0",
            "Stat_SLAResolutionBreached": "False",
            "Stat_SLAResolutionGood": "False",
            "Stat_SLAResolutionWarning": "False",
            "Stat_SLAResponseBreached": "False",
            "Stat_SLAResponseGood": "False",
            "Stat_SLAResponseWarning": "False",
            "Status": "New",
            "StatusDesc": "",
            "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f",
            "StatusOrder": "1",
            "Subcategory": "Submit Incident",
            "SubcategoryID": "",
            "TaskClosedCount": "0",
            "TasksClosed": "False",
            "TasksInProgress": "False",
            "TasksOnHold": "False",
            "TotalSTCTimeInMinutes": "0",
            "TotalTaskTime": "0",
            "TotalTasks": "0",
            "Urgency": "",
            "WaitTime": "0",
            "WalkUpSupportLocation": "",
            "WasCIDown": "False",
            "Withdraw": "False"
        }
    }
}
```

#### Human Readable Output

>### Incident: 102383
>|Approval Block ID|Assigned Team|Assigned Team ID|Assigned To|Assigned To ID|Assigned To Manager|Barcode|Breach Notes|CI Down End Date Time|CI Down Start Date Time|CI Downtime In Minutes|Call Source|Cart Item ID|Category|Cause|Change ID|Cloned Incident|Cloned Incident ID|Close Description|Closed By|Closed By ID|Closed Date Time|Closed On 1 St Call|Combined KB|Comments|Config Item Display Name|Config Item Rec ID|Config Item Type|Config Item Type ID|Cost|Created By|Created By Email|Created By ID|Created Date Time|Created During|Customer Department|Customer Display Name|Customer Rec ID|Customer Subscription Level|Customer Type ID|Default Team|Description|Description Sentiment Value|Email Notifications|ISMS Audits ID|Impact|In cident Duration In Days|In cident Duration In Hours|Incident ID|Incident Type|Incidentchild ID|Incidentchild Rec ID|Knowledge Article ID|Last Mod By|Last Mod By ID|Last Mod Time Stamp|Last Modified Date Time|Level 2 Escalation Complete|Level 2 Escalation Team|Level 3 Escalation Complete|Level 3 Escalation Team|Linked Problem|Linked SL As|Linked To Problem|Location|Major Incident|Major Incident ID|Major Incident Rec ID|Network Event ID|Next Status|Next Status One Step|Next Status Text|On Behalf Of|Pending End Date Time|Pending Previous Status|Pending Reason|Pending Start Date Time|Picked Up Date Time|Portal Affects Multiple Users|Portal Affects Primary Function|Portal Alt Contact Info|Priority|Public Id|Rec ID|Record Id|Recurring Incident|Reopened|Requester|Requester Department|Requester Email|Requester ID|Review By Deadline|SCT Fired|SCT Rec ID|SLAID|SLAID For CI|SLAID For Customer|SLAID For Service|SLA Name|SLA Name For CI|SLA Name For Customer|SLA Name For Service|SLA Resolution Warning|SLA Resolve By Deadline|SLA Respond By Deadline|SLA Response Warning|SLA Target Time ID|SLA_ Key|STC Time In Minutes|Security Event ID|Service|Service Cart ID|Service Catalog Template Name|Service Customer Is Entitled|Service Entitlements|Service ID|Show All Services|Show Contact Information|Skill ID|Smart Classify Search String|Specifics Type Id|Stat _24 X 7 Elapsed Time|Stat _ Date Time Assigned|Stat _ Date Time Closed|Stat _ Date Time In Progress|Stat _ Date Time Re Opened|Stat _ Date Time Resolved|Stat _ Date Time Responded|Stat _ First Call Resolution|Stat _ Incident Escalated|Stat _ Incident Reopened|Stat _ Number Of Escalations|Stat _ Number Of Touches|Stat _ Response Time|Stat _SLA Resolution Breached|Stat _SLA Resolution Good|Stat _SLA Resolution Warning|Stat _SLA Response Breached|Stat _SLA Response Good|Stat _SLA Response Warning|Status|Status Desc|Status ID|Status Order|Subcategory|Subcategory ID|Task Closed Count|Tasks Closed|Tasks In Progress|Tasks On Hold|Total STC Time In Minutes|Total Task Time|Total Tasks|Urgency|Wait Time|Walk Up Support Location|Was CI Down|Withdraw|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 1st Level Support | 9365b4e90592c81e3b7a024555a6c0094ba77e8773 |  |  |  |  |  |  |  | 0 | Phone |  | PeopleSoft |  |  | False |  |  |  |  |  | False |  |  |  |  |  |  | 0 | demisto admin | user1@mail.com | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | 7/22/2021 12:22 PM | 8 to 5 Monday thru Friday | Accounting | demisto admin | 9365da817530b0bfee892a48fb8815654c6071af03 |  |  | 1st Level Support | This incident was created by Cherwell test playbook-<br/>-<br/>This is from the REST API-<br/>-<br/>This is from the REST API | 2 |  |  |  | 0.02 | 0.53 | 102383 | Service Request |  |  |  | demisto admin | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 |  | 7/22/2021 12:53 PM | False | 2nd Level Support | False | 3rd Level Support |  | 93838607346b42be7074af487d9171ea9f948b7204 ,  ,  | False |  | False |  |  |  | In Progress | ActionInfoDef ID="93d9abdb6242 | Begin Work | False |  |  |  |  |  | False | False |  | 3 | 102383 | 94757184cce46253b3ab694ae58289b64d0cd867ce | 94757184cce46253b3ab694ae58289b64d0cd867ce | False | False |  | Accounting |  |  |  | False |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | Platinum |  | Platinum |  | 7/26/2021 12:07 PM | 7/26/2021 12:22 PM | 7/22/2021 4:22 PM | 7/22/2021 4:07 PM |  | Platinum_Service Request | 0 |  | Enterprise Apps |  |  | True | Platinum, Gold, Silver, Corporate | 9389f689ed2a47e91de7954ecb8f2fe733af0ecb06 | False | False | 9454f50880a42d63b93ce142d58fbbe97de1b3d672 | Submit Incident | 9398862125defd58a8deea46fe88acc411a96e2b00 | 0 |  |  |  |  |  |  | False | False | False | 0 | 4 | 0 | False | False | False | False | False | False | New |  | 938729d99cb110f2a6c3e5488ead246422a7cd115f | 1 | Submit Incident |  | 0 | False | False | False | 0 | 0 | 0 |  | 0 |  | False | False |


### cherwell-download-attachments
***
Downloads imported attachements from a specified business object.


#### Base Command

`cherwell-download-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| id_type | Type of ID. Possible values are: public_id, record_id. | Required | 
| id_value | Public ID or record ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | File result entries. | 


#### Command Example
```!cherwell-download-attachments type=incident id_type=public_id id_value=102383```

#### Context Example
```json
{
    "File": {
        "EntryID": "13537@f0716e08-9825-481c-8938-8e0a91a20557",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "4f12aef086cb181a9c6404bd28fe2a6f",
        "Name": "60X80.jpg",
        "SHA1": "df71c946e1a6c48e00a6376ebb2475f818c7f255",
        "SHA256": "cb27126f168aa69740b87f581a1af467c1f12ceabf3ff9ee56f2c142b1b8a41e",
        "SHA512": "70d3eab2ff2b64aa298e63b91809ca0ee76514c5895c145cd7f538baf58078dc3948bb263c5783647e9ab61fe20f32a4adb34f5d88c7a418a1a36a982c85e4b5",
        "SSDeep": "98304:cHwUVx2eChpJLQEnnE0wsMtEgWilmMPhGxNXnFVfM+3:Iwax2xppnctTAMPhWxr5",
        "Size": 4187889,
        "Type": "JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=9, model=FC1102, software=Google, height=0, datetime=2020:06:13 23:02:58, orientation=upper-left, description=DCIM/101MEDIA/DJI_0284.JPG, width=0], baseline, precision 8, 2750x3667, frames 3"
    }
}
```

#### Human Readable Output



### cherwell-upload-attachment
***
Uploads an attachment to a specified business object.


#### Base Command

`cherwell-upload-attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| id_type | Type of ID. Possible values are: record_id, public_id. | Required | 
| id_value | Public ID or record ID. | Required | 
| file_entry_id | File entry ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.UploadedAttachments.AttachmentFileId | String | AttachmentFileId to use to get information about the attachment. attachment | 
| Cherwell.UploadedAttachments.BusinessObjectType | String |  Business object type, for example: "Incident".  | 
| Cherwell.UploadedAttachments.PublicId | String | Public ID.  | 
| Cherwell.UploadedAttachments.RecordId | String | Record ID. | 


#### Command Example
```!cherwell-upload-attachment file_entry_id=13570@f0716e08-9825-481c-8938-8e0a91a20557 type=incident id_type=public_id id_value=102383```

#### Context Example
```json
{
    "Cherwell": {
        "UploadedAttachments": {
            "AttachmentFileId": "947571fbce24025d9bee3b42d99e6eb4dd887100f4",
            "BusinessObjectType": "incident",
            "PublicId": "102383"
        }
    }
}
```

#### Human Readable Output

>### Attachment: 947571fbce24025d9bee3b42d99e6eb4dd887100f4, was successfully attached to incident 102383

### cherwell-link-business-objects
***
Links business objects that are related.


#### Base Command

`cherwell-link-business-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_type | Parent business object type name. | Required | 
| parent_record_id | Parent business object record ID. | Required | 
| child_type | Child business object type name. | Required | 
| child_record_id | Child business object record ID. | Required | 
| relationship_id | Relationship ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cherwell-link-business-objects parent_type=incident child_type=task relationship_id=9369187528b417b4a17aaa4646b7f7a78b3c821be9 child_record_id=94757210152427ef6ff98741a9a1c01d9fbe80545d parent_record_id=94757184cce46253b3ab694ae58289b64d0cd867ce```

#### Human Readable Output

>### Incident 94757184cce46253b3ab694ae58289b64d0cd867ce and Task 94757210152427ef6ff98741a9a1c01d9fbe80545d were linked

### cherwell-unlink-business-objects
***
Unlinks business objects that are linked and related.


#### Base Command

`cherwell-unlink-business-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_type | Parent business object type name. | Required | 
| parent_record_id | Parent business object record ID. | Required | 
| child_type | Child business object type name. | Required | 
| child_record_id | Child business object record ID. | Required | 
| relationship_id | Relationship ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cherwell-unlink-business-objects parent_type=incident child_type=task relationship_id=9369187528b417b4a17aaa4646b7f7a78b3c821be9 child_record_id=94757210152427ef6ff98741a9a1c01d9fbe80545d parent_record_id=94757184cce46253b3ab694ae58289b64d0cd867ce```

#### Human Readable Output

>### Incident 94757184cce46253b3ab694ae58289b64d0cd867ce and Task 94757210152427ef6ff98741a9a1c01d9fbe80545d were unlinked

### cherwell-get-attachments-info
***
Gets information for business object attachments.


#### Base Command

`cherwell-get-attachments-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| id_type | Type of ID. Possible values are: record_id, public_id. | Required | 
| id_value | Public ID or record ID. | Required | 
| attachment_type | Type of attachment. Possible values are: linked, imported, url. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.AttachmentsInfo.AttachmentFiledId | String | Attachment field ID. | 
| Cherwell.AttachmentsInfo.FileName | String | File name. | 
| Cherwell.AttachmentsInfo.AttachmentId | String | Attachment ID. | 
| Cherwell.AttachmentsInfo.BusinessObjectType | String |  Business object type, for example: "Incident".  | 
| Cherwell.AttachmentsInfo.BusinessObjectPublicId | String | Business object public ID. | 
| Cherwell.AttachmentsInfo.BusinessObjectRecordId | String | Business object record ID. | 


#### Command Example
```!cherwell-get-attachments-info attachment_type=imported type=incident id_type=public_id id_value=102383```

#### Context Example
```json
{
    "Cherwell": {
        "AttachmentsInfo": [
            {
                "AttachmentFiledId": "9475718f7de6f1508ca8704bd9b83d215763f567d1",
                "AttachmentId": "9475718f7e153c3d751b5046b389eeba6df7d6d778",
                "BusinessObjectPublicId": "102383",
                "BusinessObjectType": "incident",
                "FileName": "60X80.jpg"
            }
        ]
    }
}
```

#### Human Readable Output

>### Incident 102383 attachments:
>|Attachment Filed Id|Attachment Id|Business Object Public Id|Business Object Type|File Name|
>|---|---|---|---|---|
>| 9475718f7de6f1508ca8704bd9b83d215763f567d1 | 9475718f7e153c3d751b5046b389eeba6df7d6d778 | 102383 | incident | 60X80.jpg |


### cherwell-remove-attachment
***
Remove the attachment from the specified business object.


#### Base Command

`cherwell-remove-attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| id_type | Type of ID. Possible values are: record_id, public_id. | Required | 
| id_value | Public ID or record ID. | Required | 
| attachment_id | Attachment ID to reomve. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cherwell-remove-attachment type=incident id_type=public_id id_value=102383 attachment_id=9475718f7e153c3d751b5046b389eeba6df7d6d778```

#### Human Readable Output

>### Attachment: 9475718f7e153c3d751b5046b389eeba6df7d6d778, was successfully removed from incident 102383

### cherwell-query-business-object
***
Runs advanced queries to search in a specified business object.


#### Base Command

`cherwell-query-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| query | The query to run. A CSV list of filters such that each filter is of the form: ["field_name","operator","value"] and operator is one of: 'eq'=equal, 'gt'=grater-than, 'lt'=less-than, 'contains', 'startwith'. Special characters should be escaped.<br/>Example: `[["CreatedDateTime":"gt":"4/10/2019 3:10:12 PM"]["Priority","eq","1"]]`. <br/>NOTE: If multiple filters are received for the same field name, an 'OR' operation between the filters will be performed, if the field names are different an 'AND' operation will be performed. | Required | 
| max_results | Maximum number of results to pull. Default is 30. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cherwell-query-business-object type=incident query=[["Description","eq","This incident was created by Cherwell test playbook"]]```

#### Context Example
```json
{
    "Cherwell": {
        "QueryResults": [
            {
                "ApprovalBlockID": "",
                "AssignedTeam": "1st Level Support",
                "AssignedTeamID": "9365b4e90592c81e3b7a024555a6c0094ba77e8773",
                "AssignedTo": "",
                "AssignedToID": "",
                "AssignedToManager": "",
                "Barcode": "",
                "BreachNotes": "",
                "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae",
                "CIDownEndDateTime": "",
                "CIDownStartDateTime": "",
                "CIDowntimeInMinutes": "0.00",
                "CallSource": "Phone",
                "CartItemID": "",
                "Category": "PeopleSoft",
                "Cause": "",
                "ChangeID": "",
                "ClonedIncident": "",
                "ClonedIncidentID": "",
                "CloseDescription": "",
                "ClosedBy": "",
                "ClosedByID": "",
                "ClosedDateTime": "",
                "ClosedOn1stCall": "False",
                "CombinedKB": "",
                "Comments": "",
                "ConfigItemDisplayName": "",
                "ConfigItemRecID": "",
                "ConfigItemType": "",
                "ConfigItemTypeID": "",
                "Cost": "0.00",
                "CreatedBy": "demisto admin",
                "CreatedByEmail": "user1@mail.com",
                "CreatedByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "CreatedDateTime": "7/21/2021 11:00:09 AM",
                "CreatedDuring": "8 to 5 Monday thru Friday",
                "CustomerDepartment": "Accounting",
                "CustomerDisplayName": "demisto admin",
                "CustomerRecID": "9365da817530b0bfee892a48fb8815654c6071af03",
                "CustomerSubscriptionLevel": "",
                "CustomerTypeID": "",
                "DefaultTeam": "1st Level Support",
                "Description": "This incident was created by Cherwell test playbook",
                "DescriptionSentimentValue": "1",
                "EmailNotifications": "",
                "ISMSAuditsID": "",
                "Impact": "",
                "IncidentDurationInDays": "0.17",
                "IncidentDurationInHours": "4.00",
                "IncidentID": "102379",
                "IncidentType": "Service Request",
                "IncidentchildID": "",
                "IncidentchildRecID": "",
                "KnowledgeArticleID": "",
                "LastModBy": "Cherwell Admin",
                "LastModByID": "93546560c6334c3c105d17437c843b9557775b2e0c",
                "LastModTimeStamp": "Byte[] Array",
                "LastModifiedDateTime": "7/21/2021 3:00:15 PM",
                "Level2EscalationComplete": "False",
                "Level2EscalationTeam": "2nd Level Support",
                "Level3EscalationComplete": "False",
                "Level3EscalationTeam": "3rd Level Support",
                "LinkedProblem": "",
                "LinkedSLAs": "93838607346b42be7074af487d9171ea9f948b7204 ,  , ",
                "LinkedToProblem": "False",
                "Location": "",
                "MajorIncident": "False",
                "MajorIncidentID": "",
                "MajorIncidentRecID": "",
                "NetworkEventID": "",
                "NextStatus": "In Progress",
                "NextStatusOneStep": "ActionInfoDef ID=\"93d9abdb6242",
                "NextStatusText": "Begin Work",
                "OnBehalfOf": "False",
                "PendingEndDateTime": "",
                "PendingPreviousStatus": "",
                "PendingReason": "",
                "PendingStartDateTime": "",
                "PickedUpDateTime": "",
                "PortalAffectsMultipleUsers": "False",
                "PortalAffectsPrimaryFunction": "False",
                "PortalAltContactInfo": "",
                "Priority": "3",
                "PublicId": "102379",
                "RecID": "947563943db20d178bf122451b8946535670196726",
                "RecordId": "947563943db20d178bf122451b8946535670196726",
                "RecurringIncident": "False",
                "Reopened": "False",
                "Requester": "",
                "RequesterDepartment": "Accounting",
                "RequesterEmail": "",
                "RequesterID": "",
                "ReviewByDeadline": "1/1/1900 12:00:00 AM",
                "SCTFired": "False",
                "SCTRecID": "",
                "SLAID": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForCI": "",
                "SLAIDForCustomer": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForService": "",
                "SLAName": "Platinum",
                "SLANameForCI": "",
                "SLANameForCustomer": "Platinum",
                "SLANameForService": "",
                "SLAResolutionWarning": "7/23/2021 10:45:09 AM",
                "SLAResolveByDeadline": "7/23/2021 11:00:09 AM",
                "SLARespondByDeadline": "7/21/2021 3:00:09 PM",
                "SLAResponseWarning": "7/21/2021 2:45:09 PM",
                "SLATargetTimeID": "",
                "SLA_Key": "Platinum_Service Request",
                "STCTimeInMinutes": "0",
                "SecurityEventID": "",
                "Service": "Enterprise Apps",
                "ServiceCartID": "",
                "ServiceCatalogTemplateName": "",
                "ServiceCustomerIsEntitled": "True",
                "ServiceEntitlements": "Platinum, Gold, Silver, Corporate",
                "ServiceID": "9389f689ed2a47e91de7954ecb8f2fe733af0ecb06",
                "ShowAllServices": "False",
                "ShowContactInformation": "False",
                "SkillID": "9454f50880a42d63b93ce142d58fbbe97de1b3d672",
                "SmartClassifySearchString": "Submit Incident",
                "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00",
                "Stat_24x7ElapsedTime": "0",
                "Stat_DateTimeAssigned": "",
                "Stat_DateTimeClosed": "",
                "Stat_DateTimeInProgress": "",
                "Stat_DateTimeReOpened": "",
                "Stat_DateTimeResolved": "",
                "Stat_DateTimeResponded": "",
                "Stat_FirstCallResolution": "False",
                "Stat_IncidentEscalated": "False",
                "Stat_IncidentReopened": "False",
                "Stat_NumberOfEscalations": "0",
                "Stat_NumberOfTouches": "5",
                "Stat_ResponseTime": "0",
                "Stat_SLAResolutionBreached": "False",
                "Stat_SLAResolutionGood": "False",
                "Stat_SLAResolutionWarning": "False",
                "Stat_SLAResponseBreached": "True",
                "Stat_SLAResponseGood": "False",
                "Stat_SLAResponseWarning": "True",
                "Status": "New",
                "StatusDesc": "",
                "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f",
                "StatusOrder": "1",
                "Subcategory": "Submit Incident",
                "SubcategoryID": "",
                "TaskClosedCount": "0",
                "TasksClosed": "False",
                "TasksInProgress": "False",
                "TasksOnHold": "False",
                "TotalSTCTimeInMinutes": "0",
                "TotalTaskTime": "0.00",
                "TotalTasks": "0.00",
                "Urgency": "",
                "WaitTime": "0",
                "WalkUpSupportLocation": "",
                "WasCIDown": "False",
                "Withdraw": "False"
            },
            {
                "ApprovalBlockID": "",
                "AssignedTeam": "1st Level Support",
                "AssignedTeamID": "9365b4e90592c81e3b7a024555a6c0094ba77e8773",
                "AssignedTo": "",
                "AssignedToID": "",
                "AssignedToManager": "",
                "Barcode": "",
                "BreachNotes": "",
                "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae",
                "CIDownEndDateTime": "",
                "CIDownStartDateTime": "",
                "CIDowntimeInMinutes": "0.00",
                "CallSource": "Phone",
                "CartItemID": "",
                "Category": "PeopleSoft",
                "Cause": "",
                "ChangeID": "",
                "ClonedIncident": "",
                "ClonedIncidentID": "",
                "CloseDescription": "",
                "ClosedBy": "",
                "ClosedByID": "",
                "ClosedDateTime": "",
                "ClosedOn1stCall": "False",
                "CombinedKB": "",
                "Comments": "",
                "ConfigItemDisplayName": "",
                "ConfigItemRecID": "",
                "ConfigItemType": "",
                "ConfigItemTypeID": "",
                "Cost": "0.00",
                "CreatedBy": "demisto admin",
                "CreatedByEmail": "user1@mail.com",
                "CreatedByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "CreatedDateTime": "7/21/2021 11:01:52 AM",
                "CreatedDuring": "8 to 5 Monday thru Friday",
                "CustomerDepartment": "Accounting",
                "CustomerDisplayName": "demisto admin",
                "CustomerRecID": "9365da817530b0bfee892a48fb8815654c6071af03",
                "CustomerSubscriptionLevel": "",
                "CustomerTypeID": "",
                "DefaultTeam": "1st Level Support",
                "Description": "This incident was created by Cherwell test playbook",
                "DescriptionSentimentValue": "1",
                "EmailNotifications": "",
                "ISMSAuditsID": "",
                "Impact": "",
                "IncidentDurationInDays": "0.17",
                "IncidentDurationInHours": "4.00",
                "IncidentID": "102380",
                "IncidentType": "Service Request",
                "IncidentchildID": "",
                "IncidentchildRecID": "",
                "KnowledgeArticleID": "",
                "LastModBy": "Cherwell Admin",
                "LastModByID": "93546560c6334c3c105d17437c843b9557775b2e0c",
                "LastModTimeStamp": "Byte[] Array",
                "LastModifiedDateTime": "7/21/2021 3:02:01 PM",
                "Level2EscalationComplete": "False",
                "Level2EscalationTeam": "2nd Level Support",
                "Level3EscalationComplete": "False",
                "Level3EscalationTeam": "3rd Level Support",
                "LinkedProblem": "",
                "LinkedSLAs": "93838607346b42be7074af487d9171ea9f948b7204 ,  , ",
                "LinkedToProblem": "False",
                "Location": "",
                "MajorIncident": "False",
                "MajorIncidentID": "",
                "MajorIncidentRecID": "",
                "NetworkEventID": "",
                "NextStatus": "In Progress",
                "NextStatusOneStep": "ActionInfoDef ID=\"93d9abdb6242",
                "NextStatusText": "Begin Work",
                "OnBehalfOf": "False",
                "PendingEndDateTime": "",
                "PendingPreviousStatus": "",
                "PendingReason": "",
                "PendingStartDateTime": "",
                "PickedUpDateTime": "",
                "PortalAffectsMultipleUsers": "False",
                "PortalAffectsPrimaryFunction": "False",
                "PortalAltContactInfo": "",
                "Priority": "1",
                "PublicId": "102380",
                "RecID": "94756398453cbed47f9b19434e91e320b92cb47d3d",
                "RecordId": "94756398453cbed47f9b19434e91e320b92cb47d3d",
                "RecurringIncident": "False",
                "Reopened": "False",
                "Requester": "",
                "RequesterDepartment": "Accounting",
                "RequesterEmail": "",
                "RequesterID": "",
                "ReviewByDeadline": "1/1/1900 12:00:00 AM",
                "SCTFired": "False",
                "SCTRecID": "",
                "SLAID": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForCI": "",
                "SLAIDForCustomer": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForService": "",
                "SLAName": "Platinum",
                "SLANameForCI": "",
                "SLANameForCustomer": "Platinum",
                "SLANameForService": "",
                "SLAResolutionWarning": "7/21/2021 2:56:52 PM",
                "SLAResolveByDeadline": "7/21/2021 3:01:52 PM",
                "SLARespondByDeadline": "7/21/2021 11:26:52 AM",
                "SLAResponseWarning": "7/21/2021 11:11:52 AM",
                "SLATargetTimeID": "",
                "SLA_Key": "Platinum_Service Request",
                "STCTimeInMinutes": "0",
                "SecurityEventID": "",
                "Service": "Enterprise Apps",
                "ServiceCartID": "",
                "ServiceCatalogTemplateName": "",
                "ServiceCustomerIsEntitled": "True",
                "ServiceEntitlements": "Platinum, Gold, Silver, Corporate",
                "ServiceID": "9389f689ed2a47e91de7954ecb8f2fe733af0ecb06",
                "ShowAllServices": "False",
                "ShowContactInformation": "False",
                "SkillID": "9454f50880a42d63b93ce142d58fbbe97de1b3d672",
                "SmartClassifySearchString": "Submit Incident",
                "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00",
                "Stat_24x7ElapsedTime": "0",
                "Stat_DateTimeAssigned": "",
                "Stat_DateTimeClosed": "",
                "Stat_DateTimeInProgress": "",
                "Stat_DateTimeReOpened": "",
                "Stat_DateTimeResolved": "",
                "Stat_DateTimeResponded": "",
                "Stat_FirstCallResolution": "False",
                "Stat_IncidentEscalated": "False",
                "Stat_IncidentReopened": "False",
                "Stat_NumberOfEscalations": "0",
                "Stat_NumberOfTouches": "11",
                "Stat_ResponseTime": "0",
                "Stat_SLAResolutionBreached": "True",
                "Stat_SLAResolutionGood": "False",
                "Stat_SLAResolutionWarning": "True",
                "Stat_SLAResponseBreached": "True",
                "Stat_SLAResponseGood": "False",
                "Stat_SLAResponseWarning": "True",
                "Status": "New",
                "StatusDesc": "",
                "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f",
                "StatusOrder": "1",
                "Subcategory": "Submit Incident",
                "SubcategoryID": "",
                "TaskClosedCount": "0",
                "TasksClosed": "False",
                "TasksInProgress": "False",
                "TasksOnHold": "False",
                "TotalSTCTimeInMinutes": "0",
                "TotalTaskTime": "0.00",
                "TotalTasks": "0.00",
                "Urgency": "",
                "WaitTime": "0",
                "WalkUpSupportLocation": "",
                "WasCIDown": "False",
                "Withdraw": "False"
            },
            {
                "ApprovalBlockID": "",
                "AssignedTeam": "1st Level Support",
                "AssignedTeamID": "9365b4e90592c81e3b7a024555a6c0094ba77e8773",
                "AssignedTo": "",
                "AssignedToID": "",
                "AssignedToManager": "",
                "Barcode": "",
                "BreachNotes": "",
                "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae",
                "CIDownEndDateTime": "",
                "CIDownStartDateTime": "",
                "CIDowntimeInMinutes": "0.00",
                "CallSource": "Phone",
                "CartItemID": "",
                "Category": "PeopleSoft",
                "Cause": "",
                "ChangeID": "",
                "ClonedIncident": "",
                "ClonedIncidentID": "",
                "CloseDescription": "",
                "ClosedBy": "",
                "ClosedByID": "",
                "ClosedDateTime": "",
                "ClosedOn1stCall": "False",
                "CombinedKB": "",
                "Comments": "",
                "ConfigItemDisplayName": "",
                "ConfigItemRecID": "",
                "ConfigItemType": "",
                "ConfigItemTypeID": "",
                "Cost": "0.00",
                "CreatedBy": "demisto admin",
                "CreatedByEmail": "user1@mail.com",
                "CreatedByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "CreatedDateTime": "7/21/2021 1:11:19 PM",
                "CreatedDuring": "8 to 5 Monday thru Friday",
                "CustomerDepartment": "Accounting",
                "CustomerDisplayName": "demisto admin",
                "CustomerRecID": "9365da817530b0bfee892a48fb8815654c6071af03",
                "CustomerSubscriptionLevel": "",
                "CustomerTypeID": "",
                "DefaultTeam": "1st Level Support",
                "Description": "This incident was created by Cherwell test playbook",
                "DescriptionSentimentValue": "1",
                "EmailNotifications": "",
                "ISMSAuditsID": "",
                "Impact": "",
                "IncidentDurationInDays": "0.79",
                "IncidentDurationInHours": "19.00",
                "IncidentID": "102381",
                "IncidentType": "Service Request",
                "IncidentchildID": "",
                "IncidentchildRecID": "",
                "KnowledgeArticleID": "",
                "LastModBy": "Cherwell Admin",
                "LastModByID": "93546560c6334c3c105d17437c843b9557775b2e0c",
                "LastModTimeStamp": "Byte[] Array",
                "LastModifiedDateTime": "7/22/2021 8:11:20 AM",
                "Level2EscalationComplete": "False",
                "Level2EscalationTeam": "2nd Level Support",
                "Level3EscalationComplete": "False",
                "Level3EscalationTeam": "3rd Level Support",
                "LinkedProblem": "",
                "LinkedSLAs": "93838607346b42be7074af487d9171ea9f948b7204 ,  , ",
                "LinkedToProblem": "False",
                "Location": "",
                "MajorIncident": "False",
                "MajorIncidentID": "",
                "MajorIncidentRecID": "",
                "NetworkEventID": "",
                "NextStatus": "In Progress",
                "NextStatusOneStep": "ActionInfoDef ID=\"93d9abdb6242",
                "NextStatusText": "Begin Work",
                "OnBehalfOf": "False",
                "PendingEndDateTime": "",
                "PendingPreviousStatus": "",
                "PendingReason": "",
                "PendingStartDateTime": "",
                "PickedUpDateTime": "",
                "PortalAffectsMultipleUsers": "False",
                "PortalAffectsPrimaryFunction": "False",
                "PortalAltContactInfo": "",
                "Priority": "3",
                "PublicId": "102381",
                "RecID": "947564c7add241eb40f5ff40f5a026147a9fc0d47d",
                "RecordId": "947564c7add241eb40f5ff40f5a026147a9fc0d47d",
                "RecurringIncident": "False",
                "Reopened": "False",
                "Requester": "",
                "RequesterDepartment": "Accounting",
                "RequesterEmail": "",
                "RequesterID": "",
                "ReviewByDeadline": "1/1/1900 12:00:00 AM",
                "SCTFired": "False",
                "SCTRecID": "",
                "SLAID": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForCI": "",
                "SLAIDForCustomer": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForService": "",
                "SLAName": "Platinum",
                "SLANameForCI": "",
                "SLANameForCustomer": "Platinum",
                "SLANameForService": "",
                "SLAResolutionWarning": "7/23/2021 12:56:19 PM",
                "SLAResolveByDeadline": "7/23/2021 1:11:19 PM",
                "SLARespondByDeadline": "7/22/2021 8:11:19 AM",
                "SLAResponseWarning": "7/21/2021 4:56:19 PM",
                "SLATargetTimeID": "",
                "SLA_Key": "Platinum_Service Request",
                "STCTimeInMinutes": "0",
                "SecurityEventID": "",
                "Service": "Enterprise Apps",
                "ServiceCartID": "",
                "ServiceCatalogTemplateName": "",
                "ServiceCustomerIsEntitled": "True",
                "ServiceEntitlements": "Platinum, Gold, Silver, Corporate",
                "ServiceID": "9389f689ed2a47e91de7954ecb8f2fe733af0ecb06",
                "ShowAllServices": "False",
                "ShowContactInformation": "False",
                "SkillID": "9454f50880a42d63b93ce142d58fbbe97de1b3d672",
                "SmartClassifySearchString": "Submit Incident",
                "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00",
                "Stat_24x7ElapsedTime": "0",
                "Stat_DateTimeAssigned": "",
                "Stat_DateTimeClosed": "",
                "Stat_DateTimeInProgress": "",
                "Stat_DateTimeReOpened": "",
                "Stat_DateTimeResolved": "",
                "Stat_DateTimeResponded": "",
                "Stat_FirstCallResolution": "False",
                "Stat_IncidentEscalated": "False",
                "Stat_IncidentReopened": "False",
                "Stat_NumberOfEscalations": "0",
                "Stat_NumberOfTouches": "5",
                "Stat_ResponseTime": "0",
                "Stat_SLAResolutionBreached": "False",
                "Stat_SLAResolutionGood": "False",
                "Stat_SLAResolutionWarning": "False",
                "Stat_SLAResponseBreached": "True",
                "Stat_SLAResponseGood": "False",
                "Stat_SLAResponseWarning": "True",
                "Status": "New",
                "StatusDesc": "",
                "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f",
                "StatusOrder": "1",
                "Subcategory": "Submit Incident",
                "SubcategoryID": "",
                "TaskClosedCount": "0",
                "TasksClosed": "False",
                "TasksInProgress": "False",
                "TasksOnHold": "False",
                "TotalSTCTimeInMinutes": "0",
                "TotalTaskTime": "0.00",
                "TotalTasks": "0.00",
                "Urgency": "",
                "WaitTime": "0",
                "WalkUpSupportLocation": "",
                "WasCIDown": "False",
                "Withdraw": "False"
            },
            {
                "ApprovalBlockID": "",
                "AssignedTeam": "1st Level Support",
                "AssignedTeamID": "9365b4e90592c81e3b7a024555a6c0094ba77e8773",
                "AssignedTo": "",
                "AssignedToID": "",
                "AssignedToManager": "",
                "Barcode": "",
                "BreachNotes": "",
                "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae",
                "CIDownEndDateTime": "",
                "CIDownStartDateTime": "",
                "CIDowntimeInMinutes": "0.00",
                "CallSource": "Phone",
                "CartItemID": "",
                "Category": "PeopleSoft",
                "Cause": "",
                "ChangeID": "",
                "ClonedIncident": "",
                "ClonedIncidentID": "",
                "CloseDescription": "",
                "ClosedBy": "",
                "ClosedByID": "",
                "ClosedDateTime": "",
                "ClosedOn1stCall": "False",
                "CombinedKB": "",
                "Comments": "",
                "ConfigItemDisplayName": "",
                "ConfigItemRecID": "",
                "ConfigItemType": "",
                "ConfigItemTypeID": "",
                "Cost": "0.00",
                "CreatedBy": "demisto admin",
                "CreatedByEmail": "user1@mail.com",
                "CreatedByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "CreatedDateTime": "7/22/2021 12:22:27 PM",
                "CreatedDuring": "8 to 5 Monday thru Friday",
                "CustomerDepartment": "Accounting",
                "CustomerDisplayName": "demisto admin",
                "CustomerRecID": "9365da817530b0bfee892a48fb8815654c6071af03",
                "CustomerSubscriptionLevel": "",
                "CustomerTypeID": "",
                "DefaultTeam": "1st Level Support",
                "Description": "This incident was created by Cherwell test playbook",
                "DescriptionSentimentValue": "1",
                "EmailNotifications": "",
                "ISMSAuditsID": "",
                "Impact": "",
                "IncidentDurationInDays": "0.00",
                "IncidentDurationInHours": "0.00",
                "IncidentID": "102382",
                "IncidentType": "Service Request",
                "IncidentchildID": "",
                "IncidentchildRecID": "",
                "KnowledgeArticleID": "",
                "LastModBy": "demisto admin",
                "LastModByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "LastModTimeStamp": "Byte[] Array",
                "LastModifiedDateTime": "7/22/2021 12:22:31 PM",
                "Level2EscalationComplete": "False",
                "Level2EscalationTeam": "2nd Level Support",
                "Level3EscalationComplete": "False",
                "Level3EscalationTeam": "3rd Level Support",
                "LinkedProblem": "",
                "LinkedSLAs": "93838607346b42be7074af487d9171ea9f948b7204 ,  , ",
                "LinkedToProblem": "False",
                "Location": "",
                "MajorIncident": "False",
                "MajorIncidentID": "",
                "MajorIncidentRecID": "",
                "NetworkEventID": "",
                "NextStatus": "In Progress",
                "NextStatusOneStep": "ActionInfoDef ID=\"93d9abdb6242",
                "NextStatusText": "Begin Work",
                "OnBehalfOf": "False",
                "PendingEndDateTime": "",
                "PendingPreviousStatus": "",
                "PendingReason": "",
                "PendingStartDateTime": "",
                "PickedUpDateTime": "",
                "PortalAffectsMultipleUsers": "False",
                "PortalAffectsPrimaryFunction": "False",
                "PortalAltContactInfo": "",
                "Priority": "3",
                "PublicId": "102382",
                "RecID": "947571842387f6d7df118546e29cac13df2afafebc",
                "RecordId": "947571842387f6d7df118546e29cac13df2afafebc",
                "RecurringIncident": "False",
                "Reopened": "False",
                "Requester": "",
                "RequesterDepartment": "Accounting",
                "RequesterEmail": "",
                "RequesterID": "",
                "ReviewByDeadline": "1/1/1900 12:00:00 AM",
                "SCTFired": "False",
                "SCTRecID": "",
                "SLAID": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForCI": "",
                "SLAIDForCustomer": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForService": "",
                "SLAName": "Platinum",
                "SLANameForCI": "",
                "SLANameForCustomer": "Platinum",
                "SLANameForService": "",
                "SLAResolutionWarning": "7/26/2021 12:07:27 PM",
                "SLAResolveByDeadline": "7/26/2021 12:22:27 PM",
                "SLARespondByDeadline": "7/22/2021 4:22:27 PM",
                "SLAResponseWarning": "7/22/2021 4:07:27 PM",
                "SLATargetTimeID": "",
                "SLA_Key": "Platinum_Service Request",
                "STCTimeInMinutes": "0",
                "SecurityEventID": "",
                "Service": "Enterprise Apps",
                "ServiceCartID": "",
                "ServiceCatalogTemplateName": "",
                "ServiceCustomerIsEntitled": "True",
                "ServiceEntitlements": "Platinum, Gold, Silver, Corporate",
                "ServiceID": "9389f689ed2a47e91de7954ecb8f2fe733af0ecb06",
                "ShowAllServices": "False",
                "ShowContactInformation": "False",
                "SkillID": "9454f50880a42d63b93ce142d58fbbe97de1b3d672",
                "SmartClassifySearchString": "Submit Incident",
                "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00",
                "Stat_24x7ElapsedTime": "0",
                "Stat_DateTimeAssigned": "",
                "Stat_DateTimeClosed": "",
                "Stat_DateTimeInProgress": "",
                "Stat_DateTimeReOpened": "",
                "Stat_DateTimeResolved": "",
                "Stat_DateTimeResponded": "",
                "Stat_FirstCallResolution": "False",
                "Stat_IncidentEscalated": "False",
                "Stat_IncidentReopened": "False",
                "Stat_NumberOfEscalations": "0",
                "Stat_NumberOfTouches": "1",
                "Stat_ResponseTime": "0",
                "Stat_SLAResolutionBreached": "False",
                "Stat_SLAResolutionGood": "False",
                "Stat_SLAResolutionWarning": "False",
                "Stat_SLAResponseBreached": "False",
                "Stat_SLAResponseGood": "False",
                "Stat_SLAResponseWarning": "False",
                "Status": "New",
                "StatusDesc": "",
                "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f",
                "StatusOrder": "1",
                "Subcategory": "Submit Incident",
                "SubcategoryID": "",
                "TaskClosedCount": "0",
                "TasksClosed": "False",
                "TasksInProgress": "False",
                "TasksOnHold": "False",
                "TotalSTCTimeInMinutes": "0",
                "TotalTaskTime": "0.00",
                "TotalTasks": "0.00",
                "Urgency": "",
                "WaitTime": "0",
                "WalkUpSupportLocation": "",
                "WasCIDown": "False",
                "Withdraw": "False"
            },
            {
                "ApprovalBlockID": "",
                "AssignedTeam": "1st Level Support",
                "AssignedTeamID": "9365b4e90592c81e3b7a024555a6c0094ba77e8773",
                "AssignedTo": "",
                "AssignedToID": "",
                "AssignedToManager": "",
                "Barcode": "",
                "BreachNotes": "",
                "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae",
                "CIDownEndDateTime": "",
                "CIDownStartDateTime": "",
                "CIDowntimeInMinutes": "0.00",
                "CallSource": "Phone",
                "CartItemID": "",
                "Category": "PeopleSoft",
                "Cause": "",
                "ChangeID": "",
                "ClonedIncident": "",
                "ClonedIncidentID": "",
                "CloseDescription": "",
                "ClosedBy": "",
                "ClosedByID": "",
                "ClosedDateTime": "",
                "ClosedOn1stCall": "False",
                "CombinedKB": "",
                "Comments": "",
                "ConfigItemDisplayName": "",
                "ConfigItemRecID": "",
                "ConfigItemType": "",
                "ConfigItemTypeID": "",
                "Cost": "0.00",
                "CreatedBy": "demisto admin",
                "CreatedByEmail": "user1@mail.com",
                "CreatedByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "CreatedDateTime": "7/22/2021 12:54:18 PM",
                "CreatedDuring": "8 to 5 Monday thru Friday",
                "CustomerDepartment": "Accounting",
                "CustomerDisplayName": "demisto admin",
                "CustomerRecID": "9365da817530b0bfee892a48fb8815654c6071af03",
                "CustomerSubscriptionLevel": "",
                "CustomerTypeID": "",
                "DefaultTeam": "1st Level Support",
                "Description": "This incident was created by Cherwell test playbook",
                "DescriptionSentimentValue": "1",
                "EmailNotifications": "",
                "ISMSAuditsID": "",
                "Impact": "",
                "IncidentDurationInDays": "0.00",
                "IncidentDurationInHours": "0.00",
                "IncidentID": "102384",
                "IncidentType": "Service Request",
                "IncidentchildID": "",
                "IncidentchildRecID": "",
                "KnowledgeArticleID": "",
                "LastModBy": "demisto admin",
                "LastModByID": "9365b511f78906c1fe83644c3fb33e9ec1466f7d90",
                "LastModTimeStamp": "Byte[] Array",
                "LastModifiedDateTime": "7/22/2021 12:54:18 PM",
                "Level2EscalationComplete": "False",
                "Level2EscalationTeam": "2nd Level Support",
                "Level3EscalationComplete": "False",
                "Level3EscalationTeam": "3rd Level Support",
                "LinkedProblem": "",
                "LinkedSLAs": "93838607346b42be7074af487d9171ea9f948b7204 ,  , ",
                "LinkedToProblem": "False",
                "Location": "",
                "MajorIncident": "False",
                "MajorIncidentID": "",
                "MajorIncidentRecID": "",
                "NetworkEventID": "",
                "NextStatus": "In Progress",
                "NextStatusOneStep": "ActionInfoDef ID=\"93d9abdb6242",
                "NextStatusText": "Begin Work",
                "OnBehalfOf": "False",
                "PendingEndDateTime": "",
                "PendingPreviousStatus": "",
                "PendingReason": "",
                "PendingStartDateTime": "",
                "PickedUpDateTime": "",
                "PortalAffectsMultipleUsers": "False",
                "PortalAffectsPrimaryFunction": "False",
                "PortalAltContactInfo": "",
                "Priority": "3",
                "PublicId": "102384",
                "RecID": "947571cec8a5b5f03850c940c2bf6ca2bf116ffce9",
                "RecordId": "947571cec8a5b5f03850c940c2bf6ca2bf116ffce9",
                "RecurringIncident": "False",
                "Reopened": "False",
                "Requester": "",
                "RequesterDepartment": "Accounting",
                "RequesterEmail": "",
                "RequesterID": "",
                "ReviewByDeadline": "1/1/1900 12:00:00 AM",
                "SCTFired": "False",
                "SCTRecID": "",
                "SLAID": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForCI": "",
                "SLAIDForCustomer": "93838607346b42be7074af487d9171ea9f948b7204",
                "SLAIDForService": "",
                "SLAName": "Platinum",
                "SLANameForCI": "",
                "SLANameForCustomer": "Platinum",
                "SLANameForService": "",
                "SLAResolutionWarning": "7/26/2021 12:39:18 PM",
                "SLAResolveByDeadline": "7/26/2021 12:54:18 PM",
                "SLARespondByDeadline": "7/22/2021 4:54:18 PM",
                "SLAResponseWarning": "7/22/2021 4:39:18 PM",
                "SLATargetTimeID": "",
                "SLA_Key": "Platinum_Service Request",
                "STCTimeInMinutes": "0",
                "SecurityEventID": "",
                "Service": "Enterprise Apps",
                "ServiceCartID": "",
                "ServiceCatalogTemplateName": "",
                "ServiceCustomerIsEntitled": "True",
                "ServiceEntitlements": "Platinum, Gold, Silver, Corporate",
                "ServiceID": "9389f689ed2a47e91de7954ecb8f2fe733af0ecb06",
                "ShowAllServices": "False",
                "ShowContactInformation": "False",
                "SkillID": "9454f50880a42d63b93ce142d58fbbe97de1b3d672",
                "SmartClassifySearchString": "Submit Incident",
                "SpecificsTypeId": "9398862125defd58a8deea46fe88acc411a96e2b00",
                "Stat_24x7ElapsedTime": "0",
                "Stat_DateTimeAssigned": "",
                "Stat_DateTimeClosed": "",
                "Stat_DateTimeInProgress": "",
                "Stat_DateTimeReOpened": "",
                "Stat_DateTimeResolved": "",
                "Stat_DateTimeResponded": "",
                "Stat_FirstCallResolution": "False",
                "Stat_IncidentEscalated": "False",
                "Stat_IncidentReopened": "False",
                "Stat_NumberOfEscalations": "0",
                "Stat_NumberOfTouches": "1",
                "Stat_ResponseTime": "0",
                "Stat_SLAResolutionBreached": "False",
                "Stat_SLAResolutionGood": "False",
                "Stat_SLAResolutionWarning": "False",
                "Stat_SLAResponseBreached": "False",
                "Stat_SLAResponseGood": "False",
                "Stat_SLAResponseWarning": "False",
                "Status": "New",
                "StatusDesc": "",
                "StatusID": "938729d99cb110f2a6c3e5488ead246422a7cd115f",
                "StatusOrder": "1",
                "Subcategory": "Submit Incident",
                "SubcategoryID": "",
                "TaskClosedCount": "0",
                "TasksClosed": "False",
                "TasksInProgress": "False",
                "TasksOnHold": "False",
                "TotalSTCTimeInMinutes": "0",
                "TotalTaskTime": "0.00",
                "TotalTasks": "0.00",
                "Urgency": "",
                "WaitTime": "0",
                "WalkUpSupportLocation": "",
                "WasCIDown": "False",
                "Withdraw": "False"
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Results
>|Approval Block ID|Assigned Team|Assigned Team ID|Assigned To|Assigned To ID|Assigned To Manager|Barcode|Breach Notes|Business Object Id|CI Down End Date Time|CI Down Start Date Time|CI Downtime In Minutes|Call Source|Cart Item ID|Category|Cause|Change ID|Cloned Incident|Cloned Incident ID|Close Description|Closed By|Closed By ID|Closed Date Time|Closed On 1 St Call|Combined KB|Comments|Config Item Display Name|Config Item Rec ID|Config Item Type|Config Item Type ID|Cost|Created By|Created By Email|Created By ID|Created Date Time|Created During|Customer Department|Customer Display Name|Customer Rec ID|Customer Subscription Level|Customer Type ID|Default Team|Description|Description Sentiment Value|Email Notifications|ISMS Audits ID|Impact|In cident Duration In Days|In cident Duration In Hours|Incident ID|Incident Type|Incidentchild ID|Incidentchild Rec ID|Knowledge Article ID|Last Mod By|Last Mod By ID|Last Mod Time Stamp|Last Modified Date Time|Level 2 Escalation Complete|Level 2 Escalation Team|Level 3 Escalation Complete|Level 3 Escalation Team|Linked Problem|Linked SL As|Linked To Problem|Location|Major Incident|Major Incident ID|Major Incident Rec ID|Network Event ID|Next Status|Next Status One Step|Next Status Text|On Behalf Of|Pending End Date Time|Pending Previous Status|Pending Reason|Pending Start Date Time|Picked Up Date Time|Portal Affects Multiple Users|Portal Affects Primary Function|Portal Alt Contact Info|Priority|Public Id|Rec ID|Record Id|Recurring Incident|Reopened|Requester|Requester Department|Requester Email|Requester ID|Review By Deadline|SCT Fired|SCT Rec ID|SLAID|SLAID For CI|SLAID For Customer|SLAID For Service|SLA Name|SLA Name For CI|SLA Name For Customer|SLA Name For Service|SLA Resolution Warning|SLA Resolve By Deadline|SLA Respond By Deadline|SLA Response Warning|SLA Target Time ID|SLA_ Key|STC Time In Minutes|Security Event ID|Service|Service Cart ID|Service Catalog Template Name|Service Customer Is Entitled|Service Entitlements|Service ID|Show All Services|Show Contact Information|Skill ID|Smart Classify Search String|Specifics Type Id|Stat _24 X 7 Elapsed Time|Stat _ Date Time Assigned|Stat _ Date Time Closed|Stat _ Date Time In Progress|Stat _ Date Time Re Opened|Stat _ Date Time Resolved|Stat _ Date Time Responded|Stat _ First Call Resolution|Stat _ Incident Escalated|Stat _ Incident Reopened|Stat _ Number Of Escalations|Stat _ Number Of Touches|Stat _ Response Time|Stat _SLA Resolution Breached|Stat _SLA Resolution Good|Stat _SLA Resolution Warning|Stat _SLA Response Breached|Stat _SLA Response Good|Stat _SLA Response Warning|Status|Status Desc|Status ID|Status Order|Subcategory|Subcategory ID|Task Closed Count|Tasks Closed|Tasks In Progress|Tasks On Hold|Total STC Time In Minutes|Total Task Time|Total Tasks|Urgency|Wait Time|Walk Up Support Location|Was CI Down|Withdraw|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 1st Level Support | 9365b4e90592c81e3b7a024555a6c0094ba77e8773 |  |  |  |  |  | 6dd53665c0c24cab86870a21cf6434ae |  |  | 0.00 | Phone |  | PeopleSoft |  |  |  |  |  |  |  |  | False |  |  |  |  |  |  | 0.00 | demisto admin | user1@mail.com | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | 7/21/2021 11:00:09 AM | 8 to 5 Monday thru Friday | Accounting | demisto admin | 9365da817530b0bfee892a48fb8815654c6071af03 |  |  | 1st Level Support | This incident was created by Cherwell test playbook | 1 |  |  |  | 0.17 | 4.00 | 102379 | Service Request |  |  |  | Cherwell Admin | 93546560c6334c3c105d17437c843b9557775b2e0c | Byte[] Array | 7/21/2021 3:00:15 PM | False | 2nd Level Support | False | 3rd Level Support |  | 93838607346b42be7074af487d9171ea9f948b7204 ,  ,  | False |  | False |  |  |  | In Progress | ActionInfoDef ID="93d9abdb6242 | Begin Work | False |  |  |  |  |  | False | False |  | 3 | 102379 | 947563943db20d178bf122451b8946535670196726 | 947563943db20d178bf122451b8946535670196726 | False | False |  | Accounting |  |  | 1/1/1900 12:00:00 AM | False |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | Platinum |  | Platinum |  | 7/23/2021 10:45:09 AM | 7/23/2021 11:00:09 AM | 7/21/2021 3:00:09 PM | 7/21/2021 2:45:09 PM |  | Platinum_Service Request | 0 |  | Enterprise Apps |  |  | True | Platinum, Gold, Silver, Corporate | 9389f689ed2a47e91de7954ecb8f2fe733af0ecb06 | False | False | 9454f50880a42d63b93ce142d58fbbe97de1b3d672 | Submit Incident | 9398862125defd58a8deea46fe88acc411a96e2b00 | 0 |  |  |  |  |  |  | False | False | False | 0 | 5 | 0 | False | False | False | True | False | True | New |  | 938729d99cb110f2a6c3e5488ead246422a7cd115f | 1 | Submit Incident |  | 0 | False | False | False | 0 | 0.00 | 0.00 |  | 0 |  | False | False |
>|  | 1st Level Support | 9365b4e90592c81e3b7a024555a6c0094ba77e8773 |  |  |  |  |  | 6dd53665c0c24cab86870a21cf6434ae |  |  | 0.00 | Phone |  | PeopleSoft |  |  |  |  |  |  |  |  | False |  |  |  |  |  |  | 0.00 | demisto admin | user1@mail.com | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | 7/21/2021 11:01:52 AM | 8 to 5 Monday thru Friday | Accounting | demisto admin | 9365da817530b0bfee892a48fb8815654c6071af03 |  |  | 1st Level Support | This incident was created by Cherwell test playbook | 1 |  |  |  | 0.17 | 4.00 | 102380 | Service Request |  |  |  | Cherwell Admin | 93546560c6334c3c105d17437c843b9557775b2e0c | Byte[] Array | 7/21/2021 3:02:01 PM | False | 2nd Level Support | False | 3rd Level Support |  | 93838607346b42be7074af487d9171ea9f948b7204 ,  ,  | False |  | False |  |  |  | In Progress | ActionInfoDef ID="93d9abdb6242 | Begin Work | False |  |  |  |  |  | False | False |  | 1 | 102380 | 94756398453cbed47f9b19434e91e320b92cb47d3d | 94756398453cbed47f9b19434e91e320b92cb47d3d | False | False |  | Accounting |  |  | 1/1/1900 12:00:00 AM | False |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | Platinum |  | Platinum |  | 7/21/2021 2:56:52 PM | 7/21/2021 3:01:52 PM | 7/21/2021 11:26:52 AM | 7/21/2021 11:11:52 AM |  | Platinum_Service Request | 0 |  | Enterprise Apps |  |  | True | Platinum, Gold, Silver, Corporate | 9389f689ed2a47e91de7954ecb8f2fe733af0ecb06 | False | False | 9454f50880a42d63b93ce142d58fbbe97de1b3d672 | Submit Incident | 9398862125defd58a8deea46fe88acc411a96e2b00 | 0 |  |  |  |  |  |  | False | False | False | 0 | 11 | 0 | True | False | True | True | False | True | New |  | 938729d99cb110f2a6c3e5488ead246422a7cd115f | 1 | Submit Incident |  | 0 | False | False | False | 0 | 0.00 | 0.00 |  | 0 |  | False | False |
>|  | 1st Level Support | 9365b4e90592c81e3b7a024555a6c0094ba77e8773 |  |  |  |  |  | 6dd53665c0c24cab86870a21cf6434ae |  |  | 0.00 | Phone |  | PeopleSoft |  |  |  |  |  |  |  |  | False |  |  |  |  |  |  | 0.00 | demisto admin | user1@mail.com | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | 7/21/2021 1:11:19 PM | 8 to 5 Monday thru Friday | Accounting | demisto admin | 9365da817530b0bfee892a48fb8815654c6071af03 |  |  | 1st Level Support | This incident was created by Cherwell test playbook | 1 |  |  |  | 0.79 | 19.00 | 102381 | Service Request |  |  |  | Cherwell Admin | 93546560c6334c3c105d17437c843b9557775b2e0c | Byte[] Array | 7/22/2021 8:11:20 AM | False | 2nd Level Support | False | 3rd Level Support |  | 93838607346b42be7074af487d9171ea9f948b7204 ,  ,  | False |  | False |  |  |  | In Progress | ActionInfoDef ID="93d9abdb6242 | Begin Work | False |  |  |  |  |  | False | False |  | 3 | 102381 | 947564c7add241eb40f5ff40f5a026147a9fc0d47d | 947564c7add241eb40f5ff40f5a026147a9fc0d47d | False | False |  | Accounting |  |  | 1/1/1900 12:00:00 AM | False |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | Platinum |  | Platinum |  | 7/23/2021 12:56:19 PM | 7/23/2021 1:11:19 PM | 7/22/2021 8:11:19 AM | 7/21/2021 4:56:19 PM |  | Platinum_Service Request | 0 |  | Enterprise Apps |  |  | True | Platinum, Gold, Silver, Corporate | 9389f689ed2a47e91de7954ecb8f2fe733af0ecb06 | False | False | 9454f50880a42d63b93ce142d58fbbe97de1b3d672 | Submit Incident | 9398862125defd58a8deea46fe88acc411a96e2b00 | 0 |  |  |  |  |  |  | False | False | False | 0 | 5 | 0 | False | False | False | True | False | True | New |  | 938729d99cb110f2a6c3e5488ead246422a7cd115f | 1 | Submit Incident |  | 0 | False | False | False | 0 | 0.00 | 0.00 |  | 0 |  | False | False |
>|  | 1st Level Support | 9365b4e90592c81e3b7a024555a6c0094ba77e8773 |  |  |  |  |  | 6dd53665c0c24cab86870a21cf6434ae |  |  | 0.00 | Phone |  | PeopleSoft |  |  |  |  |  |  |  |  | False |  |  |  |  |  |  | 0.00 | demisto admin | user1@mail.com | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | 7/22/2021 12:22:27 PM | 8 to 5 Monday thru Friday | Accounting | demisto admin | 9365da817530b0bfee892a48fb8815654c6071af03 |  |  | 1st Level Support | This incident was created by Cherwell test playbook | 1 |  |  |  | 0.00 | 0.00 | 102382 | Service Request |  |  |  | demisto admin | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | Byte[] Array | 7/22/2021 12:22:31 PM | False | 2nd Level Support | False | 3rd Level Support |  | 93838607346b42be7074af487d9171ea9f948b7204 ,  ,  | False |  | False |  |  |  | In Progress | ActionInfoDef ID="93d9abdb6242 | Begin Work | False |  |  |  |  |  | False | False |  | 3 | 102382 | 947571842387f6d7df118546e29cac13df2afafebc | 947571842387f6d7df118546e29cac13df2afafebc | False | False |  | Accounting |  |  | 1/1/1900 12:00:00 AM | False |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | Platinum |  | Platinum |  | 7/26/2021 12:07:27 PM | 7/26/2021 12:22:27 PM | 7/22/2021 4:22:27 PM | 7/22/2021 4:07:27 PM |  | Platinum_Service Request | 0 |  | Enterprise Apps |  |  | True | Platinum, Gold, Silver, Corporate | 9389f689ed2a47e91de7954ecb8f2fe733af0ecb06 | False | False | 9454f50880a42d63b93ce142d58fbbe97de1b3d672 | Submit Incident | 9398862125defd58a8deea46fe88acc411a96e2b00 | 0 |  |  |  |  |  |  | False | False | False | 0 | 1 | 0 | False | False | False | False | False | False | New |  | 938729d99cb110f2a6c3e5488ead246422a7cd115f | 1 | Submit Incident |  | 0 | False | False | False | 0 | 0.00 | 0.00 |  | 0 |  | False | False |
>|  | 1st Level Support | 9365b4e90592c81e3b7a024555a6c0094ba77e8773 |  |  |  |  |  | 6dd53665c0c24cab86870a21cf6434ae |  |  | 0.00 | Phone |  | PeopleSoft |  |  |  |  |  |  |  |  | False |  |  |  |  |  |  | 0.00 | demisto admin | user1@mail.com | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | 7/22/2021 12:54:18 PM | 8 to 5 Monday thru Friday | Accounting | demisto admin | 9365da817530b0bfee892a48fb8815654c6071af03 |  |  | 1st Level Support | This incident was created by Cherwell test playbook | 1 |  |  |  | 0.00 | 0.00 | 102384 | Service Request |  |  |  | demisto admin | 9365b511f78906c1fe83644c3fb33e9ec1466f7d90 | Byte[] Array | 7/22/2021 12:54:18 PM | False | 2nd Level Support | False | 3rd Level Support |  | 93838607346b42be7074af487d9171ea9f948b7204 ,  ,  | False |  | False |  |  |  | In Progress | ActionInfoDef ID="93d9abdb6242 | Begin Work | False |  |  |  |  |  | False | False |  | 3 | 102384 | 947571cec8a5b5f03850c940c2bf6ca2bf116ffce9 | 947571cec8a5b5f03850c940c2bf6ca2bf116ffce9 | False | False |  | Accounting |  |  | 1/1/1900 12:00:00 AM | False |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | 93838607346b42be7074af487d9171ea9f948b7204 |  | Platinum |  | Platinum |  | 7/26/2021 12:39:18 PM | 7/26/2021 12:54:18 PM | 7/22/2021 4:54:18 PM | 7/22/2021 4:39:18 PM |  | Platinum_Service Request | 0 |  | Enterprise Apps |  |  | True | Platinum, Gold, Silver, Corporate | 9389f689ed2a47e91de7954ecb8f2fe733af0ecb06 | False | False | 9454f50880a42d63b93ce142d58fbbe97de1b3d672 | Submit Incident | 9398862125defd58a8deea46fe88acc411a96e2b00 | 0 |  |  |  |  |  |  | False | False | False | 0 | 1 | 0 | False | False | False | False | False | False | New |  | 938729d99cb110f2a6c3e5488ead246422a7cd115f | 1 | Submit Incident |  | 0 | False | False | False | 0 | 0.00 | 0.00 |  | 0 |  | False | False |


### cherwell-get-field-info
***
Gets information for a field, by one of its properties (Name, Display Name, or id).


#### Base Command

`cherwell-get-field-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type |  Business object type, for example: "Incident". . | Required | 
| field_property | Field property to search by (Name, DIsplay Name or Field id). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.FieldInfo.DisplayName | String | Field display name \(as it displays in the Cherwell UI\). | 
| Cherwell.FieldInfo.FieldId | String | Field ID. | 
| Cherwell.FieldInfo.Name | String | The name to use when working with business object commands. | 


#### Command Example
```!cherwell-get-field-info type=incident field_property=Customer Display Name```

#### Context Example
```json
{
    "Cherwell": {
        "FieldInfo": {
            "DisplayName": "Customer Display Name",
            "FieldId": "93734aaff77b19d1fcfd1d4b4aba1b0af895f25788",
            "Name": "CustomerDisplayName"
        }
    }
}
```

#### Human Readable Output

>### Field info:
>|Display Name|Field Id|Name|
>|---|---|---|
>| Customer Display Name | 93734aaff77b19d1fcfd1d4b4aba1b0af895f25788 | CustomerDisplayName |


### cherwell-run-saved-search
***
Returns the results of a saved search.


#### Base Command

`cherwell-run-saved-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| association_id | Business object association ID for the saved search. | Required | 
| scope | Scope name or ID for the saved search. | Required | 
| scope_owner | Scope owner ID for the saved search. Use "(None)" when no scope owner exists. | Required | 
| search_name | Name of the saved search. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cherwell-get-business-object-id
***
Get a general business object id by name


#### Base Command

`cherwell-get-business-object-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| business_object_name | Business object name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.BusinessObjectInfo.BusinessObjectId | String | Business object ID. | 
| Cherwell.BusinessObjectInfo.BusinessObjectName | String | Business object name. | 


#### Command Example
```!cherwell-get-business-object-id business_object_name=incident```

#### Context Example
```json
{
    "Cherwell": {
        "BusinessObjectInfo": {
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae",
            "BusinessObjectName": "incident"
        }
    }
}
```

#### Human Readable Output

>### Business Object Info:
>|Business Object Id|Business Object Name|
>|---|---|
>| 6dd53665c0c24cab86870a21cf6434ae | incident |


### cherwell-get-business-object-summary
***
Get business object summary by name or ID.


#### Base Command

`cherwell-get-business-object-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the business object. | Optional | 
| id | The ID of the business object. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.BusinessObjectSummary.supporting | Boolean | Whether the business object is a supporting business object or not. | 
| Cherwell.BusinessObjectSummary.major | Boolean | Whether the business object is a major business object or not. | 
| Cherwell.BusinessObjectSummary.group | Boolean | Whether the business object is a group business object or not. | 
| Cherwell.BusinessObjectSummary.name | String | The name of the business object. | 
| Cherwell.BusinessObjectSummary.stateFieldId | String | The ID of the business object state field. | 
| Cherwell.BusinessObjectSummary.busObId | String | The ID of the business object. | 
| Cherwell.BusinessObjectSummary.states | String | The valid states of the business object. | 
| Cherwell.BusinessObjectSummary.lookup | Boolean | Whether the object is a lookup object or not. | 
| Cherwell.BusinessObjectSummary.displayName | String | The display name of the business object. | 
| Cherwell.BusinessObjectSummary.firstRecIdField | String | The ID value of the first business object record ID (RecID) field. | 
| Cherwell.BusinessObjectSummary.recIdFields | String | The IDs of business object record ID (RecID) fields. | 


#### Command Example
```!cherwell-get-business-object-summary name=task```

#### Context Example
```json
{
    "Cherwell": {
        "BusinessObjectSummary": {
            "busObId": "9446978f53c84aef2835904a7ab96cfc882efe030c",
            "displayName": "Task",
            "firstRecIdField": "9355d5ed41677b1e9c897e4fa9b4065d34319187f0",
            "group": true,
            "groupSummaries": [
                {
                    "busObId": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b",
                    "displayName": "Work Item",
                    "firstRecIdField": "9355d5ed41677b1e9c897e4fa9b4065d34319187f0",
                    "group": false,
                    "groupSummaries": [],
                    "lookup": false,
                    "major": false,
                    "name": "Work_Item",
                    "recIdFields": "9355d5ed41677b1e9c897e4fa9b4065d34319187f0",
                    "stateFieldId": "9368f0fb7b744108a666984c21afc932562eb7dc16",
                    "states": "New,In Progress,Closed,Acknowledged",
                    "supporting": true
                }
            ],
            "lookup": false,
            "major": false,
            "name": "Task",
            "recIdFields": "9355d5ed41677b1e9c897e4fa9b4065d34319187f0",
            "stateFieldId": "9368f0fb7b744108a666984c21afc932562eb7dc16",
            "states": "New,In Progress,Closed,Acknowledged",
            "supporting": false
        }
    }
}
```

#### Human Readable Output

>### Business Object Summary:
>|Bus Ob Id|Display Name|First Rec Id Field|Group|Group Summaries|Lookup|Major|Name|Rec Id Fields|State Field Id|States|Supporting|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 9446978f53c84aef2835904a7ab96cfc882efe030c | Task | 9355d5ed41677b1e9c897e4fa9b4065d34319187f0 | true | {'firstRecIdField': '9355d5ed41677b1e9c897e4fa9b4065d34319187f0', 'groupSummaries': [], 'recIdFields': '9355d5ed41677b1e9c897e4fa9b4065d34319187f0', 'stateFieldId': '9368f0fb7b744108a666984c21afc932562eb7dc16', 'states': 'New,In Progress,Closed,Acknowledged', 'busObId': '9355d5ed41e384ff345b014b6cb1c6e748594aea5b', 'displayName': 'Work Item', 'group': False, 'lookup': False, 'major': False, 'name': 'Work_Item', 'supporting': True} | false | false | Task | 9355d5ed41677b1e9c897e4fa9b4065d34319187f0 | 9368f0fb7b744108a666984c21afc932562eb7dc16 | New,In Progress,Closed,Acknowledged | false |


### cherwell-get-one-step-actions-for-business-object
***
Get One-Step Actions by business object ID.


#### Base Command

`cherwell-get-one-step-actions-for-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| busobjectid | The ID of the business object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cherwell.OneStepActions.BusinessObjectId | String | The ID of the business object. | 
| Cherwell.OneStepActions.Actions | Unknown | The business object actions. | 


#### Command Example
```!cherwell-get-one-step-actions-for-business-object busobjectid=6dd53665c0c24cab86870a21cf6434ae```

#### Context Example
```json
{
    "Cherwell": {
        "OneStepActions": {
            "Actions": {
                "Buttons": [
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Launches Skype to contact the Customer.",
                        "displayName": "Call Contact",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._48x48.mobilephone3.png",
                        "id": "9389e70ed88b73a6b1393948a0951e25993cff6c66",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Call Contact",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393948a0951e25993cff6c66#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Abandons the incident and opens the default dashboard",
                        "displayName": "Cancel Incident",
                        "galleryImage": "",
                        "id": "944414556cbeebd3bf521840bdad54264072e6e430",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Cancel Incident",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:944414556cbeebd3bf521840bdad54264072e6e430#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Task with a Status of In-Progress and prompts the user for a Title, Description and Time Spent.  Used primarily in iCherwell",
                        "displayName": "Create a Task with Time Spent",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.alarmclock.png",
                        "id": "93dfb3fc4f3339c24f199d4eed888d50a2da3e2908",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Crear una tarea con el tiempo dedicado",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dfb3fc4f3339c24f199d4eed888d50a2da3e2908#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Create and Send Survey",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.SubReport.ico",
                        "id": "943a2f7631f172ade8507347a5ada7b2a39daec900",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create and Send Survey",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:943a2f7631f172ade8507347a5ada7b2a39daec900#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Changes the Incident Status to Pending and creates a Change Request Record from the current Incident. Prompts User to select a reason and enter a short title for the Change, and links the Change Request to the Incident.",
                        "displayName": "Create Change from Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Editors.BusObEditor-Lifecycle.png",
                        "id": "9378b5149c22e1173219ac42a699f88b881885bc11",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create Change from Incident",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9378b5149c22e1173219ac42a699f88b881885bc11#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Problem Record from the Incident.  Adds the Problem to the Problem Management Queue.",
                        "displayName": "Create Problem from Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs.trafficlight_on.ico",
                        "id": "935ecc5e96f6f2e26994e445dd8be9fef86252399e",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Cria um problema de um incidente",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:935ecc5e96f6f2e26994e445dd8be9fef86252399e#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Change Request Record from the current Incident.",
                        "displayName": "Create Standard Change from Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Editors.BusObEditor-Lifecycle.png",
                        "id": "93e2938fd4d656b25516ba41b986365596101e39a5",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create Standard Change from Incident",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93e2938fd4d656b25516ba41b986365596101e39a5#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Conditional expression One-Step that shows a Configuration Map",
                        "displayName": "Impacted CI's Button Actions",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Editors.WidgetEditor_ScatterChart.png",
                        "id": "93dfe7325dd236465ec873418e97ca948f738974a0",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Impacted CIs Button Actions",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dfe7325dd236465ec873418e97ca948f738974a0#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a new Knowledge Article (KA) populated with the Categorization,  Description and Solution/Workaround from the Incident.",
                        "displayName": "Nominate for KB",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.Knowledge.KnowledgeViewCurrent.png",
                        "id": "9365abfe787a1bce3282c446a9ae9914204703a7fe",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Nominate for KB",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9365abfe787a1bce3282c446a9ae9914204703a7fe#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Task time tracking entry and prompts the User for time spent and task completion details. Sets the Task Close Code to Completed.",
                        "displayName": "Track Task Time Against Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.alarmclock.png",
                        "id": "93d4ee5220e714428a9a4f4189a329409e69e48056",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Marcar tempo da tarefa contra o incidente",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93d4ee5220e714428a9a4f4189a329409e69e48056#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    }
                ],
                "Config Item Tasks": [
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Pings the Primary CI (specified on the Incident Form) using the IP Address provided in the CI details.",
                        "displayName": "Ping System",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs.workstation_network.ico",
                        "id": "9379e37ed996514927afa143658d9d46c06b3f1558",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Ping System",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9379e37ed996514927afa143658d9d46c06b3f1558#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Launches Remote Desktop Connection (MSTSC.exe) to the selected CI.  Assumes the current User has rights to use remote desktop and remote connections are configured on the target CI.",
                        "displayName": "RDP to Primary CI",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._48x48.workstation_network.png",
                        "id": "939850e292d4b54454e9d8471db023c97db04ec279",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "RDP to Primary CI",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:939850e292d4b54454e9d8471db023c97db04ec279#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Reboots the Primary CI (specified on the Incident Form), and then updates the Close Description field to track that the CI was rebooted.",
                        "displayName": "Reboot Computer",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.Views.workplace2.png",
                        "id": "936592312d5676ab8accd94673a45ceaa41777e31e",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Reboot Computer",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:936592312d5676ab8accd94673a45ceaa41777e31e#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Sets password for selected User or Customer to \"ChangeMe,\" and sets account to active if locked out. Updates Incident Form to indicate that password was reset and changes Status to Resolved.",
                        "displayName": "Reset Password",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs.workstation_network.ico",
                        "id": "935467d76aacbb0fe7317345f58cc75e38c6640e38",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Reset Password",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:935467d76aacbb0fe7317345f58cc75e38c6640e38#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    }
                ],
                "Global": [
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Launches Remote Desktop Connection (MSTSC.exe) to the selected CI.  Assumes the current User has rights to use remote desktop and remote connections are configured on the target CI.",
                        "displayName": "RDP to Primary CI",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._48x48.workstation_network.png",
                        "id": "939850e292d4b54454e9d8471db023c97db04ec279",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "RDP to Primary CI",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:939850e292d4b54454e9d8471db023c97db04ec279#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Pings the Primary CI (specified on the Incident Form) using the IP Address provided in the CI details.",
                        "displayName": "Ping System",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs.workstation_network.ico",
                        "id": "9379e37ed996514927afa143658d9d46c06b3f1558",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Ping System",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9379e37ed996514927afa143658d9d46c06b3f1558#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Reboots the Primary CI (specified on the Incident Form), and then updates the Close Description field to track that the CI was rebooted.",
                        "displayName": "Reboot Computer",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.Views.workplace2.png",
                        "id": "936592312d5676ab8accd94673a45ceaa41777e31e",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Reboot Computer",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:936592312d5676ab8accd94673a45ceaa41777e31e#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Clones information from the current Incident into a new Incident Record. Populates the Description, Call Source, Categorization, and Priority fields with information from the cloned record.",
                        "displayName": "Clone Current Incident",
                        "galleryImage": "",
                        "id": "9389f945cc0784caad651a491db626b6baf78bb19c",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Clone Current Incident",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9389f945cc0784caad651a491db626b6baf78bb19c#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Displays a popup message if the individual selected as the Incident Owner is out of the office (as defined in the UserInfo Time-off dates).",
                        "displayName": "Not Available",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.about.png",
                        "id": "93b2c31172b273237c7311487b9c6eace6fcdef071",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Not Available",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93b2c31172b273237c7311487b9c6eace6fcdef071#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Launches Skype to contact the Customer.",
                        "displayName": "Call Contact",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._48x48.mobilephone3.png",
                        "id": "9389e70ed88b73a6b1393948a0951e25993cff6c66",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Call Contact",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393948a0951e25993cff6c66#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Changes the Incident Status to Pending and creates a Change Request Record from the current Incident. Prompts User to select a reason and enter a short title for the Change, and links the Change Request to the Incident.",
                        "displayName": "Create Change from Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Editors.BusObEditor-Lifecycle.png",
                        "id": "9378b5149c22e1173219ac42a699f88b881885bc11",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create Change from Incident",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9378b5149c22e1173219ac42a699f88b881885bc11#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates and sends an e-mail to a Customer that her request for a new employee computer is denied. Attaches the e-mail to the Incident History Record.",
                        "displayName": "New Employee Request Denied",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.mail2.png",
                        "id": "93d5744310efa377c99eac4cd6a029e203095cfdf6",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "New Employee Request Denied",
                        "parentFolder": "9386dfe9a8b61715d6adac4b2eaf97ea07f8c59026",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93d5744310efa377c99eac4cd6a029e203095cfdf6#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Create a new Journal - Note entry for Incident.  Used primarily in iCherwell.",
                        "displayName": "Create a Journal Note Entry for Incident",
                        "galleryImage": "",
                        "id": "93dfb39503a41fb67670734ef495fd0c34216726de",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create a Journal Note Entry for Incident",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dfb39503a41fb67670734ef495fd0c34216726de#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Task with a Status of In-Progress and prompts the user for a Title, Description and Time Spent.  Used primarily in iCherwell",
                        "displayName": "Create a Task with Time Spent",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.alarmclock.png",
                        "id": "93dfb3fc4f3339c24f199d4eed888d50a2da3e2908",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Crear una tarea con el tiempo dedicado",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dfb3fc4f3339c24f199d4eed888d50a2da3e2908#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates Tasks for new employee items and adds request to New Request Queue.",
                        "displayName": "New Employee Tasks",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People.woman1.ico",
                        "id": "93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "New Employee Tasks",
                        "parentFolder": "9386dfe9a8b61715d6adac4b2eaf97ea07f8c59026",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Change Request Record from the current Incident.",
                        "displayName": "Create Standard Change from Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Editors.BusObEditor-Lifecycle.png",
                        "id": "93e2938fd4d656b25516ba41b986365596101e39a5",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create Standard Change from Incident",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93e2938fd4d656b25516ba41b986365596101e39a5#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Changes the Incident Status from Resolved to Reopened, and clears the resolution fields that are used with the Email Monitor. Sets the Resolved Time in minutes and the Total STC Time in minutes to restart the SLA Clock.",
                        "displayName": "Reopen Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.Unlock32.png",
                        "id": "93c28182ecc977b3dab73446549d977a008cd84ad2",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Reopen Incident",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93c28182ecc977b3dab73446549d977a008cd84ad2#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Sets password for selected User or Customer to \"ChangeMe,\" and sets account to active if locked out. Updates Incident Form to indicate that password was reset and changes Status to Resolved.",
                        "displayName": "Reset Password",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs.workstation_network.ico",
                        "id": "935467d76aacbb0fe7317345f58cc75e38c6640e38",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Reset Password",
                        "parentFolder": "9386dfed35b006a71b4e6c42d2b6b2fe8c0a16fea5",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:935467d76aacbb0fe7317345f58cc75e38c6640e38#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Task time tracking entry and prompts the User for time spent and task completion details. Sets the Task Close Code to Completed.",
                        "displayName": "Track Task Time Against Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.alarmclock.png",
                        "id": "93d4ee5220e714428a9a4f4189a329409e69e48056",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Marcar tempo da tarefa contra o incidente",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93d4ee5220e714428a9a4f4189a329409e69e48056#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Sets the Incident Status to Resolved.  Used for Mobile Apps.",
                        "displayName": "Set Incident Status to Resolved",
                        "galleryImage": "",
                        "id": "93dcaa69fd0dee94e4f1f24cb6b86395bfb5cdbe77",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Set Incident Status to Resolved",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dcaa69fd0dee94e4f1f24cb6b86395bfb5cdbe77#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Conditional expression One-Step that shows a Configuration Map",
                        "displayName": "Impacted CI's Button Actions",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Editors.WidgetEditor_ScatterChart.png",
                        "id": "93dfe7325dd236465ec873418e97ca948f738974a0",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Impacted CIs Button Actions",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dfe7325dd236465ec873418e97ca948f738974a0#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Closes an Incident Record as a duplicate of another Incident. Prompts the User to enter the number (RecID) of the Incident that it duplicates.",
                        "displayName": "Close as Duplicate",
                        "galleryImage": "",
                        "id": "938737bddabf85fd0c881a4c26b93982d9411e91ef",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Close as Duplicate",
                        "parentFolder": "9386dfe936b88eacef32394c0c8a148924c6a10eca",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:938737bddabf85fd0c881a4c26b93982d9411e91ef#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Close Request",
                        "galleryImage": "",
                        "id": "93c281891b5c3819fe72934f6da3ca31efa03f7023",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Close Request",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93c281891b5c3819fe72934f6da3ca31efa03f7023#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Sets the Incident Priority to 1.  Used for iCherwell and Android Mobile Apps.",
                        "displayName": "Set Incident to Priority One",
                        "galleryImage": "",
                        "id": "93dcaa73f25bd4c232c8b94ca1b29a0a63b5d4ee4b",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Set Incident to Priority One",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dcaa73f25bd4c232c8b94ca1b29a0a63b5d4ee4b#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a new Knowledge Article (KA) populated with the Categorization,  Description and Solution/Workaround from the Incident.",
                        "displayName": "Nominate for KB",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.Knowledge.KnowledgeViewCurrent.png",
                        "id": "9365abfe787a1bce3282c446a9ae9914204703a7fe",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Nominate for KB",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9365abfe787a1bce3282c446a9ae9914204703a7fe#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a follow-up e-mail to send the Customer regarding a question or update about the Incident. Allows the User to edit the e-mail before clicking Send. Attaches the e-mail to the Incident History Record.",
                        "displayName": "Follow-up E-mail",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.mail2.png",
                        "id": "9344807867705870519cd54caf852e8600e42ed537",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "FollowUp EMail",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9344807867705870519cd54caf852e8600e42ed537#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "When 3 days lapse from the last modified date time, sends a reminder e-mail to the Incident Owner to follow up with the Customer.",
                        "displayName": "SLA Escalate if not Touched in 3 Days",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.mail2.png",
                        "id": "93a606bfdcaf4fa68bf8284a7d8e195bae5e851992",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "SLA Escalate if not Touched in 3 Days",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93a606bfdcaf4fa68bf8284a7d8e195bae5e851992#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Makes the current user the owner of the Incident. \nChanges the Incident status from new to assigned.",
                        "displayName": "Take Ownership",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People._48x48.user2.png",
                        "id": "93d50acaac30f5fe73aef345cf923763d34f756c0c",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Take Ownership",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93d50acaac30f5fe73aef345cf923763d34f756c0c#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Escalate to Level 3",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People.users2.ico",
                        "id": "940794577aeb1e8265242c452eb83401abcefda781",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Escalate to Level 3",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:940794577aeb1e8265242c452eb83401abcefda781#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Escalation Complete",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People.users3.ico",
                        "id": "940794cdb072fb6649a9fc49b8b3ce3f77760c9964",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Escalation Complete",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:940794cdb072fb6649a9fc49b8b3ce3f77760c9964#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates escalation task to predefined level 2 and level 3 teams based on data in Incident Subcategory table.",
                        "displayName": "Escalation to Level 2 and 3",
                        "galleryImage": "",
                        "id": "93f72f43c5c4979d75c5f547e795400ef411cb8a6b",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Invite pour le d\u00e9tails de la transmission au troisi\u00e8me",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93f72f43c5c4979d75c5f547e795400ef411cb8a6b#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates a Problem Record from the Incident.  Adds the Problem to the Problem Management Queue.",
                        "displayName": "Create Problem from Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs.trafficlight_on.ico",
                        "id": "935ecc5e96f6f2e26994e445dd8be9fef86252399e",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Cria um problema de um incidente",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:935ecc5e96f6f2e26994e445dd8be9fef86252399e#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Create Incident",
                        "galleryImage": "",
                        "id": "93dbbd9b58b12daa093a9944d8a356e57cefd7d277",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Crear incidencia",
                        "parentFolder": "9386dfe936b88eacef32394c0c8a148924c6a10eca",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dbbd9b58b12daa093a9944d8a356e57cefd7d277#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Filter SCTs",
                        "galleryImage": "",
                        "id": "9411e83cb4677257b43dd24021aae88c85a3213805",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Filtrar SCTs",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9411e83cb4677257b43dd24021aae88c85a3213805#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Converts an Incident into a Major Incident",
                        "displayName": "Convert into Major Incident",
                        "galleryImage": "",
                        "id": "94434b2049907a382f535b4004a442ebae3c1af753",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Convert into Major Incident",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:94434b2049907a382f535b4004a442ebae3c1af753#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Abandons the incident and opens the default dashboard",
                        "displayName": "Cancel Incident",
                        "galleryImage": "",
                        "id": "944414556cbeebd3bf521840bdad54264072e6e430",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Cancel Incident",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:944414556cbeebd3bf521840bdad54264072e6e430#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Opens the current record",
                        "displayName": "Go to Record",
                        "galleryImage": "",
                        "id": "9445b97b516056a1278bb1483bb5c7f93e08e4635a",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Go to Record",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9445b97b516056a1278bb1483bb5c7f93e08e4635a#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Requester Follow Up Email",
                        "galleryImage": "",
                        "id": "9450a0600c044e15f723d349958b5dec22924863e8",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Requester Follow Up Email",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9450a0600c044e15f723d349958b5dec22924863e8#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates an e-mail to the Customer that her Incident was resolved. Allows the User to edit the e-mail before clicking Send. Attaches the e-mail to the Incident History Record.",
                        "displayName": "Resolved Confirmation",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.mail2.png",
                        "id": "9454250878f3b7ff56de064ca781b2787105c8e667",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Confirma\u00e7\u00e3o de resolu\u00e7\u00e3o",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9454250878f3b7ff56de064ca781b2787105c8e667#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Recommended Assignee",
                        "galleryImage": "",
                        "id": "9454e641d3819fbf16c6394037af3814de18670bf8",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Recommended Assignee",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9454e641d3819fbf16c6394037af3814de18670bf8#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Create and Send Survey",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.SubReport.ico",
                        "id": "943a2f7631f172ade8507347a5ada7b2a39daec900",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Create and Send Survey",
                        "parentFolder": "9386dfe7e0a85ff749cfe74aea867ee52ee2cd1cf1",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:943a2f7631f172ade8507347a5ada7b2a39daec900#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Sample Onestep Called from API",
                        "galleryImage": "",
                        "id": "947509fc528a451570e6c14223a9a8ca12b0856fc2",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Sample Onestep Called from API",
                        "parentFolder": "",
                        "parentIsScopeFolder": true,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:947509fc528a451570e6c14223a9a8ca12b0856fc2#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    }
                ],
                "Record Templates": [
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Closes an Incident Record as a duplicate of another Incident. Prompts the User to enter the number (RecID) of the Incident that it duplicates.",
                        "displayName": "Close as Duplicate",
                        "galleryImage": "",
                        "id": "938737bddabf85fd0c881a4c26b93982d9411e91ef",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Close as Duplicate",
                        "parentFolder": "9386dfe936b88eacef32394c0c8a148924c6a10eca",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:938737bddabf85fd0c881a4c26b93982d9411e91ef#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Create Incident",
                        "galleryImage": "",
                        "id": "93dbbd9b58b12daa093a9944d8a356e57cefd7d277",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Crear incidencia",
                        "parentFolder": "9386dfe936b88eacef32394c0c8a148924c6a10eca",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93dbbd9b58b12daa093a9944d8a356e57cefd7d277#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    }
                ],
                "Service Request Models": [
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates and sends an e-mail to a Customer that her request for a new employee computer is denied. Attaches the e-mail to the Incident History Record.",
                        "displayName": "New Employee Request Denied",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.mail2.png",
                        "id": "93d5744310efa377c99eac4cd6a029e203095cfdf6",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "New Employee Request Denied",
                        "parentFolder": "9386dfe9a8b61715d6adac4b2eaf97ea07f8c59026",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93d5744310efa377c99eac4cd6a029e203095cfdf6#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates Tasks for new employee items and adds request to New Request Queue.",
                        "displayName": "New Employee Tasks",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People.woman1.ico",
                        "id": "93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "New Employee Tasks",
                        "parentFolder": "9386dfe9a8b61715d6adac4b2eaf97ea07f8c59026",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    }
                ],
                "Workflow Actions": [
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Escalate to Level 3",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People.users2.ico",
                        "id": "940794577aeb1e8265242c452eb83401abcefda781",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Escalate to Level 3",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:940794577aeb1e8265242c452eb83401abcefda781#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "",
                        "displayName": "Escalation Complete",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People.users3.ico",
                        "id": "940794cdb072fb6649a9fc49b8b3ce3f77760c9964",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Escalation Complete",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:940794cdb072fb6649a9fc49b8b3ce3f77760c9964#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Creates escalation task to predefined level 2 and level 3 teams based on data in Incident Subcategory table.",
                        "displayName": "Escalation to Level 2 and 3",
                        "galleryImage": "",
                        "id": "93f72f43c5c4979d75c5f547e795400ef411cb8a6b",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Invite pour le d\u00e9tails de la transmission au troisi\u00e8me",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93f72f43c5c4979d75c5f547e795400ef411cb8a6b#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Changes the Incident Status from Resolved to Reopened, and clears the resolution fields that are used with the Email Monitor. Sets the Resolved Time in minutes and the Total STC Time in minutes to restart the SLA Clock.",
                        "displayName": "Reopen Incident",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Common.Unlock32.png",
                        "id": "93c28182ecc977b3dab73446549d977a008cd84ad2",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Reopen Incident",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93c28182ecc977b3dab73446549d977a008cd84ad2#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "When 3 days lapse from the last modified date time, sends a reminder e-mail to the Incident Owner to follow up with the Customer.",
                        "displayName": "SLA Escalate if not Touched in 3 Days",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.BusObs._32x32.mail2.png",
                        "id": "93a606bfdcaf4fa68bf8284a7d8e195bae5e851992",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "SLA Escalate if not Touched in 3 Days",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93a606bfdcaf4fa68bf8284a7d8e195bae5e851992#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    },
                    {
                        "association": "6dd53665c0c24cab86870a21cf6434ae",
                        "description": "Makes the current user the owner of the Incident. \nChanges the Incident status from new to assigned.",
                        "displayName": "Take Ownership",
                        "galleryImage": "[PlugIn]Images;Trebuchet.PlugIn.Images.Images.Public.People._48x48.user2.png",
                        "id": "93d50acaac30f5fe73aef345cf923763d34f756c0c",
                        "links": [],
                        "localizedScopeName": "Global",
                        "name": "Take Ownership",
                        "parentFolder": "93a78f732e67cfbcf4df6c4276a48c2bb32443dfa7",
                        "parentIsScopeFolder": false,
                        "scope": "Global",
                        "scopeOwner": "(None)",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:93d50acaac30f5fe73aef345cf923763d34f756c0c#Owner:6dd53665c0c24cab86870a21cf6434ae"
                    }
                ]
            },
            "BusinessObjectId": "6dd53665c0c24cab86870a21cf6434ae"
        }
    }
}
```

#### Human Readable Output

>### Global one-step actions:
>|Name|Display Name|Description|Id|Association|Stand In Key|
>|---|---|---|---|---|---|
>| RDP to Primary CI | RDP to Primary CI | Launches Remote Desktop Connection (MSTSC.exe) to the selected CI.  Assumes the current User has rights to use remote desktop and remote connections are configured on the target CI. | 939850e292d4b54454e9d8471db023c97db04ec279 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:939850e292d4b54454e9d8471db023c97db04ec279#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Ping System | Ping System | Pings the Primary CI (specified on the Incident Form) using the IP Address provided in the CI details. | 9379e37ed996514927afa143658d9d46c06b3f1558 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9379e37ed996514927afa143658d9d46c06b3f1558#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Reboot Computer | Reboot Computer | Reboots the Primary CI (specified on the Incident Form), and then updates the Close Description field to track that the CI was rebooted. | 936592312d5676ab8accd94673a45ceaa41777e31e | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:936592312d5676ab8accd94673a45ceaa41777e31e#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Clone Current Incident | Clone Current Incident | Clones information from the current Incident into a new Incident Record. Populates the Description, Call Source, Categorization, and Priority fields with information from the cloned record. | 9389f945cc0784caad651a491db626b6baf78bb19c | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9389f945cc0784caad651a491db626b6baf78bb19c#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Not Available | Not Available | Displays a popup message if the individual selected as the Incident Owner is out of the office (as defined in the UserInfo Time-off dates). | 93b2c31172b273237c7311487b9c6eace6fcdef071 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93b2c31172b273237c7311487b9c6eace6fcdef071#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Call Contact | Call Contact | Launches Skype to contact the Customer. | 9389e70ed88b73a6b1393948a0951e25993cff6c66 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393948a0951e25993cff6c66#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create Change from Incident | Create Change from Incident | Changes the Incident Status to Pending and creates a Change Request Record from the current Incident. Prompts User to select a reason and enter a short title for the Change, and links the Change Request to the Incident. | 9378b5149c22e1173219ac42a699f88b881885bc11 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9378b5149c22e1173219ac42a699f88b881885bc11#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| New Employee Request Denied | New Employee Request Denied | Creates and sends an e-mail to a Customer that her request for a new employee computer is denied. Attaches the e-mail to the Incident History Record. | 93d5744310efa377c99eac4cd6a029e203095cfdf6 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93d5744310efa377c99eac4cd6a029e203095cfdf6#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create a Journal Note Entry for Incident | Create a Journal Note Entry for Incident | Create a new Journal - Note entry for Incident.  Used primarily in iCherwell. | 93dfb39503a41fb67670734ef495fd0c34216726de | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dfb39503a41fb67670734ef495fd0c34216726de#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Crear una tarea con el tiempo dedicado | Create a Task with Time Spent | Creates a Task with a Status of In-Progress and prompts the user for a Title, Description and Time Spent.  Used primarily in iCherwell | 93dfb3fc4f3339c24f199d4eed888d50a2da3e2908 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dfb3fc4f3339c24f199d4eed888d50a2da3e2908#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| New Employee Tasks | New Employee Tasks | Creates Tasks for new employee items and adds request to New Request Queue. | 93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create Standard Change from Incident | Create Standard Change from Incident | Creates a Change Request Record from the current Incident. | 93e2938fd4d656b25516ba41b986365596101e39a5 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93e2938fd4d656b25516ba41b986365596101e39a5#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Reopen Incident | Reopen Incident | Changes the Incident Status from Resolved to Reopened, and clears the resolution fields that are used with the Email Monitor. Sets the Resolved Time in minutes and the Total STC Time in minutes to restart the SLA Clock. | 93c28182ecc977b3dab73446549d977a008cd84ad2 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93c28182ecc977b3dab73446549d977a008cd84ad2#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Reset Password | Reset Password | Sets password for selected User or Customer to "ChangeMe," and sets account to active if locked out. Updates Incident Form to indicate that password was reset and changes Status to Resolved. | 935467d76aacbb0fe7317345f58cc75e38c6640e38 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:935467d76aacbb0fe7317345f58cc75e38c6640e38#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Marcar tempo da tarefa contra o incidente | Track Task Time Against Incident | Creates a Task time tracking entry and prompts the User for time spent and task completion details. Sets the Task Close Code to Completed. | 93d4ee5220e714428a9a4f4189a329409e69e48056 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93d4ee5220e714428a9a4f4189a329409e69e48056#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Set Incident Status to Resolved | Set Incident Status to Resolved | Sets the Incident Status to Resolved.  Used for Mobile Apps. | 93dcaa69fd0dee94e4f1f24cb6b86395bfb5cdbe77 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dcaa69fd0dee94e4f1f24cb6b86395bfb5cdbe77#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Impacted CIs Button Actions | Impacted CI's Button Actions | Conditional expression One-Step that shows a Configuration Map | 93dfe7325dd236465ec873418e97ca948f738974a0 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dfe7325dd236465ec873418e97ca948f738974a0#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Close as Duplicate | Close as Duplicate | Closes an Incident Record as a duplicate of another Incident. Prompts the User to enter the number (RecID) of the Incident that it duplicates. | 938737bddabf85fd0c881a4c26b93982d9411e91ef | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:938737bddabf85fd0c881a4c26b93982d9411e91ef#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Close Request | Close Request |  | 93c281891b5c3819fe72934f6da3ca31efa03f7023 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93c281891b5c3819fe72934f6da3ca31efa03f7023#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Set Incident to Priority One | Set Incident to Priority One | Sets the Incident Priority to 1.  Used for iCherwell and Android Mobile Apps. | 93dcaa73f25bd4c232c8b94ca1b29a0a63b5d4ee4b | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dcaa73f25bd4c232c8b94ca1b29a0a63b5d4ee4b#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Nominate for KB | Nominate for KB | Creates a new Knowledge Article (KA) populated with the Categorization,  Description and Solution/Workaround from the Incident. | 9365abfe787a1bce3282c446a9ae9914204703a7fe | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9365abfe787a1bce3282c446a9ae9914204703a7fe#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| FollowUp EMail | Follow-up E-mail | Creates a follow-up e-mail to send the Customer regarding a question or update about the Incident. Allows the User to edit the e-mail before clicking Send. Attaches the e-mail to the Incident History Record. | 9344807867705870519cd54caf852e8600e42ed537 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9344807867705870519cd54caf852e8600e42ed537#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| SLA Escalate if not Touched in 3 Days | SLA Escalate if not Touched in 3 Days | When 3 days lapse from the last modified date time, sends a reminder e-mail to the Incident Owner to follow up with the Customer. | 93a606bfdcaf4fa68bf8284a7d8e195bae5e851992 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93a606bfdcaf4fa68bf8284a7d8e195bae5e851992#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Take Ownership | Take Ownership | Makes the current user the owner of the Incident. <br/>Changes the Incident status from new to assigned. | 93d50acaac30f5fe73aef345cf923763d34f756c0c | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93d50acaac30f5fe73aef345cf923763d34f756c0c#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Escalate to Level 3 | Escalate to Level 3 |  | 940794577aeb1e8265242c452eb83401abcefda781 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:940794577aeb1e8265242c452eb83401abcefda781#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Escalation Complete | Escalation Complete |  | 940794cdb072fb6649a9fc49b8b3ce3f77760c9964 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:940794cdb072fb6649a9fc49b8b3ce3f77760c9964#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Invite pour le détails de la transmission au troisième | Escalation to Level 2 and 3 | Creates escalation task to predefined level 2 and level 3 teams based on data in Incident Subcategory table. | 93f72f43c5c4979d75c5f547e795400ef411cb8a6b | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93f72f43c5c4979d75c5f547e795400ef411cb8a6b#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Cria um problema de um incidente | Create Problem from Incident | Creates a Problem Record from the Incident.  Adds the Problem to the Problem Management Queue. | 935ecc5e96f6f2e26994e445dd8be9fef86252399e | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:935ecc5e96f6f2e26994e445dd8be9fef86252399e#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Crear incidencia | Create Incident |  | 93dbbd9b58b12daa093a9944d8a356e57cefd7d277 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dbbd9b58b12daa093a9944d8a356e57cefd7d277#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Filtrar SCTs | Filter SCTs |  | 9411e83cb4677257b43dd24021aae88c85a3213805 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9411e83cb4677257b43dd24021aae88c85a3213805#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Convert into Major Incident | Convert into Major Incident | Converts an Incident into a Major Incident | 94434b2049907a382f535b4004a442ebae3c1af753 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:94434b2049907a382f535b4004a442ebae3c1af753#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Cancel Incident | Cancel Incident | Abandons the incident and opens the default dashboard | 944414556cbeebd3bf521840bdad54264072e6e430 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:944414556cbeebd3bf521840bdad54264072e6e430#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Go to Record | Go to Record | Opens the current record | 9445b97b516056a1278bb1483bb5c7f93e08e4635a | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9445b97b516056a1278bb1483bb5c7f93e08e4635a#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Requester Follow Up Email | Requester Follow Up Email |  | 9450a0600c044e15f723d349958b5dec22924863e8 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9450a0600c044e15f723d349958b5dec22924863e8#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Confirmação de resolução | Resolved Confirmation | Creates an e-mail to the Customer that her Incident was resolved. Allows the User to edit the e-mail before clicking Send. Attaches the e-mail to the Incident History Record. | 9454250878f3b7ff56de064ca781b2787105c8e667 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9454250878f3b7ff56de064ca781b2787105c8e667#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Recommended Assignee | Recommended Assignee |  | 9454e641d3819fbf16c6394037af3814de18670bf8 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9454e641d3819fbf16c6394037af3814de18670bf8#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create and Send Survey | Create and Send Survey |  | 943a2f7631f172ade8507347a5ada7b2a39daec900 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:943a2f7631f172ade8507347a5ada7b2a39daec900#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Sample Onestep Called from API | Sample Onestep Called from API |  | 947509fc528a451570e6c14223a9a8ca12b0856fc2 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:947509fc528a451570e6c14223a9a8ca12b0856fc2#Owner:6dd53665c0c24cab86870a21cf6434ae |
>### Buttons one-step actions:
>|Name|Display Name|Description|Id|Association|Stand In Key|
>|---|---|---|---|---|---|
>| Call Contact | Call Contact | Launches Skype to contact the Customer. | 9389e70ed88b73a6b1393948a0951e25993cff6c66 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393948a0951e25993cff6c66#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Cancel Incident | Cancel Incident | Abandons the incident and opens the default dashboard | 944414556cbeebd3bf521840bdad54264072e6e430 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:944414556cbeebd3bf521840bdad54264072e6e430#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Crear una tarea con el tiempo dedicado | Create a Task with Time Spent | Creates a Task with a Status of In-Progress and prompts the user for a Title, Description and Time Spent.  Used primarily in iCherwell | 93dfb3fc4f3339c24f199d4eed888d50a2da3e2908 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dfb3fc4f3339c24f199d4eed888d50a2da3e2908#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create and Send Survey | Create and Send Survey |  | 943a2f7631f172ade8507347a5ada7b2a39daec900 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:943a2f7631f172ade8507347a5ada7b2a39daec900#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create Change from Incident | Create Change from Incident | Changes the Incident Status to Pending and creates a Change Request Record from the current Incident. Prompts User to select a reason and enter a short title for the Change, and links the Change Request to the Incident. | 9378b5149c22e1173219ac42a699f88b881885bc11 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9378b5149c22e1173219ac42a699f88b881885bc11#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Cria um problema de um incidente | Create Problem from Incident | Creates a Problem Record from the Incident.  Adds the Problem to the Problem Management Queue. | 935ecc5e96f6f2e26994e445dd8be9fef86252399e | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:935ecc5e96f6f2e26994e445dd8be9fef86252399e#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Create Standard Change from Incident | Create Standard Change from Incident | Creates a Change Request Record from the current Incident. | 93e2938fd4d656b25516ba41b986365596101e39a5 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93e2938fd4d656b25516ba41b986365596101e39a5#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Impacted CIs Button Actions | Impacted CI's Button Actions | Conditional expression One-Step that shows a Configuration Map | 93dfe7325dd236465ec873418e97ca948f738974a0 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dfe7325dd236465ec873418e97ca948f738974a0#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Nominate for KB | Nominate for KB | Creates a new Knowledge Article (KA) populated with the Categorization,  Description and Solution/Workaround from the Incident. | 9365abfe787a1bce3282c446a9ae9914204703a7fe | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9365abfe787a1bce3282c446a9ae9914204703a7fe#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Marcar tempo da tarefa contra o incidente | Track Task Time Against Incident | Creates a Task time tracking entry and prompts the User for time spent and task completion details. Sets the Task Close Code to Completed. | 93d4ee5220e714428a9a4f4189a329409e69e48056 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93d4ee5220e714428a9a4f4189a329409e69e48056#Owner:6dd53665c0c24cab86870a21cf6434ae |
>### Config Item Tasks one-step actions:
>|Name|Display Name|Description|Id|Association|Stand In Key|
>|---|---|---|---|---|---|
>| Ping System | Ping System | Pings the Primary CI (specified on the Incident Form) using the IP Address provided in the CI details. | 9379e37ed996514927afa143658d9d46c06b3f1558 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:9379e37ed996514927afa143658d9d46c06b3f1558#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| RDP to Primary CI | RDP to Primary CI | Launches Remote Desktop Connection (MSTSC.exe) to the selected CI.  Assumes the current User has rights to use remote desktop and remote connections are configured on the target CI. | 939850e292d4b54454e9d8471db023c97db04ec279 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:939850e292d4b54454e9d8471db023c97db04ec279#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Reboot Computer | Reboot Computer | Reboots the Primary CI (specified on the Incident Form), and then updates the Close Description field to track that the CI was rebooted. | 936592312d5676ab8accd94673a45ceaa41777e31e | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:936592312d5676ab8accd94673a45ceaa41777e31e#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Reset Password | Reset Password | Sets password for selected User or Customer to "ChangeMe," and sets account to active if locked out. Updates Incident Form to indicate that password was reset and changes Status to Resolved. | 935467d76aacbb0fe7317345f58cc75e38c6640e38 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:935467d76aacbb0fe7317345f58cc75e38c6640e38#Owner:6dd53665c0c24cab86870a21cf6434ae |
>### Record Templates one-step actions:
>|Name|Display Name|Description|Id|Association|Stand In Key|
>|---|---|---|---|---|---|
>| Close as Duplicate | Close as Duplicate | Closes an Incident Record as a duplicate of another Incident. Prompts the User to enter the number (RecID) of the Incident that it duplicates. | 938737bddabf85fd0c881a4c26b93982d9411e91ef | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:938737bddabf85fd0c881a4c26b93982d9411e91ef#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Crear incidencia | Create Incident |  | 93dbbd9b58b12daa093a9944d8a356e57cefd7d277 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93dbbd9b58b12daa093a9944d8a356e57cefd7d277#Owner:6dd53665c0c24cab86870a21cf6434ae |
>### Service Request Models one-step actions:
>|Name|Display Name|Description|Id|Association|Stand In Key|
>|---|---|---|---|---|---|
>| New Employee Request Denied | New Employee Request Denied | Creates and sends an e-mail to a Customer that her request for a new employee computer is denied. Attaches the e-mail to the Incident History Record. | 93d5744310efa377c99eac4cd6a029e203095cfdf6 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93d5744310efa377c99eac4cd6a029e203095cfdf6#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| New Employee Tasks | New Employee Tasks | Creates Tasks for new employee items and adds request to New Request Queue. | 93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93b51a73bd4eabbc7d81614d06ab3de5fd9ad4756b#Owner:6dd53665c0c24cab86870a21cf6434ae |
>### Workflow Actions one-step actions:
>|Name|Display Name|Description|Id|Association|Stand In Key|
>|---|---|---|---|---|---|
>| Escalate to Level 3 | Escalate to Level 3 |  | 940794577aeb1e8265242c452eb83401abcefda781 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:940794577aeb1e8265242c452eb83401abcefda781#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Escalation Complete | Escalation Complete |  | 940794cdb072fb6649a9fc49b8b3ce3f77760c9964 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:940794cdb072fb6649a9fc49b8b3ce3f77760c9964#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Invite pour le détails de la transmission au troisième | Escalation to Level 2 and 3 | Creates escalation task to predefined level 2 and level 3 teams based on data in Incident Subcategory table. | 93f72f43c5c4979d75c5f547e795400ef411cb8a6b | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93f72f43c5c4979d75c5f547e795400ef411cb8a6b#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Reopen Incident | Reopen Incident | Changes the Incident Status from Resolved to Reopened, and clears the resolution fields that are used with the Email Monitor. Sets the Resolved Time in minutes and the Total STC Time in minutes to restart the SLA Clock. | 93c28182ecc977b3dab73446549d977a008cd84ad2 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93c28182ecc977b3dab73446549d977a008cd84ad2#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| SLA Escalate if not Touched in 3 Days | SLA Escalate if not Touched in 3 Days | When 3 days lapse from the last modified date time, sends a reminder e-mail to the Incident Owner to follow up with the Customer. | 93a606bfdcaf4fa68bf8284a7d8e195bae5e851992 | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93a606bfdcaf4fa68bf8284a7d8e195bae5e851992#Owner:6dd53665c0c24cab86870a21cf6434ae |
>| Take Ownership | Take Ownership | Makes the current user the owner of the Incident. <br/>Changes the Incident status from new to assigned. | 93d50acaac30f5fe73aef345cf923763d34f756c0c | 6dd53665c0c24cab86870a21cf6434ae | DefType:OneStepDef#Scope:Global#Id:93d50acaac30f5fe73aef345cf923763d34f756c0c#Owner:6dd53665c0c24cab86870a21cf6434ae |


### cherwell-run-one-step-action-on-business-object
***
Run a One-Step Action using a OneStepActionRequest. This request is used to start a One-Step Action run with additional information, such as prompt values.


#### Base Command

`cherwell-run-one-step-action-on-business-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| busobjectid | The ID of the business object. | Required | 
| busobrecid | The ID of the business object record. | Required | 
| oneStepAction_StandInKey | The key to find the One-Step Action to run. You can get it using the command cherwell-get-one-step-actions-for-business-object. | Required | 
| prompt_values | Additional information to run the action in JSON format. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!cherwell-run-one-step-action-on-business-object busobjectid=6dd53665c0c24cab86870a21cf6434ae busobrecid=94757184cce46253b3ab694ae58289b64d0cd867ce oneStepAction_StandInKey=DefType:OneStepDef#Scope:Global#Id:947509fc528a451570e6c14223a9a8ca12b0856fc2#Owner:6dd53665c0c24cab86870a21cf6434ae prompt_values=[{"promptDefId": "947509fe4c84176152bcaa472b929d556b47c5df6d","value": "This is from the REST API"}]```

#### Human Readable Output

>One-Step action has been executed successfully.