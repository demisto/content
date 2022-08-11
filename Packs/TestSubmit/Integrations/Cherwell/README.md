Cloud-based IT service management solution
## Configure Cherwell on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cherwell.
3. Click **Add instance** to create and configure a new integration instance.

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
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

### cherwell-get-business-object-summary
***
Get a business object summary by name or ID.


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
| Cherwell.BusinessObjectSummary.firstRecIdField | String | The ID value of the first business object record ID \(RecID\) field. | 
| Cherwell.BusinessObjectSummary.recIdFields | String | The IDs of business object record ID \(RecID\) fields. | 

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

There is no context output for this command.