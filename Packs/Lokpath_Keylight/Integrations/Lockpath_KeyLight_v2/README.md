Use the LockPath KeyLight integration to manage GRC tickets in the Keylight platform.
This integration was integrated and tested with version 5.5.018.10 of Lockpath KeyLight.
## Configure Lockpath KeyLight v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL in the form of `https://[server]:<port>`; (e.g. https://192.168.0.1:4443) | True |
| credentials | Credentials | True |
| incidentType | Incident type | False |
| component_name | Name of component to fetch from | False |
| filter_field | Name of field to fetch by | False |
| fetch_limit | Fetch Limit | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### kl-get-component
***
Retrieves a component specified by ID or alias. If no parameters are specified, all components will be retrieved.


##### Base Command

`kl-get-component`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The id of the component. | Optional | 
| alias | The alias of the component. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Component.ID | String | The ID of the component. | 
| Keylight.Component.Name | String | The name of the component. | 
| Keylight.Component.ShortName | String | The short name of the component. | 
| Keylight.Component.SystemName | String | The system name of the component. | 


##### Command Example
```!kl-get-component alias="_auditdemisto"```

##### Context Example
```
{
    "Keylight": {
        "Component": {
            "ID": 10359,
            "Name": "Audit (Demisto Test)",
            "ShortName": "_auditdemisto",
            "SystemName": "_auditdemisto"
        }
    }
}
```

##### Human Readable Output
### Keylight Components
|ID|Name|ShortName|SystemName|
|---|---|---|---|
| 10359 | Audit Tasks (Demisto Test) | _auditdemisto | _auditdemisto |


### kl-get-field-list
***
Retrieves a detail field listing for a component specified by ID.


##### Base Command

`kl-get-field-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The id of the component. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Field.ID | String | The ID of the field. | 
| Keylight.Field.Name | String | The field&\#x27;s name. | 
| Keylight.Field.SystemName | String | The system name of the field. | 
| Keylight.Field.ShortName | String | The short name of the field. | 
| Keylight.Field.ReadOnly | Boolean | Is the field read only. | 
| Keylight.Field.Required | Boolean | Is the field required. | 


##### Command Example
```!kl-get-field-list component_id="10359"```

##### Context Example
```
{
    "Keylight": {
        "Field": [
            {
                "FieldType": 5,
                "ID": 8998,
                "MatrixRows": [],
                "Name": "Assignee",
                "OneToMany": false,
                "ReadOnly": false,
                "Required": true,
                "ShortName": "_assignee",
                "SystemName": "_assignee"
            },
            {
                "FieldType": 8,
                "ID": 9071,
                "MatrixRows": [],
                "Name": "Attachment",
                "OneToMany": true,
                "ReadOnly": false,
                "Required": false,
                "ShortName": "_attachment",
                "SystemName": "_attachment"
            },
            {
                "FieldType": 1,
                "ID": 9013,
                "MatrixRows": [],
                "Name": "Comments",
                "OneToMany": false,
                "ReadOnly": false,
                "Required": false,
                "ShortName": "_commentstest",
                "SystemName": "_commentstest"
            },
            {
                "FieldType": 3,
                "ID": 8949,
                "MatrixRows": [],
                "Name": "Created At",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "CreatedAt",
                "SystemName": "CreatedAt"
            },
            {
                "FieldType": 5,
                "ID": 8950,
                "MatrixRows": [],
                "Name": "Created By",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "CreatedBy",
                "SystemName": "CreatedBy"
            },
            {
                "FieldType": 2,
                "ID": 8948,
                "MatrixRows": [],
                "Name": "Current Revision",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "Version",
                "SystemName": "Version"
            },
            {
                "FieldType": 10,
                "ID": 8956,
                "MatrixRows": [],
                "Name": "Deleted",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "Deleted",
                "SystemName": "Deleted"
            },
            {
                "FieldType": 1,
                "ID": 9082,
                "MatrixRows": [],
                "Name": "Description",
                "OneToMany": false,
                "ReadOnly": false,
                "Required": true,
                "ShortName": "_taskdesc",
                "SystemName": "_taskdesc"
            },
            {
                "FieldType": 8,
                "ID": 9084,
                "MatrixRows": [],
                "Name": "Document Attachment",
                "OneToMany": true,
                "ReadOnly": false,
                "Required": false,
                "ShortName": "_Document",
                "SystemName": "_Document"
            },
            {
                "FieldType": 3,
                "ID": 9002,
                "MatrixRows": [],
                "Name": "Due Date",
                "OneToMany": false,
                "ReadOnly": false,
                "Required": true,
                "ShortName": "_duedatetest",
                "SystemName": "_duedatetest"
            },
            {
                "FieldType": 8,
                "ID": 9006,
                "MatrixRows": [],
                "Name": "Evidence",
                "OneToMany": true,
                "ReadOnly": false,
                "Required": false,
                "ShortName": "_evidencetest",
                "SystemName": "_evidencetest"
            },
            {
                "FieldType": 2,
                "ID": 8947,
                "MatrixRows": [],
                "Name": "Id",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "Id",
                "SystemName": "Id"
            },
            {
                "FieldType": 2,
                "ID": 8959,
                "MatrixRows": [],
                "Name": "Published Revision",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "PublishedVersion",
                "SystemName": "PublishedVersion"
            },
            {
                "FieldType": 1,
                "ID": 9083,
                "MatrixRows": [],
                "MaxLength": 100,
                "Name": "Task ID",
                "OneToMany": false,
                "ReadOnly": false,
                "Required": true,
                "ShortName": "_taskid",
                "SystemName": "_taskid"
            },
            {
                "FieldType": 3,
                "ID": 8952,
                "MatrixRows": [],
                "Name": "Updated At",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "UpdatedAt",
                "SystemName": "UpdatedAt"
            },
            {
                "FieldType": 5,
                "ID": 8953,
                "MatrixRows": [],
                "Name": "Updated By",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "UpdatedBy",
                "SystemName": "UpdatedBy"
            },
            {
                "FieldType": 1,
                "ID": 9012,
                "MatrixRows": [],
                "MaxLength": 100,
                "Name": "Work Log",
                "OneToMany": false,
                "ReadOnly": false,
                "Required": false,
                "ShortName": "_worktime",
                "SystemName": "_worktime"
            },
            {
                "FieldType": 5,
                "ID": 8957,
                "MatrixRows": [],
                "Name": "Workflow Stage",
                "OneToMany": false,
                "ReadOnly": true,
                "Required": false,
                "ShortName": "WorkflowStage",
                "SystemName": "WorkflowStage"
            }
        ]
    }
}
```

##### Human Readable Output
### Keylight fields for component 10359:
|ID|Name|SystemName|ShortName|ReadOnly|Required|
|---|---|---|---|---|---|
| 8998 | Assignee | _assignee | _assignee | false | true |
| 9071 | Attachment | _attachment | _attachment | false | false |
| 9013 | Comments | _commentstest | _commentstest | false | false |
| 8949 | Created At | CreatedAt | CreatedAt | true | false |
| 8950 | Created By | CreatedBy | CreatedBy | true | false |
| 8948 | Current Revision | Version | Version | true | false |
| 8956 | Deleted | Deleted | Deleted | true | false |
| 9082 | Description | _taskdesc | _taskdesc | false | true |
| 9084 | Document Attachment | _Document | _Document | false | false |
| 9002 | Due Date | _duedatetest | _duedatetest | false | true |
| 9006 | Evidence | _evidencetest | _evidencetest | false | false |
| 8947 | Id | Id | Id | true | false |
| 9083 | Task ID | _taskid | _taskid | false | true |
| 8952 | Updated At | UpdatedAt | UpdatedAt | true | false |
| 8953 | Updated By | UpdatedBy | UpdatedBy | true | false |
| 9012 | Work Log | _worktime | _worktime | false | false |
| 8957 | Workflow Stage | WorkflowStage | WorkflowStage | true | false |


### kl-get-field
***
Retrieves details for a field specified by ID.


##### Base Command

`kl-get-field`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the component. Get the ID from the kl-get-component command. | Required | 
| field_name | The name of the field. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Field.ID | String | The ID of the field. | 
| Keylight.Field.Name | String | The field&\#x27;s name. | 
| Keylight.Field.SystemName | String | The system name of the field. | 
| Keylight.Field.ShortName | String | The short name of the field. | 
| Keylight.Field.ReadOnly | Boolean | Is the field read only. | 
| Keylight.Field.Required | String | Is the field required. | 


##### Command Example
```!kl-get-field component_id="10359" field_name="Task ID"```

##### Context Example
```
{
    "Keylight": {
        "Field": {
            "FieldType": 1,
            "ID": 9083,
            "MatrixRows": [],
            "MaxLength": 100,
            "Name": "Task ID",
            "OneToMany": false,
            "ReadOnly": false,
            "Required": true,
            "ShortName": "_taskid",
            "SystemName": "_taskid"
        }
    }
}
```

##### Human Readable Output
### Keylight field 9083:
|ID|Name|SystemName|ShortName|ReadOnly|Required|
|---|---|---|---|---|---|
| 9083 | Task ID | _taskid | _taskid | false | true |


### kl-get-record
***
Returns the complete set of fields for a given record within a component.


##### Base Command

`kl-get-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The component ID. Get the D from the kl-get-component. | Required | 
| field_names | The filter specific for field names.<br/>* Case sensitive.<br/>* If one of the names contains a space, add all names in parenthesis (such as &quot;Id,Published Revision&quot;). | Optional | 
| record_id | The record ID. Get the ID from Keylight or from the kl-get-records command. | Required | 
| detailed | Whether to get detailed records. Default is false. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Record.ID | String | The record ID. | 
| Keylight.Record.Fields | String | The fields in the record. | 
| Keylight.Record.ComponentID | String | The component ID of the record. | 
| Keylight.Record.DisplayName | String | The display name of the record. | 


##### Command Example
```!kl-get-record record_id=13  component_id=10359```

##### Context Example
```
{
    "Keylight": {
        "Record": {
            "ComponentID": "10359",
            "DisplayName": "This is a task",
            "Fields": {
                "Assignee": {
                    "ID": 6,
                    "Value": "Admin, Keylight"
                },
                "Attachment": [],
                "Audit Project": null,
                "Authority Doc Citations": null,
                "Comments": null,
                "Created At": "2019-11-20T14:26:17.2285486",
                "Created By": {
                    "ID": 268,
                    "Value": "Development, Demisto"
                },
                "Current Revision": 1,
                "Deleted": false,
                "Description": null,
                "Document Attachment": [],
                "Due Date": null,
                "Evidence": [],
                "Id": 13,
                "Published Revision": 1,
                "Task ID": "This is a task",
                "Updated At": "2019-11-20T14:26:17.2285486",
                "Updated By": {
                    "ID": 268,
                    "Value": "Development, Demisto"
                },
                "Work Log": null,
                "Workflow Stage": {
                    "ID": 221,
                    "Value": "Published"
                }
            },
            "ID": 13
        }
    }
}
```

##### Human Readable Output
### Details for record This is a task:
|ComponentID|DisplayName|ID|
|---|---|---|
| 10359 | This is a task | 13 |
### With the following fields:
|Assignee|Attachment|Audit Project|Authority Doc Citations|Comments|Created At|Created By|Current Revision|Deleted|Description|Document Attachment|Due Date|Evidence|Id|Published Revision|Task ID|Updated At|Updated By|Work Log|Workflow Stage|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Value: Admin, Keylight<br></br>ID: 6 |  |  |  |  | 2019-11-20T14:26:17.2285486 | Value: Development, Demisto<br></br>ID: 268 | 1 | false |  |  |  |  | 13 | 1 | This is a task | 2019-11-20T14:26:17.2285486 | Value: Development, Demisto<br></br>ID: 268 |  | Value: Published<br></br>ID: 221 |


### kl-get-records
***
Retrieves the title/default field for a set of records within a chosen component.
Filters may be applied to retrieve only the records meeting the selected criteria.


##### Base Command

`kl-get-records`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the desired component. Get the ID from the kl-get-component command. | Required | 
| page_index | The index of the page of result to return. Must be &gt;= 0 | Optional | 
| page_size | The index of the page of result to return. Must be between 0 and 100. | Optional | 
| filter_type | The type of filter to apply. Can be: &quot;Contains&quot;, &quot;Excludes&quot;, &quot;Starts With&quot;, &quot;Ends With&quot;, &quot;Equals&quot;, &quot;Not Equals&quot;, &quot;Greater Than&quot;, &quot;Less Than&quot;, &quot;Greater Than&quot;, &quot;Less Than&quot;, &quot;Greater Equals Than&quot;, &quot;Between&quot;, &quot;Not Between&quot;, &quot;Is Null&quot;, &quot;Is Not Null&quot;. | Optional | 
| filter_field_name | The name of the field for which to apply the filter. | Optional | 
| filter_value | The value for which to filter. | Optional | 
| detailed | Whether to get detailed records. | Optional | 
| returned_fields | A list of specific fields to return. If empty, return all fields. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Record.ComponentID | String | The ID of the component containing the record. | 
| Keylight.Record.DisplayName | String | The display name of the record. | 
| Keylight.Record.Fields | Unknown | The fields in the record. | 
| Keylight.Record.ID | Unknown | The ID of the record. | 


##### Command Example
```!kl-get-records component_id="10359" filter_type="Starts With" filter_field_name="Task ID" filter_value="Updated" detailed="True"```

##### Context Example
```
{
    "Keylight": {
        "Record": null
    }
}
```

##### Human Readable Output
### Records for component 10359 
### with filter "Starts With: Updated" on field "Task ID"
**No entries.**


### kl-get-record-count
***
Get the number of records for a specific component and filter.


##### Base Command

`kl-get-record-count`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the desired component. Get the ID from the kl-get-component command. | Required | 
| filter_type | The type of filter to apply. Can be: &quot;Contains&quot;, &quot;Excludes&quot;, &quot;Starts With&quot;, &quot;Ends With&quot;, &quot;Equals&quot;, &quot;Not Equals&quot;, &quot;Greater Than&quot;, &quot;Less Than&quot;, &quot;Greater Than&quot;, &quot;Less Than&quot;, &quot;Greater Equals Than&quot;, &quot;Between&quot;, &quot;Not Between&quot;, &quot;Is Null&quot;, &quot;Is Not Null&quot;. | Optional | 
| filter_field_name | The name of the field for which to apply the filter. | Optional | 
| filter_value | The value for which to filter. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kl-get-record-count component_id=10359```

##### Context Example
```
{}
```

##### Human Readable Output
## There are **27** records in component 10359.


### kl-get-record-attachments
***
Return the attachments of a specific field and record.


##### Base Command

`kl-get-record-attachments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the desired component. Get the ID from the kl-get-component command. | Required | 
| record_id | The record ID. Can get from Keylight or from the kl-get-records command. | Required | 
| field_name | The name of the field that holds the attachments. Must be type &quot;Documents&quot;. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Attachment.FileName | String | The name of the attachment. | 
| Keylight.Attachment.FieldID | String | The field ID of the attachment. | 
| Keylight.Attachment.DocumentID | String | The ID of the document containing the attachment. | 
| Keylight.Attachment.ComponentID | String | The component ID of the attachment. | 
| Keylight.Attachment.RecordID | String | The record ID of the attachment. | 


##### Command Example
```!kl-get-record-attachments component_id=10359 field_name="Evidence" record_id=4```

##### Context Example
```
{
    "Keylight": {
        "Attachment": {
            "ComponentID": "10359",
            "DocumentID": 409,
            "FieldID": 9006,
            "FileName": "20170105_133423 (1).jpg",
            "RecordID": "4"
        }
    }
}
```

##### Human Readable Output
### Field Evidence in record 4 has the following attachments:
|ComponentID|DocumentID|FieldID|FileName|RecordID|
|---|---|---|---|---|
| 10359 | 409 | 9006 | 20170105_133423 (1).jpg | 4 |


### kl-get-record-attachment
***
Returns a single attachment associated with the component ID, record ID, documents field ID, and the document ID.


##### Base Command

`kl-get-record-attachment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the desired component. Get the ID from the kl-get-component command. | Required | 
| record_id | The record ID. Can get from Keylight or from the kl-get-records command. | Required | 
| field_name | The name of the field that holds the attachments. Must be type &quot;Documents&quot;. | Required | 
| document_id | The ID of the document. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kl-get-record-attachment component_id=10359 field_name="Evidence" record_id=4 document_id=409```

##### Context Example
```
{
    "File": {
        "EntryID": "3780@02173cac-a766-46f9-865a-a98cd0a061dc",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "e0d98c1054eff8763e7bc3c06e3a8a6b",
        "Name": "20170105_133423 (1).jpg",
        "SHA1": "af3037c5ffd649b25c5eef2af58a8e7583bf963c",
        "SHA256": "5af85edac1bdec966440ee138d283b00f0e10e6b47a5e7de1782ad2c51e49cbf",
        "SHA512": "55d1db4a3754c3cd6a1221ea73493c130f97e8bb21ef55b8b1b3d73677492edb94fee675528f7b655e1053b91e7c1ca5968401fb4b6a8d4a329991ef9b690a6b",
        "SSDeep": "24576:zyK02314tDlzpa/64euXT6CtlPjPdq0O7UR5RCqSpupwP2jpOUcVnRhInUS:zyK02314FL4rX1UURPCqSpupwyQcUS",
        "Size": 1810926,
        "Type": "JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=12, height=1836, manufacturer=samsung, model=SM-G920F, orientation=upper-left, xresolution=210, yresolution=218, resolutionunit=2, software=G920FXXU4DPGV, datetime=2017:01:11 13:14:17, width=3264], baseline, precision 8, 3264x1836, frames 3"
    }
}
```

##### Human Readable Output


### kl-delete-record
***
Deletes a selected record from within a chosen component.


##### Base Command

`kl-delete-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The component ID. Get the ID from the kl-get-component command. | Required | 
| record_id | The record ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kl-delete-record component_id="10359" record_id="106"```

##### Context Example
```
{}
```

##### Human Readable Output
### Record 106 of component 10359 was deleted successfully.

### kl-delete-record-attachment
***
Deletes a specific attachment.


##### Base Command

`kl-delete-record-attachment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the component. Get the ID from the kl-get-component command. | Required | 
| record_id | The ID of the record to delete. | Required | 
| field_id | The ID of the field. | Required | 
| document_id | The ID of the document to delete. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### kl-get-lookup-report-column-fields
***
Retrieves information of each field in a field path, which relates to a lookup report column.


##### Base Command

`kl-get-lookup-report-column-fields`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lookup_field_id | The lookup field ID, which relates to a lookup field that uses the report definition. | Required | 
| field_path_id | The field path ID, which relates to the field path that retrieves fields. Get from the kl-get-record command. Detailed=True. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.LookupField.ID | String | The lookup field&\#x27;s ID. | 
| Keylight.LookupField.Name | String | The lookup field&\#x27;s name. | 
| Keylight.LookupField.ComponentID | String | The lookup field&\#x27;s component ID. | 
| Keylight.LookupField.SystemName | String | The system name of the lookup field. | 


##### Command Example
``` ```

##### Human Readable Output


### kl-create-record
***
Creates a new record within the specified component of the Keylight application.
* The Required option for a field is only enforced through the user interface, not through Cortex XSOAR.


##### Base Command

`kl-create-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the component the record should be created in. Get the ID from the kl-get-component command. | Required | 
| record_json | A JSON file in the format that the API requests. The exact format is found in the API documentation. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Record.ComponentID | String | The component ID of the record. | 
| Keylight.Record.DisplayName | String | The display name of the record. | 
| Keylight.Record.Fields | Unknown | The fields in the record. | 
| Keylight.Record.ID | String | The record ID. | 


##### Command Example
```!kl-create-record component_id="10359" record_json="[{\"fieldName\": \"Task ID\", \"value\": \"Created by Demisto Test Playbook\", \"isLookup\": false}, {\"fieldName\": \"Audit Project\", \"value\": 3, \"isLookup\": true}]"```

##### Context Example
```
{
    "Keylight": {
        "Record": {
            "ComponentID": "10359",
            "DisplayName": "Created by Demisto Test Playbook",
            "Fields": {
                "Assignee": null,
                "Attachment": [],
                "Audit Project": {
                    "ID": 3,
                    "Value": "123"
                },
                "Authority Doc Citations": null,
                "Comments": null,
                "Created At": "2020-04-19T07:20:16.195364Z",
                "Created By": {
                    "ID": 268,
                    "Value": "Development, Demisto"
                },
                "Current Revision": 1,
                "Deleted": false,
                "Description": null,
                "Document Attachment": [],
                "Due Date": null,
                "Evidence": [],
                "Id": 359,
                "Published Revision": null,
                "Task ID": "Created by Demisto Test Playbook",
                "Updated At": "2020-04-19T07:20:16.195364Z",
                "Updated By": {
                    "ID": 268,
                    "Value": "Development, Demisto"
                },
                "Work Log": null,
                "Workflow Stage": {
                    "ID": 221,
                    "Value": "Published"
                }
            },
            "ID": 359
        }
    }
}
```

##### Human Readable Output
### Task "Created by Demisto Test Playbook":
|ComponentID|DisplayName|ID|
|---|---|---|
| 10359 | Created by Demisto Test Playbook | 359 |
### With the following fields:
|Assignee|Attachment|Audit Project|Authority Doc Citations|Comments|Created At|Created By|Current Revision|Deleted|Description|Document Attachment|Due Date|Evidence|Id|Published Revision|Task ID|Updated At|Updated By|Work Log|Workflow Stage|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  | Value: 123<br></br>ID: 3 |  |  | 2020-04-19T07:20:16.195364Z | Value: Development, Demisto<br></br>ID: 268 | 1 | false |  |  |  |  | 359 |  | Created by Demisto Test Playbook | 2020-04-19T07:20:16.195364Z | Value: Development, Demisto<br></br>ID: 268 |  | Value: Published<br></br>ID: 221 |


### kl-update-record
***
Update fields in a specified record.
* The Required option for a field is only enforced through the user interface, not through Cortex XSOAR.


##### Base Command

`kl-update-record`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_id | The ID of the component. Get the ID from the kl-get-component command. | Required | 
| record_id | The ID of the record to be updated. Get the ID from Keylight or from the kl-get-records command. | Required | 
| record_json | A JSON file in the format that the API requests. The exact format is found in the API documentation. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.Record.ComponentID | String | The ID of the component the record is in. | 
| Keylight.Record.DisplayName | String | The display name of the record. | 
| Keylight.Record.Fields | String | The fields in the record. | 
| Keylight.Record.ID | String | The record ID | 


##### Command Example
``` ```

##### Human Readable Output


### kl-get-user-by-id
***
Get user details by his ID.


##### Base Command

`kl-get-user-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keylight.User.Id | String | The user ID. | 
| Keylight.User.FullName | String | The user&\#x27;s full name. | 
| Keylight.User.Username | String | The user&\#x27;s username. | 
| Keylight.User.Active | Boolean | Is the user active. | 
| Keylight.User.FirstName | String | The user&\#x27;s first name. | 
| Keylight.User.MiddleName | String | The users middle name. | 
| Keylight.User.LastName | String | The user&\#x27;s last name. | 
| Keylight.User.EmailAddress | String | The user&\#x27;s email address. | 
| Keylight.User.HomePhone | String | The user&\#x27;s home phone. | 
| Keylight.User.WorkPhone | String | The user&\#x27;s work phone. | 
| Keylight.User.MobilePhone | String | The user&\#x27;s mobile phone. | 


##### Command Example
```!kl-get-user-by-id user_id=268```

##### Context Example
```
{
    "Keylight": {
        "User": {
            "APIAccess": true,
            "AccountType": 1,
            "Active": true,
            "Deleted": false,
            "EmailAddress": "demisto@demisto.com",
            "Fax": "",
            "FirstName": "Demisto",
            "FullName": "Development, Demisto",
            "FunctionalRoles": [],
            "Groups": [
                {
                    "Id": 42,
                    "Name": "Demisto Development"
                }
            ],
            "HomePhone": "",
            "Id": 268,
            "IsLDAP": false,
            "IsSAML": false,
            "Language": 1033,
            "LastName": "Development",
            "Locked": false,
            "MiddleName": "",
            "MobilePhone": "",
            "SecurityConfiguration": {
                "DisplayName": "Standard User Configuration",
                "Id": 7
            },
            "SecurityRoles": [
                {
                    "Id": 28,
                    "Name": "Demisto Developer"
                }
            ],
            "Title": "Demisto Users",
            "Username": "demisto@demisto.com",
            "WorkPhone": ""
        }
    }
}
```

##### Human Readable Output
### Keylight user 268
|APIAccess|AccountType|Active|Deleted|EmailAddress|Fax|FirstName|FullName|FunctionalRoles|Groups|HomePhone|Id|IsLDAP|IsSAML|Language|LastName|Locked|MiddleName|MobilePhone|SecurityConfiguration|SecurityRoles|Title|Username|WorkPhone|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| true | 1 | true | false | demisto@demisto.com |  | Demisto | Development, Demisto |  | {'Id': 42, 'Name': 'Demisto Development'} |  | 268 | false | false | 1033 | Development | false |  |  | Id: 7<br></br>DisplayName: Standard User Configuration | {'Id': 28, 'Name': 'Demisto Developer'} | Demisto Users | demisto@demisto.com |  |
