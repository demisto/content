The RSA Archer GRC platform provides a common foundation for managing policies, controls, risks, assessments, and deficiencies across lines of business.
## Configure RSA Archer v2_1.2.14_TEST on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RSA Archer v2_1.2.14_TEST.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://192.168.0.1/rsaarcher or https://192.168.0.1/ or https://192.168.0.1/archer) |  | True |
    | Advanced: API Endpoint | Change only if you have another API endpoint. | False |
    | Instance name |  | True |
    | Username |  | True |
    | Password |  | True |
    | User domain |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Application ID for fetch |  | True |
    | Application date field for fetch | The value should be the field name | True |
    | Maximum number of incidents to pull per fetch |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, 3 months, 1 year) |  | False |
    | List of fields from the application to get into the incident |  | False |
    | Timeout | Request timeout value, in seconds. Default is 400. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### archer-search-applications

***
Gets application details or a list of all applications.

#### Base Command

`archer-search-applications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The application ID to get details for. Leave empty to get a list of all applications. | Optional | 
| limit | The maximum number of applications to return. Default is 20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Application.Guid | String | The application GUID. | 
| Archer.Application.Id | Number | The unique ID of the application. | 
| Archer.Application.Status | Number | The application status. | 
| Archer.Application.Type | Number | The application type. | 
| Archer.Application.Name | String | The application name. | 

### archer-get-application-fields

***
Gets all application fields by application ID.

#### Base Command

`archer-get-application-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The application ID to get the application fields for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.ApplicationField.FieldId | Number | The unique ID of the field. | 
| Archer.ApplicationField.FieldName | String | The field name. | 
| Archer.ApplicationField.FieldType | String | The field type. | 
| Archer.ApplicationField.LevelID | Number | The field level ID. | 

### archer-get-field

***
Returns a mapping from list value name to list value ID.

#### Base Command

`archer-get-field`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldID | The ID of the field. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.ApplicationField.FieldId | Number | The unique ID of the field. | 
| Archer.ApplicationField.FieldName | String | The field name. | 
| Archer.ApplicationField.FieldType | String | The field type. | 
| Archer.ApplicationField.LevelID | Number | The field level ID. | 

### archer-get-mapping-by-level

***
Returns a mapping of fields by level ID.

#### Base Command

`archer-get-mapping-by-level`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| level | The ID of the level. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.LevelMapping.Id | Number | The unique ID of the field. | 
| Archer.LevelMapping.Name | String | The field name. | 
| Archer.LevelMapping.Type | String | The field type. | 
| Archer.LevelMapping.LevelId | Number | The field level ID. | 

### archer-get-record

***
Gets information about a content record in the given application.

#### Base Command

`archer-get-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| depth | In case of nesting, to which level to go in the depth of the recursion. Default is 3. | Optional | 
| contentId | The record ID. | Required | 
| applicationId | The application ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Record.Id | Number | The unique ID of the record. | 

### archer-create-record

***
Creates a new content record in the given application.

#### Base Command

`archer-create-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The application ID. | Required | 
| fieldsToValues | Record fields in JSON format: { "Name1": Value1, "Name2": Value2 }. Field names are case sensitive. | Required | 
| levelId | The Level ID to use to create the record. If empty, the command by default takes the first level ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Record.Id | Number | The unique ID of the record. | 

### archer-delete-record

***
Deletes an existing content record in the given application.

#### Base Command

`archer-delete-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contentId | The ID of the record to delete. | Required | 

#### Context Output

There is no context output for this command.
### archer-update-record

***
Updates an existing content record in the given application.

#### Base Command

`archer-update-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The application ID. | Required | 
| fieldsToValues | Record fields in JSON format: { "Name1": Value1, "Name2": Value2 }. Field names are case sensitive. | Required | 
| contentId | The ID of the record to update. | Required | 
| levelId | The Level ID to use to update the record. If empty, the command by default takes the first level ID. | Optional | 

#### Context Output

There is no context output for this command.
### archer-execute-statistic-search-by-report

***
Performs a statistic search by report GUID.

#### Base Command

`archer-execute-statistic-search-by-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportGuid | The report GUID. | Required | 
| maxResults | Maximum number of pages for the reports. Default is 100. | Required | 

#### Context Output

There is no context output for this command.
### archer-get-reports

***
Gets all reports from Archer.

#### Base Command

`archer-get-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### archer-get-search-options-by-guid

***
Returns search criteria by report GUID.

#### Base Command

`archer-get-search-options-by-guid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportGuid | The report GUID. | Required | 

#### Context Output

There is no context output for this command.
### archer-reset-cache

***
Resets Archer's integration cache. Run this command if you change the fields of your Archer application.

#### Base Command

`archer-reset-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### archer-get-valuelist

***
Returns a list of values for a specified field, for example, fieldID=16114. This command only works for value list fields (type 4).

#### Base Command

`archer-get-valuelist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldID | The field ID. | Required | 
| depth | In case of nesting, to which level to go in the depth of the recursion. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.ApplicationField.ValuesList.Id | Number | The field value ID. | 
| Archer.ApplicationField.ValuesList.IsSelectable | Boolean | Specifies whether you can select the field value. | 
| Archer.ApplicationField.ValuesList.Name | String | The field value name. | 
| Archer.ApplicationField.ValuesList.Parent | String | The field value parent. | 
| Archer.ApplicationField.ValuesList.Depth | Number | The field value depth. | 

### archer-upload-file

***
Uploads a file to Archer.

#### Base Command

`archer-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The entry ID of the file in Cortex XSOAR context. | Required | 
| applicationId | ID of the application to upload the file to. | Optional | 
| contentId | The content (record) ID to update. | Optional | 
| associatedField | Archer field name to associate the file with. Default is Supporting Documentation. | Optional | 

#### Context Output

There is no context output for this command.
### archer-get-file

***
Downloads a file from Archer to Cortex XSOAR context.

#### Base Command

`archer-get-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileId | The file ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type as determined by libmagic \(same as displayed in file entries\). | 

### archer-list-users

***
Gets details for a user or a list of all users.

#### Base Command

`archer-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | The ID of the user to get details for. Leave empty to get a list of all users. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.User.AccountStatus | String | The account status of the user. | 
| Archer.User.DisplayName | String | The display name of the user. | 
| Archer.User.FirstName | String | The first name of the user. | 
| Archer.User.Id | Number | The unique ID of the user. | 
| Archer.User.LastLoginDate | Date | The last login date of user. | 
| Archer.User.LastName | String | The last name of the user. | 
| Archer.User.MiddleName | String | The middle name of the user. | 
| Archer.User.UserName | String | The username associated with the account. | 

### archer-search-records

***
Searches for records in the given application.

#### Base Command

`archer-search-records`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The ID of the application in which to search for records. | Required | 
| fieldToSearchOn | The name of the field on which to search. Leave empty to search on all fields. | Optional | 
| fieldToSearchById | The name of the primary Id field on which to search. Used instead of the fieldToSearchOn argument for searching by the application primary field. | Optional | 
| searchValue | Search value. Leave empty to search for all. | Optional | 
| maxResults | Maximum number of results to return from the search. Default is 10. | Optional | 
| fieldsToDisplay | Fields to display in the search results (in array format). For example "Title,Incident Summary". | Optional | 
| numericOperator | Numeric search operator. Can be "Equals", "NotEqual", "GreaterThan", or "LessThan". Possible values are: Equals, NotEqual, GreaterThan, LessThan. | Optional | 
| dateOperator | Date search operator. Can be "Equals", "DoesNotEqual", "GreaterThan", or "LessThan". Possible values are: Equals, DoesNotEqual, GreaterThan, LessThan. | Optional | 
| fieldsToGet | Fields to fetch from the application. | Optional | 
| fullData | Whether to get extended responses with all of the data regarding this search. For example, "fullData=true". Possible values are: True, False. Default is False. | Required | 
| isDescending | Whether to order by descending order. Possible values are: true, false. | Optional | 
| levelId | The Level ID to use for searching. This argument is relevant when fullData is True. If empty, the command by default takes the first level ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Record | Unknown | The content object. | 
| Archer.Record.Id | Number | The content ID. | 

### archer-search-records-by-report

***
Searches records by report GUID.

#### Base Command

`archer-search-records-by-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportGuid | The report GUID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.SearchByReport.ReportGUID | String | The report GUID. | 
| Archer.SearchByReport.RecordsAmount | Number | The number of records found by the search. | 
| Archer.SearchByReport.Record | Unknown | The records found by the search. | 

### archer-print-cache

***
Prints the Archer's integration cache.

#### Base Command

`archer-print-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
