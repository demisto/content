The RSA Archer GRC Platform provides a common foundation for managing policies, controls, risks, assessments and deficiencies across lines of business.

## Configure RSA Archer v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RSA Archer v2.
3. Click **Add instance** to create and configure a new integration instance.

## Clarifications  
The timezone (offset) parameter should be used if the Cortex XSOAR server and Archer's server aren't in the same time zone.
If the Cortex XSOAR server time is 00:00 and the Archer server time is 01:00, the timezone parameter should be +60 (minutes).

| **Parameter** | **Description** | **Required** |

| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| instanceName | Instance name | True |
| userDomain | User domain | False |
| applicationId | Application ID for fetch | True |
| applicationDateField | Application date field for fetch | True |
| fetch_limit | How many incidents to fetch each time | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| fields_to_fetch | List of fields from the application to gets into the incident | False |
| time_zone | Timezone offset in minutes of the RSA Archer server machine \(\+60, \-60, in minutes\) | False |
| useEuropeanTime | Use European Time format (DD/MM/YYYY) instead of the American one. (According to the applicationDateField) | False | 

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### archer-search-applications
***
Gets application details or list of all applications.


#### Base Command

`archer-search-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | Get application by ID (leave empty to get all applications) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Application.Guid | String | The application Guid | 
| Archer.Application.Id | Number | Unique Id of application | 
| Archer.Application.Status | Number | The application Status | 
| Archer.Application.Type | Number | The application Type | 
| Archer.Application.Name | String | The application name | 


#### Command Example
```!archer-search-applications applicationId=75```

#### Context Example
```
{
    "Archer": {
        "Application": {
            "Guid": "982fc3be-7c43-4d79-89a1-858ed262b930",
            "Id": 75,
            "LanguageId": 1,
            "Name": "Incidents",
            "Status": 1,
            "Type": 2
        }
    }
}
```

#### Human Readable Output

>### Search applications results
>|Guid|Id|LanguageId|Name|Status|Type|
>|---|---|---|---|---|---|
>| 982fc3be-7c43-4d79-89a1-858ed262b930 | 75 | 1 | Incidents | 1 | 2 |


### archer-get-application-fields
***
Gets all application fields by application ID


#### Base Command

`archer-get-application-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | ID of the application to search fields in | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.ApplicationField.FieldId | Number | Unique Id of field | 
| Archer.ApplicationField.FieldName | String | The field name | 
| Archer.ApplicationField.FieldType | String | The field type | 
| Archer.ApplicationField.LevelID | Number | The field level Id | 


#### Command Example
```!archer-get-application-fields applicationId=75```

#### Context Example
```
{
    "Archer": {
        "ApplicationField": [
            {
                "FieldId": 296,
                "FieldName": "Incident ID",
                "FieldType": "TrackingID",
                "LevelID": 67
            },
            {
                "FieldId": 297,
                "FieldName": "Date Created",
                "FieldType": "First Published",
                "LevelID": 67
            },
            {
                "FieldId": 298,
                "FieldName": "Last Updated",
                "FieldType": "Last Updated Field",
                "LevelID": 67
            },
            {
                "FieldId": 302,
                "FieldName": "Status",
                "FieldType": "Values List",
                "LevelID": 67
            },
            {
                "FieldId": 303,
                "FieldName": "Date/Time Occurred",
                "FieldType": "Date",
                "LevelID": 67
            },
            {
                "FieldId": 304,
                "FieldName": "Priority",
                "FieldType": "Values List",
                "LevelID": 67
            }
        ]
    }
}
```

#### Human Readable Output

>### Application fields
>|FieldId|FieldName|FieldType|LevelID|
>|---|---|---|---|
>| 296 | Incident ID | TrackingID | 67 |
>| 297 | Date Created | First Published | 67 |
>| 298 | Last Updated | Last Updated Field | 67 |
>| 302 | Status | Values List | 67 |
>| 303 | Date/Time Occurred | Date | 67 |
>| 304 | Priority | Values List | 67 |


### archer-get-field
***
Returns mapping from list value name to list value id


#### Base Command

`archer-get-field`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldID | Id of the field | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.ApplicationField.FieldId | Number | Unique Id of field | 
| Archer.ApplicationField.FieldName | String | The field name | 
| Archer.ApplicationField.FieldType | String | The field type | 
| Archer.ApplicationField.LevelID | Number | The field level Id | 


#### Command Example
```!archer-get-field fieldID=350```

#### Context Example
```
{
    "Archer": {
        "ApplicationField": {
            "FieldId": 350,
            "FieldName": "Reported to Police",
            "FieldType": "Values List",
            "LevelID": 67
        }
    }
}
```

#### Human Readable Output

>### Application field
>|FieldId|FieldName|FieldType|LevelID|
>|---|---|---|---|
>| 350 | Reported to Police | Values List | 67 |


### archer-get-mapping-by-level
***
Return mapping of fields by level id


#### Base Command

`archer-get-mapping-by-level`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| level | Id of the level | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.LevelMapping.Id | Number | Unique Id of field | 
| Archer.LevelMapping.Name | String | The field name | 
| Archer.LevelMapping.Type | String | The field type | 
| Archer.LevelMapping.LevelId | Number | The field level Id | 


#### Command Example
```!archer-get-mapping-by-level level=67```

#### Context Example
```
{
    "Archer": {
        "LevelMapping": [
            {
                "Id": 296,
                "LevelId": 67,
                "Name": "Incident ID",
                "Type": "TrackingID"
            },
            {
                "Id": 297,
                "LevelId": 67,
                "Name": "Date Created",
                "Type": "First Published"
            },
            {
                "Id": 298,
                "LevelId": 67,
                "Name": "Last Updated",
                "Type": "Last Updated Field"
            },
            {
                "Id": 302,
                "LevelId": 67,
                "Name": "Status",
                "Type": "Values List"
            }
        ]
    }
}
```

#### Human Readable Output

>### Level mapping for level 67
>|Id|LevelId|Name|Type|
>|---|---|---|---|
>| 296 | 67 | Incident ID | TrackingID |
>| 297 | 67 | Date Created | First Published |
>| 298 | 67 | Last Updated | Last Updated Field |
>| 302 | 67 | Status | Values List |

### archer-get-record
***
Gets information about a content record in the given application


#### Base Command

`archer-get-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contentId | The record id | Required | 
| applicationId | The application Id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Record.Id | Number | Unique Id of record | 


#### Command Example
```!archer-get-record applicationId=75 contentId=227602```

#### Context Example
```
{
    "Archer": {
        "Record": {
            "Current Status": {
                "OtherText": null,
                "ValuesListIds": [
                    6412
                ]
            },
            "Date/Time Occurred": "2018-03-23T07:00:00",
            "Date/Time Reported": "2018-03-26T10:03:32.243",
            "Days Open": 805,
            "Default Record Permissions": {
                "GroupList": [
                    {
                        "HasDelete": true,
                        "HasRead": true,
                        "HasUpdate": true,
                        "Id": 50
                    },
                    {
                        "HasDelete": false,
                        "HasRead": true,
                        "HasUpdate": false,
                        "Id": 51
                    }
                ],
                "UserList": []
            },
            "Google Map": "<a target='_new' href='http://maps.google.com/maps?f=q&ie=UTF8&om=1&hl=en&q=, , , '>Google Map</a>",
            "Id": 227602,
            "Incident Details": "Incident Details",
            "Incident Result": {
                "OtherText": null,
                "ValuesListIds": [
                    531
                ]
            },
            "Incident Summary": "Summary...",
            "Is BSA (Bank Secrecy Act) reporting required in the US?": {
                "OtherText": null,
                "ValuesListIds": [
                    835
                ]
            },
            "Notify Incident Owner": {
                "OtherText": null,
                "ValuesListIds": [
                    6422
                ]
            },
            "Override Rejected Submission": {
                "OtherText": null,
                "ValuesListIds": [
                    9565
                ]
            },
            "Status": {
                "OtherText": null,
                "ValuesListIds": [
                    466
                ]
            },
            "Status Change": {
                "OtherText": null,
                "ValuesListIds": [
                    156
                ]
            },
            "Supporting Documentation": [
                125
            ]
        }
    }
}
```

#### Human Readable Output

>### Record details
>|Current Status|Date/Time Occurred|Date/Time Reported|Days Open|Default Record Permissions|Google Map|Id|Incident Details|Incident Result|Incident Summary|Is BSA (Bank Secrecy Act) reporting required in the US?|Notify Incident Owner|Override Rejected Submission|Status|Status Change|Supporting Documentation|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ValuesListIds: 6412<br/>OtherText: null | 2018-03-23T07:00:00 | 2018-03-26T10:03:32.243 | 805.0 | UserList: <br/>GroupList: {'Id': 50, 'HasRead': True, 'HasUpdate': True, 'HasDelete': True},<br/>{'Id': 51, 'HasRead': True, 'HasUpdate': False, 'HasDelete': False} | <a target='_new' href='http://maps.google.com/maps?f=q&ie=UTF8&om=1&hl=en&q=, , , '>Google Map</a> | 227602 | Incident Details | ValuesListIds: 531<br/>OtherText: null | Summary... | ValuesListIds: 835<br/>OtherText: null | ValuesListIds: 6422<br/>OtherText: null | ValuesListIds: 9565<br/>OtherText: null | ValuesListIds: 466<br/>OtherText: null | ValuesListIds: 156<br/>OtherText: null | 125 |


### archer-create-record
***
Creates a new content record in the given application.

In this command when creating a new record, it is important to pay attention to the way the values are sent through the argument - *fieldsToValues*.

when field type is *Values List* - example: {"Type": \["Switch"], fieldname: \[value1, value2]}

when field type is *External Links* - example: {"Patch URL": \[{"value":"github", "link": "https://github.com"}]}

when field type is *Users/Groups List* - example: {"Policy Owner":{"users":ֿ \[20],"groups": \[30]}}

when field type is *Cross- Reference* - for example: {"Area Reference(s)": \[20]}

In other cases the value can be sent as is.

To know what the type of the value you are using, you can use `archer-get-application-fields` command with the `applicationId` to get the list of all *FieldType* by *FieldName*.

#### Base Command

`archer-create-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The application Id | Required | 
| fieldsToValues | Record fields in JSON format: { "Name1": Value1, "Name2": Value2 }. Field name is case sensitive | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Record.Id | Number | Unique Id of record | 


#### Command Example
`!archer-create-record applicationId=75 fieldsToValues={"Incident Summary":"This is the incident summary","Priority":["High"]}`

#### Context Example
```
{
    "Archer": {
        "Record": {
            "Id": 239643
        }
    }
}
```

#### Human Readable Output

>Record created successfully, record id: 239643

### archer-delete-record
***
Delete existing content record in the given application


#### Base Command

`archer-delete-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contentId | The record Id to delete | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!archer-delete-record contentId=239642```

#### Context Example
```
{}
```

#### Human Readable Output

>Record 239642 deleted successfully



### archer-update-record
***
Updates existing content record in the given application


#### Base Command

`archer-update-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | The application Id | Required | 
| fieldsToValues | Record fields in JSON format: { "Name1": Value1, "Name2": Value2 }. Field name is case sensitive | Required | 
| contentId | The record Id to update | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!archer-update-record applicationId=75 contentId=239326 fieldsToValues={"Priority":["High"]}`

#### Context Example
```
{}
```

#### Human Readable Output

>Record 239326 updated successfully

### archer-execute-statistic-search-by-report
***
Performs statistic search by report Guid


#### Base Command

`archer-execute-statistic-search-by-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportGuid | The report GUID | Required | 
| maxResults | Maximum pages of the reports | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!archer-execute-statistic-search-by-report maxResults=100 reportGuid=e4b18575-52c0-4f70-b41b-3ff8b6f13b1c```

#### Context Example
```
{}
```

#### Human Readable Output

>{
>  "Groups": {
>    "@count": "3",
>    "Metadata": {
>      "FieldDefinitions": {
>        "FieldDefinition": [
>          {
>            "@alias": "Classification",
>            "@guid": "769b2548-6a98-49b6-95c5-03e391f0a40e",
>            "@id": "76",
>            "@name": "Classification"
>          },
>          {
>            "@alias": "Standard_Name",
>            "@guid": "a569fd34-16f9-4965-93b0-889fcb91ba7a",
>            "@id": "1566",
>            "@name": "Standard Name"
>          }
>        ]
>      }
>    },
>    "Total": {
>      "Aggregate": {
>        "@Count": "1497",
>        "@FieldId": "1566"
>      }
>    }
>  }
>}

### archer-get-reports
***
Gets all the reports from Archer


#### Base Command

`archer-get-reports`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```archer-get-reports```

#### Context Example
```
{
    "Archer": {
        "Report": [
            {
                "ApplicationGUID": "982fc3be-7c43-4d79-89a1-858ed262b930",
                "ApplicationName": "Policies",
                "ApplicationDescription": "This report displays a listing of all security Policies.",
                "ReportGUID": "22961b81-4866-40ea-a298-99afb348598d",
                "ReportName": "Policies - Summary view"
            }
        ]
    }
}
```

#### Human Readable Output

### archer-get-search-options-by-guid
***
Returns search criteria by report GUID


#### Base Command

`archer-get-search-options-by-guid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportGuid | The report GUID | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!archer-get-search-options-by-guid reportGuid=bce4222c-ecfe-4cef-a556-fe746e959f12```

#### Context Example
```
{}
```

#### Human Readable Output

>{
>  "SearchReport": {
>    "Criteria": {
>      "ModuleCriteria": {
>        "BuildoutRelationship": "Union",
>        "IsKeywordModule": "True",
>        "Module": "421",
>        "SortFields": {
>          "SortField": [
>            {
>              "Field": "15711",
>              "SortType": "Ascending"
>            },
>            {
>              "Field": "15683",
>              "SortType": "Ascending"
>            }
>          ]
>        }
>      }
>    },
>    "DisplayFields": {
>      "DisplayField": [
>        "15683",
>        "15686",
>        "15687",
>        "15690",
>        "15706",
>        "15711",
>        "15710",
>        "15712",
>        "15713",
>        "15714",
>        "15715",
>        "15716",
>        "15725",
>        "15717",
>        "15718"
>      ]
>    },
>    "PageSize": "50"
>  }
>}

### archer-reset-cache
***
Reset Archer's integration cache. Run this command if you change the fields of your Archer application


#### Base Command

`archer-reset-cache`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!archer-reset-cache```

#### Context Example
```
{}
```

#### Human Readable Output



### archer-get-valuelist
***
Returns a list of values for a specified field, e.g., fieldID=16114. This command only works for value list fields (type 4).


#### Base Command

`archer-get-valuelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldID | The field Id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.ApplicationField.ValuesList.Id | Number | The field value Id | 
| Archer.ApplicationField.ValuesList.IsSelectable | Boolean | Specifies whether the field value is selectable | 
| Archer.ApplicationField.ValuesList.Name | String | The field value name | 


#### Command Example
```!archer-get-valuelist fieldID=302```

#### Context Example
```
{
    "Archer": {
        "ApplicationField": {
            "FieldId": "302",
            "ValuesList": [
                {
                    "Id": 466,
                    "IsSelectable": true,
                    "Name": "New"
                },
                {
                    "Id": 467,
                    "IsSelectable": true,
                    "Name": "Assigned"
                },
                {
                    "Id": 468,
                    "IsSelectable": true,
                    "Name": "In Progress"
                },
                {
                    "Id": 469,
                    "IsSelectable": true,
                    "Name": "On Hold"
                },
                {
                    "Id": 470,
                    "IsSelectable": true,
                    "Name": "Closed"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Value list for field 302
>|Id|IsSelectable|Name|
>|---|---|---|
>| 466 | true | New |
>| 467 | true | Assigned |
>| 468 | true | In Progress |
>| 469 | true | On Hold |
>| 470 | true | Closed |


### archer-upload-file
***
Uploads a file to Archer. Can associate the file to a record.
To associate to a record, must provide all of the following arguments: applicationId, contentId, associatedField.


#### Base Command

`archer-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryId | The entry id of the file in Demisto's context | Required | 
| contentId | The Content (record) ID to update.| Optional | 
| applicationId | ID of the application which we want to upload the file to. | Optional | 
| associatedField | Archer field name to associate the file with. | Optional
#### Context Output

There is no context output for this command.

#### Command Example
```!archer-upload-file entryId=16695@b32fdf18-1c65-43af-8918-7f85a1fab951```

#### Context Example
```
{}
```

#### Human Readable Output

>File uploaded succsessfully, attachment ID: 126


### archer-get-file
***
Downloads file from Archer to Demisto's war room context


#### Base Command

`archer-get-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileId | The attachment Id | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!archer-get-file fileId=125```

#### Context Example
```
{
    "File": {
        "EntryID": "16680@b32fdf18-1c65-43af-8918-7f85a1fab951",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "fb80f3fc41f2524",
        "Name": "11.jpg",
        "SHA1": "6898512eaa3",
        "SHA256": "f4bed94abd752",
        "SHA512": "ecce92345fb8b6aa",
        "SSDeep": "768:XYDWR",
        "Size": 52409,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 750x561, frames 3"
    }
}
```

#### Human Readable Output



### archer-list-users
***
Gets user details or list of all users.


#### Base Command

`archer-list-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | Get user by ID (leave empty to get all users) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.User.AccountStatus | String | The status of the user | 
| Archer.User.DisplayName | String | Display name of the user | 
| Archer.User.FirstName | String | The first name of the user | 
| Archer.User.Id | Number | Unique Id of user | 
| Archer.User.LastLoginDate | Date | Last login date of user | 
| Archer.User.LastName | String | The last name of the user | 
| Archer.User.MiddleName | String | The middle name of the user | 
| Archer.User.UserName | String | The username of the account | 


#### Command Example
```!archer-list-users```

#### Context Example
```
{
    "Archer": {
        "User": {
            "AccountStatus": "Locked",
            "DisplayName": "cash, johnny",
            "FirstName": "johnny",
            "Id": 202,
            "LastLoginDate": "2018-09-03T07:56:51.027",
            "LastName": "cash",
            "MiddleName": null,
            "UserName": "johnnyCash"
        }
    }
}
```

#### Human Readable Output

>### Users list
>|AccountStatus|DisplayName|FirstName|Id|LastLoginDate|LastName|MiddleName|UserName|
>|---|---|---|---|---|---|---|---|
>| Locked | cash, johnny | johnny | 202 | 2018-09-03T07:56:51.027 | cash |  | johnnyCash |


### archer-search-records
***
Search for records inside the given application


#### Base Command

`archer-search-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | Id of the application to search records in | Required | 
| fieldToSearchOn | Name of field to search on (leave empty to search for all) | Optional | 
| searchValue | Search value (leave empty to search for all) | Optional | 
| maxResults | Maximum results to return from the search (default is 10) | Optional | 
| fieldsToDisplay | Fields to present in the search results in array format (for example: "Title,Incident Summary") | Optional | 
| numericOperator | Numeric search operator | Optional | 
| dateOperator | Date search operator | Optional | 
| fieldsToGet | Fields to fetch from the the application | Optional | 
| fullData | Get an extended responses with all of the data regarding this search. For example, "fullData=true" | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.Record | Unknown | The content object | 
| Archer.Record.Id | Number | The content Id | 


#### Command Example
```!archer-search-records applicationId=75 fullData=False fieldsToDisplay=`Date/Time Occurred,Days Open` fieldsToGet=`Date/Time Occurred,Days Open` fieldToSearchOn=`Date/Time Occurred` dateOperator=GreaterThan searchValue=2018-06-23T07:00:00Z maxResults=100```

#### Context Example
```
{
    "Archer": {
        "Record": {
            "Date/Time Occurred": "2018-07-10T08:00:00Z",
            "Days Open": "30",
            "Id": "227664"
        }
    }
}
```

#### Human Readable Output

>### Search records results
>|Date/Time Occurred|Days Open|
>|---|---|
>| 2018-07-10T08:00:00Z | 30 |


### archer-search-records-by-report
***
Search records by report Guid


#### Base Command

`archer-search-records-by-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportGuid | The report GUID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Archer.SearchByReport.ReportGUID | String | The report GUID | 
| Archer.SearchByReport.RecordsAmount | Number | Amount of records found by the search | 
| Archer.SearchByReport.Record | Unknown | The records found by the search | 


#### Command Example
```!archer-search-records-by-report reportGuid=bce4222c-ecfe-4cef-a556-fe746e959f12```

#### Context Example
```
{
    "Archer": {
        "SearchByReport": {
            "Record": [
                {
                    "Description": "<p>\u00a0test_procedure_0</p>",
                    "Id": "227528",
                    "Procedure Name": "test_procedure_0",
                    "Threat Category": "Malware",
                    "Tracking ID": "227528"
                },
                {
                    "Description": "<p>\u00a0test_procedure_1</p>",
                    "Id": "227529",
                    "Procedure Name": "test_procedure_1",
                    "Threat Category": "Malware",
                    "Tracking ID": "227529"
                },
                {
                    "Description": "<p>test_procedure_2\u00a0</p>",
                    "Id": "227531",
                    "Procedure Name": "test_procedure_2",
                    "Threat Category": "Malware",
                    "Tracking ID": "227531"
                },
                {
                    "Description": "<p>test_procedure_3</p>",
                    "Id": "227532",
                    "Procedure Name": "test_procedure_3",
                    "Threat Category": "Malware",
                    "Tracking ID": "227532"
                }
            ],
            "RecordsAmount": 4,
            "ReportGUID": "bce4222c-ecfe-4cef-a556-fe746e959f12"
        }
    }
}
```

#### Human Readable Output

>### Search records by report results
>|Description|Id|Procedure Name|Threat Category|Tracking ID|
>|---|---|---|---|---|
>| <p> test_procedure_0</p> | 227528 | test_procedure_0 | Malware | 227528 |
>| <p> test_procedure_1</p> | 227529 | test_procedure_1 | Malware | 227529 |
>| <p>test_procedure_2 </p> | 227531 | test_procedure_2 | Malware | 227531 |
>| <p>test_procedure_3</p> | 227532 | test_procedure_3 | Malware | 227532 |


### archer-print-cache
***
prints Archer's integration cache.


#### Base Command

`archer-print-cache`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!archer-print-cache```

#### Context Example
```
{}
```

#### Human Readable Output

>{
>  "75": [
>    {
>      "level": 67,
>      "mapping": {
>        "10052": {
>          "FieldId": "10052",
>          "IsRequired": false,
>          "Name": "Related Incidents (2)",
>          "RelatedValuesListId": null,
>          "Type": 23
>        },
>        "10172": {
>          "FieldId": "10172",
>          "IsRequired": false,
>          "Name": "Source",
>          "RelatedValuesListId": 1176,
>          "Type": 4
>        },
>        "10183": {
>          "FieldId": "10183",
>          "IsRequired": false,
>          "Name": "Is BSA (Bank Secrecy Act) reporting required in the US?",
>          "RelatedValuesListId": 152,
>          "Type": 4
>        },
>        "10188": {
>          "FieldId": "10188",
>          "IsRequired": false,
>          "Name": "Batch File Format",
>          "RelatedValuesListId": 1183,
>          "Type": 4
>        }
>      }
>    }
>  ],
>  "fieldValueList": {
>    "7782": {
>      "FieldId": "7782",
>      "ValuesList": [
>        {
>          "Id": 6412,
>          "IsSelectable": true,
>          "Name": "New"
>        },
>        {
>          "Id": 6413,
>          "IsSelectable": true,
>          "Name": "Assigned"
>        },
>        {
>          "Id": 6414,
>          "IsSelectable": true,
>          "Name": "In Progress"
>        },
>        {
>          "Id": 6415,
>          "IsSelectable": true,
>          "Name": "On Hold"
>        },
>        {
>          "Id": 6416,
>          "IsSelectable": true,
>          "Name": "Closed"
>        }
>      ]
>    }
>  }
>}
