TOPdesk’s Enterprise Service Management software (ESM) lets your service teams join forces and process requests from a single platform.
This integration was integrated and tested with 10.08.008-on-premises-release3-build2 for Linux x86 64-bit of TOPdesk.

## Use cases
1. Get, update, and create TOPdesk incidents, as well as (de-)escalate, (un)archive or upload files to the incidents.
2. Fetch newly created TOPdesk incidents.
3. Get information about branches, persons and operators.

Test of mirroring! 1. 2. 3. 4.

## Configure TOPdesk on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TOPdesk.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://topdesk.mydomain/tas/) | The server url. | True |
    | Username | See section about auth details below | True |
    | Password | See section about auth details below | True |
    | Fetch incidents |  | False |
    | Maximum number of incidents per fetch |  | False |
    | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Default Incident Caller ID | The default caller ID which is added when creating new TOPdesk incidents and no explicit caller ID is provided. See See [Finding the Default Incident Caller ID](#finding-the-default-incident-caller-id). | False |
    | The query to use when fetching incidents | Getting incidents with new style FIQL query is available only from TOPdeskRestAPI version 3.4.0. For earlier versions this field will be used as additional inline params as supported. | False |
    | Incident type | Use *TOPdesk Incident* for some predefined layouts | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

### Auth Details
*Person* and *operator* are TOPdesk's user types. Each user type has a different set of actions that he is allowed to perform.
For example, a *person* can only update incidents he created, while an *operator* can update a wider range of incidents.

In general, if an account is able to preform the requested command in TOPdesk's UI, it should be able to preform it using this integration. 
Make sure you use the right account for your needs and that the account used has all the required permissions. 

#### Setup TOPdesk's application password
1. Login to TOPdesk with the designated account.
2. In TOPdesk, click **Open user menu** (top right side of the front page) > Choose **My settings**
3. At the bottom of the page should be an **Application passwords** section. You can view all application passwords that are configured for the logged in account. 
4. At the bottom right corner, click **Add**.
5. A window should open requesting a name for the application. Choose any convenient name (e.g., XSOAR-key) and click **Create**. 
6. The application password should be shown - copy it to a safe location. This is the password that will be used for the integration in XSOAR.
7. Once copied for further usage you can click **Close**.

#### Configure Username and Password
**Username**: Use the account username from which the application password was generated. (*Not* the key name)

**Password**: Use the application password generated in step 6 of the **Setup TOPdesk's application password** procedure. 

#### Troubleshooting
Make sure the application password is not expired by logging in TOPdesk and viewing it as described in step 3 of the **Setup TOPdesk's application password** procedure. 

### Finding the Default Incident Caller ID
The TOPdesk incident caller is the TOPdesk person who requested a specific TOPdesk incident and is the contact person for all activities related to this incident.  
To find the incident caller ID which should be used as the default caller when creating a new TOPdesk incident, first configure the integration instance *without* providing the **Default Incident Caller ID**. Then run the command `!topdesk-persons-list` in the *Playground - War Room*.  
You will receive a list of people and their IDs. Copy the ID of the desired person and edit the integration instance to set the **Default Incident Caller ID**.

### Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and TOPdesk incidents.

To setup the mirroring follow these instructions:
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for **TOPdesk** and select your integration instance.
3. Enable **Fetches incidents**.
4. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:
    - Incoming - Any changes in TOPdesk incidents (`processingStatus`, `priority`, `urgency`, `impact`) will be reflected in Cortex XSOAR incidents.
    - Outgoing - Any changes in Cortex XSOAR incidents will be reflected in TOPdesk incidents (`processingStatus`, `priority`, `urgency`, `impact`).
    - Incoming And Outgoing - Changes in Cortex XSOAR incidents and TOPdesk incidents will be reflected in both directions.
    - None - Turns off incident mirroring.
5. The *Comment Entry Tag*, *Work Note Entry Tag* and *File Entry Tag* integration parameters can be used to specify which comments and attachments should be mirrored to TOPdesk. When the tag *Comment Entry Tag* is used, the comment is visible to the operator and the person. If the tag *Work Note Entry Tag* is used, the comment is only visible to the operator and the tag *File Entry Tag* is used to mirror files from Cortex XSOAR to TOPdesk.
6. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding incident is closed in TOPdesk.
7. Optional: Check the *Close Mirrored TOPdesk Incident* integration parameter to close the TOPdesk incident when the corresponding Cortex XSOAR incident is closed.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.

**Important Notes**
 To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and TOPdesk.
 
 ### FIQL query
A few implemented commands can get a query as a parameter. A partial list of these commands: 
- `topdesk-incidents-list`
- `topdesk-branches-list` 
- `topdesk-persons-list` 
- `topdesk-operators-list`

While the new versions of TOPdesk all use the new [FIQL query format](https://developers.topdesk.com/tutorial.html#query), older versions use limited inline parameters for filters in the requests.
Specifically there are 2 versions being used:
#### [TOPdeskRestAPI](https://developers.topdesk.com/documentation/index.html) 
Implements: `topdesk-incidents-list`

Supports FIQL query version `3.3.0` and higher.

Conveniently, TOPdeskRestAPI also provides an endpoint revealing the API version. 
Therefore, once the integration is configured, it automatically translates FIQL query to 
inline parameters and vice versa depending on the TOPdesk version.

#### [SupportingFilesAPI](https://developers.topdesk.com/explorer/?page=supporting-files) 
Implements: `topdesk-branches-list`, `topdesk-persons-list`, `topdesk-operators-list`

Supports FIQL query version `1.38.0` and higher.

Unlike TOPdeskRestAPI, SupportingFilesAPI does not currently provide an endpoint revealing the API version.
Therefore, this integration only supports SupportingFilesAPI version `1.38.0` and higher. 

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### topdesk-subcategories-list
***
Get list of subcategories.

#### Permissions
**Operator**: 1st/2nd line incident permissions; Category/Branch/Operator filters apply.

**Person**: Unrestricted access.

#### Base Command

`topdesk-subcategories-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of subcategories to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Subcategory.Id | String | Subcategory ID. | 
| TOPdesk.Subcategory.Name | String | Subcategory name. | 
| TOPdesk.Subcategory.Category.Id | String | Category ID of the subcategory. | 
| TOPdesk.Subcategory.Category.Name | String | Category name of the subcategory. | 


#### Command Example
```!topdesk-subcategories-list```

#### Context Example
```json
{
    "TOPdesk": {
        "Subcategories": [
            {
                "Category": {
                    "Id": "some-category-id-1",
                    "Name": "User Security"
                },
                "Id": "some-subcategory-id-1",
                "Name": "Endpoint Security"
            },
            {
                "Category": {
                    "Id": "some-category-id-1",
                    "Name": "User Security"
                },
                "Id": "some-subcategory-id-2",
                "Name": "Mobile Threat Prevention"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk subcategories
>|Id|Name|CategoryId|CategoryName|
>|---|---|---|---|
>| some-subcategory-id-1 | Endpoint Security | some-category-id | User Security |
>| some-subcategory-id-2 | Mobile Threat Prevention | some-category-id | User Security |

### topdesk-categories-list
***
Get list of categories.

#### Permissions
**Operator**: With 1st/2nd line incident permission; Category/Branch/Operator filters apply

**Person**: Unrestricted access

#### Base Command

`topdesk-categories-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of categories to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Category.Id | String | Category ID. | 
| TOPdesk.Category.Name | String | Category name. | 


#### Command Example
```!topdesk-categories-list```

#### Context Example
```json
{
    "TOPdesk": {
        "Category": [
            {
                "Id": "some-category-id-1",
                "Name": "User Security"
            },
            {
                "Id": "some-category-id-2",
                "Name": "Network Security"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk categories
>|Id|Name|
>|---|---|
>| some-category-id-1 | User Security |
>| some-category-id-2 | Network Security |


### topdesk-entry-types-list
***
Get list of entry types.

#### Permissions
**Operator**: With 1st/2nd line incident permission; Category/Branch/Operator filters apply

**Person**: No access

#### Base Command

`topdesk-entry-types-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of entry types to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.EntryType.Id | String | EntryType ID. | 
| TOPdesk.EntryType.Name | String | EntryType name. | 


#### Command Example
```!topdesk-entry-types-list```

#### Context Example
```json
{
    "TOPdesk": {
        "EntryType": [
            {
                "Id": "some-entry-type-id-1",
                "Name": "Self Service Desk"
            },
            {
                "Id": "some-entry-type-id-2",
                "Name": "Telephone"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk entry types
>|Id|Name|
>|---|---|
>| some-entry-type-id-1 | Self Service Desk |
>| some-entry-type-id-2 | Telephone |


### topdesk-call-types-list
***
Get list of entry types.

#### Permissions
**Operator**: With 1st/2nd line incident permission; Category/Branch/Operator filters apply

**Person**: Unrestricted access

#### Base Command

`topdesk-call-types-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of call types to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.CallType.Id | String | CallType ID. | 
| TOPdesk.CallType.Name | String | CallType name. | 


#### Command Example
```!topdesk-call-types-list```

#### Context Example
```json
{
    "TOPdesk": {
        "CallType": [
            {
                "Id": "some-call-type-id-1",
                "Name": "Request for Information"
            },
            {
                "Id": "some-call-type-id-2",
                "Name": "Problem"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk call types
>|Id|Name|
>|---|---|
>| some-call-type-id-1 | Request for Information |
>| some-call-type-id-2 | Problem |


### topdesk-deescalation-reasons-list
***
Get list of deescalation reasons.

#### Permissions
**Operator**: With 1st and 2nd line incident write permission; Feature must be enabled.

**Person**: No access

#### Base Command

`topdesk-deescalation-reasons-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of deescalation reasons to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.DeescalationReason.Id | String | Deescalation reason ID. | 
| TOPdesk.DeescalationReason.Name | String | Deescalation reason name. | 


#### Command Example
```!topdesk-deescalation-reasons-list```

#### Context Example
```json
{
    "TOPdesk": {
        "DeescalationReason": [
            {
                "Id": "some-deescalation-reason-id-1",
                "Name": "Resolves after reset"
            },
            {
                "Id": "some-deescalation-reason-id-2",
                "Name": "Workaround exists"
            }
        ]
    }
}
```

#### Human Readable Output
>|Id|Name|
>|---|---|
>| some-deescalation-reason-id-1 | Resolves after reset |
>| some-deescalation-reason-id-2 | Workaround exists |


### topdesk-escalation-reasons-list
***
Get list of escalation reasons.

#### Permissions
**Operator**: With 1st line incident write permission and write permission for escalating incidents

**Person**: No access

#### Base Command

`topdesk-escalation-reasons-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of escalation reasons to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.EscalationReason.Id | String | Escalation reason ID. | 
| TOPdesk.EscalationReason.Name | String | Escalation reason name. | 


#### Command Example
```!topdesk-escalation-reasons-list```

#### Context Example
```json
{
    "TOPdesk": {
        "EscalationReason": [
            {
                "Id": "some-escalation-reason-id-1",
                "Name": "Call from president"
            },
            {
                "Id": "some-escalation-reason-id-2",
                "Name": "Money is being lost"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk escalation reasons
>|Id|Name|
>|---|---|
>| some-escalation-reason-id-1 | Call from president |
>| some-escalation-reason-id-2 | Money is being lost |


### topdesk-archiving-reasons-list
***
Get list of archiving reasons.

#### Permissions
**Operator**: Incident write permission and archiving permission; Category/Branch/Operator filters apply;

**Person**: No access

#### Base Command

`topdesk-archiving-reasons-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the amount of archiving reasons to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.ArchiveReason.Id | String | Archiving reason ID. | 
| TOPdesk.ArchiveReason.Name | String | Archiving reason name. | 


#### Command Example
```!topdesk-archiving-reasons-list```

#### Context Example
```json
{
    "TOPdesk": {
        "ArchiveReason": [
            {
                "Id": "some-archive-reason-id-1",
                "Name": "No longer valid"
            },
            {
                "Id": "some-archive-reason-id-2",
                "Name": "No longer employed"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk archiving reasons
>|Id|Name|
>|---|---|
>| some-archive-reason-id-1 | No longer valid |
>| some-archive-reason-id-2 | No longer employed |


### topdesk-persons-list
***
Get list of persons.

#### Permissions
**Operator**: With read permission on persons; Branch filters apply

Visible fields in response: all

**Person**: Only accessible when phonebook is enabled.
 
Visible fields in response: id, dynamicName, phoneNumber, mobileNumber, fax, email, jobTitle, department, department.id, department.name, city, departmentFree, branch, branch.id, branch.name, location, location.id, location.branch, location.branch.id, location.branch.name, location.name, location.room
 
#### Base Command

`topdesk-persons-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The offset at which to start listing the persons at. Must be greater or equal to 0. Default is 0. | Optional | 
| page_size | The amount of persons to be returned per request. Must be between 1 and 100. Default is 10. | Optional | 
| query | A FIQL search expression to filter the result. (e.g., manager.name==Alice) Available from Supporting-Files-API version 1.38.0. The FIQL query syntax is documented in the TOPdesk tutorial. | Optional | 
| fields | A comma-separated list of which fields should be included. By default all fields will be included. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Person.Id | String | Person ID. | 
| TOPdesk.Person.Status | String | Person status. | 
| TOPdesk.Person.SurName | String | Person's surname. | 
| TOPdesk.Person.FirstName | String | Person's first name. | 
| TOPdesk.Person.DynamicName | String | Person's dynamic name \(firstName SecondName\). | 
| TOPdesk.Person.FirstInitials | String | Person's first initials. | 
| TOPdesk.Person.Prefixes | String | Person's prefixes \(e.g., DR, MR\) | 
| TOPdesk.Person.BirthName | String | Person's birth name. | 
| TOPdesk.Person.Title | String | Person's title. | 
| TOPdesk.Person.Gender | String | Person's gender. | 
| TOPdesk.Person.Language.Id | String | Person's language ID. | 
| TOPdesk.Person.Language.Name | String | Person's language name. | 
| TOPdesk.Person.PhoneNumber | String | Person's phone number. | 
| TOPdesk.Person.MobileNumber | String | Person's mobile number. | 
| TOPdesk.Person.Fax | String | Person's fax. | 
| TOPdesk.Person.Email | String | Person's email. | 
| TOPdesk.Person.JobTitle | String | Person's job title. | 
| TOPdesk.Person.Department | Unknown | Person's department. | 
| TOPdesk.Person.BudgetHolder | Unknown | Person's budget holder. | 
| TOPdesk.Person.EmployeeNumber | String | Person's employee number. | 
| TOPdesk.Person.NetworkLoginName | String | Person's network login name. | 
| TOPdesk.Person.MainframeLoginName | String | Person's mainframe login name. | 
| TOPdesk.Person.ClientReferenceNumber | String | Person's client reference number. | 
| TOPdesk.Person.City | String | Person's city. | 
| TOPdesk.Person.TasLoginName | String | Person's tas login name. | 
| TOPdesk.Person.ShowBranch | Boolean | Person's branch visibility. | 
| TOPdesk.Person.ShowBudgetholder | Boolean | Person's budget holder visibility. | 
| TOPdesk.Person.ShowDepartment | Boolean | Person's department visibility. | 
| TOPdesk.Person.ShowSubsidiaries | Boolean | Person's subsidiaries visibility. | 
| TOPdesk.Person.ShowAllBranches | Boolean | Person's all branches visibility. | 
| TOPdesk.Person.AuthorizeAll | Boolean | Person authorization on everything. | 
| TOPdesk.Person.AuthorizeDepartment | Boolean | Person authorization on department. | 
| TOPdesk.Person.AuthorizeBudgetHolder | Boolean | Person's authorization on budget holder. | 
| TOPdesk.Person.AuthorizeBranch | Boolean | Person's authorization on branch. | 
| TOPdesk.Person.AuthorizeSubsidiaryBranches | Boolean | Person's authorization on subsidiary branches. | 
| TOPdesk.Person.IsManager | Boolean | Is the person manager. | 
| TOPdesk.Person.Manager | Unknown | Person's manager. | 
| TOPdesk.Person.HasAttention | Boolean | Does the person have attention. | 
| TOPdesk.Person.Attention | Unknown | Person's attention object. | 
| TOPdesk.Person.AttentionComment | String | Person's attention comment. | 
| TOPdesk.Person.Creator.Id | String | Person's creator ID. | 
| TOPdesk.Person.Creator.Name | String | Person's creator name. | 
| TOPdesk.Person.CreationDate | Date | Person's creation date. | 
| TOPdesk.Person.Modifier.Id | String | Person's modifier ID. | 
| TOPdesk.Person.Modifier.Name | String | Person's modifier name. | 
| TOPdesk.Person.ModificationDate | Date | Person's modification date. | 
| TOPdesk.Person.OptionalFields1.Boolean1 | Boolean | Person's optional fields1 boolean1. | 
| TOPdesk.Person.OptionalFields1.Boolean2 | Boolean | Person's optional fields1 boolean2. | 
| TOPdesk.Person.OptionalFields1.Boolean3 | Boolean | Person's optional fields1 boolean3. | 
| TOPdesk.Person.OptionalFields1.Boolean4 | Boolean | Person's optional fields1 boolean4. | 
| TOPdesk.Person.OptionalFields1.Boolean5 | Boolean | Person's optional fields1 boolean5. | 
| TOPdesk.Person.OptionalFields1.Number1 | Number | Person's optional fields1 number1. | 
| TOPdesk.Person.OptionalFields1.Number2 | Number | Person's optional fields1 number2. | 
| TOPdesk.Person.OptionalFields1.Number3 | Number | Person's optional fields1 number3. | 
| TOPdesk.Person.OptionalFields1.Number4 | Number | Person's optional fields1 number4. | 
| TOPdesk.Person.OptionalFields1.Number5 | Number | Person's optional fields1 number5. | 
| TOPdesk.Person.OptionalFields1.Date1 | Unknown | Person's optional fields1 date1. | 
| TOPdesk.Person.OptionalFields1.Date2 | Unknown | Person's optional fields1 date2. | 
| TOPdesk.Person.OptionalFields1.Date3 | Unknown | Person's optional fields1 date3. | 
| TOPdesk.Person.OptionalFields1.Date4 | Unknown | Person's optional fields1 date4. | 
| TOPdesk.Person.OptionalFields1.Date5 | Unknown | Person's optional fields1 date5. | 
| TOPdesk.Person.OptionalFields1.Text1 | String | Person's optional fields1 text1. | 
| TOPdesk.Person.OptionalFields1.Text2 | String | Person's optional fields1 text2. | 
| TOPdesk.Person.OptionalFields1.Text3 | String | Person's optional fields1 text3. | 
| TOPdesk.Person.OptionalFields1.Text4 | String | Person's optional fields1 text4. | 
| TOPdesk.Person.OptionalFields1.Text5 | String | Person's optional fields1 text5. | 
| TOPdesk.Person.OptionalFields1.Memo1 | Unknown | Person's optional fields1 memo1. | 
| TOPdesk.Person.OptionalFields1.Memo2 | Unknown | Person's optional fields1 memo2. | 
| TOPdesk.Person.OptionalFields1.Memo3 | Unknown | Person's optional fields1 memo3. | 
| TOPdesk.Person.OptionalFields1.Memo4 | Unknown | Person's optional fields1 memo4. | 
| TOPdesk.Person.OptionalFields1.Memo5 | Unknown | Person's optional fields1 memo5. | 
| TOPdesk.Person.OptionalFields1.Searchlist1 | Unknown | Person's optional fields1 searchlist1. | 
| TOPdesk.Person.OptionalFields1.Searchlist2 | Unknown | Person's optional fields1 searchlist2. | 
| TOPdesk.Person.OptionalFields1.Searchlist3 | Unknown | Person's optional fields1 searchlist3. | 
| TOPdesk.Person.OptionalFields1.Searchlist4 | Unknown | Person's optional fields1 searchlist4. | 
| TOPdesk.Person.OptionalFields1.Searchlist5 | Unknown | Person's optional fields1 searchlist5. | 
| TOPdesk.Person.OptionalFields2.Boolean1 | Boolean | Person's optional fields2 boolean1. | 
| TOPdesk.Person.OptionalFields2.Boolean2 | Boolean | Person's optional fields2 boolean2. | 
| TOPdesk.Person.OptionalFields2.Boolean3 | Boolean | Person's optional fields2 boolean3. | 
| TOPdesk.Person.OptionalFields2.Boolean4 | Boolean | Person's optional fields2 boolean4. | 
| TOPdesk.Person.OptionalFields2.Boolean5 | Boolean | Person's optional fields2 boolean5. | 
| TOPdesk.Person.OptionalFields2.Number1 | Number | Person's optional fields2 number1. | 
| TOPdesk.Person.OptionalFields2.Number2 | Number | Person's optional fields2 number2. | 
| TOPdesk.Person.OptionalFields2.Number3 | Number | Person's optional fields2 number3. | 
| TOPdesk.Person.OptionalFields2.Number4 | Number | Person's optional fields2 number4. | 
| TOPdesk.Person.OptionalFields2.Number5 | Number | Person's optional fields2 number5. | 
| TOPdesk.Person.OptionalFields2.Date1 | Unknown | Person's optional fields2 date1. | 
| TOPdesk.Person.OptionalFields2.Date2 | Unknown | Person's optional fields2 date2. | 
| TOPdesk.Person.OptionalFields2.Date3 | Unknown | Person's optional fields2 date3. | 
| TOPdesk.Person.OptionalFields2.Date4 | Unknown | Person's optional fields2 date4. | 
| TOPdesk.Person.OptionalFields2.Date5 | Unknown | Person's optional fields2 date5. | 
| TOPdesk.Person.OptionalFields2.Text1 | String | Person's optional fields2 text1. | 
| TOPdesk.Person.OptionalFields2.Text2 | String | Person's optional fields2 text2. | 
| TOPdesk.Person.OptionalFields2.Text3 | String | Person's optional fields2 text3. | 
| TOPdesk.Person.OptionalFields2.Text4 | String | Person's optional fields2 text4. | 
| TOPdesk.Person.OptionalFields2.Text5 | String | Person's optional fields2 text5. | 
| TOPdesk.Person.OptionalFields2.Memo1 | Unknown | Person's optional fields2 memo1. | 
| TOPdesk.Person.OptionalFields2.Memo2 | Unknown | Person's optional fields2 memo2. | 
| TOPdesk.Person.OptionalFields2.Memo3 | Unknown | Person's optional fields2 memo3. | 
| TOPdesk.Person.OptionalFields2.Memo4 | Unknown | Person's optional fields2 memo4. | 
| TOPdesk.Person.OptionalFields2.Memo5 | Unknown | Person's optional fields2 memo5. | 
| TOPdesk.Person.OptionalFields2.Searchlist1 | Unknown | Person's optional fields2 searchlist1. | 
| TOPdesk.Person.OptionalFields2.Searchlist2 | Unknown | Person's optional fields2 searchlist2. | 
| TOPdesk.Person.OptionalFields2.Searchlist3 | Unknown | Person's optional fields2 searchlist3. | 
| TOPdesk.Person.OptionalFields2.Searchlist4 | Unknown | Person's optional fields2 searchlist4. | 
| TOPdesk.Person.OptionalFields2.Searchlist5 | Unknown | Person's optional fields2 searchlist5. | 
| TOPdesk.Person.PersonExtraFieldA | Unknown | Person's extra field A. | 
| TOPdesk.Person.PersonExtraFieldB | Unknown | Person's extra field B. | 
| TOPdesk.Person.DepartmentFree | Unknown | Person's department free. | 
| TOPdesk.Person.Branch.Id | String | Person's branch ID. | 
| TOPdesk.Person.Branch.Name | String | Person's branch name. | 
| TOPdesk.Person.Branch.ClientReferenceNumber | String | Person's branch client reference number. | 
| TOPdesk.Person.Branch.TimeZone | String | Person's branch timezone. | 
| TOPdesk.Person.Branch.ExtraA.Id | String | Person's branch extra A ID. | 
| TOPdesk.Person.Branch.ExtraA.Name | String | Person's branch extra A name. | 
| TOPdesk.Person.Branch.ExtraB | Unknown | Person's branch extra B. | 
| TOPdesk.Person.Branch.ExtraB.Id | String | Person's branch extra B ID. | 
| TOPdesk.Person.Branch.ExtraB.Name | String | Person's branch extra B name. | 
| TOPdesk.Person.Location | Unknown | Person's location. | 


#### Command Example
```!topdesk-persons-list```

#### Context Example
```json
{
    "TOPdesk": {
        "Person": [
            {
                "AttentionComment": "",
                "AuthorizeAll": false,
                "AuthorizeBranch": false,
                "AuthorizeBudgetHolder": false,
                "AuthorizeDepartment": false,
                "AuthorizeSubsidiaryBranches": false,
                "BirthName": "",
                "Branch": {
                    "ClientReferenceNumber": "1337",
                    "ExtraA": {
                        "Id": "some-extra-id",
                        "Name": "Building in progress"
                    },
                    "Id": "some-branch-id-1",
                    "Name": "HQ",
                    "TimeZone": ""
                },
                "City": "",
                "ClientReferenceNumber": "1337",
                "CreationDate": "2020-12-21T09:16:34.000+0000",
                "Creator": {
                    "Id": "some-admin-id",
                    "Name": "TOPdesk Admin"
                },
                "DynamicName": "Xsoar - User - A",
                "Email": "",
                "EmployeeNumber": "",
                "Fax": "",
                "FirstInitials": "",
                "FirstName": "Xsoar -",
                "Gender": "UNDEFINED",
                "HasAttention": false,
                "Id": "some-user-id-a",
                "IsManager": false,
                "JobTitle": "",
                "Language": {
                    "Id": "some-eng-lng-id",
                    "Name": "ENG"
                },
                "MainframeLoginName": "",
                "MobileNumber": "",
                "ModificationDate": "2020-12-21T09:20:53.000+0000",
                "Modifier": {
                    "Id": "some-admin-id",
                    "Name": "TOPdesk Admin"
                },
                "NetworkLoginName": "",
                "OptionalFields1": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "OptionalFields2": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "PhoneNumber": "",
                "Prefixes": "",
                "ShowAllBranches": false,
                "ShowBranch": true,
                "ShowBudgetholder": false,
                "ShowDepartment": false,
                "ShowSubsidiaries": false,
                "Status": "person",
                "SurName": "User - A",
                "TasLoginName": "xsoar-user-a",
                "Title": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk persons
>|Id|Name|BranchName|
>|---|---|---|
>| some-user-id-a | Xsoar - User - A | XSoar - Customer - A |
>| some-user-id-b | Xsoar - User - B | Xsoar - Customer - B |


### topdesk-operators-list
***
Get list of operators.

#### Permissions
**Operator**: With read permission on operators; Branch/Operator filters apply

**Person**: No access

#### Base Command

`topdesk-operators-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The offset at which to start listing the operators at. Must be greater or equal to 0. Default is 0. | Optional | 
| page_size | The amount of operators to be returned per request. Must be between 1 and 100. Default is 10. | Optional | 
| query | A FIQL search expression to filter the result. (e.g., manager.name==Alice) Available from Supporting-Files-API version 1.38.0. The FIQL query syntax is documented in the TOPdesk tutorial. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Operator.Id | String | Operator's ID. | 
| TOPdesk.Operator.PrincipalId | String | Operator's principal ID. | 
| TOPdesk.Operator.Status | String | Operator's status. | 
| TOPdesk.Operator.SurName | String | Operator's surname. | 
| TOPdesk.Operator.FirstName | String | Operator's first name. | 
| TOPdesk.Operator.DynamicName | String | Operator's dynamic name. | 
| TOPdesk.Operator.Initials | String | Operator's initials. | 
| TOPdesk.Operator.Prefixes | String | Operator's prefixes. | 
| TOPdesk.Operator.BirthName | String | Operator's birth name. | 
| TOPdesk.Operator.Title | String | Operator's title. | 
| TOPdesk.Operator.Gender | String | Operator's gender. | 
| TOPdesk.Operator.Language.Id | String | Operator's language ID. | 
| TOPdesk.Operator.Language.Name | String | Operator's language name. | 
| TOPdesk.Operator.Branch.Id | String | Operator's branch ID. | 
| TOPdesk.Operator.Branch.Name | String | Operator's branch name. | 
| TOPdesk.Operator.Branch.ClientReferenceNumber | String | Operator's Branch Client reference number. | 
| TOPdesk.Operator.Branch.TimeZone | String | Operator's branch timezone. | 
| TOPdesk.Operator.Branch.ExtraA.Id | String | Operator's branch extra A ID. | 
| TOPdesk.Operator.Branch.ExtraA.Name | String | Operator's branch extra A name. | 
| TOPdesk.Operator.Branch.ExtraB.Id | String | Operator's branch extra B ID. | 
| TOPdesk.Operator.Branch.ExtraB.Name | String | Operator's branch extra B name. | 
| TOPdesk.Operator.Location | Unknown | Operator's location. | 
| TOPdesk.Operator.Telephone | String | Operator's telephone. | 
| TOPdesk.Operator.MobileNumber | String | Operator's mobile number. | 
| TOPdesk.Operator.FaxNumber | String | Operator's fax number. | 
| TOPdesk.Operator.Email | String | Operator's email. | 
| TOPdesk.Operator.ExchangeAccount | String | Operator's exchange account. | 
| TOPdesk.Operator.LoginName | String | Operator's login name. | 
| TOPdesk.Operator.LoginPermission | Boolean | Operator's login permission. | 
| TOPdesk.Operator.JobTitle | String | Operator's job title. | 
| TOPdesk.Operator.Department | Unknown | Operator's department. | 
| TOPdesk.Operator.BudgetHolder | Unknown | Operator's budget holder. | 
| TOPdesk.Operator.EmployeeNumber | String | Operator's employee number. | 
| TOPdesk.Operator.HourlyRate | Number | Operator's hourly rate. | 
| TOPdesk.Operator.NetworkLoginName | String | Operator's network login name. | 
| TOPdesk.Operator.MainframeLoginName | String | Operator's mainframe login name. | 
| TOPdesk.Operator.HasAttention | Boolean | Operator's has attention. | 
| TOPdesk.Operator.Attention | Unknown | Operator's attention. | 
| TOPdesk.Operator.Comments | String | Operator's comments. | 
| TOPdesk.Operator.Installer | Boolean | Operator's installer. | 
| TOPdesk.Operator.FirstLineCallOperator | Boolean | Operator's first line call operator. | 
| TOPdesk.Operator.SecondLineCallOperator | Boolean | Operator's second line call operator. | 
| TOPdesk.Operator.ProblemManager | Boolean | Operator's problem manager. | 
| TOPdesk.Operator.ProblemOperator | Boolean | Operator's problem operator. | 
| TOPdesk.Operator.ChangeCoordinator | Boolean | Operator's change coordinator. | 
| TOPdesk.Operator.ChangeActivitiesOperator | Boolean | Operator's change activities operator. | 
| TOPdesk.Operator.RequestForChangeOperator | Boolean | Operator's request for change operator. | 
| TOPdesk.Operator.ExtensiveChangeOperator | Boolean | Operator's extensive change operator. | 
| TOPdesk.Operator.SimpleChangeOperator | Boolean | Operator's simple change operator. | 
| TOPdesk.Operator.ScenarioManager | Boolean | Operator's scenario manager. | 
| TOPdesk.Operator.PlanningActivityManager | Boolean | Operator's planning activity manager. | 
| TOPdesk.Operator.ProjectCoordinator | Boolean | Operator's project coordinator. | 
| TOPdesk.Operator.ProjectActiviesOperator | Boolean | Operator's project activities operator. | 
| TOPdesk.Operator.StockManager | Boolean | Operator's stock manager. | 
| TOPdesk.Operator.ReservationsOperator | Boolean | Operator's reservations operator. | 
| TOPdesk.Operator.ServiceOperator | Boolean | Operator's service operator. | 
| TOPdesk.Operator.ExternalHelpDeskParty | Boolean | Operator's external help desk party. | 
| TOPdesk.Operator.ContractManager | Boolean | Operator's contract manager. | 
| TOPdesk.Operator.OperationsOperator | Boolean | Operator's operations operator. | 
| TOPdesk.Operator.OperationsManager | Boolean | Operator's operations manager. | 
| TOPdesk.Operator.KnowledgeBaseManager | Boolean | Operator's knowledge base manager. | 
| TOPdesk.Operator.AccountManager | Boolean | Operator's account manager. | 
| TOPdesk.Operator.CreationDate | Date | Operator's creation date. | 
| TOPdesk.Operator.Creator.Id | String | Operator's creator ID. | 
| TOPdesk.Operator.Creator.Name | String | Operator's creator name. | 
| TOPdesk.Operator.ModificationDate | Date | Operator's modification date. | 
| TOPdesk.Operator.Modifier.Id | String | Operator's modifier ID. | 
| TOPdesk.Operator.Modifier.Name | String | Operator's modifier name. | 
| TOPdesk.Operator.OptionalFields1.Boolean1 | Boolean | Operator's optional fields1 boolean1. | 
| TOPdesk.Operator.OptionalFields1.Boolean2 | Boolean | Operator's optional fields1 boolean2. | 
| TOPdesk.Operator.OptionalFields1.Boolean3 | Boolean | Operator's optional fields1 boolean3. | 
| TOPdesk.Operator.OptionalFields1.Boolean4 | Boolean | Operator's optional fields1 boolean4. | 
| TOPdesk.Operator.OptionalFields1.Boolean5 | Boolean | Operator's optional fields1 boolean5. | 
| TOPdesk.Operator.OptionalFields1.Number1 | Number | Operator's optional fields1 number1. | 
| TOPdesk.Operator.OptionalFields1.Number2 | Number | Operator's optional fields1 number2. | 
| TOPdesk.Operator.OptionalFields1.Number3 | Number | Operator's optional fields1 number3. | 
| TOPdesk.Operator.OptionalFields1.Number4 | Number | Operator's optional fields1 number4. | 
| TOPdesk.Operator.OptionalFields1.Number5 | Number | Operator's optional fields1 number5. | 
| TOPdesk.Operator.OptionalFields1.Date1 | Unknown | Operator's optional fields1 date1. | 
| TOPdesk.Operator.OptionalFields1.Date2 | Unknown | Operator's optional fields1 date2. | 
| TOPdesk.Operator.OptionalFields1.Date3 | Unknown | Operator's optional fields1 date3. | 
| TOPdesk.Operator.OptionalFields1.Date4 | Unknown | Operator's optional fields1 date4. | 
| TOPdesk.Operator.OptionalFields1.Date5 | Unknown | Operator's optional fields1 date5. | 
| TOPdesk.Operator.OptionalFields1.Text1 | String | Operator's optional fields1 text1. | 
| TOPdesk.Operator.OptionalFields1.Text2 | String | Operator's optional fields1 text2. | 
| TOPdesk.Operator.OptionalFields1.Text3 | String | Operator's optional fields1 text3. | 
| TOPdesk.Operator.OptionalFields1.Text4 | String | Operator's optional fields1 text4. | 
| TOPdesk.Operator.OptionalFields1.Text5 | String | Operator's optional fields1 text5. | 
| TOPdesk.Operator.OptionalFields1.Memo1 | Unknown | Operator's optional fields1 memo1. | 
| TOPdesk.Operator.OptionalFields1.Memo2 | Unknown | Operator's optional fields1 memo2. | 
| TOPdesk.Operator.OptionalFields1.Memo3 | Unknown | Operator's optional fields1 memo3. | 
| TOPdesk.Operator.OptionalFields1.Memo4 | Unknown | Operator's optional fields1 memo4. | 
| TOPdesk.Operator.OptionalFields1.Memo5 | Unknown | Operator's optional fields1 memo5. | 
| TOPdesk.Operator.OptionalFields1.Searchlist1 | Unknown | Operator's optional fields1 searchlist1. | 
| TOPdesk.Operator.OptionalFields1.Searchlist2 | Unknown | Operator's optional fields1 searchlist2. | 
| TOPdesk.Operator.OptionalFields1.Searchlist3 | Unknown | Operator's optional fields1 searchlist3. | 
| TOPdesk.Operator.OptionalFields1.Searchlist4 | Unknown | Operator's optional fields1 searchlist4. | 
| TOPdesk.Operator.OptionalFields1.Searchlist5 | Unknown | Operator's optional fields1 searchlist5. | 
| TOPdesk.Operator.OptionalFields2.Boolean1 | Boolean | Operator's optional fields2 boolean1. | 
| TOPdesk.Operator.OptionalFields2.Boolean2 | Boolean | Operator's optional fields2 boolean2. | 
| TOPdesk.Operator.OptionalFields2.Boolean3 | Boolean | Operator's optional fields2 boolean3. | 
| TOPdesk.Operator.OptionalFields2.Boolean4 | Boolean | Operator's optional fields2 boolean4. | 
| TOPdesk.Operator.OptionalFields2.Boolean5 | Boolean | Operator's optional fields2 boolean5. | 
| TOPdesk.Operator.OptionalFields2.Number1 | Number | Operator's optional fields2 number1. | 
| TOPdesk.Operator.OptionalFields2.Number2 | Number | Operator's optional fields2 number2. | 
| TOPdesk.Operator.OptionalFields2.Number3 | Number | Operator's optional fields2 number3. | 
| TOPdesk.Operator.OptionalFields2.Number4 | Number | Operator's optional fields2 number4. | 
| TOPdesk.Operator.OptionalFields2.Number5 | Number | Operator's optional fields2 number5. | 
| TOPdesk.Operator.OptionalFields2.Date1 | Unknown | Operator's optional fields2 date1. | 
| TOPdesk.Operator.OptionalFields2.Date2 | Unknown | Operator's optional fields2 date2. | 
| TOPdesk.Operator.OptionalFields2.Date3 | Unknown | Operator's optional fields2 date3. | 
| TOPdesk.Operator.OptionalFields2.Date4 | Unknown | Operator's optional fields2 date4. | 
| TOPdesk.Operator.OptionalFields2.Date5 | Unknown | Operator's optional fields2 date5. | 
| TOPdesk.Operator.OptionalFields2.Text1 | String | Operator's optional fields2 text1. | 
| TOPdesk.Operator.OptionalFields2.Text2 | String | Operator's optional fields2 text2. | 
| TOPdesk.Operator.OptionalFields2.Text3 | String | Operator's optional fields2 text3. | 
| TOPdesk.Operator.OptionalFields2.Text4 | String | Operator's optional fields2 text4. | 
| TOPdesk.Operator.OptionalFields2.Text5 | String | Operator's optional fields2 text5. | 
| TOPdesk.Operator.OptionalFields2.Memo1 | Unknown | Operator's optional fields2 memo1. | 
| TOPdesk.Operator.OptionalFields2.Memo2 | Unknown | Operator's optional fields2 memo2. | 
| TOPdesk.Operator.OptionalFields2.Memo3 | Unknown | Operator's optional fields2 memo3. | 
| TOPdesk.Operator.OptionalFields2.Memo4 | Unknown | Operator's optional fields2 memo4. | 
| TOPdesk.Operator.OptionalFields2.Memo5 | Unknown | Operator's optional fields2 memo5. | 
| TOPdesk.Operator.OptionalFields2.Searchlist1 | Unknown | Operator's optional fields2 searchlist1. | 
| TOPdesk.Operator.OptionalFields2.Searchlist2 | Unknown | Operator's optional fields2 searchlist2. | 
| TOPdesk.Operator.OptionalFields2.Searchlist3 | Unknown | Operator's optional fields2 searchlist3. | 
| TOPdesk.Operator.OptionalFields2.Searchlist4 | Unknown | Operator's optional fields2 searchlist4. | 
| TOPdesk.Operator.OptionalFields2.Searchlist5 | Unknown | Operator's optional fields2 searchlist5. | 


#### Command Example
```!topdesk-operators-list```

#### Context Example
```json
{
    "TOPdesk": {
        "Operator": {
            "AccountManager": false,
            "BirthName": "",
            "Branch": {
                "ClientReferenceNumber": "1337",
                "ExtraA": {
                    "Id": "some-extra-id",
                    "Name": "Building in progress"
                },
                "Id": "some-branch-id-1",
                "Name": "HQ",
                "TimeZone": ""
            },
            "ChangeActivitiesOperator": false,
            "ChangeCoordinator": false,
            "Comments": "",
            "ContractManager": false,
            "CreationDate": "2020-12-21T09:24:35.000+0000",
            "Creator": {
                "Id": "some-admin-id",
                "Name": "TOPdesk Admin"
            },
            "DynamicName": "Xsoar - Operator",
            "Email": "xsoar-dev@example.com",
            "EmployeeNumber": "",
            "ExchangeAccount": "xsoar-dev@example.com",
            "ExtensiveChangeOperator": false,
            "ExternalHelpDeskParty": false,
            "FaxNumber": "",
            "FirstLineCallOperator": true,
            "FirstName": "Xsoar -",
            "Gender": "UNDEFINED",
            "HasAttention": false,
            "Id": "some-operator-id",
            "Initials": "",
            "Installer": false,
            "JobTitle": "",
            "KnowledgeBaseManager": false,
            "Language": {
                "Id": "some-eng-lng-id",
                "Name": "ENG"
            },
            "LoginName": "XSOAR-OPERATOR",
            "LoginPermission": true,
            "MainframeLoginName": "",
            "MobileNumber": "",
            "ModificationDate": "2020-12-21T09:24:35.000+0000",
            "Modifier": {
                "Id": "some-admin-id",
                "Name": "TOPdesk Admin"
            },
            "NetworkLoginName": "",
            "OperationsManager": false,
            "OperationsOperator": false,
            "OptionalFields1": {
                "Text1": "",
                "Text2": "",
                "Text3": "",
                "Text4": "",
                "Text5": ""
            },
            "OptionalFields2": {
                "Text1": "",
                "Text2": "",
                "Text3": "",
                "Text4": "",
                "Text5": ""
            },
            "PlanningActivityManager": false,
            "Prefixes": "",
            "PrincipalId": "some-principal-id",
            "ProblemManager": false,
            "ProblemOperator": false,
            "ProjectActiviesOperator": false,
            "ProjectCoordinator": false,
            "RequestForChangeOperator": false,
            "ReservationsOperator": false,
            "ScenarioManager": false,
            "SecondLineCallOperator": true,
            "ServiceOperator": false,
            "SimpleChangeOperator": false,
            "Status": "operator",
            "StockManager": false,
            "SurName": "Operator",
            "Telephone": "",
            "Title": ""
        }
    }
}
```

#### Human Readable Output

>### TOPdesk operators
>|Id|Name|BranchName|
>|---|---|---|
>| some-operator-id | Xsoar - Operator | HQ |


### topdesk-branches-list
***
Get list of branches.

#### Permissions
**Operator**: Branch filters apply

**Person**: Only accessible when branches are editable in the SSP. Returns only ID and name.

#### Base Command

`topdesk-branches-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The offset at which to start listing the persons at. Must be greater or equal to 0. Default is 0. | Optional | 
| page_size | The amount of persons to be returned per request. Must be between 1 and 100. Default is 10. | Optional | 
| query | A FIQL search expression to filter the result. (e.g., address.country.name=NL) Available from Supporting-Files-API version 1.38.0. The FIQL query syntax is documented in the TOPdesk tutorial. | Optional | 
| fields | A comma-separated list of which fields should be included. By default fields ID and name will be included. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Branch.Id | String | Branch's ID. | 
| TOPdesk.Branch.Status | String | Branch's status. | 
| TOPdesk.Branch.Name | String | Branch's name. | 
| TOPdesk.Branch.Specification | String | Branch's specification. | 
| TOPdesk.Branch.ClientReferenceNumber | String | Branch's client reference number. | 
| TOPdesk.Branch.TimeZone | String | Branch's timezone. | 
| TOPdesk.Branch.ExtraA.Id | String | Branch's extra A ID. | 
| TOPdesk.Branch.ExtraA.Name | String | Branch's extra A name. | 
| TOPdesk.Branch.ExtraB.Id | String | Branch's extra B ID. | 
| TOPdesk.Branch.ExtraB.Name | String | Branch's extra B name. | 
| TOPdesk.Branch.Phone | String | Branch's phone. | 
| TOPdesk.Branch.Fax | String | Branch's fax. | 
| TOPdesk.Branch.Address.Country.Id | String | Branch's address country ID. | 
| TOPdesk.Branch.Address.Country.Name | String | Branch's address country name. | 
| TOPdesk.Branch.Address.Street | String | Branch's address street. | 
| TOPdesk.Branch.Address.Number | String | Branch's address number. | 
| TOPdesk.Branch.Address.County | String | Branch's address county. | 
| TOPdesk.Branch.Address.City | String | Branch's address city. | 
| TOPdesk.Branch.Address.Postcode | String | Branch's address postcode. | 
| TOPdesk.Branch.Address.AddressMemo | String | Branch's address memo. | 
| TOPdesk.Branch.Address.AddressType | String | Branch's address type. | 
| TOPdesk.Branch.Email | String | Branch's email. | 
| TOPdesk.Branch.Website | String | Branch's website. | 
| TOPdesk.Branch.PostalAddress.Country.Id | String | Branch's postal address country ID. | 
| TOPdesk.Branch.PostalAddress.Country.Name | String | Branch's postal address country name. | 
| TOPdesk.Branch.PostalAddress.Street | String | Branch's postal address street. | 
| TOPdesk.Branch.PostalAddress.Number | String | Branch's postal address number. | 
| TOPdesk.Branch.PostalAddress.County | String | Branch's postal address county. | 
| TOPdesk.Branch.PostalAddress.City | String | Branch's postal address city. | 
| TOPdesk.Branch.PostalAddress.Postcode | String | Branch's postal address postcode. | 
| TOPdesk.Branch.PostalAddress.AddressMemo | String | Branch's postal address memo. | 
| TOPdesk.Branch.PostalAddress.AddressType | String | Branch's postal address type. | 
| TOPdesk.Branch.BranchType | String | Branch's branch type. | 
| TOPdesk.Branch.HeadBranch.Id | String | Branch's head branch ID. | 
| TOPdesk.Branch.HeadBranch.Name | String | Branch's head branch name. | 
| TOPdesk.Branch.MembershipNumber | String | Branch's membership number. | 
| TOPdesk.Branch.AccountManager.Id | String | Branch's account manager ID. | 
| TOPdesk.Branch.AccountManager.Name | String | Branch's account manager name. | 
| TOPdesk.Branch.Contact.Id | String | Branch's contact ID. | 
| TOPdesk.Branch.Contact.Name | String | Branch's contact name. | 
| TOPdesk.Branch.VatNumber | String | Branch's VAT number. | 
| TOPdesk.Branch.SurfaceArea | Number | Branch's surface area. | 
| TOPdesk.Branch.Volume | Number | Branch's volume. | 
| TOPdesk.Branch.Attention.Id | String | Branch's attention ID. | 
| TOPdesk.Branch.Attention.Name | String | Branch's attention name. | 
| TOPdesk.Branch.AttentionComment | String | Branch's attention comment. | 
| TOPdesk.Branch.AdditionalInfo | String | Branch's additional info. | 
| TOPdesk.Branch.ServiceWindowOption | String | Branch's service window option. | 
| TOPdesk.Branch.ServiceWindow.Id | String | Branch's service window ID. | 
| TOPdesk.Branch.ServiceWindow.Name | String | Branch's service window name window name. | 
| TOPdesk.Branch.RealEstate.RegistryReference | String | Branch's real estate registry reference. | 
| TOPdesk.Branch.RealEstate.OwnerName | String | Branch's real estate owner name. | 
| TOPdesk.Branch.RealEstate.OwnerMobile | String | Branch's real estate owner mobile. | 
| TOPdesk.Branch.RealEstate.OwnerTelephone | String | Branch's real estate owner telephone. | 
| TOPdesk.Branch.RealEstate.OwnerEmail | String | Branch's real estate owner email. | 
| TOPdesk.Branch.RealEstate.DesignatedUse.Id | String | Branch's real estate designated use ID. | 
| TOPdesk.Branch.RealEstate.DesignatedUse.Name | String | Branch's real estate designated use name. | 
| TOPdesk.Branch.RealEstate.ListedBuilding.Id | String | Branch's real estate listed building ID. | 
| TOPdesk.Branch.RealEstate.ListedBuilding.Name | String | Branch's real estate listed building name. | 
| TOPdesk.Branch.RealEstate.ConstructionYear | Number | Branch's real estate construction year. | 
| TOPdesk.Branch.RealEstate.AcquisitionYear | Number | Branch's real estate acquisition year. | 
| TOPdesk.Branch.RealEstate.AcquisitionPrice | Number | Branch's real estate acquisition price. | 
| TOPdesk.Branch.RealEstate.EnergyPerformance.Id | String | Branch's real estate energy performance ID. | 
| TOPdesk.Branch.RealEstate.EnergyPerformance.Name | String | Branch's real estate energy performance name. | 
| TOPdesk.Branch.RealEstate.EnergyPerformanceMeasurementDate | Date | Branch's real estate energy performance measurement date. | 
| TOPdesk.Branch.RealEstate.EnvironmentalImpact.Id | String | Branch's real estate environmental impact ID. | 
| TOPdesk.Branch.RealEstate.EnvironmentalImpact.Name | String | Branch's real estate environmental impact name. | 
| TOPdesk.Branch.RealEstate.EnvironmentalImpactMeasurementDate | Date | Branch's real estate environmental impact measurement date. | 
| TOPdesk.Branch.RealEstate.BuildingLevelEPC.Id | String | Branch's real estate building level EPC ID. | 
| TOPdesk.Branch.RealEstate.BuildingLevelEPC.Name | String | Branch's real estate building level EPC name. | 
| TOPdesk.Branch.RealEstate.TotalAcquisitionCost | Number | Branch's real estate total acquisition cost. | 
| TOPdesk.Branch.RealEstate.PropertyValuation | Number | Branch's real estate property valuation. | 
| TOPdesk.Branch.RealEstate.ResidualValue | Number | Branch's real estate residual value. | 
| TOPdesk.Branch.RealEstate.AnnualDepreciation | Number | Branch's real estate annual depreciation. | 
| TOPdesk.Branch.RealEstate.DepreciationPeriod | Number | Branch's real estate depreciation period. | 
| TOPdesk.Branch.RealEstate.LiquidationValue | Number | Branch's real estate liquidation value. | 
| TOPdesk.Branch.RealEstate.LiquidationValueSurveyDate | Date | Branch's real estate liquidation value survey date. | 
| TOPdesk.Branch.RealEstate.LandValue | Number | Branch's real estate land value. | 
| TOPdesk.Branch.RealEstate.LandValueSurveyDate | Date | Branch's real estate land value survey date. | 
| TOPdesk.Branch.RealEstate.MarketValue | Number | Branch's real estate market value. | 
| TOPdesk.Branch.RealEstate.MarketValueSurveyDate | Date | Branch's real estate market value survey date. | 
| TOPdesk.Branch.RealEstate.RentalValue | Number | Branch's real estate rental value. | 
| TOPdesk.Branch.RealEstate.RentalValueSurveyDate | Date | Branch's real estate rental value survey date. | 
| TOPdesk.Branch.RealEstate.RebuildingValue | Number | Branch's real estate rebuilding value. | 
| TOPdesk.Branch.RealEstate.RebuildingValueSurveyDate | Date | Branch's real estate rebuilding value survey date. | 
| TOPdesk.Branch.OptionalFields1.Boolean1 | Boolean | Branch's optional fields1 boolean1. | 
| TOPdesk.Branch.OptionalFields1.Boolean2 | Boolean | Branch's optional fields1 boolean2. | 
| TOPdesk.Branch.OptionalFields1.Boolean3 | Boolean | Branch's optional fields1 boolean3. | 
| TOPdesk.Branch.OptionalFields1.Boolean4 | Boolean | Branch's optional fields1 boolean4. | 
| TOPdesk.Branch.OptionalFields1.Boolean5 | Boolean | Branch's optional fields1 boolean5. | 
| TOPdesk.Branch.OptionalFields1.Number1 | Number | Branch's optional fields1 number1. | 
| TOPdesk.Branch.OptionalFields1.Number2 | Number | Branch's optional fields1 number2. | 
| TOPdesk.Branch.OptionalFields1.Number3 | Number | Branch's optional fields1 number3. | 
| TOPdesk.Branch.OptionalFields1.Number4 | Number | Branch's optional fields1 number4. | 
| TOPdesk.Branch.OptionalFields1.Number5 | Number | Branch's optional fields1 number5. | 
| TOPdesk.Branch.OptionalFields1.Date1 | Date | Branch's optional fields1 date1. | 
| TOPdesk.Branch.OptionalFields1.Date2 | Date | Branch's optional fields1 date2. | 
| TOPdesk.Branch.OptionalFields1.Date3 | Date | Branch's optional fields1 date3. | 
| TOPdesk.Branch.OptionalFields1.Date4 | Date | Branch's optional fields1 date4. | 
| TOPdesk.Branch.OptionalFields1.Date5 | Date | Branch's optional fields1 date5. | 
| TOPdesk.Branch.OptionalFields1.Text1 | String | Branch's optional fields1 text1. | 
| TOPdesk.Branch.OptionalFields1.Text2 | String | Branch's optional fields1 text2. | 
| TOPdesk.Branch.OptionalFields1.Text3 | String | Branch's optional fields1 text3. | 
| TOPdesk.Branch.OptionalFields1.Text4 | String | Branch's optional fields1 text4. | 
| TOPdesk.Branch.OptionalFields1.Text5 | String | Branch's optional fields1 text5. | 
| TOPdesk.Branch.OptionalFields1.Memo1 | String | Branch's optional fields1 memo1. | 
| TOPdesk.Branch.OptionalFields1.Memo2 | String | Branch's optional fields1 memo2. | 
| TOPdesk.Branch.OptionalFields1.Memo3 | String | Branch's optional fields1 memo3. | 
| TOPdesk.Branch.OptionalFields1.Memo4 | String | Branch's optional fields1 memo4. | 
| TOPdesk.Branch.OptionalFields1.Memo5 | String | Branch's optional fields1 memo5. | 
| TOPdesk.Branch.OptionalFields1.Searchlist1.Id | String | Branch's optional fields1 searchlist1 ID. | 
| TOPdesk.Branch.OptionalFields1.Searchlist1.Name | String | Branch's optional fields1 searchlist1 name. | 
| TOPdesk.Branch.OptionalFields1.Searchlist2.Id | String | Branch's optional fields1 searchlist2 ID. | 
| TOPdesk.Branch.OptionalFields1.Searchlist2.Name | String | Branch's optional fields1 searchlist2 name. | 
| TOPdesk.Branch.OptionalFields1.Searchlist3.Id | String | Branch's optional fields1 searchlist3 ID. | 
| TOPdesk.Branch.OptionalFields1.Searchlist3.Name | String | Branch's optional fields1 searchlist3 name. | 
| TOPdesk.Branch.OptionalFields1.Searchlist4.Id | String | Branch's optional fields1 searchlist4 ID. | 
| TOPdesk.Branch.OptionalFields1.Searchlist4.Name | String | Branch's optional fields1 searchlist4 name. | 
| TOPdesk.Branch.OptionalFields1.Searchlist5.Id | String | Branch's optional fields1 searchlist5 ID. | 
| TOPdesk.Branch.OptionalFields1.Searchlist5.Name | String | Branch's optional fields1 searchlist5 name. | 
| TOPdesk.Branch.OptionalFields2.Boolean1 | Boolean | Branch's optional fields2 boolean1. | 
| TOPdesk.Branch.OptionalFields2.Boolean2 | Boolean | Branch's optional fields2 boolean2. | 
| TOPdesk.Branch.OptionalFields2.Boolean3 | Boolean | Branch's optional fields2 boolean3. | 
| TOPdesk.Branch.OptionalFields2.Boolean4 | Boolean | Branch's optional fields2 boolean4. | 
| TOPdesk.Branch.OptionalFields2.Boolean5 | Boolean | Branch's optional fields2 boolean5. | 
| TOPdesk.Branch.OptionalFields2.Number1 | Number | Branch's optional fields2 number1. | 
| TOPdesk.Branch.OptionalFields2.Number2 | Number | Branch's optional fields2 number2. | 
| TOPdesk.Branch.OptionalFields2.Number3 | Number | Branch's optional fields2 number3. | 
| TOPdesk.Branch.OptionalFields2.Number4 | Number | Branch's optional fields2 number4. | 
| TOPdesk.Branch.OptionalFields2.Number5 | Number | Branch's optional fields2 number5. | 
| TOPdesk.Branch.OptionalFields2.Date1 | Date | Branch's optional fields2 date1. | 
| TOPdesk.Branch.OptionalFields2.Date2 | Date | Branch's optional fields2 date2. | 
| TOPdesk.Branch.OptionalFields2.Date3 | Date | Branch's optional fields2 date3. | 
| TOPdesk.Branch.OptionalFields2.Date4 | Date | Branch's optional fields2 date4. | 
| TOPdesk.Branch.OptionalFields2.Date5 | Date | Branch's optional fields2 date5. | 
| TOPdesk.Branch.OptionalFields2.Text1 | String | Branch's optional fields2 text1. | 
| TOPdesk.Branch.OptionalFields2.Text2 | String | Branch's optional fields2 text2. | 
| TOPdesk.Branch.OptionalFields2.Text3 | String | Branch's optional fields2 text3. | 
| TOPdesk.Branch.OptionalFields2.Text4 | String | Branch's optional fields2 text4. | 
| TOPdesk.Branch.OptionalFields2.Text5 | String | Branch's optional fields2 text5. | 
| TOPdesk.Branch.OptionalFields2.Memo1 | String | Branch's optional fields2 memo1. | 
| TOPdesk.Branch.OptionalFields2.Memo2 | String | Branch's optional fields2 memo2. | 
| TOPdesk.Branch.OptionalFields2.Memo3 | String | Branch's optional fields2 memo3. | 
| TOPdesk.Branch.OptionalFields2.Memo4 | String | Branch's optional fields2 memo4. | 
| TOPdesk.Branch.OptionalFields2.Memo5 | String | Branch's optional fields2 memo5. | 
| TOPdesk.Branch.OptionalFields2.Searchlist1.Id | String | Branch's optional fields2 searchlist1 ID. | 
| TOPdesk.Branch.OptionalFields2.Searchlist1.Name | String | Branch's optional fields2 searchlist1 name. | 
| TOPdesk.Branch.OptionalFields2.Searchlist2.Id | String | Branch's optional fields2 searchlist2 ID. | 
| TOPdesk.Branch.OptionalFields2.Searchlist2.Name | String | Branch's optional fields2 searchlist2 name. | 
| TOPdesk.Branch.OptionalFields2.Searchlist3.Id | String | Branch's optional fields2 searchlist3 ID. | 
| TOPdesk.Branch.OptionalFields2.Searchlist3.Name | String | Branch's optional fields2 searchlist3 name. | 
| TOPdesk.Branch.OptionalFields2.Searchlist4.Id | String | Branch's optional fields2 searchlist4 ID. | 
| TOPdesk.Branch.OptionalFields2.Searchlist4.Name | String | Branch's optional fields2 searchlist4 name. | 
| TOPdesk.Branch.OptionalFields2.Searchlist5.Id | String | Branch's optional fields2 searchlist5 ID. | 
| TOPdesk.Branch.OptionalFields2.Searchlist5.Name | String | Branch's optional fields2 searchlist5 name. | 
| TOPdesk.Branch.Notes | String | Branch's notes. | 
| TOPdesk.Branch.Creator.Id | String | Branch's creator ID. | 
| TOPdesk.Branch.Creator.Name | String | Branch's creator name. | 
| TOPdesk.Branch.CreationDate | Date | Branch's creation date. | 
| TOPdesk.Branch.Modifier.Id | String | Branch's modifier ID. | 
| TOPdesk.Branch.Modifier.Name | String | Branch's modifier name. | 
| TOPdesk.Branch.ModificationDate | Date | Branch's modification date. | 
| TOPdesk.Branch.HasAttention | Boolean | Branch's has attention. | 


#### Command Example
```!topdesk-branches-list start=5```

#### Context Example
```json
{
    "TOPdesk": {
        "Branch": [
          {
            "Id": "some-branch-id",
            "Status": "Active",
            "Name": "HeadQuarters",
            "Specification": "string",
            "ClientReferenceNumber": "string",
            "TimeZone": "string",
            "ExtraA": {
              "Id": "some-id-76",
              "Name": "string"
            },
            "ExtraB": {
              "Id": "some-id-98",
              "Name": "string"
            },
            "Phone": "1337",
            "Fax": "string",
            "Address": {
              "Country": {
                "Id": "some-id-78",
                "Name": "string"
              },
              "Street": "Featherstone Street",
              "Number": "49",
              "County": "Greater London",
              "City": "London",
              "Postcode": "EC1Y 8SY",
              "AddressMemo": "49 Featherstone Street\nLONDON\nEC1Y 8SY\nUNITED KINGDOM",
              "AddressType": "GB"
            },
            "Email": "string",
            "Website": "some-domain.com",
            "PostalAddress": {
              "Country": {
                "Id": "some-id-56",
                "Name": "string"
              },
              "Street": "Featherstone Street",
              "Number": "49",
              "County": "Greater London",
              "City": "London",
              "Postcode": "EC1Y 8SY",
              "AddressMemo": "49 Featherstone Street\nLONDON\nEC1Y 8SY\nUNITED KINGDOM",
              "AddressType": "GB"
            },
            "BranchType": "string",
            "HeadBranch": {
              "Id": "some-id-45",
              "Name": "string"
            },
            "MembershipNumber": "string",
            "AccountManager": {
              "Id": "some-id-45",
              "Name": "string"
            },
            "Contact": {
              "Id": "some-id-34",
              "Name": "string"
            },
            "VatNumber": "string",
            "SurfaceArea": 0,
            "Volume": 0,
            "Attention": {
              "Id": "some-id-23",
              "Name": "string"
            },
            "AttentionComment": "string",
            "AdditionalInfo": "string",
            "ServiceWindowOption": "string",
            "ServiceWindow": {
              "Id": "some-id-12",
              "Name": "string"
            },
            "RealEstate": {
              "RegistryReference": "string",
              "OwnerName": "string",
              "OwnerMobile": "string",
              "OwnerTelephone": "string",
              "OwnerEmail": "string",
              "DesignatedUse": {
                "Id": "some-id-99",
                "Name": "string"
              },
              "ListedBuilding": {
                "Id": "some-id-88",
                "Name": "string"
              },
              "ConstructionYear": 0,
              "AcquisitionYear": 0,
              "AcquisitionPrice": 0,
              "EnergyPerformance": {
                "Id": "some-id-77",
                "Name": "string"
              },
              "EnergyPerformanceMeasurementDate": "2021-03-24T12:39:50.643Z",
              "EnvironmentalImpact": {
                "Id": "some-id-66",
                "Name": "string"
              },
              "EnvironmentalImpactMeasurementDate": "2021-03-24T12:39:50.643Z",
              "BuildingLevelEPC": {
                "Id": "some-id-55",
                "Name": "string"
              },
              "TotalAcquisitionCost": 0,
              "PropertyValuation": 0,
              "ResidualValue": 0,
              "AnnualDepreciation": 0,
              "DepreciationPeriod": 0,
              "LiquidationValue": 0,
              "LiquidationValueSurveyDate": "2021-03-24T12:39:50.643Z",
              "LandValue": 0,
              "LandValueSurveyDate": "2021-03-24T12:39:50.643Z",
              "MarketValue": 0,
              "MarketValueSurveyDate": "2021-03-24T12:39:50.643Z",
              "RentalValue": 0,
              "RentalValueSurveyDate": "2021-03-24T12:39:50.643Z",
              "RebuildingValue": 0,
              "RebuildingValueSurveyDate": "2021-03-24T12:39:50.643Z"
            },
            "OptionalFields1": {
              "Boolean1": true,
              "Boolean2": true,
              "Boolean3": true,
              "Boolean4": true,
              "Boolean5": true,
              "Number1": 0,
              "Number2": 0,
              "Number3": 0,
              "Number4": 0,
              "Number5": 0,
              "Date1": "2021-03-24T12:39:50.643Z",
              "Date2": "2021-03-24T12:39:50.643Z",
              "Date3": "2021-03-24T12:39:50.643Z",
              "Date4": "2021-03-24T12:39:50.643Z",
              "Date5": "2021-03-24T12:39:50.643Z",
              "Text1": "string",
              "Text2": "string",
              "Text3": "string",
              "Text4": "string",
              "Text5": "string",
              "Memo1": "string",
              "Memo2": "string",
              "Memo3": "string",
              "Memo4": "string",
              "Memo5": "string",
              "Searchlist1": {
                "Id": "some-id-55",
                "Name": "string"
              },
              "Searchlist2": {
                "Id": "some-id-44",
                "Name": "string"
              },
              "Searchlist3": {
                "Id": "some-id-33",
                "Name": "string"
              },
              "Searchlist4": {
                "Id": "some-id-22",
                "Name": "string"
              },
              "searchlist5": {
                "Id": "some-id-11",
                "Name": "string"
              }
            },
            "optionalFields2": {
              "Boolean1": true,
              "Boolean2": true,
              "Boolean3": true,
              "Boolean4": true,
              "Boolean5": true,
              "Number1": 0,
              "Number2": 0,
              "Number3": 0,
              "Number4": 0,
              "Number5": 0,
              "Date1": "2021-03-24T12:39:50.643Z",
              "Date2": "2021-03-24T12:39:50.643Z",
              "Date3": "2021-03-24T12:39:50.643Z",
              "Date4": "2021-03-24T12:39:50.643Z",
              "Date5": "2021-03-24T12:39:50.643Z",
              "Text1": "string",
              "Text2": "string",
              "Text3": "string",
              "Text4": "string",
              "Text5": "string",
              "Memo1": "string",
              "Memo2": "string",
              "Memo3": "string",
              "Memo4": "string",
              "Memo5": "string",
              "Searchlist1": {
                "Id": "some-id-6",
                "Name": "string"
              },
              "Searchlist2": {
                "Id": "some-id-5",
                "Name": "string"
              },
              "Searchlist3": {
                "Id": "some-id-4",
                "Name": "string"
              },
              "Searchlist4": {
                "Id": "some-id-3",
                "Name": "string"
              },
              "searchlist5": {
                "Id": "some-id-2",
                "Name": "string"
              }
            },
            "Notes": "string",
            "Creator": {
              "Id": "some-id-1",
              "name": "string"
            },
            "CreationDate": "2021-03-24T12:39:50.644Z",
            "Modifier": {
              "Id": "some-id",
              "Name": "string"
            },
            "ModificationDate": "2021-03-24T12:39:50.644Z",
            "HasAttention": true
          }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk branches
>|Id|Status|Name|Phone|Website|Address|
>|---|---|---|---|---|---|
>| some-branch-id | Active | HeadQuarters | 1337 | some-domain.com | 49 Featherstone Street\nLONDON\nEC1Y 8SY\nUNITED KINGDOM

### topdesk-incidents-list
***
Get list of incidents.

#### Permissions
**Operator**: With read permission on 1st/2nd line incident; Category/Branch/Operator filters apply

**Person**: Accessible; Person visibility settings apply

#### Base Command

`topdesk-incidents-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The offset at which to start listing the operators at. Must be greater or equal to 0. Default is 0. | Optional | 
| page_size | The amount of operators to be returned per request. Must be between 1 and 100. Default is 10. | Optional | 
| query | A search expression to filter the result. The FIQL query syntax will be used if 'Use new query option' in the settings is checked, otherwise old style query will be used. The FIQL query syntax is documented in the in the TOPdesk tutorial. TOPdesk tutorial. (e.g., (FIQL) status==firsLine) (e.g., (old style) status=firsLine). | Optional | 
| incident_id | The ID of the incident to retrieve, overrides any other arguments. | Optional | 
| incident_number | The number of the incident to retrieve, overrides any other argument but incident_id. | Optional | 
| status. | Retrieve only the incidents of the given status. firstLine/secondLine/partial. Possible values are: firstLine, secondLine, partial. | Optional | 
| caller_id | Retrieve only the incidents of the given caller ID. | Optional | 
| branch_id | Retrieve only the incidents of the given branch ID. | Optional | 
| category | Retrieve only the incidents of the given category. Supported only with new FIQL type queries. | Optional | 
| subcategory | Retrieve only the incidents of the given subcategory. Supported only with new FIQL type queries. | Optional | 
| call_type | Retrieve only the incidents of the given call type. Supported only with new FIQL type queries. | Optional | 
| entry_type | Retrieve only the incidents of the given entry type. Supported only with new FIQL type queries. | Optional | 
| fields | A comma-separated list of which fields should be returned. By default all fields will be returned. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's OptionalFields2.Text3 | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incidents-list```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": [
            {
                "Action": "/tas/api/incidents/id/some-id/actions",
                "Attachments": "/tas/api/incidents/id/some-id/attachments",
                "BriefDescription": "",
                "CallDate": "2021-03-24T08:15:13.867+0000",
                "Caller": {
                    "DynamicName": "some-caller"
                },
                "Closed": false,
                "Completed": false,
                "CreationDate": "2021-03-24T08:15:13.867+0000",
                "Creator": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "ExternalNumber": "",
                "Id": "some-id",
                "MajorCall": false,
                "ModificationDate": "2021-03-24T08:15:13.000+0000",
                "Modifier": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "Monitored": false,
                "Number": "XSOAR-1337",
                "OnHold": false,
                "OptionalFields1": {
                    "Searchlist1": {
                        "Id": "some-id-3",
                        "Name": "Some Search Name"
                    },
                    "Searchlist3": {
                        "Id": "some-id-4",
                        "Name": "Some Other Search Name"
                    },
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "OptionalFields2": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "ProcessingStatus": {
                    "Id": "some-processing-status-id",
                    "Name": "Logged"
                },
                "PublishToSsd": false,
                "Requests": "/tas/api/incidents/id/some-id/requests",
                "Responded": false,
                "Status": "firstLine"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | firstLine | some-caller | Logged |


### topdesk-incident-actions
***
List all actions for specific incident

#### Permissions:
**Operator**: With read permission on 1st/2nd line incident; Category/Branch/Operator filters apply

**Persons**: Accessible; Person visibility settings apply

#### Base Command

`topdesk-incident-actions-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. An ID or a number must be set. If both are set, the ID will be used. | Optional |
| incident_number | The incident number. An ID or a number must be set. If both are set, the ID will be used. | Optional |
| limit | The limit for the amount of actions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Action.EntryDate | Date | Date of entry of the action |
| TOPdesk.Action.Flag | Unknown | Action's flag |
| TOPdesk.Action.Operator.Id | String | ID of the operator who created the action. |
| TOPdesk.Action.Operator.Name | String | Name of the operator who created the action. |
| TOPdesk.Action.InvisibleForCaller | Bool | If the action is visible for person. |
| TOPdesk.Action.Person | String | Person who created the action, not operator. |
| TOPdesk.Action.Id | String | ID of the action. |
| TOPdesk.Action.Memotext | String | Content of the action. |

### topdesk-incident-create
***
Create an incident in TOPdesk.

The command first uses the callerLookup option and tries to attach an existing user to the caller field of the incident. 
If the callerLookup shows up empty, the command will create an incident with an unregistered caller with a name as provided in the caller option.

#### Permissions: 
**Operator**: With create permission on 1st/2nd line incident, partials require 2nd line create permission

**Person**: Can only create first line incidents for himself. Only the following fields can be set depending on the setting for the new call form:
 - request
 - briefDescription
 - callType
 - category
 - subcategory
 - object
 - location
 - operatorGroup
 
#### Base Command

`topdesk-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caller | The caller ID for this incident. For an unregistered caller provide a name. | Required | 
| status. | Status of the incident. Can only be set by operators. Possible values are: firstLine, secondLine, partial. | Optional | 
| description | Brief description. maximum 80 characters. | Optional | 
| request | Initial request. Can be set by operators and persons. | Optional | 
| action | Initial action. Can be set by operators and persons. | Optional | 
| action_invisible_for_caller | Whether the initial action is invisible for persons. Can only be set by operators. Default value is false. Possible values are: true, false. | Optional | 
| entry_type | Entry type by name. Can only be set by operators. XSOAR is set by default for mirroring. | Optional | 
| category | Category by name. Can be set by operators. It is an error to provide both an ID and a name. | Optional | 
| subcategory | Subcategory by name. Can be set by operators. It is an error to provide both an ID and a name. | Optional | 
| external_number | External number. Can only be set by operators. Max 60 characters. | Optional | 
| main_incident | Main incident ID or number, required for creating a partial incident. Can only be set by operators. | Optional | 
| additional_params | Additional parameters to pass when creating an incident. (e.g., {"optionalFields1":{"text1":"test"}}) | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's optional fields2.text3. | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incident-create caller=some-caller```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": [
            {
                "Action": "/tas/api/incidents/id/some-id/actions",
                "Attachments": "/tas/api/incidents/id/some-id/attachments",
                "BriefDescription": "",
                "CallDate": "2021-03-24T08:15:13.867+0000",
                "Caller": {
                    "DynamicName": "some-caller"
                },
                "Closed": false,
                "Completed": false,
                "CreationDate": "2021-03-24T08:15:13.867+0000",
                "Creator": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "ExternalNumber": "",
                "Id": "some-id",
                "MajorCall": false,
                "ModificationDate": "2021-03-24T08:15:13.000+0000",
                "Modifier": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "Monitored": false,
                "Number": "XSOAR-1337",
                "OnHold": false,
                "OptionalFields1": {
                    "Searchlist1": {
                        "Id": "some-id-3",
                        "Name": "Some Search Name"
                    },
                    "Searchlist3": {
                        "Id": "some-id-4",
                        "Name": "Some Other Search Name"
                    },
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "OptionalFields2": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "ProcessingStatus": {
                    "Id": "some-processing-status-id",
                    "Name": "Logged"
                },
                "PublishToSsd": false,
                "Requests": "/tas/api/incidents/id/some-id/requests",
                "Responded": false,
                "Status": "firstLine"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | firstLine | some-caller | Logged |


### topdesk-incident-update
***
Update an incident in TOPdesk.

#### Permissions: 
**Operator**: With edit permission on 1st/2nd line incident; Category/Branch/Operator filters apply

**Person**: Accessible; Person visibility settings apply.
Depending on settings, the following fields can be updated:
- action
- closed
- feedbackRating
- feedbackMessage
 
#### Base Command

`topdesk-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| status. | Status of the incident. Can only be set by operators. Possible values are: firstLine, secondLine, partial. | Optional | 
| description | Brief description. maximum 80 characters. | Optional | 
| request | Initial request. Can be set by operators and persons. | Optional | 
| action | Initial action. Can be set by operators and persons. | Optional | 
| caller | The caller ID for this incident. For an unregistered caller provide a name. | Optional | 
| action_invisible_for_caller | Whether the initial action is invisible for persons. Can only be set by operators. Default value is false. Possible values are: true, false. | Optional | 
| entry_type | Entry type by name. Can only be set by operators. XSOAR is set by default for mirroring. | Optional | 
| category | Category by name. Can be set by operators. It is an error to provide both an ID and a name. | Optional | 
| subcategory | Subcategory by name. Can be set by operators. It is an error to provide both an ID and a name. | Optional | 
| external_number | External number. Can only be set by operators. Max 60 characters. | Optional | 
| main_incident | Main incident ID or number, required for creating a partial incident. Can only be set by operators. | Optional | 
| additional_params | Additional parameters to pass when creating an incident. (e.g., {"optionalFields1":{"text1":"test"}}) | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's Optional fields2.text3 | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incident-update description=some-updated-description number=XSOAR-1337```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": [
            {
                "Action": "/tas/api/incidents/id/some-id/actions",
                "Attachments": "/tas/api/incidents/id/some-id/attachments",
                "BriefDescription": "some-updated-description",
                "CallDate": "2021-03-24T08:15:13.867+0000",
                "Caller": {
                    "DynamicName": "some-caller"
                },
                "Closed": false,
                "Completed": false,
                "CreationDate": "2021-03-24T08:15:13.867+0000",
                "Creator": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "ExternalNumber": "",
                "Id": "some-id",
                "MajorCall": false,
                "ModificationDate": "2021-03-24T08:15:13.000+0000",
                "Modifier": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "Monitored": false,
                "Number": "XSOAR-1337",
                "OnHold": false,
                "OptionalFields1": {
                    "Searchlist1": {
                        "Id": "some-id-3",
                        "Name": "Some Search Name"
                    },
                    "Searchlist3": {
                        "Id": "some-id-4",
                        "Name": "Some Other Search Name"
                    },
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "OptionalFields2": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "ProcessingStatus": {
                    "Id": "some-processing-status-id",
                    "Name": "Logged"
                },
                "PublishToSsd": false,
                "Requests": "/tas/api/incidents/id/some-id/requests",
                "Responded": false,
                "Status": "firstLine"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | firstLine | some-caller | Logged |



### topdesk-incident-escalate
***
Escalate an incident in TOPdesk.

#### Permissions
**Operator**: With 1st line incident write permission and write permission for escalating incidents; Category/Branch/Operator filters apply

**Person**: No access

#### Base Command

`topdesk-incident-escalate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| escalate_reason_id | The escalation reason ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's optional fields2.text3. | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incident-escalate number=XSOAR-1337 escalate_reason_id=some-escalation-id-1```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": [
            {
                "Action": "/tas/api/incidents/id/some-id/actions",
                "Attachments": "/tas/api/incidents/id/some-id/attachments",
                "BriefDescription": "some-updated-description",
                "CallDate": "2021-03-24T08:15:13.867+0000",
                "Caller": {
                    "DynamicName": "some-caller"
                },
                "Closed": false,
                "Completed": false,
                "CreationDate": "2021-03-24T08:15:13.867+0000",
                "Creator": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "ExternalNumber": "",
                "Id": "some-id",
                "MajorCall": false,
                "ModificationDate": "2021-03-24T08:15:13.000+0000",
                "Modifier": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "Monitored": false,
                "Number": "XSOAR-1337",
                "OnHold": false,
                "OptionalFields1": {
                    "Searchlist1": {
                        "Id": "some-id-3",
                        "Name": "Some Search Name"
                    },
                    "Searchlist3": {
                        "Id": "some-id-4",
                        "Name": "Some Other Search Name"
                    },
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "OptionalFields2": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "ProcessingStatus": {
                    "Id": "some-processing-status-id",
                    "Name": "Logged"
                },
                "PublishToSsd": false,
                "Requests": "/tas/api/incidents/id/some-id/requests",
                "Responded": false,
                "Status": "secondLine"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | secondLine | some-caller | Logged |

### topdesk-incident-deescalate
***
Deescalate an incident in TOPdesk.

#### Permissions
**Operator**: With 1st and 2nd line incident write permission; Category/Branch/Operator filters apply; Feature must be enabled

**Person**: No access


#### Base Command

`topdesk-incident-deescalate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| deescalate_reason_id | The deescalation reason ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's optional fields2.text3. | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incident-deescalate number=XSOAR-1337 deescalate_reason_id=some-deescalation-id-1```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": [
            {
                "Action": "/tas/api/incidents/id/some-id/actions",
                "Attachments": "/tas/api/incidents/id/some-id/attachments",
                "BriefDescription": "some-updated-description",
                "CallDate": "2021-03-24T08:15:13.867+0000",
                "Caller": {
                    "DynamicName": "some-caller"
                },
                "Closed": false,
                "Completed": false,
                "CreationDate": "2021-03-24T08:15:13.867+0000",
                "Creator": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "ExternalNumber": "",
                "Id": "some-id",
                "MajorCall": false,
                "ModificationDate": "2021-03-24T08:15:13.000+0000",
                "Modifier": {
                    "Id": "some-id-1",
                    "Name": "Xsoar - Operator"
                },
                "Monitored": false,
                "Number": "XSOAR-1337",
                "OnHold": false,
                "OptionalFields1": {
                    "Searchlist1": {
                        "Id": "some-id-3",
                        "Name": "Some Search Name"
                    },
                    "Searchlist3": {
                        "Id": "some-id-4",
                        "Name": "Some Other Search Name"
                    },
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "OptionalFields2": {
                    "Text1": "",
                    "Text2": "",
                    "Text3": "",
                    "Text4": "",
                    "Text5": ""
                },
                "ProcessingStatus": {
                    "Id": "some-processing-status-id",
                    "Name": "Logged"
                },
                "PublishToSsd": false,
                "Requests": "/tas/api/incidents/id/some-id/requests",
                "Responded": false,
                "Status": "firstLine"
            }
        ]
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | firstLine | some-caller | Logged |


### topdesk-incident-archive
***
Archive an incident in TOPdesk.

#### Permissions
**Operator**: Incident write permission and archiving permission; Category/Branch/Operator filters apply;

**Person**: No access

#### Base Command

`topdesk-incident-archive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| archive_reason_id | The archiving reason ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's optional fields2.text3. | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incident-archive archive_reason_id=some-reason-id-1 number=XSOAR-1337```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": {
            "Action": "/tas/api/incidents/id/some-id/actions",
            "ArchivingReason": {
                "Id": "some-reason-id-1",
                "Name": "No longer valid"
            },
            "Attachments": "/tas/api/incidents/id/some-id/attachments",
            "BriefDescription": "",
            "CallDate": "2021-03-21T17:38:03.007+0000",
            "Caller": {
                "Branch": {
                    "ClientReferenceNumber": null,
                    "ExtraA": null,
                    "ExtraB": null,
                    "Id": null,
                    "Name": "",
                    "TimeZone": null
                },
                "DynamicName": "xsoar_test"
            },
            "Closed": false,
            "Completed": false,
            "CreationDate": "2021-03-21T17:38:03.007+0000",
            "Creator": {
                "Id": "some-operator-id",
                "Name": "Xsoar - Operator"
            },
            "ExternalNumber": "",
            "Id": "some-id",
            "MajorCall": false,
            "ModificationDate": "2021-03-24T08:15:06.000+0000",
            "Modifier": {
                "Id": "some-operator-id",
                "Name": "Xsoar - Operator"
            },
            "Monitored": false,
            "Number": "XSOAR-1337",
            "OnHold": false,
            "OptionalFields1": {
                "Searchlist1": {
                    "Id": "some-id-33",
                    "Name": "Searchlist 1"
                },
                "Searchlist3": {
                    "Id": "some-id-34",
                    "Name": "Searchlist 3"
                },
                "Text1": "",
                "Text2": "",
                "Text3": "",
                "Text4": "",
                "Text5": ""
            },
            "OptionalFields2": {
                "Text1": "",
                "Text2": "",
                "Text3": "",
                "Text4": "",
                "Text5": ""
            },
            "ProcessingStatus": {
                "Id": "some-processing-id",
                "Name": "Logged"
            },
            "PublishToSsd": false,
            "Requests": "/tas/api/incidents/id/some-id/requests",
            "Responded": false,
            "Status": "firstLineArchived"
        }
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | firstLineArchived | xsoar_test | Logged |


### topdesk-incident-unarchive
***
Unarchive an incident in TOPdesk.


#### Permissions
**Operator**: Incident write permission and archiving permission; Category/Branch/Operator filters apply;

**Person**: No access

#### Base Command

`topdesk-incident-unarchive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Incident.Id | String | TOPdesk incident's ID. | 
| TOPdesk.Incident.Status | String | TOPdesk incident's status. | 
| TOPdesk.Incident.Number | String | TOPdesk incident's number. | 
| TOPdesk.Incident.Request | String | TOPdesk incident's request. | 
| TOPdesk.Incident.Requests | String | TOPdesk incident's requests. | 
| TOPdesk.Incident.Action | String | TOPdesk incident's action. | 
| TOPdesk.Incident.Attachments | String | TOPdesk incident's attachments. | 
| TOPdesk.Incident.Caller.Id | String | TOPdesk incident's caller ID. | 
| TOPdesk.Incident.Caller.DynamicName | String | TOPdesk incident's caller dynamic name. | 
| TOPdesk.Incident.Caller.Branch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.Caller.Branch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.Caller.Branch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.Caller.Branch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.Caller.Branch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.Caller.Branch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.CallerBranch.ClientReferenceNumber | String | TOPdesk incident's caller branch client reference number. | 
| TOPdesk.Incident.CallerBranch.TimeZone | String | TOPdesk incident's caller branch timezone. | 
| TOPdesk.Incident.CallerBranch.ExtraA | Unknown | TOPdesk incident's caller branch extra A. | 
| TOPdesk.Incident.CallerBranch.ExtraB | Unknown | TOPdesk incident's caller branch extra B. | 
| TOPdesk.Incident.CallerBranch.Id | String | TOPdesk incident's caller branch ID. | 
| TOPdesk.Incident.CallerBranch.Name | String | TOPdesk incident's caller branch name. | 
| TOPdesk.Incident.BranchExtraFieldA | Unknown | TOPdesk incident's branch extra field A. | 
| TOPdesk.Incident.BranchExtraFieldB | Unknown | TOPdesk incident's branch extra field B. | 
| TOPdesk.Incident.BriefDescription | String | TOPdesk incident's brief description. | 
| TOPdesk.Incident.ExternalNumber | String | TOPdesk incident's external number. | 
| TOPdesk.Incident.Category.Id | String | TOPdesk incident's category ID. | 
| TOPdesk.Incident.Category.Name | String | TOPdesk incident's category name. | 
| TOPdesk.Incident.Subcategory.Id | String | TOPdesk incident's subcategory ID. | 
| TOPdesk.Incident.Subcategory.Name | String | TOPdesk incident's subcategory name. | 
| TOPdesk.Incident.CallType.Id | String | TOPdesk incident's call type ID. | 
| TOPdesk.Incident.CallType.Name | String | TOPdesk incident's call type name. | 
| TOPdesk.Incident.EntryType.Id | String | TOPdesk incident's entry type ID. | 
| TOPdesk.Incident.EntryType.Name | String | TOPdesk incident's entry type name. | 
| TOPdesk.Incident.Object.Id | String | TOPdesk incident's object ID. | 
| TOPdesk.Incident.Object.Name | String | TOPdesk incident's object name. | 
| TOPdesk.Incident.Object.Type.Id | String | TOPdesk incident's object type ID. | 
| TOPdesk.Incident.Object.Type.Name | String | TOPdesk incident's object type name. | 
| TOPdesk.Incident.Object.Make.Id | String | TOPdesk incident's object make ID. | 
| TOPdesk.Incident.Object.Make.Name | String | TOPdesk incident's object make name. | 
| TOPdesk.Incident.Object.Model.Id | String | TOPdesk incident's object model ID. | 
| TOPdesk.Incident.Object.Model.Name | String | TOPdesk incident's object model name. | 
| TOPdesk.Incident.Object.Branch.Id | String | TOPdesk incident's object branch ID. | 
| TOPdesk.Incident.Object.Branch.Name | String | TOPdesk incident's object branch name. | 
| TOPdesk.Incident.Object.Location.Id | String | TOPdesk incident's object location ID. | 
| TOPdesk.Incident.Object.Location.Name | String | TOPdesk incident's object location name. | 
| TOPdesk.Incident.Object.Specification | String | TOPdesk incident's object specification. | 
| TOPdesk.Incident.Object.SerialNumber | String | TOPdesk incident's object serial number. | 
| TOPdesk.Incident.Asset.Id | String | TOPdesk incident's asset ID. | 
| TOPdesk.Incident.Branch.ClientReferenceNumber | String | TOPdesk incident's branch client reference number. | 
| TOPdesk.Incident.Branch.TimeZone | String | TOPdesk incident's branch timezone. | 
| TOPdesk.Incident.Branch.ExtraA | Unknown | TOPdesk incident's branch extra A. | 
| TOPdesk.Incident.Branch.ExtraB | Unknown | TOPdesk incident's branch extra B. | 
| TOPdesk.Incident.Branch.Id | String | TOPdesk incident's branch ID. | 
| TOPdesk.Incident.Branch.Name | String | TOPdesk incident's branch name. | 
| TOPdesk.Incident.Location.Id | String | TOPdesk incident's location ID. | 
| TOPdesk.Incident.Location.Branch.ClientReferenceNumber | String | TOPdesk incident's location branch client reference number. | 
| TOPdesk.Incident.Location.Branch.TimeZone | String | TOPdesk incident's location branch timezone. | 
| TOPdesk.Incident.Location.Branch.ExtraA | Unknown | TOPdesk incident's location branch extra A. | 
| TOPdesk.Incident.Location.Branch.ExtraB | Unknown | TOPdesk incident's location branch extra B. | 
| TOPdesk.Incident.Location.Branch.Id | String | TOPdesk incident's location branch ID. | 
| TOPdesk.Incident.Location.Branch.Name | String | TOPdesk incident's location branch name. | 
| TOPdesk.Incident.Location.Name | String | TOPdesk incident's location name. | 
| TOPdesk.Incident.Location.Room | String | TOPdesk incident's location room. | 
| TOPdesk.Incident.Impact.Id | String | TOPdesk incident's impact ID. | 
| TOPdesk.Incident.Impact.Name | String | TOPdesk incident's impact name. | 
| TOPdesk.Incident.Urgency.Id | String | TOPdesk incident's urgency ID. | 
| TOPdesk.Incident.Urgency.Name | String | TOPdesk incident's urgency name. | 
| TOPdesk.Incident.Priority.Id | String | TOPdesk incident's priority ID. | 
| TOPdesk.Incident.Priority.Name | String | TOPdesk incident's priority name. | 
| TOPdesk.Incident.Duration.Id | String | TOPdesk incident's duration ID. | 
| TOPdesk.Incident.Duration.Name | String | TOPdesk incident's duration name. | 
| TOPdesk.Incident.TargetDate | Date | TOPdesk incident's target date. | 
| TOPdesk.Incident.Sla.Id | String | TOPdesk incident's sla ID. | 
| TOPdesk.Incident.OnHold | Boolean | TOPdesk incident's on hold. | 
| TOPdesk.Incident.OnHoldDate | Unknown | TOPdesk incident's on hold date. | 
| TOPdesk.Incident.OnHoldDuration | Number | TOPdesk incident's on hold duration. | 
| TOPdesk.Incident.FeedbackMessage | Unknown | TOPdesk incident's feedback message. | 
| TOPdesk.Incident.FeedbackRating | Unknown | TOPdesk incident's feedback rating. | 
| TOPdesk.Incident.Operator.Id | String | TOPdesk incident's operator ID. | 
| TOPdesk.Incident.Operator.Status | String | TOPdesk incident's operator status. | 
| TOPdesk.Incident.Operator.Name | String | TOPdesk incident's operator name. | 
| TOPdesk.Incident.OperatorGroup.Id | String | TOPdesk incident's operator group ID. | 
| TOPdesk.Incident.OperatorGroup.Name | String | TOPdesk incident's operator group name. | 
| TOPdesk.Incident.Supplier.Id | String | TOPdesk incident's supplier ID. | 
| TOPdesk.Incident.Supplier.Name | String | TOPdesk incident's supplier name. | 
| TOPdesk.Incident.Supplier.ForFirstLine | Boolean | TOPdesk incident's supplier for first line. | 
| TOPdesk.Incident.Supplier.ForSecondLine | Boolean | TOPdesk incident's supplier for second line. | 
| TOPdesk.Incident.ProcessingStatus.Id | String | TOPdesk incident's processing status ID. | 
| TOPdesk.Incident.ProcessingStatus.Name | String | TOPdesk incident's processing status name. | 
| TOPdesk.Incident.Completed | Boolean | TOPdesk incident's completed. | 
| TOPdesk.Incident.CompletedDate | Unknown | TOPdesk incident's completed date. | 
| TOPdesk.Incident.Closed | Boolean | TOPdesk incident's closed. | 
| TOPdesk.Incident.ClosedDate | Unknown | TOPdesk incident's closed date. | 
| TOPdesk.Incident.ClosureCode.Id | String | TOPdesk incident's closure code ID. | 
| TOPdesk.Incident.ClosureCode.Name | String | TOPdesk incident's closure code name. | 
| TOPdesk.Incident.TimeSpent | Number | TOPdesk incident's time spent. | 
| TOPdesk.Incident.TimeSpentFirstLine | Number | TOPdesk incident's time spent first line | 
| TOPdesk.Incident.TimeSpentSecondLineAndPartials | Number | TOPdesk incident's time spent second line and partials. | 
| TOPdesk.Incident.Costs | Number | TOPdesk incident's costs. | 
| TOPdesk.Incident.EscalationStatus | String | TOPdesk incident's escalation status. | 
| TOPdesk.Incident.EscalationReason.Id | String | TOPdesk incident's escalation reason ID. | 
| TOPdesk.Incident.EscalationReason.Name | String | TOPdesk incident's escalation reason name. | 
| TOPdesk.Incident.EscalationOperator.Id | String | TOPdesk incident's escalation operator ID. | 
| TOPdesk.Incident.EscalationOperator.Name | String | TOPdesk incident's escalation operator name. | 
| TOPdesk.Incident.CallDate | Date | TOPdesk incident's call date. | 
| TOPdesk.Incident.Creator.Id | String | TOPdesk incident's creator ID. | 
| TOPdesk.Incident.Creator.Name | String | TOPdesk incident's creator name. | 
| TOPdesk.Incident.CreationDate | Date | TOPdesk incident's creation date. | 
| TOPdesk.Incident.Modifier.Id | String | TOPdesk incident's modifier ID. | 
| TOPdesk.Incident.Modifier.Name | String | TOPdesk incident's modifier name. | 
| TOPdesk.Incident.ModificationDate | Date | TOPdesk incident's modification date. | 
| TOPdesk.Incident.MajorCall | Boolean | TOPdesk incident's major call. | 
| TOPdesk.Incident.MajorCallObject.Name | String | TOPdesk incident's Major call object name. | 
| TOPdesk.Incident.MajorCallObject.Id | String | TOPdesk incident's major call object ID. | 
| TOPdesk.Incident.MajorCallObject.Status | Number | TOPdesk incident's major call object status. | 
| TOPdesk.Incident.MajorCallObject.MajorIncident | Boolean | TOPdesk incident's major call object major incident. | 
| TOPdesk.Incident.PublishToSsd | Boolean | TOPdesk incident's publish to SSD. | 
| TOPdesk.Incident.Monitored | Boolean | TOPdesk incident's monitored. | 
| TOPdesk.Incident.ExpectedTimeSpent | Number | TOPdesk incident's expected time spent. | 
| TOPdesk.Incident.MainIncident | Unknown | TOPdesk incident's main incident. | 
| TOPdesk.Incident.PartialIncidents.Link | String | TOPdesk incident's partial incidents link. | 
| TOPdesk.Incident.OptionalFields1.Boolean1 | Boolean | TOPdesk incident's optional fields1 boolean1. | 
| TOPdesk.Incident.OptionalFields1.Boolean2 | Boolean | TOPdesk incident's optional fields1 boolean2. | 
| TOPdesk.Incident.OptionalFields1.Boolean3 | Boolean | TOPdesk incident's optional fields1 boolean3. | 
| TOPdesk.Incident.OptionalFields1.Boolean4 | Boolean | TOPdesk incident's optional fields1 boolean4. | 
| TOPdesk.Incident.OptionalFields1.Boolean5 | Boolean | TOPdesk incident's optional fields1 boolean5. | 
| TOPdesk.Incident.OptionalFields1.Number1 | Number | TOPdesk incident's optional fields1 number1. | 
| TOPdesk.Incident.OptionalFields1.Number2 | Number | TOPdesk incident's optional fields1 number2. | 
| TOPdesk.Incident.OptionalFields1.Number3 | Number | TOPdesk incident's optional fields1 number3. | 
| TOPdesk.Incident.OptionalFields1.Number4 | Number | TOPdesk incident's optional fields1 number4. | 
| TOPdesk.Incident.OptionalFields1.Number5 | Number | TOPdesk incident's optional fields1 number5. | 
| TOPdesk.Incident.OptionalFields1.Date1 | Date | TOPdesk incident's optional fields1 date1. | 
| TOPdesk.Incident.OptionalFields1.Date2 | Date | TOPdesk incident's optional fields1 date2. | 
| TOPdesk.Incident.OptionalFields1.Date3 | Date | TOPdesk incident's optional fields1 date3. | 
| TOPdesk.Incident.OptionalFields1.Date4 | Date | TOPdesk incident's optional fields1 date4. | 
| TOPdesk.Incident.OptionalFields1.Date5 | Date | TOPdesk incident's optional fields1 date5. | 
| TOPdesk.Incident.OptionalFields1.Text1 | String | TOPdesk incident's optional fields1 text1. | 
| TOPdesk.Incident.OptionalFields1.Text2 | String | TOPdesk incident's optional fields1 text2. | 
| TOPdesk.Incident.OptionalFields1.Text3 | String | TOPdesk incident's optional fields1 text3. | 
| TOPdesk.Incident.OptionalFields1.Text4 | String | TOPdesk incident's optional fields1 text4. | 
| TOPdesk.Incident.OptionalFields1.Text5 | String | TOPdesk incident's optional fields1 text5. | 
| TOPdesk.Incident.OptionalFields1.Memo1 | String | TOPdesk incident's optional fields1 memo1. | 
| TOPdesk.Incident.OptionalFields1.Memo2 | String | TOPdesk incident's optional fields1 memo2. | 
| TOPdesk.Incident.OptionalFields1.Memo3 | String | TOPdesk incident's optional fields1 memo3. | 
| TOPdesk.Incident.OptionalFields1.Memo4 | String | TOPdesk incident's optional fields1 memo4. | 
| TOPdesk.Incident.OptionalFields1.Memo5 | String | TOPdesk incident's optional fields1 memo5. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Id | String | TOPdesk incident's optional fields1 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist1.Name | String | TOPdesk incident's optional fields1 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Id | String | TOPdesk incident's optional fields1 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist2.Name | String | TOPdesk incident's optional fields1 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Id | String | TOPdesk incident's optional fields1 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist3.Name | String | TOPdesk incident's optional fields1 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Id | String | TOPdesk incident's optional fields1 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist4.Name | String | TOPdesk incident's optional fields1 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Id | String | TOPdesk incident's optional fields1 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields1.Searchlist5.Name | String | TOPdesk incident's optional fields1 searchlist5 name. | 
| TOPdesk.Incident.OptionalFields2.Boolean1 | Boolean | TOPdesk incident's optional fields2 boolean1. | 
| TOPdesk.Incident.OptionalFields2.Boolean2 | Boolean | TOPdesk incident's optional fields2 boolean2. | 
| TOPdesk.Incident.OptionalFields2.Boolean3 | Boolean | TOPdesk incident's optional fields2 boolean3. | 
| TOPdesk.Incident.OptionalFields2.Boolean4 | Boolean | TOPdesk incident's optional fields2 boolean4. | 
| TOPdesk.Incident.OptionalFields2.Boolean5 | Boolean | TOPdesk incident's optional fields2 boolean5. | 
| TOPdesk.Incident.OptionalFields2.Number1 | Number | TOPdesk incident's optional fields2 number1. | 
| TOPdesk.Incident.OptionalFields2.Number2 | Number | TOPdesk incident's optional fields2 number2. | 
| TOPdesk.Incident.OptionalFields2.Number3 | Number | TOPdesk incident's optional fields2 number3. | 
| TOPdesk.Incident.OptionalFields2.Number4 | Number | TOPdesk incident's optional fields2 number4. | 
| TOPdesk.Incident.OptionalFields2.Number5 | Number | TOPdesk incident's optional fields2 number5. | 
| TOPdesk.Incident.OptionalFields2.Date1 | Date | TOPdesk incident's optional fields2 date1. | 
| TOPdesk.Incident.OptionalFields2.Date2 | Date | TOPdesk incident's optional fields2 date2. | 
| TOPdesk.Incident.OptionalFields2.Date3 | Date | TOPdesk incident's optional fields2 date3. | 
| TOPdesk.Incident.OptionalFields2.Date4 | Date | TOPdesk incident's optional fields2 date4. | 
| TOPdesk.Incident.OptionalFields2.Date5 | Date | TOPdesk incident's optional fields2 date5. | 
| TOPdesk.Incident.OptionalFields2.Text1 | String | TOPdesk incident's optional fields2 text1. | 
| TOPdesk.Incident.OptionalFields2.Text2 | String | TOPdesk incident's optional fields2 text2. | 
| TOPdesk.Incident.OptionalFields2.Text3 | String | TOPdesk incident's optional fields2.text3. | 
| TOPdesk.Incident.OptionalFields2.Text4 | String | TOPdesk incident's optional fields2 text4. | 
| TOPdesk.Incident.OptionalFields2.Text5 | String | TOPdesk incident's optional fields2 text5. | 
| TOPdesk.Incident.OptionalFields2.Memo1 | String | TOPdesk incident's optional fields2 memo1. | 
| TOPdesk.Incident.OptionalFields2.Memo2 | String | TOPdesk incident's optional fields2 memo2. | 
| TOPdesk.Incident.OptionalFields2.Memo3 | String | TOPdesk incident's optional fields2 memo3. | 
| TOPdesk.Incident.OptionalFields2.Memo4 | String | TOPdesk incident's optional fields2 memo4. | 
| TOPdesk.Incident.OptionalFields2.Memo5 | String | TOPdesk incident's optional fields2 memo5. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Id | String | TOPdesk incident's optional fields2 searchlist1 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist1.Name | String | TOPdesk incident's optional fields2 searchlist1 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Id | String | TOPdesk incident's optional fields2 searchlist2 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist2.Name | String | TOPdesk incident's optional fields2 searchlist2 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Id | String | TOPdesk incident's optional fields2 searchlist3 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist3.Name | String | TOPdesk incident's optional fields2 searchlist3 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Id | String | TOPdesk incident's optional fields2 searchlist4 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist4.Name | String | TOPdesk incident's optional fields2 searchlist4 name. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Id | String | TOPdesk incident's optional fields2 searchlist5 ID. | 
| TOPdesk.Incident.OptionalFields2.Searchlist5.Name | String | TOPdesk incident's optional fields2 searchlist5 name. | 
| TOPdesk.Incident.ExternalLinks.Id | String | TOPdesk incident's external links ID. | 
| TOPdesk.Incident.ExternalLinks.Type | String | TOPdesk incident's external links type. | 
| TOPdesk.Incident.ExternalLinks.Date | Date | TOPdesk incident's external links date. | 


#### Command Example
```!topdesk-incident-unarchive number=XSOAR-1337```

#### Context Example
```json
{
    "TOPdesk": {
        "Incident": {
            "Action": "/tas/api/incidents/id/some-id/actions",
            "Attachments": "/tas/api/incidents/id/some-id/attachments",
            "BriefDescription": "",
            "CallDate": "2021-03-21T17:38:03.007+0000",
            "Caller": {
                "Branch": {
                    "ClientReferenceNumber": null,
                    "ExtraA": null,
                    "ExtraB": null,
                    "Id": null,
                    "Name": "",
                    "TimeZone": null
                },
                "DynamicName": "xsoar_test"
            },
            "Closed": false,
            "Completed": false,
            "CreationDate": "2021-03-21T17:38:03.007+0000",
            "Creator": {
                "Id": "some-operator-id",
                "Name": "Xsoar - Operator"
            },
            "ExternalNumber": "",
            "Id": "some-id",
            "MajorCall": false,
            "ModificationDate": "2021-03-24T08:15:06.000+0000",
            "Modifier": {
                "Id": "some-operator-id",
                "Name": "Xsoar - Operator"
            },
            "Monitored": false,
            "Number": "XSOAR-1337",
            "OnHold": false,
            "OptionalFields1": {
                "Searchlist1": {
                    "Id": "some-id-33",
                    "Name": "Searchlist 1"
                },
                "Searchlist3": {
                    "Id": "some-id-34",
                    "Name": "Searchlist 3"
                },
                "Text1": "",
                "Text2": "",
                "Text3": "",
                "Text4": "",
                "Text5": ""
            },
            "OptionalFields2": {
                "Text1": "",
                "Text2": "",
                "Text3": "",
                "Text4": "",
                "Text5": ""
            },
            "ProcessingStatus": {
                "Id": "some-processing-id",
                "Name": "Logged"
            },
            "PublishToSsd": false,
            "Requests": "/tas/api/incidents/id/some-id/requests",
            "Responded": false,
            "Status": "firstLine"
        }
    }
}
```

#### Human Readable Output

>### TOPdesk incidents
>|Id|Number|Line|CallerName|Status|
>|---|---|---|---|---|
>| some-id | XSOAR-1337 | firstLine | xsoar_test | Logged |

### topdesk-incident-attachment-upload
***
Upload an attachment to an incident in TOPdesk.

#### Permissions
**Operator**: With edit permission on 1st/2nd line incident; Category/Branch/Operator filters apply

**Person**: Accessible; Person visibility settings apply.

#### Base Command

`topdesk-incident-attachment-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| file | Entry ID of the file to upload. | Required | 
| file_name | In case specified entry contains more than one file, the given file name will be used. If not specified the first file in the entry will be used. | Optional | 
| invisible_for_caller | Whether the uploaded file is invisible for the caller of the incident. Possible values are: true, false. | Optional | 
| file_description | The description of the uploaded file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Attachment.Id | String | Attachment's ID. | 
| TOPdesk.Attachment.FileName | String | Attachment's file name. | 
| TOPdesk.Attachment.DownloadUrl | String | Attachment's download URL. | 
| TOPdesk.Attachment.Size | Number | Attachment's size. | 
| TOPdesk.Attachment.Description | String | Attachment's description. | 
| TOPdesk.Attachment.InvisibleForCaller | Boolean | Attachment's invisible for caller. | 
| TOPdesk.Attachment.EntryDate | Date | Attachment's entry date. | 
| TOPdesk.Attachment.Operator.Id | String | Attachment's operator ID. | 
| TOPdesk.Attachment.Operator.Name | String | Attachment's operator name. | 
| TOPdesk.Attachment.Person | Unknown | Attachment's person. | 


#### Command Example
```!topdesk-incident-attachment-upload number=XSOAR-1337 file=932@some-file-entry```

#### Context Example
```json
{
    "TOPdesk": {
        "Attachment": {
            "DownloadUrl": "/tas/api/incidents/id/some-incident-id/attachments/some-id/download",
            "EntryDate": "2021-03-24T13:40:47.000+0000",
            "FileName": "tiny_upload_file",
            "Id": "some-id",
            "InvisibleForCaller": false,
            "Operator": {
              "Id": "some-operator-id",
              "Name": "xsoar operator a"
            }
        }
    }
}
```

#### Human Readable Output

>### TOPdesk Attachments
>|Id|FileName|DownloadUrl|InvisibleForCaller|EntryDate|Operator|
>|---|---|---|---|---|---|
>| some-id | tiny_upload_file | /tas/api/incidents/id/some-incident-id/attachments/some-id/download | False | 2021-03-24T13:40:47.000+0000 | xsoar operator a |


#### Base Command

`topdesk-incident-attachments-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| number. | The incident number. An ID or a number must be set. If both are set incident with relevant ID will be updated. | Optional | 
| limit | The limit for the amount of attachments to store in the Context Data. -1 stores all categories. Default value is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TOPdesk.Attachment.Id | String | Attachment's ID. | 
| TOPdesk.Attachment.FileName | String | Attachment's file name. | 
| TOPdesk.Attachment.DownloadUrl | String | Attachment's download URL. | 
| TOPdesk.Attachment.Size | Number | Attachment's size. | 
| TOPdesk.Attachment.Description | String | Attachment's description. | 
| TOPdesk.Attachment.InvisibleForCaller | Boolean | Attachment's invisible for caller. | 
| TOPdesk.Attachment.EntryDate | Date | Attachment's entry date. | 
| TOPdesk.Attachment.Operator.Id | String | Attachment's operator ID. | 
| TOPdesk.Attachment.Operator.Name | String | Attachment's operator name. | 
| TOPdesk.Attachment.Person | Unknown | Attachment's person. | 


#### Command Example
```!topdesk-incident-attachments-list number=XSOAR-1337```

#### Context Example
```json
{
    "TOPdesk": {
        "Attachment": {
            "DownloadUrl": "/tas/api/incidents/id/some-incident-id/attachments/some-id/download",
            "EntryDate": "2021-03-24T13:40:47.000+0000",
            "FileName": "tiny_upload_file",
            "Id": "some-id",
            "InvisibleForCaller": false,
            "Operator": {
              "Id": "some-operator-id",
              "Name": "xsoar operator a"
            }
        }
    }
}
```

#### Human Readable Output

>### TOPdesk Attachments
>|Id|FileName|DownloadUrl|InvisibleForCaller|EntryDate|Operator|
>|---|---|---|---|---|---|
>|some-id|tiny_upload_file|/tas/api/incidents/id/some-incident-id/attachments/some-id/download|False|2021-03-24T13:40:47.000+0000|xsoar operator a|
