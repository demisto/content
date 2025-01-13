Ivanti Heat service manager
This integration was integrated and tested with version 2020.1.0.20200313 of Ivanti Heat
## Configure Ivanti Heat in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| token | API Token | True |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\) | False |
| incident_name_field | The object field to use for incident name | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ivanti-heat-objects-list
***
Fetches business object records based on the defined filter values.


#### Base Command

`ivanti-heat-objects-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rec-id | Buisiness object ID | Optional | 
| from | Start date of object records to return in the following format 2012-01-01T00:00:00Z. | Optional | 
| to | End date of object records to return in the following format 2012-01-01T00:00:00Z. | Optional | 
| limit | The maximum number of object records to return | Optional | 
| offset | Starting record index to begin retrieving object records from | Optional | 
| search-query | Fetches business object records based on the defined search keyword | Optional | 
| object-type | Type of object record | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IvantiHeat.incidents.RecId | String | Incident ID | 
| IvantiHeat.incidents.Subject | String | Incident subject | 
| IvantiHeat.incidents.Status | String | Incident status | 
| IvantiHeat.incidents.CreatedDateTime | Date | Incident createion time | 
| IvantiHeat.incidents.Symptom | String | Incident description | 
| IvantiHeat.incidents.OwnerTeam | String | Incident owner team | 
| IvantiHeat.incidents.IncidentNumber | Number | The incident number | 
| IvantiHeat.incidents.CreatedBy | String | The user who created the incident | 
| IvantiHeat.incidents.Owner | String | Incident owner | 
| IvantiHeat.incidents.Category | String | Incident category | 
| IvantiHeat.incidents.Priority | Number | Incident priority | 
| IvantiHeat.incidents.TypeOfIncident | String | Incident type | 
| IvantiHeat.incidents.ActualCategory | String | Incident actual category | 
| IvantiHeat.incidents.SocialTextHeader | String | Incident text header | 
| IvantiHeat.incidents.Email | String | Incident owner Email | 


#### Command Example
```!ivanti-heat-objects-list object-type=problems search-query=email from=2011-09-01 to=2012-01-01```

#### Context Example
```
{
    "IvantiHeat": {
        "problems": {
            "Category": "Accessibility",
            "Category_Valid": "48686D",
            "ClosedBy": null,
            "ClosedDateTime": "2020-07-01T08:42:33Z",
            "Cost": 188,
            "CreatedBy": "johnny cash",
            "CreatedDateTime": "2011-09-18T23:42:38Z",
            "Description": "Email down",
            "Environment": "",
            "Environment_Valid": "",
            "ErrorMessage": "",
            "FirstIncidentLinkedDateTime": null,
            "Impact": "Low",
            "Impact_Valid": "0ABE7B3BC5E9B19B258",
            "IncidentToRootCauseDuration": 277203595,
            "IsInFinalState": false,
            "IsUnRead": false,
            "IsWorkAround": false,
            "KPIAfterIdentification": 0,
            "KPIBeforeIdentification": 0,
            "KPITimeUntilRootCause": 0,
            "KnownErrorDate": "2011-09-18T23:44:37Z",
            "KnownErrorDuration": 0,
            "LastModBy": "Admin",
            "LastModDateTime": "2020-07-01T08:42:33Z",
            "OrganizationalUnit": "",
            "OrganizationalUnit_Valid": "",
            "Owner": "ADale",
            "OwnerEmailAddress": "user@domain.com",
            "OwnerTeam": "Problem Management",
            "OwnerTeam_Valid": "2D8B665640EC10B522A",
            "Owner_Valid": "C19505062E42B83CB",
            "Priority": "4",
            "Priority_Valid": "DD1B90A",
            "ProblemDuration": 0,
            "ProblemLifetime": 0,
            "ProblemNumber": 10053,
            "ReadOnly": false,
            "RecId": "83837179C323966",
            "Resolution": "I cant see my emails",
            "ResolutionAction": "Request for Change",
            "ResolutionAction_Valid": "87D63706706DBE12A1",
            "ResolutionEscLink": "",
            "ResolutionEscLink_Category": "",
            "ResolutionEscLink_RecID": "",
            "ResponseEscalationLink": "",
            "ResponseEscalationLink_Category": "",
            "ResponseEscalationLink_RecID": "",
            "RootCause": "Missing DLL",
            "RootCauseDateTimeCreated": "2011-09-22T23:42:38Z",
            "Service": "",
            "Service_Valid": "",
            "SocialTextHeader": "Problem 103: Email down",
            "Source": "Incident Management",
            "Source_Valid": "A7D73C90FB4AA0D549FF03C36",
            "Status": "Resolved",
            "Status_Valid": "6C9D23834",
            "Subject": "Email down",
            "TargetResolutionTime": null,
            "TotalTimeSpent": 208,
            "TotalWaitingDuration": 0,
            "TypeOfProblem": "Known Error",
            "TypeOfProblem_Valid": "50075354BCAAE1",
            "Urgency": "Medium",
            "Urgency_Valid": "44021B4B3306053AE",
            "WaitingEscLink": "",
            "WaitingEscLink_Category": "",
            "WaitingEscLink_RecID": "",
            "Workaround": ""
        }
    }
}
```

#### Human Readable Output

>### problems results
>|RecId|Subject|Status|CreatedDateTime|Urgency|OwnerTeam|CreatedBy|Owner|Category|Description|Priority|ClosedDateTime|SocialTextHeader|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8383718895204FFBB3EC95E79C323966 | Email down | Resolved | 2011-09-18T23:42:38Z | Medium | Problem Management | johnny cash | owner | Accessibility | Email down | 4 | 2020-07-01T08:42:33Z | Problem 103: Email down |


### ivanti-heat-object-update
***
Update details of a business object such as a change, problem, or incident.


#### Base Command

`ivanti-heat-object-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rec-id | Buisiness object ID to update | Required | 
| fields | Fields values in json format to update in the record, e.g: {"Priority":5} | Required | 
| object-type | Type of object record | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IvantiHeat.incidents.RecId | String | Incident ID | 
| IvantiHeat.incidents.Subject | String | Incident subject | 
| IvantiHeat.incidents.Status | String | Incident status | 
| IvantiHeat.incidents.CreatedDateTime | Date | Incident createion time | 
| IvantiHeat.incidents.Symptom | String | Incident description | 
| IvantiHeat.incidents.OwnerTeam | String | Incident owner team | 
| IvantiHeat.incidents.IncidentNumber | Number | The incident number | 
| IvantiHeat.incidents.CreatedBy | String | The user who created the incident | 
| IvantiHeat.incidents.Owner | String | Incident owner | 
| IvantiHeat.incidents.Category | String | Incident category | 
| IvantiHeat.incidents.Priority | Number | Incident priority | 
| IvantiHeat.incidents.TypeOfIncident | String | Incident type | 
| IvantiHeat.incidents.ActualCategory | String | Incident actual category | 
| IvantiHeat.incidents.SocialTextHeader | String | Incident text header | 
| IvantiHeat.incidents.Email | String | Incident owner Email | 


#### Command Example
```!ivanti-heat-object-update fields={"Description":desc","Priority":1} object-type=problems rec-id=5874A667```

#### Context Example
```
{
    "IvantiHeat": {
        "problems": {
            "@odata.context": "https://*ivanti-host*/api/odata/$metadata#problems/$entity",
            "Category": "Applications",
            "Category_Valid": "2E3A3EC0",
            "ClosedBy": null,
            "ClosedDateTime": "2020-07-05T12:28:12Z",
            "Cost": 48,
            "CreatedBy": "Admin",
            "CreatedDateTime": "2012-10-22T23:35:21Z",
            "Description": "desc",
            "Environment": "",
            "Environment_Valid": "",
            "ErrorMessage": "File format not supported",
            "FirstIncidentLinkedDateTime": "2015-06-10T21:26:17Z",
            "Impact": "Medium",
            "Impact_Valid": "1AFFC174C7EA4AB79CCA6B15EB67006D",
            "IncidentToRootCauseDuration": 243003171,
            "IsInFinalState": false,
            "IsUnRead": false,
            "IsWorkAround": false,
            "KPIAfterIdentification": 0,
            "KPIBeforeIdentification": 0,
            "KPITimeUntilRootCause": 0,
            "KnownErrorDate": null,
            "KnownErrorDuration": 0,
            "LastModBy": "Admin",
            "LastModDateTime": "2020-07-05T12:28:12Z",
            "OrganizationalUnit": "",
            "OrganizationalUnit_Valid": "",
            "Owner": "ADale",
            "OwnerEmailAddress": "user@domain.com",
            "OwnerTeam": "Problem Management",
            "OwnerTeam_Valid": "2D8BB522A",
            "Owner_Valid": "C195083CB",
            "Priority": "1",
            "Priority_Valid": "1F2B8",
            "ProblemDuration": 0,
            "ProblemLifetime": 0,
            "ProblemNumber": 106,
            "ReadOnly": false,
            "RecId": "588467A667",
            "Resolution": "File format not supported",
            "ResolutionAction": "Vendor Fix",
            "ResolutionAction_Valid": "443D4AB",
            "ResolutionEscLink": "",
            "ResolutionEscLink_Category": "",
            "ResolutionEscLink_RecID": "",
            "ResponseEscalationLink": "",
            "ResponseEscalationLink_Category": "",
            "ResponseEscalationLink_RecID": "",
            "RootCause": "",
            "RootCauseDateTimeCreated": "2012-11-07T04:35:27Z",
            "Service": "",
            "Service_Valid": "",
            "SocialTextHeader": "Problem 106: Unable to open Office 2007/2010 files",
            "Source": "Incident Management",
            "Source_Valid": "A76",
            "Status": "Resolved",
            "Status_Valid": "6C934",
            "Subject": "Unable to open Office 2007/2010 files",
            "TargetResolutionTime": null,
            "TotalTimeSpent": 377,
            "TotalWaitingDuration": 0,
            "TypeOfProblem": "Problem",
            "TypeOfProblem_Valid": "B14E72CCA804",
            "Urgency": "Medium",
            "Urgency_Valid": "44021B6053AE",
            "WaitingEscLink": "",
            "WaitingEscLink_Category": "",
            "WaitingEscLink_RecID": "",
            "Workaround": ""
        }
    }
}
```

#### Human Readable Output

>### 54A667 updated successfully
>|RecId|Subject|Status|CreatedDateTime|Urgency|OwnerTeam|CreatedBy|Owner|Category|Description|Priority|ClosedDateTime|SocialTextHeader|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 54A667 | Unable to open Office 2007/2010 files | Resolved | 2012-10-22T23:35:21Z | Medium | Problem Management | Admin | johnny cash | Applications | desc | 1 | 2020-07-05T12:28:12Z | Problem 106: Unable to open Office 2007/2010 files |


### ivanti-heat-object-delete
***
Delete a business object such as a change, problem, or incident by its Record ID.


#### Base Command

`ivanti-heat-object-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rec-id | Buisiness object ID | Required | 
| object-type | Type of object record | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ivanti-heat-object-delete object-type=incidents rec-id=490C3```

#### Context Example
```
{}
```

#### Human Readable Output

>Record 490C3 deleted successfully

### ivanti-heat-object-attachment-download
***
Get attachments from business objects by attachment ID.


#### Base Command

`ivanti-heat-object-attachment-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment-id | The attachment ID | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ivanti-heat-object-attachment-download attachment-id=C03CE103827944E59A4EC23498EA9C6A```

#### Context Example
```
{
    "File": {
        "EntryID": "1807ab951",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "5d1017c592",
        "Name": "a.txt",
        "SHA1": "aaf4c6182cd9aea9434d",
        "SHA256": "2cf24dba24",
        "SHA512": "9b71d224bd62cf73bcdec043",
        "SSDeep": "3:iKn:p",
        "Size": 5,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



### ivanti-heat-object-attachment-upload
***
Upload attachments to business objects.


#### Base Command

`ivanti-heat-object-attachment-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry-id | The entry ID of the file in XSOAR's context | Required | 
| rec-id | Buisiness object ID | Required | 
| object-type | Type of object record | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IvantiHeat.Attachment.AttachmentId | String | The ID of the attachment | 
| IvantiHeat.Attachment.FileName | String | The name of the attachment | 
| IvantiHeat.Attachment.RecId | String | Attachement buisiness object ID | 


#### Command Example
```!ivanti-heat-object-attachment-upload object-type=problem rec-id=D14D995B entry-id=18ab951```

#### Context Example
```
{
    "IvantiHeat": {
        "Attachment": {
            "AttachmentId": "A3039BF750",
            "FileName": "11.jpg",
            "RecId": "D14D995B"
        }
    }
}
```

#### Human Readable Output

>11.jpg uploaded successfully, attachment ID: A3039BF750

### ivanti-heat-object-perform-action
***
Performs quick actions for a business object. For example, close, clone or resolve an incident or a problem.


#### Base Command

`ivanti-heat-object-perform-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object-type | Type of object record | Required | 
| object-id | Buisiness object ID | Required | 
| action | The action to perform | Required | 
| request-data | The request body in JSON format | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ivanti-heat-object-perform-action action=Close_Incident object-id=123ABC object-type=incidents request-data=${ivantiHeat.CloseIncidentJSON}```

#### Human Readable Output
> Close_Incident action success


### ivanti-heat-object-create
***
create business objects available out-of-the-box, such as a Change, Problem, Incident, or any custom defined business object of your choice.


#### Base Command

`ivanti-heat-object-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object-type | Type of object record | Required | 
| fields | The request body in JSON format, or using script for create the request payload e.g IvantiHeatCloseIncidentExample | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IvantiHeat.incidents.RecId | String | Incident ID | 
| IvantiHeat.incidents.Subject | String | Incident subject | 
| IvantiHeat.incidents.Status | String | Incident status | 
| IvantiHeat.incidents.CreatedDateTime | Date | Incident createion time | 
| IvantiHeat.incidents.Symptom | String | Incident description | 
| IvantiHeat.incidents.OwnerTeam | String | Incident owner team | 
| IvantiHeat.incidents.IncidentNumber | Number | The incident number | 
| IvantiHeat.incidents.CreatedBy | String | The user who created the incident | 
| IvantiHeat.incidents.Owner | String | Incident owner | 
| IvantiHeat.incidents.Category | String | Incident category | 
| IvantiHeat.incidents.Priority | Number | Incident priority | 
| IvantiHeat.incidents.TypeOfIncident | String | Incident type | 
| IvantiHeat.incidents.ActualCategory | String | Incident actual category | 
| IvantiHeat.incidents.SocialTextHeader | String | Incident text header | 
| IvantiHeat.incidents.Email | String | Incident owner Email | 


#### Command Example
```!ivanti-heat-object-create object-type=incidents fields=`{"Category":"Connectivity","ProfileLink":"1087E597","Symptom":"the description","Subject":"test incident","Service":"Desktop Service","Owner":"johnny cash"}````

#### Context Example
```
{
    "IvantiHeat": {
        "incidents": {
            "@odata.context": "https://*ivanti-host*/api/odata/$metadata#incidents/$entity",
            "ActualCategory": "Connectivity",
            "ActualCategory_Valid": null,
            "ActualService": "Desktop Service",
            "ActualService_Valid": "164A9DCC1A",
            "AlternateContactEmail": null,
            "AlternateContactLink": null,
            "AlternateContactLink_Category": null,
            "AlternateContactLink_RecID": null,
            "AlternateContactPhone": null,
            "ApprovalStatus": null,
            "Approver": "user@domain.com",
            "Approver_Valid": "2F8539C7",
            "Category": "Connectivity",
            "Category_Valid": "6013B2C7",
            "CauseCode": null,
            "CauseCode_Valid": null,
            "ClosedBy": null,
            "ClosedDateTime": null,
            "ClosedDuration": 0,
            "ClosingEscLink": null,
            "ClosingEscLink_Category": null,
            "ClosingEscLink_RecID": null,
            "Cost": "0.0000",
            "CostPerMinute": "0.4000",
            "CostPerMinute_Currency": "USD",
            "CostPerMinute_CurrencyValid": null,
            "Cost_Currency": "USD",
            "Cost_CurrencyValid": null,
            "CreatedBy": "Admin",
            "CreatedByType": "Web Client",
            "CreatedDateTime": "2020-07-05T12:28:16Z",
            "CustomerDepartment": "IT",
            "CustomerLocation": "USA",
            "CustomerLocation_Valid": "A4DD2BCF246A",
            "Email": "user@domain.com",
            "EntityLink": "4A051AD111",
            "EntityLink_Category": "OrganizationalUnit",
            "EntityLink_RecID": "4A05123D6AD111",
            "EventCIRecId": null,
            "FirstCallResolution": false,
            "HRCaseLink": null,
            "HRCaseLink_Category": null,
            "HRCaseLink_RecID": null,
            "HoursOfOperation": "Weekly HOP",
            "HoursOfOperation_Valid": "FF57246B2E0047D193C1AEC1011D746B",
            "Impact": null,
            "Impact_Valid": null,
            "IncidentDetailSummary": null,
            "IncidentDetailWorkflowTag": null,
            "IncidentNetworkUserName": "jcash",
            "IncidentNumber": 112,
            "IsApprovalNeeded": false,
            "IsDSMTaskExisted": false,
            "IsInFinalState": false,
            "IsMasterIncident": false,
            "IsNewRecord": false,
            "IsNotification": true,
            "IsReclassifiedForResolution": false,
            "IsRelatedIncidentResolutionUpdate": false,
            "IsRelatedIncidentUpdate": false,
            "IsReportedByAlternateContact": false,
            "IsResolvedByMaster": false,
            "IsUnRead": false,
            "IsVIP": false,
            "IsWorkAround": false,
            "KnowledgeLink": null,
            "KnowledgeLink_Category": null,
            "KnowledgeLink_RecID": null,
            "LastModBy": "Admin",
            "LastModDateTime": "2020-07-05T12:28:16Z",
            "LoginId": "ATaylor",
            "MasterIncidentLink": null,
            "MasterIncidentLink_Category": null,
            "MasterIncidentLink_RecID": null,
            "NewNotes": null,
            "OrgUnitLink": "4A0AD111",
            "OrgUnitLink_Category": "OrganizationalUnit",
            "OrgUnitLink_RecID": "4A05123D611",
            "OrganizationUnitID": "GMI",
            "Owner": "ATaylor",
            "OwnerEmail": "user@domain.com",
            "OwnerTeam": "Service Desk",
            "OwnerTeamEmail": "user@domain.com",
            "OwnerTeam_Valid": "2E4BABF0D9B80C47",
            "OwnerType": "Employee",
            "Owner_Valid": "108452E597",
            "OwnershipAssignmentEmail": "user@domain.com",
            "OwningOrgUnitId": "GMI",
            "OwningOrgUnitId_Valid": "4A0AD111",
            "Phone": "+1 22.33.44",
            "PreviousState": null,
            "Priority": "3",
            "Priority_Valid": "29CD5096",
            "ProblemLink": null,
            "ProblemLink_Category": null,
            "ProblemLink_RecID": null,
            "ProfileFullName": "johnny cash",
            "ProfileLink": "108734597",
            "ProfileLink_Category": "Employee",
            "ProfileLink_RecID": "10873D64B452E597",
            "ProgressBarPosition": "3",
            "ReadOnly": false,
            "RecId": "FDF098DE",
            "ReportedBy": null,
            "ReportingOrgUnitID": null,
            "ReportingOrgUnitID_Valid": null,
            "Resolution": null,
            "ResolutionEscLink": null,
            "ResolutionEscLink_Category": null,
            "ResolutionEscLink_RecID": null,
            "ResolvedBy": null,
            "ResolvedByIncidentNumber": 0,
            "ResolvedByType": null,
            "ResolvedDateTime": null,
            "RespondedBy": null,
            "RespondedDateTime": null,
            "ResponseEscLink": null,
            "ResponseEscLink_Category": null,
            "ResponseEscLink_RecID": null,
            "SLA": "",
            "SLADisplayText": "",
            "SLALink": null,
            "SLALink_Category": null,
            "SLALink_RecID": null,
            "SendSurveyNotification": false,
            "Service": "Desktop Service",
            "ServiceOwnerEmail": null,
            "ServiceReqLink": null,
            "ServiceReqLink_Category": null,
            "ServiceReqLink_RecID": null,
            "Service_Valid": "164A2AC1A",
            "SocialTextHeader": "Incident 11152: test incident",
            "Source": "Phone",
            "Source_Valid": "EF78045C",
            "Status": "Active",
            "Status_Valid": "EAB221AA",
            "Subcategory": null,
            "Subcategory_Valid": null,
            "Subject": "test incident",
            "Symptom": "the description",
            "TeamManagerEmail": "user@domain.com",
            "TotalTimeSpent": 0,
            "TypeOfIncident": "Failure",
            "Urgency": null,
            "Urgency_Valid": null,
            "ViewType": null,
            "WaitingEscLink": null,
            "WaitingEscLink_Category": null,
            "WaitingEscLink_RecID": null,
            "helpdesk_Priority": null,
            "helpdesk_Priority_Valid": null
        }
    }
}
```

#### Human Readable Output

>### incidents object created successfully
>|RecId|Subject|Status|CreatedDateTime|Symptom|OwnerTeam|IncidentNumber|CreatedBy|Owner|Category|Priority|Email|TypeOfIncident|ActualCategory|SocialTextHeader|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| FDF08798DE | test incident | Active | 2020-07-05T12:28:16Z | the description | Service Desk | 152 | Admin | jcash | Connectivity | 3 | user@domain.com | Failure | Connectivity | Incident 112: test incident |