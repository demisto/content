BMC Helix Remedyforce integration allows customers to create/update service requests and incidents. It also allows to update status, resolve service requests and incidents with customer notes. This integration exposes standard ticketing capabilities that can be utilized as part of automation & orchestration.
This integration was integrated and tested with version 202002.79 of BMC Helix Remedyforce.
## Configure BMC Helix Remedyforce in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | BMC Remedyforce URL \(e.g. https://example.com) | True |
| username | Username | True |
| password | Password | True |
| type | Type | False |
| category | Category | False |
| impact | Impact | False |
| urgency | Urgency | False |
| status | Status | False |
| queue | Queue | False |
| max_incidents | Max Incidents | False |
| fetch_note | Fetch Note\(s\) | False |
| query | Query \(If provided other filtering parameters will be ignored\) e.g. select Name, LastModifiedDate from BMCServiceDesk\_\_Incident\_\_c where BMCServiceDesk\_\_Impact\_Id\_\_c = 'High' | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| request_timeout | HTTP\(S\) Request Timeout \(in seconds\) | True |
| isFetch | Fetch incidents | False |
| firstFetchTimestamp | First Fetch Timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bmc-remedy-service-request-definition-get
***
This command gets details of service request definitions with the help of service request definition name.


#### Base Command

`bmc-remedy-service-request-definition-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_request_definition_name | service_request_definition_name is the name of the service request definition whose details the user wants to get. If any value is not specified, it gets details of all service request definitions. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.ServiceRequestDefinition.Id | String | Service Request Definition Id. | 
| BmcRemedyforce.ServiceRequestDefinition.CategoryId | String | Category Id of the Service Request Definition. | 
| BmcRemedyforce.ServiceRequestDefinition.IsProblem | Boolean | Indicates if it is a problem or not. | 
| BmcRemedyforce.ServiceRequestDefinition.LastModifiedDate | Date | Last modified date. | 
| BmcRemedyforce.ServiceRequestDefinition.CreatedDate | Date | Created Date. | 
| BmcRemedyforce.ServiceRequestDefinition.Questions.Id | String | Id of question attached with Service Request Definition. | 
| BmcRemedyforce.ServiceRequestDefinition.Questions.IsRequired | Boolean | Indicates if a question is required or not. | 
| BmcRemedyforce.ServiceRequestDefinition.Questions.Type | String | Type of the question. | 
| BmcRemedyforce.ServiceRequestDefinition.Questions.Text | String | Name of the question. | 
| BmcRemedyforce.ServiceRequestDefinition.Conditions.SRDId | String | Service Request Definition Id of condition. | 
| BmcRemedyforce.ServiceRequestDefinition.Conditions.Value | String | Value of the condition. | 
| BmcRemedyforce.ServiceRequestDefinition.Conditions.Operator | String | Operator of the condition. | 
| BmcRemedyforce.ServiceRequestDefinition.Conditions.DependentQuestionId | String | Question Id of dependent question which is associated with the condition. | 
| BmcRemedyforce.ServiceRequestDefinition.Conditions.Id | String | Id of the condition. | 
| BmcRemedyforce.ServiceRequestDefinition.Conditions.QuestionId | String | Associate question Id for the condition. | 
| BmcRemedyforce.ServiceRequestDefinition.requestFor | String | Request for field value. | 
| BmcRemedyforce.ServiceRequestDefinition.requestedBy | String | Requested by field value. | 
| BmcRemedyforce.ServiceRequestDefinition.title | String | Title field value for Service Request Definition. | 
| BmcRemedyforce.ServiceRequestDefinition.description | String | Description field value for Service Request Definition. | 
| BmcRemedyforce.ServiceRequestDefinition.approvalRequired | Boolean | Indicates if approval is required or not. |


#### Command Example
```!bmc-remedy-service-request-definition-get service_request_definition_name="Ask Benefits/HR Question"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "ServiceRequestDefinition": {
            "CategoryId": "a212w000000UFftAAG",
            "CreatedDate": "2020-07-14 06:02:49",
            "Id": "a3H2w000000H5UhEAK",
            "IsProblem": false,
            "LastModifiedDate": "2020-07-14 06:02:49",
            "Questions": [
                {
                    "Id": "a3D2w000000TmAKEA0",
                    "IsRequired": false,
                    "Text": "Benefits/HR Question Details",
                    "Type": "header section"
                },
                {
                    "Id": "a3D2w000000TmALEA0",
                    "IsRequired": true,
                    "Text": "Please provide details on the information you are requesting",
                    "Type": "textarea"
                }
            ],
            "approvalRequired": false,
            "description": "Service Request for information pertaining to Benefits/HR",
            "email": "testuser@mail.com",
            "requestFor": "Test user",
            "requestedBy": "Test user",
            "title": "Ask Benefits/HR Question"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved service request definition(s): 1
>|Service Request Definition Id|Service Request Definition Name|Questions|
>|---|---|---|
>| a3H2w000000H5UhEAK | Ask Benefits/HR Question | Id: a3D2w000000TmAKEA0<br/>Question: Benefits/HR Question Details<br/>Is Required: No<br/><br/>Id: a3D2w000000TmALEA0<br/>Question: Please provide details on the information you are requesting<br/>Is Required: Yes |


### bmc-remedy-note-create
***
This command creates notes for incidents and service requests.


#### Base Command

`bmc-remedy-note-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_number | The unique incident or service request number that needs to be updated with a note. | Required | 
| summary | Description of incident or service request while creating the note.<br/>Default value of summary is 'Client Note'. | Optional | 
| note | Detailed note for incident or service request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Note.Id | String | Id of the created note. | 
| BmcRemedyforce.Note.WorkInfoType | String | Work Information of note. | 
| BmcRemedyforce.Note.ViewAccess | String | View Access Information of note. | 
| BmcRemedyforce.Note.Summary | String | The description of the note. | 
| BmcRemedyforce.Note.Submitter | String | User who added note. | 
| BmcRemedyforce.Note.srId | String | Id of the Service Request/Incident on which we have added note. | 
| BmcRemedyforce.Note.Notes | String | Note for Service Request/Incident. | 
| BmcRemedyforce.Note.ModifiedDate | Date | Last modified date for note. | 
| BmcRemedyforce.Note.CreatedDate | Date | Created date of note. | 


#### Command Example
```!bmc-remedy-note-create request_number=SR00000054 summary="demo note" note="demo note"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Note": {
            "CreatedDate": "2020-07-30 09:25:42",
            "Id": "a2N2w000000Y39FEAS",
            "ModifiedDate": "2020-07-30 09:25:42",
            "Notes": "demo note\r\ntestuser@bmcremedyforce.com 7/30/2020 2:25 AM",
            "Submitter": "Test user",
            "Summary": "Test user's summary",
            "srId": "a2U2w000000YGQREA4"
        }
    }
}
```

#### Human Readable Output

>The service request/incident SR00000054 is successfully updated with the note.

### bmc-remedy-service-request-update
***
This command updates the details of a service request for a given service request number.


#### Base Command

`bmc-remedy-service-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_request_number | The unique number of the service request for which details needs to be updated. | Required | 
| category_id | category_id is the unique Id of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes.<br/>Users can get the category Id from the category name using 'bmc-remedy-category-details-get' command. | Optional | 
| queue_id | queue_id is the unique Id of the owner.<br/>Users can get the queue Id from the owner name using 'bmc-remedy-queue-details-get' command. | Optional | 
| staff_id | staff_id is the unique Id of the staff to whom the user wants to assign the record.<br/>Users can get the staff Id from the staff details using 'bmc-remedy-user-details-get' command. | Optional | 
| status_id | status_id is the unique Id of the status that is used to display the progress of the service request through its stages of opening to closure. <br/>Users can get the status Id from the status name using 'bmc-remedy-status-details-get' command. | Optional | 
| urgency_id | urgency_id is the unique Id of the urgency which is used to determine the priority of the service request. <br/>Users can get the urgency Id from the urgency name using 'bmc-remedy-urgency-details-get' command. | Optional | 
| client_id | client_id is the unique Id of the client. It helps to select a client for a particular service request.<br/>Users can get the client Id from the email using 'bmc-remedy-user-details-get' command. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". <br/>Possible fields: impact_id, account_id or any other custom field. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.ServiceRequest.Number | String | Service request number. | 
| BmcRemedyforce.ServiceRequest.Id | String | Service request Id. | 
| BmcRemedyforce.ServiceRequest.LastUpdatedDate | String | Last updated date &amp; time of a service request. | 


#### Command Example
```!bmc-remedy-service-request-update service_request_number=SR00000054 status_id=a3w2w000000TfGlAAK category_id=a212w000000UFfyAAG aditional_fields="impact_id=HIGH;asset_id=a0K2w000000wi2uEAA"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "ServiceRequest": {
            "Id": "a2U2w000000YGQREA4",
            "LastUpdatedDate": "2020-08-01T12:05:48Z",
            "Number": "00000054"
        }
    }
}
```

#### Human Readable Output

>The service request 00000054 is successfully updated.

### bmc-remedy-service-request-create
***
This command allows the user to create a new service request. A service request is the request record that is generated from the service request definition to manage and track the execution.


#### Base Command

`bmc-remedy-service-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_request_definition_id | The unique Id of the service request definition.<br/>Users can get the service request definition Id from service request definition name using 'bmc-remedy-service-request-definition-get' command. | Required | 
| service_request_definition_params | Each service request definition expects specific parameters to be supplied. Specify the parameters as a delimiter (;) separated string.<br/>Example: "param1=value1; param2=value2". | Optional | 
| client_id | client_id is the unique Id of the client. It helps to select a client for a particular service request.<br/>Users can get the client Id from the email using 'bmc-remedy-user-details-get' command. | Optional | 
| category_id | category_id is the unique Id of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes.<br/>Users can get the category Id from the category name using 'bmc-remedy-category-details-get' command. | Optional | 
| queue_id | queue_id is the unique Id of the owner. <br/>Users can get the queue Id from the owner name using 'bmc-remedy-queue-details-get' command. | Optional | 
| staff_id | staff_id is the unique Id of the staff to whom the user wants to assign the record.<br/>Users can get the staff Id from the staff details using 'bmc-remedy-user-details-get' command. | Optional | 
| urgency_id | urgency_id is the unique Id of the urgency which is used to determine the priority of the service request.<br/>Users can get the urgency Id from the urgency name using 'bmc-remedy-urgency-details-get' command. | Optional | 
| status_id | status_id is the unique Id of the status that is used to display the progress of the service request through its stages of opening to closure.<br/>Users can get the status Id from the status name using 'bmc-remedy-status-details-get' command. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". <br/>Possible fields: impact_id, account_id or any other custom field. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.ServiceRequest.Number | String | Service request number. | 
| BmcRemedyforce.ServiceRequest.Id | String | Service request Id. | 
| BmcRemedyforce.ServiceRequest.CreatedDate | String | Creation date &amp; time of service request. | 


#### Command Example
```!bmc-remedy-service-request-create service_request_definition_id=a3H2w000000H5UVEA0 category_id=a212w000000UFfyAAG status_id=a3w2w000000TfGBAA0```

#### Context Example
```
{
    "BmcRemedyforce": {
        "ServiceRequest": {
            "CreatedDate": "2020-08-01T12:05:13Z",
            "Id": "a2U2w000000YTEhEAO",
            "Number": "00012192"
        }
    }
}
```

#### Human Readable Output

>The service request 00012192 is successfully created.

### bmc-remedy-template-details-get
***
This command helps to get template details for Incidents. Templates enable users to prepopulate commonly used fields in a form.


#### Base Command

`bmc-remedy-template-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_name | template_name is the name of the template whose details the user wants to get. If any value is not specified, it gets details of all the available templates. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Template.Id | String | Template Id. | 
| BmcRemedyforce.Template.Name | String | Template name. | 
| BmcRemedyforce.Template.Description | String | Template description. | 
| BmcRemedyforce.Template.Recurring | Boolean | Recurrence of template. | 


#### Command Example
```!bmc-remedy-template-details-get template_name="General Support - SR"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Template": {
            "Description": "Used for the General Support Service Request to capture any issues or requests that may not yet be covered by published SRs.",
            "Id": "a3k2w000000LSl9AAG",
            "Name": "General Support - SR",
            "Recurring": false
        }
    }
}
```

#### Human Readable Output

>### Total retrieved template(s): 1
>|Id|Name|Description|Recurring|
>|---|---|---|---|
>| a3k2w000000LSl9AAG | General Support - SR | Used for the General Support Service Request to capture any issues or requests that may not yet be covered by published SRs. | false |


### bmc-remedy-impact-details-get
***
This command helps to get impact details for incidents and service requests. Impact helps to calculate priority of the incident or service request.


#### Base Command

`bmc-remedy-impact-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| impact_name | impact_name is the name of the impact whose details the user wants to get. If any value is not specified, it gets details of all the available impacts. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Impact.Id | String | Impact Id. | 
| BmcRemedyforce.Impact.Name | String | Impact Name. | 


#### Command Example
```!bmc-remedy-impact-details-get impact_name=HIGH```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Impact": {
            "Id": "a2M2w000000UApmEAG",
            "Name": "HIGH"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved impact(s): 1
>|Id|Name|
>|---|---|
>| a2M2w000000UApmEAG | HIGH |


### bmc-remedy-service-offering-details-get
***
This command helps to get service offering details for incidents. Users can link a service offering of the associated service.


#### Base Command

`bmc-remedy-service-offering-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_offering_name | service_offering_name is the name of service offering whose details the user wants to get. If any value is not specified, it gets details of all the available service offerings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.ServiceOffering.Id | String | Service offering Id. | 
| BmcRemedyforce.ServiceOffering.Name | String | Service offering name. | 


#### Command Example
```!bmc-remedy-service-offering-details-get service_offering_name="Building Access"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "ServiceOffering": {
            "Id": "a0K2w000000wi3FEAQ",
            "Name": "Building Access"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved service offering(s): 1
>|Id|Name|
>|---|---|
>| a0K2w000000wi3FEAQ | Building Access |


### bmc-remedy-incident-create
***
This command allows the user to create a new incident.


#### Base Command

`bmc-remedy-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_id | client_id is the unique Id of the client. It helps to select a client for a particular Incident.<br/>Users can get the client Id from the email using 'bmc-remedy-user-details-get' command. | Required | 
| description | This field represents the description of the incident that the user wants to create. | Optional | 
| opened_date | opened_date is the date and time at which the incident was created. Use the yyyy-MM-ddTHH:mm:ss.SSS+/-HHmm or yyyy-MM-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. | Optional | 
| due_date | due_date is the date and time at which the incident should be completed. Use the yyyy-MM-ddTHH:mm:ss.SSS+/-HHmm or yyyy-MM-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. | Optional | 
| queue_id | queue_id is the unique Id of the owner.<br/>Users can get the queue Id from the owner name using 'bmc-remedy-queue-details-get' command. | Optional | 
| template_id | template_id is the unique Id of the template. Templates enable users to pre-populate commonly used fields in a form. <br/>Users can get the template Id from the template name using 'bmc-remedy-template-details-get' command. | Optional | 
| category_id | category_id is the unique Id of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes.<br/>Users can get the category Id from the category name using 'bmc-remedy-category-details-get' command. | Optional | 
| urgency_id | urgency_id is the unique Id of the urgency which is used to determine the priority of the incident.<br/>Users can get the urgency Id from the urgency name using 'bmc-remedy-urgency-details-get' command. | Optional | 
| status_id | status_id is the unique Id of the status that is used to display the progress of the incident through its stages of opening to closure. Users can get the status Id from the status name using 'bmc-remedy-status-details-get' command. | Optional | 
| staff_id | staff_id is the unique Id of the staff to whom the user wants to assign the record.<br/>Users can get the staff Id from the staff details using 'bmc-remedy-user-details-get' command. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". <br/>Possible fields: broadcast_id, service_id,impact_id, service_offering_id, asset_id, outage_start, outage_end, account_id or any other custom field. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Incident.Id | String | Incident Id. | 
| BmcRemedyforce.Incident.Number | String | Incident number. | 
| BmcRemedyforce.Incident.CreatedDate | String | Creation date &amp; time of Incident. | 


#### Command Example
```!bmc-remedy-incident-create client_id=0052w000004Z9vJAAS status_id=a3w2w000000TfGlAAK category_id=a212w000000UFfyAAG```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Incident": {
            "CreatedDate": "2020-08-01 12:06:08",
            "Id": "a2U2w000000YTEmEAO",
            "Number": "00012193"
        }
    }
}
```

#### Human Readable Output

>The incident 00012193 is successfully created.

### bmc-remedy-incident-update
***
This command updates the details of an incident for a given incident number.


#### Base Command

`bmc-remedy-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_number | The unique number of the incident whose details need to be updated. | Required | 
| category_id | category_id is the unique Id of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes.<br/>Users can get the category Id from the category name using 'bmc-remedy-category-details-get' command. | Optional | 
| queue_id | queue_id is the unique Id of the owner.<br/>Users can get the queue Id from the owner name using 'bmc-remedy-queue-details-get' command. | Optional | 
| staff_id | staff_id is the unique Id of the staff to whom the user wants to assign the record.<br/>Users can get the staff Id from the staff details using 'bmc-remedy-user-details-get' command. | Optional | 
| status_id | status_id is the unique Id of the status that is used to display the progress of the incident through its stages of opening to closure. <br/>Users can get the status Id from the status name using 'bmc-remedy-status-details-get' command. | Optional | 
| urgency_id | urgency_id is the unique Id of the urgency which is used to determine the priority of the incident.<br/>Users can get the urgency Id from the urgency name using 'bmc-remedy-urgency-details-get' command. | Optional | 
| due_date | due_date is the date and time until which the incident should be completed. Use the yyyy-MM-ddTHH:mm:ss.SSS+/-HHmm or yyyy-MM-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. | Optional | 
| client_id | client_id is the unique Id of the client. It helps to select the client for a particular incident.<br/>Users can get the client Id from the email using 'bmc-remedy-user-details-get' command. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". <br/>Possible fields: broadcast_id, service_id,impact_id, service_offering_id, asset_id, outage_start, outage_end, account_id or any other custom field. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Incident.Id | String | Incident Id. | 
| BmcRemedyforce.Incident.Number | String | Incident number. | 
| BmcRemedyforce.Incident.LastUpdatedDate | String | Last updated date &amp; time of Incident. | 


#### Command Example
```!bmc-remedy-incident-update incident_number=IN00000182 status_id=a3w2w000000TfGlAAK category_id=a212w000000UFfyAAG aditional_fields="impact_id=HIGH;asset_id=a0K2w000000wi2uEAA" using=BMCHelixRemedyforce_instance_1```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Incident": {
            "Id": "a2U2w000000YGaHEAW",
            "LastUpdatedDate": "2020-08-01T12:05:37Z",
            "Number": "00000182"
        }
    }
}
```

#### Human Readable Output

>The incident 00000182 is successfully updated.

### bmc-remedy-asset-details-get
***
This command helps to get asset or configuration item details for incidents.


#### Base Command

`bmc-remedy-asset-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | asset_name is the name of the asset for which the command will find the metadata. | Optional | 
| instance_type | Assets belonging to the selected instance_type will be populated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Asset.Id | String | Asset Id. | 
| BmcRemedyforce.Asset.Name | String | Asset name. | 
| BmcRemedyforce.Asset.Description | String | Asset description. | 
| BmcRemedyforce.Asset.Class_Name | String | Asset under BMC class type. | 
| BmcRemedyforce.Asset.Asset_Number | String | Asset number. | 
| BmcRemedyforce.Asset.Instance_Type | String | Assets belonging to selected class. | 


#### Command Example
```!bmc-remedy-asset-details-get asset_name=BlackBerry-Houston01```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Asset": {
            "Asset_Number": "1102942",
            "Class_Name": "BMC_ComputerSystem",
            "Description": "Houston BlackBerry Server",
            "Id": "a0K2w000000wi1bEAA",
            "Instance_Type": "CI / Asset",
            "Name": "BlackBerry-Houston01"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved asset(s): 1
>|Id|Name|Description|Asset #|Class Name|Instance Type|
>|---|---|---|---|---|---|
>| a0K2w000000wi1bEAA | BlackBerry-Houston01 | Houston BlackBerry Server | 1102942 | BMC_ComputerSystem | CI / Asset |


### bmc-remedy-account-details-get
***
This command helps to get account details for incidents and service requests.


#### Base Command

`bmc-remedy-account-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | account_name is the account name of the account whose details the user wants to get. If any value is not specified, it gets details of all the available accounts. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Account.Id | String | Account Id. | 
| BmcRemedyforce.Account.Name | String | Account name. | 


#### Command Example
```!bmc-remedy-account-details-get account_name="test_account"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Account": {
            "Id": "0012w00000GMthNAAT",
            "Name": "test_account"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved account(s): 1
>|Id|Name|
>|---|---|
>| 0012w00000GMthNAAT | test_account |


### bmc-remedy-status-details-get
***
This command helps to get status details for incidents and service requests. Status is used to display the progress of the service request or incident through its stages of opening to closure.


#### Base Command

`bmc-remedy-status-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status_name | status_name is the status name whose details the user wants to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Status.Id | String | Status Id. | 
| BmcRemedyforce.Status.Name | String | Status name. | 


#### Command Example
```!bmc-remedy-status-details-get status_name="OPENED"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Status": {
            "Id": "a3w2w000000TfGBAA0",
            "Name": "OPENED"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved status: 1
>|Id|Name|
>|---|---|
>| a3w2w000000TfGBAA0 | OPENED |


### bmc-remedy-urgency-details-get
***
This command helps to get urgency details for incidents and service requests. Urgency is used to determine the priority of the incident or service request.


#### Base Command

`bmc-remedy-urgency-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urgency_name | urgency_name is the name of the urgency whose details the user wants to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Urgency.Id | String | Urgency Id. | 
| BmcRemedyforce.Urgency.Name | String | Urgency name. | 


#### Command Example
```!bmc-remedy-urgency-details-get urgency_name="LOW"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Urgency": {
            "Id": "a472w000000Tyk6AAC",
            "Name": "LOW"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved urgencies: 1
>|Id|Name|
>|---|---|
>| a472w000000Tyk6AAC | LOW |


### bmc-remedy-category-details-get
***
This command helps to get category details for incidents and service requests. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes.


#### Base Command

`bmc-remedy-category-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | type is the category type whose details the user wants to get. | Optional | 
| category_name | category_name is the category name whose details the user wants to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Category.Id | String | Category Id. | 
| BmcRemedyforce.Category.Name | String | Category name. | 
| BmcRemedyforce.Category.ChildrenCount | String | Number of children of the category. | 


#### Command Example
```!bmc-remedy-category-details-get category_name="Email"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Category": {
            "ChildrenCount": 0,
            "Id": "a212w000000UFfyAAG",
            "Name": "Email"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved categories: 1
>|Id|Name|Children Count|
>|---|---|---|
>| a212w000000UFfyAAG | Email | 0.0 |


### bmc-remedy-queue-details-get
***
This command helps to get queue details for incidents and service requests. It accepts queue name and type as arguments.


#### Base Command

`bmc-remedy-queue-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_name | queue_name is the name of the queue as the owner whose details the user wants to get. | Optional | 
| type | type will allow the user to filter with its possible values as incident or service request and get details accordingly. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Queue.Id | String | Queue Id. | 
| BmcRemedyforce.Queue.Name | String | Queue name. | 
| BmcRemedyforce.Queue.Email | String | Queue email. | 


#### Command Example
```!bmc-remedy-queue-details-get queue_name="Application Development"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Queue": {
            "Email": "testuser@bmcremedyforce.com",
            "Id": "00G2w0000027SeUEAU",
            "Name": "Application Development"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved queue(s): 1
>|Id|Name|Email|
>|---|---|---|
>| 00G2w0000027SeUEAU | Application Development |  testuser@bmcremedyforce.com |


### bmc-remedy-user-details-get
***
This command helps to get user details for incidents and service requests. It accepts username, account name, email, queue name, and is_staff as arguments.


#### Base Command

`bmc-remedy-user-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | username is the name of the user whose details the user wants to get. | Optional | 
| account_name | account_name is the account name of the user whose details the user wants to get. | Optional | 
| email | email is the email address of the user whose details the user wants to get. | Optional | 
| queue_name | queue_name is the group/queue name for which user wants to get user details. | Optional | 
| is_staff | is_staff will allow the user to filter with its possible values true or false and get details of users accordingly. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.User.Id | String | User Id which uniquely identifies the user. | 
| BmcRemedyforce.User.Name | String | Full name of the user. | 
| BmcRemedyforce.User.FirstName | String | First name of the user. | 
| BmcRemedyforce.User.LastName | String | Last name of the user. | 
| BmcRemedyforce.User.Username | String | Username of the user. | 
| BmcRemedyforce.User.Email | String | Email of the user. | 
| BmcRemedyforce.User.Phone | String | Phone number of the user. | 
| BmcRemedyforce.User.Account | String | Account name of the user. | 
| BmcRemedyforce.User.CompanyName | String | Company name of the user. | 
| BmcRemedyforce.User.Division | String | Division of the user. | 
| BmcRemedyforce.User.Department | String | Department name of the user. | 
| BmcRemedyforce.User.Title | String | Title of the user. | 
| BmcRemedyforce.User.IsStaff | Boolean | Shows whether the user belongs to the staff or not. | 


#### Command Example
```!bmc-remedy-user-details-get queue_name="BMC Client Management"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "User": [
            {
                "CompanyName": "Company",
                "Email": "bmcremedyforce@example.com",
                "FirstName": "user1",
                "Id": "0052w000004nsLdAAI",
                "IsStaff": true,
                "LastName": "test",
                "Name": "user1 test",
                "Username": "testuser1@bmcremedyforce.com"
            },
            {
                "CompanyName": "Company",
                "Email": "bmcremedyforce@example.com",
                "FirstName": "user2",
                "Id": "0052w000004nsLaAAI",
                "IsStaff": true,
                "LastName": "test",
                "Name": "user2 test",
                "Username": "testuser2@bmcremedyforce.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total retrieved user(s): 2
>|Id|Username|First Name|Last Name|Email|Company Name|Is Staff|
>|---|---|---|---|---|---|---|
>| 0052w000004nsLdAAI | testuser1@bmcremedyforce.com | user1 | test | bmcremedy@example.com | Company | true | 
>| 0052w000004nsLaAAI | testuser2@bmcremedyforce.com | user2 | test | bmcremedy@example.com | Company | true |


### bmc-remedy-broadcast-details-get
***
This command helps to get broadcast details for incidents. Broadcast enables users to send messages to the entire organization, selected groups within the organization and to external customers.


#### Base Command

`bmc-remedy-broadcast-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| broadcast_name | broadcast_name is the name of the broadcast whose details the user wants to get. | Optional | 
| category_name | category_name is the name of the category whose details the user wants to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Broadcast.Id | String | Broadcast Id. | 
| BmcRemedyforce.Broadcast.Name | String | Broadcast name. | 
| BmcRemedyforce.Broadcast.Description | String | Broadcast description. | 
| BmcRemedyforce.Broadcast.Category | String | Broadcast category. | 
| BmcRemedyforce.Broadcast.Status | String | Broadcast status. | 
| BmcRemedyforce.Broadcast.Priority | String | Broadcast priority. | 
| BmcRemedyforce.Broadcast.Urgency | String | Broadcast urgency. | 
| BmcRemedyforce.Broadcast.Impact | String | Broadcast impact. | 


#### Command Example
```!bmc-remedy-broadcast-details-get broadcast_name="BES Server is down completely"```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Broadcast": {
            "Category": "Telecommunication",
            "Id": "a1v2w000000IaP7AAK",
            "Impact": "HIGH",
            "Name": "BES Server is down completely",
            "Priority": "1",
            "Status": "OPENED",
            "Urgency": "HIGH"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved broadcast(s): 1
>|Id|Name|Priority|Urgency|Impact|Category|Status|
>|---|---|---|---|---|---|---|
>| a1v2w000000IaP7AAK | BES Server is down completely | 1 | HIGH | HIGH | Telecommunication | OPENED |


### bmc-remedy-incident-get
***
This command helps to get details of incidents.


#### Base Command

`bmc-remedy-incident-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_fetch_time | The time range to consider for getting the incident. Use the format "&lt;number&gt; &lt;time unit&gt;". Example: 12 hours, 7 days, 3 months, 1 year. | Optional | 
| incident_number | The unique number of the incident whose details user wants to get. | Optional | 
| maximum_incident | The maximum number of the incidents user wants to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.Incident.Id | String | Incident Id. | 
| BmcRemedyforce.Incident.Number | String | Incident number. | 
| BmcRemedyforce.Incident.Priority | String | Incident priority. | 
| BmcRemedyforce.Incident.Description | String | Incident description. | 
| BmcRemedyforce.Incident.ClientID | String | Incident client Id. | 
| BmcRemedyforce.Incident.Status | String | Incident status. | 
| BmcRemedyforce.Incident.dueDateTime | String | Incident due datetime. | 
| BmcRemedyforce.Incident.Staff | String | Incident staff. | 
| BmcRemedyforce.Incident.Queue | String | Incident queue. | 
| BmcRemedyforce.Incident.Category | String | Incident category. | 
| BmcRemedyforce.Incident.Urgency | String | Incident urgency. | 
| BmcRemedyforce.Incident.ClientAccount | String | Incident client account. | 
| BmcRemedyforce.Incident.Broadcast | String | Incident broadcast. | 
| BmcRemedyforce.Incident.closeDateTime | String | Incident close datetime. | 
| BmcRemedyforce.Incident.CreatedDate | String | Incident created date. | 
| BmcRemedyforce.Incident.LastModifiedDate | String | Incident last modified date. | 
| BmcRemedyforce.Incident.openDateTime | String | Incident open datetime. | 
| BmcRemedyforce.Incident.outageTo | String | Incident outage end. | 
| BmcRemedyforce.Incident.outageFrom | String | Incident outage start. | 
| BmcRemedyforce.Incident.Resolution | String | Incident resolution. | 
| BmcRemedyforce.Incident.respondedDateTime | String | Incident responded datetime. | 
| BmcRemedyforce.Incident.Service | String | Incident service. | 
| BmcRemedyforce.Incident.ServiceOffering | String | Incident service offering. | 
| BmcRemedyforce.Incident.Template | String | Incident template. | 
| BmcRemedyforce.Incident.Type | String | Incident type. | 
| BmcRemedyforce.Incident.Impact | String | Incident impact. | 
| BmcRemedyforce.Incident.Asset | String | Incident asset. | 


#### Command Example
```!bmc-remedy-incident-get last_fetch_time="1 hours" maximum_incident=2  ```

#### Context Example
```
{
    "BmcRemedyforce": {
        "Incident": {
            "Category": "Human Resources",
            "ClientID": "Clinet ID",
            "CreatedDate": "2020-08-14T12:47:58.000+0000",
            "Id": "a2U2w00000096QEEAY",
            "Impact": "LOW",
            "LastModifiedDate": "2020-08-14T15:18:07.000+0000",
            "Number": "00000059",
            "Priority": "5",
            "Service": "Client Services",
            "Staff": "Staff Name",
            "Status": "OPENED",
            "Template": "Benefits Question - SR",
            "Type": "Incident",
            "Urgency": "LOW",
            "dueDateTime": "2020-08-17T20:47:58.000+0000",
            "openDateTime": "2020-08-14T12:47:58.000+0000"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved incident(s): 1
>|Number|Priority|Client ID|Status|Staff|
>|---|---|---|---|---|
>| 00000059 | 5 | Client ID | OPENED | Staff Name |


### bmc-remedy-service-request-get
***
This command helps to get the service request details.


#### Base Command

`bmc-remedy-service-request-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_request_number | The unique number of the service request whose details user wants to get. | Optional | 
| last_fetch_time | The time range to consider for getting the service request. Use the format "&lt;number&gt; &lt;time unit&gt;". Example: 12 hours, 7 days, 3 months, 1 year. | Optional | 
| maximum_service_request | The maximum number of the service request user wants to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcRemedyforce.ServiceRequest.Id | String | Service Request Id. | 
| BmcRemedyforce.ServiceRequest.Number | String | Service Request number. | 
| BmcRemedyforce.ServiceRequest.Priority | String | Service Request priority. | 
| BmcRemedyforce.ServiceRequest.Description | String | Service Request description. | 
| BmcRemedyforce.ServiceRequest.ClientID | String | Service Request client. | 
| BmcRemedyforce.ServiceRequest.Status | String | Service Request status. | 
| BmcRemedyforce.ServiceRequest.DueDateTime | String | Service Request due datetime. | 
| BmcRemedyforce.ServiceRequest.Staff | String | Service Request staff. | 
| BmcRemedyforce.ServiceRequest.Queue | String | Service Request queue. | 
| BmcRemedyforce.ServiceRequest.Category | String | Service Request category. | 
| BmcRemedyforce.ServiceRequest.Urgency | String | Service Request urgency. | 
| BmcRemedyforce.ServiceRequest.Broadcast | String | Service Request broadcast. | 
| BmcRemedyforce.ServiceRequest.closeDateTime | String | Service Request close datetime. | 
| BmcRemedyforce.ServiceRequest.CreatedDate | String | Service Request created date. | 
| BmcRemedyforce.ServiceRequest.LastUpdatedDate | String | Service Request last modified date. | 
| BmcRemedyforce.ServiceRequest.OpenDateTime | String | Service Request open datetime. | 
| BmcRemedyforce.ServiceRequest.Resolution | String | Service Request resolution. | 
| BmcRemedyforce.ServiceRequest.ServiceOffering | String | Service Request service offering. | 
| BmcRemedyforce.ServiceRequest.Template | String | Service Request template. | 
| BmcRemedyforce.ServiceRequest.Impact | String | Service Request impact. | 
| BmcRemedyforce.ServiceRequest.BusinessService | String | Service Request business service. | 
| BmcRemedyforce.ServiceRequest.ServiceRequestDefinition | String | Service Request definition. | 
| BmcRemedyforce.ServiceRequest.ClientAccount | String | Account held by service request. | 
| BmcRemedyforce.ServiceRequest.Type | String | Service Desk Type. | 


#### Command Example
```!bmc-remedy-service-request-get last_fetch_time="1 hours" maximum_service_request=2```

#### Context Example
```
{
    "BmcRemedyforce": {
        "ServiceRequest": {
            "BusinessService": "Printing Services",
            "Category": "File & Print",
            "CreatedDate": "2020-08-14T13:32:17.000+0000",
            "DueDateTime": "2020-08-17T21:32:16.000+0000",
            "Id": "a2U2w00000096yCEAQ",
            "Impact": "LOW",
            "LastUpdatedDate": "2020-08-14T14:28:12.000+0000",
            "Number": "00000929",
            "OpenDateTime": "2020-08-14T13:32:16.000+0000",
            "Priority": "5",
            "Queue": "Incident Queue",
            "ServiceOffering": "Printer Configuration",
            "ServiceRequestDefinition": "Setup Printer",
            "Status": "OPENED",
            "Template": "Printer Setup - SR",
            "Type": "Service Request",
            "Urgency": "LOW"
        }
    }
}
```

#### Human Readable Output

>### Total retrieved service request(s): 1
>|Number|Priority|Status|Queue|
>|---|---|---|---|
>| 00000929 | 5 | OPENED | Incident Queue |
