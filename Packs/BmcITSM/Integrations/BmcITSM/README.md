BMC Remedy ITSM integration allows customers to manage service request, incident, change request, task, problem investigation and known error tickets.
This integration was integrated and tested with version 21.02 of BmcITSM

## Configure BMC Remedy ITSM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BMC Remedy ITSM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | For Example: https://localhost:8008 | True |
    | Username |  | True |
    | Password |  | True |
    | Maximum incidents per fetch. | Default is 50. Maximum is 200. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). |  | False |
    | Ticket Type | The type of the tickets to fetch. | False |
    | Ticket Status | The status of the tickets to fetch. Since Each ticket type has it's own unique status pool, consider to select only those who match to the selected ticket types. | False |
    | Ticket Impact | The impact of the tickets to fetch. | False |
    | Ticket Urgency | The urgnecy of the tickets to fetch. | False |
    | Fetch By Query | Search qualification to fetch tickets. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing params. You can Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html | False |
    | Fetch incidents |  | False |
    | Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from  BMC Remedy ITSM to XSOAR\), Outgoing \(from XSOAR to BMC Remedy ITSM\), or Incoming and Outgoing \(from/to XSOAR and BMC Remedy ITSM\). | False |
    | Close Mirrored XSOAR Incident | When selected, closing the BMC Remedy ITSM ticket is mirrored in Cortex XSOAR. | False |
    | Close Mirrored BMC Remedy ITSM Ticket | When selected, closing the XSOAR incident is mirrored in BMC Remedy ITSM. | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bmc-itsm-user-list
***
List users profile in BMC Helix ITSM. The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them.


#### Base Command

`bmc-itsm-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | Comma separated list of user ID. Filtering argument. Possible values are: . | Optional | 
| query | Search qualification to list by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| first_name | The user first name. Filtering argument. Possible values are: . | Optional | 
| last_name | The user first name. Filtering argument. Possible values are: . | Optional | 
| company | The user company name. Filtering argument. Possible values are: . | Optional | 
| department | The user department name. Filtering argument. Possible values are: . | Optional | 
| organization | The user organization name. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.User.Id | String | user ID. | 
| BmcITSM.User.FirstName | String | user first name. | 
| BmcITSM.User.LastName | String | user last name. | 

#### Command example
```!bmc-itsm-user-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "User": [
            {
                "Company": "Calbro Services",
                "Department": null,
                "FirstName": "App",
                "Id": "PPL000000000005",
                "LastName": "Admin",
                "Organization": null,
                "Region": "Americas",
                "Site": "Headquarters, Building 1.31",
                "SiteGroup": "United States"
            },
            {
                "Company": "Calbro Services",
                "Department": null,
                "FirstName": "Orchestration",
                "Id": "PPL000000000012",
                "LastName": "Admin",
                "Organization": null,
                "Region": "Americas",
                "Site": "Headquarters, Building 1.31",
                "SiteGroup": "United States"
            }
        ]
    }
}
```

#### Human Readable Output

>### List Users.
>Showing 2 records out of 12.
>|Id|First Name|Last Name|Company|Department|Site Group|Region|Site|Organization|
>|---|---|---|---|---|---|---|---|---|
>| PPL000000000005 | App | Admin | Calbro Services |  | United States | Americas | Headquarters, Building 1.31 |  |
>| PPL000000000012 | Orchestration | Admin | Calbro Services |  | United States | Americas | Headquarters, Building 1.31 |  |


### bmc-itsm-company-list
***
List companies in BMC Helix ITSM. The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them.


#### Base Command

`bmc-itsm-company-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_ids | Comma separated list of company ID. Filtering argument. Possible values are: . | Optional | 
| query | Search qualification to list by.For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| company | The user company name. Filtering argument. Possible values are: . | Optional | 
| company_type | The user company type. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Company.Id | String | Company ID | 
| BmcITSM.Company.Name | String | Company name. | 
| BmcITSM.Company.Type | String | Company Type | 

#### Command example
```!bmc-itsm-company-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "Company": [
            {
                "Id": "CPY000000000015",
                "Name": "- Global -",
                "Type": "- System -"
            },
            {
                "Id": "CPY000000000016",
                "Name": "Adobe Systems",
                "Type": "Manufacturer"
            }
        ]
    }
}
```

#### Human Readable Output

>### List Companies.
>Showing 2 records out of 28.
>|Id|Name|Type|
>|---|---|---|
>| CPY000000000015 | - Global - | - System - |
>| CPY000000000016 | Adobe Systems | Manufacturer |


### bmc-itsm-service-request-definition-list
***
List service request definitions. The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them.


#### Base Command

`bmc-itsm-service-request-definition-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| srd_ids | Comma separated list of service request defintion ID. Filtering argument. Possible values are: . | Optional | 
| query | Search qualification to list by.For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| description | Service request definition description. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ServiceRequestDefinition.Id | String | Service Request definition ID. | 
| BmcITSM.ServiceRequestDefinition.Description | String | Service Request Definition Description. | 
| BmcITSM.ServiceRequestDefinition.InstanceID | String | Service Request Instance ID. Useful for creating Service Request. | 

#### Command example
```!bmc-itsm-service-request-definition-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "ServiceRequestDefinition": [
            {
                "Description": "Other request to facilities that isn't specifically listed.",
                "Id": "000000000000382",
                "InstanceID": "SRGAA5V0GENAWAO6U31IO5YO03KYL3"
            },
            {
                "Description": "Request to order new office equipment",
                "Id": "000000000000381",
                "InstanceID": "SRGAA5V0GENAWAO6U2OFO5YNN0K4Y6"
            }
        ]
    }
}
```

#### Human Readable Output

>### List service request definitions.
>Showing 2 records out of 157.
>|Id|Description|Instance ID|
>|---|---|---|
>| 000000000000382 | Other request to facilities that isn't specifically listed. | SRGAA5V0GENAWAO6U31IO5YO03KYL3 |
>| 000000000000381 | Request to order new office equipment | SRGAA5V0GENAWAO6U2OFO5YNN0K4Y6 |


### bmc-itsm-ticket-list
***
List BMC Helix ITSM tickets.The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them. 


#### Base Command

`bmc-itsm-ticket-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_type | The type of the tickets to list by. Possible values are: service request, incident, task, change request, problem investigation, known error. | Required | 
| query | Search qualification to list by.For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| ticket_ids | Comma separated list of ticket request ID. Filtering argument. Possible values are: . | Optional | 
| status | Ticket status. Since Each ticket type has it's own unique status pool, consider to select only those who match to the selected ticket types. Filtering argument. Possible values are: Draft, In Cart, In Review, Submitted, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed, New, Assigned, Resolved, Request For Authorization, Request For Change, Planning In Progress, Scheduled For Review, Scheduled For Approval, Scheduled, Implementation In Progress, Staged, Work In Progress, Waiting, Bypassed, Under Review, Under Investigation, Scheduled For Correction, Assigned To Vendor, No Action Planned, Corrected. | Optional | 
| impact | Ticket impact. Filtering argument. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| urgency | Ticket urgency. Filtering argument. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| priority | Ticket Priority. Filtering argument. Possible values are: Critical, High, Medium, Low. | Optional | 
| risk_level | Ticket risk level. Filtering argument. Possible values are: Risk Level 1, Risk Level 2, Risk Level 3, Risk Level 4. | Optional | 
| change_type | Ticket change type level. Relevant only to change reqiest ticket type. Filtering argument. Possible values are: Project, Change, Release, Asset Configuration, Asset Management, Asset Lease, Purchase Requisition, Asset Maintenance. | Optional | 
| summary | Ticket summary. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Ticket.RequestID | String | Ticket ID. | 
| BmcITSM.Ticket.DisplayID | String | Ticket Request Number. | 
| BmcITSM.Ticket.InstanceId | String | Ticket Instance ID. | 
| BmcITSM.Ticket.Type | String | Ticket type. | 
| BmcITSM.Ticket.TargetDate | Date | Ticket target date in UTC. | 
| BmcITSM.Ticket.Status | String | Ticket status. | 
| BmcITSM.Ticket.StatusReason | String | Ticket status reason. | 
| BmcITSM.Ticket.Submitter | String | Ticket submitter. | 
| BmcITSM.Ticket.Priority | String | Ticket priority. | 
| BmcITSM.Ticket.RiskLevel | String | Ticket risk level. | 
| BmcITSM.Ticket.Impact | String | Ticket impact. | 
| BmcITSM.Ticket.Urgency | String | Ticket urgency. | 
| BmcITSM.Ticket.Requester | Unknown | Ticket's requester info. | 
| BmcITSM.Ticket.Customer | Unknown | Ticket's customer info. | 
| BmcITSM.Ticket.assignee | Unknown | Ticket assignee info.  | 
| BmcITSM.Ticket.Summary | String | Ticket summary. | 
| BmcITSM.Ticket.Details | String | Ticket details. | 
| BmcITSM.Ticket.CreateDate | Date | Ticket create time in UTC. | 
| BmcITSM.Ticket.LastModifiedDate | Date | Ticket last update time in UTC. | 

#### Command example
```!bmc-itsm-ticket-list ticket_type="service request" limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "Ticket": [
            {
                "Assignee": {
                    "AssignedGroup": null,
                    "FullName": "Bob Baxter",
                    "Group": "Backoffice Support",
                    "SupportCompany": "Calbro Services",
                    "SupportOrganization": "IT Support"
                },
                "CreateDate": "2022-02-23T13:54:47",
                "Customer": {
                    "Company": "Calbro Services",
                    "Department": "Customer Service",
                    "E-mail": "A.Allbrook@calbroservices.com",
                    "FirstName": "Allen",
                    "LastName": "Allbrook",
                    "Organization": "Information Technology",
                    "PhoneNumber": "1 212 555-5454 (11)"
                },
                "DisplayID": "REQ000000000001",
                "Impact": "3-Moderate/Limited",
                "InstanceId": "SRGAI7ZXDK9WFARHR5Z1RGSGM6WLHZ",
                "Request Type": "Standard",
                "RequestID": "000000000000001",
                "Requester": {
                    "Company": "Calbro Services",
                    "FirstName": "Allen",
                    "LastName": "Allbrook",
                    "Region": "Americas",
                    "Site": "Headquarters, Building 1.31",
                    "SiteGroup": "United States"
                },
                "Status": "Planning",
                "StatusReason": null,
                "Status-History": {
                    "Draft": {
                        "timestamp": "2022-02-23T13:54:48.000+0000",
                        "user": "Allen"
                    },
                    "Planning": {
                        "timestamp": "2022-02-23T13:54:50.000+0000",
                        "user": "Remedy Application Service"
                    },
                    "Submitted": {
                        "timestamp": "2022-02-23T13:54:48.000+0000",
                        "user": "Allen"
                    },
                    "Waiting Approval": {
                        "timestamp": "2022-02-23T13:54:50.000+0000",
                        "user": "Remedy Application Service"
                    }
                },
                "Submitter": "Allen",
                "Summary": "Audio Visual/Video Conferencing",
                "TargetDate": null,
                "Type": "service request",
                "Urgency": "3-Medium"
            },
            {
                "Assignee": {
                    "AssignedGroup": null,
                    "FullName": "Bob Baxter",
                    "Group": "Backoffice Support",
                    "SupportCompany": "Calbro Services",
                    "SupportOrganization": "IT Support"
                },
                "CreateDate": "2022-02-23T15:28:33",
                "Customer": {
                    "Company": "Calbro Services",
                    "Department": "Customer Service",
                    "E-mail": "A.Allbrook@calbroservices.com",
                    "FirstName": "Allen",
                    "LastName": "Allbrook",
                    "Organization": "Information Technology",
                    "PhoneNumber": "1 212 555-5454 (11)"
                },
                "DisplayID": "REQ000000000002",
                "Impact": "1-Extensive/Widespread",
                "InstanceId": "SRGAI7ZXDK9WFARHRK1LRGS0YQWNQ3",
                "Request Type": "Standard",
                "RequestID": "000000000000002",
                "Requester": {
                    "Company": "Calbro Services",
                    "FirstName": "Allen",
                    "LastName": "Allbrook",
                    "Region": "Americas",
                    "Site": "Headquarters, Building 1.31",
                    "SiteGroup": "United States"
                },
                "Status": "Draft",
                "Status-History": {
                    "Draft": {
                        "timestamp": "2022-04-05T13:44:24.000+0000",
                        "user": "appadmin"
                    },
                    "Planning": {
                        "timestamp": "2022-04-05T10:17:18.000+0000",
                        "user": "Demo"
                    },
                    "Rejected": {
                        "timestamp": "2022-04-05T10:21:03.000+0000",
                        "user": "Demo"
                    },
                    "Submitted": {
                        "timestamp": "2022-02-23T15:28:33.000+0000",
                        "user": "Allen"
                    },
                    "Waiting Approval": {
                        "timestamp": "2022-02-23T15:28:34.000+0000",
                        "user": "Remedy Application Service"
                    }
                },
                "Submitter": "Allen",
                "Summary": "Audio Visual/Video Conferencing",
                "TargetDate": null,
                "Type": "service request",
                "Urgency": "3-Medium"
            }
        ]
    }
}
```

#### Human Readable Output

>### List Tickets.
>Showing 2 records out of 227.
>|Type|Request ID|Display ID|Summary|Status|Urgency|Impact|Create Date|Last Modified Date|
>|---|---|---|---|---|---|---|---|---|
>| service request | 000000000000001 | REQ000000000001 | Audio Visual/Video Conferencing | Planning | 3-Medium | 3-Moderate/Limited | 2022-02-23T13:54:47 |  |
>| service request | 000000000000002 | REQ000000000002 | Audio Visual/Video Conferencing | Draft | 3-Medium | 1-Extensive/Widespread | 2022-02-23T15:28:33 |  |


### bmc-itsm-service-request-create
***
Create a new service request. A service request is the request record that is generated from the service request definition to manage and track the execution. In order to create it, you need to provide the srd_instance_id argument which can be retrieved by by executing "bmc-itsm-service-request-definition-list" command and extracting the instanceID field. User and company related arguments can be retrieved from fields retrived by executing the "bmc-itsm-user-list" and "bmc-itsm-company-list"


#### Base Command

`bmc-itsm-service-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| srd_instance_id | The instance ID of the requested service. It can be retrieved by executing bmc-itsm-service-request-definition-list command. . Possible values are: . | Required | 
| first_name | Requester first name. By default is determined by the logged in user. If provided, login_id, first_name and last_name arguments must be provided together. Possible values are: . | Optional | 
| last_name | Requester last name. Requester last name. By default is determined by the logged in user. If provided, login_id, first_name and last_name arguments must be provided together. . Possible values are: . | Optional | 
| login_id | Requester login ID. By default is determined by the logged in user. If provided, login_id, first_name and last_name arguments must be provided together. Possible values are: . | Optional | 
| summary | Service Request summary. Possible values are: . | Optional | 
| status | Service Request status. . Possible values are: Draft, In Cart, In Review, Submitted, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed. | Optional | 
| urgency | Incident Request urgency. Required when the creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| impact | Incident Request impact. Required when the creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ServiceRequest.RequestID | String | Service Request unique Request ID. | 
| BmcITSM.ServiceRequest.DisplayID | String | Service Request Request number. | 
| BmcITSM.ServiceRequest.CreateDate | Date | Service Request Create time in UTC. | 

### bmc-itsm-service-request-update
***
Update the details of an service request for a given request ID. User and company related arguments can be retrieved from fields retrived by executing the "bmc-itsm-user-list" and "bmc-itsm-company-list".


#### Base Command

`bmc-itsm-service-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_request_id | Unique identifier of the service request to update. Possible values are: . | Required | 
| customer_first_name | Customer First name. By default is determined by the logged in user. . Possible values are: . | Optional | 
| customer_last_name | Customer last name. By default is determined by the logged in user. . Possible values are: . | Optional | 
| status | Service Request status. . Possible values are: Draft, In Cart, In Review, Submitted, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed. | Optional | 
| urgency | Incident Request urgency. Required when the creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| impact | Incident Request impact. Required when the creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| status_reason | The reason for updaing the status. Required only if status argument is provided. . Possible values are: Review, Need More Information, Approval, System Error, With Issues, Automatically Closed, Successful, By User, By Provider, System, Cancelled, Reopen By User. | Optional | 
| location_company | Company associated with SR process. Possible values are: . | Optional | 
| region | Region associated with Location Company. Possible values are: . | Optional | 
| site_group | Site Group associated with Region. Possible values are: . | Optional | 
| site | Site associated with Site Group. Possible values are: . | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-service-request-update service_request_id=000000000000259 status=Cancelled status_reason=Cancelled```
#### Human Readable Output

>Service Request: 000000000000259 was successfully updated.

### bmc-itsm-incident-update
***
Update incident ticket. 


#### Base Command

`bmc-itsm-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the incident request ticket to update. Possible values are: . | Required | 
| first_name | Customer first name whom the incident request is for. Possible values are: . | Optional | 
| last_name | Customer last name whom the incident request is for. Possible values are: . | Optional | 
| summary | incident summary. Possible values are: . | Optional | 
| service_type | The type of the incident. . Possible values are: User Service Restoration, User Service Request, Infrastructure Restoration, Infrastructure Event, Security Incident. | Optional | 
| urgency | Incident Request urgency. Required when the creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| impact | Incident Request impact. Required when the creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| status | Incident status. Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Optional | 
| reported_source | Incident reported source. . Possible values are: Direct Input, Email,External Escalation, Fax, Self Service, Systems Management, Phone, Voice Mail, Walk In, Web, Other, BMC Impact Manager Event. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assigned Group, Assignee or any other custom field.. | Optional | 
| detailed_description | Incident summary. Possible values are: . | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| assigned_support_company | This is the Company for the Assignee’s Support Organization.  This Company is part of the Assignee’s Support Organization data structure  It makes up the 1st tier of the Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_support_organization | This is the Company for the Assignee’s Support Organization.  This Company is part of the Assignee’s Support Organization data structure  It makes up the second tier of the Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_group | This is the Company for the Assignee’s Support Organization.  This Company is part of the Assignee’s Support Organization data structure  It makes up the third tier of the Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assignee_login_id | The login ID of the assignee. The assignee and assignee_login_id arguments must be provided together. Possible values are: . | Optional | 
| region | It makes up the second tier of the Customer’s Business Organization data structure. Possible values are: . | Optional | 
| site_group | Site Group associated with Region. Possible values are: . | Optional | 
| site | Site associated with Site Group. Possible values are: . | Optional | 
| status_reason | The reason for updating the ticket status. Required when status is provided. Possible values are: Infrastructure Change Created, Local Site Action Required, Purchase Order Approval, Registration Approval, Supplier Delivery, Support Contact Hold, Third Party Vendor Action Reqd, Client Action Required, Infrastructure Change Request, Future Enhancement, Pending Original Incident, Client Hold, Monitoring Incident, Customer Follow-Up Required, Temporary Corrective Action, No Further Action Required, Resolved by Original Incident, Automated Resolution Reported, No longer a Causal CI, Pending Causal Incident Resolution, Resolved by Causal Incident. | Optional | 
| resolution | Ticket resolution description. Required when status is provided. | Optional | 


#### Context Output

There is no context output for this command.
### bmc-itsm-ticket-delete
***
Delete ticket by it's request ID. Only admin users can perform this command.


#### Base Command

`bmc-itsm-ticket-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_ids | Comma seperated list of ticket request ID to delete. Possible values are: . | Required | 
| ticket_type | The type of the tickets to delete. Possible values are: incident, task, change request, problem investigation, known error. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-ticket-delete ticket_ids=TAS000000000260 ticket_type=task```
#### Human Readable Output

>task TAS000000000260 was deleted successfully

### bmc-itsm-incident-create
***
Create a new incident ticket. An incident is any event that is not part of the standard operation of a service and that causes an interruption to or a reduction in the quality of that service. 


#### Base Command

`bmc-itsm-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | Customer first name whom the incident request is for. Possible values are: . | Required | 
| last_name | Customer last name whom the incident request is for. Possible values are: . | Required | 
| template_instance_id | The instance ID of the template to use. Required only when the ticket attributes should be based on the template's fields. The instance ID can be retrieved by executing bmc-itsm-incident-template-list commad. Possible values are: . | Optional | 
| summary | incident summary. Required when template_instance_id argument is not provided. Possible values are: . | Optional | 
| service_type | The type of the incident. Required when template_instance_id argument is not provided. Possible values are: User Service Restoration, User Service Request, Infrastructure Restoration, Infrastructure Event, Security Incident. | Optional | 
| urgency | Incident Request urgency. Required when the creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required | 
| impact | Incident Request impact. Required when the creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required | 
| status | Incident status. Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Required | 
| reported_source | Incident reported source.  Required when template_instance_id argument is not provided. Possible values are: Direct Input, Email,External Escalation, Fax, Self Service, Systems Management, Phone, Voice Mail, Walk In, Web, Other, BMC Impact Manager Event. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assigned Group, Assignee or any other custom field.. | Optional | 
| details | Incident detailed description. Possible values are: . | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| assigned_support_company | This is the Company for the Assignee’s Support Organization.  This Company is part of the Assignee’s Support Organization data structure  It makes up the 1st tier of the Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_support_organization | This is the Company for the Assignee’s Support Organization.  This Company is part of the Assignee’s Support Organization data structure  It makes up the second tier of the Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_group | This is the Company for the Assignee’s Support Organization.  This Company is part of the Assignee’s Support Organization data structure  It makes up the third tier of the Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. The assignee and assignee_login_id arguments must be provided together. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assignee_login_id | The login ID of the assignee. The assignee and assignee_login_id arguments must be provided together.It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| region | Region associated with Company. Possible values are: . | Optional | 
| site_group | Site Group associated with Region. Possible values are: . | Optional | 
| site | Site associated with Site Group. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Incident.RequestID | String | Incident request ID | 
| BmcITSM.Incident.DisplayID | String | Incident display ID.  | 
| BmcITSM.Incident.CreateDate | Date | Incident create time in UTC.  | 

#### Command example
```!bmc-itsm-incident-create first_name=Allen last_name=Allbrook impact="1-Extensive/Widespread" status=Assigned urgency="1-Critical" template_instance_id=AG00123F73CF5EKnsTSQ5rvrAAZfQA```
#### Context Example
```json
{
    "BmcITSM": {
        "Incident": {
            "CreateDate": "2022-06-29T15:40:51",
            "DisplayID": "INC000000000498",
            "RequestID": "INC000000000582"
        }
    }
}
```

#### Human Readable Output

>### Incident ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-06-29T15:40:51 | INC000000000498 | INC000000000582 |


### bmc-itsm-change-request-create
***
Create Change Request ticket in BMC Helix ITSM.The ticket is created by using a template or from scratch.


#### Base Command

`bmc-itsm-change-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | Requester first name. Possible values are: . | Required | 
| last_name | Requester last name. Possible values are: . | Required | 
| customer_first_name | Customer first name. . Possible values are: . | Optional | 
| customer_last_name | Customer last name. Possible values are: . | Optional | 
| summary | Change request title. Required when template ID argument is not provided. Possible values are: . | Optional | 
| template_id | The instance ID of the template to use. Required only when the ticket attributes should be based on the template's fields. The ID caan be retrieved by executing bmc-itsm-change-request-template-list commad. . Possible values are: . | Optional | 
| change_type | Change request type. Required when the creation is without a template. Possible values are: Project, Change, Release, Asset Configuration, Asset Management, Asset Lease, Purchase Requisition, Asset Maintenance. | Optional | 
| change_timing | The class of the change request which best describes your scenario. . Possible values are: Emergency, Expedited, Latent, Normal, No Impact, Standard. | Optional | 
| impact | Change Request impact. Required when the creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| urgency | Change Request urgency. Required when the creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| risk_level | Change Request risk level. Required when the creation is without a template. Possible values are: Risk Level 1, Risk Level 2, Risk Level 3, Risk Level 4, Risk Level 5. | Optional | 
| status | Change Request status. Required when the creation is without a template. Possible values are: Request For Authorization, Request For Change, Planning In Progress, Scheduled For Review, Scheduled For Approval, Scheduled, Implementation In Progress, Pending, Rejected, Completed, Closed, Cancelled. | Optional | 
| location_company | Company associated with CR process. Required when template ID argument is not provided. Possible values are: . | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ChangeRequest.RequestID | String | Change Request unique Request ID. | 
| BmcITSM.ChangeRequest.DisplayID | String | Change Request Request number. | 
| BmcITSM.ChangeRequest.CreateDate | Date | Change Request Create time. | 

#### Command example
```!bmc-itsm-change-request-create template_id=AG00123F73CF5EK3sTSQTb3rAAbfQA first_name=Allen last_name=Allbrook summary="Change request for README"```
#### Context Example
```json
{
    "BmcITSM": {
        "ChangeRequest": {
            "CreateDate": "2022-06-29T15:27:56",
            "DisplayID": "CRQ000000000342",
            "RequestID": "CRQ000000000337"
        }
    }
}
```

#### Human Readable Output

>### Change Request ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-06-29T15:27:56 | CRQ000000000342 | CRQ000000000337 |


### bmc-itsm-change-request-update
***
Update the details of change request ticket for the specfied request ID.


#### Base Command

`bmc-itsm-change-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the change request ticket to update. | Required | 
| first_name | Customer first name whom the change request is for. . Possible values are: . | Optional | 
| last_name | Customer last name whom the change request is for. . Possible values are: . | Optional | 
| summary | Change request summary. Possible values are: . | Optional | 
| change_type | Change request type. . Possible values are: Project, Change, Release, Asset Configuration, Asset Management, Asset Lease, Purchase Requisition, Asset Maintenance. | Optional | 
| change_timing | The class of the change request which best describes your scenario. . Possible values are: Emergency, Expedited, Latent, Normal, No Impact, Standard. | Optional | 
| impact | Change Request impact. . Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| urgency | Change Request urgency. . Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| risk_level | Change Request risk level. Possible values are: Risk Level 1, Risk Level 2, Risk Level 3, Risk Level 4, Risk Level 5. | Optional | 
| status | Change Request status. . Possible values are: Request For Authorization, Request For Change, Planning In Progress, Scheduled For Review, Scheduled For Approval, Scheduled, Implementation In Progress, Pending, Rejected, Completed, Closed, Cancelled. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| organization | Organization associated with the Requester. Possible values are: . | Optional | 
| department | Department associated with the Requester. Possible values are: . | Optional | 
| location_company | Company associated with CR process. Possible values are: . | Optional | 
| region | Region associated with Location Company. Possible values are: . | Optional | 
| site_group | Site Group associated with Region. Possible values are: . | Optional | 
| site | Site associated with Site Group. Possible values are: . | Optional | 
| support_organization | It makes up the second tier of the Change Manager’s Support Organization data structure. Possible values are: . | Optional | 
| support_group_name | It makes up the third tier of the Change Manager’s Support Organization data structure. Possible values are: . | Optional | 
| status_reason | The reason for updating the ticket status. Required when status is provided. . Possible values are: No Longer Required, Funding Not Available, To Be Re-Scheduled, Resources Not Available, Successful, Successful with Issues, Unsuccessful, Backed Out, Final Review Complete, Final Review Required, Additional Coding Required, Insufficient Task Data, In Verification, In Rollout, Insufficient Change Data, Schedule Conflicts, In Development, In Test, In Build, In Rollback, In Documentation, Vendor Purchase, Support Group Communication, Task Review, Miscellaneous, Future Enhancement, Manager Intervention, Accepted, Assigned, Built, On Hold. | Optional | 
| details | Change request ticket details. Possible values are: . | Optional | 


#### Context Output

There is no context output for this command.
### bmc-itsm-task-create
***
Create a new task ticket. You can create and manage tasks to resolve cases. Tasks are child records of cases that enable you to split the cases into individual assignments so that you can focus on one assignment at a time and achieve the required results efficiently. Task ticket type can be attached only to the following types:change request,incident,problem investigation and known error.


#### Base Command

`bmc-itsm-task-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The instance ID of the template to use. The ID can be retrieved by executing 'bmc-itsm-task-template-list' commad. Possible values are: . | Optional | 
| summary | Task summary. Possible values are: . | Required | 
| details | Task detailed description. Possible values are: . | Required | 
| root_ticket_type | Parent ticket type. Possible values are: change request, incident, problem investigation, known error. | Required | 
| root_request_id | The request ID of the parent ticket. Can be found in the context output of ticket bmc-itsm-ticket-list command. . Possible values are: . | Required | 
| root_request_name | The display name of the parent ticket in the task ticket. If not provoded, the parent ticket displayID will be displayed. . Possible values are: . | Optional | 
| root_request_mode | Parent request mode. . Possible values are: Real, Simulation. Default is Real. | Optional | 
| status | task status. Possible values are: Staged, Assigned, Pending, Work In Progress, Waiting, Closed, Bypassed. | Required | 
| task_type | Whether it is a manual Task or an automatic one. Possible values are: Automatic, Manual. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assignee or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assignee or any other custom field.. | Optional | 
| priority | Task priority. Possible values are: Critical, High, Medium, Low. | Required | 
| location_company | Company associated with the task process. Possible values are: . | Required | 
| support_company | Technical support team assoiciated company. Possible values are: . | Optional | 
| assigned_support_organization | It makes up the second tier of the Task's Support Organization data structure. The arguments assigned_support_organization,assigned_group,support_company Should be provided together. Possible values are: . | Optional | 
| assigned_support_group | It makes up the third tier of the Task’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,support_company Should be provided together. Possible values are: . | Optional | 
| impact | Task impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| urgency | Task urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| scedulded_start_date | Task schedulded Future start date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 
| scedulded_end_date | Task schedulded Future end date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Task.RequestID | String | Task unique Request ID. | 
| BmcITSM.Task.DisplayID | String | Task Request display ID. | 
| BmcITSM.Task.CreateDate | Date | Task Create time in UTC. | 

### bmc-itsm-task-update
***
Update task ticket. 


#### Base Command

`bmc-itsm-task-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The ID of the task request ticket to update. Possible values are: . | Required | 
| summary | Task summary. Possible values are: . | Optional | 
| details | Task detailed description. Possible values are: . | Optional | 
| priority | Task priority. Possible values are: Critical, High, Medium, Low. | Optional | 
| status | Task status. Possible values are: Staged, Assigned, Pending, Work In Progress, Waiting, Closed, Bypassed. | Optional | 
| status_reason | The reason for changing the status. Required when the status is changed. . Possible values are: Success, Failed, Cancelled, Assignment, Staging in Progress, Staging Complete, Acknowledgment, Another Task, Task Rule, Completion, Error. | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| location_company | Company associated with the task process. Possible values are: . | Optional | 
| support_company | Technical support team assoiciated company. Possible values are: . | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assigned_support_organization | It makes up the second tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| assigned_group | It makes up the third tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| task_type | Task type. . Possible values are: Automatic, Manual. | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assignee or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assignee or any other custom field.. | Optional | 
| scedulded_start_date | Task schedulded Future start date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 
| scedulded_end_date | Task schedulded Future end date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 


#### Context Output

There is no context output for this command.
### bmc-itsm-problem-investigation-create
***
Create problem investigation ticket. 


#### Base Command

`bmc-itsm-problem-investigation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | Customer first name whom the incident request is for. Possible values are: . | Required | 
| last_name | Customer last name whom the incident request is for. Possible values are: . | Required | 
| status | Problem investigation status. Possible values are: Draft, Under Review, Request for Authorization, Assigned, Under Investigation, Pending, Completed, Rejected, Closed, Cancelled. | Required | 
| investigation_driver | Problem investigation driver. . Possible values are: High Impact Incident, Re-Occuring Incidents, Non-Routine Incident, Other. | Required | 
| summary | Problem investigation summary. Possible values are: . | Required | 
| details | Detailed description on the problem investigation ticket. Possible values are: . | Optional | 
| impact | problem investigation impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required | 
| urgency | Problem investigation urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required | 
| target_resolution_date | Future resolution date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| region | The region of the problem location. The arguments region, site_group and site should be provided together. Possible values are: . | Optional | 
| site_group | The site group of the problem location.The arguments region, site_group and site should be provided together. Possible values are: . | Optional | 
| site | The site of the problem location.The arguments region, site_group and site should be provided together. Possible values are: . | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assignee_pbm_mgr | The full name of the staff member to whom the ticket will be assign to as the problem coordinator. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assigned_group_pbm_mgr | It makes up the third tier of the Problem Coordinator’s Support Organization data structure. The arguments support_organization_pbm_mgr,assigned_group_pbm_mgr,support_company_pbm_mgr Should be provided together. Possible values are: . | Optional | 
| support_company_pbm_mgr | the Company for the Problem Coordinator’s Support Organization. It makes up the first tier of it. The arguments support_organization_pbm_mgr,assigned_group_pbm_mgr,support_company_pbm_mgr Should be provided together. Possible values are: . | Optional | 
| support_organization_pbm_mgr | It makes up the second tier of the Problem Coordinator’s Support Organization data structure. The arguments support_organization_pbm_mgr,assigned_group_pbm_mgr,support_company_pbm_mgr Should be provided together. Possible values are: . | Optional | 
| assigned_support_company |  This is the Company for the Problem Assignee’s Support Organization. It makes up the first tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| assigned_support_organization | It makes up the second tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| assigned_group | It makes up the third tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| investigation_justification | The justification for the ticket creation. Possible values are: . | Optional | 
| temporary_workaround | Problem workaround. Possible values are: . | Optional | 
| resolution | Ticket resolution. Possible values are: . | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ProblemInvestigation.RequestID | String | Problem Investigation unique Request ID. | 
| BmcITSM.ProblemInvestigation.DisplayID | String | Problem Investigation Display ID. | 
| BmcITSM.ProblemInvestigation.CreateDate | Date | Problem Investigation Create time in UTC. | 

#### Command example
```!bmc-itsm-problem-investigation-create first_name=Allen last_name=Allbrook summary=Test-create-prob urgency="1-Critical" impact="4-Minor/Localized" details="Problem details" status=Assigned target_resolution_date="in 3 days" assigned_support_company="Calbro Services" assigned_support_organization="IT Support" assigned_group="Backoffice Support" investigation_driver="High Impact Incident"```
#### Context Example
```json
{
    "BmcITSM": {
        "ProblemInvestigation": {
            "CreateDate": "2022-06-29T15:28:03",
            "DisplayID": "PBI000000000370",
            "RequestID": "PBI000000000329"
        }
    }
}
```

#### Human Readable Output

>### Problem Investigation  ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-06-29T15:28:03 | PBI000000000370 | PBI000000000329 |


### bmc-itsm-problem-investigation-update
***
Update Problem Investigation ticket type.


#### Base Command

`bmc-itsm-problem-investigation-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| problem_investigation_id | Problem Investigation request ID. Possible values are: . | Required | 
| status | Problem investigation status. Possible values are: Draft, Under Review, Request for Authorization, Assigned, Under Investigation, Pending, Completed, Rejected, Closed, Cancelled. | Optional | 
| investigation_driver | Problem investigation driver. . Possible values are: High Impact Incident, Re-Occuring Incidents, Non-Routine Incident, Other. | Optional | 
| summary | Problem investigation summary. Possible values are: . | Optional | 
| impact | problem investigation impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| urgency | Problem investigation urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| target_resolution_date | Problem investigation target resolution date. Future resolution date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 
| details | Problem investigation detailed description. Possible values are: . | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| region | The region of the problem location. The arguments region, site_group and site should be provided together. Possible values are: . | Optional | 
| site_group | The site group of the problem location.The arguments region, site_group and site should be provided together. Possible values are: . | Optional | 
| site | The site of the problem location.The arguments region, site_group and site should be provided together. Possible values are: . | Optional | 
| assigned_to | To whom technical support person the ticket is asigned to. . Possible values are: . | Optional | 
| assigned_group_pbm_mgr | It makes up the third tier of the Problem Coordinator’s Support Organization data structure. The arguments support_organization_pbm_mgr,assigned_group_pbm_mgr,support_company_pbm_mgr Should be provided together. Possible values are: . | Optional | 
| support_company_pbm_mgr | the Company for the Problem Coordinator’s Support Organization. It makes up the first tier of it. The arguments support_organization_pbm_mgr,assigned_group_pbm_mgr,support_company_pbm_mgr Should be provided together. Possible values are: . | Optional | 
| support_organization_pbm_mgr | It makes up the second tier of the Problem Coordinator’s Support Organization data structure. The arguments support_organization_pbm_mgr,assigned_group_pbm_mgr,support_company_pbm_mgr Should be provided together. Possible values are: . | Optional | 
| assigned_support_company |  This is the Company for the Problem Assignee’s Support Organization. It makes up the first tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| assigned_support_organization | It makes up the second tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| assigned_group | It makes up the third tier of the Problem Assignee’s Support Organization data structure. The arguments assigned_support_organization,assigned_group,assigned_support_company Should be provided together. Possible values are: . | Optional | 
| investigation_justification | The justification for the ticket creation. Possible values are: . | Optional | 
| temporary_workaround | Problem workaround. Possible values are: . | Optional | 
| resolution | Ticket resolution. Possible values are: . | Optional | 
| status_reason | The reason for changing the status. Required when the status argument provided. Possible values are: Publish, Reject, Not Applicable. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-problem-investigation-update problem_investigation_id=PBI000000000322 details="updated problem details" status="Under Investigation" status_reason=Publish```
#### Human Readable Output

>Problem Investigation: PBI000000000322 was successfully updated.

### bmc-itsm-known-error-create
***
Create known error ticket. 


#### Base Command

`bmc-itsm-known-error-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Known error status. Possible values are: Assigned, Scheduled For Correction, Assigned To Vendor, No Action Planned, Corrected, Closed, Cancelled. | Required | 
| summary | known error summary. Possible values are: . | Required | 
| details | known error Detailed description. Possible values are: . | Required | 
| impact | Known error impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required | 
| urgency | Known error urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required | 
| view_access | Whether if the ticket is for internal view or public view. Possible values are: Public, Internal. | Required | 
| company | Company associated with the Requester. Possible values are: . | Required | 
| target_resolution_date | Known error resolution date. Future resolution date. For example, in 12 hours, in 7 days. Possible values are: . | Required | 
| resolution | Ticket resolution. Possible values are: . | Optional | 
| assigned_group_pbm_mgr | It makes up the third tier of the Problem Coordinator’s Support Organization data structure. Possible values are: . | Optional | 
| support_company_pbm_mgr | the Company for the Problem Coordinator’s Support Organization. It makes up the first tier of it. . Possible values are: . | Optional | 
| support_organization_pbm_mgr | It makes up the second tier of the Problem Coordinator’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_support_company |  This is the Company for the Problem Assignee’s Support Organization. It makes up the first tier of the Problem Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_support_organization | It makes up the second tier of the Problem Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_group | It makes up the third tier of the Problem Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| investigation_justification | The justification for the ticket creation. Possible values are: . | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assignee_pbm_mgr | The full name of the staff member to whom the ticket will be assign to as the problem coordinator. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| temporary_workaround | Error workaround. Possible values are: . | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.KnownError.RequestID | String | Known Error unique Request ID. | 
| BmcITSM.KnownError.DisplayID | String | KnownError Display ID. | 
| BmcITSM.KnownError.CreateDate | Date | KnownError Create time in UTC. | 

#### Command example
```!bmc-itsm-known-error-create summary="New Error API" details="New Error API Details" target_resolution_date=" in 5 days" company="Calbro Services" resolution="error resolution" investigation_justification=look assignee="Bob Baxter" assigned_support_company="Calbro Services" assigned_support_organization="IT Support" assigned_group="Backoffice Support" impact="2-Significant/Large" status=Assigned urgency="2-High" view_access=Internal ```
#### Context Example
```json
{
    "BmcITSM": {
        "KnownError": {
            "CreateDate": "2022-06-29T15:28:12",
            "DisplayID": "PKE000000000250",
            "RequestID": "PKE000000000230"
        }
    }
}
```

#### Human Readable Output

>### Known Error ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-06-29T15:28:12 | PKE000000000250 | PKE000000000230 |


### bmc-itsm-known-error-update
***
Update Known Error ticket type. 


#### Base Command

`bmc-itsm-known-error-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| known_error_id | Known Error request ID. Possible values are: . | Required | 
| status | Known error status. Possible values are: Assigned, Scheduled For Correction, Assigned To Vendor, No Action Planned, Corrected, Closed, Cancelled. | Optional | 
| summary | known error summary. Possible values are: . | Optional | 
| details | Known error detailed description. Possible values are: . | Optional | 
| impact | Problem investigation impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| urgency | Problem investigation urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| view_access | known error internal access. . Possible values are: Public, Internal. | Optional | 
| company | Company associated with the Requester. By default is determined by the logged in user. Possible values are: . | Optional | 
| target_resolution_date | Known error resolution date. Future resolution date. For example, in 12 hours, in 7 days. Possible values are: . | Optional | 
| resolution | Ticket resolution. Possible values are: . | Optional | 
| assigned_group_pbm_mgr | It makes up the third tier of the Problem Coordinator’s Support Organization data structure. Possible values are: . | Optional | 
| support_company_pbm_mgr | the Company for the Problem Coordinator’s Support Organization. It makes up the first tier of it. . Possible values are: . | Optional | 
| support_organization_pbm_mgr | It makes up the second tier of the Problem Coordinator’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_support_company |  This is the Company for the Problem Assignee’s Support Organization. It makes up the first tier of the Problem Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_support_organization | It makes up the second tier of the Problem Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| assigned_group | It makes up the third tier of the Problem Assignee’s Support Organization data structure. Possible values are: . | Optional | 
| temporary_workaround | Error workaround. Possible values are: . | Optional | 
| status_reason | The reason for changing the status. Required when the status provided. . Possible values are: Duplicate, No Longer Applicable, Pending PIR, Funding Not Available, Pending Infrastructure Change, Pending Third Party Vendor. | Optional | 
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| assignee_pbm_mgr | The full name of the staff member to whom the ticket will be assign to as the problem coordinator. It can be retrieved by using the 'bmc-itsm-user-list' command. Possible values are: . | Optional | 
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. Possible values are: . | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-known-error-update known_error_id=PKE000000000226 impact="2-Significant/Large" details="UPDATED KNOWN ERROR DETAILS" resolution="Updated resolution" temporary_workaround="Updated workaround" summary="Updated summary" status="Assigned To Vendor" status_reason="Pending PIR" target_resolution_date="In 20 days"    ```
#### Human Readable Output

>Known Error: PKE000000000226 was successfully updated.

### bmc-itsm-change-request-template-list
***
List all change requests ticket templates. Useful for create change request ticket. The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them.


#### Base Command

`bmc-itsm-change-request-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_ids | Comma separated list of change request template ID. Filtering argument. Possible values are: . | Optional | 
| query | Search qualification to list by.For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| description | Change request description. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ChangeRequestTemplate.Id | String | ChangeRequestTemplate ID. | 
| BmcITSM.ChangeRequestTemplate.Description | String | ChangeRequestTemplate Description. | 
| BmcITSM.ChangeRequestTemplate.InstanceID | String | ChangeRequestTemplate ID. Useful for creating change Request. | 

#### Command example
```!bmc-itsm-change-request-template-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "ChangeRequestTemplate": [
            {
                "Description": "Add New Employee",
                "Id": "CTP000000000002",
                "InstanceID": "AG00123F73CF5EK3sTSQD73rAAa_QA"
            },
            {
                "Description": "Configure new computer",
                "Id": "CTP000000000003",
                "InstanceID": "AG00123F73CF5EK3sTSQTb3rAAbfQA"
            }
        ]
    }
}
```

#### Human Readable Output

>### List change request templates.
>Showing 2 records out of 13.
>|Id|Description|Instance ID|
>|---|---|---|
>| CTP000000000002 | Add New Employee | AG00123F73CF5EK3sTSQD73rAAa_QA |
>| CTP000000000003 | Configure new computer | AG00123F73CF5EK3sTSQTb3rAAbfQA |


### bmc-itsm-incident-template-list
***
List all incident requests ticket templates. Useful for create incident ticket. The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them.


#### Base Command

`bmc-itsm-incident-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search qualification to list by.For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| description | Incident template description. Filtering argument. Possible values are: . | Optional | 
| template_ids | Comma separated list of incident template ids. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.IncidentTemplate.Id | String | Incident Template ID. | 
| BmcITSM.IncidentTemplate.Description | String | Incident Template Description. | 
| BmcITSM.IncidentTemplate.InstanceID | String | Incident Template ID. Useful for creating change Request. | 

#### Command example
```!bmc-itsm-incident-template-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "IncidentTemplate": [
            {
                "Description": "Email Password Reset",
                "Id": "HTP000000000001",
                "InstanceID": "AG00123F73CF5EKnsTSQSrvrAAYvQA"
            },
            {
                "Description": "Email Service is Down",
                "Id": "HTP000000000002",
                "InstanceID": "AG00123F73CF5EKnsTSQ5rvrAAZfQA"
            }
        ]
    }
}
```

#### Human Readable Output

>### List incident templates.
>Showing 2 records out of 2.
>|Id|Description|Instance ID|
>|---|---|---|
>| HTP000000000001 | Email Password Reset | AG00123F73CF5EKnsTSQSrvrAAYvQA |
>| HTP000000000002 | Email Service is Down | AG00123F73CF5EKnsTSQ5rvrAAZfQA |


### bmc-itsm-task-template-list
***
List all task ticket templates. Useful for create task ticket. The records are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, Each one defines a 'LIKE' operation and 'AND' operator is used between them.


#### Base Command

`bmc-itsm-task-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search qualification to list by.For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query will be used as an addition to the existing args. Review the BMC documentation for how to Build search qualifications: https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html. Possible values are: . | Optional | 
| limit | The maximum number of records to retrieve. Possible values are: . Default is 50. | Optional | 
| page_size | The maximum number of records to retrieve per page. Possible values are: . | Optional | 
| page | The page number of the results to retrieve. Possible values are: . | Optional | 
| template_ids | Comma separated list of task template ids. Filtering argument. Possible values are: . | Optional | 
| task_name | Task template name. Filtering argument. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.TaskTemplate.Id | String | Task Template ID. | 
| BmcITSM.TaskTemplate.TaskName | String | Task Template name. | 
| BmcITSM.TaskTemplate.InstanceID | String | Task Template ID. Useful for creating change Request. | 

#### Command example
```!bmc-itsm-task-template-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "TaskTemplate": [
            {
                "Id": "14",
                "InstanceID": "TM00123F73CF5EK3sTSQ877rAAhfQA",
                "TaskName": "Backup System"
            },
            {
                "Id": "13",
                "InstanceID": "TM001143D417CBD_bDQwojSFAA9qQA",
                "TaskName": "Check Approval automatically"
            }
        ]
    }
}
```

#### Human Readable Output

>### List task templates.
>Showing 2 records out of 25.
>|Id|Task Name|Instance ID|
>|---|---|---|
>| 14 | Backup System | TM00123F73CF5EK3sTSQ877rAAhfQA |
>| 13 | Check Approval automatically | TM001143D417CBD_bDQwojSFAA9qQA |

