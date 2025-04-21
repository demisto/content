BMC Helix ITSM integration enables customers to manage service request, incident, change request, task, problem investigation, known error and work order tickets.
This integration was integrated and tested with version 22.1.05 of BmcITSM

## Configure BMC Helix ITSM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | For Example: https://localhost:8008 | True |
| User Name |  | True |
| Password |  | True |
| Maximum Number of Incidents per Fetch | Default is 50. Maximum is 200. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). |  | False |
| Ticket Type | The type of the tickets to fetch. | False |
| Ticket Status | The status of the tickets to fetch. Since each ticket type has its own unique set of statuses, select only statuses that match the selected ticket type\(s\). | False |
| Ticket Impact | The impact of the tickets to fetch. | False |
| Ticket Urgency | The urgency of the tickets to fetch. | False |
| Fetch by Query | Search query to fetch tickets. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing parameters. See the BMC documentation for  [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from BMC Helix ITSM to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to BMC Helix ITSM\), or Incoming and Outgoing \(from/to Cortex XSOAR and BMC Helix ITSM\). | False |
| Close Mirrored XSOAR Incident | When selected, closing the BMC Helix ITSM ticket is mirrored in Cortex XSOAR. | False |
| Close Mirrored BMC Helix ITSM Ticket | When selected, closing the Cortex XSOAR incident is mirrored in BMC Helix ITSM. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bmc-itsm-user-list
***
Retrieves a list of user profiles from BMC Helix ITSM. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | A comma-separated list of user IDs. Used as a filtering argument. | Optional |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| first_name | The user first name. Used as a filtering argument. | Optional |
| last_name | The user first name. Used as a filtering argument. | Optional |
| company | The user company name. Used as a filtering argument. | Optional |
| department | The user department name. Used as a filtering argument. | Optional |
| organization | The user organization name. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.User.Id | String | The user ID. |
| BmcITSM.User.FirstName | String | The user first name. |
| BmcITSM.User.LastName | String | The user last name. |

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
Retrieves a list of companies from BMC Helix ITSM. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-company-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_ids | A comma-separated list of company ID. Filtering argument. | Optional |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| company | The user company name. Used as a filtering argument. | Optional |
| company_type | The user company type. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Company.Id | String | The company ID. |
| BmcITSM.Company.Name | String | The company name. |
| BmcITSM.Company.Type | String | The company type. |

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
Retrieves a list of service request definitions. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-service-request-definition-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| srd_ids | A comma-separated list of service request definition IDs. Used as a filtering argument. | Optional |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| description | The service request ticket definition description. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ServiceRequestDefinition.Id | String | The service request ticket definition ID. |
| BmcITSM.ServiceRequestDefinition.Description | String | The service request ticket definition description. |
| BmcITSM.ServiceRequestDefinition.InstanceID | String | The service request ticket instance ID. Used for creating service requests. |

#### Command example
```!bmc-itsm-service-request-definition-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "ServiceRequestDefinition": [
            {
                "Description": "Other request to facilities that isn't specifically listed.",
                "Id": "000000000000382|000000000000382",
                "InstanceID": "SRGAA5V0GENAWAO6U31IO5YO03KYL3"
            },
            {
                "Description": "Request to order new office equipment",
                "Id": "000000000000381|000000000000381",
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
>| 000000000000382\|000000000000382 | Other request to facilities that isn't specifically listed. | SRGAA5V0GENAWAO6U31IO5YO03KYL3 |
>| 000000000000381\|000000000000381 | Request to order new office equipment | SRGAA5V0GENAWAO6U2OFO5YNN0K4Y6 |


### bmc-itsm-ticket-list
***
Retrieves a list of BMC Helix ITSM tickets. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-ticket-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_type | The type of tickets to search for. Possible values are: service request, incident, task, change request, problem investigation, known error, work order. | Required |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| ticket_ids | A comma-separated list of ticket request IDs. Used as a filtering argument. Use Display ID for work order type. | Optional |
| status | The status of the tickets to fetch. Since each ticket type has its own unique set of statuses, select only statuses that match the selected ticket type(s). Possible values are: Draft, In Cart, In Review, Submitted, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed, New, Assigned, Resolved, Request For Authorization, Request For Change, Planning In Progress, Scheduled For Review, Scheduled For Approval, Scheduled, Implementation In Progress, Staged, Work In Progress, Waiting, Bypassed, Under Review, Under Investigation, Scheduled For Correction, Assigned To Vendor, No Action Planned, Corrected. | Optional |
| impact | The ticket impact. Used as a filtering argument. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| urgency | The ticket urgency. Used as a filtering argument. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| priority | The ticket priority. Used as a filtering argument. Possible values are: Critical, High, Medium, Low. | Optional |
| risk_level | The ticket risk level. Used as a filtering argument. Possible values are: Risk Level 1, Risk Level 2, Risk Level 3, Risk Level 4. | Optional |
| change_type | The ticket change type level. Relevant only for ticket type change requests. Used as a filtering argument. Possible values are: Project, Change, Release, Asset Configuration, Asset Management, Asset Lease, Purchase Requisition, Asset Maintenance. | Optional |
| summary | The ticket summary. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Ticket.RequestID | String | The ticket ID. |
| BmcITSM.Ticket.DisplayID | String | The ticket request number. |
| BmcITSM.Ticket.InstanceId | String | The ticket instance ID. |
| BmcITSM.Ticket.Type | String | The ticket type. |
| BmcITSM.Ticket.TargetDate | Date | The ticket target date in UTC. |
| BmcITSM.Ticket.Status | String | The ticket status. |
| BmcITSM.Ticket.StatusReason | String | The ticket status reason. |
| BmcITSM.Ticket.Submitter | String | The ticket submitter. |
| BmcITSM.Ticket.Priority | String | The ticket priority. |
| BmcITSM.Ticket.RiskLevel | String | The ticket risk level. |
| BmcITSM.Ticket.Impact | String | The ticket impact. |
| BmcITSM.Ticket.Urgency | String | The ticket urgency. |
| BmcITSM.Ticket.Requester | Unknown | The ticket requester info. |
| BmcITSM.Ticket.Customer | Unknown | The ticket customer info. |
| BmcITSM.Ticket.assignee | Unknown | The ticket assignee info.  |
| BmcITSM.Ticket.Summary | String | The ticket summary. |
| BmcITSM.Ticket.Details | String | The ticket details. |
| BmcITSM.Ticket.CreateDate | Date | The ticket create date time in UTC. |
| BmcITSM.Ticket.LastModifiedDate | Date | The ticket last update date time in UTC. |

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
                    "FullName": "Mary Mann",
                    "Group": "Backoffice Support",
                    "SupportCompany": "Calbro Services",
                    "SupportOrganization": "IT Support"
                },
                "CreateDate": "2022-06-29T14:38:36",
                "Customer": {
                    "Company": "Calbro Services",
                    "Department": null,
                    "E-mail": null,
                    "FirstName": "App",
                    "LastName": "Admin",
                    "Organization": null,
                    "PhoneNumber": "###"
                },
                "Details": null,
                "DisplayID": "REQ000000000398",
                "Impact": "1-Extensive/Widespread",
                "InstanceId": "AGGAI7ZXDK9WFAR4IUA2R3J3RVIB6Q",
                "LastModifiedDate": "2022-07-11T07:27:05",
                "Priority": null,
                "Request Type": "Standard",
                "RequestID": "000000000000396",
                "Requester": {
                    "Company": "Calbro Services",
                    "FirstName": "App",
                    "LastName": "Admin",
                    "Region": "Americas",
                    "Site": "Headquarters, Building 1.31",
                    "SiteGroup": "United States"
                },
                "Status": "Planning",
                "StatusReason": null,
                "Submitter": "appadmin",
                "Summary": "Add user access to network",
                "TargetDate": null,
                "Type": "service request",
                "Urgency": "2-High"
            },
            {
                "Assignee": {
                    "AssignedGroup": null,
                    "FullName": "Bob Baxter",
                    "Group": "Backoffice Support",
                    "SupportCompany": "Calbro Services",
                    "SupportOrganization": "IT Support"
                },
                "CreateDate": "2022-06-29T14:38:36",
                "Customer": {
                    "Company": "Calbro Services",
                    "Department": null,
                    "E-mail": null,
                    "FirstName": "App",
                    "LastName": "Admin",
                    "Organization": null,
                    "PhoneNumber": "###"
                },
                "Details": null,
                "DisplayID": "REQ000000000400",
                "Impact": "1-Extensive/Widespread",
                "InstanceId": "AGGAI7ZXDK9WFAR4IUA2R3J3RVIB6W",
                "LastModifiedDate": "2022-07-11T07:27:05",
                "Priority": null,
                "Request Type": "Standard",
                "RequestID": "000000000000398",
                "Requester": {
                    "Company": "Calbro Services",
                    "FirstName": "App",
                    "LastName": "Admin",
                    "Region": "Americas",
                    "Site": "Headquarters, Building 1.31",
                    "SiteGroup": "United States"
                },
                "Status": "Planning",
                "StatusReason": null,
                "Submitter": "appadmin",
                "Summary": "Add SAP printer",
                "TargetDate": null,
                "Type": "service request",
                "Urgency": "2-High"
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
>| service request | 000000000000396 | REQ000000000398 | Add user access to network | Planning | 2-High | 1-Extensive/Widespread | 2022-06-29T14:38:36 | 2022-07-11T07:27:05 |
>| service request | 000000000000398 | REQ000000000400 | Add SAP printer | Planning | 2-High | 1-Extensive/Widespread | 2022-06-29T14:38:36 | 2022-07-11T07:27:05 |


### bmc-itsm-service-request-create
***
Creates a new service request ticket. A service request ticket is the request record that is generated from the service request definition to manage and track the execution. To create it, you need to provide the srd_instance_id argument, which can be retrieved by by executing the bmc-itsm-service-request-definition-list command and extracting the instanceID field. User and company arguments can be retrieved by executing the bmc-itsm-user-list and bmc-itsm-company-list. To see the entire JSON, you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-service-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| srd_instance_id | The instance ID of the service request ticket. It can be retrieved by executing bmc-itsm-service-request-definition-list command. | Required |
| first_name | The requester first name. By default it is determined by the logged in user. If provided, login_id, first_name, and last_name arguments must be provided together. | Optional |
| last_name | The requester last name. By default it is determined by the logged in user. If provided, login_id, first_name, and last_name arguments must be provided together. | Optional |
| login_id | The requester login ID. By default it is determined by the logged in user. If provided, login_id, first_name, and last_name arguments must be provided together. | Optional |
| summary | The service request ticket summary. | Optional |
| status | The service request ticket status. Possible values are: Draft, In Cart, In Review, Submitted, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed. | Optional |
| urgency | The ticket urgency. Required when the ticket creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| impact | The ticket impact. Required when the ticket creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee, or any other custom field. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ServiceRequest.RequestID | String | The service request ticket unique request ID. |
| BmcITSM.ServiceRequest.DisplayID | String | The service request ticket request number. |
| BmcITSM.ServiceRequest.CreateDate | Date | The service request ticket create date time in UTC. |

#### Command example
```!bmc-itsm-service-request-create service_request_definition_id=SRGAA5V0GENAWAO6ZQWYO6EBWDOUAU```
#### Context Example
```json
{
    "BmcITSM": {
        "Task": {
            "CreateDate": "2022-07-27T08:44:43",
            "DisplayID": "REQ000000000513",
            "RequestID": "000000000000513"
        }
    }
}
```

#### Human Readable Output

>### Task ticket successfully Created.
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-07-27T08:44:43 | TAS000000000413 | TAS000000000413 |
### bmc-itsm-service-request-update
***
Updates the details of a service request ticket for a given request ID. User and company related arguments can be retrieved by executing the bmc-itsm-user-list and bmc-itsm-company-list commands.


#### Base Command

`bmc-itsm-service-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_request_id | The unique identifier of the service request ticket to update. | Required |
| customer_first_name | The customer first name. By default it is determined by the logged in user. | Optional |
| customer_last_name | The customer last name. By default it is determined by the logged in user. | Optional |
| status | The service request ticket status. Possible values are: Draft, In Cart, In Review, Submitted, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed. | Optional |
| urgency | The ticket request urgency. Required when the ticket creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| impact | Incident Request impact. Required when the ticket creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| status_reason | The reason for updating the status. Required only if status argument is provided. Possible values are: Review, Need More Information, Approval, System Error, With Issues, Automatically Closed, Successful, By User, By Provider, System, Cancelled, Reopen By User. | Optional |
| location_company | The company associated with the service request process. | Optional |
| region | The region associated with the company location. | Optional |
| site_group | The site group associated with the region. | Optional |
| site | The site associated with the site group. | Optional |
| assignee | The full name of the employee the ticket will be assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee, or any other custom field. | Optional |


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
| ticket_request_id | The ID of the incident ticket to update. | Required |
| first_name | The customer first name the incident ticket is for. | Optional |
| last_name | The customer last name the incident ticket is for. | Optional |
| summary | The incident ticket summary. | Optional |
| service_type | The type of the incident ticket. Possible values are: User Service Restoration, User Service Request, Infrastructure Restoration, Infrastructure Event, Security Incident. | Optional |
| urgency | The ticket urgency. Required when the ticket creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| impact | The ticket impact. Required when the ticket creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| status | The incident ticket status. Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Optional |
| reported_source | The incident ticket reported source. Possible values are: Direct Input, Email,External Escalation, Fax, Self Service, Systems Management, Phone, Voice Mail, Walk In, Web, Other, BMC Impact Manager Event. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee, or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assigned Group, Assignee, or any other custom field.. | Optional |
| detailed_description | The incident ticket summary. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| assigned_support_company | The company for the assignee’s support organization. It makes up the first tier of the assignee’s support organization data structure. | Optional |
| assigned_support_organization | The organization for the assignee’s support organization. It makes up the second tier of the assignee’s support organization data structure. | Optional |
| assigned_group | The group for the assignee’s support organization. It makes up the third tier of the assignee’s support organization data structure. | Optional |
| assignee | The full name of the employee the ticket will be assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| assignee_login_id | The login ID of the assignee. The assignee and assignee_login_id arguments must be provided together. | Optional |
| region | The region, which makes up the second tier of the customer’s business organization data structure. | Optional |
| site_group | The site group associated with the region. | Optional |
| site | The site associated with the site group. | Optional |
| status_reason | The reason for updating the ticket status. Required when status is provided. Possible values are: Infrastructure Change Created, Local Site Action Required, Purchase Order Approval, Registration Approval, Supplier Delivery, Support Contact Hold, Third Party Vendor Action Reqd, Client Action Required, Infrastructure Change Request, Future Enhancement, Pending Original Incident, Client Hold, Monitoring Incident, Customer Follow-Up Required, Temporary Corrective Action, No Further Action Required, Resolved by Original Incident, Automated Resolution Reported, No longer a Causal CI, Pending Causal Incident Resolution, Resolved by Causal Incident. | Optional |
| resolution | The ticket resolution description. Required when status is provided. | Optional |


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-incident-update request_id=INC000000000532 assignee="Mary Mann" assignee_login_id=Mary impact="2-Significant/Large" urgency="1-Critical"```
#### Human Readable Output

>Incident: INC000000000532 was successfully updated.

### bmc-itsm-ticket-delete
***
Deletes a ticket by its request ID. Only admin users can perform this command.


#### Base Command

`bmc-itsm-ticket-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_ids | A comma-separated list of ticket request IDs to delete. | Required |
| ticket_type | The type of the tickets to delete. Possible values are: incident, task, change request, problem investigation, known error, work order. | Required |


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-ticket-delete ticket_ids=TAS000000000260 ticket_type=task```
#### Human Readable Output

>task TAS000000000260 was deleted successfully

### bmc-itsm-incident-create
***
Creates a new incident ticket. An incident is any event that is not part of the standard operation of a service and that causes an interruption to or a reduction in the quality of that service.


#### Base Command

`bmc-itsm-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | The customer first name the incident ticket is for. | Required |
| last_name | The customer last name the incident ticket is for. | Required |
| template_instance_id | The instance ID of the template to use. Required only when the ticket attributes should be based on the template's fields. The instance ID can be retrieved by executing the bmc-itsm-incident-template-list command. | Optional |
| summary | The incident ticket summary. Required when the template_instance_id argument is not provided. | Optional |
| service_type | The type of the incident ticket. Required when the template_instance_id argument is not provided. Possible values are: User Service Restoration, User Service Request, Infrastructure Restoration, Infrastructure Event, Security Incident. | Optional |
| urgency | The ticket urgency. Required when the ticket creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required |
| impact | The ticket impact. Required when the creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required |
| status | Incident status. Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Required |
| reported_source | The incident ticket reported source.  Required when the template_instance_id argument is not provided. Possible values are: Direct Input, Email,External Escalation, Fax, Self Service, Systems Management, Phone, Voice Mail, Walk In, Web, Other, BMC Impact Manager Event. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee, or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assigned Group, Assignee, or any other custom field.. | Optional |
| details | The incident ticket detailed description. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| assigned_support_company | The company for the assignee’s support organization. It makes up the first tier of the assignee’s support organization data structure. | Optional |
| assigned_support_organization | The organization for the assignee’s support organization. It makes up the second tier of the assignee’s support organization data structure. | Optional |
| assigned_group | The group for the assignee’s support organization. It makes up the third tier of the assignee’s support organization data structure. | Optional |
| assignee | The full name of the employee the ticket will be assigned to. The assignee and assignee_login_id arguments must be provided together. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| assignee_login_id | The login ID of the assignee. The assignee and assignee_login_id arguments must be provided together. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| region | The region associated with the company. | Optional |
| site_group | The site group associated with the region. | Optional |
| site | The site associated with the site group. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Incident.RequestID | String | The incident ticket request ID. |
| BmcITSM.Incident.DisplayID | String | The incident ticket display ID.  |
| BmcITSM.Incident.CreateDate | Date | The incident ticket create date time in UTC. |

#### Command example
```!bmc-itsm-incident-create first_name=Allen last_name=Allbrook impact="1-Extensive/Widespread" status=Assigned urgency="1-Critical" template_instance_id=AG00123F73CF5EKnsTSQ5rvrAAZfQA```
#### Context Example
```json
{
    "BmcITSM": {
        "Incident": {
            "CreateDate": "2022-07-27T08:44:51",
            "DisplayID": "INC000000000505",
            "RequestID": "INC000000000606"
        }
    }
}
```

#### Human Readable Output

>### Incident ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-07-27T08:44:51 | INC000000000505 | INC000000000606 |


### bmc-itsm-change-request-create
***
Creates a change request ticket in BMC Helix ITSM. The ticket is created by using a template or from scratch.


#### Base Command

`bmc-itsm-change-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | The requester first name. | Required |
| last_name | The requester last name. | Required |
| customer_first_name | The customer first name. | Optional |
| customer_last_name | The customer last name. | Optional |
| summary | The change request ticket title. Required when the template ID argument is not provided. | Optional |
| template_id | The instance ID of the template to use. Required only when the ticket attributes should be based on the template's fields. The ID can be retrieved by executing the bmc-itsm-change-request-template-list command. | Optional |
| change_type | The change request ticket type. Required when the ticket creation is without a template. Possible values are: Project, Change, Release, Asset Configuration, Asset Management, Asset Lease, Purchase Requisition, Asset Maintenance. | Optional |
| change_timing | The class of the change request ticket which best describes your scenario. Possible values are: Emergency, Expedited, Latent, Normal, No Impact, Standard. | Optional |
| impact | The change request ticket impact. Required when the ticket creation is without a template. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| urgency | The change request ticket urgency. Required when the ticket creation is without a template. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| risk_level | The change request ticket risk level. Required when the ticket creation is without a template. Possible values are: Risk Level 1, Risk Level 2, Risk Level 3, Risk Level 4, Risk Level 5. | Optional |
| status | The change request ticket status. Required when the ticket creation is without a template. Possible values are: Request For Authorization, Request For Change, Planning In Progress, Scheduled For Review, Scheduled For Approval, Scheduled, Implementation In Progress, Pending, Rejected, Completed, Closed, Cancelled. | Optional |
| location_company | The company associated with the change request process. Required when template ID argument is not provided. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee, or any other custom field. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ChangeRequest.RequestID | String | The change request ticket unique request ID. |
| BmcITSM.ChangeRequest.DisplayID | String | The change request ticket request number. |
| BmcITSM.ChangeRequest.CreateDate | Date | The change request ticket create date time. |

#### Command example
```!bmc-itsm-change-request-create template_id=AG00123F73CF5EK3sTSQTb3rAAbfQA first_name=Allen last_name=Allbrook summary="Change request for README"```
#### Context Example
```json
{
    "BmcITSM": {
        "ChangeRequest": {
            "CreateDate": "2022-07-27T08:44:24",
            "DisplayID": "CRQ000000000404",
            "RequestID": "CRQ000000000406"
        }
    }
}
```

#### Human Readable Output

>### Change Request ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-07-27T08:44:24 | CRQ000000000404 | CRQ000000000406 |


### bmc-itsm-change-request-update
***
Updates the details of change request ticket for the specified request ID.


#### Base Command

`bmc-itsm-change-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_request_id | The ID of the change request ticket to update. | Required |
| first_name | The customer first name the change request ticket is for. | Optional |
| last_name | The customer last name the change request ticket is for. | Optional |
| summary | The change request ticket summary. | Optional |
| change_type | The change request ticket type. Possible values are: Project, Change, Release, Asset Configuration, Asset Management, Asset Lease, Purchase Requisition, Asset Maintenance. | Optional |
| change_timing | The class of the change request ticket which best describes your scenario. Possible values are: Emergency, Expedited, Latent, Normal, No Impact, Standard. | Optional |
| impact | The change request ticket impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| urgency | The change request ticket urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| risk_level | The change request ticket risk level. Possible values are: Risk Level 1, Risk Level 2, Risk Level 3, Risk Level 4, Risk Level 5. | Optional |
| status | The change request ticket status. Possible values are: Request For Authorization, Request For Change, Planning In Progress, Scheduled For Review, Scheduled For Approval, Scheduled, Implementation In Progress, Pending, Rejected, Completed, Closed, Cancelled. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee, or any other custom field. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| organization | The organization associated with the requester. | Optional |
| department | The department associated with the requester. | Optional |
| location_company | The company associated with the change request process. | Optional |
| region | The region associated with the company location. | Optional |
| site_group | The site group associated with the region. | Optional |
| site | The site associated with the site group. | Optional |
| support_organization | The second tier of the change manager’s support organization data structure. | Optional |
| support_group_name | The third tier of the change manager’s support organization data structure. | Optional |
| status_reason | The reason for updating the ticket status. Required when status is provided. Possible values are: No Longer Required, Funding Not Available, To Be Re-Scheduled, Resources Not Available, Successful, Successful with Issues, Unsuccessful, Backed Out, Final Review Complete, Final Review Required, Additional Coding Required, Insufficient Task Data, In Verification, In Rollout, Insufficient Change Data, Schedule Conflicts, In Development, In Test, In Build, In Rollback, In Documentation, Vendor Purchase, Support Group Communication, Task Review, Miscellaneous, Future Enhancement, Manager Intervention, Accepted, Assigned, Built, On Hold. | Optional |
| details | The change request ticket details. | Optional |


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-change-request-update reuqest_id=CRQ000000000313 status="Request For Authorization" details="more details" status_reason=Accepted ```
#### Human Readable Output

>Incident: CRQ000000000313 was successfully updated.
### bmc-itsm-task-create
***
Creates a new task ticket. By splitting cases into individual tasks (assignments), you can focus on one assignment at a time to resolve cases more efficiently. Task ticket type can be attached only to the following ticket types: change request, incident, problem investigation, known error and work order.


#### Base Command

`bmc-itsm-task-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The instance ID of the template to use. The ID can be retrieved by executing the bmc-itsm-task-template-list command. | Optional |
| summary | The task ticket summary. | Required |
| details | The task ticket detailed description. | Required |
| root_ticket_type | The parent ticket type. Possible values are: change request, incident, problem investigation, known error, work order. | Required |
| root_request_id | The request ID of the parent ticket. Can be found in the context output of the bmc-itsm-ticket-list command. Use Display ID for work orders. | Required |
| customer_company | The name of the customer company. | Optional |
| root_request_name | The display name of the parent ticket in the task ticket. If not provided, the parent ticket displayID is displayed. | Optional |
| root_request_mode | The parent ticket request mode. Possible values are: Real, Simulation. Default is Real. | Optional |
| status | The task status. Possible values are: Staged, Assigned, Pending, Work In Progress, Waiting, Closed, Bypassed. | Required |
| task_type | Whether the task is manual or automatic. Possible values are: Automatic, Manual. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assignee or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assignee or any other custom field.. | Optional |
| priority | The task ticket priority. Possible values are: Critical, High, Medium, Low. | Required |
| location_company | The company associated with the task process. | Required |
| support_company | The technical support team associated with the company. | Optional |
| assigned_support_organization | The organization for the task's support organization. It makes up the second tier of the task’s support organization data structure. The arguments assigned_support_organization, assigned_group, and support_company should be provided together. | Optional |
| assigned_support_group | The group for the task's support organization. It makes up the third tier of the task's support organization data structure. The arguments assigned_support_organization, assigned_group, and support_company should be provided together. | Optional |
| impact | The task ticket impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| urgency | The task ticket urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| assignee | The full name of the employee the ticket will be assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| scedulded_start_date | The task ticket scheduled future start date. For example, in 12 hours, in 7 days. | Optional |
| scedulded_end_date | The task ticket scheduled future end date. For example, in 12 hours, in 7 days. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.Task.RequestID | String | The task ticket unique Request ID. |
| BmcITSM.Task.DisplayID | String | The task ticket request display ID. |
| BmcITSM.Task.CreateDate | Date | The task ticket creation date time in UTC. |

#### Command example
```!bmc-itsm-task-create location_company="Calbro Services" details="Details" priority=Critical root_request_id=PBI000000000322 root_request_name=error root_ticket_type="problem investigation" status=Assigned summary="Summary task" assigned_support_group="Service Desk" assigned_support_organization="IT Support"  support_company="Calbro Services" task_type=Manual assignee="Francie Stafford" scedulded_end_date="in 10 days" scedulded_start_date="in 2 days"```
#### Context Example
```json
{
    "BmcITSM": {
        "Task": {
            "CreateDate": "2022-07-27T08:44:43",
            "DisplayID": "TAS000000000413",
            "RequestID": "TAS000000000413"
        }
    }
}
```

#### Human Readable Output

>### Task ticket successfully Created.
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-07-27T08:44:43 | TAS000000000413 | TAS000000000413 |


### bmc-itsm-task-update
***
Updates the task ticket.


#### Base Command

`bmc-itsm-task-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_request_id | The ID of the task ticket to update. | Required |
| summary | The task ticket summary. | Optional |
| details | The task ticket detailed description. | Optional |
| priority | The task ticket priority. Possible values are: Critical, High, Medium, Low. | Optional |
| customer_company | The name of the customer company. | Optional |
| status | The task ticket status. Possible values are: Staged, Assigned, Pending, Work In Progress, Waiting, Closed, Bypassed. | Optional |
| status_reason | The reason for changing the ticket status. Required when the status is changed. Possible values are: Success, Failed, Cancelled, Assignment, Staging in Progress, Staging Complete, Acknowledgment, Another Task, Task Rule, Completion, Error. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| location_company | The company associated with the task process. | Optional |
| support_company | The technical support team associated with the company. | Optional |
| assignee | The full name of the employee the ticket is assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| assigned_support_organization | The organization for the problem assignee’s support organization. It makes up the second tier of the problem assignee’s support organization data structure. The arguments assigned_support_organization, assigned_group, and assigned_support_company should be provided together. | Optional |
| assigned_group | The group for the problem assignee's support organization. It makes up the third tier of the problem assignee's support organization data structure. The arguments assigned_support_organization, assigned_group, and support_company should be provided together. | Optional |
| task_type | The task ticket type. Possible values are: Automatic, Manual. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assignee or any other custom field. Possible values are: The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value".Possible fields: Assignee or any other custom field.. | Optional |
| scedulded_start_date | The task ticket scheduled future start date. For example, in 12 hours, in 7 days. | Optional |
| scedulded_end_date | The task ticket scheduled future end date. For example, in 12 hours, in 7 days. | Optional |


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-task-update task_id=TAS000000000305 company=test priority=High status="Work In Progress" status_reason="Task Rule" summary="Updated summary for demo" details="Updated details for demo" ```
#### Human Readable Output

>Task: TAS000000000305 was successfully updated.

### bmc-itsm-problem-investigation-create
***
Creates a problem investigation ticket.


#### Base Command

`bmc-itsm-problem-investigation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | The customer first name the ticket request is for. | Required |
| last_name | The customer last name the ticket request is for. | Required |
| status | The problem investigation ticket status. Possible values are: Draft, Under Review, Request for Authorization, Assigned, Under Investigation, Pending, Completed, Rejected, Closed, Cancelled. | Required |
| investigation_driver | The problem investigation ticket driver. Possible values are: High Impact Incident, Re-Occurring Incidents, Non-Routine Incident, Other. | Required |
| summary | The problem investigation ticket summary. | Required |
| details | The detailed description on the problem investigation ticket. | Optional |
| impact | The problem investigation ticket impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required |
| urgency | The problem investigation ticket urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required |
| target_resolution_date | The future resolution date. For example, in 12 hours, in 7 days. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| region | The region of the problem investigation location. The arguments region, site_group, and site should be provided together. | Optional |
| site_group | The site group of the problem investigation location. The arguments region, site_group, and site should be provided together. | Optional |
| site | The site of the problem investigation location. The arguments region, site_group, and site should be provided together. | Optional |
| assignee | The full name of the employee the ticket will be assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| assignee_pbm_mgr | The full name of the employee the ticket will be assigned to as the problem coordinator. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| assigned_group_pbm_mgr | The group for the problem coordinator’s support organization, which makes up the third tier of the problem coordinator’s support organization data structure. The arguments support_organization_pbm_mgr, assigned_group_pbm_mgr, and support_company_pbm_mgr should be provided together. | Optional |
| support_company_pbm_mgr | The company for the problem coordinator’s support organization, which makes up the first tier of the problem coordinator’s support organization data structure. The arguments support_organization_pbm_mgr, assigned_group_pbm_mgr, and support_company_pbm_mgr should be provided together. | Optional |
| support_organization_pbm_mgr | The organization for the problem coordinator’s support organization, which makes up the second tier of the problem coordinator’s support organization data structure. The arguments support_organization_pbm_mgr, assigned_group_pbm_mgr, and support_company_pbm_mgr should be provided together. | Optional |
| assigned_support_company | The company for the problem assignee’s support organization. It makes up the first tier of the problem assignee’s support organization data structure. The arguments assigned_support_organization, assigned_group, and assigned_support_company should be provided together. | Optional |
| assigned_support_organization | The organization for the problem assignee’s support organization. It makes up the second tier of the problem assignee’s support organization data structure. The arguments assigned_support_organization, assigned_group, and assigned_support_company should be provided together. | Optional |
| assigned_group | The group for the problem assignee's support organization. It makes up the third tier of the problem assignee's support organization data structure. The arguments assigned_support_organization, assigned_group, and support_company should be provided together. | Optional |
| investigation_justification | The justification for the ticket creation. | Optional |
| temporary_workaround | The problem workaround. | Optional |
| resolution | The ticket resolution. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ProblemInvestigation.RequestID | String | The problem investigation ticket unique Request ID. |
| BmcITSM.ProblemInvestigation.DisplayID | String | The problem investigation ticket display ID. |
| BmcITSM.ProblemInvestigation.CreateDate | Date | The problem investigation ticket creation date time in UTC. |

#### Command example
```!bmc-itsm-problem-investigation-create first_name=Allen last_name=Allbrook summary=Test-create-prob urgency="1-Critical" impact="4-Minor/Localized" details="Problem details" status=Assigned target_resolution_date="in 3 days" assigned_support_company="Calbro Services" assigned_support_organization="IT Support" assigned_group="Backoffice Support" investigation_driver="High Impact Incident"```
#### Context Example
```json
{
    "BmcITSM": {
        "ProblemInvestigation": {
            "CreateDate": "2022-07-27T08:44:33",
            "DisplayID": "PBI000000000404",
            "RequestID": "PBI000000000404"
        }
    }
}
```

#### Human Readable Output

>### Problem Investigation  ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-07-27T08:44:33 | PBI000000000404 | PBI000000000404 |


### bmc-itsm-problem-investigation-update
***
Updates The problem investigation ticket type.


#### Base Command

`bmc-itsm-problem-investigation-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_request_id | The problem investigation ticket request ID. | Required |
| status | The problem investigation ticket status. Possible values are: Draft, Under Review, Request for Authorization, Assigned, Under Investigation, Pending, Completed, Rejected, Closed, Cancelled. | Optional |
| investigation_driver | The problem investigation ticket driver. Possible values are: High Impact Incident, Re-Occuring Incidents, Non-Routine Incident, Other. | Optional |
| summary | The problem investigation ticket summary. | Optional |
| impact | The problem investigation ticket impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| urgency | The problem investigation ticket urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| target_resolution_date | The problem investigation ticket target resolution date. For example, in 12 hours, in 7 days. | Optional |
| details | The problem investigation ticket detailed description. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| region | The region of the problem investigation location. The arguments region, site_group, and site should be provided together. | Optional |
| site_group | The site group of the problem investigation location. The arguments region, site_group, and site should be provided together. | Optional |
| site | The site of the problem investigation location.The arguments region, site_group, and site should be provided together. | Optional |
| assigned_to | The technical support person the ticket is assigned to. | Optional |
| assigned_group_pbm_mgr | The group for the problem coordinator’s support organization, which makes up the third tier of the problem coordinator’s support organization data structure. The arguments support_organization_pbm_mgr, assigned_group_pbm_mgr, and support_company_pbm_mgr should be provided together. | Optional |
| support_company_pbm_mgr | The company for the problem coordinator’s support organization, which makes up the first tier of the problem coordinator’s support organization data structure. The arguments support_organization_pbm_mgr, assigned_group_pbm_mgr, and support_company_pbm_mgr should be provided together. | Optional |
| support_organization_pbm_mgr | The organization for the problem coordinator’s support organization, which makes up the second tier of the problem coordinator’s support organization data structure. The arguments support_organization_pbm_mgr, assigned_group_pbm_mgr, and support_company_pbm_mgr should be provided together. | Optional |
| assigned_support_company | The company for the problem assignee’s support organization. It makes up the first tier of the problem assignee’s support organization data structure. The arguments assigned_support_organization, assigned_group, and assigned_support_company should be provided together. | Optional |
| assigned_support_organization | The organization for the problem assignee’s support organization. It makes up the second tier of the problem assignee’s support organization data structure. The arguments assigned_support_organization, assigned_group, and assigned_support_company should be provided together. | Optional |
| assigned_group | The group for the problem assignee's support organization. It makes up the third tier of the problem assignee's support organization data structure. The arguments assigned_support_organization, assigned_group, and support_company should be provided together. | Optional |
| investigation_justification | The justification for the ticket creation. | Optional |
| temporary_workaround | The problem workaround. | Optional |
| resolution | The ticket resolution. | Optional |
| status_reason | The reason for changing the status. Required when the status argument is provided. Possible values are: Publish, Reject, Not Applicable. | Optional |


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
| status | The known error ticket status. Possible values are: Assigned, Scheduled For Correction, Assigned To Vendor, No Action Planned, Corrected, Closed, Cancelled. | Required |
| summary | The known error ticket summary. | Required |
| details | The known error ticket Detailed description. | Required |
| impact | The known error ticket impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required |
| urgency | The known error ticket urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required |
| view_access | Whether if the ticket is for internal view or public view. Possible values are: Public, Internal. | Required |
| company | Company associated with the Requester. | Required |
| target_resolution_date | Known error resolution date. Future resolution date. For example, in 12 hours, in 7 days. | Required |
| resolution | Ticket resolution. | Optional |
| assigned_group_pbm_mgr | It makes up the third tier of the Problem Coordinator’s Support Organization data structure. | Optional |
| support_company_pbm_mgr | the Company for the Problem Coordinator’s Support Organization. It makes up the first tier of it. | Optional |
| support_organization_pbm_mgr | It makes up the second tier of the Problem Coordinator’s Support Organization data structure. | Optional |
| assigned_support_company | The company for the problem assignee’s support organization. It makes up the first tier of the problem assignee’s support organization data structure. | Optional |
| assigned_support_organization | The organization for the problem assignee’s support organization. It makes up the second tier of the problem assignee’s support organization data structure. | Optional |
| assigned_group | The group for the problem assignee’s support organization. It makes up the third tier of the problem assignee’s support organization data structure. | Optional |
| investigation_justification | The justification for the ticket creation. | Optional |
| assignee | The full name of the staff member to whom the ticket will be assigned to. It can be retrieved by using the 'bmc-itsm-user-list' command. | Optional |
| assignee_pbm_mgr | The full name of the staff member to whom the ticket will be assign to as the problem coordinator. It can be retrieved by using the 'bmc-itsm-user-list' command. | Optional |
| temporary_workaround | Error workaround. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. | Optional |


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
            "CreateDate": "2022-07-27T08:44:37",
            "DisplayID": "PKE000000000303",
            "RequestID": "PKE000000000303"
        }
    }
}
```

#### Human Readable Output

>### Known Error ticket successfully Created
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2022-07-27T08:44:37 | PKE000000000303 | PKE000000000303 |


### bmc-itsm-known-error-update
***
Update Known Error ticket type.


#### Base Command

`bmc-itsm-known-error-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_request_id | The known error ticket request ID. | Required |
| status | The known error ticket status. Possible values are: Assigned, Scheduled For Correction, Assigned To Vendor, No Action Planned, Corrected, Closed, Cancelled. | Optional |
| summary | The known error ticket summary. | Optional |
| details | The known error ticket detailed description. | Optional |
| impact | The known error ticket impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional |
| urgency | The known error ticket urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional |
| view_access | The known error ticket internal access. Possible values are: Public, Internal. | Optional |
| company | Company associated with the Requester. By default is determined by the logged in user. | Optional |
| target_resolution_date | Known error resolution date. Future resolution date. For example, in 12 hours, in 7 days. | Optional |
| resolution | Ticket resolution. | Optional |
| assigned_group_pbm_mgr | It makes up the third tier of the Problem Coordinator’s Support Organization data structure. | Optional |
| support_company_pbm_mgr | the Company for the Problem Coordinator’s Support Organization. It makes up the first tier of it. | Optional |
| support_organization_pbm_mgr | It makes up the second tier of the Problem Coordinator’s Support Organization data structure. | Optional |
| assigned_support_company | The company for the problem assignee’s support organization. It makes up the first tier of the problem assignee’s support organization data structure. | Optional |
| assigned_support_organization | The organization for the problem assignee’s support organization. It makes up the second tier of the problem assignee’s support organization data structure. | Optional |
| assigned_group | The group for the problem assignee’s support organization. It makes up the third tier of the problem assignee’s support organization data structure. | Optional |
| temporary_workaround | Error workaround. | Optional |
| status_reason | The reason for changing the status. Required when the status is provided. Possible values are: Duplicate, No Longer Applicable, Pending PIR, Funding Not Available, Pending Infrastructure Change, Pending Third Party Vendor. | Optional |
| assignee | The full name of the employee the ticket will be assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| assignee_pbm_mgr | The full name of the employee the ticket will be assign to as the problem coordinator. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Possible fields: Assigned Group, Assignee or any other custom field. | Optional |


#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-known-error-update known_error_id=PKE000000000226 impact="2-Significant/Large" details="UPDATED KNOWN ERROR DETAILS" resolution="Updated resolution" temporary_workaround="Updated workaround" summary="Updated summary" status="Assigned To Vendor" status_reason="Pending PIR" target_resolution_date="In 20 days"    ```
#### Human Readable Output

>Known Error: PKE000000000226 was successfully updated.

### bmc-itsm-change-request-template-list
***
Lists all change requests ticket templates. Useful for creating change request tickets. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-change-request-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_ids | A comma-separated list of change request template IDs. Used as a filtering argument. | Optional |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| description | The change request ticket description. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.ChangeRequestTemplate.Id | String | The change request ticket template ID. |
| BmcITSM.ChangeRequestTemplate.Description | String | The change request ticket template description. |
| BmcITSM.ChangeRequestTemplate.InstanceID | String | The change request ticket template instance ID. Useful for creating change request tickets. |

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
Lists all incident requests ticket templates. Useful for create incident tickets. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-incident-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| description | The incident ticket template description. Used as a filtering argument. | Optional |
| template_ids | A comma-separated list of incident template IDs. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.IncidentTemplate.Id | String | The incident ticket template ID. |
| BmcITSM.IncidentTemplate.Description | String | The incident ticket template description. |
| BmcITSM.IncidentTemplate.InstanceID | String | The incident ticket template ID. Useful for creating change request tickets. |

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
Lists all task ticket templates. Useful for creating task tickets. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON then you can use the raw_response=true at the end of the command.


#### Base Command

`bmc-itsm-task-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to search by. For example: Status = "Draft" AND Impact = "1-Extensive/Widespread". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| template_ids | A comma-separated list of task template IDs. Used as a filtering argument. | Optional |
| task_name | The task ticket template name. Used as a filtering argument. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.TaskTemplate.Id | String | The task ticket template ID. |
| BmcITSM.TaskTemplate.TaskName | String | The task template name. |
| BmcITSM.TaskTemplate.InstanceID | String | The task ticket template ID. Useful for creating change request tickets. |

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


### get-mapping-fields
***
Returns the list of fields for an incident type.


#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### get-remote-data
***
Gets remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required |
| lastUpdate | Retrieves entries that were created after lastUpdate. | Required |


#### Context Output

There is no context output for this command.

### get-modified-remote-data
***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available in Cortex XSOAR from version 6.1.


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | A date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Optional |

#### Context Output

There is no context output for this command.


### bmc-itsm-support-group-list

***
Lists all support groups. Useful for getting possible (Company, Support Organization, Support Group) triplets.

#### Base Command

`bmc-itsm-support-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| company | Company name. Used as a filtering argument. | Optional |
| support_organization | Support organization name. Used as a filtering argument. | Optional |
| support_group | Support group name. Used as a filtering argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.SupportGroup.SupportGroupID | String | The support group ID. |
| BmcITSM.SupportGroup.Company | String | The support company. |
| BmcITSM.SupportGroup.SupportOrganization | String | The support organization. |
| BmcITSM.SupportGroup.SupportGroupName | String | The support group. |

#### Command example
```!bmc-itsm-support-group-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "SupportGroup": [
            {
                "Company": "Apex Global",
                "SupportGroupID": "APX990000000029",
                "SupportGroupName": "Apex Global - Facilities",
                "SupportOrganization": "Facilities Support"
            },
            {
                "Company": "Calbro Services",
                "SupportGroupID": "SGP000000000110",
                "SupportGroupName": "Application Development / Deployment",
                "SupportOrganization": "Application Support"
            }
        ]
    }
}
```

#### Human Readable Output

>### List support groups.
>Showing 2 records out of 15.
>|Support Group ID|Company|Support Organization|Support Group Name|
>|---|---|---|---|
>| APX990000000029 | Apex Global | Facilities Support | Apex Global - Facilities |
>| SGP000000000110 | Calbro Services | Application Support | Application Development / Deployment |


### bmc-itsm-work-order-template-list

***
Lists all work order templates. Useful for creating work orders. The records are retrieved by the query argument or by the filtering arguments. When using filtering arguments, each one defines a 'LIKE' operation and an 'AND' operator is used between them. To see the entire JSON, you can use the raw_response=true at the end of the command.

#### Base Command

`bmc-itsm-work-order-template-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to search by. For example, query="Company like \"BMCOpsMonitoring\"". The query is used in addition to the existing arguments. See the BMC documentation for [building search qualifications](https://docs.bmc.com/docs/ars2008/building-qualifications-and-expressions-929630007.html). | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| page | The page number of the results to retrieve. | Optional |
| template_ids | A comma-separated list of work order template GUIDs. Used as a filtering argument. | Optional |
| template_name | The work order template name. Used as a filtering argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.WorkOrderTemplate.Id | String | The work order template ID. |
| BmcITSM.WorkOrderTemplate.Name | String | The work order template name. |
| BmcITSM.WorkOrderTemplate.GUID | String | The work order template GUID. |

#### Command example
```!bmc-itsm-work-order-template-list limit=2```
#### Context Example
```json
{
    "BmcITSM": {
        "WorkOrderTemplate": [
            {
                "GUID": "IDGCWH5RDMNSBARVRM5ERVRM5EKP11",
                "Id": "000000000000002",
                "Name": "Share Folder Access"
            },
            {
                "GUID": "IDGCWH5RDMNSBARVRNNGRVRNNGKY0X",
                "Id": "000000000000003",
                "Name": "New Share Folder Access"
            }
        ]
    }
}
```

#### Human Readable Output

>### List work order templates.
>Showing 2 records out of 9.
>|Id|Name|GUID|
>|---|---|---|
>| 000000000000002 | Share Folder Access | IDGCWH5RDMNSBARVRM5ERVRM5EKP11 |
>| 000000000000003 | New Share Folder Access | IDGCWH5RDMNSBARVRNNGRVRNNGKY0X |


### bmc-itsm-work-order-create

***
Creates a new work order ticket.

#### Base Command

`bmc-itsm-work-order-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_guid | The instance GUID of the template to use. The GUID can be retrieved by executing the bmc-itsm-work-order-template-list command. | Optional |
| first_name | Requester first name. | Optional |
| last_name | Requester last name. | Optional |
| customer_first_name | Customer first name. | Required |
| customer_last_name | Customer last name. | Required |
| customer_company | Customer company. | Required |
| customer_person_id | Customer person ID. Use it when customer first and last name pair is not unique. | Optional |
| summary | The work order summary. | Required |
| detailed_description | The work order ticket detailed description. | Required |
| status | The work order status. Possible values are: Assigned, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed. | Required |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Example: additional_fields="Support Company=Calbro Services;Support Organization=IT Support;Support Group Name=Service Desk;Request Assignee=Scully Agent". | Optional |
| priority | The work order ticket priority. Possible values are: Critical, High, Medium, Low. | Required |
| work_order_type | The work order ticket type. Possible values are: General, Project. | Optional |
| location_company | The company associated with the task process. | Required |
| scedulded_start_date | The work order ticket scheduled future start date. For example, in 12 hours, in 7 days. | Optional |
| scedulded_end_date | The work order ticket scheduled future end date. For example, in 12 hours, in 7 days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BmcITSM.WorkOrder.RequestID | String | The work order ticket unique Request ID. |
| BmcITSM.WorkOrder.DisplayID | String | The work order ticket unique Display ID. |
| BmcITSM.WorkOrder.CreateDate | Date | The work order ticket creation date time in UTC. |

#### Command example
```!bmc-itsm-work-order-create customer_company="Calbro Services" customer_first_name="Scully" customer_last_name="Agent" detailed_description="Easy peasy work order" location_company="Calbro Services" priority=Low status=Pending summary="Easy peasy work order. No, really." customer_person_id=PPL000000000607 additional_fields="Support Company=Calbro Services;Support Organization=IT Support;Support Group Name=Service Desk;Request Assignee=Scully Agent"```
#### Context Example
```json
{
    "BmcITSM": {
        "WorkOrder": {
            "CreateDate": "2024-02-07T08:08:23",
            "DisplayID": "WO0000000001002",
            "RequestID": "WO0000000000702"
        }
    }
}
```

#### Human Readable Output

>### Work order ticket successfully created.
>|Create Date|Display ID|Request ID|
>|---|---|---|
>| 2024-02-07T08:08:23 | WO0000000001002 | WO0000000000702 |


### bmc-itsm-work-order-update

***
Updates the work order ticket.

#### Base Command

`bmc-itsm-work-order-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the work order ticket to update. | Required |
| summary | The work order ticket summary. | Optional |
| detailed_description | The work order ticket detailed description. | Optional |
| priority | The work order ticket priority. Possible values are: Critical, High, Medium, Low. | Optional |
| status | The work order ticket status. Possible values are: Assigned, Pending, Waiting Approval, Planning, In Progress, Completed, Rejected, Cancelled, Closed. | Optional |
| status_reason | The reason for changing the ticket status. Possible values are: Initial Status, Awaiting Request Assignee, Client Hold, Client Additional Information Requested, Client Action Required, Support Contact Hold, Local Site Action Required, Purchase Order Approval, Supplier Delivery, Third Party Vendor Action Required, Infrastructure Change, Work not started, Successful, Successful with Issues, Cancelled by Requester, Cancelled by Support, Customer Close, System Close, System Close with Issues. | Optional |
| company | The company associated with the requester. By default it is determined by the logged in user. | Optional |
| location_company | The company associated with the work order process. | Optional |
| assignee | The full name of the employee the work order is assigned to. It can be retrieved by using the bmc-itsm-user-list command. | Optional |
| support_organization | The organization for the problem assignee's support organization. It makes up the second tier of the problem assignee's support organization data structure. The arguments support_organization, support_group should be provided together. It can be retrieved by using the bmc-itsm-support-group-list command. | Optional |
| support_group | The group for the problem assignee's support group. It makes up the third tier of the problem assignee's support organization data structure. The arguments support_organization, support_group should be provided together. It can be retrieved by using the bmc-itsm-support-group-list command. | Optional |
| work_order_type | The work order ticket type. Possible values are: General, Project. | Optional |
| additional_fields | The fields which are not present in the current argument list can be added here in the format "fieldname1=value;fieldname2=value". Example: additional_fields="Support Company=Calbro Services;Support Organization=IT Support;Support Group Name=Service Desk;Request Assignee=Scully Agent". | Optional |
| scedulded_start_date | The work order ticket scheduled future start date. For example, in 12 hours, in 7 days. | Optional |
| scedulded_end_date | The work order ticket scheduled future end date. For example, in 12 hours, in 7 days. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!bmc-itsm-work-order-update request_id=WO0000000000701 summary="Updated summary" status="In Progress" support_organization="IT Support" support_group="Service Desk"```
#### Human Readable Output

>Work Order: WO0000000000701 was successfully updated.



## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and BMC Helix ITSM corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in BMC Helix ITSM events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in BMC Helix ITSM events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and BMC Helix ITSM events will be reflected in both directions. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in BMC Helix ITSM.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and BMC Helix ITSM.