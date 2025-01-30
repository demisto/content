Deprecated. use BMC Helix ITSM instead.

This integration was integrated and tested with version 9.1 of Remedy On-Demand
## Configure Remedy On-Demand in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. 'https://myurl.com', 'http://41.79.151.82'\) | True |
| port | Port | False |
| credentials | Username | True |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### remedy-incident-create
***
Create new ticket incident.<br/>
<br/>
Note: according to Remedy AR API documentation it is recommended to provide all of the non-custom arguments. However, there is no accurate specification, and it is possible to provide other fields using the custom-fields argument alone.

#### Base Command

`remedy-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first-name | customer's first name (make sure customer already exists). | Required | 
| last-name | customer's first name (make sure customer already exists). | Required | 
| description | Incident description. | Required | 
| status | Incident status. Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Required | 
| source | Incident source. Possible values are: Direct Input, Email, External Escalation, Fax, Self-Service, Systems Management, Phone, Voice Mail, Walk, Web, Other. | Required | 
| service-type | Incident service-type. Possible values are: User Service Restoration, User Service Request, Infrastructure Event, Infrastructure Restoration. | Required | 
| impact | Incident impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required | 
| urgency | Incident urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required | 
| custom-fields | Custom fields for incident creation. Comma-separated query or custom-fields-seperator separated query. (e.g., field1=value1,field2=value2). | Optional |
| custom-fields-separator | A custom delimiter to use for the custom-fields. Don't use '=' as a delimiter. Default value is ','. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | string | Ticket ID | 
| Ticket.Submitter | string | Ticket submitter | 
| Ticket.Status | string | Ticket status | 
| Ticket.Description | string | Ticket description | 
| Ticket.Source | string | Ticket reported source | 
| Ticket.Impact | string | TicketiImpact | 
| Ticket.Urgency | string | Ticket urgency | 
| Ticket.Type | string | Ticket service type | 


#### Command Example
```!remedy-incident-create first-name=App last-name=admin description="hola mundo" impact="1-Extensive/Widespread" service-type="User Service Request" source="Direct Input" status=New urgency="3-Medium"```

#### Human Readable Output

>### Incident created:
>|Client Sensitivity|Client Type|Company|Contact_Company|Create Date|DatasetId|Default City|Default Country|Description|First_Name|Impact Incident|Number|InfrastructureEventType|InstanceId|Last Modified By|Modified Date|Person Instance ID|Priority|Weight|ReconciliationIdentity|Region Reported|Date Reported|Source Request ID|Description|Site|Site Group|Site ID|State Province|Status|History|Street|Submitter|Time Zone|Urgency VIP|Zip/Postal Code|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|Standard|Office-Based Employee|Calbro Services|Calbro Services|2019-02-07T11:42:58.000+0000|0|New York| United States|hola mundo|App|1-Extensive/Widespread|INC123| None       | AGGA5B9BGBHP4APMKA9MPLNHKM0GM4 | admin         | 2019-02-07T11:42:58.000+0000 | AG0050560C63F2E1pSRAl5svAA5h4A | High   | 19                     | 0               | Americas      | 2019-02-07T11:42:58.000+0000 | Direct Input 000000000000012 | User Service Request | Headquarters, Building 1.31 | United States | STE_SOLN0002846 | New York | New     | {"New":{"user":"admin","timestamp":"2019-02-07T11:42:58.000+0000"}} | 1114 Eighth Avenue, 31st Floor | admin     | (GMT-05:00) Eastern Time (US &amp; Canada) | 3-Medium No     | 10036 |

### remedy-get-incident
***
Get one incident by ID


#### Base Command

`remedy-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ID | Incident Entry ID. If EntryID is not available to you, incident details can be found using `remedy-fetch-incidents query="'Incident Number' = \"&lt;incident number&gt;\"". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | string | Ticket ID | 
| Ticket.Submitter | string | Ticket submitter | 
| Ticket.Status | string | Ticket status | 
| Ticket.Description | string | Ticket description | 
| Ticket.Source | string | Ticket reported source | 
| Ticket.Impact | string | TicketiImpact | 
| Ticket.Urgency | string | Ticket urgency | 
| Ticket.Type | string | Ticket service type | 


#### Command Example
```!remedy-get-incident ID=9```

#### Human Readable Output

>### Incident:
>|Client Sensitivity|Client Type|Company|Contact_Company|Create Date|DatasetId|Default City|Default Country|Description|First_Name|Impact Incident|Number|InfrastructureEventType|InstanceId|Last Modified By|Modified Date|Person Instance ID|Priority|Weight|ReconciliationIdentity|Region Reported|Date Reported|Source Request ID|Description|Site|Site Group|Site ID|State Province|Status|History|Street|Submitter|Time Zone|Urgency VIP|Zip/Postal Code|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|Standard|Office-Based Employee|Calbro Services|Calbro Services|2019-02-07T11:42:58.000+0000|0|New York| United States|hola mundo|App|1-Extensive/Widespread|INC123| None       | AGGA5B9BGBHP4APMKA9MPLNHKM0GM4 | admin         | 2019-02-07T11:42:58.000+0000 | AG0050560C63F2E1pSRAl5svAA5h4A | High   | 19                     | 0               | Americas      | 2019-02-07T11:42:58.000+0000 | Direct Input 000000000000012 | User Service Request | Headquarters, Building 1.31 | United States | STE_SOLN0002846 | New York | New     | {"New":{"user":"admin","timestamp":"2019-02-07T11:42:58.000+0000"}} | 1114 Eighth Avenue, 31st Floor | admin     | (GMT-05:00) Eastern Time (US &amp; Canada) | 3-Medium No     | 10036 |


### remedy-fetch-incidents
***
Fetch all incidents


#### Base Command

`remedy-fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query/qualification format of '&lt;field&gt; LIKE "&lt;values&gt;"' (e.g. 'Company LIKE "My company"', 'Submitter LIKE "%john%"'). | Optional | 
| sort | Sort query results in descending or ascending order. Format:'&lt;field&gt;.asc' or '&lt;field&gt;.desc' (e.g. 'Assigned To.asc'). | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Assignee | string | Ticket assignee |
| Ticket.Description | string | Ticket description |
| Ticket.Email | string | Ticket email |
| Ticket.EntryID | string | Ticket entry ID | 
| Ticket.ID | string | Ticket request ID |
| Ticket.Impact | string | Ticket impact |
| Ticket.IncidentNumber | string | Ticket number |
| Ticket.ModifiedDate | string | Ticket modified date |
| Ticket.Priority | string | Ticket priority |
| Ticket.RequestID | string | Ticket request ID |
| Ticket.ServiceType | string | Ticket service type |
| Ticket.Source | string | Ticket reported source |
| Ticket.Status | string | Ticket reported status |
| Ticket.Submitter | string | Ticket submitter |
| Ticket.Type | string | Ticket service type |
| Ticket.Urgency | string | Ticket urgency |


#### Command Example
```!remedy-fetch-incidents```

#### Human Readable Output

>### Incidents:
>|Client Sensitivity|Client Type|Company|Contact_Company|Create Date|DatasetId|Default City|Default Country|Description|First_Name|Impact Incident|Number|InfrastructureEventType|InstanceId|Last Modified By|Modified Date|Person Instance ID|Priority|Weight|ReconciliationIdentity|Region Reported|Date Reported|Source Request ID|Description|Site|Site Group|Site ID|State Province|Status|History|Street|Submitter|Time Zone|Urgency VIP|Zip/Postal Code|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|Standard|Office-Based Employee|Calbro Services|Calbro Services|2019-02-07T11:42:58.000+0000|0|New York| United States|hola mundo|App|1-Extensive/Widespread|INC123| None       | AGGA5B9BGBHP4APMKA9MPLNHKM0GM4 | admin         | 2019-02-07T11:42:58.000+0000 | AG0050560C63F2E1pSRAl5svAA5h4A | High   | 19                     | 0               | Americas      | 2019-02-07T11:42:58.000+0000 | Direct Input 000000000000012 | User Service Request | Headquarters, Building 1.31 | United States | STE_SOLN0002846 | New York | New     | {"New":{"user":"admin","timestamp":"2019-02-07T11:42:58.000+0000"}} | 1114 Eighth Avenue, 31st Floor | admin     | (GMT-05:00) Eastern Time (US &amp; Canada) | 3-Medium No     | 10036 |


### remedy-incident-update
***
Update exiting incident


#### Base Command

`remedy-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ID | Incident Entry ID. If EntryID is not available to you, incident details can be found using `remedy-fetch-incidents query="'Incident Number' = \"&lt;incident number&gt;\"". | Required | 
| description | Updated description. | Optional | 
| status | Updated status (unchanged if not specified). Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Optional | 
| urgency | Updated urgency (unchanged if not specified). Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Optional | 
| impact | Updated impact (unchanged if not specified). Possible values are: 1-Extensive/Widespread, 2-Signinficant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Optional | 
| source | Updated reported source (unchanged if not specified). Possible values are: Direct Input, Email, External Escalation, Fax, Self-Service, Systems Management, Phone, Voice Mail, Walk, Web, Other. | Optional | 
| service-type | Updated service-type (unchanged if not specified). Possible values are: User Service Restoration, User Service Request, Infrastructure Event, Infrastructure Restoration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | string | Ticket ID | 
| Ticket.Submitter | string | Ticket submitter | 
| Ticket.Status | string | Ticket status | 
| Ticket.Description | string | Ticket description | 
| Ticket.Source | string | Ticket reported source | 
| Ticket.Impact | string | TicketiImpact | 
| Ticket.Urgency | string | Ticket urgency | 
| Ticket.Type | string | Ticket service type | 


#### Command Example
```!remedy-incident-update ID=9 description="Turns out it wasn't so bad after all!" impact="4-Minor/Localized" urgency="4-Low"```

#### Human Readable Output

>### Updated incident::
>|Client Sensitivity|Client Type|Company|Contact_Company|Create Date|DatasetId|Default City|Default Country|Description|First_Name|Impact Incident|Number|InfrastructureEventType|InstanceId|Last Modified By|Modified Date|Person Instance ID|Priority|Weight|ReconciliationIdentity|Region Reported|Date Reported|Source Request ID|Description|Site|Site Group|Site ID|State Province|Status|History|Street|Submitter|Time Zone|Urgency VIP|Zip/Postal Code|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|Standard|Office-Based Employee|Calbro Services|Calbro Services|2019-02-07T11:42:58.000+0000|0|New York| United States|hola mundo|App|1-Extensive/Widespread|INC123| None       | AGGA5B9BGBHP4APMKA9MPLNHKM0GM4 | admin         | 2019-02-07T11:42:58.000+0000 | AG0050560C63F2E1pSRAl5svAA5h4A | High   | 19                     | 0               | Americas      | 2019-02-07T11:42:58.000+0000 | Direct Input 000000000000012 | User Service Request | Headquarters, Building 1.31 | United States | STE_SOLN0002846 | New York | New     | {"New":{"user":"admin","timestamp":"2019-02-07T11:42:58.000+0000"}} | 1114 Eighth Avenue, 31st Floor | admin     | (GMT-05:00) Eastern Time (US &amp; Canada) | 3-Medium No     | 10036 |