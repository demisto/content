Use Remedy On-Demand to manage tickets
This integration was integrated and tested with version xx of Remedy On-Demand_copy

## Configure Remedy On-Demand_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Remedy On-Demand_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. 'https://myurl.com', 'http://41.79.151.82') | True |
    | Port | False |
    | Username | True |
    | Password | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### remedy-incident-create
***
Create new ticket incident


#### Base Command

`remedy-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first-name | costumer's first name (make sure costumer already exists). | Required | 
| last-name | costumer's first name (make sure costumer already exists). | Required | 
| description | Incident description. | Required | 
| status | Incident status. Possible values are: New, Assigned, In Progress, Pending, Resolved, Closed, Cancelled. | Required | 
| source | Incident source. Possible values are: Direct Input, Email, External Escalation, Fax, Self-Service, Systems Management, Phone, Voice Mail, Walk, Web, Other. | Required | 
| service-type | Incident service-type. Possible values are: User Service Restoration, User Service Request, Infrastructure Event, Infrastructure Restoration. | Required | 
| impact | Incident impact. Possible values are: 1-Extensive/Widespread, 2-Significant/Large, 3-Moderate/Limited, 4-Minor/Localized. | Required | 
| urgency | Incident urgency. Possible values are: 1-Critical, 2-High, 3-Medium, 4-Low. | Required | 
| custom-fields | Custom fields for incident creation. Should be comma separated query (i.e. field1=value1,field2=value2). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | Ticket ID | 
| Ticket.Submitter | unknown | Ticket submitter | 
| Ticket.Status | unknown | Ticket status | 
| Ticket.Description | unknown | Ticket description | 
| Ticket.Source | unknown | Ticket reported source | 
| Ticket.Impact | unknown | TicketiImpact | 
| Ticket.Urgency | unknown | Ticket urgency | 
| Ticket.Type | unknown | Ticket service type | 


#### Command Example
``` ```

#### Human Readable Output



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
| Ticket.ID | unknown | Ticket ID | 
| Ticket.Submitter | unknown | Ticket submitter | 
| Ticket.Status | unknown | Ticket status | 
| Ticket.Description | unknown | Ticket description | 
| Ticket.Source | unknown | Ticket reported source | 
| Ticket.Impact | unknown | TicketiImpact | 
| Ticket.Urgency | unknown | Ticket urgency | 
| Ticket.Type | unknown | Ticket service type | 


#### Command Example
``` ```

#### Human Readable Output



### remedy-fetch-incidents
***
Fetch all incidents


#### Base Command

`remedy-fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query/qualification format of '&lt;field&gt; LIKE "&lt;values&gt;"' (e.g. 'Company LIKE "My company"', 'Submitter LIKE "%john%"'). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | Ticket ID | 
| Ticket.Submitter | unknown | Ticket submitter | 
| Ticket.Status | unknown | Ticket status | 
| Ticket.Description | unknown | Ticket description | 
| Ticket.Source | unknown | Ticket reported source | 
| Ticket.Impact | unknown | TicketiImpact | 
| Ticket.Urgency | unknown | Ticket urgency | 
| Ticket.Type | unknown | Ticket service type | 


#### Command Example
``` ```

#### Human Readable Output



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
| Ticket.ID | unknown | Ticket ID | 
| Ticket.Submitter | unknown | Ticket submitter | 
| Ticket.Status | unknown | Ticket status | 
| Ticket.Description | unknown | Ticket description | 
| Ticket.Source | unknown | Ticket reported source | 
| Ticket.Impact | unknown | TicketiImpact | 
| Ticket.Urgency | unknown | Ticket urgency | 
| Ticket.Type | unknown | Ticket service type | 


#### Command Example
``` ```

#### Human Readable Output


