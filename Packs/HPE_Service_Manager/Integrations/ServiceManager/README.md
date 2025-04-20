Service Manager By Micro Focus (Formerly HPE Software).

## Configure Micro Focus Service Manager in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.0.1:13080) | True |
| Username | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hpsm-update-incident
***
Updates existing incident (beta).


#### Base Command

`hpsm-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | The ID of the incident. For example: "IM10013". | Required | 
| title | The title of the incident. | Optional | 
| description | The description of the incident. | Optional | 
| service | The service. For example: "CI1001060", "CI1001030". | Optional | 
| impact | The impact. Default is 4. Should be a number like 3 or 4. | Optional | 
| urgency | The urgency. Default is 4. Should be a number like 3 or 4. | Optional | 
| alertStatus | The alert status. For example: "SLA BREACH". | Optional | 
| area | The area. For example: "performance", "failure", "hardware", "access". . | Optional | 
| assignmentGroup | The assignment group. For example: "Office Supplies (North America)". | Optional | 
| affectedCI | The affected CI. For example: "CI1000783". | Optional | 
| category | Category of the incident. For example: "incident", "complaint". | Optional | 
| company | The company. For example: "advantage". | Optional | 
| phase | The phase. For example: "Categorization". | Optional | 
| status | The status. For example: "Categorize". | Optional | 
| subarea | The sub-area. For example: system or application hangs, function or feature not working, error message, job failed, hardware failure, etc. | Optional | 
| customFields | Custom fields in JSON format. For example: {"businessUnit":"5"}. Field name is case-sensitive. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | The ID of the ticket. | 
| Ticket.Creator | unknown | The name of the user who created/opened the ticket. | 
| Ticket.Assignee | unknown | To whom the ticket is assigned. | 
| Ticket.State | unknown | The state of the ticket \(open, closed, on hold\). | 
| HPSM.Incidents.IncidentID | unknown | The ID of the incident. | 
| HPSM.Incidents.Service | unknown | Service/device number \(For example: CI1001030\). | 
| HPSM.Incidents.Area | unknown | Incident area. | 
| HPSM.Incidents.Assignee | unknown | Incident assignee. | 
| HPSM.Incidents.AssignmentGroup | unknown | Incident assignment group. | 
| HPSM.Incidents.Category | unknown | Incident category. | 
| HPSM.Incidents.ClosedBy | unknown | The user who closed the incident. | 
| HPSM.Incidents.ClosedTime | unknown | Incident close time. | 
| HPSM.Incidents.ClosureCode | unknown | Incident closure code. | 
| HPSM.Incidents.Company | unknown | Incident company. | 
| HPSM.Incidents.Contact | unknown | Incident contact details. | 
| HPSM.Incidents.Description | unknown | Incident description. | 
| HPSM.Incidents.Impact | unknown | Incident impact. | 
| HPSM.Incidents.JournalUpdates | unknown | Incident journal updates. | 
| HPSM.Incidents.OpenTime | unknown | Incident open time. | 
| HPSM.Incidents.OpenedBy | unknown | The user who opened the incident. | 
| HPSM.Incidents.Phase | unknown | Incident phase. | 
| HPSM.Incidents.Solution | unknown | Incident solution. | 
| HPSM.Incidents.Status | unknown | Incident status. | 
| HPSM.Incidents.Subarea | unknown | Incident sub-area. | 
| HPSM.Incidents.Title | unknown | Incident title. | 
| HPSM.Incidents.UpdatedBy | unknown | The last user who updated the incident. | 
| HPSM.Incidents.UpdatedTime | unknown | Incident update time. | 
| HPSM.Incidents.Urgency | unknown | Incident urgency. | 

### hpsm-create-incident
***
Creates a new incident.


#### Base Command

`hpsm-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the incident. | Required | 
| description | The description of the incident. | Required | 
| service | The service. For example: "CI1001060", "CI1001030". | Required | 
| impact | The impact. Default is 4. Should be a number like 3 or 4. | Optional | 
| urgency | The impact. Default is 4. Should be a number like 3 or 4. | Optional | 
| alertStatus | The alert status. For example: "SLA BREACH". | Optional | 
| area | The area. For example: "performance", "failure", "hardware", "access". | Optional | 
| assignmentGroup | The assignment group. For example: "Office Supplies (North America)". | Optional | 
| affectedCI | The affected CI. For example: "CI1000783". | Optional | 
| category | Category of the incident. For example: "incident", "complaint". | Required | 
| company | The company. For example: "advantage". | Optional | 
| phase | The phase. For example: "Categorization". | Optional | 
| status | The status. For example: "Categorize". | Optional | 
| subarea | The sub-area. For example: system or application hangs, function or feature not working, error message, job failed, hardware failure, etc. | Optional | 
| customFields | Custom fields in JSON format. For example: {"businessUnit":"5"}. Field name is case-sensitive. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | The ID of the ticket. | 
| Ticket.Creator | unknown | The user who created/opened the ticket. | 
| Ticket.Assignee | unknown | To whom the ticket is assigned. | 
| Ticket.State | unknown | The state of the ticket \(open, closed, on hold\). | 
| HPSM.Incidents.IncidentID | unknown | The ID of the incident. | 
| HPSM.Incidents.Service | unknown | Service/device number. | 
| HPSM.Incidents.Area | unknown | Incident area. | 
| HPSM.Incidents.Assignee | unknown | Incident assignee. | 
| HPSM.Incidents.AssignmentGroup | unknown | Incident assignment group. | 
| HPSM.Incidents.Category | unknown | Incident category. | 
| HPSM.Incidents.ClosedBy | unknown | The user who closed the incident. | 
| HPSM.Incidents.ClosedTime | unknown | Incident close time. | 
| HPSM.Incidents.ClosureCode | unknown | Incident closure code. | 
| HPSM.Incidents.Company | unknown | Incident company. | 
| HPSM.Incidents.Contact | unknown | Incident contact details. | 
| HPSM.Incidents.Description | unknown | Incident description. | 
| HPSM.Incidents.Impact | unknown | Incident impact. | 
| HPSM.Incidents.JournalUpdates | unknown | Incident journal updates. | 
| HPSM.Incidents.OpenTime | unknown | Incident open time. | 
| HPSM.Incidents.OpenedBy | unknown | The user who opened the incident. | 
| HPSM.Incidents.Phase | unknown | Incident phase. | 
| HPSM.Incidents.Solution | unknown | Incident solution. | 
| HPSM.Incidents.Status | unknown | Incident status. | 
| HPSM.Incidents.Subarea | unknown | Incident sub-area. | 
| HPSM.Incidents.Title | unknown | Incident title. | 
| HPSM.Incidents.UpdatedBy | unknown | The last user who updated the incident. | 
| HPSM.Incidents.UpdatedTime | unknown | Incident update time. | 
| HPSM.Incidents.Urgency | unknown | Incident urgency. | 

### hpsm-list-incidents
***
Returns all incidents.


#### Base Command

`hpsm-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query by which to limit the returned list of incidents. For example: field1=value1&amp;field2=value2. For more information, see https://docs.microfocus.com/SM/9.41/Codeless/Content/Resources/PDF_PD/HP_Service_Manager_Web_Services_codeless.pdf. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPSM.IncidentIDs | unknown | An array of incident IDs. | 

### hpsm-get-incident-by-id
***
Returns a single incident by ID. If no incident exists with the specified ID, an error will be returned.


#### Base Command

`hpsm-get-incident-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | The ID of an incident. For exampleJ: "IM10013". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | The ID of the ticket. | 
| Ticket.Creator | unknown | The user who created/opened the ticket. | 
| Ticket.Assignee | unknown | To whom the ticket is assigned. | 
| Ticket.State | unknown | The state of the ticket \(open, closed, on hold\). | 
| HPSM.Incidents.IncidentID | unknown | The ID of the incident. | 
| HPSM.Incidents.Service | unknown | Service/device number. | 
| HPSM.Incidents.Area | unknown | Incident area. | 
| HPSM.Incidents.Assignee | unknown | Incident assignee. | 
| HPSM.Incidents.AssignmentGroup | unknown | Incident assignment group. | 
| HPSM.Incidents.Category | unknown | Incident category. | 
| HPSM.Incidents.ClosedBy | unknown | The user who closed the incident. | 
| HPSM.Incidents.ClosedTime | unknown | Incident close time. | 
| HPSM.Incidents.ClosureCode | unknown | Incident closure code. | 
| HPSM.Incidents.Company | unknown | Incident company. | 
| HPSM.Incidents.Contact | unknown | Incident contact details. | 
| HPSM.Incidents.Description | unknown | Incident description. | 
| HPSM.Incidents.Impact | unknown | Incident impact. | 
| HPSM.Incidents.JournalUpdates | unknown | Incident journal updates. | 
| HPSM.Incidents.OpenTime | unknown | Incident open time. | 
| HPSM.Incidents.OpenedBy | unknown | The user who opened the incident. | 
| HPSM.Incidents.Phase | unknown | Incident phase. | 
| HPSM.Incidents.Solution | unknown | Incident solution. | 
| HPSM.Incidents.Status | unknown | Incident status. | 
| HPSM.Incidents.Subarea | unknown | Incident sub-area. | 
| HPSM.Incidents.Title | unknown | Incident title. | 
| HPSM.Incidents.UpdatedBy | unknown | The last user who updated the incident. | 
| HPSM.Incidents.UpdatedTime | unknown | Incident update time. | 
| HPSM.Incidents.Urgency | unknown | Incident urgency. | 

### hpsm-create-resource
***
Updates the existing resource (beta).


#### Base Command

`hpsm-create-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the resource. | Required | 
| description | The description of the resource. | Required | 
| service | The service. For example: "CI1001060", "CI1001030". | Required | 
| impact | The impact. Default is 4. Should be a number like 3 or 4. | Optional | 
| urgency | The urgency. Default is 4. Should be a number like 3 or 4. | Optional | 
| alertStatus | The alert status. For example: "SLA BREACH". | Optional | 
| area | The area. For example: performance, failure, hardware, access". | Optional | 
| assignmentGroup | The assignment group. For example: "Office Supplies (North America)". | Optional | 
| affectedCI | The affected CI. For example: "CI1000783". | Optional | 
| category | Category of resource. For example: "resource", "complaint". | Required | 
| company | The company. For example: "advantage". | Optional | 
| phase | The phase. For example: "Categorization". | Optional | 
| status | The status. For example: "Categorize". | Optional | 
| subarea | The sub-area. For example: system or application hangs, function or feature not working, error message, job failed, hardware failure, etc. | Optional | 
| customFields | Custom fields in JSON format. For example: {"businessUnit":"5"}. Field name is case-sensitive. | Optional | 
| resourceName | The resource name (API URI) that will be used. For example: "incidents". | Required | 
| resourceKey | The resource key that will be used. For example: "InteractionID". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | The ID of the ticket. | 
| Ticket.Creator | unknown | The user who created/opened the ticket. | 
| Ticket.Assignee | unknown | To whom the ticket is assigned. | 
| Ticket.State | unknown | The state of the ticket \(open, closed, on hold\). | 
| HPSM.Resources.ResourceID | unknown | The ID of the resource. | 
| HPSM.Resources.Service | unknown | Service/device number. | 
| HPSM.Resources.Area | unknown | Resource area. | 
| HPSM.Resources.Assignee | unknown | Resource assignee. | 
| HPSM.Resources.AssignmentGroup | unknown | Resource assignment group. | 
| HPSM.Resources.Category | unknown | Resource category. | 
| HPSM.Resources.ClosedBy | unknown | The user who closed the resource. | 
| HPSM.Resources.ClosedTime | unknown | Resource close time. | 
| HPSM.Resources.ClosureCode | unknown | Resource closure code. | 
| HPSM.Resources.Company | unknown | Resource company. | 
| HPSM.Resources.Contact | unknown | Resource contact details. | 
| HPSM.Resources.Description | unknown | Resource description. | 
| HPSM.Resources.Impact | unknown | Resource impact. | 
| HPSM.Resources.JournalUpdates | unknown | Resource journal updates. | 
| HPSM.Resources.OpenTime | unknown | Resource open time. | 
| HPSM.Resources.OpenedBy | unknown | The user who opened the resource. | 
| HPSM.Resources.Phase | unknown | Resource phase. | 
| HPSM.Resources.Solution | unknown | Resource solution. | 
| HPSM.Resources.Status | unknown | Resource status. | 
| HPSM.Resources.Subarea | unknown | Resource sub-area. | 
| HPSM.Resources.Title | unknown | Resource title. | 
| HPSM.Resources.UpdatedBy | unknown | The last user who updated the resource. | 
| HPSM.Resources.UpdatedTime | unknown | Resource update time. | 
| HPSM.Resources.Urgency | unknown | Resource urgency. | 

### hpsm-update-resource
***
Creates a new resource.


#### Base Command

`hpsm-update-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the resource. | Required | 
| description | The description of the resource. | Required | 
| service | The service. For example: "CI1001060", "CI1001030". | Required | 
| impact | The impact. Default is 4. Should be a number like 3 or 4. | Optional | 
| urgency | The urgency. Default is 4. Should be a number like 3 or 4. | Optional | 
| alertStatus | The alert status. For example: "SLA BREACH". | Optional | 
| area | The area. For example: "performance", "failure", "hardware", "access". | Optional | 
| assignmentGroup | The assignment group. For example: "Office Supplies (North America)". | Optional | 
| affectedCI | The affected CI. For example: "CI1000783". | Optional | 
| category | Category of resource. For example: "resource", "complaint". | Required | 
| company | The company. For example: "advantage". | Optional | 
| phase | The phase. For example: "Categorization". | Optional | 
| status | The status. For example: "Categorize". | Optional | 
| subarea | The sub-area. For example: system or application hangs, function or feature not working, error message, job failed, hardware failure, etc. | Optional | 
| customFields | Custom fields in JSON format. For example: {"businessUnit":"5"}. Field name is case-sensitive. | Optional | 
| resourceName | The resource name (API URI) that will be used. For example: "incidents". | Required | 
| resourceKey | The resource key that will be used. For example: "InteractionID". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | The ID of the ticket. | 
| Ticket.Creator | unknown | The user who created/opened the ticket. | 
| Ticket.Assignee | unknown | To whom the ticket is assigned. | 
| Ticket.State | unknown | The state of the ticket \(open, closed, on hold\). | 
| HPSM.Resources.ResourceID | unknown | The ID of the resource. | 
| HPSM.Resources.Service | unknown | Service/device number. | 
| HPSM.Resources.Area | unknown | Resource area. | 
| HPSM.Resources.Assignee | unknown | Resource assignee. | 
| HPSM.Resources.AssignmentGroup | unknown | Resource assignment group. | 
| HPSM.Resources.Category | unknown | Resource category. | 
| HPSM.Resources.ClosedBy | unknown | The user who closed the resource. | 
| HPSM.Resources.ClosedTime | unknown | Resource close time. | 
| HPSM.Resources.ClosureCode | unknown | Resource closure code. | 
| HPSM.Resources.Company | unknown | Resource company. | 
| HPSM.Resources.Contact | unknown | Resource contact details. | 
| HPSM.Resources.Description | unknown | Resource description. | 
| HPSM.Resources.Impact | unknown | Resource impact. | 
| HPSM.Resources.JournalUpdates | unknown | Resource journal updates. | 
| HPSM.Resources.OpenTime | unknown | Resource open time. | 
| HPSM.Resources.OpenedBy | unknown | The user who opened the resource. | 
| HPSM.Resources.Phase | unknown | Resource phase. | 
| HPSM.Resources.Solution | unknown | Resource solution. | 
| HPSM.Resources.Status | unknown | Resource status. | 
| HPSM.Resources.Subarea | unknown | Resource sub-area. | 
| HPSM.Resources.Title | unknown | Resource title. | 
| HPSM.Resources.UpdatedBy | unknown | The last user who updated the resource. | 
| HPSM.Resources.UpdatedTime | unknown | Resource update time. | 
| HPSM.Resources.Urgency | unknown | Resource urgency. | 

### hpsm-list-resources
***
Returns all resources (beta).


#### Base Command

`hpsm-list-resources`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query by which to limit the returned list of incidents. For example: field1=value1&amp;field2=value2. For more information, see https://docs.microfocus.com/SM/9.41/Codeless/Content/Resources/PDF_PD/HP_Service_Manager_Web_Services_codeless.pdf. | Optional | 
| resourceName | The resource name (API URI) that will be used. For example: "incidents". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPSM.ResourceIDs | unknown | An array of resource IDs. | 

### hpsm-get-resource-by-id
***
Returns a single resource by ID. If no resource exists with the specified ID, an error will be returned (beta).


#### Base Command

`hpsm-get-resource-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resourceId | The ID of the resource. For example: "IM10013". | Required | 
| resourceName | The resource name (API URI) that will be used. For example: "incidents". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.ID | unknown | The ID of the ticket. | 
| Ticket.Creator | unknown | The user who created/opened the ticket. | 
| Ticket.Assignee | unknown | To whom the ticket is assigned. | 
| Ticket.State | unknown | The state of the ticket \(open, closed, on hold\). | 
| HPSM.Resources.ResourceID | unknown | The ID of the resource. | 
| HPSM.Resources.Service | unknown | Service/device number. | 
| HPSM.Resources.Area | unknown | Resource area. | 
| HPSM.Resources.Assignee | unknown | Resource assignee. | 
| HPSM.Resources.AssignmentGroup | unknown | Resource assignment group. | 
| HPSM.Resources.Category | unknown | Resource category. | 
| HPSM.Resources.ClosedBy | unknown | The user who closed the resource. | 
| HPSM.Resources.ClosedTime | unknown | Resource close time. | 
| HPSM.Resources.ClosureCode | unknown | Resource closure code. | 
| HPSM.Resources.Company | unknown | Resource company. | 
| HPSM.Resources.Contact | unknown | Resource contact details. | 
| HPSM.Resources.Description | unknown | Resource description. | 
| HPSM.Resources.Impact | unknown | Resource impact. | 
| HPSM.Resources.JournalUpdates | unknown | Resource journal updates. | 
| HPSM.Resources.OpenTime | unknown | Resource open time. | 
| HPSM.Resources.OpenedBy | unknown | The user who opened the resource. | 
| HPSM.Resources.Phase | unknown | Resource phase. | 
| HPSM.Resources.Solution | unknown | Resource solution. | 
| HPSM.Resources.Status | unknown | Resource status. | 
| HPSM.Resources.Subarea | unknown | Resource sub-area. | 
| HPSM.Resources.Title | unknown | Resource title. | 
| HPSM.Resources.UpdatedBy | unknown | The last user who updated the resource. | 
| HPSM.Resources.UpdatedTime | unknown | Resource update time. | 
| HPSM.Resources.Urgency | unknown | Resource urgency. | 

### hpsm-list-devices
***
Returns a list of devices, filtered according to query.


#### Base Command

`hpsm-list-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query by which to limit the returned list of incidents. For example: field1=value1&amp;field2=value2. For more information, see https://docs.microfocus.com/SM/9.41/Codeless/Content/Resources/PDF_PD/HP_Service_Manager_Web_Services_codeless.pdf. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPSM.DeviceIDs | unknown | The IDs \(configuration items\) of the devices. | 

### hpsm-get-device
***
Find and return a device by ID.


#### Base Command

`hpsm-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| configurationItem | ID of the configuration item of the device. For example: "CI1000011". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPSM.Devices.AssignmentGroup | unknown | Device assignment group. | 
| HPSM.Devices.Company | unknown | Device company. | 
| HPSM.Devices.ConfigurationItem | unknown | Device configuration item. | 
| HPSM.Devices.ConfigurationItemSubType | unknown | Device configurationItem sub-type. | 
| HPSM.Devices.ConfigurationItemType | unknown | Device configuration item type. | 
| HPSM.Devices.Department | unknown | Device department. | 
| HPSM.Devices.DisplayName | unknown | Device display name. | 
| HPSM.Devices.Location | unknown | Device location. | 
| HPSM.Devices.LocationCode | unknown | Device location code. | 
| HPSM.Devices.Model | unknown | Device model. | 
| HPSM.Devices.PartNumber | unknown | Device part number. | 
| HPSM.Devices.Status | unknown | Device status. | 
| HPSM.Devices.UpdatedBy | unknown | The last user who updated the device. | 

### hpsm-create-request
***
Creates a new service request


#### Base Command

`hpsm-create-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the request. | Required | 
| purpose | The purpose of the request. | Required | 
| callbackcontactname | Who created/opened the service request. | Optional | 
| contactname | Incident contact details. | Required | 
| resourceName | The resource name (API URI) that will be used. For example: "incidents". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPSM.ServiceRequest.ContactName | unknown | Who created/opened the service request | 
| HPSM.ServiceRequest.ID | unknown | The id of the service request | 
| HPSM.ServiceRequest.CallbackContactName | unknown | Incident contact details | 
| HPSM.ServiceRequest.Title | unknown | Incident title | 