## Overview
---

Use the Securonix integration to manage incidents and watchlists.
Integration was build and tested with: SNYPR Version 6.3.
Creating incidents and watchlists is currently not supported due to API limitations.

## Configure Securonix on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Securonix.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __tenant__
    * __username__
    * __password__
    * __Fetch incidents__
    * __Incidents to fetch__
    * __Incident type__
    * __First fetch time range (<number> <time unit>, e.g., 1 hour, 30 minutes)__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. securonix-list-workflows
2. securonix-get-default-assignee-for-workflow
3. securonix-list-possible-threat-actions
4. securonix-list-policies
5. securonix-list-resource-groups
6. securonix-list-users
7. securonix-list-activity-data
8. securonix-list-violation-data
9. securonix-list-incidents
10. securonix-get-incident
11. securonix-get-incident-status
12. securonix-get-incident-workflow
13. securonix-get-incident-available-actions
14. securonix-perform-action-on-incident
15. securonix-add-comment-to-incident
16. securonix-list-watchlists
17. securonix-get-watchlist
### 1. securonix-list-workflows
---
List all available workflows.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-workflows`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Workflows.Workflow | String | Workflow name. | 
| Securonix.Workflows.Type | String | Workflow type. | 
| Securonix.Workflows.Value | String | Workflow value. | 


##### Command Example
``` ```

##### Human Readable Output


### 2. securonix-get-default-assignee-for-workflow
---
Get the default assignee for the specified workflow.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-get-default-assignee-for-workflow`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow | Worflow name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Workflows.Workflow | String | Workflow name. | 
| Securonix.Workflows.Type | String | Workflow type. | 
| Securonix.Workflows.Value | String | Workflow value. | 


##### Command Example
``` ```

##### Human Readable Output


### 3. securonix-list-possible-threat-actions
---
List possible threat actions.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-possible-threat-actions`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.ThreatActions | String | Threat actions. | 


##### Command Example
``` ```

##### Human Readable Output


### 4. securonix-list-policies
---
List policies.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-policies`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Policies.CreatedBy | String | Creator of the policy. | 
| Securonix.Policies.CreatedOn | Date | Policy created date. | 
| Securonix.Policies.Criticality | String | Policy criticality. | 
| Securonix.Policies.Description | String | Policy description. | 
| Securonix.Policies.Hql | String | Policy Hibernate Query Language. | 
| Securonix.Policies.ID | String | Policy ID. | 
| Securonix.Policies.Name | String | Policy name. | 


##### Command Example
``` ```

##### Human Readable Output


### 5. securonix-list-resource-groups
---
List resource groups.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-resource-groups`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.ResourceGroups.Name | String | Resource group name. | 
| Securonix.ResourceGroups.Type | String | Resource group type. | 


##### Command Example
``` ```

##### Human Readable Output


### 6. securonix-list-users
---
List users.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-users`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Users.LastName | String | User last name. | 
| Securonix.Users.SkipEncryption | String | Whether to skip the user encryption. | 
| Securonix.Users.Riskscore | String | User risk score. | 
| Securonix.Users.EmployeeID | String | User Emplyee ID. | 
| Securonix.Users.Masked | String | Whether the user is masked. | 
| Securonix.Users.Division | String | User division. | 
| Securonix.Users.Criticality | String | User criticality. | 
| Securonix.Users.Status | String | User status. | 
| Securonix.Users.Department | String | User department. | 
| Securonix.Users.Title | String | User title. | 
| Securonix.Users.FirstName | String | User first name. | 
| Securonix.Users.Email | String | User email. | 


##### Command Example
``` ```

##### Human Readable Output


### 7. securonix-list-activity-data
---
List activity data ofr a resource group.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-activity-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start range in format MM/dd/yyyy HH:mm:ss. | Required | 
| to | Start range in format MM/dd/yyyy HH:mm:ss. | Required | 
| query | Open query. e.g: "resourcegroupname =WindowsSnare" | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.ActivityData.Accountname | String | Account name. | 
| Securonix.ActivityData.Agentfilename | String | Agent file name. | 
| Securonix.ActivityData.Categorybehavior | String | Category behavior. | 
| Securonix.ActivityData.Categoryobject | String | Category object. | 
| Securonix.ActivityData.Categoryseverity | String | Category severity. | 
| Securonix.ActivityData.Collectionmethod | String | Collection method. | 
| Securonix.ActivityData.Collectiontimestamp | String | Collection timestamp. | 
| Securonix.ActivityData.Destinationprocessname | String | Destination process name. | 
| Securonix.ActivityData.Destinationusername | String | Destination username. | 
| Securonix.ActivityData.Deviceaddress | String | Device address. | 
| Securonix.ActivityData.Deviceexternalid | String | Device external ID. | 
| Securonix.ActivityData.Devicehostname | String | Device hostname. | 
| Securonix.ActivityData.EventID | String | Event ID. | 
| Securonix.ActivityData.Eventoutcome | String | Event outcome. | 
| Securonix.ActivityData.Eventtime | String | Event time. | 
| Securonix.ActivityData.Filepath | String | File path. | 
| Securonix.ActivityData.Ingestionnodeid | String | Ingestion node ID. | 
| Securonix.ActivityData.JobID | String | Job ID. | 
| Securonix.ActivityData.Jobstarttime | String | Job start time. | 
| Securonix.ActivityData.Message | String | Message. | 
| Securonix.ActivityData.Publishedtime | String | Published time. | 
| Securonix.ActivityData.Receivedtime | String | Received time. | 
| Securonix.ActivityData.Resourcename | String | Resource name. | 
| Securonix.ActivityData.ResourceGroupCategory | String | Resource group category. | 
| Securonix.ActivityData.ResourceGroupFunctionality | String | Resource group functionality. | 
| Securonix.ActivityData.ResourceGroupID | String | Resource group ID. | 
| Securonix.ActivityData.ResourceGroupName | String | Resource group name. | 
| Securonix.ActivityData.ResourceGroupTypeID | String | Resource group resource type ID. | 
| Securonix.ActivityData.ResourceGroupVendor | String | Resource group vendor. | 
| Securonix.ActivityData.Sourcehostname | String | Source hostname. | 
| Securonix.ActivityData.Sourceusername | String | Source username. | 
| Securonix.ActivityData.TenantID | String | Tenant ID. | 
| Securonix.ActivityData.Tenantname | String | Tenant name. | 
| Securonix.ActivityData.Timeline | String | Timeline. | 


##### Command Example
``` ```

##### Human Readable Output


### 8. securonix-list-violation-data
---
List activity data ofr an account name.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-violation-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start range in format MM/dd/yyyy HH:mm:ss. | Required | 
| to | End range in format MM/dd/yyyy HH:mm:ss. | Required | 
| query | Open query. e.g: "policyname = Possible Privilege Escalation - Self Escalation" | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.ViolationData.Accountname | String | Account name. | 
| Securonix.ViolationData.Agentfilename | String | Agent file name. | 
| Securonix.ViolationData.Baseeventid | String | Base event ID. | 
| Securonix.ViolationData.Categorybehavior | String | Category behavior. | 
| Securonix.ViolationData.Category | String | Category. | 
| Securonix.ViolationData.Categoryobject | String | Category object. | 
| Securonix.ViolationData.Categoryseverity | String | Category severity. | 
| Securonix.ViolationData.Destinationaddress | String | Destination address. | 
| Securonix.ViolationData.Destinationntdomain | String | Destination nt domain. | 
| Securonix.ViolationData.Destinationuserid | String | Destination user ID. | 
| Securonix.ViolationData.Gestinationusername | String | Gestination username. | 
| Securonix.ViolationData.Deviceaddress | String | Device address. | 
| Securonix.ViolationData.Deviceeventcategory | String | Device event category. | 
| Securonix.ViolationData.Deviceexternalid | String | Device external ID. | 
| Securonix.ViolationData.Devicehostname | String | Device hostname. | 
| Securonix.ViolationData.EventID | String | Event ID. | 
| Securonix.ViolationData.Eventoutcome | String | Event outcome. | 
| Securonix.ViolationData.Eventtime | String | Event time. | 
| Securonix.ViolationData.Generationtime | String | Generation time. | 
| Securonix.ViolationData.Invalid | String | Invalid. | 
| Securonix.ViolationData.JobID | String | Job ID. | 
| Securonix.ViolationData.Jobstarttime | String | Job start time. | 
| Securonix.ViolationData.Policyname | String | Policy name. | 
| Securonix.ViolationData.Resourcename | String | Resource name. | 
| Securonix.ViolationData.ResourceGroupID | String | Resource group ID. | 
| Securonix.ViolationData.ResourceGroupName | String | Resource group name. | 
| Securonix.ViolationData.Riskscore | String | Risk score. | 
| Securonix.ViolationData.Riskthreatname | String | Risk threat name. | 
| Securonix.ViolationData.Sessionid | String | Session ID. | 
| Securonix.ViolationData.Sourcehostname | String | Source hostname. | 
| Securonix.ViolationData.Sourcentdomain | String | Source nt domain. | 
| Securonix.ViolationData.Sourceuserid | String | Source user ID. | 
| Securonix.ViolationData.Sourceusername | String | Source username. | 
| Securonix.ViolationData.Sourceuserprivileges | String | Source user privileges. | 
| Securonix.ViolationData.TenantID | String | Tenant ID. | 
| Securonix.ViolationData.Tenantname | String | Tenant name. | 
| Securonix.ViolationData.Timeline | String | Timeline. | 
| Securonix.ViolationData.Createdate | String | Create date. | 
| Securonix.ViolationData.Criticality | String | Criticality. | 
| Securonix.ViolationData.DataSourceID | String | Data source ID. | 
| Securonix.ViolationData.Department | String | Department. | 
| Securonix.ViolationData.EmployeeID | String | Employee ID. | 
| Securonix.ViolationData.Encrypted | String | Encrypted. | 
| Securonix.ViolationData.Firstname | String | Firstname. | 
| Securonix.ViolationData.Fullname | String | Fullname. | 
| Securonix.ViolationData.ID | String | ID. | 
| Securonix.ViolationData.LanID | String | LanID. | 
| Securonix.ViolationData.Lastname | String | Lastname. | 
| Securonix.ViolationData.Lastsynctime | String | Last sync time. | 
| Securonix.ViolationData.Masked | String | Masked. | 
| Securonix.ViolationData.Mergeuniquecode | String | Merge unique code. | 
| Securonix.ViolationData.Riskscore | String | Risk score. | 
| Securonix.ViolationData.Skipencryption | String | Skip encryption. | 
| Securonix.ViolationData.Status | String | Status. | 
| Securonix.ViolationData.Timezoneoffset | String | Timezone offset. | 
| Securonix.ViolationData.Title | String | Title. | 
| Securonix.ViolationData.Uniquecode | String | Unique code. | 
| Securonix.ViolationData.UserID | String | Last sync time. | 
| Securonix.ViolationData.Workemail | String | Work email. | 
| Securonix.ViolationData.Violator | String | Violator. | 


##### Command Example
``` ```

##### Human Readable Output


### 9. securonix-list-incidents
---
List incidents.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-incidents`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from |  from time range (<number> <time unit>, e.g., 1 hour, 30 minutes) | Required | 
| to | To time of incident to pull. e.g: 2019-11-25 09:01:46. Default is current time. | Optional | 
| incident_types | Incident range. can be 1 or more from: updated,opened,closed | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Incidents.ViolatorID | String | Incident Violator ID. | 
| Securonix.Incidents.Entity | String | Incident entity. | 
| Securonix.Incidents.Riskscore | Number | Incident risk score. | 
| Securonix.Incidents.Priority | String | Incident priority. | 
| Securonix.Incidents.Reason | String | Reason for the incident. Usually includes policy name and/or possible threat name. | 
| Securonix.Incidents.IncidentStatus | String | Incident status. | 
| Securonix.Incidents.WorkflowName | String | Incident workflow name. | 
| Securonix.Incidents.Watchlisted | Boolean | Whether the incident is in a watchlist. | 
| Securonix.Incidents.IncidentType | String | Incident type. | 
| Securonix.Incidents.IncidentID | String | Incident ID. | 
| Securonix.Incidents.LastUpdateDate | Number | Last update date of the incident in epoch. | 
| Securonix.Incidents.Url | String | URL that links to the incident on Securonix. | 
| Securonix.Incidents.ViolatorText | String | Incident violator text. | 
| Securonix.Incidents.AssignedUser | String | Assigned user to the incident. | 
| Securonix.Incidents.IsWhitelisted | Boolean | Whether the incident is whitelisted. | 


##### Command Example
``` ```

##### Human Readable Output


### 10. securonix-get-incident
---
Get incident details.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-get-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Incidents.ViolatorID | String | Incident Violator ID. | 
| Securonix.Incidents.Entity | String | Incident entity. | 
| Securonix.Incidents.Riskscore | Number | Incident risk score. | 
| Securonix.Incidents.Priority | String | Incident priority. | 
| Securonix.Incidents.Reason | String | Reason for the incident. Usually includes policy name and/or possible threat name. | 
| Securonix.Incidents.IncidentStatus | String | Incident status. | 
| Securonix.Incidents.WorkflowName | String | Incident workflow name. | 
| Securonix.Incidents.Watchlisted | Boolean | Whether the incident is in a watchlist. | 
| Securonix.Incidents.IncidentType | String | Incident type. | 
| Securonix.Incidents.IncidentID | String | Incident ID. | 
| Securonix.Incidents.LastUpdateDate | Number | Last update date of the incident in epoch. | 
| Securonix.Incidents.Url | String | URL that links to the incident on Securonix. | 
| Securonix.Incidents.ViolatorText | String | Incident violator text. | 
| Securonix.Incidents.AssignedUser | String | Assigned user to the incident. | 
| Securonix.Incidents.IsWhitelisted | Boolean | Whether the incident is whitelisted. | 


##### Command Example
``` ```

##### Human Readable Output


### 11. securonix-get-incident-status
---
Get incident status.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-get-incident-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Incidents.IncidentStatus | String | Incident status. | 
| Securonix.Incidents.IncidentID | String | Incident ID. | 


##### Command Example
``` ```

##### Human Readable Output


### 12. securonix-get-incident-workflow
---
Get incident workflow.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-get-incident-workflow`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Incidents.Workflow | String | Incident workflow. | 
| Securonix.Incidents.IncidentID | String | Incident ID. | 


##### Command Example
``` ```

##### Human Readable Output


### 13. securonix-get-incident-available-actions
---
List available actions for an incident.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-get-incident-available-actions`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### 14. securonix-perform-action-on-incident
---
Performs an action on an incident.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-perform-action-on-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 
| action | Action to perform on the incident. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### 15. securonix-add-comment-to-incident
---
Add a comment to an incident.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-add-comment-to-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 
| comment | Comment. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### 16. securonix-list-watchlists
---
List watchlists.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-list-watchlists`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.WatchlistsNames | String | Watchlist names. | 


##### Command Example
``` ```

##### Human Readable Output


### 17. securonix-get-watchlist
---
Get a watchlist.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`securonix-get-watchlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | Watchlist name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Watchlists.TenantID | String | Watchlist tenant ID. | 
| Securonix.Watchlists.Tenantname | String | Watchlist tenant name. | 
| Securonix.Watchlists.Type | String | Watchlist type. | 
| Securonix.Watchlists.Watchlistname | String | Watchlist name. | 
| Securonix.Watchlists.Events.ExpiryDate | String | Expiry date of the entity in the watchlist in epoch. | 
| Securonix.Watchlists.Events.Workemail | String | Work eamil of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Fullname | String | Full name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Reason | String | Reason for the entity in the watchlist. | 
| Securonix.Watchlists.Events.LanID | String | Lan ID of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Lastname | String | Last name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.EntityName | String | Entity name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Title | String | Title of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Firstname | String | First name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.EmployeeID | String | Employee Id of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Masked | String | Whether the entity in the watchlist is masked. | 
| Securonix.Watchlists.Events.Division | String | Division of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Departmant | String | Departmant of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Status | String | Status of the entity in the watchlist. | 


##### Command Example
``` ```

##### Human Readable Output

