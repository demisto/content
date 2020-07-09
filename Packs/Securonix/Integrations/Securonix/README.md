## Overview
Use the Securonix integration to manage incidents and watchlists.
Integration was built and tested with SNYPR Versions: 6.2, 6.3, 6.3.1.

This integration supports both cloud and on-prem instances of Securonix.
To configure a cloud base instance use the *tenant* parameter only.
To configure an on-prem instance, use both the *host* and *tenant* parameters.
For more information, visit: `securonix/etnants/<tenantname>/securonix_home/responses/demisto` 

## Configure Securonix on Demisto
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Securonix.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| host | Host (Overrides the default hostname: `https://{tenant}.net/Snypr`) | False |
| tenant | Tenant | True |
| username | Username | True |
| password | Password | True |
| isFetch | Fetch incidents | False |
| incident_status | Incidents to fetch | False |
| incidentType | Incident type | False |
| fetch_time | First fetch time range (`<number> <time unit>`, e.g., 1 hour, 30 minutes) | False |
| max_fetch | The maximum number of incidents to fetch each time. Maximum is 50. | False |
| unsecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### securonix-list-workflows
***
Gets a list of all available workflows.


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
```!securonix-list-workflows```

##### Context Example
```
{
    "Securonix": {
        "Workflows": [
            {
                "Type": "USER",
                "Value": "admin",
                "Workflow": "SOCTeamReview"
            },
            {
                "Type": "USER",
                "Value": "admin",
                "Workflow": "ActivityOutlierWorkflow"
            },
            {
                "Type": "USER",
                "Value": "admin",
                "Workflow": "AccessCertificationWorkflow"
            },
            {
                "Type": "USER",
                "Value": "admin",
                "Workflow": "test"
            }
        ]
    }
}
```

##### Human Readable Output
### Available workflows:
|Workflow|Type|Value|
|---|---|---|
| SOCTeamReview | USER | admin |
| ActivityOutlierWorkflow | USER | admin |
| AccessCertificationWorkflow | USER | admin |
| test | USER | admin |


### securonix-get-default-assignee-for-workflow
***
Gets the default assignee for the specified workflow.


##### Base Command

`securonix-get-default-assignee-for-workflow`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow | Workflow name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Workflows.Workflow | String | Workflow name. | 
| Securonix.Workflows.Type | String | Workflow type. | 
| Securonix.Workflows.Value | String | Workflow value. | 


##### Command Example
```!securonix-get-default-assignee-for-workflow workflow=SOCTeamReview```

##### Context Example
```
{
    "Securonix": {
        "Workflows": {
            "Type": "USER",
            "Value": "admin",
            "Workflow": "SOCTeamReview"
        }
    }
}
```

##### Human Readable Output
Default assignee for the workflow SOCTeamReview is: admin.

### securonix-list-possible-threat-actions
***
Gets a list available threat actions.


##### Base Command

`securonix-list-possible-threat-actions`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.ThreatActions | String | A list of threat actions. | 


##### Command Example
```!securonix-list-possible-threat-actions```

##### Context Example
```
{
    "Securonix": {
        "ThreatActions": [
            "Mark as concern and create incident",
            "Non-Concern",
            "Mark in progress (still investigating)"
        ]
    }
}
```

##### Human Readable Output
Possible threat actions are: Mark as concern and create incident, Non-Concern, Mark in progress (still investigating).

### securonix-list-policies
***
Gets a list of all policies.


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
```!securonix-list-policies```

##### Context Example
```
{
    "Securonix": {
        "Policies": [
            {
                "CreatedBy": "admin",
                "CreatedOn": "2013-11-09T16:13:23Z",
                "Criticality": "Low",
                "Description": null,
                "Hql": "FROM AccessAccount AS accessaccount, Resources AS resources, AccessAccountUser AS accessaccountuser WHERE ((accessaccount.resourceid  = resources.id  AND accessaccountuser.id.accountid  = accessaccount.id )) AND ((accessaccountuser.id.userid  = '-1'))",
                "ID": "1",
                "Name": "Accounts that dont have Users"
            },
            {
                "CreatedBy": "admin",
                "CreatedOn": "2013-11-09T16:31:09Z",
                "Criticality": "Medium",
                "Description": null,
                "Hql": "FROM Users AS users, AccessAccountUser AS accessaccountuser, AccessAccount AS accessaccount, Resources AS resources WHERE ((users.id  = accessaccountuser.id.userid  AND accessaccountuser.id.accountid  = accessaccount.id  AND accessaccount.resourceid  = resources.id )) AND ((users.status  = '0'))",
                "ID": "2",
                "Name": "Accounts that belong to terminated user"
            },
           
        ]
    }
}
```

##### Human Readable Output
### Policies:
|ID|Name|Criticality|Created On|Created By|Description|
|---|---|---|---|---|---|
| 1 | Accounts that dont have Users | Low | 2013-11-09T16:13:23Z | admin |  |
| 2 | Accounts that belong to terminated user | Medium | 2013-11-09T16:31:09Z | admin |  |


### securonix-list-resource-groups
***
Gets a list of resource groups.


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
```!securonix-list-resource-groups```

##### Context Example
```
{
    "Securonix": {
        "ResourceGroups": [
            {
                "Name": "Windows-CST1",
                "Type": "Microsoft Windows SNARE"
            },
            {
                "Name": "Websense Proxy",
                "Type": "Websense Proxy Server"
            },
            {
                "Name": "Palo Alto",
                "Type": "Palo Alto Next-Generation Firewall"
            },
            {
                "Name": "CDS1",
                "Type": "ControlsDS1"
            },
            {
                "Name": "Bluecoat",
                "Type": "Bluecoat Proxy"
            },
            {
                "Name": "Symantec-Email",
                "Type": "Symantec Message Security Gateway"
            },
            {
                "Name": "Proofpoint Email Gateway",
                "Type": "Proofpoint Email Gateway"
            },
            {
                "Name": "CiscoASA",
                "Type": "Cisco ASA"
            },
            {
                "Name": "CiscoAMP",
                "Type": "Cisco FireAMP"
            },
            {
                "Name": "PA800-adam",
                "Type": "Palo Alto Next-Generation Firewall"
            },
            {
                "Name": "CrowdStrike-PartnerAPI",
                "Type": "Crowdstrike Alerts Streaming"
            },
            {
                "Name": "squid-partners",
                "Type": "Squid Proxy"
            },
            {
                "Name": "Bluecoat_OP",
                "Type": "Bluecat_DHCP"
            },
            {
                "Name": "Bluecoat - Test",
                "Type": "Bluecoat Proxy"
            },
            {
                "Name": "Bluecoat_New",
                "Type": "Bluecoat Proxy"
            }
        ]
    }
}
```

##### Human Readable Output
### Resource groups:
|Name|Type|
|---|---|
| Windows-CST1 | Microsoft Windows SNARE |
| Websense Proxy | Websense Proxy Server |
| Palo Alto | Palo Alto Next-Generation Firewall |
| CDS1 | ControlsDS1 |
| Bluecoat | Bluecoat Proxy |
| Symantec-Email | Symantec Message Security Gateway |
| Proofpoint Email Gateway | Proofpoint Email Gateway |
| CiscoASA | Cisco ASA |
| CiscoAMP | Cisco FireAMP |
| PA800-adam | Palo Alto Next-Generation Firewall |
| CrowdStrike-PartnerAPI | Crowdstrike Alerts Streaming |
| squid-partners | Squid Proxy |
| Bluecoat_OP | Bluecat_DHCP |
| Bluecoat - Test | Bluecoat Proxy |
| Bluecoat_New | Bluecoat Proxy |


### securonix-list-users
***
Gets a list of users.


##### Base Command

`securonix-list-users`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Users.LastName | String | User last name. | 
| Securonix.Users.SkipEncryption | String | Whether user encryption was skipped. | 
| Securonix.Users.Riskscore | String | User risk score. | 
| Securonix.Users.EmployeeID | String | User Employee ID. | 
| Securonix.Users.Masked | String | Whether the user is masked. | 
| Securonix.Users.Division | String | User division. | 
| Securonix.Users.Criticality | String | User criticality. | 
| Securonix.Users.Status | String | User status. | 
| Securonix.Users.Department | String | User department. | 
| Securonix.Users.Title | String | User title. | 
| Securonix.Users.FirstName | String | User first name. | 
| Securonix.Users.Email | String | User email address. | 


##### Command Example
```!securonix-list-users```

##### Context Example
```
{
    "Securonix": {
        "Users": [
            {
                "ContractEndDate": "2020-01-14T00:40:44Z",
                "Criticality": "Low",
                "Department": "Data Services",
                "Division": "Global Technology",
                "Email": "jon.doe@test.com",
                "EmployeeID": "1001",
                "FirstName": "jon",
                "LastName": "doe",
                "Masked": "false",
                "Riskscore": "0.0",
                "SkipEncryption": "false",
                "Status": "1",
                "Title": "Associate-Data Services"
            }
        ]
    }
}
```

##### Human Readable Output
### Resource groups:
|First Name|Last Name|Criticality|Title|Email|
|---|---|---|---|---|
| jon | doe | Low | Associate-Data Services | jon.doe@test.com |


### securonix-list-activity-data
***
Gets a list of activity data for the specified resource group.


##### Base Command

`securonix-list-activity-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss). | Required | 
| to | End date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss). | Required | 
| query | Free-text query. For example, query=“resourcegroupname=WindowsSnare and policyname=Possible Privilege Escalation - Self Escalation”. | Optional | 


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
| Securonix.ActivityData.Eventtime | String | Time the event occurred. | 
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
| Securonix.ActivityData.Timeline | String | Time when the activity occurred, in Epoch time. | 


##### Command Example
``` ```

##### Human Readable Output


### securonix-list-violation-data
***
Gets a list activity data for an account name.


##### Base Command

`securonix-list-violation-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | Start date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss). | Required | 
| to | End date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss). | Required | 
| query | Free-text query. For example, query="resourcegroupname=WindowsSnare and policyname=Possible Privilege Escalation - Self Escalation"." | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.ViolationData.Accountname | String | Account name. | 
| Securonix.ViolationData.Agentfilename | String | Agent file name. | 
| Securonix.ViolationData.Baseeventid | String | Base event ID. | 
| Securonix.ViolationData.Categorybehavior | String | Category behavior. | 
| Securonix.ViolationData.Category | String | Violation category. | 
| Securonix.ViolationData.Categoryobject | String | Category object. | 
| Securonix.ViolationData.Categoryseverity | String | Category severity. | 
| Securonix.ViolationData.Destinationaddress | String | Destination address. | 
| Securonix.ViolationData.Destinationntdomain | String | Destination nt domain. | 
| Securonix.ViolationData.Destinationuserid | String | Destination user ID. | 
| Securonix.ViolationData.Gestinationusername | String | Destination username. | 
| Securonix.ViolationData.Deviceaddress | String | Device address. | 
| Securonix.ViolationData.Deviceeventcategory | String | Device event category. | 
| Securonix.ViolationData.Deviceexternalid | String | Device external ID. | 
| Securonix.ViolationData.Devicehostname | String | Device hostname. | 
| Securonix.ViolationData.EventID | String | Event ID. | 
| Securonix.ViolationData.Eventoutcome | String | Event outcome. | 
| Securonix.ViolationData.Eventtime | String | Time the event occurred. | 
| Securonix.ViolationData.Generationtime | String | Time that the violation was generated in Securonix. | 
| Securonix.ViolationData.Invalid | String | Whether the violation is valid. | 
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
| Securonix.ViolationData.Timeline | String | Time when the activity occurred, in Epoch time. | 
| Securonix.ViolationData.Createdate | String | Create date. | 
| Securonix.ViolationData.Criticality | String | Violation criticality. | 
| Securonix.ViolationData.DataSourceID | String | Data source ID. | 
| Securonix.ViolationData.Department | String | Department affected by the violation. | 
| Securonix.ViolationData.EmployeeID | String | Employee ID. | 
| Securonix.ViolationData.Encrypted | String | Whether the violation is encrypted. | 
| Securonix.ViolationData.Firstname | String | First name of the user that violated the policy. | 
| Securonix.ViolationData.Fullname | String | Full name of the user that violated the policy. | 
| Securonix.ViolationData.ID | String | ID of the user that violated the policy. | 
| Securonix.ViolationData.LanID | String | LAN ID associated with the policy violation. | 
| Securonix.ViolationData.Lastname | String | Last name of the user that violated the policy. | 
| Securonix.ViolationData.Lastsynctime | String | Last sync time, in Epoch time. | 
| Securonix.ViolationData.Masked | String | Whether the violation is masked. | 
| Securonix.ViolationData.Mergeuniquecode | String | Merge unique code. | 
| Securonix.ViolationData.Riskscore | String | Risk score. | 
| Securonix.ViolationData.Skipencryption | String | Skip encryption. | 
| Securonix.ViolationData.Status | String | Status of the policy violation. | 
| Securonix.ViolationData.Timezoneoffset | String | Timezone offset. | 
| Securonix.ViolationData.Title | String | Title. | 
| Securonix.ViolationData.Uniquecode | String | Unique code. | 
| Securonix.ViolationData.UserID | String | Last sync time, in Epoch time. | 
| Securonix.ViolationData.Workemail | String | Work email address of the user that violated the policy. | 
| Securonix.ViolationData.Violator | String | Violator. | 


##### Command Example
``` ```

##### Human Readable Output


### securonix-list-incidents
***
Gets a list of incidents.


##### Base Command

`securonix-list-incidents`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from |  Start time range for which to return incidents (`<number> <time unit>`, e.g., 1 hour, 30 minutes) | Required | 
| to | End date/time for which to retrieve incidents (in the format MM/dd/yyyy HH:mm:ss) Default is current time. | Optional | 
| incident_types | The incident type. Can be "updated", "opened", or "closed". Supports multiple selections. | Optional | 


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
| Securonix.Incidents.LastUpdateDate | Number | Last update date of the incident in Epoch time. | 
| Securonix.Incidents.Url | String | URL that links to the incident on Securonix. | 
| Securonix.Incidents.ViolatorText | String | Incident violator text. | 
| Securonix.Incidents.AssignedUser | String | User assigned to the incident. | 
| Securonix.Incidents.IsWhitelisted | Boolean | Whether the incident is whitelisted. | 


##### Command Example
```!securonix-list-incidents from="5 days" incident_types=opened```

##### Context Example
```
```

##### Human Readable Output
No incidents where found in this time frame.

### securonix-get-incident
***
Gets details of the specified incident.


##### Base Command

`securonix-get-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Incidents.ViolatorID | String | Incident violator ID. | 
| Securonix.Incidents.Entity | String | Incident entity. | 
| Securonix.Incidents.Riskscore | Number | Incident risk score. | 
| Securonix.Incidents.Priority | String | Incident priority. | 
| Securonix.Incidents.Reason | String | Reason for the incident. Usually includes policy name and/or possible threat name. | 
| Securonix.Incidents.IncidentStatus | String | Incident status. | 
| Securonix.Incidents.WorkflowName | String | Incident workflow name. | 
| Securonix.Incidents.Watchlisted | Boolean | Whether the incident is in a watchlist. | 
| Securonix.Incidents.IncidentType | String | Incident type. | 
| Securonix.Incidents.IncidentID | String | Incident ID. | 
| Securonix.Incidents.LastUpdateDate | Number | The time when the incident was last updated, in Epoch time. | 
| Securonix.Incidents.Url | String | URL that links to the incident on Securonix. | 
| Securonix.Incidents.ViolatorText | String | Incident violator text. | 
| Securonix.Incidents.AssignedUser | String | User assigned to the incident. | 
| Securonix.Incidents.IsWhitelisted | Boolean | Whether the incident is whitelisted. | 


##### Command Example
```!securonix-get-incident incident_id=30107```

##### Context Example
```
{
    "Securonix": {
        "Incidents": {
            "AssignedUser": "Admin Admin",
            "Casecreatetime": 1579687173702,
            "Entity": "Users",
            "IncidentID": "30107",
            "IncidentStatus": "Open",
            "IncidentType": "Policy",
            "IsWhitelisted": false,
            "LastUpdateDate": 1579687173702,
            "ParentCaseId": "",
            "Priority": "Critical",
            "Reason": [
                "Resource: BLUECOAT",
                "Policy: Uploads to personal websites",
                "Threat: Data egress via network uploads"
            ],
            "Riskscore": 0,
            "SandBoxPolicy": false,
            "StatusCompleted": false,
            "TenantInfo": {
                "tenantcolor": "#000000",
                "tenantid": 1,
                "tenantname": "Securonix",
                "tenantshortcode": "SE"
            },
            "Url": {url},
            "ViolatorID": "9",
            "ViolatorSubText": "1009",
            "ViolatorText": "Judi Mcabee",
            "Watchlisted": false,
            "WorkflowName": "SOCTeamReview"
        }
    }
}
```

##### Human Readable Output
### Incident:
|Assigned User|Casecreatetime|Entity|Incident Status|Incident Type|IncidentID|Is Whitelisted|Last Update Date|Priority|Reason|Riskscore|Sand Box Policy|Status Completed|Tenant Info|Url|Violator Sub Text|Violator Text|ViolatorID|Watchlisted|Workflow Name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Admin Admin | 1579687173702 | Users | Open | Policy | 30107 | false | 1579687173702 | Critical | Resource: BLUECOAT,Policy: Uploads to personal websites,Threat: Data egress via network uploads | 0.0 | false | false | tenantid: 1 tenantname: {name} | {url} | 1009 | john smith | 9 | false | SOCTeamReview |


### securonix-get-incident-status
***
Gets the status of the specified incident.


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
```!securonix-get-incident-status incident_id=30107```

##### Context Example
```
{
    "Securonix": {
        "Incidents": {
            "IncidentID": "30107",
            "IncidentStatus": "Open"
        }
    }
}
```

##### Human Readable Output
Incident 30107 status is Open.

### securonix-get-incident-workflow
***
Gets the workflow of the specified incident.


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
```!securonix-get-incident-workflow incident_id=30107```

##### Context Example
```
{
    "Securonix": {
        "Incidents": {
            "IncidentID": "30107",
            "WorkflowName": "SOCTeamReview"
        }
    }
}
```

##### Human Readable Output
Incident 30107 workflow is SOCTeamReview.

### securonix-get-incident-available-actions
***
Gets a list of available actions for the specified incident.


##### Base Command

`securonix-get-incident-available-actions`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!securonix-get-incident-available-actions incident_id=30107```

##### Context Example
```
{
    "Securonix": {
        "Incidents": {
            "AvailableActions": [
                "CLAIM",
                "ASSIGN TO ANALYST",
                "ASSIGN TO SECOPS"
            ],
            "IncidentID": "30107"
        }
    }
}
```

##### Human Readable Output
Incident 30107 available actions: ['CLAIM', 'ASSIGN TO ANALYST', 'ASSIGN TO SECOPS'].

### securonix-perform-action-on-incident
***
Performs an action on the specified incident.


##### Base Command

`securonix-perform-action-on-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 
| action | Action to perform on the incident. You can see them using securonix-get-incident-available-actions. e.g: "CLAIM", "ASSIGN TO SECOPS", "ASSIGN TO ANALYST", "RELEASE", or "COMMENT". | Required | 
| action_parameters | The parameters, if needed, to perform the action. e.g, For the ASSIGN TO ANALYST action: assigntouserid={user_id},assignedTo=USER. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### securonix-add-comment-to-incident
***
Adds a comment to the specified incident.


##### Base Command

`securonix-add-comment-to-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 
| comment | Comment to add to the incident. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!securonix-add-comment-to-incident incident_id=30107 comment="Just a comment"```

##### Context Example
```
{}
```

##### Human Readable Output
Comment was added to the incident 30107 successfully.

### securonix-list-watchlists
***
Gets a list of watchlists.


##### Base Command

`securonix-list-watchlists`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.WatchlistsNames | String | Watchlist names. | 


##### Command Example
```!securonix-list-watchlists```

##### Context Example
```
{
    "Securonix": {
        "WatchlistsNames": {
            "Bad_Performance_Review": "0",
            "Contractors-UpComing_Termination": "0",
            "Domain_Admin": "0",
            "Employees-UpComing_Terminations": "0",
            "Exiting_Behavior_Watchlist": "0",
            "Flight_Risk_Users_Watchlist": "0",
            "Privileged_Accounts": "0",
            "Privileged_Users": "0",
            "Recent_Hires": "0",
            "Recent_Transfers": "0",
            "Terminated_Contractors": "0",
            "Terminated_Employees": "0",
            "Test_watchlist": "0",
            "Test_watchlist2": "0"
        }
    }
}
```

##### Human Readable Output
Watchlists: Domain_Admin, Flight_Risk_Users_Watchlist, Recent_Transfers, Exiting_Behavior_Watchlist, Test_watchlist2, Bad_Performance_Review, Terminated_Contractors, Contractors-UpComing_Termination, Privileged_Accounts, Terminated_Employees, Test_watchlist, Privileged_Users, Recent_Hires, Employees-UpComing_Terminations.

### securonix-get-watchlist
***
Gets information for the specified watchlist.


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
| Securonix.Watchlists.Events.ExpiryDate | String | Expiration date of the entity in the watchlist, in Epoch time. | 
| Securonix.Watchlists.Events.Workemail | String | Work email address of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Fullname | String | Full name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Reason | String | Reason that the entity is in the watchlist. | 
| Securonix.Watchlists.Events.LanID | String | Lan ID of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Lastname | String | Last name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.EntityName | String | Entity name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Title | String | Title of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Firstname | String | First name of the entity in the watchlist. | 
| Securonix.Watchlists.Events.EmployeeID | String | Employee ID of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Masked | String | Whether the entity in the watchlist is masked. | 
| Securonix.Watchlists.Events.Division | String | Division of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Departmant | String | Department of the entity in the watchlist. | 
| Securonix.Watchlists.Events.Status | String | Status of the entity in the watchlist. | 


##### Command Example
``` ```

##### Human Readable Output


### securonix-create-watchlist
***
Creates a watchlist in Securonix.


##### Base Command

`securonix-create-watchlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The name of the watchlist. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!securonix-create-watchlist watchlist_name=test_watchlist```

##### Context Example
```
{
    "Securonix": {
        "Watchlists": "test_watchlist"
    }
}
```

##### Human Readable Output
Watchlist test_watchlist was created successfully.

### securonix-check-entity-in-watchlist
***
Checks if the specified entity is in a watchlist.


##### Base Command

`securonix-check-entity-in-watchlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_name | The name of the entity to check. For example: 1002. | Required | 
| watchlist_name | The name of the watchlist in which to check the entity. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.EntityInWatchlist.Watchlistnames | String | The names of the watchlists in which the entity appears. | 
| Securonix.EntityInWatchlist.EntityID | String | The entity ID. | 


##### Command Example
```!securonix-check-entity-in-watchlist entity_name=1002 watchlist_name=test_watchlist```

##### Context Example
```
{
    "Securonix": {
        "EntityInWatchlist": {
            "Entityname": "1002"
        }
    }
}
```

##### Human Readable Output
Entity unique identifier 1002 provided is not in the watchlist: test_watchlist.

### securonix-add-entity-to-watchlist
***
Adds an entity to a watchlist.


##### Base Command

`securonix-add-entity-to-watchlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The name of the watchlist to which to add the entity. | Required | 
| entity_type | The entity type. Can be "Users", "Activityaccount", "RGActivityaccount", "Resources", or "Activityip". | Required | 
| entity_name | The name of the entity to add to the watchlist. For example: 1022. | Required | 
| expiry_days | The number of days after which the entity will be removed from the watchlist. The default value is "30". | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### securonix-create-incident
***
Creates an incident. For more information about the required arguments, see the Securonix documentation.


##### Base Command

`securonix-create-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| violation_name | The violation name or policy name. For example: "Uploads to personal Websites". | Required | 
| resource_group | The resource group name. For example: "BLUECOAT", "Palo Alto Firewall". | Required | 
| entity_type | The entity type. Can be "Users", "Activityaccount", "RGActivityaccount", "Resources", or "Activityip". | Required | 
| entity_name | The entity name associated with the violation. Can be "LanID" or "Workemail". For more information, see the Securonix documentation. | Required | 
| action_name | The action name. Can be "Mark as concern and create incident", "Non-Concern", or "Mark in progress (still investigating)". | Required | 
| resource_name | The resource name. For example: "BLUECOAT", "Palo Alto Firewall". | Required | 
| criticality | The incident severity (criticality) for the new incident. Can be "Low", "High", or "Critical". | Optional | 
| comment | A comment for the new incident. | Optional | 
| workflow | The workflow name. This argument is optional, but required when the action_name argument is set to "Mark as concern and create incident". Can be "SOCTeamReview", "ActivityOutlierWorkflow", or "AccessCertificationWorkflow". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Securonix.Incidents.ViolatorID | String | The ID of the incident violator. | 
| Securonix.Incidents.Entity | String | The incident entity. | 
| Securonix.Incidents.Riskscore | Number | The incident risk score. | 
| Securonix.Incidents.Priority | String | The incident priority. | 
| Securonix.Incidents.Reason | String | The reason that the incident was created. Usually includes the policy name and/or possible threat name. | 
| Securonix.Incidents.IncidentStatus | String | The incident status. | 
| Securonix.Incidents.WorkflowName | String | The incident workflow name. | 
| Securonix.Incidents.Watchlisted | Boolean | Whether the incident is in a watchlist. | 
| Securonix.Incidents.IncidentType | String | The incident type. | 
| Securonix.Incidents.IncidentID | String | The incident ID. | 
| Securonix.Incidents.LastUpdateDate | Number | The time when the incident was last updated, in Epoch time. | 
| Securonix.Incidents.Url | String | The URL that links to the incident on Securonix. | 
| Securonix.Incidents.ViolatorText | String | Text of the incident violator. | 
| Securonix.Incidents.AssignedUser | String | The user assigned to the incident. | 
| Securonix.Incidents.IsWhitelisted | Boolean | Whether the incident is whitelisted. | 


##### Command Example
```!securonix-create-incident action_name="Mark as concern and create incident" entity_name=MH1014 entity_type=Users resource_group="BLUECOAT" resource_name="BLUECOAT" violation_name="Uploads to personal Websites" workflow=SOCTeamReview  comment=bgdfs criticality=Critical```

##### Context Example
```
{
    "Securonix": {
        "Incidents": {
            "AssignedUser": "Admin Admin",
            "Casecreatetime": 1579687771677,
            "Entity": "Users",
            "IncidentID": "30134",
            "IncidentStatus": "Open",
            "IncidentType": "Policy",
            "IsWhitelisted": false,
            "LastUpdateDate": 1579687771677,
            "ParentCaseId": "",
            "Priority": "Critical",
            "Reason": [
                "Resource: BLUECOAT",
                "Policy: Uploads to personal websites",
                "Threat: Data egress via network uploads"
            ],
            "Riskscore": 0,
            "SandBoxPolicy": false,
            "StatusCompleted": false,
            "TenantInfo": {
                "tenantcolor": "#000000",
                "tenantid": 1,
                "tenantname": "Securonix",
                "tenantshortcode": "SE"
            },
            "Url": "{url}",
            "ViolatorID": "14",
            "ViolatorSubText": "1014",
            "ViolatorText": "john doe",
            "Watchlisted": false,
            "WorkflowName": "SOCTeamReview"
        }
    }
}
```

##### Human Readable Output
### Incident was created successfully
|Entity|Incident Status|Incident Type|IncidentID|Priority|Reason|Url|
|---|---|---|---|---|---|---|
| Users | Open | Policy | 30134 | Critical | Resource: BLUECOAT,Policy: Uploads to personal websites,Threat: Data egress via network uploads | {url} |

## Limitations
  - The `opened` argument for fetching and listing incidents is currently not filtering only the opened incidents.
    This is an open issue on the vendor side.
  - Until version 6.3.1, the *max_fetch argument is not used. Hence, every *fetch incidents*, only the 10 most recent incidents are going to be fetched.
