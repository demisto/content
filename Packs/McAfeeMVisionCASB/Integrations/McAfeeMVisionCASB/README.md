Skyhigh CASB is a cloud-based, multi-tenant service that enables Cloud Discovery and Risk Monitoring, Cloud Usage Analytics, Cloud Access and Control.
This integration was integrated and tested with version xx of McAfee MVision CASB

## Configure McAfee MVision CASB on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for McAfee MVision CASB.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Password | The UserName and Password to use for connection | True |
    | Maximum number of incidents to fetch every time. Default is 50. maximum is 500. |  | False |
    | First fetch in timestamp format (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days. |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mvision-casb-incident-query
***
Retrieves a list of incidents in ascending time modified order.


#### Base Command

`mvision-casb-incident-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of items that will be returned within a single response. Default is 50 maximum is 500. If value exceeds maximum 500 it will not be flagged as an error but will also not increase results. Default is 50. | Optional | 
| page | Pagination support for use with a big “limit” value. | Optional | 
| page_size | Pagination support for use with a big “limit” value. The maximum is 500. | Optional | 
| start_time | For time arguments use the ISO-8601 standard - '%Y-%m-%dT%H:%M:%SZ' or relative time (last X days). Default is 3 days. | Optional | 
| end_time | For time arguments use the ISO-8601 standard - '%Y-%m-%dT%H:%M:%SZ' or relative time (last X days). | Optional | 
| actor_ids | The actor ids of the incidents to retrieve. | Optional | 
| service_names | The service names of the incidents to retrieve. | Optional | 
| incident_types | The type of the incidents to retrieve. Possible values are: Alert, Threat. | Optional | 
| categories | The categories of the incidents to retrieve. When defining the categories argument the incident_types argument does not affect. Possible values are: Access, Admin, Audit, CompromisedAccount, Data, InsiderThreat, Policy, PrivilegeAccess, Vulnerability. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MVisionCASB.Incident | Unknown | The incident that wes returned. | 

### mvision-casb-incident-status-update
***
Update status of single/multiple incidents.
Note!
For multiple Ids  - single status will be changed for all IDs
e.g. 123, 456, 789 >> change status to >> closed.


#### Base Command

`mvision-casb-incident-status-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | The incidents ids that should be updated. | Required | 
| status | The new status of the incidents. Possible values are: new, opened, false positive, resolved, suppressed, archived. | Required | 


#### Context Output

There is no context output for this command.
### mvision-casb-anomaly-activity-list
***
Fetches activities for a given anomaly Id.


#### Base Command

`mvision-casb-anomaly-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| anomaly_id | The anomaly id from where to retrieve the activities. Only incident of type anomaly (ANO-123). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MVisionCASB.AnomalyActivity.timeStamp | String | The timestamp | 
| MVisionCASB.AnomalyActivity.actionName | String | The action name | 
| MVisionCASB.AnomalyActivity.asnName | String |  | 
| MVisionCASB.AnomalyActivity.city | String |  | 
| MVisionCASB.AnomalyActivity.collabGroup | String |  | 
| MVisionCASB.AnomalyActivity.count | Number |  | 
| MVisionCASB.AnomalyActivity.country | String |  | 
| MVisionCASB.AnomalyActivity.deviceManaged | String |  | 
| MVisionCASB.AnomalyActivity.directory | String |  | 
| MVisionCASB.AnomalyActivity.downloadBytes | Number |  | 
| MVisionCASB.AnomalyActivity.eventCount | Number |  | 
| MVisionCASB.AnomalyActivity.fileFolderPath | String |  | 
| MVisionCASB.AnomalyActivity.fileName | String |  | 
| MVisionCASB.AnomalyActivity.fileSharingEnabled | Boolean |  | 
| MVisionCASB.AnomalyActivity.fileSize | Number |  | 
| MVisionCASB.AnomalyActivity.fileType | String |  | 
| MVisionCASB.AnomalyActivity.geoOrgNameV1 | String |  | 
| MVisionCASB.AnomalyActivity.httpMethod | String |  | 
| MVisionCASB.AnomalyActivity.instanceId | String |  | 
| MVisionCASB.AnomalyActivity.isSourceTrusted | Boolean |  | 
| MVisionCASB.AnomalyActivity.networkType | String |  | 
| MVisionCASB.AnomalyActivity.objectType | String |  | 
| MVisionCASB.AnomalyActivity.operation | String |  | 
| MVisionCASB.AnomalyActivity.proxyDescription | String |  | 
| MVisionCASB.AnomalyActivity.proxyType | String |  | 
| MVisionCASB.AnomalyActivity.region | String |  | 
| MVisionCASB.AnomalyActivity.serviceName | String |  | 
| MVisionCASB.AnomalyActivity.siteUrl | String |  | 
| MVisionCASB.AnomalyActivity.sourceIP | IP |  | 
| MVisionCASB.AnomalyActivity.sourceIdentifier | String |  | 
| MVisionCASB.AnomalyActivity.targetId | String |  | 
| MVisionCASB.AnomalyActivity.targetType | String |  | 
| MVisionCASB.AnomalyActivity.tenantId | Number |  | 
| MVisionCASB.AnomalyActivity.threatCategory | String |  | 
| MVisionCASB.AnomalyActivity.trustEntity | String |  | 
| MVisionCASB.AnomalyActivity.trustReason | String |  | 
| MVisionCASB.AnomalyActivity.uploadBytes | Number |  | 
| MVisionCASB.AnomalyActivity.url | String |  | 
| MVisionCASB.AnomalyActivity.user | String |  | 

### mvision-casb-policy-dictionary-list
***
List existing Policy Dictionaries.


#### Base Command

`mvision-casb-policy-dictionary-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of policies that will be returned within a single response. Default is 50. | Optional | 
| page | Pagination support for use with a big “limit” value. | Optional | 
| page_size | Pagination support for use with a big “limit” value. | Optional | 
| name | The name of the policies to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MVisionCASB.dictionaries.ID | Number | The dictionary ID. This is the unique identifier for the target dictionary. | 
| MVisionCASB.dictionaries.LastModified | String | The dictionary last modified time | 
| MVisionCASB.dictionaries.Name | String | The dictionary name | 

### mvision-casb-policy-dictionary-update
***
Adds new content to an existing Policy Dictionaries.


#### Base Command

`mvision-casb-policy-dictionary-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The dictionary where to set the policy. | Required | 
| name | A name for the new key-value which will be added in the dictionary. | Required | 
| content | The value to be set in the dictionary for the given key-name. Multiple values can be separated by commas. | Required | 


#### Context Output

There is no context output for this command.