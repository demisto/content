Microsoft Cloud App Security is a multimode Cloud Access Security Broker (CASB). It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyber threats across all your cloud services. Use the integration to view and resolve alerts, view activities, view files, and view user accounts.
This integration was integrated and tested with version xx of MicrosoftCloudAppSecurity_copy

## Configure MicrosoftCloudAppSecurity_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MicrosoftCloudAppSecurity_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://example.net) |  | True |
    | User's key to access the API |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident severity |  | False |
    | Maximum alerts to fetch |  | False |
    | First fetch time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | Incident resolution status |  | False |
    | Custom Filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. An example of a Custom Filter is: \{"severity":\{"eq":2\}\}. Note that for filtering by "entity.policy", you should use the ID of the policy. For example, for retrieving the policy: \{"policyType": "ANOMALY_DETECTION", "id": "1234", "label": "Impossible travel", "type": "policyRule"\}" please query on \{"entity.policy":\{"eq":1234\}\}. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-alerts\#filters. | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### microsoft-cas-alerts-list
***
Returns a list of alerts that match the specified filters.


#### Base Command

`microsoft-cas-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. | Optional | 
| limit | The maximum number of records to return. Default is 50. Default is 50. | Optional | 
| severity | The severity of the alert. Possible values are: "Low", "Medium", and "High". Possible values are: Low, Medium, High. | Optional | 
| resolution_status | The alert resolution status. Possible values are: "Open", "Dismissed", and "Resolved". Possible values are: Open, Dismissed, Resolved. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-alerts#filters. | Optional | 
| alert_id | The alert ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Alerts._id | String | The alert ID. | 
| MicrosoftCloudAppSecurity.Alerts.timestamp | Date | The time the alert was created. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.id | String | The ID of the rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.label | String | The label of the rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.type | String | The type of rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.policyType | String | The policy type of the rule that triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.service.id | Number | The cloud service ID. | 
| MicrosoftCloudAppSecurity.Alerts.service.label | String | The cloud service name. | 
| MicrosoftCloudAppSecurity.Alerts.service.type | String | The cloud service type. | 
| MicrosoftCloudAppSecurity.Alerts.file.id | String | The ID of the alert file. | 
| MicrosoftCloudAppSecurity.Alerts.file.label | String | THe label of the alert file. | 
| MicrosoftCloudAppSecurity.Alerts.file.type | String | The alert file type. | 
| MicrosoftCloudAppSecurity.Alerts.user.id | String | The ID of the user who received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.user.label | String | The label of the user who received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.user.type | String | The type of the user who received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.country.id | String | The country ID where the alert originated. | 
| MicrosoftCloudAppSecurity.Alerts.country.label | String | The country label where the alert originated. | 
| MicrosoftCloudAppSecurity.Alerts.country.type | String | The country type where the alert originated. | 
| MicrosoftCloudAppSecurity.Alerts.ip.id | String | The IP address where the alert came. | 
| MicrosoftCloudAppSecurity.Alerts.ip.label | String | The IP label where the alert came. | 
| MicrosoftCloudAppSecurity.Alerts.ip.type | String | The IP type where the alert came. | 
| MicrosoftCloudAppSecurity.Alerts.ip.triggeredAlert | Boolean | Whether this IP address triggered the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.id | String | The ID of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.label | String | The label of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.type | String | The type of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.inst | Number | The instance of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.saas | Number | The service of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.pa | String | The email of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.account.entityType | Number | The entity type of the account that received the alert. | 
| MicrosoftCloudAppSecurity.Alerts.title | String | The title of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.description | String | The description of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.policy.id | String | The ID of the reason \(policy\) that explains why the alert was triggered. | 
| MicrosoftCloudAppSecurity.Alerts.policy.label | String | The label of the reason \(policy\) that explains why the alert was triggered. | 
| MicrosoftCloudAppSecurity.Alerts.policy.policyType | String | The policy type of the reason \(policy\) that explains why the alert was triggered. | 
| MicrosoftCloudAppSecurity.Alerts.threatScore | Number | The threat score of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.isSystemAlert | Boolean | Whether it is a system alert. | 
| MicrosoftCloudAppSecurity.Alerts.statusValue | Number | The status value of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.severityValue | Number | The severity value of the alert. | 
| MicrosoftCloudAppSecurity.Alerts.handledByUser | String | The user who handled the alert. | 
| MicrosoftCloudAppSecurity.Alerts.comment | String | The comment relating to the alert. | 
| MicrosoftCloudAppSecurity.Alerts.resolveTime | Date | The date/time that the alert was resolved. | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-alert-close-benign
***
An alert on a suspicious but not malicious activity, such as a penetration test or other authorized suspicious action


#### Base Command

`microsoft-cas-alert-close-benign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alerts matching the specified filters.<br/>Alert_id should appear similar to - "1234567890abcdefg".<br/>Mandatory, unless you use a custom filter. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| comment | Comment describing why the alerts were dismissed. | Optional | 
| reason | The reason for closing the alerts as benign. Providing a reason helps improve the accuracy of the detection over time. Possible values include:<br/>* Actual severity is lower<br/>* Other<br/>* Confirmed with end user<br/>* Triggered by test. Possible values are: Actual severity is lower, Other, Confirmed with end user, Triggered by test. | Optional | 
| sendFeedback | Whether feedback about this alert is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| feedbackText | The text of the feedback. | Optional | 
| allowContact | Whether consent to contact the user is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| contactEmail | The email address of the user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-alert-close-true-positive
***
Cֹlose multiple alerts matching the specified filters as true positive (an alert on a confirmed malicious activity.


#### Base Command

`microsoft-cas-alert-close-true-positive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alerts matching the specified filters.<br/>Alert_id should appear similar to - "1234567890abcdefg".<br/>Mandatory, unless you use a custom filter. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| comment | Comment describing why the alerts were dismissed. | Optional | 
| sendFeedback | Whether feedback about this alert is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| feedbackText | The text of the feedback. | Optional | 
| allowContact | Whether consent to contact the user is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| contactEmail | The email address of the user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-alert-close-false-positive
***
Close multiple alerts matching the specified filters as false positive (an alert on a non-malicious activity).


#### Base Command

`microsoft-cas-alert-close-false-positive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alerts matching the specified filters.<br/>Alert_id should appear similar to - "1234567890abcdefg".<br/>Mandatory, unless you use a custom filter. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| comment | Comment describing why the alerts were dismissed. Default is None. | Optional | 
| reason | The reason for closing the alerts as false positive. Providing a reason helps improve the accuracy of the detection over time. Possible values include:<br/>* Not of interest<br/>* Too many similar alerts<br/>* Alert is not accurate<br/>* Other. Possible values are: Not of interest, Too many similar alerts, Alert is not accurate, Other. | Optional | 
| sendFeedback | Whether feedback about this alert is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| feedbackText | The text of the feedback. | Optional | 
| allowContact | Whether consent to contact the user is provided. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| contactEmail | The email address of the user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-activities-list
***
Returns a list of activities that match the specified filters. In case of timeout errors, please consider increasing the timeout argument.


#### Base Command

`microsoft-cas-activities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | The number of records to skip. Default is 50. | Optional | 
| limit | Maximum number of records returned to the user. Default is 50. | Optional | 
| ip | The origin of the specified IP address. | Optional | 
| ip_category | The subnet categories. Valid values are: "Corporate", "Administrative", "Risky", "VPN", "Cloud_provider", and "Other". Possible values are: Corporate, Administrative, Risky, VPN, Cloud_provider, Other. | Optional | 
| taken_action | The actions taken on activities. Valid values are: "block", "proxy", "BypassProxy", "encrypt", "decrypt", "verified", "encryptionFailed", "protect", "verify", and "null". Possible values are: block, proxy, BypassProxy, encrypt, decrypt, verified, encryptionFailed, protect, verify. | Optional | 
| source | The source type. Valid values are: "Access_control", "Session_control", "App_connector", "App_connector_analysis", "Discovery", and "MDATP". Possible values are: Access_control, Session_control, App_connector, App_connector_analysis, Discovery, MDATP. | Optional | 
| custom_filter | A custom filter by which to filter the returned activities. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| activity_id | The ID of the activity. | Optional | 
| timeout | Timeout of the request to Microsoft CAS, in seconds. Default is 60 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| MicrosoftCloudAppSecurity.Activities._id | String | The ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.saasId | Number | The ID of the cloud service. | 
| MicrosoftCloudAppSecurity.Activities.timestamp | Date | The time the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.instantiation | Date | The instantiation of the activity. | 
| MicrosoftCloudAppSecurity.Activities.created | Date | The time the activity was created. | 
| MicrosoftCloudAppSecurity.Activities.eventTypeValue | String | The event type of the activity. | 
| MicrosoftCloudAppSecurity.Activities.device.clientIP | String | The device client IP address of the activity. | 
| MicrosoftCloudAppSecurity.Activities.device.userAgent | String | The user agent of the activity. | 
| MicrosoftCloudAppSecurity.Activities.device.countryCode | String | The country code \(name\) of the device. | 
| MicrosoftCloudAppSecurity.Activities.location.countryCode | String | The country code \(name\) of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.city | String | The city of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.region | String | The region of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.longitude | Number | The longitude of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.latitude | Number | The latitude of the activity. | 
| MicrosoftCloudAppSecurity.Activities.location.categoryValue | String | The category value of the activity. | 
| MicrosoftCloudAppSecurity.Activities.user.userName | String | The username associated with the activity. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.family | String | The family of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.name | String | The name of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.operatingSystem.name | String | The name of the operating system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.operatingSystem.family | String | The family of the operating system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.type | String | The type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.typeName | String | The name of the type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.version | String | The version of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.deviceType | String | The device type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.nativeBrowser | Boolean | The native browser type of the system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.os | String | The operating system in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.userAgent.browser | String | The browser in which the activity occurred. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.instanceId | Number | The ID of the instance of the event objects. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.saasId | Number | The ID of the cloud service of the event objects. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.id | String | The ID of the event objects. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.activityResult.isSuccess | Boolean | Whether the activities were successful. | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.type | String | The type of activity. | 
| MicrosoftCloudAppSecurity.Activities.confidenceLevel | Number | The confidence level of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.id | String | The user ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.saasId | String | The user cloud service ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.instanceId | String | The user instance ID of the activity. | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.name | String | The username of the activity. | 
| MicrosoftCloudAppSecurity.Activities.eventTypeName | String | The event that triggered the activity. | 
| MicrosoftCloudAppSecurity.Activities.classifications | String | The classifications of the activity. | 
| MicrosoftCloudAppSecurity.Activities.entityData.displayName | String | The display name of entity activity. | 
| MicrosoftCloudAppSecurity.Activities.entityData.id.id | String | The ID of the entity activity. | 
| MicrosoftCloudAppSecurity.Activities.entityData.resolved | Boolean | Whether the entity was resolved. | 
| MicrosoftCloudAppSecurity.Activities.description | String | The description of the activity. | 
| MicrosoftCloudAppSecurity.Activities.genericEventType | String | The generic event type of the activity. | 
| MicrosoftCloudAppSecurity.Activities.severity | String | The severity of the activity. | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-files-list
***
Returns a list of files that match the specified filters. Filters include file type, file share value, file extension, file quarantine status, and a custom filter. If you pass the custom_filter argument it will override the other filters in this command.


#### Base Command

`microsoft-cas-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. Default is 50. | Optional | 
| limit | Maximum number of records to return. Default is 50. | Optional | 
| file_type | The file type. Valid value are: Other, Document, Spreadsheet, Presentation, Text, Image, and Folder. Possible values are: Other, Document, Spreadsheet, Presentation, Text, Image, Folder. | Optional | 
| sharing | Filter files with the specified sharing levels. Valid values are: Private, Internal, External, Public, Public_Internet. Possible values are: Private, Internal, External, Public, Public_Internet. | Optional | 
| extension | Filter files by the specified file extension. | Optional | 
| quarantined | Filter by whether the file is quarantined. Valid values are: "True" or "False". Possible values are: True, False. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 
| file_id | Filter by the file ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Files._id | String | The ID of the file. | 
| MicrosoftCloudAppSecurity.Files.saasId | Number | The cloud service ID of the file. | 
| MicrosoftCloudAppSecurity.Files.instId | Number | The instance ID of the file. | 
| MicrosoftCloudAppSecurity.Files.fileSize | Number | The size of the file. | 
| MicrosoftCloudAppSecurity.Files.createdDate | Date | The date the file was created. | 
| MicrosoftCloudAppSecurity.Files.modifiedDate | Date | The date the file was last modified. | 
| MicrosoftCloudAppSecurity.Files.parentId | String | The parent ID of the file. | 
| MicrosoftCloudAppSecurity.Files.ownerName | String | The name of the file owner. | 
| MicrosoftCloudAppSecurity.Files.isFolder | Boolean | Whether the file is a folder. | 
| MicrosoftCloudAppSecurity.Files.fileType | String | The file type. | 
| MicrosoftCloudAppSecurity.Files.name | String | The name of the file. | 
| MicrosoftCloudAppSecurity.Files.isForeign | Boolean | Whether the file is foreign. | 
| MicrosoftCloudAppSecurity.Files.noGovernance | Boolean | Whether the file is no governance. | 
| MicrosoftCloudAppSecurity.Files.fileAccessLevel | String | The access level of the file. | 
| MicrosoftCloudAppSecurity.Files.ownerAddress | String | The email address of the file owner. | 
| MicrosoftCloudAppSecurity.Files.externalShares | String | The external shares of the file. | 
| MicrosoftCloudAppSecurity.Files.domains | String | The domains of the file. | 
| MicrosoftCloudAppSecurity.Files.mimeType | String | The mime type of the file. | 
| MicrosoftCloudAppSecurity.Files.ownerExternal | Boolean | Whether the owner of this file is external. | 
| MicrosoftCloudAppSecurity.Files.fileExtension | String | The file extension. | 
| MicrosoftCloudAppSecurity.Files.groupIds | String | The group IDs of the file. | 
| MicrosoftCloudAppSecurity.Files.groups | String | The group the file belongs to. | 
| MicrosoftCloudAppSecurity.Files.collaborators | String | The collaborators of the file. | 
| MicrosoftCloudAppSecurity.Files.fileStatus | String | The status of the file. | 
| MicrosoftCloudAppSecurity.Files.appName | String | The name of the app. | 
| MicrosoftCloudAppSecurity.Files.actions.task_name | String | The name of the task. | 
| MicrosoftCloudAppSecurity.Files.actions.type | String | The type of actions taken on the file. | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-users-accounts-list
***
Returns a list of user accounts that match the specified filters. Filters include user account type, group ID, external/internal, user account status, and custom filter. The accounts object schema includes information about how users and accounts use your organization's cloud apps.


#### Base Command

`microsoft-cas-users-accounts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | The number of records to skip. | Optional | 
| limit | The maximum number of records to return. Default is 50. Possible values are: . Default is 50. | Optional | 
| type | The type by which to filter the information about the user accounts. | Optional | 
| group_id | The group ID by which to filter the information about the user accounts. | Optional | 
| is_admin | Filter the user accounts that are defined as admins. | Optional | 
| is_external | The affiliation of the user accounts. Valid values are: "External", "Internal", and "No_value". Possible values are: External, Internal, No_value. | Optional | 
| status | The status by which to filter the information about the user accounts. Valid values are: "N/A", "Staged", "Active", "Suspended", and "Deleted". Possible values are: N/A, Staged, Active, Suspended, Deleted. | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters in this command. For more information about filter syntax, refer to https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.UsersAccounts.displayName | String | The display name of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.id | String | The ID of the user account in the product. | 
| MicrosoftCloudAppSecurity.UsersAccounts._id | String | The ID of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.isAdmin | Boolean | Whether the user account has admin privileges. | 
| MicrosoftCloudAppSecurity.UsersAccounts.isExternal | Boolean | Whether the user account is external. | 
| MicrosoftCloudAppSecurity.UsersAccounts.email | String | The email address of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.role | String | The role of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.organization | String | The organization to which the user account belongs. | 
| MicrosoftCloudAppSecurity.UsersAccounts.lastSeen | Unknown | The date the user account was last active. | 
| MicrosoftCloudAppSecurity.UsersAccounts.domain | String | The domain of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.threatScore | Unknown | The threat score of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.idType | Number | The ID type \(number\) of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.isFake | Boolean | Whether the user account is marked as fake. | 
| MicrosoftCloudAppSecurity.UsersAccounts.username | String | The username of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.actions.task_name | String | The task name of the action of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.actions.type | String | The type of action of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts._id | String | The account ID of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.inst | Number | The number of instances of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.saas | Number | The cloud services of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.dn | String | The domain name of the cloud services of the user accounts. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.aliases | String | The user account aliases. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.isFake | Boolean | Whether the user account is marked as fake. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.em | Unknown | The email address of the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.actions.task_name | String | The task name of the action. | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.actions.type | String | The type of the action. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups._id | String | The ID of the user group for the user account. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.id | String | The ID of the user group in the product. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.name | String | The name of the user group. | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.usersCount | Number | The number of users in the user group. | 


#### Command Example
``` ```

#### Human Readable Output


