This is the MicrosoftCloudAppSecurity integration.
This integration was integrated and tested with version xx of MicrosoftCloudAppSecurity
## Configure MicrosoftCloudAppSecurity on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MicrosoftCloudAppSecurity.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| token | User's key to access the api | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| severity | Incidents Severity | False |
| max_fetch | Maximum alerts to fetch | False |
| first_fetch | First fetch time | False |
| resolution_status | incident resolution status | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### microsoft-cas-alert-dismiss-bulk
***
Command to dismiss multiple alerts matching the specified filters.


#### Base Command

`microsoft-cas-alert-dismiss-bulk`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Multiple alerts matching the specified filters.<br/>Alert_id should be like this template - "55af7415f8a0a7a29eef2e1f". | Optional | 
| customer_filters | Filter that the customer builds himself. | Optional | 
| comment | Comment about why the alerts are dismissed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.AlertDismiss.dismissed | Number | AlertDismiss dismissed | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-alerts-list
***
List alerts command - prints list alerts


#### Base Command

`microsoft-cas-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. | Optional | 
| limit | Maximum number of records returned by the request. | Optional | 
| severity | The severity of the alert. | Optional | 
| service | Filter alerts related to the specified service appId. | Optional | 
| instance | Filter alerts related to the specified instances. | Optional | 
| resolution_status | Filter by alert resolution status. | Optional | 
| customer_filters | Filter that the customer builds himself. (If the customer use "customer_filters" other filters will not work) | Optional | 
| alert_id | alert id | Optional | 
| username | Username. (Usually its an email address) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Alert._id | String | Alert id | 
| MicrosoftCloudAppSecurity.Alert.timestamp | Date | Alert date | 
| MicrosoftCloudAppSecurity.Alert.entities.id | Number | Alert entities id | 
| MicrosoftCloudAppSecurity.Alert.entities.label | String | Alert entities label | 
| MicrosoftCloudAppSecurity.Alert.entities.type | String | Alert entities type | 
| MicrosoftCloudAppSecurity.Alert.entities.inst | Number | Alert entities instance | 
| MicrosoftCloudAppSecurity.Alert.entities.saas | Number | Alert entities saas | 
| MicrosoftCloudAppSecurity.Alert.title | String | Alert title | 
| MicrosoftCloudAppSecurity.Alert.description | String | Alert description | 
| MicrosoftCloudAppSecurity.Alert.policy.id | String | Alert policy id | 
| MicrosoftCloudAppSecurity.Alert.policy.label | String | Alert policy label | 
| MicrosoftCloudAppSecurity.Alert.policy.policyType | String | Alert policy policyType | 
| MicrosoftCloudAppSecurity.Alert.threatScore | Number | Alert threatScore | 
| MicrosoftCloudAppSecurity.Alert.isSystemAlert | Number | Alert isSystemAlert | 
| MicrosoftCloudAppSecurity.Alert.statusValue | Number | Alert statusValue | 
| MicrosoftCloudAppSecurity.Alert.severityValue | Number | Alert severityValue | 
| MicrosoftCloudAppSecurity.Alert.handledByUser | Unknown | Alert handledByUser | 
| MicrosoftCloudAppSecurity.Alert.comment | Unknown | Alert comment | 
| MicrosoftCloudAppSecurity.Alert.resolveTime | Date | Alert resolveTime | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-alert-resolve-bulk
***
Command to resolve multiple alerts matching the specified filters.


#### Base Command

`microsoft-cas-alert-resolve-bulk`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Multiple alerts matching the specified filters.<br/>Alert_id should be like this template - "55af7415f8a0a7a29eef2e1f". | Optional | 
| customer_filters | Filter that the customer builds himself. | Optional | 
| comment | Comment about why the alerts are dismissed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.AlertResolve.resolved | Number | AlertResolved resolved | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-activities-list
***
Command for list of activities matching the specified filters.


#### Base Command

`microsoft-cas-activities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. | Optional | 
| limit | Maximum number of records returned by the request. | Optional | 
| service  | Filter activities related to the specified service appID. | Optional | 
| instance | Filter activities from specified instances. | Optional | 
| ip  | Filter activities originating from the given IP address. | Optional | 
| ip_category  | Filter activities with the specified subnet categories. | Optional | 
| username | Filter activities by the user who performed the activity. | Optional | 
| taken_action | Filter activities by the actions taken on them. | Optional | 
| source | Filter all activities by source type. | Optional | 
| customer_filters | Filter that the customer builds himself. (If the customer use "customer_filters" other filters will not work) | Optional | 
| activity_id | The ID of the activity. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Activities._id | String | Activities \_id | 
| MicrosoftCloudAppSecurity.Activities.saasId | Number | Activities saasId | 
| MicrosoftCloudAppSecurity.Activities.timestamp | Date | Activities timestamp | 
| MicrosoftCloudAppSecurity.Activities.instantiation | Date | Activities instantiation | 
| MicrosoftCloudAppSecurity.Activities.created | Date | Activities created | 
| MicrosoftCloudAppSecurity.Activities.eventTypeValue | String | Activities eventTypeValue | 
| MicrosoftCloudAppSecurity.Activities.device.clientIP | String | Activities device clientIP | 
| MicrosoftCloudAppSecurity.Activities.device.userAgent | String | Activities device userAgent | 
| MicrosoftCloudAppSecurity.Activities.device.countryCode | String | Activities device countryCode | 
| MicrosoftCloudAppSecurity.Activities.location.countryCode | String | Activities location countryCode | 
| MicrosoftCloudAppSecurity.Activities.location.city | String | Activities location city | 
| MicrosoftCloudAppSecurity.Activities.location.region | String | Activities location region | 
| MicrosoftCloudAppSecurity.Activities.location.longitude | Number | Activities location longitude | 
| MicrosoftCloudAppSecurity.Activities.location.latitude | Number | Activities location latitude | 
| MicrosoftCloudAppSecurity.Activities.location.categoryValue | String | Activities location categoryValue | 
| MicrosoftCloudAppSecurity.Activities.user.userName | String | Activities user userName | 
| MicrosoftCloudAppSecurity.Activities.userAgent.family | String | Activities userAgent family | 
| MicrosoftCloudAppSecurity.Activities.userAgent.name | String | Activities userAgent name | 
| MicrosoftCloudAppSecurity.Activities.userAgent.operatingSystem.name | String | Activities userAgent operatingSystem.name | 
| MicrosoftCloudAppSecurity.Activities.userAgent.operatingSystem.family | String | Activities userAgent operatingSystem family | 
| MicrosoftCloudAppSecurity.Activities.userAgent.type | String | Activities userAgent type | 
| MicrosoftCloudAppSecurity.Activities.userAgent.typeName | String | Activities userAgent typeName | 
| MicrosoftCloudAppSecurity.Activities.userAgent.version | String | Activities userAgent version | 
| MicrosoftCloudAppSecurity.Activities.userAgent.deviceType | String | Activities userAgent deviceType | 
| MicrosoftCloudAppSecurity.Activities.userAgent.nativeBrowser | Number | Activities userAgent nativeBrowser | 
| MicrosoftCloudAppSecurity.Activities.userAgent.os | String | Activities userAgent os | 
| MicrosoftCloudAppSecurity.Activities.userAgent.browser | String | Activities userAgent browser | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.instanceId | Number | Activities mainInfo eventObjects instanceId | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.saasId | Number | Activities mainInfo eventObjects saasId | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.eventObjects.id | String | Activities mainInfo eventObjects id | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.activityResult.isSuccess | String | Activities mainInfo activityResult isSuccess | 
| MicrosoftCloudAppSecurity.Activities.mainInfo.type | String | Activities mainInfo type | 
| MicrosoftCloudAppSecurity.Activities.confidenceLevel | Number | Activities confidenceLevel | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.id | String | Activities resolvedActor id | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.saasId | String | Activities resolvedActor saasId | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.instanceId | String | Activities resolvedActor instanceId | 
| MicrosoftCloudAppSecurity.Activities.resolvedActor.name | String | Activities resolvedActor name | 
| MicrosoftCloudAppSecurity.Activities.eventTypeName | String | Activities eventTypeName | 
| MicrosoftCloudAppSecurity.Activities.classifications | String | Activities classifications | 
| MicrosoftCloudAppSecurity.Activities.entityData.displayName | String | Activities entityData displayName | 
| MicrosoftCloudAppSecurity.Activities.entityData.id.id | String | Activities entityData id id | 
| MicrosoftCloudAppSecurity.Activities.entityData.resolved | Number | Activities entityData resolved | 
| MicrosoftCloudAppSecurity.Activities.description | String | Activities description | 
| MicrosoftCloudAppSecurity.Activities.genericEventType | String | Activities genericEventType | 
| MicrosoftCloudAppSecurity.Activities.severity | String | Activities severity | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-files-list
***
Command to fetch a list of files matching the specified filters.


#### Base Command

`microsoft-cas-files-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. | Optional | 
| limit | Maximum number of records returned by the request. | Optional | 
| service | Filter files from specified app appID. | Optional | 
| instance | Filter files from specified instances. | Optional | 
| file_type | Filter files with the specified file type. | Optional | 
| username | Filter files owned by specified entities. | Optional | 
| sharing | Filter files with the specified sharing levels. | Optional | 
| extension | Filter files by a given file extension. | Optional | 
| quarantined | Filter Is the file quarantined. | Optional | 
| customer_filters | Filter that the customer builds himself. (If the customer use "customer_filters" other filters will not work) | Optional | 
| file_id | Filter by file id | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Files._id | String | Files \_id | 
| MicrosoftCloudAppSecurity.Files.saasId | Number | Files saasId | 
| MicrosoftCloudAppSecurity.Files.instId | Number | Files instId | 
| MicrosoftCloudAppSecurity.Files.fileSize | Number | Files fileSize | 
| MicrosoftCloudAppSecurity.Files.createdDate | Date | Files createdDate | 
| MicrosoftCloudAppSecurity.Files.modifiedDate | Date | Files modifiedDate | 
| MicrosoftCloudAppSecurity.Files.parentId | String | Files parentId | 
| MicrosoftCloudAppSecurity.Files.ownerName | String | Files ownerName | 
| MicrosoftCloudAppSecurity.Files.isFolder | Number | Files isFolder | 
| MicrosoftCloudAppSecurity.Files.fileType | String | Files fileType | 
| MicrosoftCloudAppSecurity.Files.name | String | Files name | 
| MicrosoftCloudAppSecurity.Files.isForeign | Number | Files isForeign | 
| MicrosoftCloudAppSecurity.Files.noGovernance | Number | Files noGovernance | 
| MicrosoftCloudAppSecurity.Files.fileAccessLevel | String | Files fileAccessLevel | 
| MicrosoftCloudAppSecurity.Files.ownerAddress | String | Files ownerAddress | 
| MicrosoftCloudAppSecurity.Files.externalShares | String | Files externalShares | 
| MicrosoftCloudAppSecurity.Files.domains | String | Files domains | 
| MicrosoftCloudAppSecurity.Files.mimeType | String | Files mimeType | 
| MicrosoftCloudAppSecurity.Files.ownerExternal | Number | Files ownerExternal | 
| MicrosoftCloudAppSecurity.Files.fileExtension | String | Files fileExtension | 
| MicrosoftCloudAppSecurity.Files.groupIds | String | Files groupIds | 
| MicrosoftCloudAppSecurity.Files.groups | String | Files groups | 
| MicrosoftCloudAppSecurity.Files.collaborators | String | Files collaborators | 
| MicrosoftCloudAppSecurity.Files.fileStatus | String | Files fileStatus | 
| MicrosoftCloudAppSecurity.Files.appName | String | Files appName | 
| MicrosoftCloudAppSecurity.Files.actions.task_name | String | Files actions task\_name | 
| MicrosoftCloudAppSecurity.Files.actions.type | String | Files actions type | 


#### Command Example
``` ```

#### Human Readable Output



### microsoft-cas-users-accounts-list
***
Command for basic information about the users and accounts using your organization's cloud apps.


#### Base Command

`microsoft-cas-users-accounts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip | Skips the specified number of records. | Optional | 
| limit | Maximum number of records returned by the request<br/> | Optional | 
| service | Filter entities using services with the specified SaaS ID. | Optional | 
| instance | Filter entities using services with the specified Appstances. | Optional | 
| type | Filter entities by their type. | Optional | 
| username | Filter entities with specific entities pks. If a user is selected, will also return all of its accounts. | Optional | 
| group_id | Filter entities by their associated group IDs. | Optional | 
| is_admin | Filter entities that are admins. | Optional | 
| is_external | The entity's affiliation. | Optional | 
| status | Filter entities by status. | Optional | 
| customer_filters | Filter that the customer builds himself. (If the customer use "customer_filters" other filters will not work) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.UsersAccounts.displayName | String | UsersAccounts displayName | 
| MicrosoftCloudAppSecurity.UsersAccounts.id | String | UsersAccounts cloud service id | 
| MicrosoftCloudAppSecurity.UsersAccounts._id | String | UsersAccounts cas ID | 
| MicrosoftCloudAppSecurity.UsersAccounts.isAdmin | Number | UsersAccounts isAdmin | 
| MicrosoftCloudAppSecurity.UsersAccounts.isExternal | Number | UsersAccounts isExternal | 
| MicrosoftCloudAppSecurity.UsersAccounts.email | String | UsersAccounts email | 
| MicrosoftCloudAppSecurity.UsersAccounts.role | String | UsersAccounts role | 
| MicrosoftCloudAppSecurity.UsersAccounts.organization | Unknown | UsersAccounts organization | 
| MicrosoftCloudAppSecurity.UsersAccounts.lastSeen | Unknown | UsersAccounts lastSeen | 
| MicrosoftCloudAppSecurity.UsersAccounts.domain | String | UsersAccounts domain | 
| MicrosoftCloudAppSecurity.UsersAccounts.threatScore | Unknown | UsersAccounts threatScore | 
| MicrosoftCloudAppSecurity.UsersAccounts.idType | Number | UsersAccounts idType | 
| MicrosoftCloudAppSecurity.UsersAccounts.isFake | Number | UsersAccounts isFake | 
| MicrosoftCloudAppSecurity.UsersAccounts.username | String | UsersAccounts username | 
| MicrosoftCloudAppSecurity.UsersAccounts.actions.task_name | String | UsersAccounts actions task\_name | 
| MicrosoftCloudAppSecurity.UsersAccounts.actions.type | String | UsersAccounts actions type | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts._id | String | UsersAccounts accounts \_id | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.inst | Number | UsersAccounts accounts inst | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.saas | Number | UsersAccounts accounts saas | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.dn | String | UsersAccounts accounts dn | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.aliases | String | UsersAccounts accounts aliases | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.isFake | Number | UsersAccounts accounts isFake | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.em | Unknown | UsersAccounts accounts email | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.actions.task_name | String | UsersAccounts accounts actions task\_name | 
| MicrosoftCloudAppSecurity.UsersAccounts.accounts.actions.type | String | UsersAccounts accounts actions type | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups._id | String | UsersAccounts userGroups \_id | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.id | String | UsersAccounts userGroups id | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.name | String | UsersAccounts userGroups name | 
| MicrosoftCloudAppSecurity.UsersAccounts.userGroups.usersCount | Number | UsersAccounts userGroups usersCount | 


#### Command Example
``` ```

#### Human Readable Output


