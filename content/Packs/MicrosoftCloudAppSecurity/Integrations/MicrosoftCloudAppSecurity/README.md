This is the MicrosoftCloudAppSecurity integration.
This integration was integrated and tested with version 178 of MicrosoftCloudAppSecurity

For more details about how to generate a new token, see [Microsoft Cloud App Security - Managing API tokens](https://docs.microsoft.com/en-us/cloud-app-security/api-authentication).

For more information about which permissions are required for the token owner in Microsoft Cloud App Security, see [Microsoft Cloud App Security - Manage admin access](https://docs.microsoft.com/en-us/cloud-app-security/manage-admins).

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
| alert_id | Multiple alerts matching the specified filters.<br/>Alert_id should be like this template - "55af7415f8a0a7a29eef2e1f". | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. Example for Custom Filter: {"entity .policy":{"eq":"Impossible travel"}}. For more information about filter syntax, please see [Microsoft Docs](https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters). | Optional | 
| comment | Comment about why the alerts are dismissed. | Optional | 


#### Context Output
Because the API does not return a value relevant to this command, this command has no outputs.


#### Command Example
```!microsoft-cas-alert-dismiss-bulk```

#### Context Example
```
{}
```

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
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. Example for Custom Filter: {"entity .policy":{"eq":"Impossible travel"}}. For more information about filter syntax, please see [Microsoft Docs](https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters). | Optional | 
| alert_id | alert id | Optional | 
| username | Username. (Usually its an email address) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.Alerts._id | String | Alert id | 
| MicrosoftCloudAppSecurity.Alerts.timestamp | Date | Alert date | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.id | Number | Alerts policyRule id | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.label | String | Alerts policyRule label | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.type | String | Alerts policyRule type | 
| MicrosoftCloudAppSecurity.Alerts.policyRule.policyType | String | Alerts policyRule policyType | 
| MicrosoftCloudAppSecurity.Alerts.service.id | Number | Alerts service id | 
| MicrosoftCloudAppSecurity.Alerts.service.label | Number | Alerts service label | 
| MicrosoftCloudAppSecurity.Alerts.service.type | Number | Alerts service type | 
| MicrosoftCloudAppSecurity.Alerts.file.id | Number | Alerts file id | 
| MicrosoftCloudAppSecurity.Alerts.file.label | Number | Alerts file label | 
| MicrosoftCloudAppSecurity.Alerts.file.type | Number | Alerts file type | 
| MicrosoftCloudAppSecurity.Alerts.user.id | Number | Alerts user id | 
| MicrosoftCloudAppSecurity.Alerts.user.label | Number | Alerts user label | 
| MicrosoftCloudAppSecurity.Alerts.user.type | Number | Alerts user type | 
| MicrosoftCloudAppSecurity.Alerts.country.id | Number | Alerts country id | 
| MicrosoftCloudAppSecurity.Alerts.country.label | Number | Alerts country label | 
| MicrosoftCloudAppSecurity.Alerts.country.type | Number | Alerts country type | 
| MicrosoftCloudAppSecurity.Alerts.ip.id | Number | Alerts ip id | 
| MicrosoftCloudAppSecurity.Alerts.ip.label | Number | Alerts ip label | 
| MicrosoftCloudAppSecurity.Alerts.ip.type | Number | Alerts ip type | 
| MicrosoftCloudAppSecurity.Alerts.ip.triggeredAlert | Number | Alerts ip triggeredAlert | 
| MicrosoftCloudAppSecurity.Alerts.account.id | Number | Alerts account id | 
| MicrosoftCloudAppSecurity.Alerts.account.label | Number | Alerts account label | 
| MicrosoftCloudAppSecurity.Alerts.account.type | Number | Alerts account type | 
| MicrosoftCloudAppSecurity.Alerts.account.inst | Number | Alerts account inst | 
| MicrosoftCloudAppSecurity.Alerts.account.saas | Number | Alerts account saas | 
| MicrosoftCloudAppSecurity.Alerts.account.pa | Number | Alerts account pa | 
| MicrosoftCloudAppSecurity.Alerts.account.entityType | Number | Alerts account entityType | 
| MicrosoftCloudAppSecurity.Alerts.title | String | Alert title | 
| MicrosoftCloudAppSecurity.Alerts.description | String | Alert description | 
| MicrosoftCloudAppSecurity.Alerts.policy.id | String | Alert policy id | 
| MicrosoftCloudAppSecurity.Alerts.policy.label | String | Alert policy label | 
| MicrosoftCloudAppSecurity.Alerts.policy.policyType | String | Alert policy policyType | 
| MicrosoftCloudAppSecurity.Alerts.threatScore | Number | Alert threatScore | 
| MicrosoftCloudAppSecurity.Alerts.isSystemAlert | Number | Alert isSystemAlert | 
| MicrosoftCloudAppSecurity.Alerts.statusValue | Number | Alert statusValue | 
| MicrosoftCloudAppSecurity.Alerts.severityValue | Number | Alert severityValue | 
| MicrosoftCloudAppSecurity.Alerts.handledByUser | Unknown | Alert handledByUser | 
| MicrosoftCloudAppSecurity.Alerts.comment | Unknown | Alert comment | 
| MicrosoftCloudAppSecurity.Alerts.resolveTime | Date | Alert resolveTime | 


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
| alert_id | Multiple alerts matching the specified filters.<br/>Alert_id should be like this template - "55af7415f8a0a7a29eef2e1f". | Optional | 
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. Example for Custom Filter: {"entity .policy":{"eq":"Impossible travel"}}. For more information about filter syntax, please see [Microsoft Docs](https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters). | Optional | 
| comment | Comment about why the alerts are dismissed. | Optional | 


#### Context Output

Because the api does not return a value relevant to this command, this command has no outputs.


#### Command Example
```!microsoft-cas-alert-resolve-bulk```

#### Context Example
```
{}
```

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
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. Example for Custom Filter: {"entity .policy":{"eq":"Impossible travel"}}. For more information about filter syntax, please see [Microsoft Docs](https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters). | Optional | 
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
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. Example for Custom Filter: {"entity .policy":{"eq":"Impossible travel"}}. For more information about filter syntax, please see [Microsoft Docs](https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters). | Optional | 
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
```!microsoft-cas-files-list```

#### Context Example
```

```

#### Human Readable Output

>### Results
>|owner_name|file_create_date|file_type|file_name|file_access_level|file_status|app_name|
>|---|---|---|---|---|---|---|
>| John Smith | 1595199073000 | 4,<br/>TEXT | 20200325_101206.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1595199072000 | 4,<br/>TEXT | 20200325_100518.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1595199073000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-ca070a36092e.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1595199072000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-b3b46a6d77f9.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| SharePoint App | 1594890271000 |  | playbook_folder | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft SharePoint Online |
>| SharePoint App | 1594890070000 | 4,<br/>TEXT | test.txt | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft SharePoint Online |
>| John Smith | 1594721784000 | 4,<br/>TEXT | 20200325_101206.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594721784000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-9af56fe0585b.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594721767000 | 4,<br/>TEXT | IMG-20200619-WA0000.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594721767000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-fc3b0a3a02e8.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326579000 | 4,<br/>TEXT | 20200325_104025.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326579000 | 4,<br/>TEXT | 20200325_101544.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326579000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-57ccdca766aa.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326572000 | 4,<br/>TEXT | DSC_6375.JPG.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326579000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-838665d33aa8.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326572000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-1b3e5cb3f878.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326560000 | 4,<br/>TEXT | 20200325_100530.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326570000 | 4,<br/>TEXT | 20200325_101206.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326560000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-a670c7317bfc.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326573000 | 4,<br/>TEXT | 20200325_101451.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326570000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-828906a2e0b4.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326573000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-24215449ab36.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326559000 | 4,<br/>TEXT | 20200325_100518.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326559000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-7a1ac1f1f3e5.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326548000 | 4,<br/>TEXT | photo_2020-07-05 18.33.29.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326551000 | 4,<br/>TEXT | photo_2020-07-05 18.33.46.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326545000 | 4,<br/>TEXT | photo_2020-07-05 18.06.47.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326548000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-1880feaf90ff.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326548000 | 4,<br/>TEXT | photo_2020-07-05 18.33.38.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326546000 | 4,<br/>TEXT | photo_2020-07-05 18.06.51.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326551000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-c9f5d143283c.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326545000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-2d65a84f383b.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326548000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-430368e8fecf.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326546000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-8b98d4c03aa3.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326542000 | 4,<br/>TEXT | photo_2020-07-05 18.06.33.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326543000 | 4,<br/>TEXT | photo_2020-07-05 18.06.40.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326540000 | 4,<br/>TEXT | IMG-20200619-WA0000.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| John Smith | 1594326540000 | 4,<br/>TEXT | photo_2020-07-05 18.06.26.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326543000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-25cc5b5e5f84.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326542000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-66f5a48e7973.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326540000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-30bee381e8ff.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326540000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-bfe508b9a649.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325614000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-4eaa7c4186c6.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325614000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-bbdf2c002a6a.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325610000 | 5,<br/>IMAGE | 12345678-cafe-dead-beef-588fc13d54d8.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |

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
| custom_filter | A custom filter by which to filter the returned files. If you pass the custom_filter argument it will override the other filters from the integration instance configuration. Example for Custom Filter: {"entity .policy":{"eq":"Impossible travel"}}. For more information about filter syntax, please see [Microsoft Docs](https://docs.microsoft.com/en-us/cloud-app-security/api-activities#filters). | Optional | 


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
```!microsoft-cas-users-accounts-list```

#### Context Example
```

```

#### Human Readable Output

>### Results
>|display_name|last_seen|is_admin|is_external|email|username|
>|---|---|---|---|---|---|
>| Cloud App Security Service Account for SharePoint | 2020-07-28T09:18:39.301Z | false | false | tmcassp_fa02d7a6fe55edb22020060112572594@example.com | {"id": "12345678-cafe-dead-beef-aeac04433eb7", "saas": 11161, "inst": 0} |
>| MS Graph User DEV | 2020-07-28T05:34:24Z | false | true |  | {"id": "12345678-cafe-dead-beef-c19d60613e54", "saas": 11161, "inst": 0} |
>| MS Graph Groups | 2020-07-28T01:43:12Z | false | true |  | {"id": "12345678-cafe-dead-beef-40a33d90dc90", "saas": 11161, "inst": 0} |
>| MS Graph Groups DEV | 2020-07-28T01:42:36Z | false | true |  | {"id": "12345678-cafe-dead-beef-d94e912023e1", "saas": 11161, "inst": 0} |
>| Microsoft Approval Management | 2020-07-28T01:42:07Z | false | false |  | {"id": "12345678-cafe-dead-beef-0add61688c74", "saas": 11161, "inst": 0} |
>| MS Graph User | 2020-07-28T01:42:07Z | false | true |  | {"id": "12345678-cafe-dead-beef-da7d658844d0", "saas": 11161, "inst": 0} |
>| John Smith | 2020-07-27T13:05:21.508Z | true | false | john@example.com | {"id": "12345678-cafe-dead-beef-8089fe9991e2", "saas": 11161, "inst": 0} |
>| Cloud App Security | 2020-07-27T10:36:02.246Z | false | false |  | {"id": "Cloud App Security", "saas": 11161, "inst": 0} |
>| John Smith | 2020-07-24T17:52:33.096Z | true | false | john@example.com | {"id": "12345678-cafe-dead-beef-d84915c6912f", "saas": 11161, "inst": 0} |
>| AAD App Management | 2020-07-24T16:31:08Z | false | false |  | {"id": "12345678-cafe-dead-beef-679e38eea492", "saas": 11161, "inst": 0} |
>| Microsoft Exchange Online Protection | 2020-07-23T09:01:52Z | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Device Registration Service | 2020-07-19T22:59:52Z | false | false |  | {"id": "12345678-cafe-dead-beef-d28bd4d359a9", "saas": 11161, "inst": 0} |
>| Microsoft Intune | 2020-07-15T14:46:07Z | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Trend Micro Cloud App Security | 2020-07-15T08:42:20Z | false | true |  | {"id": "12345678-cafe-dead-beef-687b755fb160", "saas": 11161, "inst": 0} |
>| Windows Azure Service Management API | 2020-07-10T14:33:09Z | false | false |  | {"id": "12345678-cafe-dead-beef-dac1f8f63013", "saas": 11161, "inst": 0} |
>| Azure Resource Graph | 2020-07-05T23:50:54.723Z | false | false |  | {"id": "12345678-cafe-dead-beef-e9d4a1996ca4", "saas": 11161, "inst": 0} |
>| demisto dev | 2020-07-05T13:19:55Z | true | false | demistodev@example.com | {"id": "12345678-cafe-dead-beef-25984e968637", "saas": 11161, "inst": 0} |
>| Media Analysis and Transformation Service | 2020-07-05T09:12:37Z | false | false |  | {"id": "12345678-cafe-dead-beef-804ed95e767e", "saas": 11161, "inst": 0} |
>| Office 365 SharePoint Online | 2020-07-05T09:12:30Z | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| MS Graph Files | 2020-06-30T09:11:49Z | false | true |  | {"id": "12345678-cafe-dead-beef-97d384764d79", "saas": 11161, "inst": 0} |
>| MS Graph Files Dev | 2020-06-30T09:09:56Z | false | true |  | {"id": "12345678-cafe-dead-beef-8ce97e9cc435", "saas": 11161, "inst": 0} |
>| SecurityCenter | 2020-05-17T08:30:13.957Z | false | true |  | {"id": "12345678-cafe-dead-beef-386428b3811c", "saas": 11161, "inst": 0} |
>| Managed Disks Resource Provider | 2020-05-05T07:56:05.291Z | false | false |  | {"id": "12345678-cafe-dead-beef-23c25a2169af", "saas": 11161, "inst": 0} |
>| Microsoft Azure Policy Insights | 2020-03-17T01:48:21.101Z | false | false |  | {"id": "12345678-cafe-dead-beef-dd72f50a3ec0", "saas": 11161, "inst": 0} |
>| Azure Security Center | 2020-03-17T00:36:01.976Z | false | true |  | {"id": "12345678-cafe-dead-beef-744e3d8d2152", "saas": 11161, "inst": 0} |
>| Azure Compute | 2020-03-17T00:34:32.951Z | false | true |  | {"id": "12345678-cafe-dead-beef-8d14b008aa78", "saas": 11161, "inst": 0} |
>| AzureCompute | 2020-03-17T00:33:19.047Z | false | true |  | {"id": "12345678-cafe-dead-beef-fcff173735a5", "saas": 11161, "inst": 0} |
>| Microsoft.Azure.GraphExplorer |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Cactus |  | true | false | itay@example.com | {"id": "12345678-cafe-dead-beef-8352e0e9df65", "saas": 11161, "inst": 0} |
>| Azure Classic Portal |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Microsoft App Access Panel |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| svc |  | true | false | svc@example.com | {"id": "12345678-cafe-dead-beef-836e8a8e30c9", "saas": 11161, "inst": 0} |
>| Yammer |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Power BI Service |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Microsoft Office Web Apps Service |  | false | false |  | {"id": "12345678-cafe-dead-beef-0de1c7f97287", "saas": 11161, "inst": 0} |
>| Skype for Business Online |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Office 365 Exchange Online |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |
>| Microsoft.ExtensibleRealUserMonitoring |  | false | false |  | {"id": "12345678-cafe-dead-beef-ad15a8179ba0", "saas": 11161, "inst": 0} |
>| Microsoft Office 365 Portal |  | false | false |  | {"id": "12345678-cafe-dead-beef-000000000000", "saas": 11161, "inst": 0} |

