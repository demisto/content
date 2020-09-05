This is the MicrosoftCloudAppSecurity integration.
This integration was integrated and tested with version 178 of MicrosoftCloudAppSecurity
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
| customer_filters | Filter that the customer builds himself. | Optional | 
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
| customer_filters | Filter that the customer builds himself. (If the customer use "customer_filters" other filters will not work) | Optional | 
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
| customer_filters | Filter that the customer builds himself. | Optional | 
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
```!microsoft-cas-files-list```

#### Context Example
```

```

#### Human Readable Output

>### Results
>|owner_name|file_create_date|file_type|file_name|file_access_level|file_status|app_name|
>|---|---|---|---|---|---|---|
>| Avishai Brandeis | 1595199073000 | 4,<br/>TEXT | 20200325_101206.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1595199072000 | 4,<br/>TEXT | 20200325_100518.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1595199073000 | 5,<br/>IMAGE | f9c89b9b-18d2-4a2f-8cba-ca070a36092e.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1595199072000 | 5,<br/>IMAGE | d82388df-f3ec-4288-bf4f-b3b46a6d77f9.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| SharePoint App | 1594890271000 |  | playbook_folder | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft SharePoint Online |
>| SharePoint App | 1594890070000 | 4,<br/>TEXT | test.txt | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft SharePoint Online |
>| Avishai Brandeis | 1594721784000 | 4,<br/>TEXT | 20200325_101206.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594721784000 | 5,<br/>IMAGE | 9a45eafa-b471-43c0-9dc8-9af56fe0585b.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594721767000 | 4,<br/>TEXT | IMG-20200619-WA0000.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594721767000 | 5,<br/>IMAGE | 14ac91a6-a2ca-450e-978f-fc3b0a3a02e8.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326579000 | 4,<br/>TEXT | 20200325_104025.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326579000 | 4,<br/>TEXT | 20200325_101544.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326579000 | 5,<br/>IMAGE | 56aa5551-0c4c-42d7-93f1-57ccdca766aa.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326572000 | 4,<br/>TEXT | DSC_6375.JPG.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326579000 | 5,<br/>IMAGE | 2cf7cb13-9385-4d90-8eff-838665d33aa8.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326572000 | 5,<br/>IMAGE | 3ebd512c-4868-4bc3-9325-1b3e5cb3f878.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326560000 | 4,<br/>TEXT | 20200325_100530.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326570000 | 4,<br/>TEXT | 20200325_101206.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326560000 | 5,<br/>IMAGE | cfe6b7e5-bf03-4da9-87c6-a670c7317bfc.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326573000 | 4,<br/>TEXT | 20200325_101451.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326570000 | 5,<br/>IMAGE | c4350358-99bf-4b25-9e78-828906a2e0b4.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326573000 | 5,<br/>IMAGE | 4da54ac0-0b3d-4eb4-a1ab-24215449ab36.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326559000 | 4,<br/>TEXT | 20200325_100518.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326559000 | 5,<br/>IMAGE | e063ef77-e7de-4187-8448-7a1ac1f1f3e5.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326548000 | 4,<br/>TEXT | photo_2020-07-05 18.33.29.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326551000 | 4,<br/>TEXT | photo_2020-07-05 18.33.46.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326545000 | 4,<br/>TEXT | photo_2020-07-05 18.06.47.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326548000 | 5,<br/>IMAGE | 5bc3308d-a583-43a6-821c-1880feaf90ff.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326548000 | 4,<br/>TEXT | photo_2020-07-05 18.33.38.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326546000 | 4,<br/>TEXT | photo_2020-07-05 18.06.51.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326551000 | 5,<br/>IMAGE | 01f30b27-0a9d-41e0-aa57-c9f5d143283c.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326545000 | 5,<br/>IMAGE | 6814e9f2-0851-4585-a7d5-2d65a84f383b.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326548000 | 5,<br/>IMAGE | 92a62911-7c1b-47ae-8942-430368e8fecf.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326546000 | 5,<br/>IMAGE | f0e38201-a3d0-4e58-b6c5-8b98d4c03aa3.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326542000 | 4,<br/>TEXT | photo_2020-07-05 18.06.33.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326543000 | 4,<br/>TEXT | photo_2020-07-05 18.06.40.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326540000 | 4,<br/>TEXT | IMG-20200619-WA0000.jpg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>| Avishai Brandeis | 1594326540000 | 4,<br/>TEXT | photo_2020-07-05 18.06.26.jpeg.txt | 0,<br/>PRIVATE | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326543000 | 5,<br/>IMAGE | 9b10eb41-0fa1-4982-aded-25cc5b5e5f84.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326542000 | 5,<br/>IMAGE | dfbea149-a811-4e73-86cd-66f5a48e7973.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326540000 | 5,<br/>IMAGE | 9aa6317b-2c50-4e8b-8f71-30bee381e8ff.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594326540000 | 5,<br/>IMAGE | ac015a88-aef1-4969-a0cc-bfe508b9a649.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325614000 | 5,<br/>IMAGE | cca52237-74d9-4aff-b92e-4eaa7c4186c6.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325614000 | 5,<br/>IMAGE | c82fe4f0-f550-4941-87b5-bbdf2c002a6a.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325610000 | 5,<br/>IMAGE | 5dd21d9c-ba3c-45a1-8bc1-588fc13d54d8.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325608000 | 5,<br/>IMAGE | bc36b8a1-d2f1-4bd7-8dd3-e010460db08b.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325603000 | 5,<br/>IMAGE | 639977fd-f19b-46f0-b8da-30bdce7cdbb4.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325600000 | 5,<br/>IMAGE | 14012d04-f9d9-40f3-b4e7-07ee35b9cae6.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325600000 | 5,<br/>IMAGE | 3356552a-4bd0-4953-9f59-6bdaa087b448.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325591000 | 5,<br/>IMAGE | dba0af17-2a8c-4a60-9fd5-9acaf93b2f08.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325592000 | 5,<br/>IMAGE | 7941ed8e-1e51-46d5-8561-09ce27b3b975.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325582000 | 5,<br/>IMAGE | 047e77e2-e0e5-4989-8a0c-ff9054fd5175.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325582000 | 5,<br/>IMAGE | 2e5812b4-8000-48b8-b384-142f984d5ec2.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325587000 | 5,<br/>IMAGE | 6327024b-1edf-4463-802c-2b78b4f9fdad.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325578000 | 5,<br/>IMAGE | 542895d5-7c84-4310-9f5e-a15dae89d7fc.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325558000 | 5,<br/>IMAGE | 2d2ef892-4166-4661-bb3b-92ee409c21c8.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325535000 | 5,<br/>IMAGE | 30e9aa83-e872-4ddb-b2f7-c0e73a71867d.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325535000 | 5,<br/>IMAGE | ec02ac37-c455-4d04-b8aa-c6da3136686d.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325533000 | 5,<br/>IMAGE | aff07901-2e64-4e57-bab6-ed4930fd2974.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325532000 | 5,<br/>IMAGE | 5139071d-4832-41d5-a21c-458327f935ef.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325530000 | 5,<br/>IMAGE | 906d178e-adf5-4b3f-bd2d-469b048e20f0.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325530000 | 5,<br/>IMAGE | fe45c984-451e-497e-a6c7-c0a90887820a.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325527000 | 5,<br/>IMAGE | df8ad58d-a418-431f-87f5-d059ea238d27.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325527000 | 5,<br/>IMAGE | d1bfee21-ef58-40e9-b0e2-ed1ccb2b48c7.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325525000 | 5,<br/>IMAGE | c7c42269-657a-49e4-9829-7afd2bef0301.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325524000 | 5,<br/>IMAGE | 9c69944a-ff97-4331-834b-df30a6571865.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325521000 | 5,<br/>IMAGE | dea354b5-93e7-4903-a969-d77f75512d77.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594325523000 | 5,<br/>IMAGE | d120d7aa-f931-4dfa-8cb0-f439ed5bf845.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295507000 | 5,<br/>IMAGE | 56c858dc-3798-454d-b71d-7670dc33a519.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295507000 | 5,<br/>IMAGE | ee6eb54f-eee3-4f3f-9824-cd8949d7e3c3.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295500000 | 5,<br/>IMAGE | 279c29cb-8c9b-4da3-acbb-0dcb222080f9.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295479000 | 5,<br/>IMAGE | a87afd92-66ed-45dd-b048-442a54f769a6.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295461000 | 5,<br/>IMAGE | 9da79bd0-8523-4cb4-b7d1-9499367542ff.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295461000 | 5,<br/>IMAGE | df88a2d1-9da8-4fef-a326-a554af6303b9.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295458000 | 5,<br/>IMAGE | 78e7bddd-225b-453f-b68d-622a3d50645a.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295456000 | 5,<br/>IMAGE | 4ce510f0-c0a7-4c65-b195-387bc3dcb80e.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295458000 | 5,<br/>IMAGE | 8ed05b63-7ecc-4e3f-a0cd-3d536ae1c249.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295453000 | 5,<br/>IMAGE | cf224158-46bc-4143-adf3-0c8d35b5350e.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295455000 | 5,<br/>IMAGE | af5e2534-d35e-4df7-a1ed-3b45e11683d3.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295452000 | 5,<br/>IMAGE | 0a355451-e289-4722-86af-2c648e7cc283.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295450000 | 5,<br/>IMAGE | 0470b912-a2eb-44b9-9dec-953ab4e05c6f.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295448000 | 5,<br/>IMAGE | fe4cdb75-30b7-4d10-ab51-e81f8e6d79a5.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295450000 | 5,<br/>IMAGE | 1f84df98-64ec-4278-bd27-8bf8345d0cdf.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594295448000 | 5,<br/>IMAGE | a3cbb7a7-72e6-453e-901c-cb549e276a59.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294827000 | 5,<br/>IMAGE | f2edccd6-2be2-439c-a2f9-a0f390e9b80e.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294573000 | 5,<br/>IMAGE | 601a5a3e-0cf1-4541-836c-743dd3fabc91.JPG | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294560000 | 5,<br/>IMAGE | f5e5c5cc-4f05-4ccb-9be4-d86f4d3a26b6.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294562000 | 5,<br/>IMAGE | 7b538b05-0c5c-4ba3-98a0-3d07d563a975.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294557000 | 5,<br/>IMAGE | d8af96a9-18f3-4320-bc5b-71ebdea835fe.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294557000 | 5,<br/>IMAGE | d6634cd3-0baf-4ebd-8f6e-de66927b1b2c.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294555000 | 5,<br/>IMAGE | 967a6e5c-a012-4928-a909-32687f426a09.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294560000 | 5,<br/>IMAGE | 5ccab71a-7a08-48ac-ba95-bb6f11a63a04.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294552000 | 5,<br/>IMAGE | 83c1745c-abf4-4e48-bdd9-24376ac50027.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294554000 | 5,<br/>IMAGE | b5261c49-0725-427f-b956-cd875fa236d8.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294551000 | 5,<br/>IMAGE | 55cfdba5-d823-47e6-b37e-a3cb0ae9035b.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294536000 | 5,<br/>IMAGE | dd33b82b-20da-4d56-bf3f-c474278a3829.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594294537000 | 5,<br/>IMAGE | e71a8958-97fe-4d7e-8259-ad92984a38d9.jpeg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594293974000 | 5,<br/>IMAGE | c588bf6f-f87a-401c-9ebc-5cc03b03d1d5.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594293976000 | 5,<br/>IMAGE | d95a09e8-4873-4aec-9e5d-9b9b3d85b6c6.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |
>|  | 1594293035000 | 5,<br/>IMAGE | 7036c013-cab0-4aee-b5e2-3f125ba40034.jpg | 1,<br/>INTERNAL | 0,<br/>EXISTS | Microsoft OneDrive for Business |


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
```!microsoft-cas-users-accounts-list```

#### Context Example
```

```

#### Human Readable Output

>### Results
>|display_name|last_seen|is_admin|is_external|email|username|
>|---|---|---|---|---|---|
>| Cloud App Security Service Account for SharePoint | 2020-07-28T09:18:39.301Z | false | false | tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com | {"id": "9aa388ae-d7ad-4f38-af49-aeac04433eb7", "saas": 11161, "inst": 0} |
>| MS Graph User DEV | 2020-07-28T05:34:24Z | false | true |  | {"id": "954d66fa-f865-493c-b1cb-c19d60613e54", "saas": 11161, "inst": 0} |
>| MS Graph Groups | 2020-07-28T01:43:12Z | false | true |  | {"id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90", "saas": 11161, "inst": 0} |
>| MS Graph Groups DEV | 2020-07-28T01:42:36Z | false | true |  | {"id": "9de2d7c5-45a6-4b98-b283-d94e912023e1", "saas": 11161, "inst": 0} |
>| Microsoft Approval Management | 2020-07-28T01:42:07Z | false | false |  | {"id": "65d91a3d-ab74-42e6-8a2f-0add61688c74", "saas": 11161, "inst": 0} |
>| MS Graph User | 2020-07-28T01:42:07Z | false | true |  | {"id": "d7508c5c-988b-485e-93c3-da7d658844d0", "saas": 11161, "inst": 0} |
>| Avishai Brandeis | 2020-07-27T13:05:21.508Z | true | false | avishai@demistodev.onmicrosoft.com | {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0} |
>| Cloud App Security | 2020-07-27T10:36:02.246Z | false | false |  | {"id": "Cloud App Security", "saas": 11161, "inst": 0} |
>| Lance Pettay | 2020-07-24T17:52:33.096Z | true | false | lpettay@demistodev.onmicrosoft.com | {"id": "3987137d-eb30-4cc9-baef-d84915c6912f", "saas": 11161, "inst": 0} |
>| AAD App Management | 2020-07-24T16:31:08Z | false | false |  | {"id": "f0ae4899-d877-4d3c-ae25-679e38eea492", "saas": 11161, "inst": 0} |
>| Microsoft Exchange Online Protection | 2020-07-23T09:01:52Z | false | false |  | {"id": "00000007-0000-0ff1-ce00-000000000000", "saas": 11161, "inst": 0} |
>| Device Registration Service | 2020-07-19T22:59:52Z | false | false |  | {"id": "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9", "saas": 11161, "inst": 0} |
>| Microsoft Intune | 2020-07-15T14:46:07Z | false | false |  | {"id": "0000000a-0000-0000-c000-000000000000", "saas": 11161, "inst": 0} |
>| Trend Micro Cloud App Security | 2020-07-15T08:42:20Z | false | true |  | {"id": "32eb7c81-01f8-4f56-b847-687b755fb160", "saas": 11161, "inst": 0} |
>| Windows Azure Service Management API | 2020-07-10T14:33:09Z | false | false |  | {"id": "797f4846-ba00-4fd7-ba43-dac1f8f63013", "saas": 11161, "inst": 0} |
>| Eran Korish | 2020-07-06T08:06:17.116Z | false | false | eran@demistodev.onmicrosoft.com | {"id": "e2397ddc-d33f-4324-a6d4-5955ae199903", "saas": 11161, "inst": 0} |
>| Azure Resource Graph | 2020-07-05T23:50:54.723Z | false | false |  | {"id": "509e4652-da8d-478d-a730-e9d4a1996ca4", "saas": 11161, "inst": 0} |
>| demisto dev | 2020-07-05T13:19:55Z | true | false | dev@demistodev.onmicrosoft.com | {"id": "2827c1e7-edb6-4529-b50d-25984e968637", "saas": 11161, "inst": 0} |
>| Media Analysis and Transformation Service | 2020-07-05T09:12:37Z | false | false |  | {"id": "944f0bd1-117b-4b1c-af26-804ed95e767e", "saas": 11161, "inst": 0} |
>| Office 365 SharePoint Online | 2020-07-05T09:12:30Z | false | false |  | {"id": "00000003-0000-0ff1-ce00-000000000000", "saas": 11161, "inst": 0} |
>| MS Graph Files | 2020-06-30T09:11:49Z | false | true |  | {"id": "6b495fcf-df22-4544-99a3-97d384764d79", "saas": 11161, "inst": 0} |
>| MS Graph Files Dev | 2020-06-30T09:09:56Z | false | true |  | {"id": "2c160fab-7040-4f08-bec2-8ce97e9cc435", "saas": 11161, "inst": 0} |
>| lior kolnik | 2020-06-30T08:13:48Z | false | false | liork@demistodev.onmicrosoft.com | {"id": "023096d0-595e-47b5-80dd-ea5886ab9294", "saas": 11161, "inst": 0} |
>| sr test02 | 2020-06-30T00:13:44Z | false | false | sr-test02@demistodev.onmicrosoft.com | {"id": "9702a3de-f219-425b-b0ef-9c343b786030", "saas": 11161, "inst": 0} |
>| SecurityCenter | 2020-05-17T08:30:13.957Z | false | true |  | {"id": "8ccae514-af28-4b44-9f19-386428b3811c", "saas": 11161, "inst": 0} |
>| Managed Disks Resource Provider | 2020-05-05T07:56:05.291Z | false | false |  | {"id": "60e6cd67-9c8c-4951-9b3c-23c25a2169af", "saas": 11161, "inst": 0} |
>| Microsoft Azure Policy Insights | 2020-03-17T01:48:21.101Z | false | false |  | {"id": "1d78a85d-813d-46f0-b496-dd72f50a3ec0", "saas": 11161, "inst": 0} |
>| Azure Security Center | 2020-03-17T00:36:01.976Z | false | true |  | {"id": "61f36b84-ce6b-4ca8-9d55-744e3d8d2152", "saas": 11161, "inst": 0} |
>| Azure Compute | 2020-03-17T00:34:32.951Z | false | true |  | {"id": "e16945f4-e521-4da9-87f5-8d14b008aa78", "saas": 11161, "inst": 0} |
>| AzureCompute | 2020-03-17T00:33:19.047Z | false | true |  | {"id": "9ead7552-8ee2-47e1-b435-fcff173735a5", "saas": 11161, "inst": 0} |
>| Logs Analysis test |  | true | false | logs@demistodev.onmicrosoft.com | {"id": "5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de", "saas": 11161, "inst": 0} |
>| Microsoft.Azure.GraphExplorer |  | false | false |  | {"id": "0000000f-0000-0000-c000-000000000000", "saas": 11161, "inst": 0} |
>| Itay Keren |  | true | false | itay@demistodev.onmicrosoft.com | {"id": "8918c390-35b8-42c3-83f1-8352e0e9df65", "saas": 11161, "inst": 0} |
>| Azure Classic Portal |  | false | false |  | {"id": "00000013-0000-0000-c000-000000000000", "saas": 11161, "inst": 0} |
>| van Helsing |  | true | false | vanhelsing@demistodev.onmicrosoft.com | {"id": "21395465-a687-4d0f-9ea6-b0bd39531c47", "saas": 11161, "inst": 0} |
>| Microsoft App Access Panel |  | false | false |  | {"id": "0000000c-0000-0000-c000-000000000000", "saas": 11161, "inst": 0} |
>| svc |  | true | false | svc@demistodev.onmicrosoft.com | {"id": "e8a03722-99a2-4b26-bde4-836e8a8e30c9", "saas": 11161, "inst": 0} |
>| Yammer |  | false | false |  | {"id": "00000005-0000-0ff1-ce00-000000000000", "saas": 11161, "inst": 0} |
>| ServiceAccount1 |  | true | false | serviceaccount1@demistodev.onmicrosoft.com | {"id": "70585180-517a-43ea-9403-2d80b97ab19d", "saas": 11161, "inst": 0} |
>| Power BI Service |  | false | false |  | {"id": "00000009-0000-0000-c000-000000000000", "saas": 11161, "inst": 0} |
>| itayadmin |  | true | false | itayadmin@demistodev.onmicrosoft.com | {"id": "5d8d8aad-14ab-4683-aa57-fa37642599a4", "saas": 11161, "inst": 0} |
>| Microsoft Office Web Apps Service |  | false | false |  | {"id": "67e3df25-268a-4324-a550-0de1c7f97287", "saas": 11161, "inst": 0} |
>| Jochman |  | true | false | jochman@demistodev.onmicrosoft.com | {"id": "fc3aea12-f19f-461e-b62b-25ee818deb6d", "saas": 11161, "inst": 0} |
>| Skype for Business Online |  | false | false |  | {"id": "00000004-0000-0ff1-ce00-000000000000", "saas": 11161, "inst": 0} |
>| Tsach zimmer |  | false | false | tsach@demistodev.onmicrosoft.com | {"id": "259d2a3c-167b-411c-b2ee-88646ce6e054", "saas": 11161, "inst": 0} |
>| Office 365 Exchange Online |  | false | false |  | {"id": "00000002-0000-0ff1-ce00-000000000000", "saas": 11161, "inst": 0} |
>| Guy Lichtman |  | false | false | lichtman@demistodev.onmicrosoft.com | {"id": "3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4", "saas": 11161, "inst": 0} |
>| Microsoft.ExtensibleRealUserMonitoring |  | false | false |  | {"id": "e3583ad2-c781-4224-9b91-ad15a8179ba0", "saas": 11161, "inst": 0} |
>| Bar Katzir |  | false | false | bkatzir@demistodev.onmicrosoft.com | {"id": "7bd0dd8e-7d2f-4ace-af36-19f91a670281", "saas": 11161, "inst": 0} |
>| Microsoft Office 365 Portal |  | false | false |  | {"id": "00000006-0000-0ff1-ce00-000000000000", "saas": 11161, "inst": 0} |

