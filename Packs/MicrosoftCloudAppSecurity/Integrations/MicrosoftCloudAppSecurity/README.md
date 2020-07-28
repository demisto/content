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
| alert_id | Multiple alerts matching the specified filters.<br/>Alert_id should be like this template - "55af7415f8a0a7a29eef2e1f". | Optional | 
| customer_filters | Filter that the customer builds himself. | Optional | 
| comment | Comment about why the alerts are dismissed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.AlertDismiss.dismissed | Number | AlertDismiss dismissed | 


#### Command Example
```!microsoft-cas-alert-dismiss-bulk```

#### Context Example
```
{}
```

#### Human Readable Output

>Error in API call [400] - Bad Request
>{"filters": [{"error": "This field is required", "errorMessageCode": "CONSOLE_FORMS_FIELD_REQUIRED"}], "error": true}

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftCloudAppSecurity.AlertResolve.resolved | Number | AlertResolved resolved | 


#### Command Example
```!microsoft-cas-alert-resolve-bulk```

#### Context Example
```
{}
```

#### Human Readable Output

>Error in API call [400] - Bad Request
>{"filters": [{"error": "This field is required", "errorMessageCode": "CONSOLE_FORMS_FIELD_REQUIRED"}], "error": true}

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
{
    "MicrosoftCloudAppSecurity": {
        "Files": {
            "_id": "5f06fc1ac3b664209df1b864",
            "_tid": 97134000,
            "actions": [
                {
                    "alert_display_title": null,
                    "bulk_display_description": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_BULK_DISPLAY_DESCRIPTION",
                    "bulk_support": true,
                    "confirm_button_style": "red",
                    "confirmation_button_text": null,
                    "confirmation_link": null,
                    "display_alert_success_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                    "display_alert_text": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                    "display_description": {
                        "parameters": {
                            "fileName": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg"
                        },
                        "template": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_DESCRIPTION"
                    },
                    "display_title": "TASKS_ADALIBPY_QUARANTINE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                    "governance_type": null,
                    "has_icon": true,
                    "is_blocking": null,
                    "optional_notify": null,
                    "preview_only": false,
                    "task_name": "QuarantineTask",
                    "type": "file",
                    "uiGovernanceCategory": 1
                },
                {
                    "alert_display_title": null,
                    "bulk_display_description": null,
                    "bulk_support": false,
                    "confirm_button_style": "red",
                    "confirmation_button_text": null,
                    "confirmation_link": null,
                    "display_alert_success_text": null,
                    "display_alert_text": null,
                    "display_description": {
                        "parameters": {
                            "fileName": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
                            "fileType": {
                                "template": "ENUM_FILE_TYPE_FILE"
                            }
                        },
                        "template": "TASKS_ADALIBPY_REMOVE_COLLABORATOR_PERMISSION_FILE_CHANGE_USER_DISPLAY_DESCRIPTION_EXTENDED"
                    },
                    "display_title": "TASKS_ADALIBPY_REMOVE_COLLABORATOR_PERMISSION_FILE_CHANGE_USER_DISPLAY_TITLE",
                    "governance_type": "collaborator",
                    "has_icon": true,
                    "is_blocking": null,
                    "optional_notify": null,
                    "preview_only": false,
                    "task_name": "RemoveCollaboratorPermissionFileTask",
                    "type": "file",
                    "uiGovernanceCategory": 2
                },
                {
                    "alert_display_title": null,
                    "bulk_display_description": "TASKS_ADALIBPY_REMOVE_EVERYONE_FILE_SHARING_PERMISSION_DISPLAY_BULK_DISPLAY_DESCRIPTION_FOLDER",
                    "bulk_support": true,
                    "confirm_button_style": "red",
                    "confirmation_button_text": null,
                    "confirmation_link": null,
                    "display_alert_success_text": "TASKS_ADALIBPY_REMOVE_EVERYONE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_SUCCESS_TEXT",
                    "display_alert_text": "TASKS_ADALIBPY_REMOVE_EVERYONE_FILE_SHARING_PERMISSION_DISPLAY_ALERT_TEXT",
                    "display_description": {
                        "parameters": {
                            "fileName": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
                            "fileType": {
                                "template": "ENUM_FILE_TYPE_FILE"
                            },
                            "folderWarning": ""
                        },
                        "template": "TASKS_ADALIBPY_REMOVE_EVERYONE_FILE_SHARING_PERMISSION_DISPLAY_DISPLAY_DESCRIPTION"
                    },
                    "display_title": "TASKS_ADALIBPY_REMOVE_EVERYONE_FILE_SHARING_PERMISSION_DISPLAY_TITLE",
                    "governance_type": null,
                    "has_icon": true,
                    "is_blocking": null,
                    "optional_notify": null,
                    "preview_only": false,
                    "task_name": "RemoveEveryoneFileTask",
                    "type": "file",
                    "uiGovernanceCategory": 2
                },
                {
                    "alert_display_title": null,
                    "bulk_display_description": null,
                    "bulk_support": true,
                    "confirm_button_style": "red",
                    "confirmation_button_text": null,
                    "confirmation_link": null,
                    "display_alert_success_text": null,
                    "display_alert_text": null,
                    "display_description": null,
                    "display_title": "TASKS_ADALIBPY_RESCAN_FILE_DISPLAY_TITLE",
                    "governance_type": null,
                    "has_icon": true,
                    "is_blocking": null,
                    "optional_notify": null,
                    "preview_only": false,
                    "task_name": "RescanFileTask",
                    "type": "file",
                    "uiGovernanceCategory": 0
                },
                {
                    "alert_display_title": null,
                    "bulk_display_description": "TASKS_ADALIBPY_TRASH_FILE_BULK_DISPLAY_DESCRIPTION",
                    "bulk_support": true,
                    "confirm_button_style": "red",
                    "confirmation_button_text": null,
                    "confirmation_link": null,
                    "display_alert_success_text": "TASKS_ADALIBPY_TRASH_FILE_ALERT_SUCCESS_TEXT",
                    "display_alert_text": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_ALERT_TEXT",
                    "display_description": {
                        "parameters": {
                            "fileName": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg"
                        },
                        "template": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_DESCRIPTION"
                    },
                    "display_title": "TASKS_ADALIBPY_TRASH_FILE_DISPLAY_TITLE",
                    "governance_type": null,
                    "has_icon": true,
                    "is_blocking": null,
                    "optional_notify": null,
                    "preview_only": false,
                    "task_name": "TrashFileTask",
                    "type": "file",
                    "uiGovernanceCategory": 1
                }
            ],
            "alternateLink": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/Quarantine_/7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
            "appId": 15600,
            "appName": "Microsoft OneDrive for Business",
            "collaborators": [
                {
                    "accessLevel": 1,
                    "id": "5",
                    "name": "Everyone except external users",
                    "role": 0,
                    "type": 2
                }
            ],
            "createdDate": 1594293035000,
            "display_collaborators": [
                {
                    "allowRemoveCollaborator": true,
                    "id": "Everyone except external users",
                    "label": "Group: Everyone except external users",
                    "type": "group"
                }
            ],
            "dlpScanResults": [],
            "domains": [
                "demistodev.onmicrosoft.com"
            ],
            "driveId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0",
            "effectiveParents": [
                "cac4b654-5fcf-44f0-818e-479cf8ae42ac|81bc41b0-926b-4078-88aa-8402f1320762",
                "cac4b654-5fcf-44f0-818e-479cf8ae42ac|ac8c3025-8b97-4758-ac74-c4b7c5c04ea0"
            ],
            "emails": [
                "avishai@demistodev.onmicrosoft.com"
            ],
            "enriched": true,
            "externalShares": [],
            "fTags": [],
            "facl": 1,
            "fileAccessLevel": [
                1,
                "INTERNAL"
            ],
            "fileExtension": "jpg",
            "filePath": "/personal/avishai_demistodev_onmicrosoft_com/Quarantine_/7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
            "fileSize": 175564,
            "fileStatus": [
                0,
                "EXISTS"
            ],
            "fileType": [
                5,
                "IMAGE"
            ],
            "fstat": 0,
            "ftype": 5,
            "groupIds": [
                "/personal/avishai_demistodev_onmicrosoft_com|5"
            ],
            "groups": [
                "Everyone except external users"
            ],
            "id": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|c88fb875-c021-4619-b692-f2def957796a",
            "instId": 0,
            "isFolder": false,
            "isForeign": false,
            "lastNrtTimestamp": 1594293273774,
            "mimeType": "image/jpeg",
            "modifiedDate": 1594293053000,
            "name": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
            "name_l": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
            "noGovernance": false,
            "originalId": "5f06fc1ac3b664209df1b864",
            "ownerAddress": "avishai@demistodev.onmicrosoft.com",
            "ownerExternal": false,
            "ownerName": "Avishai Brandeis",
            "parentId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac|81bc41b0-926b-4078-88aa-8402f1320762",
            "parentIds": [
                "cac4b654-5fcf-44f0-818e-479cf8ae42ac|81bc41b0-926b-4078-88aa-8402f1320762"
            ],
            "saasId": 15600,
            "scanVersion": 4,
            "sharepointItem": {
                "Author": {
                    "LoginName": "i:0#.f|membership|avishai@demistodev.onmicrosoft.com",
                    "externalUser": false,
                    "oneDriveEmail": "avishai@demistodev.onmicrosoft.com",
                    "sourceBitmask": 0,
                    "trueEmail": "avishai@demistodev.onmicrosoft.com"
                },
                "Length": 175564,
                "LinkingUrl": "",
                "ModifiedBy": {
                    "LoginName": "i:0#.f|membership|avishai@demistodev.onmicrosoft.com"
                },
                "Name": "7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
                "ServerRelativeUrl": "/personal/avishai_demistodev_onmicrosoft_com/Quarantine_/7036c013-cab0-4aee-b5e2-3f125ba40034.jpg",
                "TimeCreated": "2020-07-09T11:10:35Z",
                "TimeLastModified": "2020-07-09T11:10:53Z",
                "UniqueId": "c88fb875-c021-4619-b692-f2def957796a",
                "hasUniqueRoleAssignments": false,
                "parentUniqueId": "81bc41b0-926b-4078-88aa-8402f1320762",
                "roleAssignments": [
                    {
                        "Member": {
                            "Alerts": {},
                            "Email": "avishai@demistodev.onmicrosoft.com",
                            "Expiration": "",
                            "Groups": {},
                            "Id": 4,
                            "IsEmailAuthenticationGuestUser": false,
                            "IsHiddenInUI": false,
                            "IsShareByEmailGuestUser": false,
                            "IsSiteAdmin": true,
                            "LoginName": "i:0#.f|membership|avishai@demistodev.onmicrosoft.com",
                            "PrincipalType": 1,
                            "Title": "Avishai Brandeis",
                            "UserId": {
                                "NameId": "100300009abc2878",
                                "NameIdIssuer": "urn:federation:microsoftonline"
                            },
                            "UserPrincipalName": "avishai@demistodev.onmicrosoft.com"
                        },
                        "PrincipalId": 4,
                        "RoleDefinitionBindings": {
                            "results": [
                                {
                                    "BasePermissions": {
                                        "High": "2147483647",
                                        "Low": "4294967295"
                                    },
                                    "Hidden": false,
                                    "Id": 1073741829,
                                    "Name": "Full Control",
                                    "Order": 1,
                                    "RoleTypeKind": 5
                                }
                            ]
                        }
                    },
                    {
                        "Member": {
                            "Alerts": {},
                            "Email": "",
                            "Expiration": "",
                            "Groups": {},
                            "Id": 5,
                            "IsEmailAuthenticationGuestUser": false,
                            "IsHiddenInUI": false,
                            "IsShareByEmailGuestUser": false,
                            "IsSiteAdmin": false,
                            "LoginName": "c:0-.f|rolemanager|spo-grid-all-users/ebac1a16-81bf-449b-8d43-5732c3c1d999",
                            "PrincipalType": 4,
                            "Title": "Everyone except external users",
                            "UserId": null,
                            "UserPrincipalName": null
                        },
                        "PrincipalId": 5,
                        "RoleDefinitionBindings": {
                            "results": [
                                {
                                    "BasePermissions": {
                                        "High": "176",
                                        "Low": "138612833"
                                    },
                                    "Hidden": false,
                                    "Id": 1073741826,
                                    "Name": "Read",
                                    "Order": 128,
                                    "RoleTypeKind": 2
                                }
                            ]
                        }
                    }
                ],
                "urlFromMetadata": "https://demistodev-my.sharepoint.com/personal/avishai_demistodev_onmicrosoft_com/_api/Web/GetFileByServerRelativePath(decodedurl='/personal/avishai_demistodev_onmicrosoft_com/Quarantine_/7036c013-cab0-4aee-b5e2-3f125ba40034.jpg')"
            },
            "siteCollection": "/personal/avishai_demistodev_onmicrosoft_com",
            "siteCollectionId": "cac4b654-5fcf-44f0-818e-479cf8ae42ac",
            "sitePath": "/personal/avishai_demistodev_onmicrosoft_com",
            "snapshotLastModifiedDate": "2020-07-09T11:14:34.852Z",
            "spDomain": "https://demistodev-my.sharepoint.com",
            "unseenScans": 6
        }
    }
}
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
{
    "MicrosoftCloudAppSecurity": {
        "UsersAccounts": [
            {
                "_id": "5f01db17229037823e1eedfe",
                "accounts": [
                    {
                        "_id": "fa-5f01db17229037823e1eedfe-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "cloud app security service account for sharepoint",
                            "tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com",
                            "tmcassp_fa02d7a6fe55edb22020060112572594",
                            "9aa388ae-d7ad-4f38-af49-aeac04433eb7"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "Cloud App Security Service Account for SharePoint",
                        "em": null,
                        "ext": false,
                        "i": "9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                        "ii": "11161|0|9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-28T09:18:39.301Z",
                        "p": "11161|0|9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                        "pa": "tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "2020-07-27T10:06:54Z",
                            "20892": "2020-07-27T10:19:34.144Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Cloud App Security Service Account for SharePoint",
                "domain": "demistodev.onmicrosoft.com",
                "email": "tmcassp_fa02d7a6fe55edb22020060112572594@demistodev.onmicrosoft.com",
                "id": "9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|9aa388ae-d7ad-4f38-af49-aeac04433eb7",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-28T09:18:39.301Z",
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"9aa388ae-d7ad-4f38-af49-aeac04433eb7\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc42229037823e3c3631",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "MS Graph User DEV",
                "domain": null,
                "email": null,
                "id": "954d66fa-f865-493c-b1cb-c19d60613e54",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|954d66fa-f865-493c-b1cb-c19d60613e54",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-07-28T05:34:24Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"954d66fa-f865-493c-b1cb-c19d60613e54\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc3d229037823e3b9e92",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "MS Graph Groups",
                "domain": null,
                "email": null,
                "id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|7e14f6a3-185d-49e3-85e8-40a33d90dc90",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-07-28T01:43:12Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"7e14f6a3-185d-49e3-85e8-40a33d90dc90\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc14229037823e375f78",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "MS Graph Groups DEV",
                "domain": null,
                "email": null,
                "id": "9de2d7c5-45a6-4b98-b283-d94e912023e1",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|9de2d7c5-45a6-4b98-b283-d94e912023e1",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-07-28T01:42:36Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"9de2d7c5-45a6-4b98-b283-d94e912023e1\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dbaf229037823e2db67c",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft Approval Management",
                "domain": null,
                "email": null,
                "id": "65d91a3d-ab74-42e6-8a2f-0add61688c74",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|65d91a3d-ab74-42e6-8a2f-0add61688c74",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-28T01:42:07Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"65d91a3d-ab74-42e6-8a2f-0add61688c74\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc43229037823e3c3ade",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "MS Graph User",
                "domain": null,
                "email": null,
                "id": "d7508c5c-988b-485e-93c3-da7d658844d0",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|d7508c5c-988b-485e-93c3-da7d658844d0",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-07-28T01:42:07Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"d7508c5c-988b-485e-93c3-da7d658844d0\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf2229037823e1b2279",
                "accounts": [
                    {
                        "_id": "fa-5f01daf2229037823e1b2279-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "avishai",
                            "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "avishai@demistodev.onmicrosoft.com",
                            "avishai brandeis"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "Avishai Brandeis",
                        "em": "avishai@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "ii": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-28T08:09:49Z",
                        "p": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "pa": "avishai@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "2020-07-28T08:09:26Z",
                            "20892": "2020-07-28T08:09:49Z",
                            "20893": "2020-07-15T03:54:31.598Z",
                            "25275": "2020-07-27T10:15:43Z",
                            "28375": "2020-07-05T10:33:01Z"
                        },
                        "t": 1
                    },
                    {
                        "_id": "fa-5f01daf2229037823e1b2279-12260",
                        "actions": [],
                        "aliases": [
                            "avishai",
                            "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "avishai@demistodev.onmicrosoft.com",
                            "avishai brandeis"
                        ],
                        "appData": {
                            "appId": 12260,
                            "lastSeen": "2020-07-28T01:32:10.784Z",
                            "name": "Microsoft Azure"
                        },
                        "dn": "Avishai Brandeis",
                        "em": "avishai@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "ii": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-28T09:37:41.957Z",
                        "p": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "pa": "avishai@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 12260,
                        "sub": {},
                        "t": 1
                    },
                    {
                        "_id": "fa-5f01daf2229037823e1b2279-20595",
                        "actions": [],
                        "aliases": [
                            "avishai",
                            "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                            "avishai@demistodev.onmicrosoft.com",
                            "avishai brandeis"
                        ],
                        "appData": {
                            "appId": 20595,
                            "lastSeen": "2020-07-18T06:54:07.032Z",
                            "name": "Microsoft Cloud App Security"
                        },
                        "dn": "Avishai Brandeis",
                        "em": "avishai@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "ii": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-28T09:06:23.389Z",
                        "p": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "pa": "avishai@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 20595,
                        "sub": {},
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "avishai@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "avishai@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "avishai@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Avishai Brandeis",
                "domain": "demistodev.onmicrosoft.com",
                "email": "avishai@demistodev.onmicrosoft.com",
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-27T13:05:21.508Z",
                "organization": null,
                "role": "Company Administrator",
                "scoreTrends": {
                    "20200714": {
                        "alert": {
                            "m365": 32
                        }
                    },
                    "20200715": {
                        "alert": {
                            "m365": 32
                        }
                    },
                    "20200716": {},
                    "20200717": {},
                    "20200718": {},
                    "20200719": {
                        "alert": {
                            "m365": 38
                        }
                    },
                    "20200720": {
                        "alert": {
                            "m365": 57
                        }
                    },
                    "20200721": {
                        "alert": {
                            "m365": 57
                        }
                    },
                    "20200722": {
                        "alert": {
                            "m365": 57
                        }
                    },
                    "20200723": {
                        "alert": {
                            "m365": 113
                        }
                    },
                    "20200724": {
                        "alert": {
                            "m365": 113
                        }
                    },
                    "20200725": {
                        "alert": {
                            "m365": 113
                        }
                    },
                    "20200726": {
                        "alert": {
                            "m365": 75
                        }
                    },
                    "20200727": {
                        "alert": {
                            "m365": 56
                        }
                    },
                    "20200728": {
                        "alert": {
                            "m365": 56
                        }
                    }
                },
                "sctime": 1595895010409,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": 56,
                "threatScoreHistory": [
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 56
                            }
                        },
                        "dateFormatted": "20200728",
                        "dateUtc": 1595929918000,
                        "percentile": 100,
                        "score": 56
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 56
                            }
                        },
                        "dateFormatted": "20200727",
                        "dateUtc": 1595843518000,
                        "percentile": 100,
                        "score": 56
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 75
                            }
                        },
                        "dateFormatted": "20200726",
                        "dateUtc": 1595757118000,
                        "percentile": 0,
                        "score": 75
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 113
                            }
                        },
                        "dateFormatted": "20200725",
                        "dateUtc": 1595670718000,
                        "percentile": 0,
                        "score": 113
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 113
                            }
                        },
                        "dateFormatted": "20200724",
                        "dateUtc": 1595584318000,
                        "percentile": 0,
                        "score": 113
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 113
                            }
                        },
                        "dateFormatted": "20200723",
                        "dateUtc": 1595497918000,
                        "percentile": 100,
                        "score": 113
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 57
                            }
                        },
                        "dateFormatted": "20200722",
                        "dateUtc": 1595411518000,
                        "percentile": 0,
                        "score": 57
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 57
                            }
                        },
                        "dateFormatted": "20200721",
                        "dateUtc": 1595325118000,
                        "percentile": 0,
                        "score": 57
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 57
                            }
                        },
                        "dateFormatted": "20200720",
                        "dateUtc": 1595238718000,
                        "percentile": 100,
                        "score": 57
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 38
                            }
                        },
                        "dateFormatted": "20200719",
                        "dateUtc": 1595152318000,
                        "percentile": 100,
                        "score": 38
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200718",
                        "dateUtc": 1595065918000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200717",
                        "dateUtc": 1594979518000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200716",
                        "dateUtc": 1594893118000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 32
                            }
                        },
                        "dateFormatted": "20200715",
                        "dateUtc": 1594806718000,
                        "percentile": 0,
                        "score": 32
                    }
                ],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"3fa9f28b-eb0e-463a-ba7b-8089fe9991e2\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f06d788229037823ed84cae",
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/Cloud App Security",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Cloud App Security",
                "domain": null,
                "email": null,
                "id": "Cloud App Security",
                "idType": 0,
                "identifiers": [],
                "ii": "11161|0|Cloud App Security",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-27T10:36:02.246Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": null,
                "subApps": [
                    {
                        "appId": 20892,
                        "lastSeen": "2020-07-28T01:44:48Z",
                        "name": "Microsoft SharePoint Online"
                    },
                    {
                        "appId": 15600,
                        "lastSeen": "1970-01-01T00:00:00Z",
                        "name": "Microsoft OneDrive for Business"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [],
                "username": "{\"id\": \"Cloud App Security\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db0a229037823e1d7fe0",
                "accounts": [
                    {
                        "_id": "fa-5f01db0a229037823e1d7fe0-12260",
                        "actions": [],
                        "aliases": [
                            "lpettay@demistodev.onmicrosoft.com",
                            "3987137d-eb30-4cc9-baef-d84915c6912f",
                            "lance pettay",
                            "lpettay"
                        ],
                        "appData": {
                            "appId": 12260,
                            "lastSeen": "2020-07-28T01:32:10.784Z",
                            "name": "Microsoft Azure"
                        },
                        "dn": "Lance Pettay",
                        "em": null,
                        "ext": false,
                        "i": "3987137d-eb30-4cc9-baef-d84915c6912f",
                        "ii": "11161|0|3987137d-eb30-4cc9-baef-d84915c6912f",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-24T17:52:33.096Z",
                        "p": "11161|0|3987137d-eb30-4cc9-baef-d84915c6912f",
                        "pa": "lpettay@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 12260,
                        "sub": {},
                        "t": 1
                    },
                    {
                        "_id": "fa-5f01db0a229037823e1d7fe0-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3987137d-eb30-4cc9-baef-d84915c6912f",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "lpettay@demistodev.onmicrosoft.com",
                            "3987137d-eb30-4cc9-baef-d84915c6912f",
                            "lance pettay",
                            "lpettay"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "Lance Pettay",
                        "em": null,
                        "ext": false,
                        "i": "3987137d-eb30-4cc9-baef-d84915c6912f",
                        "ii": "11161|0|3987137d-eb30-4cc9-baef-d84915c6912f",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-24T17:52:33.096Z",
                        "p": "11161|0|3987137d-eb30-4cc9-baef-d84915c6912f",
                        "pa": "lpettay@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {},
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "lpettay@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "lpettay@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "lpettay@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3987137d-eb30-4cc9-baef-d84915c6912f",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3987137d-eb30-4cc9-baef-d84915c6912f",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Lance Pettay",
                "domain": "demistodev.onmicrosoft.com",
                "email": "lpettay@demistodev.onmicrosoft.com",
                "id": "3987137d-eb30-4cc9-baef-d84915c6912f",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|3987137d-eb30-4cc9-baef-d84915c6912f",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-24T17:52:33.096Z",
                "organization": null,
                "role": "Company Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"3987137d-eb30-4cc9-baef-d84915c6912f\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dbe4229037823e32951b",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "AAD App Management",
                "domain": null,
                "email": null,
                "id": "f0ae4899-d877-4d3c-ae25-679e38eea492",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|f0ae4899-d877-4d3c-ae25-679e38eea492",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-24T16:31:08Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"f0ae4899-d877-4d3c-ae25-679e38eea492\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8b229037823e2a6bca",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft Exchange Online Protection",
                "domain": null,
                "email": null,
                "id": "00000007-0000-0ff1-ce00-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000007-0000-0ff1-ce00-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-23T09:01:52Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 20892,
                        "lastSeen": "2020-07-28T01:44:48Z",
                        "name": "Microsoft SharePoint Online"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000007-0000-0ff1-ce00-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db9a229037823e2bbdcb",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Device Registration Service",
                "domain": null,
                "email": null,
                "id": "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-19T22:59:52Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8a229037823e2a5cf8",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft Intune",
                "domain": null,
                "email": null,
                "id": "0000000a-0000-0000-c000-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|0000000a-0000-0000-c000-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-15T14:46:07Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"0000000a-0000-0000-c000-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc26229037823e394d63",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Trend Micro Cloud App Security",
                "domain": null,
                "email": null,
                "id": "32eb7c81-01f8-4f56-b847-687b755fb160",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|32eb7c81-01f8-4f56-b847-687b755fb160",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-07-15T08:42:20Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"32eb7c81-01f8-4f56-b847-687b755fb160\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8f229037823e2ad50e",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Windows Azure Service Management API",
                "domain": null,
                "email": null,
                "id": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|797f4846-ba00-4fd7-ba43-dac1f8f63013",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-10T14:33:09Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"797f4846-ba00-4fd7-ba43-dac1f8f63013\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db1e229037823e1face2",
                "accounts": [
                    {
                        "_id": "fa-5f01db1e229037823e1face2-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/e2397ddc-d33f-4324-a6d4-5955ae199903",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "eran",
                            "eran korish",
                            "eran@demistodev.onmicrosoft.com",
                            "e2397ddc-d33f-4324-a6d4-5955ae199903"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "Eran Korish",
                        "em": "eran@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "e2397ddc-d33f-4324-a6d4-5955ae199903",
                        "ii": "11161|0|e2397ddc-d33f-4324-a6d4-5955ae199903",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-06T08:06:17.116Z",
                        "p": "11161|0|e2397ddc-d33f-4324-a6d4-5955ae199903",
                        "pa": "eran@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "1970-01-01T00:00:00Z",
                            "20893": "2020-07-06T08:06:17.116Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "eran@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "eran@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "eran@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/e2397ddc-d33f-4324-a6d4-5955ae199903",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/e2397ddc-d33f-4324-a6d4-5955ae199903",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Eran Korish",
                "domain": "demistodev.onmicrosoft.com",
                "email": "eran@demistodev.onmicrosoft.com",
                "id": "e2397ddc-d33f-4324-a6d4-5955ae199903",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|e2397ddc-d33f-4324-a6d4-5955ae199903",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-06T08:06:17.116Z",
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"e2397ddc-d33f-4324-a6d4-5955ae199903\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dbce229037823e306e7d",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Azure Resource Graph",
                "domain": null,
                "email": null,
                "id": "509e4652-da8d-478d-a730-e9d4a1996ca4",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|509e4652-da8d-478d-a730-e9d4a1996ca4",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-05T23:50:54.723Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"509e4652-da8d-478d-a730-e9d4a1996ca4\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf1229037823e1b0790",
                "accounts": [
                    {
                        "_id": "fa-5f01daf1229037823e1b0790-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/2827c1e7-edb6-4529-b50d-25984e968637",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "dev@demistodev.onmicrosoft.com",
                            "dev",
                            "2827c1e7-edb6-4529-b50d-25984e968637",
                            "demisto dev"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "demisto dev",
                        "em": "dev@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "2827c1e7-edb6-4529-b50d-25984e968637",
                        "ii": "11161|0|2827c1e7-edb6-4529-b50d-25984e968637",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-28T08:38:41Z",
                        "p": "11161|0|2827c1e7-edb6-4529-b50d-25984e968637",
                        "pa": "dev@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "2020-07-22T14:49:01Z",
                            "20892": "2020-07-22T14:48:57Z",
                            "20893": "2020-07-28T08:38:41Z"
                        },
                        "t": 1
                    },
                    {
                        "_id": "fa-5f01daf1229037823e1b0790-20595",
                        "actions": [],
                        "aliases": [
                            "dev@demistodev.onmicrosoft.com",
                            "dev",
                            "2827c1e7-edb6-4529-b50d-25984e968637",
                            "demisto dev"
                        ],
                        "appData": {
                            "appId": 20595,
                            "lastSeen": "2020-07-18T06:54:07.032Z",
                            "name": "Microsoft Cloud App Security"
                        },
                        "dn": "demisto dev",
                        "em": "dev@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "2827c1e7-edb6-4529-b50d-25984e968637",
                        "ii": "11161|0|2827c1e7-edb6-4529-b50d-25984e968637",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-18T06:54:07.032Z",
                        "p": "11161|0|2827c1e7-edb6-4529-b50d-25984e968637",
                        "pa": "dev@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 20595,
                        "sub": {},
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "dev@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "dev@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "dev@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/2827c1e7-edb6-4529-b50d-25984e968637",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/2827c1e7-edb6-4529-b50d-25984e968637",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "demisto dev",
                "domain": "demistodev.onmicrosoft.com",
                "email": "dev@demistodev.onmicrosoft.com",
                "id": "2827c1e7-edb6-4529-b50d-25984e968637",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|2827c1e7-edb6-4529-b50d-25984e968637",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-05T13:19:55Z",
                "organization": null,
                "role": "Security Administrator",
                "scoreTrends": {
                    "20200714": {
                        "alert": {
                            "m365": 19
                        }
                    },
                    "20200715": {
                        "alert": {
                            "m365": 19
                        }
                    },
                    "20200716": {},
                    "20200717": {},
                    "20200718": {},
                    "20200719": {},
                    "20200720": {},
                    "20200721": {},
                    "20200722": {},
                    "20200723": {},
                    "20200724": {},
                    "20200725": {},
                    "20200726": {},
                    "20200727": {},
                    "20200728": {}
                },
                "sctime": 1595896500159,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": 0,
                "threatScoreHistory": [
                    {
                        "breakdown": {},
                        "dateFormatted": "20200728",
                        "dateUtc": 1595929918000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200727",
                        "dateUtc": 1595843518000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200726",
                        "dateUtc": 1595757118000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200725",
                        "dateUtc": 1595670718000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200724",
                        "dateUtc": 1595584318000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200723",
                        "dateUtc": 1595497918000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200722",
                        "dateUtc": 1595411518000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200721",
                        "dateUtc": 1595325118000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200720",
                        "dateUtc": 1595238718000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200719",
                        "dateUtc": 1595152318000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200718",
                        "dateUtc": 1595065918000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200717",
                        "dateUtc": 1594979518000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {},
                        "dateFormatted": "20200716",
                        "dateUtc": 1594893118000,
                        "percentile": 0,
                        "score": 0
                    },
                    {
                        "breakdown": {
                            "alert": {
                                "m365": 19
                            }
                        },
                        "dateFormatted": "20200715",
                        "dateUtc": 1594806718000,
                        "percentile": 0,
                        "score": 19
                    }
                ],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"2827c1e7-edb6-4529-b50d-25984e968637\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc8c229037823e44497a",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Media Analysis and Transformation Service",
                "domain": null,
                "email": null,
                "id": "944f0bd1-117b-4b1c-af26-804ed95e767e",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|944f0bd1-117b-4b1c-af26-804ed95e767e",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-05T09:12:37Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": null,
                "subApps": [
                    {
                        "appId": 20892,
                        "lastSeen": "2020-07-28T01:44:48Z",
                        "name": "Microsoft SharePoint Online"
                    },
                    {
                        "appId": 15600,
                        "lastSeen": "1970-01-01T00:00:00Z",
                        "name": "Microsoft OneDrive for Business"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"944f0bd1-117b-4b1c-af26-804ed95e767e\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8b229037823e2a6f62",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Office 365 SharePoint Online",
                "domain": null,
                "email": null,
                "id": "00000003-0000-0ff1-ce00-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000003-0000-0ff1-ce00-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-07-05T09:12:30Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 20892,
                        "lastSeen": "2020-07-28T01:44:48Z",
                        "name": "Microsoft SharePoint Online"
                    },
                    {
                        "appId": 15600,
                        "lastSeen": "1970-01-01T00:00:00Z",
                        "name": "Microsoft OneDrive for Business"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000003-0000-0ff1-ce00-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc1f229037823e389def",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "MS Graph Files",
                "domain": null,
                "email": null,
                "id": "6b495fcf-df22-4544-99a3-97d384764d79",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|6b495fcf-df22-4544-99a3-97d384764d79",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-06-30T09:11:49Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 20892,
                        "lastSeen": "2020-07-28T01:44:48Z",
                        "name": "Microsoft SharePoint Online"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"6b495fcf-df22-4544-99a3-97d384764d79\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dc24229037823e392921",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "MS Graph Files Dev",
                "domain": null,
                "email": null,
                "id": "2c160fab-7040-4f08-bec2-8ce97e9cc435",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|2c160fab-7040-4f08-bec2-8ce97e9cc435",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-06-30T09:09:56Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 20892,
                        "lastSeen": "2020-07-28T01:44:48Z",
                        "name": "Microsoft SharePoint Online"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"2c160fab-7040-4f08-bec2-8ce97e9cc435\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db1c229037823e1f8895",
                "accounts": [
                    {
                        "_id": "fa-5f01db1c229037823e1f8895-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/023096d0-595e-47b5-80dd-ea5886ab9294",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "lior kolnik",
                            "liork",
                            "liork@demistodev.onmicrosoft.com",
                            "023096d0-595e-47b5-80dd-ea5886ab9294"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "lior kolnik",
                        "em": "liork@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "023096d0-595e-47b5-80dd-ea5886ab9294",
                        "ii": "11161|0|023096d0-595e-47b5-80dd-ea5886ab9294",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-07T00:13:46Z",
                        "p": "11161|0|023096d0-595e-47b5-80dd-ea5886ab9294",
                        "pa": "liork@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "2020-07-07T00:13:46Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "liork@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "liork@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "liork@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/023096d0-595e-47b5-80dd-ea5886ab9294",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/023096d0-595e-47b5-80dd-ea5886ab9294",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "lior kolnik",
                "domain": "demistodev.onmicrosoft.com",
                "email": "liork@demistodev.onmicrosoft.com",
                "id": "023096d0-595e-47b5-80dd-ea5886ab9294",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|023096d0-595e-47b5-80dd-ea5886ab9294",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-06-30T08:13:48Z",
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"023096d0-595e-47b5-80dd-ea5886ab9294\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db1e229037823e1faad9",
                "accounts": [
                    {
                        "_id": "fa-5f01db1e229037823e1faad9-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/9702a3de-f219-425b-b0ef-9c343b786030",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "sr-test02",
                            "9702a3de-f219-425b-b0ef-9c343b786030",
                            "sr test02",
                            "sr-test02@demistodev.onmicrosoft.com"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "sr test02",
                        "em": "sr-test02@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "9702a3de-f219-425b-b0ef-9c343b786030",
                        "ii": "11161|0|9702a3de-f219-425b-b0ef-9c343b786030",
                        "inst": 0,
                        "isFake": true,
                        "ls": "2020-07-06T05:47:43Z",
                        "p": "11161|0|9702a3de-f219-425b-b0ef-9c343b786030",
                        "pa": "sr-test02@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "2020-07-06T05:47:43Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "sr-test02@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "sr-test02@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "sr-test02@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/9702a3de-f219-425b-b0ef-9c343b786030",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/9702a3de-f219-425b-b0ef-9c343b786030",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "sr test02",
                "domain": "demistodev.onmicrosoft.com",
                "email": "sr-test02@demistodev.onmicrosoft.com",
                "id": "9702a3de-f219-425b-b0ef-9c343b786030",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|9702a3de-f219-425b-b0ef-9c343b786030",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-06-30T00:13:44Z",
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"9702a3de-f219-425b-b0ef-9c343b786030\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5ec0f6fa845ec2103c949e77",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "SecurityCenter",
                "domain": null,
                "email": null,
                "id": "8ccae514-af28-4b44-9f19-386428b3811c",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|8ccae514-af28-4b44-9f19-386428b3811c",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-05-17T08:30:13.957Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"8ccae514-af28-4b44-9f19-386428b3811c\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5eb121f5d217689d5838907f",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Managed Disks Resource Provider",
                "domain": null,
                "email": null,
                "id": "60e6cd67-9c8c-4951-9b3c-23c25a2169af",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|60e6cd67-9c8c-4951-9b3c-23c25a2169af",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-05-05T07:56:05.291Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"60e6cd67-9c8c-4951-9b3c-23c25a2169af\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5e702cce3d4ed7278a558dcf",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft Azure Policy Insights",
                "domain": null,
                "email": null,
                "id": "1d78a85d-813d-46f0-b496-dd72f50a3ec0",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|1d78a85d-813d-46f0-b496-dd72f50a3ec0",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": "2020-03-17T01:48:21.101Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"1d78a85d-813d-46f0-b496-dd72f50a3ec0\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5e701c4c3d4ed7278abb7dcb",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Azure Security Center",
                "domain": null,
                "email": null,
                "id": "61f36b84-ce6b-4ca8-9d55-744e3d8d2152",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|61f36b84-ce6b-4ca8-9d55-744e3d8d2152",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-03-17T00:36:01.976Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"61f36b84-ce6b-4ca8-9d55-744e3d8d2152\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5e701b793d4ed7278a89964f",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Azure Compute",
                "domain": null,
                "email": null,
                "id": "e16945f4-e521-4da9-87f5-8d14b008aa78",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|e16945f4-e521-4da9-87f5-8d14b008aa78",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-03-17T00:34:32.951Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"e16945f4-e521-4da9-87f5-8d14b008aa78\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5e701b493d4ed7278a7e7252",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "AzureCompute",
                "domain": null,
                "email": null,
                "id": "9ead7552-8ee2-47e1-b435-fcff173735a5",
                "idType": 4,
                "identifiers": [],
                "ii": "11161|0|9ead7552-8ee2-47e1-b435-fcff173735a5",
                "isAdmin": false,
                "isExternal": true,
                "isFake": false,
                "lastSeen": "2020-03-17T00:33:19.047Z",
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [
                    {
                        "appId": 12260,
                        "lastSeen": "2020-07-28T01:32:10.784Z",
                        "name": "Microsoft Azure"
                    }
                ],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    },
                    {
                        "_id": "5e6fa9ace2367fc6340f4864",
                        "description": "Either a user who is not a member of any of the managed domains you configured in General settings or a third-party app",
                        "id": "000000200000000000000000",
                        "name": "External users",
                        "usersCount": 108
                    }
                ],
                "username": "{\"id\": \"9ead7552-8ee2-47e1-b435-fcff173735a5\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf0229037823e1af99e",
                "accounts": [],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "logs@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "logs@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "logs@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Logs Analysis test",
                "domain": "demistodev.onmicrosoft.com",
                "email": "logs@demistodev.onmicrosoft.com",
                "id": "5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Service Support Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db89229037823e2a550e",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft.Azure.GraphExplorer",
                "domain": null,
                "email": null,
                "id": "0000000f-0000-0000-c000-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|0000000f-0000-0000-c000-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"0000000f-0000-0000-c000-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf3229037823e1b3ea8",
                "accounts": [],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "itay@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "itay@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "itay@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/8918c390-35b8-42c3-83f1-8352e0e9df65",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/8918c390-35b8-42c3-83f1-8352e0e9df65",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Itay Keren",
                "domain": "demistodev.onmicrosoft.com",
                "email": "itay@demistodev.onmicrosoft.com",
                "id": "8918c390-35b8-42c3-83f1-8352e0e9df65",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|8918c390-35b8-42c3-83f1-8352e0e9df65",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Company Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"8918c390-35b8-42c3-83f1-8352e0e9df65\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db89229037823e2a5618",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Azure Classic Portal",
                "domain": null,
                "email": null,
                "id": "00000013-0000-0000-c000-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000013-0000-0000-c000-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000013-0000-0000-c000-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf3229037823e1b4089",
                "accounts": [],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "vanhelsing@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "vanhelsing@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "vanhelsing@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/21395465-a687-4d0f-9ea6-b0bd39531c47",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/21395465-a687-4d0f-9ea6-b0bd39531c47",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "van Helsing",
                "domain": "demistodev.onmicrosoft.com",
                "email": "vanhelsing@demistodev.onmicrosoft.com",
                "id": "21395465-a687-4d0f-9ea6-b0bd39531c47",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|21395465-a687-4d0f-9ea6-b0bd39531c47",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Compliance Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"21395465-a687-4d0f-9ea6-b0bd39531c47\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8a229037823e2a5be1",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft App Access Panel",
                "domain": null,
                "email": null,
                "id": "0000000c-0000-0000-c000-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|0000000c-0000-0000-c000-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"0000000c-0000-0000-c000-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf4229037823e1b42f5",
                "accounts": [
                    {
                        "_id": "fa-5f01daf4229037823e1b42f5-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "svc@demistodev.onmicrosoft.com",
                            "svc",
                            "e8a03722-99a2-4b26-bde4-836e8a8e30c9"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "svc",
                        "em": "svc@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                        "ii": "11161|0|e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                        "inst": 0,
                        "isFake": true,
                        "ls": "1970-01-01T00:00:00Z",
                        "p": "11161|0|e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                        "pa": "svc@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "1970-01-01T00:00:00Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "svc@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "svc@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "svc@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "svc",
                "domain": "demistodev.onmicrosoft.com",
                "email": "svc@demistodev.onmicrosoft.com",
                "id": "e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|e8a03722-99a2-4b26-bde4-836e8a8e30c9",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Company Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"e8a03722-99a2-4b26-bde4-836e8a8e30c9\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8a229037823e2a6663",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Yammer",
                "domain": null,
                "email": null,
                "id": "00000005-0000-0ff1-ce00-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000005-0000-0ff1-ce00-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000005-0000-0ff1-ce00-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf5229037823e1b6536",
                "accounts": [
                    {
                        "_id": "fa-5f01daf5229037823e1b6536-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/70585180-517a-43ea-9403-2d80b97ab19d",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "serviceaccount1",
                            "70585180-517a-43ea-9403-2d80b97ab19d",
                            "serviceaccount1@demistodev.onmicrosoft.com"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "ServiceAccount1",
                        "em": null,
                        "ext": false,
                        "i": "70585180-517a-43ea-9403-2d80b97ab19d",
                        "ii": "11161|0|70585180-517a-43ea-9403-2d80b97ab19d",
                        "inst": 0,
                        "isFake": true,
                        "ls": "1970-01-01T00:00:00Z",
                        "p": "11161|0|70585180-517a-43ea-9403-2d80b97ab19d",
                        "pa": "serviceaccount1@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "1970-01-01T00:00:00Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "serviceaccount1@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "serviceaccount1@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "serviceaccount1@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/70585180-517a-43ea-9403-2d80b97ab19d",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/70585180-517a-43ea-9403-2d80b97ab19d",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "ServiceAccount1",
                "domain": "demistodev.onmicrosoft.com",
                "email": "serviceaccount1@demistodev.onmicrosoft.com",
                "id": "70585180-517a-43ea-9403-2d80b97ab19d",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|70585180-517a-43ea-9403-2d80b97ab19d",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Service Support Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"70585180-517a-43ea-9403-2d80b97ab19d\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8b229037823e2a69a3",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Power BI Service",
                "domain": null,
                "email": null,
                "id": "00000009-0000-0000-c000-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000009-0000-0000-c000-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000009-0000-0000-c000-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf6229037823e1b836e",
                "accounts": [
                    {
                        "_id": "fa-5f01daf6229037823e1b836e-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/5d8d8aad-14ab-4683-aa57-fa37642599a4",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "itayadmin",
                            "itayadmin@demistodev.onmicrosoft.com",
                            "5d8d8aad-14ab-4683-aa57-fa37642599a4"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "itayadmin",
                        "em": null,
                        "ext": false,
                        "i": "5d8d8aad-14ab-4683-aa57-fa37642599a4",
                        "ii": "11161|0|5d8d8aad-14ab-4683-aa57-fa37642599a4",
                        "inst": 0,
                        "isFake": true,
                        "ls": "1970-01-01T00:00:00Z",
                        "p": "11161|0|5d8d8aad-14ab-4683-aa57-fa37642599a4",
                        "pa": "itayadmin@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "1970-01-01T00:00:00Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "itayadmin@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "itayadmin@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "itayadmin@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/5d8d8aad-14ab-4683-aa57-fa37642599a4",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/5d8d8aad-14ab-4683-aa57-fa37642599a4",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "itayadmin",
                "domain": "demistodev.onmicrosoft.com",
                "email": "itayadmin@demistodev.onmicrosoft.com",
                "id": "5d8d8aad-14ab-4683-aa57-fa37642599a4",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|5d8d8aad-14ab-4683-aa57-fa37642599a4",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Company Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"5d8d8aad-14ab-4683-aa57-fa37642599a4\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8b229037823e2a6db2",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft Office Web Apps Service",
                "domain": null,
                "email": null,
                "id": "67e3df25-268a-4324-a550-0de1c7f97287",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|67e3df25-268a-4324-a550-0de1c7f97287",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"67e3df25-268a-4324-a550-0de1c7f97287\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf6229037823e1b857b",
                "accounts": [
                    {
                        "_id": "fa-5f01daf6229037823e1b857b-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/fc3aea12-f19f-461e-b62b-25ee818deb6d",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "jochman",
                            "fc3aea12-f19f-461e-b62b-25ee818deb6d",
                            "jochman@demistodev.onmicrosoft.com"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "Jochman",
                        "em": "jochman@demistodev.onmicrosoft.com",
                        "ext": false,
                        "i": "fc3aea12-f19f-461e-b62b-25ee818deb6d",
                        "ii": "11161|0|fc3aea12-f19f-461e-b62b-25ee818deb6d",
                        "inst": 0,
                        "isFake": true,
                        "ls": "1970-01-01T00:00:00Z",
                        "p": "11161|0|fc3aea12-f19f-461e-b62b-25ee818deb6d",
                        "pa": "jochman@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "1970-01-01T00:00:00Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "jochman@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "jochman@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "jochman@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/fc3aea12-f19f-461e-b62b-25ee818deb6d",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/fc3aea12-f19f-461e-b62b-25ee818deb6d",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Jochman",
                "domain": "demistodev.onmicrosoft.com",
                "email": "jochman@demistodev.onmicrosoft.com",
                "id": "fc3aea12-f19f-461e-b62b-25ee818deb6d",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|fc3aea12-f19f-461e-b62b-25ee818deb6d",
                "isAdmin": true,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "Company Administrator",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [
                    {
                        "_id": "5f01dbbc68df27c17aa6ca82",
                        "appId": 11161,
                        "description": "Company administrators, user account administrators, helpdesk administrators, service support administrators, and billing administrators",
                        "id": "5f01dbbc68df27c17aa6ca81",
                        "name": "Office 365 administrator",
                        "usersCount": 10
                    }
                ],
                "username": "{\"id\": \"fc3aea12-f19f-461e-b62b-25ee818deb6d\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8b229037823e2a7ebe",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Skype for Business Online",
                "domain": null,
                "email": null,
                "id": "00000004-0000-0ff1-ce00-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000004-0000-0ff1-ce00-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000004-0000-0ff1-ce00-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01daf8229037823e1badea",
                "accounts": [],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "tsach@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "tsach@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "tsach@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/259d2a3c-167b-411c-b2ee-88646ce6e054",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/259d2a3c-167b-411c-b2ee-88646ce6e054",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Tsach zimmer",
                "domain": "demistodev.onmicrosoft.com",
                "email": "tsach@demistodev.onmicrosoft.com",
                "id": "259d2a3c-167b-411c-b2ee-88646ce6e054",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|259d2a3c-167b-411c-b2ee-88646ce6e054",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"259d2a3c-167b-411c-b2ee-88646ce6e054\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8c229037823e2a7f10",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Office 365 Exchange Online",
                "domain": null,
                "email": null,
                "id": "00000002-0000-0ff1-ce00-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000002-0000-0ff1-ce00-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000002-0000-0ff1-ce00-000000000000\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dafb229037823e1bfa09",
                "accounts": [
                    {
                        "_id": "fa-5f01dafb229037823e1bfa09-11161",
                        "actions": [
                            {
                                "alert_display_title": null,
                                "bulk_display_description": null,
                                "bulk_support": null,
                                "confirm_button_style": "red",
                                "confirmation_button_text": null,
                                "confirmation_link": null,
                                "display_alert_success_text": null,
                                "display_alert_text": null,
                                "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                                "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                                "governance_type": "link",
                                "has_icon": true,
                                "is_blocking": null,
                                "optional_notify": null,
                                "preview_only": false,
                                "task_name": "UserAADSettingsLink",
                                "type": "user",
                                "uiGovernanceCategory": null
                            }
                        ],
                        "aliases": [
                            "lichtman",
                            "lichtman@demistodev.onmicrosoft.com",
                            "3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                            "guy lichtman"
                        ],
                        "appData": {
                            "appId": 11161,
                            "instance": 0,
                            "name": "Office 365",
                            "saas": 11161
                        },
                        "dn": "Guy Lichtman",
                        "em": null,
                        "ext": false,
                        "i": "3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                        "ii": "11161|0|3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                        "inst": 0,
                        "isFake": true,
                        "ls": "1970-01-01T00:00:00Z",
                        "p": "11161|0|3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                        "pa": "lichtman@demistodev.onmicrosoft.com",
                        "s": 2,
                        "saas": 11161,
                        "sub": {
                            "15600": "1970-01-01T00:00:00Z"
                        },
                        "t": 1
                    }
                ],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "lichtman@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "lichtman@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "lichtman@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Guy Lichtman",
                "domain": "demistodev.onmicrosoft.com",
                "email": "lichtman@demistodev.onmicrosoft.com",
                "id": "3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"3a6efd73-b4bb-4ef6-b0ed-2c76f043dba4\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8c229037823e2a8cae",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft.ExtensibleRealUserMonitoring",
                "domain": null,
                "email": null,
                "id": "e3583ad2-c781-4224-9b91-ad15a8179ba0",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|e3583ad2-c781-4224-9b91-ad15a8179ba0",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"e3583ad2-c781-4224-9b91-ad15a8179ba0\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01dafb229037823e1c012e",
                "accounts": [],
                "actions": [
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "bkatzir@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_CONFIRM_USER_COMPROMISED_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "ConfirmUserCompromisedTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "bkatzir@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_INVALIDATE_ALL_REFRESH_TOKENS_FOR_A_USER_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "InvalidateAllRefreshTokensForAUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_BULK_DISPLAY_DESCRIPTION_O365",
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_SUCCESS_TEXT",
                        "display_alert_text": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_ALERT_TEXT",
                        "display_description": {
                            "parameters": {
                                "user": "bkatzir@demistodev.onmicrosoft.com"
                            },
                            "template": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_DESCRIPTION_O365"
                        },
                        "display_title": "TASKS_ADALIBPY_SUSPEND_USER_SUSPENSION_DISPLAY_TITLE",
                        "governance_type": null,
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "SuspendUserTask",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/7bd0dd8e-7d2f-4ace-af36-19f91a670281",
                        "display_title": "TASKS_ADALIBPY_USER_AAD_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserAADSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    },
                    {
                        "alert_display_title": null,
                        "bulk_display_description": null,
                        "bulk_support": null,
                        "confirm_button_style": "red",
                        "confirmation_button_text": null,
                        "confirmation_link": null,
                        "display_alert_success_text": null,
                        "display_alert_text": null,
                        "display_description": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/7bd0dd8e-7d2f-4ace-af36-19f91a670281",
                        "display_title": "TASKS_ADALIBPY_USER_SETTINGS_LINK_DISPLAY_TITLE",
                        "governance_type": "link",
                        "has_icon": true,
                        "is_blocking": null,
                        "optional_notify": null,
                        "preview_only": false,
                        "task_name": "UserSettingsLink",
                        "type": "user",
                        "uiGovernanceCategory": null
                    }
                ],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Bar Katzir",
                "domain": "demistodev.onmicrosoft.com",
                "email": "bkatzir@demistodev.onmicrosoft.com",
                "id": "7bd0dd8e-7d2f-4ace-af36-19f91a670281",
                "idType": 1,
                "identifiers": [],
                "ii": "11161|0|7bd0dd8e-7d2f-4ace-af36-19f91a670281",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": "User",
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "threatScoreHistory": [],
                "type": 2,
                "userGroups": [],
                "username": "{\"id\": \"7bd0dd8e-7d2f-4ace-af36-19f91a670281\", \"saas\": 11161, \"inst\": 0}"
            },
            {
                "_id": "5f01db8d229037823e2a8d42",
                "actions": [],
                "appData": {
                    "appId": 11161,
                    "instance": 0,
                    "name": "Office 365",
                    "saas": 11161
                },
                "displayName": "Microsoft Office 365 Portal",
                "domain": null,
                "email": null,
                "id": "00000006-0000-0ff1-ce00-000000000000",
                "idType": 17,
                "identifiers": [],
                "ii": "11161|0|00000006-0000-0ff1-ce00-000000000000",
                "isAdmin": false,
                "isExternal": false,
                "isFake": false,
                "lastSeen": null,
                "organization": null,
                "role": null,
                "scoreTrends": null,
                "sctime": null,
                "sid": null,
                "status": 2,
                "subApps": [],
                "threatScore": null,
                "type": 1,
                "userGroups": [
                    {
                        "_id": "5e6fa9ade2367fc6340f487e",
                        "description": "App-initiated",
                        "id": "0000003b0000000000000000",
                        "name": "Application (Cloud App Security)",
                        "usersCount": 565
                    }
                ],
                "username": "{\"id\": \"00000006-0000-0ff1-ce00-000000000000\", \"saas\": 11161, \"inst\": 0}"
            }
        ]
    }
}
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

