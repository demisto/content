Secret Server is the only fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. It empowers security and IT ops teams to secure and manage all types of privileged accounts and offers the fastest time to value of any PAM solution.
This integration was integrated and tested with version 5.0 of Delinea
## Configure Delinea in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetchCredentials | Fetches credentials | False |
| credentialobjects | List secret name for fetch credentials \(separated by commas\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### delinea-secret-password-get
***
Retrieved password from secret


#### Base Command

`delinea-secret-password-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Password | String | Retrieved password from secret  | 


#### Command Example
```!delinea-secret-password-get secret_id=2```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Password": "1234567890"
        }
    }
}
```


### delinea-secret-username-get
***
Retrieved username from secret


#### Base Command

`delinea-secret-username-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Username | String | Retrieved username from secret. | 


#### Command Example
```!delinea-secret-username-get secret_id=2```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Username": "w2\\w2"
        }
    }
}
```


### delinea-secret-search-name
***
Search ID secret by field name


#### Base Command

`delinea-secret-search-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | Search name secret. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Id | String | Retrieved list ID for find secret by field secret name | 


#### Command Example
```!delinea-secret-search-name search_name=xsoarSecret```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Id": [
                5
            ]
        }
    }
}
```


### delinea-secret-password-update
***
Update password for secret


#### Base Command

`delinea-secret-password-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret for update  password | Required | 
| newpassword | Value new password for secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Newpassword | String | New password changed for secret | 


#### Command Example
```!delinea-secret-password-update secret_id=2 newpassword=12345```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Newpassword": "12345"
        }
    }
}
```


### delinea-secret-checkout
***
Check Out a secret


#### Base Command

`delinea-secret-checkout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret for check out command | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Checkout | String | Return call command Check Out | 


#### Command Example
```!delinea-secret-checkout secret_id=2```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Checkout": {
            		"responseCodes":null
            }
        }
    }
}
```


### delinea-secret-checkin
***
Check In a secret


#### Base Command

`delinea-secret-checkin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | Secret ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Checkin | String | Secret object | 


#### Command Example
```!delinea-secret-checkin secret_id=13```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Checkin": {
                "active": true,
                "autoChangeEnabled": false,
                "checkOutEnabled": true,
                "checkedOut": false,
                "createDate": "2020-12-15T09:13:49.487",
                "daysUntilExpiration": null,
                "doubleLockEnabled": false,
                "extendedFields": null,
                "folderId": 3,
                "hidePassword": false,
                "id": 13,
                "inheritsPermissions": true,
                "isOutOfSync": false,
                "isRestricted": true,
                "lastAccessed": null,
                "lastHeartBeatStatus": "Pending",
                "lastPasswordChangeAttempt": "0001-01-01T00:00:00",
                "name": "secretT",
                "outOfSyncReason": "",
                "requiresApproval": false,
                "requiresComment": false,
                "responseCodes": null,
                "secretTemplateId": 6003,
                "secretTemplateName": "Windows Account",
                "siteId": 1
            }
        }
    }
}
```



### delinea-folder-create
***
Create a new secret folder


#### Base Command

`delinea-folder-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| foldername | Folder name | Required | 
| foldertypeid | Folder type ID(1=&lt; ID =&lt; 3 | Required | 
| parentfolderid | Parent folder ID | Required | 
| inheritPermissions | Whether the folder should inherit permissions from its parent (default: true) | Optional | 
| inheritSecretPolicy | Whether the folder should inherit the secret policy. Defaults to true unless creating a root folder. | Optional | 
| secretPolicyId | Secret policy ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Folder.Create | Unknown | New object folder | 


#### Command Example
```!delinea-folder-create foldername="xsoarFolderTest" foldertypeid="1" parentfolderid="3"```

#### Context Example
```json
{
    "Delinea": {
        "Folder": {
            "Create": {
                "childFolders": null,
                "folderName": "xsoarFolderTest",
                "folderPath": "\\Personal Folders\\XSOAR integration\\xsoarFolderTest",
                "folderTypeId": 1,
                "id": 5,
                "inheritPermissions": false,
                "inheritSecretPolicy": false,
                "parentFolderId": 3,
                "secretPolicyId": -1,
                "secretTemplates": null
            }
        }
    }
}
```


### delinea-folder-search
***
Search folder by name folder


#### Base Command

`delinea-folder-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| foldername | Search name folder | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Folder.Id | String | Retrieved folder ID from search query | 


#### Command Example
```!delinea-folder-search foldername="xsoarFolderTest"```

#### Context Example
```json
{
    "Delinea": {
        "Folder": {
            "Id": [
                5
            ]
        }
    }
}
```


#### Command Example
```!delinea-folder-delete folder_id="18"```

#### Context Example
```json
{
    "Delinea": {
        "Folder": {
            "Delete": {
                "id": 18,
                "objectType": "Folder",
                "responseCodes": []
            }
        }
    }
}
```


### delinea-secret-get
***
Get secret object by ID secret


#### Base Command

`delinea-secret-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID for secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret | String | Secret object | 


#### Command Example
```!delinea-secret-get secret_id=2```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "accessRequestWorkflowMapId": -1,
            "active": true,
            "allowOwnersUnrestrictedSshCommands": false,
            "autoChangeEnabled": false,
            "autoChangeNextPassword": "2$C$7vl8*SN@",
            "checkOutChangePasswordEnabled": false,
            "checkOutEnabled": true,
            "checkOutIntervalMinutes": -1,
            "checkOutMinutesRemaining": 30,
            "checkOutUserDisplayName": "XSOAR integration",
            "checkOutUserId": 3,
            "checkedOut": true,
            "doubleLockId": -1,
            "enableInheritPermissions": true,
            "enableInheritSecretPolicy": true,
            "failedPasswordChangeAttempts": 0,
            "folderId": 3,
            "id": 2,
            "isDoubleLock": false,
            "isOutOfSync": false,
            "isRestricted": true,
            "items": [
                {
                    "fieldDescription": "The Server or Location of the Windows Machine.",
                    "fieldId": 83,
                    "fieldName": "Machine",
                    "fileAttachmentId": null,
                    "filename": null,
                    "isFile": false,
                    "isNotes": false,
                    "isPassword": false,
                    "itemId": 5,
                    "itemValue": "192.168.100.1",
                    "slug": "machine"
                },
                {
                    "fieldDescription": "The Username of the Windows User.",
                    "fieldId": 86,
                    "fieldName": "Username",
                    "fileAttachmentId": null,
                    "filename": null,
                    "isFile": false,
                    "isNotes": false,
                    "isPassword": false,
                    "itemId": 6,
                    "itemValue": "w2\\w2",
                    "slug": "username"
                },
                {
                    "fieldDescription": "The password of the Windows User.",
                    "fieldId": 85,
                    "fieldName": "Password",
                    "fileAttachmentId": null,
                    "filename": null,
                    "isFile": false,
                    "isNotes": false,
                    "isPassword": true,
                    "itemId": 7,
                    "itemValue": "1234567890",
                    "slug": "password"
                },
                {
                    "fieldDescription": "Any additional notes.",
                    "fieldId": 84,
                    "fieldName": "Notes",
                    "fileAttachmentId": null,
                    "filename": null,
                    "isFile": false,
                    "isNotes": true,
                    "isPassword": false,
                    "itemId": 8,
                    "itemValue": "",
                    "slug": "notes"
                }
            ],
            "lastHeartBeatCheck": "0001-01-01T00:00:00",
            "lastHeartBeatStatus": "Pending",
            "lastPasswordChangeAttempt": "0001-01-01T00:00:00",
            "launcherConnectAsSecretId": -1,
            "name": "test-w2",
            "outOfSyncReason": "",
            "passwordTypeWebScriptId": -1,
            "proxyEnabled": false,
            "requiresApprovalForAccess": false,
            "requiresComment": false,
            "responseCodes": [],
            "restrictSshCommands": false,
            "secretPolicyId": -1,
            "secretTemplateId": 6003,
            "secretTemplateName": "Windows Account",
            "sessionRecordingEnabled": false,
            "siteId": 1
        }
    }
}
```


### delinea-secret-search
***
Search secret ID by multiply params


#### Base Command

`delinea-secret-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter.allowDoubleLocks | Whether to allow DoubleLocks as part of the search. True by default | Optional | 
| filter.doNotCalculateTotal | Whether to return the total number of secrets matching the filters. False by default | Optional | 
| filter.doubleLockId | Only include Secrets with this DoubleLock ID assigned in the search results | Optional | 
| filter.extendedFields | Names of Secret Template fields to return. Only exposed fields can be returned. | Optional | 
| filter.extendedTypeId | Return only secrets matching a certain extended type | Optional | 
| filter.folderId | Return only secrets within a certain folder | Optional | 
| filter.heartbeatStatus | Return only secrets with a certain heartbeat status | Optional | 
| filter.includeActive | Whether to include active secrets in results (when excluded equals true) | Optional | 
| filter.includeInactive | Whether to include inactive secrets in results | Optional | 
| filter.includeRestricted | Whether to include restricted secrets in results		 | Optional | 
| filter.isExactMatch | Whether to do an exact match of the search text or a partial match | Optional | 
| filter.onlyRPCEnabled | Whether to only include secrets whose template has Remote Password Changing enabled | Optional | 
| filter.onlySharedWithMe | When true only Secrets where you are not the owner and the Secret was shared explicitly with your user id will be returned. | Optional | 
| filter.passwordTypeIds | Return only secrets matching certain password types | Optional | 
| filter.permissionRequired | Specify whether to filter by List, View, Edit, or Owner permission. Default is List. (List = 1, View = 2, Edit = 3, Owner = 4 | Optional | 
| filter.scope | Specify whether to search AllSecrets, Recent, or Favorites (All = 1, Recent = 2,Favorites = 3 | Optional | 
| filter.searchField | Field to search | Optional | 
| filter.searchFieldSlug | Field-slug to search. This will override SearchField. | Optional | 
| filter.searchText | Search text | Optional | 
| filter.secretTemplateId | Return only secrets matching a certain template | Optional | 
| filter.siteId | Return only secrets within a certain site | Optional | 
| skip | Number of records to skip before taking results | Optional | 
| sortBy[0].direction | Sort direction | Optional | 
| sortBy[0].name | Sort field name | Optional | 
| sortBy[0].priority | Priority index. Sorts with lower values are executed earlier | Optional | 
| take | Maximum number of records to include in results | Optional | 
| filter.includeSubFolders | Whether to include secrets in subfolders of the specified folder | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Secret | String | Search secret object | 


#### Command Example
```!delinea-user-search filter_searchfields="username" filter_searchtext="xsoar"```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Secret": [
                5
            ]
        }
    }
}
```



### delinea-folder-update
***
Update a single secret folder by ID


#### Base Command

`delinea-folder-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folderName | Folder name | Optional | 
| folderTypeId | Folder type ID | Optional | 
| id | Folder ID. Must match ID in path | Required | 
| inheritPermissions | Whether the folder inherits permissions from its parent | Optional | 
| inheritSecretPolicy | Whether the folder inherits the secret policy | Optional | 
| parentFolderId | ID parent folder | Optional | 
| secretPolicyId | Secret Policy ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Folder.Update | String | Retrieved return operation update folder | 


#### Command Example
```!delinea-folder-update id=4 foldername="SafexsoarTest"```

#### Context Example
```json
{
    "Delinea": {
        "Folder": {
            "Update": {
                "childFolders": null,
                "folderName": "SafexsoarTest",
                "folderPath": "\\Personal Folders\\XSOAR integration\\SafexsoarTest",
                "folderTypeId": 1,
                "id": 4,
                "inheritPermissions": false,
                "inheritSecretPolicy": false,
                "parentFolderId": 3,
                "secretPolicyId": -1,
                "secretTemplates": null
            }
        }
    }
}
```


### delinea-secret-create
***
Create new object Secret


#### Base Command

`delinea-secret-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| autoChangeEnabled | AutoChangeEnabled options | Optional | 
| checkOutChangePasswordEnabled | CheckOutChangePasswordEnabled options | Optional | 
| checkOutEnabled | Whether secret checkout is enabled | Optional | 
| checkOutIntervalMinutes | Checkout interval, in minutes (integer) | Optional | 
| enableInheritPermissions | Whether the secret inherits permissions from the containing folder | Optional | 
| enableInheritSecretPolicy | Whether the secret policy is inherited from the containing folder | Optional | 
| folderId | Secret folder ID. May be null unless secrets are required to be in folders.(integer) | Optional | 
| launcherConnectAsSecretId | LauncherConnectAsSecretId(integer) | Optional | 
| name | Secret name | Required | 
| passwordTypeWebScriptId | passwordTypeWebScriptId options(integer) | Optional | 
| proxyEnabled | proxyEnabled options | Optional | 
| requiresCommen | requiresCommen options | Optional | 
| secretPolicyId | secretPolicyId options(integer) | Optional | 
| secretTemplateId | Secret Template ID (integer) | Required | 
| sessionRecordingEnabled | sessionRecordingEnabled options | Optional | 
| siteId | siteId options (integer) | Required | 
| sshKeyArgs | sshKeyArgs options(list args) | Optional | 
| domain_item | Item Domain for secret. If need to select template. | Optional | 
| machine_item | Item Machine for secret. If need to select template. | Optional | 
| username_item | Item Username for secret.If need to select template. | Optional | 
| password_item | Item Password for secret.If need to select template. | Optional | 
| notes_item | Item Notes for secret.IF  need to select template. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Create | String | Secret Model | 


#### Command Example
```!delinea-secret-create name="xsoarSecret" secrettemplateid="6003" siteid="1" checkoutenabled=true folderid=3 machine_item="my-machine" username_item="my-username" password_item="XXXXXX@@@@@####"```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Create": {
                "accessRequestWorkflowMapId": -1,
                "active": true,
                "allowOwnersUnrestrictedSshCommands": false,
                "autoChangeEnabled": false,
                "autoChangeNextPassword": null,
                "checkOutChangePasswordEnabled": false,
                "checkOutEnabled": true,
                "checkOutIntervalMinutes": -1,
                "checkOutMinutesRemaining": 0,
                "checkOutUserDisplayName": "",
                "checkOutUserId": 0,
                "checkedOut": false,
                "doubleLockId": 0,
                "enableInheritPermissions": true,
                "enableInheritSecretPolicy": false,
                "failedPasswordChangeAttempts": 0,
                "folderId": 3,
                "id": 5,
                "isDoubleLock": false,
                "isOutOfSync": false,
                "isRestricted": true,
                "items": [
                    {
                        "fieldDescription": "The Server or Location of the Windows Machine.",
                        "fieldId": 83,
                        "fieldName": "Machine",
                        "fileAttachmentId": null,
                        "filename": null,
                        "isFile": false,
                        "isNotes": false,
                        "isPassword": false,
                        "itemId": 19,
                        "itemValue": "my-machine",
                        "slug": "machine"
                    },
                    {
                        "fieldDescription": "The Username of the Windows User.",
                        "fieldId": 86,
                        "fieldName": "Username",
                        "fileAttachmentId": null,
                        "filename": null,
                        "isFile": false,
                        "isNotes": false,
                        "isPassword": false,
                        "itemId": 20,
                        "itemValue": "my-username",
                        "slug": "username"
                    },
                    {
                        "fieldDescription": "The password of the Windows User.",
                        "fieldId": 85,
                        "fieldName": "Password",
                        "fileAttachmentId": null,
                        "filename": null,
                        "isFile": false,
                        "isNotes": false,
                        "isPassword": true,
                        "itemId": 21,
                        "itemValue": "XXXXXX@@@@@####",
                        "slug": "password"
                    },
                    {
                        "fieldDescription": "Any additional notes.",
                        "fieldId": 84,
                        "fieldName": "Notes",
                        "fileAttachmentId": null,
                        "filename": null,
                        "isFile": false,
                        "isNotes": true,
                        "isPassword": false,
                        "itemId": 22,
                        "itemValue": "",
                        "slug": "notes"
                    }
                ],
                "lastHeartBeatCheck": "0001-01-01T00:00:00",
                "lastHeartBeatStatus": "Pending",
                "lastPasswordChangeAttempt": "0001-01-01T00:00:00",
                "launcherConnectAsSecretId": -1,
                "name": "xsoarSecret",
                "outOfSyncReason": "",
                "passwordTypeWebScriptId": -1,
                "proxyEnabled": false,
                "requiresApprovalForAccess": false,
                "requiresComment": false,
                "responseCodes": [],
                "restrictSshCommands": false,
                "secretPolicyId": -1,
                "secretTemplateId": 6003,
                "secretTemplateName": "Windows Account",
                "sessionRecordingEnabled": false,
                "siteId": 1
            }
        }
    }
}
```


### delinea-secret-delete
***
Delete secret


#### Base Command

`delinea-secret-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID secret for delete | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.Delete | String | Information about an object that was deleted | 


#### Command Example
```!delinea-secret-delete id=2```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "Deleted": {
                "id": 2,
                "objectType": "Secret",
                "responseCodes": []
            }
        }
    }
}
```


### delinea-user-create
***
Create a new user


#### Base Command

`delinea-user-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| displayName | User display name | Required | 
| password | Password for new user | Required | 
| userName | Username | Required | 
| adGuid | Active Directory unique identifier | Optional | 
| domainId | Active Directory domain ID | Optional | 
| duoTwoFactor | Whether Duo two-factor authentication is enabled | Optional | 
| emailAddress | User email address | Optional | 
| enabled | Whether the user account is enabled | Optional | 
| fido2TwoFactor | Whether Duo two-factor authentication is enabled | Optional | 
| isApplicationAccount | IsApplicationAccount | Optional | 
| oathTwoFactor | Whether OATH two-factor authentication is enabled | Optional | 
| radiusTwoFactor | Whether RADIUS two-factor authentication is enabled | Optional | 
| radiusUserName | RADIUS username | Optional | 
| twoFactor | Whether two-factor authentication is enabled | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.User.Create | String | User Model | 


#### Command Example
```!delinea-user-create displayname="UserOne" password="12345" username="UserOne" ```

#### Context Example
```json
{
    "Delinea": {
        "User": {
            "Create": {
            		"adAccountExpires":"0001-01-01T00:00:00",
					"adGuid":null,
					"created":"2022-06-01T08:31:15.275Z",
					"dateOptionId":-1,
					"displayName":"UserOne",
					"domainId":-1,
					"duoTwoFactor":false,
					"emailAddress":null,
					"enabled":true,
					"externalUserSource":"None",
					"fido2TwoFactor":false,
					"id":29,
					"ipAddressRestrictions":null,
					"isApplicationAccount":false,
					"isEmailCopiedFromAD":false,
					"isEmailVerified":false,
					"isLockedOut":false,
					"lastLogin":0001-01-01T00:00:00,
					"lastSessionActivity":null,
					"lockOutReason":null,
					"lockOutReasonDescription":null,
					"loginFailures":0,
					"mustVerifyEmail":false,
					"oathTwoFactor":false,
					"oathVerified":false,
					"passwordLastChanged":"0001-01-01T00:00:00",
					"personalGroupId":0,
					"radiusTwoFactor":false,
					"radiusUserName":null,
					"resetSessionStarted":"0001-01-01T00:00:00",
					"slackId":null,
					"timeOptionId":-1,
					"twoFactor":false,
					"unixAuthenticationMethod":Password,
					"userLcid":0,
					"userName":"UserOne",
					"verifyEmailSentDate":"0001-01-01T00:00:00"
            }
        }
    }
}

```

### delinea-user-search
***
Search, filter, sort, and page users


#### Base Command

`delinea-user-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter.domainId | Filter users by Active Directory domain (integer) | Optional | 
| filter.includeInactive | Whether to include inactive users in the results | Optional | 
| filter.searchFields | Fields to search | Optional | 
| filter.searchText | Search text | Optional | 
| skip | Number of records to skip before taking results | Optional | 
| sortBy[0].direction | Sort direction | Optional | 
| sortBy[0].name | Sort field name | Optional | 
| sortBy[0].priority | Priority index. Sorts with lower values are executed earlier (integer) | Optional | 
| take | Maximum number of records to include in results(integer) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.User.Search | String | Specify paging and sorting options for querying records and returning results | 


#### Command Example
```!delinea-user-search filter_searchfields="userName" filter_searchtext="xsoarUser"```

#### Context Example
```json
{
    "Delinea": {
        "User": {
            "Search": null
        }
    }
}
```


### delinea-user-update
***
Update a single user by ID


#### Base Command

`delinea-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID | Required | 
| dateOptionId | DateOptionId(integer) | Optional | 
| displayName | Display name | Optional | 
| duoTwoFactor | Whether Duo two-factor authentication is enabled | Optional | 
| emailAddress | E-mail | Optional | 
| enabled | Whether the user account is enabled | Optional | 
| fido2TwoFactor | Whether FIDO2 two-factor authentication is enabled | Optional | 
| groupOwners | GroupOwners(integer) | Optional | 
| isApplicationAccount | IsApplicationAccount | Optional | 
| isGroupOwnerUpdate | isGroupOwnerUpdate | Optional | 
| isLockedOut | Whether the user is locked out | Optional | 
| loginFailures | Number of login failures | Optional | 
| oathTwoFactor | Whether OATH two-factor authentication is enabled | Optional | 
| password | Password | Optional | 
| radiusTwoFactor | Whether RADIUS two-factor authentication is enabled | Optional | 
| radiusUserName | RADIUS username | Optional | 
| timeOptionId | timeOptionId (integer) | Optional | 
| twoFactor | Whether two-factor authentication is enabled | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.User.Update | String | User Model | 


#### Command Example
```!delinea-user-update id=28 displayname="myTestUser"```

#### Context Example
```json
{
    "Delinea": {
        "User": {
            "Update": {
            		"unixAuthenticationMethod":"Password",
					"enabled":true,
					"passwordLastChanged":"0001-01-01T00:00:00",
					"isEmailCopiedFromAD":false,
					"isApplicationAccount":false,
					"lockOutReason":null,
					"created":"2022-06-01T08:09:39",
					"radiusUserName":"UserOne",
					"radiusTwoFactor":false,
					"verifyEmailSentDate":"0001-01-01T00:00:00",
					"adAccountExpires":"0001-01-01T00:00:00",
					"slackId":null,
					"adGuid":null,
					"displayName":"myTestUser",
					"oathVerified":false,
					"lastSessionActivity":null,
					"externalUserSource":"None",
					"loginFailures":0,
					"lastLogin":"0001-01-01T00:00:00",
					"ipAddressRestrictions":null,
					"oathTwoFactor":false,
					"lockOutReasonDescription":null,
					"userName":"UserOne",
					"fido2TwoFactor":false,
					"emailAddress":null,
					"resetSessionStarted":"0001-01-01T00:00:00",
					"mustVerifyEmail":false,
					"isEmailVerified":false,
					"personalGroupId":0,
					"isLockedOut":false,
					"id":28,
					"twoFactor":false,
					"duoTwoFactor":false,
					"timeOptionId":-1,
					"userLcid":0,
					"dateOptionId":-1,
					"domainId":-1,
            }
        }
    }
}

```


### delinea-user-delete
***
Delete a user by ID


#### Base Command

`delinea-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.User.Delete | String | Information about an object that was deleted | 


#### Command Example
```!delinea-user-delete id=5 ```

#### Context Example
```json
{
    "Delinea": {
        "User": {
            "Delete": {
                "id": 5,
                "objectType": "User",
                "responseCodes": null
            }
        }
    }
}
```

### delinea-secret-rpc-changepassword
***
Change a secret's password


#### Base Command

`delinea-secret-rpc-changepassword`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | Secret ID | Required | 
| newPassword | New secret password | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.Secret.ChangePassword | String | Secret summary object | 


#### Command Example
```!delinea-secret-rpc-changepassword secret_id=4 newPassword="Test000"```

#### Context Example
```json
{
    "Delinea": {
        "Secret": {
            "ChangePassword": {
                "active": true,
                "autoChangeEnabled": false,
                "checkOutEnabled": false,
                "checkedOut": false,
                "createDate": "2020-11-02T18:06:07.357",
                "daysUntilExpiration": null,
                "doubleLockEnabled": false,
                "extendedFields": null,
                "folderId": -1,
                "hidePassword": false,
                "id": 4,
                "inheritsPermissions": false,
                "isOutOfSync": false,
                "isRestricted": false,
                "lastAccessed": null,
                "lastHeartBeatStatus": "Success",
                "lastPasswordChangeAttempt": "0001-01-01T00:00:00",
                "name": "g1-machine",
                "outOfSyncReason": "",
                "requiresApproval": false,
                "requiresComment": false,
                "responseCodes": null,
                "secretTemplateId": 6007,
                "secretTemplateName": "Unix Account (SSH)",
                "siteId": 1
            }
        }
    }
}
```

### delinea-fetch-users
***
Fetch credentials from secret


#### Base Command

`delinea-fetch-users`
#### Input
NO input argumets


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Delinea.User.Credentials | String | Secret credential objects | 


#### Command Example
```!delinea-fetch-users```

#### Context Example
```json
[
    {
        "name": "4219",
        "password": "test3",
        "user": "test3"
    },
    {
        "name": "4217",
        "password": "dhPQhf1d@!E",
        "user": "secret2"
    }
]
```