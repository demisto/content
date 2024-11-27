Secret Server is the only fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. It empowers security and IT ops teams to secure and manage all types of privileged accounts and offers the fastest time to value of any PAM solution.
This integration was integrated and tested with version 5.0 of Thycotic
## Configure Thycotic in Cortex


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
### thycotic-secret-password-get
***
Retrieved password from secret


#### Base Command

`thycotic-secret-password-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Password | String | Retrieved password from secret  | 


#### Command Example
```!thycotic-secret-password-get secret_id=2```

#### Context Example
```json
{
    "Thycotic": {
        "Secret": {
            "Password": "1234567890"
        }
    }
}
```

#### Human Readable Output

>Retrieved password by ID 2 1234567890

### thycotic-secret-username-get
***
Retrieved username from secret


#### Base Command

`thycotic-secret-username-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Username | String | Retrieved username from secret. | 


#### Command Example
```!thycotic-secret-username-get secret_id=2```

#### Context Example
```json
{
    "Thycotic": {
        "Secret": {
            "Username": "w2\\w2"
        }
    }
}
```

#### Human Readable Output

>Retrieved username by ID 2 w2\w2

### thycotic-secret-search-name
***
Search ID secret by field name


#### Base Command

`thycotic-secret-search-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | Search name secret. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Id | String | Retrieved list ID for find secret by field secret name | 


#### Command Example
```!thycotic-secret-search-name search_name=xsoarSecret```

#### Context Example
```json
{
    "Thycotic": {
        "Secret": {
            "Id": [
                5
            ]
        }
    }
}
```

#### Human Readable Output

>Retrieved list ID for search by secret name = xsoarSecret
>List ID:
>5

### thycotic-secret-password-update
***
Update password for secret


#### Base Command

`thycotic-secret-password-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret for update  password | Required | 
| newpassword | Value new password for secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Newpassword | String | New password changed for secret | 


#### Command Example
```!thycotic-secret-password-update secret_id=2 newpassword=12345```

#### Context Example
```json
{
    "Thycotic": {
        "Secret": {
            "Newpassword": "12345"
        }
    }
}
```

#### Human Readable Output

>Set new password for secret ID 2, set 12345

### thycotic-secret-checkout
***
Check Out a secret


#### Base Command

`thycotic-secret-checkout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret for check out command | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Checkout | String | Return call command Check Out | 


#### Command Example
```!thycotic-secret-checkout secret_id=2```

#### Context Example
```json
{}
```

#### Human Readable Output

>Check Out for secret ID 2, ResponseCode - None

### thycotic-secret-checkin
***
Check In a secret


#### Base Command

`thycotic-secret-checkin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | Secret ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Checkin | String | Secret object | 


#### Command Example
```!thycotic-secret-checkin secret_id=13```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>Check In for secret ID=13. CheckOut = False


### thycotic-folder-create
***
Create a new secret folder


#### Base Command

`thycotic-folder-create`
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
| Thycotic.Folder.Create | Unknown | New object folder | 


#### Command Example
```!thycotic-folder-create foldername="xsoarFolderTest" foldertypeid="1" parentfolderid="3"```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>Create new folder - xsoarFolderTest

### thycotic-folder-search
***
Search folder by name folder


#### Base Command

`thycotic-folder-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| foldername | Search name folder | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Folder.Id | String | Retrieved folder ID from search query | 


#### Command Example
```!thycotic-folder-search foldername="xsoarFolderTest"```

#### Context Example
```json
{
    "Thycotic": {
        "Folder": {
            "Id": [
                5
            ]
        }
    }
}
```

#### Human Readable Output

>Retrieved list ID for folder by folder name = xsoarFolderTest
>List ID:
>5

#### Command Example
```!thycotic-folder-delete folder_id="18"```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>Deleted folder ID: 18

### thycotic-secret-get
***
Get secret object by ID secret


#### Base Command

`thycotic-secret-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID for secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret | String | Secret object | 


#### Command Example
```!thycotic-secret-get secret_id=2```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>Secret object by ID 2
>{'id': 2, 'name': 'test-w2', 'secretTemplateId': 6003, 'folderId': 3, 'active': True, 'items': [{'itemId': 5, 'fileAttachmentId': None, 'filename': None, 'itemValue': '192.168.100.1', 'fieldId': 83, 'fieldName': 'Machine', 'slug': 'machine', 'fieldDescription': 'The Server or Location of the Windows Machine.', 'isFile': False, 'isNotes': False, 'isPassword': False}, {'itemId': 6, 'fileAttachmentId': None, 'filename': None, 'itemValue': 'w2\\w2', 'fieldId': 86, 'fieldName': 'Username', 'slug': 'username', 'fieldDescription': 'The Username of the Windows User.', 'isFile': False, 'isNotes': False, 'isPassword': False}, {'itemId': 7, 'fileAttachmentId': None, 'filename': None, 'itemValue': '1234567890', 'fieldId': 85, 'fieldName': 'Password', 'slug': 'password', 'fieldDescription': 'The password of the Windows User.', 'isFile': False, 'isNotes': False, 'isPassword': True}, {'itemId': 8, 'fileAttachmentId': None, 'filename': None, 'itemValue': '', 'fieldId': 84, 'fieldName': 'Notes', 'slug': 'notes', 'fieldDescription': 'Any additional notes.', 'isFile': False, 'isNotes': True, 'isPassword': False}], 'launcherConnectAsSecretId': -1, 'checkOutMinutesRemaining': 30, 'checkedOut': True, 'checkOutUserDisplayName': 'XSOAR integration', 'checkOutUserId': 3, 'isRestricted': True, 'isOutOfSync': False, 'outOfSyncReason': '', 'autoChangeEnabled': False, 'autoChangeNextPassword': '2$C$7vl8*SN@', 'requiresApprovalForAccess': False, 'requiresComment': False, 'checkOutEnabled': True, 'checkOutIntervalMinutes': -1, 'checkOutChangePasswordEnabled': False, 'accessRequestWorkflowMapId': -1, 'proxyEnabled': False, 'sessionRecordingEnabled': False, 'restrictSshCommands': False, 'allowOwnersUnrestrictedSshCommands': False, 'isDoubleLock': False, 'doubleLockId': -1, 'enableInheritPermissions': True, 'passwordTypeWebScriptId': -1, 'siteId': 1, 'enableInheritSecretPolicy': True, 'secretPolicyId': -1, 'lastHeartBeatStatus': 'Pending', 'lastHeartBeatCheck': '0001-01-01T00:00:00', 'failedPasswordChangeAttempts': 0, 'lastPasswordChangeAttempt': '0001-01-01T00:00:00', 'secretTemplateName': 'Windows Account', 'responseCodes': []}

### thycotic-secret-search
***
Search secret ID by multiply params


#### Base Command

`thycotic-secret-search`
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
| Thycotic.Secret.Secret | String | Search secret object | 


#### Command Example
```!thycotic-secret-search filter.folderId=3 filter.includeSubFolders=true filter.searchField=name filter.searchText=xsoar```

#### Context Example
```json
{
    "Thycotic": {
        "Secret": {
            "Secret": [
                5
            ]
        }
    }
}
```

#### Human Readable Output

>Search secret [5]

### thycotic-folder-update
***
Update a single secret folder by ID


#### Base Command

`thycotic-folder-update`
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
| Thycotic.Folder.Update | String | Retrieved return operation update folder | 


#### Command Example
```!thycotic-folder-update id=4 folderName="SafexsoarTest"```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>{'id': 4, 'folderName': 'SafexsoarTest', 'folderPath': '\\Personal Folders\\XSOAR integration\\SafexsoarTest', 'parentFolderId': 3, 'folderTypeId': 1, 'secretPolicyId': -1, 'inheritSecretPolicy': False, 'inheritPermissions': False, 'childFolders': None, 'secretTemplates': None}

### thycotic-secret-create
***
Create new object Secret


#### Base Command

`thycotic-secret-create`
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
| Thycotic.Secret.Create | String | Secret Model | 


#### Command Example
```!thycotic-secret-create name="xsoarSecret" secretTemplateId="6003" siteId="1" checkOutEnabled=true folderId=3 machine_item="my-machine" username_item="my-username" password_item="XXXXXX@@@@@####"```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>Create new secret with xsoarSecret,
> object - {'id': 5, 'name': 'xsoarSecret', 'secretTemplateId': 6003, 'folderId': 3, 'active': True, 'items': [{'itemId': 19, 'fileAttachmentId': None, 'filename': None, 'itemValue': 'my-machine', 'fieldId': 83, 'fieldName': 'Machine', 'slug': 'machine', 'fieldDescription': 'The Server or Location of the Windows Machine.', 'isFile': False, 'isNotes': False, 'isPassword': False}, {'itemId': 20, 'fileAttachmentId': None, 'filename': None, 'itemValue': 'my-username', 'fieldId': 86, 'fieldName': 'Username', 'slug': 'username', 'fieldDescription': 'The Username of the Windows User.', 'isFile': False, 'isNotes': False, 'isPassword': False}, {'itemId': 21, 'fileAttachmentId': None, 'filename': None, 'itemValue': 'XXXXXX@@@@@####', 'fieldId': 85, 'fieldName': 'Password', 'slug': 'password', 'fieldDescription': 'The password of the Windows User.', 'isFile': False, 'isNotes': False, 'isPassword': True}, {'itemId': 22, 'fileAttachmentId': None, 'filename': None, 'itemValue': '', 'fieldId': 84, 'fieldName': 'Notes', 'slug': 'notes', 'fieldDescription': 'Any additional notes.', 'isFile': False, 'isNotes': True, 'isPassword': False}], 'launcherConnectAsSecretId': -1, 'checkOutMinutesRemaining': 0, 'checkedOut': False, 'checkOutUserDisplayName': '', 'checkOutUserId': 0, 'isRestricted': True, 'isOutOfSync': False, 'outOfSyncReason': '', 'autoChangeEnabled': False, 'autoChangeNextPassword': None, 'requiresApprovalForAccess': False, 'requiresComment': False, 'checkOutEnabled': True, 'checkOutIntervalMinutes': -1, 'checkOutChangePasswordEnabled': False, 'accessRequestWorkflowMapId': -1, 'proxyEnabled': False, 'sessionRecordingEnabled': False, 'restrictSshCommands': False, 'allowOwnersUnrestrictedSshCommands': False, 'isDoubleLock': False, 'doubleLockId': 0, 'enableInheritPermissions': True, 'passwordTypeWebScriptId': -1, 'siteId': 1, 'enableInheritSecretPolicy': False, 'secretPolicyId': -1, 'lastHeartBeatStatus': 'Pending', 'lastHeartBeatCheck': '0001-01-01T00:00:00', 'failedPasswordChangeAttempts': 0, 'lastPasswordChangeAttempt': '0001-01-01T00:00:00', 'secretTemplateName': 'Windows Account', 'responseCodes': []}

### thycotic-secret-delete
***
Delete secret


#### Base Command

`thycotic-secret-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID secret for delete | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.Delete | String | Information about an object that was deleted | 


#### Command Example
```!thycotic-secret-delete id=2```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>Deleted secret ID:2

### thycotic-user-create
***
Create a new user


#### Base Command

`thycotic-user-create`
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
| Thycotic.User.Create | String | User Model | 


#### Command Example
``` ```

#### Human Readable Output



### thycotic-user-search
***
Search, filter, sort, and page users


#### Base Command

`thycotic-user-search`
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
| Thycotic.User.Search | String | Specify paging and sorting options for querying records and returning results | 


#### Command Example
```!thycotic-user-search filter.searchFields="userName" filter.searchText="xsoarUser"```

#### Context Example
```json
{
    "Thycotic": {
        "User": {
            "Search": null
        }
    }
}
```

#### Human Readable Output

>[]

### thycotic-user-update
***
Update a single user by ID


#### Base Command

`thycotic-user-update`
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
| Thycotic.User.Update | String | User Model | 


#### Command Example
``` ```

#### Human Readable Output



### thycotic-user-delete
***
Delete a user by ID


#### Base Command

`thycotic-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.User.Delete | String | Information about an object that was deleted | 


#### Command Example
``` ```

#### Human Readable Output



### thycotic-secret-rpc-changepassword
***
Change a secret's password


#### Base Command

`thycotic-secret-rpc-changepassword`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | Secret ID | Required | 
| newPassword | New secret password | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.Secret.ChangePassword | String | Secret summary object | 


#### Command Example
```!thycotic-secret-rpc-changepassword secret_id=4 newPassword="Test000"```

#### Context Example
```json
{
    "Thycotic": {
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

#### Human Readable Output

>{'id': 4, 'name': 'g1-machine', 'secretTemplateId': 6007, 'secretTemplateName': 'Unix Account (SSH)', 'folderId': -1, 'siteId': 1, 'active': True, 'checkedOut': False, 'isRestricted': False, 'isOutOfSync': False, 'outOfSyncReason': '', 'lastHeartBeatStatus': 'Success', 'lastPasswordChangeAttempt': '0001-01-01T00:00:00', 'responseCodes': None, 'lastAccessed': None, 'extendedFields': None, 'checkOutEnabled': False, 'autoChangeEnabled': False, 'doubleLockEnabled': False, 'requiresApproval': False, 'requiresComment': False, 'inheritsPermissions': False, 'hidePassword': False, 'createDate': '2020-11-02T18:06:07.357', 'daysUntilExpiration': None}