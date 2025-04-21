Integrate with Oracle Identity Access Management service to execute CRUD (create, read, update, and delete) operations for employee lifecycle processes.

## What does this pack do?
- Create a user.
- Retrieve the details of an existing user.
- Update an existing user.
- Disable an active user.
- Create an empty group.
- Retrieve the information for a group including its members.
- Permanently remove a group.
- Updates an existing group resource.

For more information, refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure OracleIAM in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base URL | True |
| Username | True |
| Password | True |
| Allow creating users | False |
| Allow updating users | False |
| Allow enabling users | False |
| Allow disabling users | False |
| Automatically create user if not found in update command | False |
| Incoming Mapper | True |
| Outgoing Mapper | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iam-create-user
***
Creates a user.


#### Base Command

`iam-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | User Profile indicator details. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-create-user user-profile={"username": "test user name", "email": "john.doe@example.com", "givenname": "test", "surname": "test", "displayname": "test"}```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "displayname": "test",
            "email": "john.doe@example.com",
            "givenname": "test",
            "surname": "test",
            "username": "test user name"
        },
        "Vendor": {
            "action": "create",
            "active": true,
            "brand": "OracleIAM",
            "details": {
                "active": true,
                "displayName": "test test",
                "emails": [
                    {
                        "primary": false,
                        "secondary": false,
                        "type": "recovery",
                        "value": "john.doe@example.com",
                        "verified": false
                    },
                    {
                        "primary": true,
                        "secondary": false,
                        "type": "work",
                        "value": "john.doe@example.com",
                        "verified": false
                    }
                ],
                "id": "123456",
                "idcsCreatedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "idcsLastModifiedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "meta": {
                    "created": "2021-08-23T08:00:58.029Z",
                    "lastModified": "2021-08-23T08:00:58.029Z",
                    "location": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "resourceType": "User",
                    "version": "1234"
                },
                "name": {
                    "familyName": "test",
                    "formatted": "test test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User"
                ],
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User": {
                    "isFederatedUser": false
                },
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User": {
                    "locked": {
                        "on": false
                    }
                },
                "userName": "test user name"
            },
            "email": "john.doe@example.com",
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "OracleIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test user name"
        }
    }
}
```

#### Human Readable Output

>### Create User Results (OracleIAM)
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| OracleIAM | OracleIAM_instance_1 | true | true | 123456 | test user name | john.doe@example.com | idcsCreatedBy: {"type": "App", "display": "Test", "value": "123456", "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456"} |


### iam-get-user
***
Retrieves a single user resource.


#### Base Command

`iam-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-get-user user-profile={"username": "test user name"}```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "Email": "john.doe@example.com",
            "Given Name": "test",
            "Surname": "test",
            "Username": "test user name"
        },
        "Vendor": {
            "action": "get",
            "active": true,
            "brand": "OracleIAM",
            "details": {
                "active": true,
                "displayName": "test test",
                "emails": [
                    {
                        "primary": false,
                        "secondary": false,
                        "type": "recovery",
                        "value": "john.doe@example.com",
                        "verified": false
                    },
                    {
                        "primary": true,
                        "secondary": false,
                        "type": "work",
                        "value": "john.doe@example.com",
                        "verified": false
                    }
                ],
                "id": "123456",
                "idcsCreatedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "idcsLastModifiedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "meta": {
                    "created": "2021-08-23T08:00:58.029Z",
                    "lastModified": "2021-08-23T08:00:58.029Z",
                    "location": "https://test.identity.oraclecloud.com:443/admin/v1/Users/123456",
                    "resourceType": "User",
                    "version": "123456"
                },
                "name": {
                    "familyName": "test",
                    "formatted": "test test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User"
                ],
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User": {
                    "isFederatedUser": false
                },
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User": {
                    "locked": {
                        "on": false
                    }
                },
                "userName": "test user name"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "OracleIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test user name"
        }
    }
}
```

#### Human Readable Output

>### Get User Results (OracleIAM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| OracleIAM | OracleIAM_instance_1 | true | true | 123456 | test user name | idcsCreatedBy: {"type": "App", "display": "Palo", "value": "123456", "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456"} |


### iam-update-user
***
Updates an existing user with the data passed in the user-profile argument.


#### Base Command

`iam-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-update-user user-profile=`{"username": "test user name"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "username": "test user name"
        },
        "Vendor": {
            "action": "update",
            "active": true,
            "brand": "OracleIAM",
            "details": {
                "active": true,
                "displayName": "test test",
                "emails": [
                    {
                        "primary": false,
                        "secondary": false,
                        "type": "recovery",
                        "value": "john.doe@example.com",
                        "verified": false
                    },
                    {
                        "primary": true,
                        "secondary": false,
                        "type": "work",
                        "value": "john.doe@example.com",
                        "verified": false
                    }
                ],
                "id": "7611ff137b37449abb1337925c891283",
                "idcsCreatedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "idcsLastModifiedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "meta": {
                    "created": "2021-08-23T08:00:58.029Z",
                    "lastModified": "2021-08-23T08:01:06.948Z",
                    "location": "https://test.identity.oraclecloud.com:443/admin/v1/Users/123456",
                    "resourceType": "User",
                    "version": "123456"
                },
                "name": {
                    "familyName": "test",
                    "formatted": "test test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User"
                ],
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User": {
                    "isFederatedUser": false
                },
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User": {
                    "locked": {
                        "on": false
                    }
                },
                "userName": "test user name"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "OracleIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test user name"
        }
    }
}
```

#### Human Readable Output

>### Update User Results (OracleIAM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| OracleIAM | OracleIAM_instance_1 | true | true | 123456 | test user name | idcsCreatedBy: {"type": "App", "display": "Palo", "value": "123456", "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456"} |


### iam-disable-user
***
Disable an active user.


#### Base Command

`iam-disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-disable-user user-profile=`{"username": "test user name"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "username": "test user name"
        },
        "Vendor": {
            "action": "disable",
            "active": false,
            "brand": "OracleIAM",
            "details": {
                "active": false,
                "displayName": "test test",
                "emails": [
                    {
                        "primary": false,
                        "secondary": false,
                        "type": "recovery",
                        "value": "john.doe@example.com",
                        "verified": false
                    },
                    {
                        "primary": true,
                        "secondary": false,
                        "type": "work",
                        "value": "john.doe@example.com",
                        "verified": false
                    }
                ],
                "id": "123456",
                "idcsCreatedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "idcsLastModifiedBy": {
                    "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456",
                    "display": "Test",
                    "type": "App",
                    "value": "123456"
                },
                "meta": {
                    "created": "2021-08-23T08:00:58.029Z",
                    "lastModified": "2021-08-23T08:01:03.884Z",
                    "location": "https://test.identity.oraclecloud.com:443/admin/v1/Users/123456",
                    "resourceType": "User",
                    "version": "123456"
                },
                "name": {
                    "familyName": "test",
                    "formatted": "test test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User"
                ],
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User": {
                    "isFederatedUser": false
                },
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User": {
                    "locked": {
                        "on": false
                    }
                },
                "userName": "test user name"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "OracleIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test user name"
        }
    }
}
```

#### Human Readable Output

>### Disable User Results (OracleIAM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| OracleIAM | OracleIAM_instance_1 | true | false | 123456 | test user name | idcsCreatedBy: {"type": "App", "display": "Palo", "value": "123456", "$ref": "https://test.identity.oraclecloud.com:443/admin/v1/Apps/123456"} |


### iam-create-group
***
Creates an empty group


#### Base Command

`iam-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM data with the display name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateGroup.id | String | Group ID | 
| CreateGroup.displayName | String | Display name of the group. | 
| CreateGroup.success | Boolean | Success status of the command. | 
| CreateGroup.errorCode | Number | Error code if there is a failure. | 
| CreateGroup.errorMessage | Unknown | Error details if there is a failure. | 


#### Command Example
```!iam-create-group scim=`{"displayName": "The Best Group"}````

#### Context Example
```json
{
    "CreateGroup": {
        "brand": "OracleIAM",
        "displayName": "The Best Group",
        "id": "111111",
        "instanceName": "OracleIAM_instance_1",
        "success": true
    }
}
```

#### Human Readable Output

>### Oracle Cloud Create Group:
>|brand|displayName|id|instanceName|success|
>|---|---|---|---|---|
>| OracleIAM | The Best Group | 111111 | OracleIAM_instance_1 | true |


### iam-get-group
***
Retrieves the group information including members


#### Base Command

`iam-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM data. | Required | 
| includeMembers | Whether members need to be included in the response. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetGroup.id | String | Group ID. | 
| GetGroup.displayName | String | Display name of the group. | 
| GetGroup.members.display | String | Display name of the group member. | 
| GetGroup.members.value | String | ID of the group member. | 
| GetGroup.success | Boolean | Success status of the command. | 
| GetGroup.errorCode | Number | Error code if there is a failure. | 
| GetGroup.errorMessage | Unknown | Error details if there is a failure. | 


#### Command Example
```!iam-get-group scim=`{"id": "121212"}````

#### Context Example
```json
{
    "GetGroup": {
        "brand": "OracleIAM",
        "displayName": "New Group",
        "id": "121212",
        "instanceName": "OracleIAM_instance_1",
        "success": true
    }
}
```

#### Human Readable Output

>### Oracle Cloud Get Group:
>|brand|displayName|id|instanceName|success|
>|---|---|---|---|---|
>| OracleIAM | New Group | 121212 | OracleIAM_instance_1 | true |


### iam-delete-group
***
Permanently removes a group.


#### Base Command

`iam-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM with ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeleteGroup.id | String | Group ID. | 
| DeleteGroup.displayName | String | Display name of the group. | 
| DeleteGroup.success | Boolean | Success status of the command. | 
| DeleteGroup.errorCode | Number | Error code if there is a failure. | 
| DeleteGroup.errorMessage | Unknown | Error details if there is a failure. | 


#### Command Example
```!iam-delete-group scim={"id": "121212"}```

#### Context Example
```json
{
    "DeleteGroup": {
        "brand": "OracleIAM",
        "id": "121212",
        "instanceName": "OracleIAM_instance_1",
        "success": true
    }
}
```

#### Human Readable Output

>### Oracle Cloud Delete Group:
>|brand|id|instanceName|success|
>|---|---|---|---|
>| OracleIAM | 121212 | OracleIAM_instance_1 | true |


### iam-update-group
***
Updates an existing group resource. This command allows individual (or groups of) users to be added or removed from the group with a single operation. A maximum of 15,000 users can be modified in a single call.


#### Base Command

`iam-update-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM data. | Required | 
| memberIdsToAdd | List of members IDs to add. A maximum of 15,000 users per call can be modified using this command. | Optional | 
| memberIdsToDelete | List of members IDs to be deleted from the group. A maximum of 15,000 users per call can be modified using this command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateGroup.id | String | Group ID. | 
| UpdateGroup.displayName | String | Display name of the group. | 
| UpdateGroup.success | Boolean | Success status of the command. | 
| UpdateGroup.errorCode | Number | Error code if there is a failure. | 
| UpdateGroup.errorMessage | Unknown | Error details if there is a failure. | 


#### Command Example
```!iam-update-group scim={"id": "121212"} memberIdsToAdd=["123456"]```

#### Context Example
```json
{
    "UpdateGroup": {
        "brand": "OracleIAM",
        "id": "121212",
        "instanceName": "OracleIAM_instance_1",
        "success": true
    }
}
```

#### Human Readable Output

>### Oracle Cloud Update Group:
>|brand|id|instanceName|success|
>|---|---|---|---|
>| OracleIAM | 121212 | OracleIAM_instance_1 | true |