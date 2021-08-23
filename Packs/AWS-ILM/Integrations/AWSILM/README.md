An Identity and Access Management integration template.
This integration was integrated and tested with version xx of AWS-ILM

## Configure AWS-ILM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS-ILM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Base URL | True |
    | Tenant ID | True |
    | Authentication Token | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Allow creating users | False |
    | Allow updating users | False |
    | Allow enabling users | False |
    | Allow disabling users | False |
    | Automatically create user if not found in update command | False |
    | Incoming Mapper | True |
    | Outgoing Mapper | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
```!iam-create-user user-profile={"email": "john.doe@example.com", "username": "test", "givenname": "test", "surname": "test", "displayname": "test"}```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "displayname": "test",
            "email": "john.doe@example.com",
            "givenname": "test",
            "surname": "test",
            "username": "test"
        },
        "Vendor": {
            "action": "create",
            "active": false,
            "brand": "AWS-ILM",
            "details": {
                "active": false,
                "displayName": "test",
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "john.doe@example.com"
                    }
                ],
                "id": "123456",
                "meta": {
                    "created": "2021-08-23T12:53:51Z",
                    "lastModified": "2021-08-23T12:53:51Z",
                    "resourceType": "User"
                },
                "name": {
                    "familyName": "test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "userName": "test"
            },
            "email": "john.doe@example.com",
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "AWS-ILM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test"
        }
    }
}
```

#### Human Readable Output

>### Create User Results (AWS-ILM)
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| AWS-ILM | AWS-ILM_instance_1 | true | false | 123456 | test | john.doe@example.com | id: 123456<br/>meta: {"resourceType": "User", "created": "2021-08-23T12:53:51Z", "lastModified": "2021-08-23T12:53:51Z"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>userName: test<br/>name: {"familyName": "test", "givenName": "test"}<br/>displayName: test<br/>active: false<br/>emails: {'value': 'john.doe@example.com', 'type': 'work', 'primary': True} |


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
```!iam-update-user user-profile={"username": "test"}```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "username": "test"
        },
        "Vendor": {
            "action": "update",
            "active": true,
            "brand": "AWS-ILM",
            "details": {
                "active": true,
                "displayName": "test",
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "john.doe@example.com"
                    }
                ],
                "id": "123456",
                "meta": {
                    "created": "2021-08-23T12:53:51Z",
                    "lastModified": "2021-08-23T12:53:54Z",
                    "resourceType": "User"
                },
                "name": {
                    "familyName": "test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "userName": "test"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "AWS-ILM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test"
        }
    }
}
```

#### Human Readable Output

>### Update User Results (AWS-ILM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| AWS-ILM | AWS-ILM_instance_1 | true | true | 123456 | test | id: 123456<br/>meta: {"resourceType": "User", "created": "2021-08-23T12:53:51Z", "lastModified": "2021-08-23T12:53:54Z"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>userName: test<br/>name: {"familyName": "test", "givenName": "test"}<br/>displayName: test<br/>active: true<br/>emails: {'value': 'john.doe@example.com', 'type': 'work', 'primary': True} |


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
```!iam-get-user user-profile={"username": "test"}```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "Email": "john.doe@example.com",
            "Given Name": "test",
            "Surname": "test",
            "Username": "test"
        },
        "Vendor": {
            "action": "get",
            "active": false,
            "brand": "AWS-ILM",
            "details": {
                "active": false,
                "displayName": "test",
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "john.doe@example.com"
                    }
                ],
                "id": "123456",
                "meta": {
                    "created": "2021-08-23T12:53:51Z",
                    "lastModified": "2021-08-23T12:53:57Z",
                    "resourceType": "User"
                },
                "name": {
                    "familyName": "test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "userName": "test"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "AWS-ILM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test"
        }
    }
}
```

#### Human Readable Output

>### Get User Results (AWS-ILM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| AWS-ILM | AWS-ILM_instance_1 | true | false | 123456 | test | id: 123456<br/>meta: {"resourceType": "User", "created": "2021-08-23T12:53:51Z", "lastModified": "2021-08-23T12:53:57Z"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>userName: test<br/>name: {"familyName": "test", "givenName": "test"}<br/>displayName: test<br/>active: false<br/>emails: {'value': 'john.doe@example.com', 'type': 'work', 'primary': True} |


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
```!iam-disable-user user-profile={"username": "test"}```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "username": "test"
        },
        "Vendor": {
            "action": "disable",
            "active": false,
            "brand": "AWS-ILM",
            "details": {
                "active": false,
                "displayName": "test",
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "john.doe@example.com"
                    }
                ],
                "id": "123456",
                "meta": {
                    "created": "2021-08-23T12:53:51Z",
                    "lastModified": "2021-08-23T12:53:57Z",
                    "resourceType": "User"
                },
                "name": {
                    "familyName": "test",
                    "givenName": "test"
                },
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "userName": "test"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "123456",
            "instanceName": "AWS-ILM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "test"
        }
    }
}
```

#### Human Readable Output

>### Disable User Results (AWS-ILM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| AWS-ILM | AWS-ILM_instance_1 | true | false | 123456 | test | id: 123456<br/>meta: {"resourceType": "User", "created": "2021-08-23T12:53:51Z", "lastModified": "2021-08-23T12:53:57Z"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>userName: test<br/>name: {"familyName": "test", "givenName": "test"}<br/>displayName: test<br/>active: false<br/>emails: {'value': 'john.doe@example.com', 'type': 'work', 'primary': True} |


### iam-get-group
***
 


#### Base Command

`iam-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetGroup.id | String | Group Id | 
| GetGroup.displayName | String | Display Name of the Group | 
| GetGroup.members.display | String | Display Name of the group member | 
| GetGroup.members.value | String | Id of the group member | 
| GetGroup.success | Boolean | Success status of the command | 
| GetGroup.errorCode | Number | Error Code if there is failure | 
| GetGroup.errorMessage | Unknown | Error Details if there is failure | 


#### Command Example
```!iam-get-group scim=`{"id": "121212"}````

#### Context Example
```json
{
    "IamGetGroup": {
        "active": null,
        "brand": "AWS-ILM",
        "details": {
            "displayName": "The best group",
            "id": "121212",
            "members": [],
            "meta": {
                "created": "2021-08-23T12:41:43Z",
                "lastModified": "2021-08-23T12:41:43Z",
                "resourceType": "Group"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group"
            ]
        },
        "displayName": "The best group",
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "121212",
        "instanceName": "AWS-ILM_instance_1",
        "members": null,
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### AWS Get Group:
>|brand|details|displayName|id|instanceName|success|
>|---|---|---|---|---|---|
>| AWS-ILM | id: 121212<br/>meta: {"resourceType": "Group", "created": "2021-08-23T12:41:43Z", "lastModified": "2021-08-23T12:41:43Z"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:Group<br/>displayName: The best group<br/>members:  | The best group | 121212 | AWS-ILM_instance_1 | true |


### iam-create-group
***
Creates an empty group


#### Base Command

`iam-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM data with displayName. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateGroup.id | String | Group Id | 
| CreateGroup.displayName | String | Display Name of the Group | 
| CreateGroup.success | Boolean | Success status of the command | 
| CreateGroup.errorCode | Number | Error Code if there is failure | 
| CreateGroup.errorMessage | Unknown | Error Details if there is failure | 


#### Command Example
```!iam-create-group scim=`{"displayName": "The group"}````

#### Context Example
```json
{
    "IamCreateGroup": {
        "active": null,
        "brand": "AWS-ILM",
        "details": {
            "displayName": "The group",
            "id": "111111",
            "members": [],
            "meta": {
                "created": "2021-08-23T12:54:02Z",
                "lastModified": "2021-08-23T12:54:02Z",
                "resourceType": "Group"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group"
            ]
        },
        "displayName": "The group",
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "111111",
        "instanceName": "AWS-ILM_instance_1",
        "members": null,
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### AWS Create Group:
>|brand|details|displayName|id|instanceName|success|
>|---|---|---|---|---|---|
>| AWS-ILM | id: 111111<br/>meta: {"resourceType": "Group", "created": "2021-08-23T12:54:02Z", "lastModified": "2021-08-23T12:54:02Z"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:Group<br/>displayName: The group<br/>members:  | The group | 111111 | AWS-ILM_instance_1 | true |


### iam-update-group
***
Updates an existing group resource. This command allows individual (or groups of) users to be added or removed from the group with a single operation. A max of 100 users can be modified in 1 call


#### Base Command

`iam-update-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM data. | Required | 
| memberIdsToAdd | List of members ids to add. A maximum of 100 users per call can be modified using this command. Possible values are: comma separated optional values. | Optional | 
| memberIdsToDelete | List of members ids to be deleted from the group. A maximum of 100 users per call can be modified using this command. Possible values are: comma separated optional values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateGroup.id | String | Group Id | 
| UpdateGroup.displayName | String | Display Name of the Group | 
| UpdateGroup.success | Boolean | Success status of the command | 
| UpdateGroup.errorCode | Number | Error Code if there is failure | 
| UpdateGroup.errorMessage | Unknown | Error Details if there is failure | 


#### Command Example
```!iam-update-group scim={"id": "121212"} memberIdsToAdd=["123456"]```

#### Context Example
```json
{
    "IamUpdateGroup": {
        "active": null,
        "brand": "AWS-ILM",
        "details": "{'Date': 'Mon, 23 Aug 2021 12:54:08 GMT', 'Content-Type': 'application/json', 'Connection': 'keep-alive', 'x-amzn-RequestId': '123456'}",
        "displayName": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "121212",
        "instanceName": "AWS-ILM_instance_1",
        "members": null,
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### AWS Update Group:
>|brand|details|id|instanceName|success|
>|---|---|---|---|---|
>| AWS-ILM | {'Date': 'Mon, 23 Aug 2021 12:54:08 GMT', 'Content-Type': 'application/json', 'Connection': 'keep-alive', 'x-amzn-RequestId': '123456'} | 121212 | AWS-ILM_instance_1 | true |


### iam-delete-group
***
Permanently removes a group.


#### Base Command

`iam-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM with id in it. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeleteGroup.id | String | Group Id | 
| DeleteGroup.displayName | String | Display Name of the Group | 
| DeleteGroup.success | Boolean | Success status of the command | 
| DeleteGroup.errorCode | Number | Error Code if there is failure | 
| DeleteGroup.errorMessage | Unknown | Error Details if there is failure | 


#### Command Example
```!iam-delete-group scim=`{"id": "121212"}````

#### Context Example
```json
{
    "IamDeleteGroup": {
        "active": null,
        "brand": "AWS-ILM",
        "details": "{'Date': 'Mon, 23 Aug 2021 12:54:11 GMT', 'Content-Type': 'application/json', 'Connection': 'keep-alive', 'x-amzn-RequestId': '123456'}",
        "displayName": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "121212",
        "instanceName": "AWS-ILM_instance_1",
        "members": null,
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### AWS Delete Group:
>|brand|details|id|instanceName|success|
>|---|---|---|---|---|
>| AWS-ILM | {'Date': 'Mon, 23 Aug 2021 12:54:11 GMT', 'Content-Type': 'application/json', 'Connection': 'keep-alive', 'x-amzn-RequestId': '123456'} | 121212 | AWS-ILM_instance_1 | true |

