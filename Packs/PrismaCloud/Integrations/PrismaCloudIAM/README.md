Note: This integration should be used as part of our **Identity Lifecycle Management** premium pack. For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

The Prisma Cloud IAM API consists of a set of API endpoints that allow customers to perform CRUD operation on their user profiles.

## Configure PrismaCloud IAM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| Username |  | True |
| Password |  | True |
| Customer name | If you are a multi-tenant user you will also need to provide the customerName. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Allow creating users |  | False |
| Allow updating users |  | False |
| Allow enabling users |  | False |
| Allow disabling users |  | False |
| Automatically create user if not found in update command |  | False |
| Incoming Mapper |  | True |
| Outgoing Mapper |  | True |

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
```!iam-create-user user-profile=`{"email": "john.doe@example.com", "givenname": "test", "surname": "test"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "john.doe@example.com",
            "givenname": "test",
            "surname": "test"
        },
        "Vendor": {
            "action": "update",
            "active": null,
            "brand": "PrismaCloudIAM",
            "details": {
                "email": "john.doe@example.com",
                "firstName": "test",
                "lastName": "test",
                "roleId": "some_role_id",
                "timeZone": "America/Los_Angeles"
            },
            "email": "john.doe@example.com",
            "errorCode": null,
            "errorMessage": "",
            "id": null,
            "instanceName": "PrismaCloudIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": null
        }
    }
}
```

#### Human Readable Output

>### Update User Results (PrismaCloudIAM)
>|brand|instanceName|success|email|details|
>|---|---|---|---|---|
>| PrismaCloudIAM | PrismaCloudIAM_instance_1 | true | john.doe@example.com | email: john.doe@example.com<br/>firstName: test<br/>lastName: test<br/>roleId: some_role_id<br/>timeZone: America/Los_Angeles |


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
```!iam-update-user user-profile=`{"email": "john.doe@example.com", "givenname": "John"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "john.doe@example.com",
            "givenname": "John"
        },
        "Vendor": {
            "action": "update",
            "active": null,
            "brand": "PrismaCloudIAM",
            "details": {
                "email": "john.doe@example.com",
                "firstName": "John",
                "roleId": "some_role_id",
                "timeZone": "America/Los_Angeles"
            },
            "email": "john.doe@example.com",
            "errorCode": null,
            "errorMessage": "",
            "id": null,
            "instanceName": "PrismaCloudIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": null
        }
    }
}
```

#### Human Readable Output

>### Update User Results (PrismaCloudIAM)
>|brand|instanceName|success|email|details|
>|---|---|---|---|---|
>| PrismaCloudIAM | PrismaCloudIAM_instance_1 | true | john.doe@example.com | email: john.doe@example.com<br/>firstName: John<br/>roleId: some_role_id<br/>timeZone: America/Los_Angeles |


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
```!iam-get-user user-profile=`{"email": "john.doe@example.com"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "Display Name": "test test",
            "Email": "john.doe@example.com",
            "Given Name": "test",
            "Surname": "test"
        },
        "Vendor": {
            "action": "get",
            "active": true,
            "brand": "PrismaCloudIAM",
            "details": {
                "accessKeysAllowed": true,
                "displayName": "test test",
                "email": "john.doe@example.com",
                "enabled": true,
                "firstName": "test",
                "lastLoginTs": -1,
                "lastModifiedBy": "modifier@example.com",
                "lastModifiedTs": 1628152142011,
                "lastName": "test",
                "role": {
                    "id": "some_role_id",
                    "name": "System Admin"
                },
                "roleId": "some_role_id",
                "roleType": "System Admin",
                "timeZone": "America/Los_Angeles"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "john.doe@example.com",
            "instanceName": "PrismaCloudIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": null
        }
    }
}
```

#### Human Readable Output

>### Get User Results (PrismaCloudIAM)
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| PrismaCloudIAM | PrismaCloudIAM_instance_1 | true | true | john.doe@example.com | email: john.doe@example.com<br/>firstName: test<br/>lastName: test<br/>timeZone: America/Los_Angeles<br/>enabled: true<br/>roleId: some_role_id<br/>lastModifiedBy: modifier@example.com<br/>lastModifiedTs: 1628152142011<br/>lastLoginTs: -1<br/>role: {"id": "some_role_id", "name": "System Admin"}<br/>roleType: System Admin<br/>displayName: test test<br/>accessKeysAllowed: true |


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
```!iam-disable-user user-profile=`{"email": "john.doe@example.com", "givenname": "John"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "john.doe@example.com",
            "givenname": "John"
        },
        "Vendor": {
            "action": "disable",
            "active": false,
            "brand": "PrismaCloudIAM",
            "details": null,
            "email": "john.doe@example.com",
            "errorCode": null,
            "errorMessage": "",
            "id": null,
            "instanceName": "PrismaCloudIAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": null
        }
    }
}
```

#### Human Readable Output

>### Disable User Results (PrismaCloudIAM)
>|brand|instanceName|success|active|email|
>|---|---|---|---|---|
>| PrismaCloudIAM | PrismaCloudIAM_instance_1 | true | false | john.doe@example.com |


#### Outgoing Mapper
- In the `User Profile - PrismaCloudIAM (Outgoing)` you should manually configure and map the following required attributes:
    1. timeZone - the time zone of the user.
    1. roleId - the id of the role assigned to the user



