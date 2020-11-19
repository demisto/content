GitHub Integration consists of a set of API endpoints that allow customers to automate provisioning of GitHub organization membership.
This integration was integrated and tested with version v2 of GitHub IT Admin
## Configure GitHub IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GitHub IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | GitHub URL https://&lt;domain&gt;.github.com/ | True |
| token | token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| org | organization name | False |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping for UpdateUser | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Get a user detail


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | unknown | Command context path | 
| GetUser.active | boolean | Gives the active status of user. Can be true of false. | 
| GetUser.brand | string | Name of the Integration | 
| GetUser.details | string | Gives the user Profile information if the API is success else error message | 
| GetUser.email | string | Value of email ID passed as argument | 
| GetUser.errorCode | number | HTTP error response code | 
| GetUser.errorMessage | string | Reason why the API is failed | 
| GetUser.id | string | Value of id passed as argument | 
| GetUser.instanceName | string | Name of the instance used for testing | 
| GetUser.success | boolean | Status of the result. Can be true or false. | 
| GetUser.userName | string | Value of username passed as argument | 


#### Command Example
```!get-user scim={"id":"83695e8e-c68c-11ea-9fde-b2f42c33cd6b"} using=GitHubITAdmin```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "GitHub IT Admin",
        "details": {
            "active": true,
            "emails": [
                {
                    "primary": true,
                    "type": "work",
                    "value": "mona.octocat@okta.example.com"
                },
                {
                    "type": "home",
                    "value": "XoarOkat123@okta.example.com"
                }
            ],
            "externalId": null,
            "id": "83695e8e-c68c-11ea-9fde-b2f42c33cd6b",
            "meta": {
                "created": "2020-07-15T04:15:39.000-07:00",
                "lastModified": "2020-07-15T04:15:39.000-07:00",
                "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/83695e8e-c68c-11ea-9fde-b2f42c33cd6b",
                "resourceType": "User"
            },
            "name": {
                "familyName": "Xoar12345",
                "givenName": "cotex1235"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "userName": "Xoar.test1234995@paloaltonetworks.com"
        },
        "email": "mona.octocat@okta.example.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "83695e8e-c68c-11ea-9fde-b2f42c33cd6b",
        "instanceName": "GitHubITAdmin",
        "success": true,
        "username": "Xoar.test1234995@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get GitHub User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| GitHub IT Admin | GitHubITAdmin | true | true | 83695e8e-c68c-11ea-9fde-b2f42c33cd6b | Xoar.test1234995@paloaltonetworks.com | mona.octocat@okta.example.com | schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: 83695e8e-c68c-11ea-9fde-b2f42c33cd6b<br/>externalId: null<br/>userName: Xoar.test1234995@paloaltonetworks.com<br/>name: {"givenName": "cotex1235", "familyName": "Xoar12345"}<br/>emails: {'value': 'mona.octocat@okta.example.com', 'type': 'work', 'primary': True},<br/>{'value': 'XoarOkat123@okta.example.com', 'type': 'home'}<br/>active: true<br/>meta: {"resourceType": "User", "created": "2020-07-15T04:15:39.000-07:00", "lastModified": "2020-07-15T04:15:39.000-07:00", "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/83695e8e-c68c-11ea-9fde-b2f42c33cd6b"} |


### create-user
***
Creates a user


#### Base Command

`create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateUser | Unknown | Command context path | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false. | 
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.details | string | Gives the raw response from API | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.username | string | Value of username passed as argument | 


#### Command Example
```!create-user scim={"userName":"cortexXoar27July123@paloaltonetworks.com","name":{"familyName":"cortex27123","givenName":"XoarJuly123"},"emails":[{"value":"cotexXoar27July123@paloaltonetworks.com","type":"work","primary":true}]} using=GitHubITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "GitHub IT Admin",
        "details": {
            "active": true,
            "emails": [
                {
                    "primary": true,
                    "type": "work",
                    "value": "cotexXoar27July123@paloaltonetworks.com"
                }
            ],
            "externalId": null,
            "id": "9d0311e2-d004-11ea-8e50-4722a13dac29",
            "meta": {
                "created": "2020-07-27T05:28:02.000-07:00",
                "lastModified": "2020-07-27T05:28:02.000-07:00",
                "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/9d0311e2-d004-11ea-8e50-4722a13dac29",
                "resourceType": "User"
            },
            "name": {
                "familyName": "cortex27123",
                "givenName": "XoarJuly123"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "userName": "cortexXoar27July123@paloaltonetworks.com"
        },
        "email": "cotexXoar27July123@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "9d0311e2-d004-11ea-8e50-4722a13dac29",
        "instanceName": "GitHubITAdmin",
        "success": true,
        "username": "cortexXoar27July123@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create GitHub User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| GitHub IT Admin | GitHubITAdmin | true | true | 9d0311e2-d004-11ea-8e50-4722a13dac29 | cortexXoar27July123@paloaltonetworks.com | cotexXoar27July123@paloaltonetworks.com | schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: 9d0311e2-d004-11ea-8e50-4722a13dac29<br/>externalId: null<br/>userName: cortexXoar27July123@paloaltonetworks.com<br/>name: {"givenName": "XoarJuly123", "familyName": "cortex27123"}<br/>emails: {'value': 'cotexXoar27July123@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>active: true<br/>meta: {"resourceType": "User", "created": "2020-07-27T05:28:02.000-07:00", "lastModified": "2020-07-27T05:28:02.000-07:00", "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/9d0311e2-d004-11ea-8e50-4722a13dac29"} |


### update-user
***
Update a user


#### Base Command

`update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldScim | Old SCIM content in JSON format | Required | 
| newScim | New SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateUser | Unknown | Command context path | 
| UpdateUser.active | boolean | Gives the active status of user. Can be true of false. | 
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.details | string | Gives the raw response from API | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string | Reason why the API is failed | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.username | string | Value of username passed as argument | 


#### Command Example
```!update-user oldScim={"id":"83695e8e-c68c-11ea-9fde-b2f42c33cd6b"} newScim={"emails":[{"value":"XoarOkat12345@okta.example.com","type":"home"}]} using=GitHubITAdmin```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "GitHub IT Admin",
        "details": {
            "active": true,
            "emails": [
                {
                    "primary": true,
                    "type": "work",
                    "value": "mona.octocat@okta.example.com"
                },
                {
                    "type": "home",
                    "value": "XoarOkat12345@okta.example.com"
                }
            ],
            "externalId": null,
            "id": "83695e8e-c68c-11ea-9fde-b2f42c33cd6b",
            "meta": {
                "created": "2020-07-15T04:15:39.000-07:00",
                "lastModified": "2020-07-15T04:15:39.000-07:00",
                "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/83695e8e-c68c-11ea-9fde-b2f42c33cd6b",
                "resourceType": "User"
            },
            "name": {
                "familyName": "Xoar12345",
                "givenName": "cotex1235"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "userName": "Xoar.test1234995@paloaltonetworks.com"
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "83695e8e-c68c-11ea-9fde-b2f42c33cd6b",
        "instanceName": "GitHubITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Updated GitHub User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| GitHub IT Admin | GitHubITAdmin | true | true | 83695e8e-c68c-11ea-9fde-b2f42c33cd6b | schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: 83695e8e-c68c-11ea-9fde-b2f42c33cd6b<br/>externalId: null<br/>userName: Xoar.test1234995@paloaltonetworks.com<br/>name: {"givenName": "cotex1235", "familyName": "Xoar12345"}<br/>emails: {'value': 'mona.octocat@okta.example.com', 'type': 'work', 'primary': True},<br/>{'value': 'XoarOkat12345@okta.example.com', 'type': 'home'}<br/>active: true<br/>meta: {"resourceType": "User", "created": "2020-07-15T04:15:39.000-07:00", "lastModified": "2020-07-15T04:15:39.000-07:00", "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/83695e8e-c68c-11ea-9fde-b2f42c33cd6b"} |


### disable-user
***
Disable a user


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | Unknown | Command context path | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false. | 
| DisableUser.brand | string | Name of the Integration | 
| DisableUser.details | string | Gives the raw response from API in case of error | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP error response code | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.instanceName | string | Name the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false. | 
| DisableUser.username | string | Value of username passed as argument | 


#### Command Example
```!disable-user scim={"id":"034fde2c-d004-11ea-893c-7ff712fe8044"} using=GitHubITAdmin```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "GitHub IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "034fde2c-d004-11ea-893c-7ff712fe8044",
        "instanceName": "GitHubITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable GitHub User:
>|brand|instanceName|success|active|id|
>|---|---|---|---|---|
>| GitHub IT Admin | GitHubITAdmin | true | false | 034fde2c-d004-11ea-893c-7ff712fe8044 |


### enable-user
***
Enable a user


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | unknown | Command context path | 
| EnableUser.active | boolean | Gives the active status of user. Can be true of false | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.details | string | Gives the response from API | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP error response code | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.instanceName | string | Name the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false | 
| EnableUser.username | string | Value of username passed as argument | 


#### Command Example
```!enable-user scim={"userName":"cortexXoar271July12@paloaltonetworks.com","name":{"familyName":"cortex27112","givenName":"XoarJuly112"},"emails":[{"value":"cotexXoar27July112@paloaltonetworks.com","type":"work","primary":true}]} using=GitHubITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "GitHub IT Admin",
        "details": {
            "active": true,
            "emails": [
                {
                    "primary": true,
                    "type": "work",
                    "value": "cotexXoar27July112@paloaltonetworks.com"
                }
            ],
            "externalId": null,
            "id": "a132f566-d004-11ea-9e06-cf16a1980fc8",
            "meta": {
                "created": "2020-07-27T05:28:09.000-07:00",
                "lastModified": "2020-07-27T05:28:09.000-07:00",
                "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/a132f566-d004-11ea-9e06-cf16a1980fc8",
                "resourceType": "User"
            },
            "name": {
                "familyName": "cortex27112",
                "givenName": "XoarJuly112"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "userName": "cortexXoar271July12@paloaltonetworks.com"
        },
        "email": "cotexXoar27July112@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "a132f566-d004-11ea-9e06-cf16a1980fc8",
        "instanceName": "GitHubITAdmin",
        "success": true,
        "username": "cortexXoar271July12@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create GitHub User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| GitHub IT Admin | GitHubITAdmin | true | true | a132f566-d004-11ea-9e06-cf16a1980fc8 | cortexXoar271July12@paloaltonetworks.com | cotexXoar27July112@paloaltonetworks.com | schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: a132f566-d004-11ea-9e06-cf16a1980fc8<br/>externalId: null<br/>userName: cortexXoar271July12@paloaltonetworks.com<br/>name: {"givenName": "XoarJuly112", "familyName": "cortex27112"}<br/>emails: {'value': 'cotexXoar27July112@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>active: true<br/>meta: {"resourceType": "User", "created": "2020-07-27T05:28:09.000-07:00", "lastModified": "2020-07-27T05:28:09.000-07:00", "location": "https://api.github.com/scim/v2/organizations/test-sso-scim/Users/a132f566-d004-11ea-9e06-cf16a1980fc8"} |

