The Prisma Cloud API consists of a set of API endpoints that allow customers to perform CRUD operation on their user profiles. 
This integration was integrated and tested with version xx of Prisma Cloud IT Admin
## Configure Prisma Cloud IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma Cloud IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Prisma Cloud url \(e.g: https://&amp;lt;domain&amp;gt;.redlock.io/\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| customerName | Customer Name | True |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping for Update User | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Gets a user.


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | Unknown | Command context path. | 
| GetUser.active | boolean | True if the user status is active. | 
| GetUser.brand | string | Name of the integration. | 
| GetUser.details | string | API success or failure details. | 
| GetUser.email | string | User email address. | 
| GetUser.errorCode | number | HTTP error response code. | 
| GetUser.errorMessage | string | Reason why the API failed. | 
| GetUser.id | string | User ID. | 
| GetUser.instanceName | string | Name of the instance. | 
| GetUser.success | boolean | Status of the result. Can be "true" or "false". | 
| GetUser.username | string | User's username. | 


#### Command Example
```!get-user scim={"id":"testxsoar@paloaltonetworks.com"} using=PrismaCloud```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "Prisma Cloud IT Admin",
        "details": {
            "accessKeysAllowed": false,
            "displayName": "test xsoar",
            "email": "testxsoar@paloaltonetworks.com",
            "enabled": true,
            "firstName": "test",
            "lastLoginTs": -1,
            "lastModifiedBy": "svc-oktaredlock+dev@paloaltonetworks.com",
            "lastModifiedTs": 1591977022329,
            "lastName": "xsoar",
            "role": {
                "id": "58f9779b-5420-4319-b1c8-b735e4cebc86",
                "name": "demo-role"
            },
            "roleId": "58f9779b-5420-4319-b1c8-b735e4cebc86",
            "roleType": "Account Group Read Only",
            "timeZone": "America/Los_Angeles"
        },
        "email": "testxsoar@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "testxsoar@paloaltonetworks.com",
        "instanceName": "PrismaCloud",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Get PrismaCloud User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Prisma Cloud IT Admin | email: testxsoar@paloaltonetworks.com<br/>firstName: test<br/>lastName: xsoar<br/>timeZone: America/Los_Angeles<br/>enabled: true<br/>roleId: 58f9779b-5420-4319-b1c8-b735e4cebc86<br/>lastModifiedBy: svc-oktaredlock+dev@paloaltonetworks.com<br/>lastModifiedTs: 1591977022329<br/>lastLoginTs: -1<br/>role: {"id": "58f9779b-5420-4319-b1c8-b735e4cebc86", "name": "demo-role"}<br/>roleType: Account Group Read Only<br/>displayName: test xsoar<br/>accessKeysAllowed: false | testxsoar@paloaltonetworks.com |  |  | testxsoar@paloaltonetworks.com | PrismaCloud | true |  |


### create-user
***
Creates a user.


#### Base Command

`create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format. | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateUser | Unknown | Command context path. | 
| CreateUser.brand | string | Name of the integration. | 
| CreateUser.instanceName | string | Name of the instance. | 
| CreateUser.success | boolean | Status of the result. Can be "true" or "false". | 
| CreateUser.active | boolean | True if the user status is active. | 
| CreateUser.id | string | User ID. | 
| CreateUser.username | string | User's username. | 
| CreateUser.email | string | User email address. | 
| CreateUser.errorCode | number | HTTP error response code. | 
| CreateUser.errorMessage | string | Reason why the API failed. | 
| CreateUser.details | string | API success or failure details. | 


#### Command Example
```!create-user scim={"name":{"familyName":"test","givenName":"demisto"},"emails":[{"type":"work","primary":true,"value":"testdemistouser@paloaltonetworks.com"}],"timezone":"America/Los_Angeles","urn:scim:schemas:extension:custom:1.0:user":{"roleId":"58f9779b-5420-4319-b1c8-b735e4cebc86","timezone":"America/Los_Angeles"}} customMapping={"roleId":"roleId","timezone":"timeZone"} using=PrismaCloud```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Prisma Cloud IT Admin",
        "details": "<Response [200]>",
        "email": "testdemistouser@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "testdemistouser@paloaltonetworks.com",
        "instanceName": "PrismaCloud",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Create Prisma User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Prisma Cloud IT Admin | <Response [200]> | testdemistouser@paloaltonetworks.com |  |  | testdemistouser@paloaltonetworks.com | PrismaCloud | true |  |


### update-user
***
Updates a user.


#### Base Command

`update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldScim | Old SCIM content in JSON format. | Required | 
| newScim | New SCIM content in JSON format. | Required | 
| customMapping | Optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateUser | Unknown | Command context path. | 
| UpdateUser.brand | string | Name of the integration. | 
| UpdateUser.instanceName | string | Name of the instance. | 
| UpdateUser.success | boolean | Status of the result. Can be "true" or "false". | 
| UpdateUser.active | boolean | True if the user status is active. | 
| UpdateUser.id | string | User ID. | 
| UpdateUser.username | string | User's username. | 
| UpdateUser.email | string | User email address. | 
| UpdateUser.errorCode | string | HTTP error response code. | 
| UpdateUser.errorMessage | string | Reason why the API failed. | 
| UpdateUser.details | string | API success or failure details. | 


#### Command Example
```!update-user oldScim={"id":"testdemistouser@paloaltonetworks.com"} newScim={"name":{"familyName":"test","givenName":"demistouser"},"emails":[{"type":"work","primary":true,"value":"testdemistouser@paloaltonetworks.com"}],"timezone":"America/Los_Angeles","urn:scim:schemas:extension:custom:1.0:user":{"roleId":"58f9779b-5420-4319-b1c8-b735e4cebc86","timezone":"America/Los_Angeles"}} customMapping={"roleId":"roleId","timezone":"timeZone"} using=PrismaCloud```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Prisma Cloud IT Admin",
        "details": "<Response [200]>",
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "testdemistouser@paloaltonetworks.com",
        "instanceName": "PrismaCloud",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Update Prisma User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Prisma Cloud IT Admin | <Response [200]> |  |  |  | testdemistouser@paloaltonetworks.com | PrismaCloud | true |  |


### enable-user
***
Enables a user.


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | Unknown | Command context path. | 
| EnableUser.brand | string | Name of the integration. | 
| EnableUser.instanceName | string | Name of the instance. | 
| EnableUser.success | boolean | Status of the result. Can be "true" or "false". | 
| EnableUser.active | boolean | True if the user status is active. | 
| EnableUser.id | string | User ID. | 
| EnableUser.username | string | User's username. | 
| EnableUser.email | string | User email address. | 
| EnableUser.errorCode | number | HTTP error response code. | 
| EnableUser.errorMessage | string | Reason why the API failed. | 
| EnableUser.details | string | API success or failure details. | 


#### Command Example
```!enable-user scim={"id":"testdemistouser@paloaltonetworks.com"} using=PrismaCloud```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Prisma Cloud IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "testdemistouser@paloaltonetworks.com",
        "instanceName": "PrismaCloud",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Prisma User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Prisma Cloud IT Admin |  |  |  |  | testdemistouser@paloaltonetworks.com | PrismaCloud | true |  |


### disable-user
***
Disables a user.


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | unknown | Command context path. | 
| DisableUser.instanceName | string | Name of the instance. | 
| DisableUser.success | boolean | Status of the result. Can be "true" or "false". | 
| DisableUser.active | boolean | True if the user status is active. | 
| DisableUser.id | string | User ID. | 
| DisableUser.username | string | User's username. | 
| DisableUser.email | string | User email address. | 
| DisableUser.errorCode | number | HTTP error response code. | 
| DisableUser.errorMessage | string | Reason why the API failed. | 
| DisableUser.details | string | API success or failure details. | 
| DisableUser.brand | string | Name of the integration. | 


#### Command Example
```!disable-user scim={"id":"testdemistouser@paloaltonetworks.com"} using=PrismaCloud```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Prisma Cloud IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "testdemistouser@paloaltonetworks.com",
        "instanceName": "PrismaCloud",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable Prisma User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | Prisma Cloud IT Admin |  |  |  |  | testdemistouser@paloaltonetworks.com | PrismaCloud | true |  |

