1.	Get / Retrieve user information from Smartsheet
2.	Create a user in Smartsheet
3.	Update a user
4.	Disable a user
This integration was integrated and tested with version xx of Smartsheet IT Admin
## Configure Smartsheet IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Smartsheet IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping for UpdateUser | False |
| Authorization | Authorization | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### create-user
***
This command creates the user based on the scim and custom map passed in argument.


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
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.active | string | Gives the active status of user. Can be true of false.  | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code  | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.details | string | Gives the user information if the API is success else error information | 


#### Command Example
```!create-user scim={"name":{"familyName":"lastname","givenName":"name6"},"emails":[{"primary":true,"type":"work","value":"qwerty@paloaltonetwork.com"}],"urn:scim:schemas:extension:custom:1.0:user":{"admin":false,"licensedSheetCreator":false,"groupAdmin":false,"resourceViewer":false}} using=Smartsheet```

#### Context Example
```
{
    "CreateUser": {
        "active": false,
        "brand": "Smartsheet IT Admin",
        "details": {
            "admin": false,
            "email": "qwerty@paloaltonetwork.com",
            "firstName": "name6",
            "groupAdmin": false,
            "id": 3636179410151300,
            "lastName": "lastname",
            "licensedSheetCreator": false,
            "name": "name6 lastname"
        },
        "email": "qwerty@paloaltonetwork.com",
        "errorCode": null,
        "errorMessage": null,
        "id": 3636179410151300,
        "instanceName": "Smartsheet",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Create Smartsheet User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | Smartsheet IT Admin | admin: false<br/>email: qwerty@paloaltonetwork.com<br/>firstName: name6<br/>groupAdmin: false<br/>id: 3636179410151300<br/>lastName: lastname<br/>licensedSheetCreator: false<br/>name: name6 lastname | qwerty@paloaltonetwork.com |  |  | 3636179410151300 | Smartsheet | true |  |


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
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.active | string | Gives the active status of user. Can be true of false.  | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string |  Reason why the API is failed | 
| UpdateUser.details | string | Gives the user information if the API is success else error information | 


#### Command Example
```!update-user oldScim={"id":8712882293630852} newScim={"name":{"familyName":"updatedname","givenName":"updatedname"},"urn:scim:schemas:extension:custom:1.0:user":{"admin":true,"licensedSheetCreator":true,"groupAdmin":true,"resourceViewer":true}} using=Smartsheet```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Smartsheet IT Admin",
        "details": {
            "admin": false,
            "email": "test3rdjuly2020@paloaltonetwork.com",
            "firstName": "updatedname",
            "groupAdmin": false,
            "id": 8712882293630852,
            "lastName": "updatedname",
            "licensedSheetCreator": false,
            "name": "updatedname updatedname",
            "resourceViewer": false,
            "status": "PENDING"
        },
        "email": "test3rdjuly2020@paloaltonetwork.com",
        "errorCode": null,
        "errorMessage": null,
        "id": 8712882293630852,
        "instanceName": "Smartsheet",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Updated Smartsheet User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Smartsheet IT Admin | admin: false<br/>email: test3rdjuly2020@paloaltonetwork.com<br/>firstName: updatedname<br/>groupAdmin: false<br/>id: 8712882293630852<br/>lastName: updatedname<br/>licensedSheetCreator: false<br/>name: updatedname updatedname<br/>resourceViewer: false<br/>status: PENDING | test3rdjuly2020@paloaltonetwork.com |  |  | 8712882293630852 | Smartsheet | true |  |


### get-user
***
Retrieve the user details based on id.


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM User JSON with id populated. Only user?s id will be used for lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | Unknown | Command context path | 
| GetUser.status | string | User status, set to one of the following values: ACTIVE, DECLINED, or PENDING | 
| GetUser.brand | string | User?s brand name. | 
| GetUser.details | string | Gives the user information if the API is success else error information | 
| GetUser.email  | string | User?s email address.  | 
| GetUser.errorCode  | number | Error code in the case of exception.  Example: 404 | 
| GetUser.errorMessage  | string | Error message in the case of exception. Example: ?User not Found? | 
| GetUser.Users.id  | string | User?s id  | 
| GetUser.instanceName | string | Instance name for the Integration. | 
| GetUser.success | boolean | Success status. Can be True or False | 


#### Command Example
```!get-user scim={"id":8712882293630852} using=SmartsheetITAdmin_instance_1```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "Smartsheet IT Admin",
        "details": {
            "account": {
                "id": 6805651465758596,
                "name": "Rashmi Bilgundi"
            },
            "admin": false,
            "company": "",
            "department": "",
            "email": "test3rdjuly2020@paloaltonetwork.com",
            "firstName": "updatedname",
            "groupAdmin": false,
            "id": 8712882293630852,
            "lastName": "updatedname",
            "licensedSheetCreator": false,
            "locale": "en_US",
            "mobilePhone": "",
            "resourceViewer": false,
            "role": "",
            "status": "PENDING",
            "timeZone": "US/Pacific",
            "title": "",
            "workPhone": ""
        },
        "email": "test3rdjuly2020@paloaltonetwork.com",
        "errorCode": null,
        "errorMessage": null,
        "id": 8712882293630852,
        "instanceName": "SmartsheetITAdmin_instance_1",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Get Smartsheet User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Smartsheet IT Admin | account: {"id": 6805651465758596, "name": "Rashmi Bilgundi"}<br/>admin: false<br/>company: <br/>department: <br/>email: test3rdjuly2020@paloaltonetwork.com<br/>firstName: updatedname<br/>groupAdmin: false<br/>id: 8712882293630852<br/>lastName: updatedname<br/>licensedSheetCreator: false<br/>locale: en_US<br/>mobilePhone: <br/>resourceViewer: false<br/>role: <br/>status: PENDING<br/>timeZone: US/Pacific<br/>title: <br/>workPhone:  | test3rdjuly2020@paloaltonetwork.com |  |  | 8712882293630852 | SmartsheetITAdmin_instance_1 | true |  |


### disable-user
***
This command removes the user.


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM User JSON with user_id whose user details needs to be removed. | Required | 
| customMapping | Any custom field / entity not covered by scim. Example: removeFromSharing, transferSheets and transferTo. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | Unknown | Command context path | 
| DisableUser.status | string | User status, set to one of the following values: ACTIVE, DECLINED, or PENDING | 
| DisableUser.brand | string | User?s brand name. | 
| DisableUser.details | string | User?s details including id, email, firtsName, lastName, groupAdmin etc. | 
| DisableUser.email  | string | User?s email address.  | 
| DisableUser.errorCode  | number | Error code in the case of exception.  Example: 404 | 
| DisableUser.errorMessage  | string | Error message in the case of exception. Example: ?User not Found? | 
| DisableUser.Users.id  | string | User?s id  | 
| DisableUser.instanceName | string | Instance name for the Integration. | 
| DisableUser.success | boolean | Success status. Can be True or False | 


#### Command Example
```!disable-user scim={"id":3636179410151300,"urn:scim:schemas:extension:custom:1.0:user":{"smartsheettransferto":"test"}} using=Smartsheet```

#### Context Example
```
{
    "DisableUser": {
        "active": null,
        "brand": "Smartsheet IT Admin",
        "details": {
            "result": {
                "code": 1018,
                "errorCode": 1018,
                "message": "The value 'test' was not valid for the parameter 'transferTo'.",
                "name": "ApiError",
                "recommendation": "Do not retry without fixing the problem. ",
                "refId": "1uxmonxvg9wxl",
                "shouldRetry": false,
                "statusCode": 400
            }
        },
        "email": null,
        "errorCode": 400,
        "errorMessage": "The value 'test' was not valid for the parameter 'transferTo'.",
        "id": 3636179410151300,
        "instanceName": "Smartsheet",
        "success": false,
        "username": null
    }
}
```

#### Human Readable Output

>### Remove Smartsheet User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>|  | Smartsheet IT Admin | result: {"code": 1018, "errorCode": 1018, "message": "The value 'test' was not valid for the parameter 'transferTo'.", "name": "ApiError", "recommendation": "Do not retry without fixing the problem. ", "refId": "1uxmonxvg9wxl", "shouldRetry": false, "statusCode": 400} |  | 400 | The value 'test' was not valid for the parameter 'transferTo'. | 3636179410151300 | Smartsheet | false |  |


### enable-user
***
This command creates the user based on the scim and custom map passed in argument.


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | Unknown | Command context path | 
| EnableUser.brand | String | Name of the Integration | 
| EnableUser.instanceName | String | Name of the instance used for testing | 
| EnableUser.success | Boolean | Status of the result. Can be true or false. | 
| EnableUser.active | String | Gives the active status of user. Can be true of false.  | 
| EnableUser.id | String | Value of id passed as argument | 
| EnableUser.email | String | Value of email ID passed as argument | 
| EnableUser.errorCode | Number | HTTP error response code  | 
| EnableUser.errorMessage | String | Reason why the API is failed | 
| EnableUser.details | String | Gives the user information if the API is success else error information | 


#### Command Example
```!enable-user scim={"name":{"familyName":"name1","givenName":"name"},"emails":[{"primary":true,"type":"work","value":"testmail@paloaltonetwork.com"}],"urn:scim:schemas:extension:custom:1.0:user":{"admin":false,"licensedSheetCreator":false,"groupAdmin":false,"resourceViewer":false}} using=Smartsheet```

#### Context Example
```
{
    "EnableUser": {
        "active": false,
        "brand": "Smartsheet IT Admin",
        "details": {
            "admin": false,
            "email": "testmail@paloaltonetwork.com",
            "firstName": "name",
            "groupAdmin": false,
            "id": 6644443223746436,
            "lastName": "name1",
            "licensedSheetCreator": false,
            "name": "name name1"
        },
        "email": "testmail@paloaltonetwork.com",
        "errorCode": null,
        "errorMessage": null,
        "id": 6644443223746436,
        "instanceName": "Smartsheet",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Create Smartsheet User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | Smartsheet IT Admin | admin: false<br/>email: testmail@paloaltonetwork.com<br/>firstName: name<br/>groupAdmin: false<br/>id: 6644443223746436<br/>lastName: name1<br/>licensedSheetCreator: false<br/>name: name name1 | testmail@paloaltonetwork.com |  |  | 6644443223746436 | Smartsheet | true |  |

