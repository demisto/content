Envoy Integration consists of a set of API endpoints that allow customers to automate provisioning of users.
This integration was integrated and tested with version v2 of Envoy IT Admin
## Configure Envoy IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Envoy IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Envoy URL https://&lt;domain&gt;.envoy.com | True |
| token | token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
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
```!get-user scim={"id":"U2432468"} using=EnvoyITAdmin```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "Envoy IT Admin",
        "details": {
            "active": true,
            "addresses": [],
            "department": null,
            "displayName": "test Xoar",
            "emails": [
                {
                    "primary": false,
                    "type": "home",
                    "value": "test34Aug@paloaltonetworks.com"
                },
                {
                    "primary": true,
                    "type": "work",
                    "value": "testXoar123@paloaltonetworks.com"
                }
            ],
            "entitlements": [],
            "externalId": "testXoar_extn@paloaltonetworks.com",
            "groups": [],
            "id": "U2432468",
            "locale": "en_US",
            "meta": {
                "created": "2020-08-06T12:15:10Z",
                "lastModified": "2020-08-06T17:14:18Z",
                "location": "https://app.envoy.com/scim/v1/Users/U2432468"
            },
            "name": {
                "familyName": "test",
                "formatted": null,
                "givenName": "Xoar",
                "middleName": null
            },
            "phoneNumbers": [
                {
                    "primary": false,
                    "type": "mobile",
                    "value": "4567"
                },
                {
                    "primary": false,
                    "type": "work",
                    "value": "1234"
                }
            ],
            "preferredLanguage": "en_US",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "title": "Staff IT Systems Engineer",
            "urn:envoy:schemas:1.0:User": {
                "assistants": []
            },
            "userName": "testAug62020@paloaltonetworks.com"
        },
        "email": "test34Aug@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "U2432468",
        "instanceName": "EnvoyITAdmin",
        "success": true,
        "username": "testAug62020@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get Envoy User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Envoy IT Admin | EnvoyITAdmin | true | true | U2432468 | testAug62020@paloaltonetworks.com | test34Aug@paloaltonetworks.com | userName: testAug62020@paloaltonetworks.com<br/>displayName: test Xoar<br/>id: U2432468<br/>externalId: testXoar_extn@paloaltonetworks.com<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>active: true<br/>preferredLanguage: en_US<br/>title: Staff IT Systems Engineer<br/>department: null<br/>locale: en_US<br/>meta: {"location": "https://app.envoy.com/scim/v1/Users/U2432468", "created": "2020-08-06T12:15:10Z", "lastModified": "2020-08-06T17:14:18Z"}<br/>addresses: <br/>name: {"givenName": "Xoar", "familyName": "test", "formatted": null, "middleName": null}<br/>entitlements: <br/>emails: {'value': 'test34Aug@paloaltonetworks.com', 'type': 'home', 'primary': False},<br/>{'value': 'testXoar123@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>urn:envoy:schemas:1.0:User: {"assistants": []}<br/>phoneNumbers: {'value': '4567', 'type': 'mobile', 'primary': False},<br/>{'value': '1234', 'type': 'work', 'primary': False}<br/>groups:  |


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
```!create-user scim={"userName":"cortexXoar6Aug@paloaltonetworks.com","name":{"familyName":"cortex27123","givenName":"XoarAug123"},"emails":[{"value":"cotexXoar06Aug@paloaltonetworks.com","type":"work","primary":true}]} using=EnvoyITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Envoy IT Admin",
        "details": {
            "active": true,
            "addresses": [],
            "department": null,
            "displayName": "XoarAug123 cortex27123",
            "emails": [
                {
                    "primary": true,
                    "type": "work",
                    "value": "cotexXoar06Aug@paloaltonetworks.com"
                }
            ],
            "entitlements": [],
            "externalId": null,
            "groups": [],
            "id": "U2432898",
            "locale": "en_US",
            "meta": {
                "created": "2020-08-06T17:21:16Z",
                "lastModified": "2020-08-06T17:21:16Z",
                "location": "https://app.envoy.com/scim/v1/Users/U2432898"
            },
            "name": {
                "familyName": "cortex27123",
                "formatted": null,
                "givenName": "XoarAug123",
                "middleName": null
            },
            "phoneNumbers": [],
            "preferredLanguage": "en_US",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "title": null,
            "urn:envoy:schemas:1.0:User": {
                "assistants": []
            },
            "userName": "cortexXoar6Aug@paloaltonetworks.com"
        },
        "email": "cotexXoar06Aug@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "U2432898",
        "instanceName": "EnvoyITAdmin",
        "success": true,
        "username": "cortexXoar6Aug@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create Envoy User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Envoy IT Admin | EnvoyITAdmin | true | true | U2432898 | cortexXoar6Aug@paloaltonetworks.com | cotexXoar06Aug@paloaltonetworks.com | userName: cortexXoar6Aug@paloaltonetworks.com<br/>displayName: XoarAug123 cortex27123<br/>id: U2432898<br/>externalId: null<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>active: true<br/>preferredLanguage: en_US<br/>title: null<br/>department: null<br/>locale: en_US<br/>meta: {"location": "https://app.envoy.com/scim/v1/Users/U2432898", "created": "2020-08-06T17:21:16Z", "lastModified": "2020-08-06T17:21:16Z"}<br/>addresses: <br/>name: {"givenName": "XoarAug123", "familyName": "cortex27123", "formatted": null, "middleName": null}<br/>entitlements: <br/>emails: {'value': 'cotexXoar06Aug@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>urn:envoy:schemas:1.0:User: {"assistants": []}<br/>phoneNumbers: <br/>groups:  |


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
```!update-user oldScim={"id":"U2432468"} newScim={"emails":[{"value":"XoarOkat1234598@okta.example.com","type":"home"}]} using=EnvoyITAdmin```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Envoy IT Admin",
        "details": {
            "active": true,
            "addresses": [],
            "department": null,
            "displayName": "test Xoar",
            "emails": [
                {
                    "primary": false,
                    "type": "home",
                    "value": "XoarOkat1234598@okta.example.com"
                },
                {
                    "primary": true,
                    "type": "work",
                    "value": "testXoar123@paloaltonetworks.com"
                }
            ],
            "entitlements": [],
            "externalId": "testXoar_extn@paloaltonetworks.com",
            "groups": [],
            "id": "U2432468",
            "locale": "en_US",
            "meta": {
                "created": "2020-08-06T12:15:10Z",
                "lastModified": "2020-08-06T17:21:20Z",
                "location": "https://app.envoy.com/scim/v1/Users/U2432468"
            },
            "name": {
                "familyName": "test",
                "formatted": null,
                "givenName": "Xoar",
                "middleName": null
            },
            "phoneNumbers": [
                {
                    "primary": false,
                    "type": "mobile",
                    "value": "4567"
                },
                {
                    "primary": false,
                    "type": "work",
                    "value": "1234"
                }
            ],
            "preferredLanguage": "en_US",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "title": "Staff IT Systems Engineer",
            "urn:envoy:schemas:1.0:User": {
                "assistants": []
            },
            "userName": "testAug62020@paloaltonetworks.com"
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "U2432468",
        "instanceName": "EnvoyITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Update Envoy User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| Envoy IT Admin | EnvoyITAdmin | true | true | U2432468 | userName: testAug62020@paloaltonetworks.com<br/>displayName: test Xoar<br/>id: U2432468<br/>externalId: testXoar_extn@paloaltonetworks.com<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>active: true<br/>preferredLanguage: en_US<br/>title: Staff IT Systems Engineer<br/>department: null<br/>locale: en_US<br/>meta: {"location": "https://app.envoy.com/scim/v1/Users/U2432468", "created": "2020-08-06T12:15:10Z", "lastModified": "2020-08-06T17:21:20Z"}<br/>addresses: <br/>name: {"givenName": "Xoar", "familyName": "test", "formatted": null, "middleName": null}<br/>entitlements: <br/>emails: {'value': 'XoarOkat1234598@okta.example.com', 'type': 'home', 'primary': False},<br/>{'value': 'testXoar123@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>urn:envoy:schemas:1.0:User: {"assistants": []}<br/>phoneNumbers: {'value': '4567', 'type': 'mobile', 'primary': False},<br/>{'value': '1234', 'type': 'work', 'primary': False}<br/>groups:  |


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
```!disable-user scim={"id":"U2432468"} using=EnvoyITAdmin```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Envoy IT Admin",
        "details": {
            "active": false,
            "addresses": [],
            "department": null,
            "displayName": "test Xoar",
            "emails": [
                {
                    "primary": false,
                    "type": "home",
                    "value": "XoarOkat1234598@okta.example.com"
                },
                {
                    "primary": true,
                    "type": "work",
                    "value": "testXoar123@paloaltonetworks.com"
                }
            ],
            "entitlements": [],
            "externalId": "testXoar_extn@paloaltonetworks.com",
            "groups": [],
            "id": "U2432468",
            "locale": "en_US",
            "meta": {
                "created": "2020-08-06T12:15:10Z",
                "lastModified": "2020-08-06T17:21:27Z",
                "location": "https://app.envoy.com/scim/v1/Users/U2432468"
            },
            "name": {
                "familyName": "test",
                "formatted": null,
                "givenName": "Xoar",
                "middleName": null
            },
            "phoneNumbers": [
                {
                    "primary": false,
                    "type": "mobile",
                    "value": "4567"
                },
                {
                    "primary": false,
                    "type": "work",
                    "value": "1234"
                }
            ],
            "preferredLanguage": "en_US",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "title": "Staff IT Systems Engineer",
            "urn:envoy:schemas:1.0:User": {
                "assistants": []
            },
            "userName": "testAug62020@paloaltonetworks.com"
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "U2432468",
        "instanceName": "EnvoyITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable Envoy User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| Envoy IT Admin | EnvoyITAdmin | true | false | U2432468 | userName: testAug62020@paloaltonetworks.com<br/>displayName: test Xoar<br/>id: U2432468<br/>externalId: testXoar_extn@paloaltonetworks.com<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>active: false<br/>preferredLanguage: en_US<br/>title: Staff IT Systems Engineer<br/>department: null<br/>locale: en_US<br/>meta: {"location": "https://app.envoy.com/scim/v1/Users/U2432468", "created": "2020-08-06T12:15:10Z", "lastModified": "2020-08-06T17:21:27Z"}<br/>addresses: <br/>name: {"givenName": "Xoar", "familyName": "test", "formatted": null, "middleName": null}<br/>entitlements: <br/>emails: {'value': 'XoarOkat1234598@okta.example.com', 'type': 'home', 'primary': False},<br/>{'value': 'testXoar123@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>urn:envoy:schemas:1.0:User: {"assistants": []}<br/>phoneNumbers: {'value': '4567', 'type': 'mobile', 'primary': False},<br/>{'value': '1234', 'type': 'work', 'primary': False}<br/>groups:  |


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
```!enable-user scim={"id":"U2432468"} using=EnvoyITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Envoy IT Admin",
        "details": {
            "active": true,
            "addresses": [],
            "department": null,
            "displayName": "test Xoar",
            "emails": [
                {
                    "primary": false,
                    "type": "home",
                    "value": "XoarOkat1234598@okta.example.com"
                },
                {
                    "primary": true,
                    "type": "work",
                    "value": "testXoar123@paloaltonetworks.com"
                }
            ],
            "entitlements": [],
            "externalId": "testXoar_extn@paloaltonetworks.com",
            "groups": [],
            "id": "U2432468",
            "locale": "en_US",
            "meta": {
                "created": "2020-08-06T12:15:10Z",
                "lastModified": "2020-08-06T17:21:20Z",
                "location": "https://app.envoy.com/scim/v1/Users/U2432468"
            },
            "name": {
                "familyName": "test",
                "formatted": null,
                "givenName": "Xoar",
                "middleName": null
            },
            "phoneNumbers": [
                {
                    "primary": false,
                    "type": "mobile",
                    "value": "4567"
                },
                {
                    "primary": false,
                    "type": "work",
                    "value": "1234"
                }
            ],
            "preferredLanguage": "en_US",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "title": "Staff IT Systems Engineer",
            "urn:envoy:schemas:1.0:User": {
                "assistants": []
            },
            "userName": "testAug62020@paloaltonetworks.com"
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "U2432468",
        "instanceName": "EnvoyITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Envoy User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| Envoy IT Admin | EnvoyITAdmin | true | true | U2432468 | userName: testAug62020@paloaltonetworks.com<br/>displayName: test Xoar<br/>id: U2432468<br/>externalId: testXoar_extn@paloaltonetworks.com<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>active: true<br/>preferredLanguage: en_US<br/>title: Staff IT Systems Engineer<br/>department: null<br/>locale: en_US<br/>meta: {"location": "https://app.envoy.com/scim/v1/Users/U2432468", "created": "2020-08-06T12:15:10Z", "lastModified": "2020-08-06T17:21:20Z"}<br/>addresses: <br/>name: {"givenName": "Xoar", "familyName": "test", "formatted": null, "middleName": null}<br/>entitlements: <br/>emails: {'value': 'XoarOkat1234598@okta.example.com', 'type': 'home', 'primary': False},<br/>{'value': 'testXoar123@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>urn:envoy:schemas:1.0:User: {"assistants": []}<br/>phoneNumbers: {'value': '4567', 'type': 'mobile', 'primary': False},<br/>{'value': '1234', 'type': 'work', 'primary': False}<br/>groups:  |

