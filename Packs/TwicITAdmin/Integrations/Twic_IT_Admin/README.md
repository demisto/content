The Twic API consists of a set of API endpoints that allow customers to perform CRUD operation on their user profiles. 
This integration was integrated and tested with version xx of Twic IT Admin
## Configure Twic IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Twic IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Twic url \(Eg: https://&amp;lt;domain&amp;gt;/\) | True |
| authorization_token | Authorization Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping for Update User | False |
| customMappingEnableUser | Custom Mapping for Enable User | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Get a user


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | Unknown | Command context path | 
| GetUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| GetUser.brand | string | Name of the Integration | 
| GetUser.details | string | Gives the user Profile information if the API is success else error message | 
| GetUser.email | string | Value of email ID passed as argument | 
| GetUser.errorCode | number | HTTP response code other than 200 \(if there is error in response\) | 
| GetUser.errorMessage | string | Reason why the API is failed | 
| GetUser.id | string | Value of id passed as argument | 
| GetUser.instanceName | string | Name of the instance used for testing | 
| GetUser.success | boolean | Status of the result. Can be true or false. | 
| GetUser.userName | string | Value of username passed as argument | 


#### Command Example
```!get-user scim=`{"id":"01c2d172-7e7b-413f-b102-22d4574fa0dc"}` using=TwicITAdmin```

#### Context Example
```json
{
    "GetUser": {
        "active": true,
        "brand": "Twic IT Admin",
        "details": {
            "active": true,
            "displayName": "test xsoar",
            "emails": [
                {
                    "primary": true,
                    "value": "testxsoar@paloaltonetworks.com"
                }
            ],
            "id": "01c2d172-7e7b-413f-b102-22d4574fa0dc",
            "is_twic_eligible": true,
            "meta": {
                "created": "2020-09-28T07:44:14.124Z"
            },
            "name": {
                "familyName": "xsoar",
                "givenName": "test"
            },
            "profileUrl": "https://s3-us-west-1.amazonaws.com/twic.ai/avatar/default_avatar.png",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "status": 200,
            "success": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": "Engineering",
                "employeeNumber": "twic-eng-12344",
                "organization": "Twic Global"
            },
            "urn:ietf:params:scim:schemas:extension:twic:2.0:User": {},
            "userName": "testxsoar@paloaltonetworks.com"
        },
        "email": "testxsoar@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "01c2d172-7e7b-413f-b102-22d4574fa0dc",
        "instanceName": "TwicITAdmin",
        "success": true,
        "username": "testxsoar@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get Twic User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Twic IT Admin | TwicITAdmin | true | true | 01c2d172-7e7b-413f-b102-22d4574fa0dc | testxsoar@paloaltonetworks.com | testxsoar@paloaltonetworks.com | success: true<br/>status: 200<br/>active: true<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>is_twic_eligible: true<br/>id: 01c2d172-7e7b-413f-b102-22d4574fa0dc<br/>meta: {"created": "2020-09-28T07:44:14.124Z"}<br/>userName: testxsoar@paloaltonetworks.com<br/>name: {"givenName": "test", "familyName": "xsoar"}<br/>displayName: test xsoar<br/>profileUrl: https://s3-us-west-1.amazonaws.com/twic.ai/avatar/default_avatar.png<br/>emails: {'value': 'testxsoar@paloaltonetworks.com', 'primary': True}<br/>urn:ietf:params:scim:schemas:extension:enterprise:2.0:User: {"organization": "Twic Global", "employeeNumber": "twic-eng-12344", "department": "Engineering"}<br/>urn:ietf:params:scim:schemas:extension:twic:2.0:User: {} |


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
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.username | string | Value of username passed as argument | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP response code other than 200 \(if there is error in response\) | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.details | string | Gives the raw response from API | 


#### Command Example
```!create-user scim=`{"active": true, "emails": [{"primary": true, "value": "testxsoar19@paloaltonetworks.com"}], "name": {"familyName": "xsoar1","givenName": "test"},"urn:scim:schemas:extension:custom:1.0:user": {"office_country": "US"},"userName": "testxsoar19@paloaltonetworks.com"}` customMapping=`{"office_country":"office_country"}` using=TwicITAdmin```

#### Context Example
```json
{
    "CreateUser": {
        "active": true,
        "brand": "Twic IT Admin",
        "details": {
            "active": true,
            "emails": [
                {
                    "primary": true,
                    "value": "testxsoar19@paloaltonetworks.com"
                }
            ],
            "id": "02ed6c46-4d3c-4e99-a732-40d3124297f6",
            "meta": {
                "created": "2020-10-09T11:43:23.833Z"
            },
            "name": {
                "familyName": "xsoar1",
                "givenName": "test"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "status": 201,
            "success": true,
            "urn:ietf:params:scim:schemas:extension:twic:2.0:User": {
                "office_country": "US"
            },
            "userName": "testxsoar19@paloaltonetworks.com"
        },
        "email": "testxsoar19@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "02ed6c46-4d3c-4e99-a732-40d3124297f6",
        "instanceName": "TwicITAdmin",
        "success": true,
        "username": "testxsoar19@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create Twic User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Twic IT Admin | TwicITAdmin | true | true | 02ed6c46-4d3c-4e99-a732-40d3124297f6 | testxsoar19@paloaltonetworks.com | testxsoar19@paloaltonetworks.com | success: true<br/>status: 201<br/>active: true<br/>emails: {'primary': True, 'value': 'testxsoar19@paloaltonetworks.com'}<br/>name: {"familyName": "xsoar1", "givenName": "test"}<br/>userName: testxsoar19@paloaltonetworks.com<br/>urn:ietf:params:scim:schemas:extension:twic:2.0:User: {"office_country": "US"}<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: 02ed6c46-4d3c-4e99-a732-40d3124297f6<br/>meta: {"created": "2020-10-09T11:43:23.833Z"} |


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
| UpdateUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.username | string | Value of username passed as argument | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | string | HTTP response code other than 200 \(if there is error in response\) | 
| UpdateUser.errorMessage | string |  Reason why the API is failed | 
| UpdateUser.details | string | Gives the raw response from API | 


#### Command Example
```!update-user oldScim=`{"id":"0938b3de-d66c-4f88-b9e0-22e7a774b75b"}` newScim=`{"active": true, "emails": [{"primary": true, "value": "testxsoar2@paloaltonetworks.com"}], "name": {"familyName": "xsoar1","givenName": "test"},"urn:scim:schemas:extension:custom:1.0:user": {"office_country": "UK"},"userName": "testxsoar2@paloaltonetworks.com"}` customMapping=`{"office_country":"office_country"}` using=TwicITAdmin```

#### Context Example
```json
{
    "UpdateUser": {
        "active": true,
        "brand": "Twic IT Admin",
        "details": {
            "active": true,
            "id": "0938b3de-d66c-4f88-b9e0-22e7a774b75b",
            "is_twic_eligible": true,
            "name": {
                "familyName": "xsoar1",
                "givenName": "test"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "status": 200,
            "success": true,
            "urn:ietf:params:scim:schemas:extension:twic:2.0:User": {
                "office_country": "UK"
            }
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "0938b3de-d66c-4f88-b9e0-22e7a774b75b",
        "instanceName": "TwicITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Update Twic User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| Twic IT Admin | TwicITAdmin | true | true | 0938b3de-d66c-4f88-b9e0-22e7a774b75b | success: true<br/>status: 200<br/>active: true<br/>name: {"familyName": "xsoar1", "givenName": "test"}<br/>urn:ietf:params:scim:schemas:extension:twic:2.0:User: {"office_country": "UK"}<br/>is_twic_eligible: true<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: 0938b3de-d66c-4f88-b9e0-22e7a774b75b |


### enable-user
***
Enable a disabled user


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | Unknown | Command context path | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.instanceName | string | Name the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false. | 
| EnableUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.username | string | Value of username passed as argument | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP response code other than 200 \(if there is error in response\) | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.details | string | Gives the raw response from API in case of error | 


#### Command Example
```!enable-user scim=`{"id":"47314745-4510-48e2-a932-200e42f0ecda",  "emails": [{"primary": true, "value": "testxsoar2@paloaltonetworks.com"}], "name": {"familyName": "xsoar1","givenName": "test"},"urn:scim:schemas:extension:custom:1.0:user": {"office_country": "UK"},"userName": "testxsoar2@paloaltonetworks.com", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Engineering", "employeeNumber": "twic-eng-12344", "organization": "Twic Global"}}` customMapping=`{"office_country":"office_country"}` using=TwicITAdmin```

#### Context Example
```json
{
    "EnableUser": {
        "active": true,
        "brand": "Twic IT Admin",
        "details": {
            "active": true,
            "id": "47314745-4510-48e2-a932-200e42f0ecda",
            "is_twic_eligible": false,
            "name": {
                "familyName": "xsoar1",
                "givenName": "test"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "status": 200,
            "success": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": "Engineering",
                "employeeNumber": "twic-eng-12344",
                "organization": "Twic Global"
            }
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "47314745-4510-48e2-a932-200e42f0ecda",
        "instanceName": "TwicITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Twic User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| Twic IT Admin | TwicITAdmin | true | true | 47314745-4510-48e2-a932-200e42f0ecda | success: true<br/>status: 200<br/>active: true<br/>id: 47314745-4510-48e2-a932-200e42f0ecda<br/>name: {"familyName": "xsoar1", "givenName": "test"}<br/>urn:ietf:params:scim:schemas:extension:enterprise:2.0:User: {"department": "Engineering", "employeeNumber": "twic-eng-12344", "organization": "Twic Global"}<br/>is_twic_eligible: false<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User |


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
| DisableUser | unknown | Command context path | 
| DisableUser.instanceName | string | Name the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false. | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.username | string | Value of username passed as argument | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP response code other than 200 \(if there is error in response\) | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.details | string | Gives the raw response from API in case of error | 
| DisableUser.brand | string | Name of the Integration | 


#### Command Example
```!disable-user scim=`{"id":"47314745-4510-48e2-a932-200e42f0ecda"}` using=TwicITAdmin```

#### Context Example
```json
{
    "DisableUser": {
        "active": false,
        "brand": "Twic IT Admin",
        "details": {
            "Operations": [
                {
                    "op": "replace",
                    "value": {
                        "active": false
                    }
                }
            ],
            "active": false,
            "id": "47314745-4510-48e2-a932-200e42f0ecda",
            "is_twic_eligible": false,
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "status": 200,
            "success": true
        },
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "47314745-4510-48e2-a932-200e42f0ecda",
        "instanceName": "TwicITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable Twic User:
>|brand|instanceName|success|active|id|details|
>|---|---|---|---|---|---|
>| Twic IT Admin | TwicITAdmin | true | false | 47314745-4510-48e2-a932-200e42f0ecda | success: true<br/>status: 200<br/>active: false<br/>Operations: {'op': 'replace', 'value': {'active': False}}<br/>is_twic_eligible: false<br/>schemas: urn:ietf:params:scim:schemas:core:2.0:User<br/>id: 47314745-4510-48e2-a932-200e42f0ecda |

