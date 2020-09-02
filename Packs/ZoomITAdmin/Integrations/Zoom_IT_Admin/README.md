Zoom integration to manage Zoom users
This integration was integrated and tested with version xx of Zoom IT Admin
## Configure Zoom IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Zoom IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apiKey | API Key | True |
| apiSecret | API Secret | True |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| customMappingCreateUser | custom mapping for CreateUser | False |
| customMappingUpdateUser | custom mapping UpdateUser | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### create-user
***
Create a new user in zoom account


#### Base Command

`create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM formatted data | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateUser | boolean | Command context path | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false. | 
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.details | unknown | Gives the user information if the API is success else error information | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.username | string | Value of username passed as argument | 


#### Command Example
```!create-user scim={"userName":"demistotest1@paloaltonetworks.com","emails":[{"type":"work","primary":true,"value":"demistotest1@paloaltonetworks.com"}],"name":{"familyName":"Test","givenName":"Demisto"},"urn:scim:schemas:extension:custom:1.0:user":{"action":"create","type":"1"}}  using=ZoomITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Zoom IT Admin",
        "details": {
            "email": "demistotest1@paloaltonetworks.com",
            "first_name": "Demisto",
            "id": "3VE-FwLpT2G2YaEAfRty7g",
            "last_name": "Test",
            "type": 1
        },
        "email": "demistotest1@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "3VE-FwLpT2G2YaEAfRty7g",
        "instanceName": "ZoomITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Create Zoom User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Zoom IT Admin | id: 3VE-FwLpT2G2YaEAfRty7g<br/>first_name: Demisto<br/>last_name: Test<br/>email: demistotest1@paloaltonetworks.com<br/>type: 1 | demistotest1@paloaltonetworks.com |  |  | 3VE-FwLpT2G2YaEAfRty7g | ZoomITAdmin | true |  |


### update-user
***
Update information on a user?s Zoom


#### Base Command

`update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldScim | The old SCIM data to update | Required | 
| newScim | The new SCIM data to update with | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateUser | unknown | Command context path | 
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.details | Unknown | Gives the user information if the API is success else error information | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string | Reason why the API is failed | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.username | string | Value of username passed as argument | 
| UpdateUser.active | boolean | Gives the user information if the API is success else error information | 


#### Command Example
```!update-user oldScim={"id":"wRj-ffDKSTWTtR-NtqhVYg"} newScim={"name":{"familyName":"Test","givenName":"Demisto"}} using=ZoomITAdmin ```

#### Context Example
```
{
    "UpdateUser": {
        "active": null,
        "brand": "Zoom IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "wRj-ffDKSTWTtR-NtqhVYg",
        "instanceName": "ZoomITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Update Zoom User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>|  | Zoom IT Admin |  |  |  |  | wRj-ffDKSTWTtR-NtqhVYg | ZoomITAdmin | true |  |


### enable-user
***
Enables a Zoom account


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM formatted data | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | unknown | Command context path | 
| EnableUser.active | boolean | Gives the active status of user. Can be true of false. | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.details | unknown | Gives the user information if the API is success else error information | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP error response code | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.instanceName | string | Name of the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false. | 
| EnableUser.username | string | Value of username passed as argument | 


#### Command Example
```!enable-user scim={"id":"wRj-ffDKSTWTtR-NtqhVYg"} using=ZoomITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Zoom IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "wRj-ffDKSTWTtR-NtqhVYg",
        "instanceName": "ZoomITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Zoom User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Zoom IT Admin |  |  |  |  | wRj-ffDKSTWTtR-NtqhVYg | ZoomITAdmin | true |  |


### disable-user
***
Disables a Zoom account


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM formatted data | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | unknown | Command context path | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false. | 
| DisableUser.brand | string | Name of the Integration | 
| DisableUser.details | Unknown | Gives the user information if the API is success else error information | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP error response code | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.instanceName | string | Name of the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false. | 
| DisableUser.username | string | Value of username passed as argument | 


#### Command Example
```!disable-user scim={"id":"wRj-ffDKSTWTtR-NtqhVYg"} using=ZoomITAdmin ```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Zoom IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "wRj-ffDKSTWTtR-NtqhVYg",
        "instanceName": "ZoomITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable Zoom User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | Zoom IT Admin |  |  |  |  | wRj-ffDKSTWTtR-NtqhVYg | ZoomITAdmin | true |  |


### get-user
***
Gets the details of a user


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM formatted data | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | unknown | Command context path | 
| GetUser.active | boolean | Gives the active status of user. Can be true of false. | 
| GetUser.brand | string | Name of the Integration | 
| GetUser.details | Unknown | Gives the user information if the API is success else error information | 
| GetUser.email | string | User's email address. | 
| GetUser.errorCode | number | Error code in the case of exception. | 
| GetUser.errorMessage | string | Error message in the case of exception. | 
| GetUser.id | string | User's id | 
| GetUser.instanceName | string | Instance name for the Integration. | 
| GetUser.success | boolean | Success status. Can be True or False | 
| GetUser.username | string | User's username | 


#### Command Example
```!get-user scim={"id":"wRj-ffDKSTWTtR-NtqhVYg"} using=ZoomITAdmin ```

#### Context Example
```
{
    "GetUser": {
        "active": false,
        "brand": "Zoom IT Admin",
        "details": {
            "account_id": "lIwXY0nnS9Obj3_HHfsV3A",
            "created_at": "2020-08-13T19:06:47Z",
            "dept": "",
            "email": "rbilgundi+demistotest@paloaltonetworks.com",
            "first_name": "cotex00000",
            "group_ids": [
                "ROg49uQyTtuKD6sjWdnyXA"
            ],
            "host_key": "684045",
            "id": "wRj-ffDKSTWTtR-NtqhVYg",
            "im_group_ids": [],
            "jid": "wrj-ffdkstwttr-ntqhvyg@xmpp.zoom.us",
            "job_title": "",
            "language": "",
            "last_name": "Xoar00000",
            "location": "",
            "personal_meeting_url": "",
            "phone_country": "",
            "phone_number": "",
            "pmi": 0,
            "role_name": "Member",
            "status": "inactive",
            "timezone": "",
            "type": 1,
            "use_pmi": false,
            "verified": 0
        },
        "email": "rbilgundi+demistotest@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "wRj-ffDKSTWTtR-NtqhVYg",
        "instanceName": "ZoomITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Get Zoom User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | Zoom IT Admin | id: wRj-ffDKSTWTtR-NtqhVYg<br/>first_name: cotex00000<br/>last_name: Xoar00000<br/>email: rbilgundi+demistotest@paloaltonetworks.com<br/>type: 1<br/>role_name: Member<br/>pmi: 0<br/>use_pmi: false<br/>personal_meeting_url: <br/>timezone: <br/>verified: 0<br/>dept: <br/>created_at: 2020-08-13T19:06:47Z<br/>host_key: 684045<br/>jid: wrj-ffdkstwttr-ntqhvyg@xmpp.zoom.us<br/>group_ids: ROg49uQyTtuKD6sjWdnyXA<br/>im_group_ids: <br/>account_id: lIwXY0nnS9Obj3_HHfsV3A<br/>language: <br/>phone_country: <br/>phone_number: <br/>status: inactive<br/>job_title: <br/>location:  | rbilgundi+demistotest@paloaltonetworks.com |  |  | wRj-ffDKSTWTtR-NtqhVYg | ZoomITAdmin | true |  |

