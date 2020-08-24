Integration with Okta's cloud-based identity management service
This integration was integrated and tested with version xx of Okta IT Admin
## Configure Okta IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Okta IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Okta URL \(https://&amp;lt;domain&amp;gt;.okta.com\) | True |
| apitoken | API Token \(see Detailed Instructions\) | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping used for Update User | False |
| fetchLogsQuery |  | False |
| fetch_events_time_minutes |  | False |
| email_notification_ids | Email Notification Ids \(Separated by comma\) | False |
| smtp_server | SMTP Server Host | False |
| smtp_port | SMTP Server Port | False |
| from_email | From Email | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| CreateUser.active | Boolean | Gives the active status of user. Can be true of false | 
| CreateUser.brand | String | Name of the Integration | 
| CreateUser.details | Unknown | Gives the detail error information | 
| CreateUser.email | String | Value of email ID passed as argument | 
| CreateUser.errorCode | Number | HTTP error response code | 
| CreateUser.errorMessage | String | Reason why the API is failed | 
| CreateUser.id | String | Value of id passed as argument | 
| CreateUser.instanceName | Unknown | Name of the instance used for testing | 
| CreateUser.success | Boolean | Status of the result. Can be true or false | 
| CreateUser.username | String | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!create-user scim={"userName":"testdemisto2@paloaltonetworks.com","name":{"familyName":"Test","givenName":"Demisto"},"emails":[{"type":"work","primary":true,"value":"testdemisto2@paloaltonetworks.com"}]} using=OktaITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Okta IT Admin",
        "details": {
            "_links": {
                "deactivate": {
                    "href": "https://test.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/deactivate",
                    "method": "POST"
                },
                "reactivate": {
                    "href": "https://test.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/reactivate",
                    "method": "POST"
                },
                "resetPassword": {
                    "href": "https://test.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/reset_password",
                    "method": "POST"
                },
                "schema": {
                    "href": "https://test.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"
                },
                "self": {
                    "href": "https://test.com/api/v1/users/00utje4cim5v5jyTf0h7"
                },
                "suspend": {
                    "href": "https://test.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/suspend",
                    "method": "POST"
                },
                "type": {
                    "href": "https://test.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"
                }
            },
            "activated": "2020-08-24T15:04:16.000Z",
            "created": "2020-08-24T15:04:16.000Z",
            "credentials": {
                "provider": {
                    "name": "OKTA",
                    "type": "OKTA"
                }
            },
            "id": "00utje4cim5v5jyTf0h7",
            "lastLogin": null,
            "lastUpdated": "2020-08-24T15:04:16.000Z",
            "passwordChanged": null,
            "profile": {
                "email": "testdemisto2@paloaltonetworks.com",
                "firstName": "Demisto",
                "lastName": "Test",
                "login": "testdemisto2@paloaltonetworks.com",
                "mobilePhone": null,
                "secondEmail": null
            },
            "status": "PROVISIONED",
            "statusChanged": "2020-08-24T15:04:16.000Z",
            "type": {
                "id": "oty8zfz6plq7b0r830h7"
            }
        },
        "email": "testdemisto2@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "00utje4cim5v5jyTf0h7",
        "instanceName": "OktaITAdmin",
        "success": true,
        "username": "testdemisto2@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create Okta User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Okta IT Admin | OktaITAdmin | true | true | 00utje4cim5v5jyTf0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00utje4cim5v5jyTf0h7<br/>status: PROVISIONED<br/>created: 2020-08-24T15:04:16.000Z<br/>activated: 2020-08-24T15:04:16.000Z<br/>statusChanged: 2020-08-24T15:04:16.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-08-24T15:04:16.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto2@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"suspend": {"href": "https://test.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/suspend", "method": "POST"}, "schema": {"href": "https://panw-test.oktapreview.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"}, "resetPassword": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/reset_password", "method": "POST"}, "reactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/reactivate", "method": "POST"}, "self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utje4cim5v5jyTf0h7"}, "type": {"href": "https://panw-test.oktapreview.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"}, "deactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utje4cim5v5jyTf0h7/lifecycle/deactivate", "method": "POST"}} |


### update-user
***
Updates an existing user resource found with the "oldscim" with the data in the "newscim"


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
| UpdateUser.active | Boolean | Gives the active status of user. Can be true of false.Name of the Integration | 
| UpdateUser.brand | String | Name of the Integration | 
| UpdateUser.details | Unknown | Gives the detail error information | 
| UpdateUser.email | String | Value of email ID passed as argument | 
| UpdateUser.errorCode | Number | HTTP error response code | 
| UpdateUser.errorMessage | String | Reason why the API is failed | 
| UpdateUser.id | String | Value of id passed as argument | 
| UpdateUser.instanceName | String | Name of the instance used for testing | 
| UpdateUser.success | Boolean | Status of the result. Can be true or false. | 
| UpdateUser.username | String | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!update-user oldScim={"id":"00utiigb9kCWr4rzE0h7"} newScim={"name":{"givenName":"Demisto"}} using=OktaITAdmin```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Okta IT Admin",
        "details": {
            "_links": {
                "deactivate": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/deactivate",
                    "method": "POST"
                },
                "reactivate": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reactivate",
                    "method": "POST"
                },
                "resetPassword": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reset_password",
                    "method": "POST"
                },
                "schema": {
                    "href": "https://test.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"
                },
                "self": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7"
                },
                "suspend": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/suspend",
                    "method": "POST"
                },
                "type": {
                    "href": "https://test.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"
                }
            },
            "activated": "2020-08-24T15:01:20.000Z",
            "created": "2020-08-21T16:59:04.000Z",
            "credentials": {
                "provider": {
                    "name": "OKTA",
                    "type": "OKTA"
                }
            },
            "id": "00utiigb9kCWr4rzE0h7",
            "lastLogin": null,
            "lastUpdated": "2020-08-24T15:04:21.000Z",
            "passwordChanged": null,
            "profile": {
                "email": "testdemisto@paloaltonetworks.com",
                "firstName": "Demisto",
                "lastName": "Test",
                "login": "testdemisto@paloaltonetworks.com",
                "mobilePhone": null,
                "secondEmail": null
            },
            "status": "PROVISIONED",
            "statusChanged": "2020-08-24T15:01:20.000Z",
            "type": {
                "id": "oty8zfz6plq7b0r830h7"
            }
        },
        "email": "testdemisto@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "00utiigb9kCWr4rzE0h7",
        "instanceName": "OktaITAdmin",
        "success": true,
        "username": "testdemisto@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Update Okta User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Okta IT Admin | OktaITAdmin | true | true | 00utiigb9kCWr4rzE0h7 | testdemisto@paloaltonetworks.com | testdemisto@paloaltonetworks.com | id: 00utiigb9kCWr4rzE0h7<br/>status: PROVISIONED<br/>created: 2020-08-21T16:59:04.000Z<br/>activated: 2020-08-24T15:01:20.000Z<br/>statusChanged: 2020-08-24T15:01:20.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-08-24T15:04:21.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto@paloaltonetworks.com", "email": "testdemisto@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"suspend": {"href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/suspend", "method": "POST"}, "schema": {"href": "https://panw-test.oktapreview.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"}, "resetPassword": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reset_password", "method": "POST"}, "reactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reactivate", "method": "POST"}, "self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7"}, "type": {"href": "https://panw-test.oktapreview.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"}, "deactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/deactivate", "method": "POST"}} |


### get-user
***
Retrieves a single user resource.


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
| GetUser.active | Boolean | User status, set to one of the following values:  true or false | 
| GetUser.brand | String | User's brand name | 
| GetUser.details | Unknown | Gives the user information if the API is success else error information | 
| GetUser.email | String | User's email address | 
| GetUser.errorCode | Number | Error code in the case of exception.  Example: 404 | 
| GetUser.errorMessage | String | Error message in the case of exception | 
| GetUser.id | String | User''s id | 
| GetUser.instanceName | String | Instance name for the Integration | 
| GetUser.success | Boolean | Success status. Can be True or False | 
| GetUser.username | String | User''s username | 
| Account | Unknown | Account information | 


#### Command Example
```!get-user scim={"id":"00utiigb9kCWr4rzE0h7"} using=OktaITAdmin```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "Okta IT Admin",
        "details": {
            "_links": {
                "deactivate": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/deactivate",
                    "method": "POST"
                },
                "reactivate": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reactivate",
                    "method": "POST"
                },
                "resetPassword": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reset_password",
                    "method": "POST"
                },
                "schema": {
                    "href": "https://test.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"
                },
                "self": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7"
                },
                "suspend": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/suspend",
                    "method": "POST"
                },
                "type": {
                    "href": "https://test.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"
                }
            },
            "activated": "2020-08-24T15:01:20.000Z",
            "created": "2020-08-21T16:59:04.000Z",
            "credentials": {
                "provider": {
                    "name": "OKTA",
                    "type": "OKTA"
                }
            },
            "id": "00utiigb9kCWr4rzE0h7",
            "lastLogin": null,
            "lastUpdated": "2020-08-24T15:01:20.000Z",
            "passwordChanged": null,
            "profile": {
                "email": "testdemisto@paloaltonetworks.com",
                "firstName": "Demisto",
                "lastName": "Test",
                "login": "testdemisto@paloaltonetworks.com",
                "mobilePhone": null,
                "secondEmail": null
            },
            "status": "PROVISIONED",
            "statusChanged": "2020-08-24T15:01:20.000Z",
            "type": {
                "id": "oty8zfz6plq7b0r830h7"
            }
        },
        "email": "testdemisto@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "00utiigb9kCWr4rzE0h7",
        "instanceName": "OktaITAdmin",
        "success": true,
        "username": "testdemisto@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get Okta User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Okta IT Admin | OktaITAdmin | true | true | 00utiigb9kCWr4rzE0h7 | testdemisto@paloaltonetworks.com | testdemisto@paloaltonetworks.com | id: 00utiigb9kCWr4rzE0h7<br/>status: PROVISIONED<br/>created: 2020-08-21T16:59:04.000Z<br/>activated: 2020-08-24T15:01:20.000Z<br/>statusChanged: 2020-08-24T15:01:20.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-08-24T15:01:20.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto@paloaltonetworks.com", "email": "testdemisto@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"suspend": {"href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/suspend", "method": "POST"}, "schema": {"href": "https://panw-test.oktapreview.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"}, "resetPassword": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reset_password", "method": "POST"}, "reactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/reactivate", "method": "POST"}, "self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7"}, "type": {"href": "https://panw-test.oktapreview.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"}, "deactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00utiigb9kCWr4rzE0h7/lifecycle/deactivate", "method": "POST"}} |


### enable-user
***
Enable active users by setting the active attribute equal to true.


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
| EnableUser.active | Boolean | Gives the active status of user. Can be true of false. | 
| EnableUser.details | Unknown | Gives the detail error information | 
| EnableUser.email | String | Value of email ID passed as argument | 
| EnableUser.errorCode | Number | HTTP error response code | 
| EnableUser.errorMessage | String | Reason why the API is failed | 
| EnableUser.id | String | Value of id passed as argument | 
| EnableUser.instanceName | String | Name of the instance used for testing | 
| EnableUser.success | Boolean | Status of the result. Can be true or false | 
| EnableUser.brand | String | Name of the Integration | 
| EnableUser.username | String | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!enable-user scim={"id":"00utiigb9kCWr4rzE0h7"} using=OktaITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Okta IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "00utiigb9kCWr4rzE0h7",
        "instanceName": "OktaITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Okta User:
>|brand|instanceName|success|active|id|
>|---|---|---|---|---|
>| Okta IT Admin | OktaITAdmin | true | true | 00utiigb9kCWr4rzE0h7 |


### disable-user
***
Disable active users by setting the active attribute equal to false.


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
| DisableUser.active | Boolean | Gives the active status of user. Can be true of false | 
| DisableUser.brand | String | Name of the Integration | 
| DisableUser.details | Unknown | Gives the detail error information | 
| DisableUser.email | String | Value of email ID passed as argument | 
| DisableUser.errorCode | Number | HTTP error response code | 
| DisableUser.errorMessage | String | Reason why the API is failed | 
| DisableUser.id | String | Value of id passed as argument | 
| DisableUser.instanceName | String | Name of the instance used for testing | 
| DisableUser.success | Boolean | Status of the result. Can be true or false | 
| DisableUser.username | String | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!disable-user scim={"id":"00utiigb9kCWr4rzE0h7"} using=OktaITAdmin```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Okta IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "00utiigb9kCWr4rzE0h7",
        "instanceName": "OktaITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable Okta User:
>|brand|instanceName|success|active|id|
>|---|---|---|---|---|
>| Okta IT Admin | OktaITAdmin | true | false | 00utiigb9kCWr4rzE0h7 |


### okta-get-assigned-user-for-app
***
Fetches a specific user assignment for an application by id


#### Base Command

`okta-get-assigned-user-for-app`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationId | Application id of the application for which to get information | Required | 
| userId | User ID of the user for which to get information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.UserAppAssignment.profile | Unknown | App-specific profile for the user | 
| Okta.UserAppAssignment.created | Unknown | Timestamp when app user was created | 
| Okta.UserAppAssignment.credentials | Unknown | Credentials for assigned app | 
| Okta.UserAppAssignment.externalId | String | Id of user in target app | 
| Okta.UserAppAssignment.id | String | unique key of the user | 
| Okta.UserAppAssignment.status | Unknown | Status of app user | 
| Okta.UserAppAssignment.success | Boolean | Okta API call result: True/False | 
| Okta.UserAppAssignment.errorCode | Unknown | Error Code if the command fails | 
| Okta.UserAppAssignment.errorMessage | String | Error Message if the command fails | 


#### Command Example
```!okta-get-assigned-user-for-app applicationId=0oae6ioe81sQ64Aui0h7 userId=00utiigb9kCWr4rzE0h7 using=OktaITAdmin ```

#### Context Example
```
{
    "Okta": {
        "UserAppAssignment": {
            "_links": {
                "app": {
                    "href": "https://test.com/api/v1/apps/0oae6ioe81sQ64Aui0h7"
                },
                "group": {
                    "href": "https://test.com/api/v1/groups/00g9rc2fl8sCK52YN0h7",
                    "name": "All AD Users"
                },
                "user": {
                    "href": "https://test.com/api/v1/users/00utiigb9kCWr4rzE0h7"
                }
            },
            "created": "2020-08-24T15:04:29.000Z",
            "credentials": {
                "userName": "testdemisto@paloaltonetworks.com"
            },
            "externalId": null,
            "id": "00utiigb9kCWr4rzE0h7",
            "lastUpdated": "2020-08-24T15:04:29.000Z",
            "passwordChanged": null,
            "profile": {
                "admin": false,
                "email": "testdemisto@paloaltonetworks.com",
                "firstName": "Demisto",
                "groupAdmin": false,
                "lastName": "Test",
                "licensedSheetCreator": false,
                "resourceViewer": false
            },
            "scope": "GROUP",
            "status": "ACTIVE",
            "statusChanged": "2020-08-24T15:04:29.000Z",
            "success": true,
            "syncState": "DISABLED"
        }
    }
}
```

#### Human Readable Output

>### Okta User App Assignment:
>|success|id|
>|---|---|
>| true | 00utiigb9kCWr4rzE0h7 |

