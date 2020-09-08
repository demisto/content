Perform Slack Admin action in a Slack Enterprise Grid environment.
This integration was integrated and tested with version 01 of Slack IT Admin
## Configure Slack IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Slack IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_token | Slack API access token | True |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping used for Update User | False |
| proxy | Use system proxy settings | False |
| unsecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### slack-create-group
***
Creates a group.


#### Base Command

`slack-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Group Display name | Required | 
| memberIds | List of slack user Ids (Example: ["U0W0NQFFC","U0W0C30RE"]). A maximum of 15,000 users can be added per call. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!slack-create-group groupName="testGroup2" memberIds=`["W01A08KR5A5"]` using=SlackITAdmin```

#### Context Example
```
{}
```

#### Human Readable Output

>Slack Group "S01ABH7DXPS" created successfully

### slack-get-group
***
Retrieves the group information including members


#### Base Command

`slack-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | Group ID | Optional | 
| groupName | Group Name | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.Group.Id | String | Group Id | 
| Slack.Group.DisplayName | String | Display Name of the Group | 
| Slack.Group.Members.display | String | Display Name of the group member | 
| Slack.Group.Members.value | String | Id of the group member | 


#### Command Example
```!slack-get-group groupId="S0196Q89WG7" using=SlackITAdmin```

#### Context Example
```
{
    "Slack": {
        "Group": {
            "DisplayName": "TestGroup",
            "Id": "S0196Q89WG7",
            "Members": [
                {
                    "display": "Demisto Test",
                    "value": "W01A08KR5A5"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Slack Group Members: TestGroup [S0196Q89WG7]
>|display|value|
>|---|---|
>| Demisto Test | W01A08KR5A5 |


### slack-delete-group
***
Permanently removes a group (members are not deleted, only the group).


#### Base Command

`slack-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | Group ID to Delete | Optional | 
| groupName | Group name to Delete | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!slack-delete-group groupId="S019MMT3UBC"  using=SlackITAdmin```

#### Context Example
```
{}
```

#### Human Readable Output

>Slack Group: "S019MMT3UBC" was deleted successfully

### slack-update-group-members
***
Updates an existing group resource. This command allows individual (or groups of) users to be added or removed from the group with a single operation. A max of 15,000 users can be modified in 1 call


#### Base Command

`slack-update-group-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | Group ID | Optional | 
| groupName | Group Name | Optional | 
| memberIdsToAdd | List of members ids to add. A maximum of 15,000 users per call can be modified using this command | Optional | 
| memberIdsToDelete | List of members ids to be deleted from the group. A maximum of 15,000 users per call can be modified using this command | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.Group.id | Unknown | Group Id | 
| Slack.Group.displayName | Unknown | Display Name of the Group | 
| Slack.Group.members | Unknown | Id of the group member | 


#### Command Example
```!slack-update-group-members groupId="S0196Q89WG7" memberIdsToAdd=`["W019TNVDYG4"]` memberIdsToDelete=`["W01A08KR5A5"]` using=SlackITAdmin```

#### Context Example
```
{}
```

#### Human Readable Output

>Updated Slack Group Members for group : S0196Q89WG7

### slack-replace-group
***
Updates an existing group resource, overwriting all values for a group even if an attribute is empty or not provided. A maximum of 15,000 users per call can be updated using this endpoint. If the member list is not provided, all members will be removed from the group


#### Base Command

`slack-replace-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | Group ID | Optional | 
| groupName | Group name of the group to replace | Optional | 
| newGroupName | New Group Name if the group name needs to be updated. If no update is needed,, provide the old group name | Required | 
| memberIds | List of slack user ID values (example: ["U0W0NQFFC","U0W0C30RE"]). This will replace all members of a group with the members provided here | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!slack-replace-group newGroupName="TestGroup" groupId="S0196Q89WG7" memberIds=`["W01A08KR5A5"]` using=SlackITAdmin```

#### Context Example
```
{}
```

#### Human Readable Output

>### Slack Group replaced: S0196Q89WG7
>|displayName|id|members|meta|schemas|
>|---|---|---|---|---|
>| TestGroup | S0196Q89WG7 | {'value': 'W01A08KR5A5', 'display': 'Demisto Test'} | created: 2020-08-27T09:33:25-07:00<br/>location: https://api.slack.com/scim/v1/Groups/S0196Q89WG7 | urn:scim:schemas:core:1.0 |


### create-user
***
Creates a user.


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
| CreateUser | unknown | Command context path | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false | 
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.details | unknown | Gives the detail error information | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false | 
| CreateUser.username | string | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!create-user scim=`{"userName":"demistotest7@paloaltonetworks.com","emails":[{"type":"work","primary":true,"value":"demistotest7@paloaltonetworks.com"}],"name":{"familyName":"Test","givenName":"Demisto"}}`  using=SlackITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Slack IT Admin",
        "details": {
            "active": true,
            "displayName": "demistotest7",
            "emails": [
                {
                    "primary": true,
                    "value": "demistotest7@paloaltonetworks.com"
                }
            ],
            "externalId": "",
            "groups": [],
            "id": "W019F0EE6VC",
            "meta": {
                "created": "2020-08-27T10:43:31-07:00",
                "location": "https://api.slack.com/scim/v1/Users/W019F0EE6VC"
            },
            "name": {
                "familyName": "Test",
                "givenName": "Demisto"
            },
            "nickName": "demistotest7",
            "photos": [
                {
                    "type": "photo",
                    "value": "https://secure.gravatar.com/avatar/e23d3d5d34530e3637bfa91fb92e2d6b.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0008-192.png"
                }
            ],
            "profileUrl": "https://panw-grid-sandbox.enterprise.slack.com/team/demistotest7",
            "schemas": [
                "urn:scim:schemas:core:1.0"
            ],
            "timezone": "America/Los_Angeles",
            "title": "",
            "userName": "demistotest7"
        },
        "email": "demistotest7@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "W019F0EE6VC",
        "instanceName": "SlackITAdmin",
        "success": true,
        "username": "demistotest7"
    }
}
```

#### Human Readable Output

>### Create Slack User:
>|active|brand|details|email|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|
>| true | Slack IT Admin | schemas: urn:scim:schemas:core:1.0<br/>id: W019F0EE6VC<br/>externalId: <br/>meta: {"created": "2020-08-27T10:43:31-07:00", "location": "https://api.slack.com/scim/v1/Users/W019F0EE6VC"}<br/>userName: demistotest7<br/>nickName: demistotest7<br/>name: {"givenName": "Demisto", "familyName": "Test"}<br/>displayName: demistotest7<br/>profileUrl: https://panw-grid-sandbox.enterprise.slack.com/team/demistotest7<br/>title: <br/>timezone: America/Los_Angeles<br/>active: true<br/>emails: {'value': 'demistotest7@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/e23d3d5d34530e3637bfa91fb92e2d6b.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0008-192.png', 'type': 'photo'}<br/>groups:  | demistotest7@paloaltonetworks.com | W019F0EE6VC | SlackITAdmin | true | demistotest7 |


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
| EnableUser | unknown | Command context path | 
| EnableUser.active | boolean | Gives the active status of user. Can be true of false. | 
| EnableUser.details | unknown | Gives the detail error information | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP error response code | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.instanceName | string |  Name of the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.username | string | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!enable-user scim=`{"id":"W01ABAMTWHW"}` using=SlackITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Slack IT Admin",
        "details": {
            "active": true,
            "displayName": "demistotest1",
            "emails": [
                {
                    "primary": true,
                    "value": "demistotest1@paloaltonetworks.com"
                }
            ],
            "externalId": "",
            "groups": [],
            "id": "W01ABAMTWHW",
            "meta": {
                "created": "2020-08-27T09:16:28-07:00",
                "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"
            },
            "name": {
                "familyName": "Test",
                "givenName": "XSOAR"
            },
            "nickName": "demistotest1",
            "photos": [
                {
                    "type": "photo",
                    "value": "https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png"
                }
            ],
            "profileUrl": "https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1",
            "schemas": [
                "urn:scim:schemas:core:1.0"
            ],
            "timezone": "America/Los_Angeles",
            "title": "",
            "userName": "demistotest1"
        },
        "email": "demistotest1@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "W01ABAMTWHW",
        "instanceName": "SlackITAdmin",
        "success": true,
        "username": "demistotest1"
    }
}
```

#### Human Readable Output

>### Enable Slack User:
>|active|brand|details|email|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|
>| true | Slack IT Admin | schemas: urn:scim:schemas:core:1.0<br/>id: W01ABAMTWHW<br/>externalId: <br/>meta: {"created": "2020-08-27T09:16:28-07:00", "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"}<br/>userName: demistotest1<br/>nickName: demistotest1<br/>name: {"givenName": "XSOAR", "familyName": "Test"}<br/>displayName: demistotest1<br/>profileUrl: https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1<br/>title: <br/>timezone: America/Los_Angeles<br/>active: true<br/>emails: {'value': 'demistotest1@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png', 'type': 'photo'}<br/>groups:  | demistotest1@paloaltonetworks.com | W01ABAMTWHW | SlackITAdmin | true | demistotest1 |


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
| DisableUser | boolean | Command context path | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false | 
| DisableUser.brand | string | Name of the Integration | 
| DisableUser.details | string | Gives the detail error information | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP error response code | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.instanceName | string |  Name of the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false | 
| DisableUser.username | string | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!disable-user scim=`{"id":"W01ABAMTWHW"}` using=SlackITAdmin```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Slack IT Admin",
        "details": {
            "active": false,
            "displayName": "demistotest1",
            "emails": [
                {
                    "primary": true,
                    "value": "demistotest1@paloaltonetworks.com"
                }
            ],
            "externalId": "",
            "groups": [],
            "id": "W01ABAMTWHW",
            "meta": {
                "created": "2020-08-27T09:16:28-07:00",
                "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"
            },
            "name": {
                "familyName": "Test",
                "givenName": "XSOAR"
            },
            "nickName": "demistotest1",
            "photos": [
                {
                    "type": "photo",
                    "value": "https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png"
                }
            ],
            "profileUrl": "https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1",
            "schemas": [
                "urn:scim:schemas:core:1.0"
            ],
            "timezone": "America/Los_Angeles",
            "title": "",
            "userName": "demistotest1"
        },
        "email": "demistotest1@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "W01ABAMTWHW",
        "instanceName": "SlackITAdmin",
        "success": true,
        "username": "demistotest1"
    }
}
```

#### Human Readable Output

>### Disable Slack User:
>|active|brand|details|email|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|
>| false | Slack IT Admin | schemas: urn:scim:schemas:core:1.0<br/>id: W01ABAMTWHW<br/>externalId: <br/>meta: {"created": "2020-08-27T09:16:28-07:00", "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"}<br/>userName: demistotest1<br/>nickName: demistotest1<br/>name: {"givenName": "XSOAR", "familyName": "Test"}<br/>displayName: demistotest1<br/>profileUrl: https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1<br/>title: <br/>timezone: America/Los_Angeles<br/>active: false<br/>emails: {'value': 'demistotest1@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png', 'type': 'photo'}<br/>groups:  | demistotest1@paloaltonetworks.com | W01ABAMTWHW | SlackITAdmin | true | demistotest1 |


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
| UpdateUser | unknown | Command context path | 
| UpdateUser.active | boolean | Gives the active status of user. Can be true of false | 
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.details | unknown | Gives the detail error information | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string | Reason why the API is failed | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.username | string | Value of username passed as argument | 
| Account | Unknown | Account information | 


#### Command Example
```!update-user oldScim=`{"id":"W01ABAMTWHW"}` newScim=`{"name":{"familyName":"Test","givenName":"XSOAR"}}` using=SlackITAdmin```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Slack IT Admin",
        "details": {
            "active": true,
            "displayName": "demistotest1",
            "emails": [
                {
                    "primary": true,
                    "value": "demistotest1@paloaltonetworks.com"
                }
            ],
            "externalId": "",
            "groups": [],
            "id": "W01ABAMTWHW",
            "meta": {
                "created": "2020-08-27T09:16:28-07:00",
                "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"
            },
            "name": {
                "familyName": "Test",
                "givenName": "XSOAR"
            },
            "nickName": "demistotest1",
            "photos": [
                {
                    "type": "photo",
                    "value": "https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png"
                }
            ],
            "profileUrl": "https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1",
            "schemas": [
                "urn:scim:schemas:core:1.0"
            ],
            "timezone": "America/Los_Angeles",
            "title": "",
            "userName": "demistotest1"
        },
        "email": "demistotest1@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "W01ABAMTWHW",
        "instanceName": "SlackITAdmin",
        "success": true,
        "username": "demistotest1"
    }
}
```

#### Human Readable Output

>### Update Slack User:
>|active|brand|details|email|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|
>| true | Slack IT Admin | schemas: urn:scim:schemas:core:1.0<br/>id: W01ABAMTWHW<br/>externalId: <br/>meta: {"created": "2020-08-27T09:16:28-07:00", "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"}<br/>userName: demistotest1<br/>nickName: demistotest1<br/>name: {"givenName": "XSOAR", "familyName": "Test"}<br/>displayName: demistotest1<br/>profileUrl: https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1<br/>title: <br/>timezone: America/Los_Angeles<br/>active: true<br/>emails: {'value': 'demistotest1@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png', 'type': 'photo'}<br/>groups:  | demistotest1@paloaltonetworks.com | W01ABAMTWHW | SlackITAdmin | true | demistotest1 |


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
| GetUser.active | boolean | User status, set to one of the following values:  true or false | 
| GetUser.brand | string | User's brand name | 
| GetUser.details | Unknown | Gives the user information if the API is success else error information | 
| GetUser.email | string | User's email address | 
| GetUser.errorCode | number | Error code in the case of exception.  Example: 404 | 
| GetUser.errorMessage | string | Error message in the case of exception | 
| GetUser.id | string | User''s id | 
| GetUser.instanceName | string | Instance name for the Integration | 
| GetUser.success | boolean | Success status. Can be True or False | 
| GetUser.username | string | User''s username | 
| Account | Unknown | Account information | 


#### Command Example
```!get-user scim=`{"id":"W01ABAMTWHW"}` using=SlackITAdmin```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "Slack IT Admin",
        "details": {
            "active": true,
            "displayName": "demistotest1",
            "emails": [
                {
                    "primary": true,
                    "value": "demistotest1@paloaltonetworks.com"
                }
            ],
            "externalId": "",
            "groups": [],
            "id": "W01ABAMTWHW",
            "meta": {
                "created": "2020-08-27T09:16:28-07:00",
                "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"
            },
            "name": {
                "familyName": "Test",
                "givenName": "XSOAR"
            },
            "nickName": "demistotest1",
            "photos": [
                {
                    "type": "photo",
                    "value": "https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png"
                }
            ],
            "profileUrl": "https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1",
            "schemas": [
                "urn:scim:schemas:core:1.0"
            ],
            "timezone": "America/Los_Angeles",
            "title": "",
            "userName": "demistotest1"
        },
        "email": "demistotest1@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "W01ABAMTWHW",
        "instanceName": "SlackITAdmin",
        "success": true,
        "username": "demistotest1"
    }
}
```

#### Human Readable Output

>### Get Slack User:
>|active|brand|details|email|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|
>| true | Slack IT Admin | schemas: urn:scim:schemas:core:1.0<br/>id: W01ABAMTWHW<br/>externalId: <br/>meta: {"created": "2020-08-27T09:16:28-07:00", "location": "https://api.slack.com/scim/v1/Users/W01ABAMTWHW"}<br/>userName: demistotest1<br/>nickName: demistotest1<br/>name: {"givenName": "XSOAR", "familyName": "Test"}<br/>displayName: demistotest1<br/>profileUrl: https://panw-grid-sandbox.enterprise.slack.com/team/demistotest1<br/>title: <br/>timezone: America/Los_Angeles<br/>active: true<br/>emails: {'value': 'demistotest1@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/2e5d596ac7b6a9149323320bae2a08f2.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0017-192.png', 'type': 'photo'}<br/>groups:  | demistotest1@paloaltonetworks.com | W01ABAMTWHW | SlackITAdmin | true | demistotest1 |

