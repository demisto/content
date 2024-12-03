Note: This integration should be used as part of our **Identity Lifecycle Management** premium pack. For further details, visit our IAM pack documentation.

Integrate with Slack's services to execute CRUD operations for employee lifecycle processes.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Slack IAM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_token | Access Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| create_user_enabled | Allow creating users. If set to false, iam-create-user command will be skipped, and user will not be created. | False |
| update_user_enabled | Allow updating users | False |
| enable_user_enabled | Allow enabling users | False |
| disable_user_enabled | Allow disabling users | False |
| create_if_not_exists | Automatically create user if not found in update command | False |
| mapper_in | Incoming Mapper | True |
| mapper_out | Outgoing Mapper | True |

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
```!iam-create-user user-profile=`{"emails": ["testdemistomock15@paloaltonetworks.com"], "userName": "testuser15"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "emails": [
                "testdemistomock15@paloaltonetworks.com"
            ],
            "userName": "testuser15"
        },
        "Vendor": {
            "action": "create",
            "active": true,
            "brand": "Slack IAM",
            "details": {
                "active": true,
                "displayName": "testuser15",
                "emails": [
                    {
                        "primary": true,
                        "value": "testdemistomock15@paloaltonetworks.com"
                    }
                ],
                "externalId": "",
                "groups": [],
                "id": "U01KGD53152",
                "meta": {
                    "created": "2021-01-20T08:15:37-08:00",
                    "location": "https://api.slack.com/scim/v1/Users/U01KGD53152"
                },
                "name": {
                    "familyName": "",
                    "givenName": "testuser15"
                },
                "nickName": "testuser15",
                "photos": [
                    {
                        "type": "photo",
                        "value": "https://secure.gravatar.com/avatar/17de069a77ac9bf8c47f0c9a4893f598.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0005-192.png"
                    }
                ],
                "profileUrl": "https://panwtest.enterprise.slack.com/team/testuser15",
                "schemas": [
                    "urn:scim:schemas:core:1.0"
                ],
                "timezone": "America/Los_Angeles",
                "title": "",
                "userName": "testuser15"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "U01KGD53152",
            "instanceName": "Slack IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "testuser15"
        }
    }
}
```

#### Human Readable Output

>### Create User Results (Slack IAM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| Slack IAM | Slack IAM_instance_1 | true | true | U01KGD53152 | testuser15 | schemas: urn:scim:schemas:core:1.0<br/>id: U01KGD53152<br/>externalId: <br/>meta: {"created": "2021-01-20T08:15:37-08:00", "location": "https://api.slack.com/scim/v1/Users/U01KGD53152"}<br/>userName: testuser15<br/>nickName: testuser15<br/>name: {"givenName": "testuser15", "familyName": ""}<br/>displayName: testuser15<br/>profileUrl: https://panwtest.enterprise.slack.com/team/testuser15<br/>title: <br/>timezone: America/Los_Angeles<br/>active: true<br/>emails: {'value': 'testdemistomock15@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/17de069a77ac9bf8c47f0c9a4893f598.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0005-192.png', 'type': 'photo'}<br/>groups:  |


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
```!iam-update-user user-profile=`{"email": "testtesting@paloaltonetworks.com", "active": "true"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "active": "true",
            "email": "testtesting@paloaltonetworks.com"
        },
        "Vendor": {
            "action": "update",
            "active": true,
            "brand": "Slack IAM",
            "details": {
                "active": true,
                "displayName": "powershelly12",
                "emails": [
                    {
                        "primary": true,
                        "value": "testtesting@paloaltonetworks.com"
                    }
                ],
                "externalId": "",
                "groups": [],
                "id": "U01JYDGBC3Y",
                "meta": {
                    "created": "2021-01-19T07:41:11-08:00",
                    "location": "https://api.slack.com/scim/v1/Users/U01JYDGBC3Y"
                },
                "name": {
                    "familyName": "",
                    "givenName": "powershelly12"
                },
                "nickName": "powershelly12",
                "photos": [
                    {
                        "type": "photo",
                        "value": "https://secure.gravatar.com/avatar/5f359e3923fc928897380e3e90cb980e.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0007-192.png"
                    }
                ],
                "profileUrl": "https://panwtest.enterprise.slack.com/team/powershelly12",
                "schemas": [
                    "urn:scim:schemas:core:1.0"
                ],
                "timezone": "America/Los_Angeles",
                "title": "",
                "userName": "powershelly12"
            },
            "email": "testtesting@paloaltonetworks.com",
            "errorCode": null,
            "errorMessage": "",
            "id": "U01JYDGBC3Y",
            "instanceName": "Slack IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "powershelly12"
        }
    }
}
```

#### Human Readable Output

>### Update User Results (Slack IAM)
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Slack IAM | Slack IAM_instance_1 | true | true | U01JYDGBC3Y | powershelly12 | testtesting@paloaltonetworks.com | schemas: urn:scim:schemas:core:1.0<br/>id: U01JYDGBC3Y<br/>externalId: <br/>meta: {"created": "2021-01-19T07:41:11-08:00", "location": "https://api.slack.com/scim/v1/Users/U01JYDGBC3Y"}<br/>userName: powershelly12<br/>nickName: powershelly12<br/>name: {"givenName": "powershelly12", "familyName": ""}<br/>displayName: powershelly12<br/>profileUrl: https://panwtest.enterprise.slack.com/team/powershelly12<br/>title: <br/>timezone: America/Los_Angeles<br/>active: true<br/>emails: {'value': 'testtesting@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/5f359e3923fc928897380e3e90cb980e.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0007-192.png', 'type': 'photo'}<br/>groups:  |


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
```!iam-get-user user-profile=`{"email": "testdemistomock@paloaltonetworks.com", "userName": "powershelly10"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "active": false,
            "displayName": "powershelly10",
            "emails": [
                {
                    "primary": true,
                    "value": "testdemistomock@paloaltonetworks.com"
                }
            ],
            "externalId": "",
            "groups": [],
            "id": "U01KHS7J7U1",
            "meta": {
                "created": "2021-01-19T07:46:20-08:00",
                "location": "https://api.slack.com/scim/v1/Users/U01KHS7J7U1"
            },
            "name": {
                "familyName": "",
                "givenName": "powershelly10"
            },
            "nickName": "powershelly10",
            "photos": [
                {
                    "type": "photo",
                    "value": "https://secure.gravatar.com/avatar/e14bda84be03871922c78d0d03caa901.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0006-192.png"
                }
            ],
            "profileUrl": "https://panwtest.enterprise.slack.com/team/powershelly10",
            "schemas": [
                "urn:scim:schemas:core:1.0"
            ],
            "timezone": "America/Los_Angeles",
            "title": "",
            "userName": "powershelly10"
        },
        "Vendor": {
            "action": "get",
            "active": false,
            "brand": "Slack IAM",
            "details": {
                "active": false,
                "displayName": "powershelly10",
                "emails": [
                    {
                        "primary": true,
                        "value": "testdemistomock@paloaltonetworks.com"
                    }
                ],
                "externalId": "",
                "groups": [],
                "id": "U01KHS7J7U1",
                "meta": {
                    "created": "2021-01-19T07:46:20-08:00",
                    "location": "https://api.slack.com/scim/v1/Users/U01KHS7J7U1"
                },
                "name": {
                    "familyName": "",
                    "givenName": "powershelly10"
                },
                "nickName": "powershelly10",
                "photos": [
                    {
                        "type": "photo",
                        "value": "https://secure.gravatar.com/avatar/e14bda84be03871922c78d0d03caa901.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0006-192.png"
                    }
                ],
                "profileUrl": "https://panwtest.enterprise.slack.com/team/powershelly10",
                "schemas": [
                    "urn:scim:schemas:core:1.0"
                ],
                "timezone": "America/Los_Angeles",
                "title": "",
                "userName": "powershelly10"
            },
            "email": "testdemistomock@paloaltonetworks.com",
            "errorCode": null,
            "errorMessage": "",
            "id": "U01KHS7J7U1",
            "instanceName": "Slack IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "powershelly10"
        }
    }
}
```

#### Human Readable Output

>### Get User Results (Slack IAM)
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Slack IAM | Slack IAM_instance_1 | true | false | U01KHS7J7U1 | powershelly10 | testdemistomock@paloaltonetworks.com | schemas: urn:scim:schemas:core:1.0<br/>id: U01KHS7J7U1<br/>externalId: <br/>meta: {"created": "2021-01-19T07:46:20-08:00", "location": "https://api.slack.com/scim/v1/Users/U01KHS7J7U1"}<br/>userName: powershelly10<br/>nickName: powershelly10<br/>name: {"givenName": "powershelly10", "familyName": ""}<br/>displayName: powershelly10<br/>profileUrl: https://panwtest.enterprise.slack.com/team/powershelly10<br/>title: <br/>timezone: America/Los_Angeles<br/>active: false<br/>emails: {'value': 'testdemistomock@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/e14bda84be03871922c78d0d03caa901.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0006-192.png', 'type': 'photo'}<br/>groups:  |


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
```!iam-disable-user user-profile=`{"email": "testdemistomock@paloaltonetworks.com", "userName": "powershelly10"}````

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "testdemistomock@paloaltonetworks.com",
            "userName": "powershelly10"
        },
        "Vendor": {
            "action": "disable",
            "active": false,
            "brand": "Slack IAM",
            "details": {
                "active": false,
                "displayName": "powershelly10",
                "emails": [
                    {
                        "primary": true,
                        "value": "testdemistomock@paloaltonetworks.com"
                    }
                ],
                "externalId": "",
                "groups": [],
                "id": "U01KHS7J7U1",
                "meta": {
                    "created": "2021-01-19T07:46:20-08:00",
                    "location": "https://api.slack.com/scim/v1/Users/U01KHS7J7U1"
                },
                "name": {
                    "familyName": "",
                    "givenName": "powershelly10"
                },
                "nickName": "powershelly10",
                "photos": [
                    {
                        "type": "photo",
                        "value": "https://secure.gravatar.com/avatar/e14bda84be03871922c78d0d03caa901.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0006-192.png"
                    }
                ],
                "profileUrl": "https://panwtest.enterprise.slack.com/team/powershelly10",
                "schemas": [
                    "urn:scim:schemas:core:1.0"
                ],
                "timezone": "America/Los_Angeles",
                "title": "",
                "userName": "powershelly10"
            },
            "email": "testdemistomock@paloaltonetworks.com",
            "errorCode": null,
            "errorMessage": "",
            "id": "U01KHS7J7U1",
            "instanceName": "Slack IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "powershelly10"
        }
    }
}
```

#### Human Readable Output

### Disable User Results (Slack IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Slack IAM | Slack IAM_instance_1 | true | false | U01KHS7J7U1 | powershelly10 | testdemistomock@paloaltonetworks.com | schemas: urn:scim:schemas:core:1.0<br/>id: U01KHS7J7U1<br/>externalId: <br/>meta: {"created": "2021-01-19T07:46:20-08:00", "location": "https://api.slack.com/scim/v1/Users/U01KHS7J7U1"}<br/>userName: powershelly10<br/>nickName: powershelly10<br/>name: {"givenName": "powershelly10", "familyName": ""}<br/>displayName: powershelly10<br/>profileUrl: https://panwtest.enterprise.slack.com/team/powershelly10<br/>title: <br/>timezone: America/Los_Angeles<br/>active: false<br/>emails: {'value': 'testdemistomock@paloaltonetworks.com', 'primary': True}<br/>photos: {'value': 'https://secure.gravatar.com/avatar/e14bda84be03871922c78d0d03caa901.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0006-192.png', 'type': 'photo'}<br/>groups:  |


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
| CreateGroup.id | String | ID of the group. | 
| CreateGroup.displayName | String | The display name of the group. | 
| CreateGroup.success | Boolean | Indicates whether the command succeeded. | 
| CreateGroup.errorCode | Number | HTTP error response code. | 
| CreateGroup.errorMessage | String | Reason why the API failed. | 

### iam-get-group
***
Retrieves the group information including members


#### Base Command

`iam-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM Data. | Required | 
| includeMembers | Wheather to include group's members. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetGroup.id | String | ID of the group. | 
| GetGroup.displayName | String | The display name of the group. | 
| GetGroup.members.display | String | The display name of the group member. | 
| GetGroup.members.value | String | ID of the group member. | 
| GetGroup.success | Boolean | Indicates whether the command succeeded. | 
| GetGroup.errorCode | Number | HTTP error response code. | 
| GetGroup.errorMessage | String | Reason why the API failed. | 

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
| DeleteGroup.id | String | ID of the group. | 
| DeleteGroup.displayName | String | The display name of the group. | 
| DeleteGroup.success | Boolean | Indicates whether the command succeeded. | 
| DeleteGroup.errorCode | Number | HTTP error response code. | 
| DeleteGroup.errorMessage | String | Reason why the API failed. | 

### iam-update-group
***
Updates an existing group resource. This command allows individual (or groups of) users to be added or removed from the group with a single operation. A max of 15,000 users can be modified in 1 call


#### Base Command

`iam-update-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM data. | Required | 
| memberIdsToAdd | List of members ids to add. A maximum of 15,000 users per call can be modified using this command. | Optional | 
| memberIdsToDelete | List of members ids to be deleted from the group. A maximum of 15,000 users per call can be modified using this command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateGroup.id | String | ID of the group. | 
| UpdateGroup.displayName | String | The display name of the group. | 
| UpdateGroup.success | Boolean | Indicates whether the command succeeded. | 
| UpdateGroup.errorCode | Number | HTTP error response code. | 
| UpdateGroup.errorMessage | String | Reason why the API failed. |