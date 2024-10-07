Note: This integration should be used as part of our IAM premium pack. For further details, visit our IAM pack documentation.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).
Integrate with Atlassian's services to execute generic ILM management operations such as create, update, delete, etc, for employee lifecycle processes.

## Configure Atlassian IAM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Atlassian URL |  | True |
| Access Token |  | True |
| Directory ID |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| create_user_enabled | Allow creating users. If set to false, iam-create-user command will be skipped, and user will not be created. | False |
| update_user_enabled | Allow updating users | False |
| enable_user_enabled | Allow enabling users | False |
| disable_user_enabled | Allow disabling users | False |
| Automatically create user if not found in update command |  | False |
| Incoming Mapper | Incoming Mapper | True |
| Outgoing Mapper | Outgoing Mapper | True |
    
    * To allow the integration to access the mapper from within the code, as required by the ILM pack, both mappers have to be configured in their proper respective fields and not in the "Mapper (outgoing)" dropdown list selector.


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
```!iam-create-user user-profile=`{"emails":[{"value":"testatlas@paloaltonetworks.com","type":"work","primary":"true"}],"is_active": "true", "userName":"testatlas@paloaltonetworks.com"}` using="Atlassian IAM_instance_1"```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "emails": [
                {
                    "primary": "true",
                    "type": "work",
                    "value": "testatlas@paloaltonetworks.com"
                }
            ],
            "is_active": "true",
            "userName": "testatlas@paloaltonetworks.com"
        },
        "Vendor": {
            "action": "create",
            "active": true,
            "brand": "Atlassian IAM",
            "details": {
                "active": true,
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "testatlas@paloaltonetworks.com"
                    }
                ],
                "groups": [],
                "id": "247b915a-9d6c-4cd5-b5a5-071b1b3abc2e",
                "meta": {
                    "created": "2021-02-16T15:05:41.185473Z",
                    "lastModified": "2021-02-16T15:05:41.185473Z",
                    "location": "https://api.atlassian.com/scim/directory/315e79ae-404a-4061-8a88-df91c8c7db34/Users/247b915a-9d6c-4cd5-b5a5-071b1b3abc2e",
                    "resourceType": "User"
                },
                "schemas": [
                    "urn:scim:schemas:extension:atlassian-external:1.0",
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                ],
                "urn:scim:schemas:extension:atlassian-external:1.0": {
                    "atlassianAccountId": "602bdf457b23f40068547c25"
                },
                "userName": "testatlas@paloaltonetworks.com"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "247b915a-9d6c-4cd5-b5a5-071b1b3abc2e",
            "instanceName": "Atlassian IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "testatlas@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### Create User Results (Atlassian IAM)
>|brand|instanceName|success|active|id|username|details|
>|---|---|---|---|---|---|---|
>| Atlassian IAM | Atlassian IAM_instance_1 | true | true | 247b915a-9d6c-4cd5-b5a5-071b1b3abc2e | testatlas@paloaltonetworks.com | schemas: urn:scim:schemas:extension:atlassian-external:1.0,<br/>urn:ietf:params:scim:schemas:core:2.0:User,<br/>urn:ietf:params:scim:schemas:extension:enterprise:2.0:User<br/>userName: testatlas@paloaltonetworks.com<br/>emails: {'value': 'testatlas@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>meta: {"resourceType": "User", "location": "https://api.atlassian.com/scim/directory/315e79ae-404a-4061-8a88-df91c8c7db34/Users/247b915a-9d6c-4cd5-b5a5-071b1b3abc2e", "lastModified": "2021-02-16T15:05:41.185473Z", "created": "2021-02-16T15:05:41.185473Z"}<br/>groups: <br/>urn:scim:schemas:extension:atlassian-external:1.0: {"atlassianAccountId": "602bdf457b23f40068547c25"}<br/>id: 247b915a-9d6c-4cd5-b5a5-071b1b3abc2e<br/>active: true |


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
```!iam-update-user user-profile=`{"email": "testatlas@paloaltonetworks.com", "username": "testatlas@paloaltonetworks.com", "title": "Manager"}` using="Atlassian IAM_instance_1"```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "testatlas@paloaltonetworks.com",
            "title": "Manager",
            "username": "testatlas@paloaltonetworks.com"
        },
        "Vendor": {
            "action": "update",
            "active": true,
            "brand": "Atlassian IAM",
            "details": {
                "active": true,
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "testatlas@paloaltonetworks.com"
                    }
                ],
                "groups": [],
                "id": "247b915a-9d6c-4cd5-b5a5-071b1b3abc2e",
                "meta": {
                    "created": "2021-02-16T15:05:41.185473Z",
                    "lastModified": "2021-02-16T15:05:41.185473Z",
                    "location": "https://api.atlassian.com/scim/directory/315e79ae-404a-4061-8a88-df91c8c7db34/Users/247b915a-9d6c-4cd5-b5a5-071b1b3abc2e",
                    "resourceType": "User"
                },
                "schemas": [
                    "urn:scim:schemas:extension:atlassian-external:1.0",
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                ],
                "urn:scim:schemas:extension:atlassian-external:1.0": {
                    "atlassianAccountId": "602bdf457b23f40068547c25"
                },
                "userName": "testatlas@paloaltonetworks.com"
            },
            "email": "testatlas@paloaltonetworks.com",
            "errorCode": null,
            "errorMessage": "",
            "id": "247b915a-9d6c-4cd5-b5a5-071b1b3abc2e",
            "instanceName": "Atlassian IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "testatlas@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### Update User Results (Atlassian IAM)
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Atlassian IAM | Atlassian IAM_instance_1 | true | true | 247b915a-9d6c-4cd5-b5a5-071b1b3abc2e | testatlas@paloaltonetworks.com | testatlas@paloaltonetworks.com | schemas: urn:scim:schemas:extension:atlassian-external:1.0,<br/>urn:ietf:params:scim:schemas:core:2.0:User,<br/>urn:ietf:params:scim:schemas:extension:enterprise:2.0:User<br/>userName: testatlas@paloaltonetworks.com<br/>emails: {'value': 'testatlas@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>meta: {"resourceType": "User", "location": "https://api.atlassian.com/scim/directory/315e79ae-404a-4061-8a88-df91c8c7db34/Users/247b915a-9d6c-4cd5-b5a5-071b1b3abc2e", "lastModified": "2021-02-16T15:05:41.185473Z", "created": "2021-02-16T15:05:41.185473Z"}<br/>groups: <br/>urn:scim:schemas:extension:atlassian-external:1.0: {"atlassianAccountId": "602bdf457b23f40068547c25"}<br/>id: 247b915a-9d6c-4cd5-b5a5-071b1b3abc2e<br/>active: true |


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
```!iam-get-user user-profile=`{"email": "test@paloaltonetworks.com", "username": "testDemisto"}` using="Atlassian IAM_instance_1"```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "Email": "test@paloaltonetworks.com",
            "Title": "Team Lead",
            "Username": "testDemisto"
        },
        "Vendor": {
            "action": "get",
            "active": null,
            "brand": "Atlassian IAM",
            "details": {
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "test@paloaltonetworks.com"
                    }
                ],
                "groups": [],
                "id": "550364dd-1c1e-4953-bffc-418fce013c2e",
                "meta": {
                    "created": "2021-02-15T13:26:34.13545Z",
                    "lastModified": "2021-02-15T17:01:01.876067Z",
                    "location": "https://api.atlassian.com/scim/directory/315e79ae-404a-4061-8a88-df91c8c7db34/Users/550364dd-1c1e-4953-bffc-418fce013c2e",
                    "resourceType": "User"
                },
                "schemas": [
                    "urn:scim:schemas:extension:atlassian-external:1.0",
                    "urn:ietf:params:scim:schemas:core:2.0:User",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                ],
                "title": "Team Lead",
                "urn:scim:schemas:extension:atlassian-external:1.0": {
                    "atlassianAccountId": "5f3589458d89e30046317d34"
                },
                "userName": "testDemisto"
            },
            "email": null,
            "errorCode": null,
            "errorMessage": "",
            "id": "550364dd-1c1e-4953-bffc-418fce013c2e",
            "instanceName": "Atlassian IAM_instance_1",
            "reason": "",
            "skipped": false,
            "success": true,
            "username": "testDemisto"
        }
    }
}
```

#### Human Readable Output

>### Get User Results (Atlassian IAM)
>|brand|instanceName|success|id|username|details|
>|---|---|---|---|---|---|
>| Atlassian IAM | Atlassian IAM_instance_1 | true | 550364dd-1c1e-4953-bffc-418fce013c2e | testDemisto | schemas: urn:scim:schemas:extension:atlassian-external:1.0,<br/>urn:ietf:params:scim:schemas:core:2.0:User,<br/>urn:ietf:params:scim:schemas:extension:enterprise:2.0:User<br/>userName: testDemisto<br/>emails: {'value': 'test@paloaltonetworks.com', 'type': 'work', 'primary': True}<br/>title: Team Lead<br/>meta: {"resourceType": "User", "location": "https://api.atlassian.com/scim/directory/315e79ae-404a-4061-8a88-df91c8c7db34/Users/550364dd-1c1e-4953-bffc-418fce013c2e", "lastModified": "2021-02-15T17:01:01.876067Z", "created": "2021-02-15T13:26:34.13545Z"}<br/>groups: <br/>urn:scim:schemas:extension:atlassian-external:1.0: {"atlassianAccountId": "5f3589458d89e30046317d34"}<br/>id: 550364dd-1c1e-4953-bffc-418fce013c2e |


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
```!iam-disable-user user-profile=`{"email": "testdemisto@paloaltonetworks.com", "username": "Demisto"}` using="Atlassian IAM_instance_1"```

#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "testdemisto@paloaltonetworks.com",
            "username": "Demisto"
        },
        "Vendor": {
            "action": "disable",
            "active": null,
            "brand": "Atlassian IAM",
            "details": null,
            "email": "testdemisto@paloaltonetworks.com",
            "errorCode": null,
            "errorMessage": "",
            "id": null,
            "instanceName": "Atlassian IAM_instance_1",
            "reason": "User does not exist",
            "skipped": true,
            "success": true,
            "username": null
        }
    }
}
```

#### Human Readable Output

>### Disable User Results (Atlassian IAM)
>|brand|instanceName|skipped|reason|
>|---|---|---|---|
>| Atlassian IAM | Atlassian IAM_instance_1 | true | User does not exist |

