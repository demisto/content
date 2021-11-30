Integrate with Clarizen's Identity Access Management service to execute CRUD operations in the employee lifecycle processes.
For more information, refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure ClarizenIAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ClarizenIAM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Base URL | True |
    | Username | True |
    | Password | True |
    | Allow creating users | False |
    | Allow updating users | False |
    | Allow enabling users | False |
    | Allow disabling users | False |
    | Automatically create user if not found in update command | False |
    | Incoming Mapper | True |
    | Outgoing Mapper | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to check that you are able to connect to the integration.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
```!iam-create-user user-profile={\"email\": \"john.doe@example.com\", \"givenname\": \"John\", \"surname\": \"Doe\"}```

#### Human Readable Output
### Create User Results (Clarizen IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Clarizen IAM | Clarizen IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | john.doe@example.com | john.doe@example.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:54:30.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "john.doe@example.com", "email": "john.doe@example.com"}<br/>credentials: {"provider": {"type": "Clarizen", "name": "Clarizen"}} |



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
```!iam-update-user user-profile={\"email\": \"john.doe@example.com\", \"givenname\": \"John\"}```

#### Human Readable Output
### Update User Results (Clarizen IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Clarizen IAM | Clarizen IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | john.doe@example.com | john.doe@example.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "John", "lastName": "Doe", "mobilePhone": null, "secondEmail": null, "login": "john.doe@example.com", "email": "john.doe@example.com"}<br/>credentials: {"provider": {"type": "Clarizen", "name": "Clarizen"}} |



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
```!iam-get-user user-profile={\"email\": \"john.doe@example.com\"}```

#### Human Readable Output
### Get User Results (Clarizen IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Clarizen IAM | Clarizen IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | john.doe@example.com | john.doe@example.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "John", "lastName": "Doe", "mobilePhone": null, "secondEmail": null, "login": "john.doe@example.com", "email": "john.doe@example.com"}<br/>credentials: {"provider": {"type": "Clarizen", "name": "Clarizen"}} |




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
```!iam-disable-user user-profile={\"email\": \"john.doe@example.com\", \"givenname\": \"John\"}```

#### Human Readable Output
### Disable User Results (Clarizen IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Clarizen IAM | Clarizen IAM_instance_1 | true | false | 00uujxnbh3uJw4tWA0h7 | john.doe@example.com | john.doe@example.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "John", "lastName": "Doe", "mobilePhone": null, "secondEmail": null, "login": "john.doe@example.com", "email": "john.doe@example.com"}<br/>credentials: {"provider": {"type": "Clarizen", "name": "Clarizen"}} |
