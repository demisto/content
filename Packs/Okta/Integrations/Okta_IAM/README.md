> <i>Note:</i> This integration should be used along with our IAM premium pack. For further details, visit our IAM pack documentation.

Integrate with Okta's Identity Access Management service to execute CRUD operations to employee lifecycle processes.
This integration was integrated and tested with version v1 of Okta.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Okta IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Okta IAM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Okta URL \(https://&lt;domain&gt;.okta.com\) | True |
| apitoken | API Token \(see Detailed Instructions\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| create-user-enabled | Create User Command Enabled | False |
| update-user-enabled | Update User Command Enabled | False |
| enable-disable-user-enabled | Enable/Disable User Commands Enabled | False |
| create-if-not-exists | Automatically create user if not found in update and enable commands | False |
| mapper-in | Incoming Mapper | True |
| mapper-out | Outgoing Mapper | True |
| max_fetch | Fetch Limit \(recommended less than 200\) | False |
| isFetch | Fetch incidents | False |
| incidentFetchInterval | Incidents Fetch Interval | False |
| incidentType | Incident type | False |
| fetch_query_filter | Fetch Query Filter | True |
| fetch_time | First fetch timestamp (<number> <time unit>, e.g., 12 hours, 7 days) | False |

* To allow the integration to access the mapper from within the code, as required by the ILM pack, both mappers have to be configured in their proper respective fields and not in the "Mapper (outgoing)" dropdown list selector.


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true, the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | Indicates if the command executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-create-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\", \"surname\":\"Test\",\"givenname\":\"Demisto\"}```

#### Human Readable Output
### Create User Results (Okta IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Okta IAM | Okta IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:54:30.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto44@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"suspend": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/suspend", "method": "POST"}, "schema": {"href": "https://panw-test.oktapreview.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"}, "resetPassword": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/reset_password", "method": "POST"}, "reactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/reactivate", "method": "POST"}, "self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7"}, "type": {"href": "https://panw-test.oktapreview.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"}, "deactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/deactivate", "method": "POST"}} |



### iam-update-user
***
Updates an existing user with the data passed in the user-profile argument.


#### Base Command

`iam-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | True indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-update-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\", \"givenname\":\"Demisto-Test\"}```

#### Human Readable Output
### Update User Results (Okta IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Okta IAM | Okta IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto-Test", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto2@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"suspend": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/suspend", "method": "POST"}, "schema": {"href": "https://panw-test.oktapreview.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"}, "resetPassword": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/reset_password", "method": "POST"}, "reactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/reactivate", "method": "POST"}, "self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7"}, "type": {"href": "https://panw-test.oktapreview.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"}, "deactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/deactivate", "method": "POST"}} |



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
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-get-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\"}```

#### Human Readable Output
### Get User Results (Okta IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Okta IAM | Okta IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto-Test", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto2@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"suspend": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/suspend", "method": "POST"}, "schema": {"href": "https://panw-test.oktapreview.com/api/v1/meta/schemas/user/osc8zfz6plq7b0r830h7"}, "resetPassword": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/reset_password", "method": "POST"}, "reactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/reactivate", "method": "POST"}, "self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7"}, "type": {"href": "https://panw-test.oktapreview.com/api/v1/meta/types/user/oty8zfz6plq7b0r830h7"}, "deactivate": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7/lifecycle/deactivate", "method": "POST"}} |




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
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-disable-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\"}```

#### Human Readable Output
### Disable User Results (Okta IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Okta IAM | Okta IAM_instance_1 | true | false | 00uujxnbh3uJw4tWA0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto-Test", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto2@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7"}} |



### iam-enable-user
***
Enable a deprovisioned user.


#### Base Command

`iam-enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
```!iam-enable-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\"}```

#### Human Readable Output
### Enable User Results (Okta IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Okta IAM | Okta IAM_instance_1 | true | true | 00uujxnbh3uJw4tWA0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: DEPROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto-Test", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto2@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7"}} |


### okta-get-assigned-user-for-app
***
Gets a specific user assignment for an application by id.


#### Base Command

`okta-get-assigned-user-for-app`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-id | ID of the user for which to get information. | Required | 
| application-id | ID of the application for which to get information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.UserAppAssignment.profile | unknown | App-specific profile for the user. | 
| Okta.UserAppAssignment.created | date | Timestamp when app user was created. | 
| Okta.UserAppAssignment.externalId | string | ID of user in target app. | 
| Okta.UserAppAssignment.id | string | Unique ID of the user. | 
| Okta.UserAppAssignment.status | string | Status of app user. | 
| Okta.UserAppAssignment.credentials | unknown | Credentials for assigned app. | 
| Okta.UserAppAssignment.credentials.userName | string | Username of the user. | 


#### Command Example
```!okta-get-assigned-user-for-app user-id=00uuv6y8t1iy8YXm94h7 application-id=0oae3ioe51sQ64Aui2h7```

#### Human Readable Output
### Okta User App Assignment
|id|profile|created|credentials|status|
|---|---|---|---|---|
| 00uuv6y8t1iy8YXm94h7 | firstName: Test<br/>lastName: Demisto<br/>groupAdmin: false<br/>resourceViewer: false<br/>admin: false<br/>licensedSheetCreator: false<br/>email: testdemisto2@paloaltonetworks.com | 2020-11-03T09:59:30.000Z | userName: testdemisto2@paloaltonetworks.com | ACTIVE |
