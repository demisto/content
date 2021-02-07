> <i>Note:</i> This integration should be used along with our ILM premium pack. For further details, visit our ILM pack documentation.

Integrate with Okta's Identity Access Management service to execute CRUD operations to employee lifecycle processes.
This integration was integrated and tested with version v1 of the Okta integration.
For more information, refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

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
| create-user-enabled | `iam-create-user` Command Enabled | False |
| update-user-enabled | `iam-update-user` Command Enabled | False |
| disable-user-enabled | `iam-disable-user` Command Enabled | False |
| create-if-not-exists | Automatically create user if not found in update command | False |
| mapper-in | Incoming Mapper | True |
| mapper-out | Outgoing Mapper | True |
| max_fetch | Fetch Limit \(recommended less than 200\) | False |
| isFetch | Fetch incidents | False |
| incidentFetchInterval | Incidents Fetch Interval | False |
| incidentType | Incident type | False |
| auto_generate_query_filter | Query only application events configured in the IAM Configuration | False |
| fetch_query_filter | Fetch Query Filter (Okta system log events) | True |
| first_fetch | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |

* To allow the integration to access the mapper from within the code, as required by the ILM pack, both mappers have to be configured in their proper respective fields and not in the "Mapper (outgoing)" dropdown list selector.

4. Click **Test** to check that you are able to connect to the integration.

## Fetch incidents using an "IAM - Configuration" incident
When the "Query only application events configured in IAM Configuration" checkbox is selected, add or remove event types for the applications you configured in the **IAM Configuration** incident are retrieved.  You must have at least one application configured in XSOAR to fetch incidents from Okta.

## Fetch incidents using a manual query filter expression
**Note: Cortex XSOAR recommends you use the Query only application events configured in IAM Configuration option to generate the fetch-incidents query filter. The following following method should be used primarily for debugging purposes.**
Clear the "Query only application events configured in IAM Configuration" checkbox to use a custom fetch query filter expression. The expression must be in SCIM syntax, and include the add and remove event types, as well as the application ID. 
For example: `(eventType eq "application.user_membership.add" or eventType eq "application.user_membership.remove") and target.id eq "0oar418fvkm67MWGd0h7"`
You may also use the advanced search in Okta's System Logs to generate the filter expression.
For more details, visit [Okta API reference](https://developer.okta.com/docs/reference/api/system-log/#expression-filter).

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
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. | Optional | 


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
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. | Optional | 


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
```!iam-disable-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\"}```

#### Human Readable Output
### Disable User Results (Okta IAM)
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Okta IAM | Okta IAM_instance_1 | true | false | 00uujxnbh3uJw4tWA0h7 | testdemisto2@paloaltonetworks.com | testdemisto2@paloaltonetworks.com | id: 00uujxnbh3uJw4tWA0h7<br/>status: PROVISIONED<br/>created: 2020-10-18T17:54:30.000Z<br/>activated: 2020-10-18T17:54:30.000Z<br/>statusChanged: 2020-10-18T17:54:30.000Z<br/>lastLogin: null<br/>lastUpdated: 2020-10-18T17:56:53.000Z<br/>passwordChanged: null<br/>type: {"id": "oty8zfz6plq7b0r830h7"}<br/>profile: {"firstName": "Demisto-Test", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto2@paloaltonetworks.com"}<br/>credentials: {"provider": {"type": "OKTA", "name": "OKTA"}}<br/>_links: {"self": {"href": "https://panw-test.oktapreview.com/api/v1/users/00uujxnbh3uJw4tWA0h7"}} |


### okta-get-assigned-user-for-app
***
Gets a specific user assignment for an application by id.


#### Base Command

`okta-get-app-user-assignment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of the user for which to get information. | Required | 
| application_id | ID of the application for which to get information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.AppUserAssignment.UserID | string | ID of the user. | 
| Okta.AppUserAssignment.AppID | string | ID of the application. | 
| Okta.AppUserAssignment.IsAssigned | boolean | When True, indicates that the user is assigned to the application. | 
| Okta.AppUserAssignment.ProfileInApp | unknown | The user profile data in the application. | 


#### Command Example
```!okta-get-app-user-assignment user_id=00uuv6y8t1iy8YXm94h7 application_id=0oae3ioe51sQ64Aui2h7```

#### Human Readable Output
### App User Assignment
|App ID|Is Assigned|User ID|
|---|---|---|
| 0oae3ioe51sQ64Aui2h7 | true | 00uuv6y8t1iy8YXm94h7 |


### okta-list-applications
***
Returns a list of Okta applications data.


#### Base Command

`okta-iam-list-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search for applications by their names. | Optional | 
| page | Page number (0-based). Default is 0. | Optional | 
| limit | Maximum number of apps to retrieve (maximal value is 200). Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Application.ID | string | ID of the application. | 
| Okta.Application.Name | string | Name of the application. | 
| Okta.Application.Label | string | Label of the application. | 
| Okta.Application.Logo | string | Logo of the application. | 


#### Command Example
``` !okta-iam-list-applications limit=5 query="Workday" ```

#### Human Readable Output
### Okta Applications (1 - 3)
|ID|Name|Label|Logo|
|---|---|---|---|
| 0ob8zlypk6GVPRr2T0h7 | workday | Workday - Preview | ![](https://op1static.oktacdn.com/fs/bcg/4/gfsnda403rf16Qe790h7) |
| 0oabz0ozy5dDpEKyA0h7 | workday | Workday - Prod - DryRun | ![](https://op1static.oktacdn.com/fs/bcg/4/gfsnda403rf16Qe790h7) |
| 0oae3ioe51sQ64Aui2h7 | workday | Workday - Impl1 | ![](https://op1static.oktacdn.com/fs/bcg/4/gfsnda403rf16Qe790h7) |

### okta-iam-get-configuration
***
Gets the IAM configuration data from the integration context.


#### Base Command

`okta-iam-get-configuration`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.IAMConfiguration.ApplicationID | String | An Okta application ID. | 
| Okta.IAMConfiguration.Name | String | Name of the Okta application. | 
| Okta.IAMConfiguration.Label | String | Label of the Okta application. | 
| Okta.IAMConfiguration.Logo | String | Logo of the application. | 
| Okta.IAMConfiguration.Instance | String | An XSOAR IAM integration instance name. | 


#### Command Example
```!okta-iam-get-configuration using="Okta IAM_instance_1_copy"```

#### Human Readable Output
### Okta IAM Configuration
|ApplicationID|Instance|Label|Logo|Name|
|---|---|---|---|---|
| 0oc8zlypk6GVPRr2G0h7 | ServiceNow IAM_instance_1 | ServiceNow | ![](https://op1static.oktacdn.com/fs/bcg/4/gfskliw1i51ScX6pf0h7) | servicenow |
