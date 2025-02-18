> <i>Note:</i> This integration should be used along with our ILM premium pack. For further details, visit our ILM pack documentation.

Integrate with Okta's Identity Access Management service to execute CRUD operations to employee lifecycle processes.
This integration was integrated and tested with version v1 of the Okta integration.
For more information, refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Okta IAM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Okta URL \(https://&lt;domain&gt;.okta.com\) | True |
| apitoken | API Token \(see Detailed Instructions\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| create-user-enabled | Allow creating users | False |
| update-user-enabled | Allow updating users | False |
| enable-user-enabled | Allow enabling users | False |
| disable-user-enabled | Allow disabling users | False |
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


## Fetch incidents using an "IAM - Configuration" incident
When the "Query only application events configured in IAM Configuration" checkbox is selected, add or remove event types for the applications you configured in the **IAM Configuration** incident are retrieved.  You must have at least one application configured in XSOAR to fetch incidents from Okta.

## Fetch incidents using a manual query filter expression
**Note: Cortex XSOAR recommends you use the Query only application events configured in IAM Configuration option to generate the fetch-incidents query filter. The following following method should be used primarily for debugging purposes.**
Clear the "Query only application events configured in IAM Configuration" checkbox to use a custom fetch query filter expression. The expression must be in SCIM syntax, and include the add and remove event types, as well as the application ID. 
For example: `(eventType eq "application.user_membership.add" or eventType eq "application.user_membership.remove") and target.id eq "0oar418fvkm67MWGd0h7"`
You may also use the advanced search in Okta's System Logs to generate the filter expression.
For more details, visit [Okta API reference](https://developer.okta.com/docs/reference/api/system-log/#expression-filter).

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
##### Create User Results (Okta IAM)
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
##### Update User Results (Okta IAM)
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
##### Get User Results (Okta IAM)
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
##### Disable User Results (Okta IAM)
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
##### App User Assignment
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
##### Okta Applications (1 - 3)
|ID|Name|Label|Logo|
|---|---|---|---|
| 0ob8zlypk6GVPRr2T0h7 | workday | Workday - Preview | ![](../../doc_files/gfsnda403rf16Qe790h7) |
| 0oabz0ozy5dDpEKyA0h7 | workday | Workday - Prod - DryRun | ![](../../doc_files/gfsnda403rf16Qe790h7) |
| 0oae3ioe51sQ64Aui2h7 | workday | Workday - Impl1 | ![](../../doc_files/gfsnda403rf16Qe790h7) |


### okta-list-user-applications
***
Returns a list of Okta applications data.


#### Base Command

`okta-iam-list-user-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of the user for which to get the information. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Application.ID | string | ID of the application. | 
| Okta.Application.Name | string | Name of the application. | 
| Okta.Application.Label | string | Label of the application. | 
| Okta.Application.Status | string | Status of the application. | 


#### Command Example
``` !okta-iam-list-user-applications user_id=00ux9v19bvTfQIjur0h7" ```

#### Human Readable Output
##### Okta User Applications
|ID|Name|Label|Status|
|---|---|---|---|
| 0ob8zlypk6GVPRr2T0h7 | active_directory | pantest.local | ACTIVE|
| 0oabz0ozy5dDpEKyA0h7 | test_app | martsheet Test App | ACTIVE |


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
##### Okta IAM Configuration
|ApplicationID|Instance|Label|Logo|Name|
|---|---|---|---|---|
| 0oc8zlypk6GVPRr2G0h7 | ServiceNow IAM_instance_1 | ServiceNow | ![](../../doc_files/gfskliw1i51ScX6pf0h7) | servicenow |


### okta-iam-set-configuration
***
Updates IAM configuration data in the integration context.


#### Base Command

`okta-iam-set-configuration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| configuration | IAM configuration data. | Required | 


#### Context Output

There is no context output for this command.
### iam-get-group
***
Retrieves the group information, including its members.


#### Base Command

`iam-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | Group SCIM Data. | Required | 
| includeMembers | Field to indicate if members need to be included in the response. . Possible values are: true, false. Default is true. | Required | 


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
### okta-get-logs
***
Gets logs by providing optional filters.


#### Base Command

`okta-get-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Useful for performing structured queries where constraints on LogEvent attribute values can be explicitly targeted.  The following expressions are supported for events with the filter query parameter: eventType eq " :eventType" -Events that have a specific action; eventType target.id eq ":id" - Events published with a specific target id; actor.id eq ":id"- Events published with a specific actor ID. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 
| since | Filters the lower time bound of the log events in the Internet Date/Time Format profile of ISO 8601. For example: 2017-05-03T16:22:18Z. | Optional | 
| until | Filters the upper time bound of the log events in the Internet Date/Time Format profile of ISO 8601. For example: 2017-05-03T16:22:18Z. | Optional | 
| sortOrder | The order of the returned events. Can be "ASCENDING" or "DESCENDING". The default is "ASCENDING". Possible values are: ASCENDING, DESCENDING. Default is ASCENDING. | Optional | 
| limit | The maximum number of results to return. The default and maximum is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternative ID of the actor. | 
| Okta.Logs.Events.actor.displayName | String | Display name of the actor. | 
| Okta.Logs.Events.actor.id | String | ID of the actor. | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operating system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome. | 
| Okta.Logs.Events.client.device | String | Type of device from which the client operated. For example, Computer. | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address from which the client made its request. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.displayMessage | String | The display message for an event. | 
| Okta.Logs.Events.eventType | String | Type of event that was published. | 
| Okta.Logs.Events.outcome.result | String | Result of the action. Can be "SUCCESS", "FAILURE", "SKIPPED", or "UNKNOWN". | 
| Okta.Logs.Events.outcome.reason | String | Reason for the result. For example, INVALID_CREDENTIALS. | 
| Okta.Logs.Events.published | String | Timestamp when the event was published. | 
| Okta.Logs.Events.severity | String | The event severity. Can be "DEBUG", "INFO", "WARN", or "ERROR". | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to send the event's request. | 
| Okta.Logs.Events.securityContext.domain | String | Specifies whether an event's request is from a known proxy. | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source. | 
| Okta.Logs.Events.target.id | String | ID of a target. | 
| Okta.Logs.Events.target.type | String | Type of a target. | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target. | 
| Okta.Logs.Events.target.displayName | String | Display name of a target. | 
