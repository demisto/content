Integration with Okta's cloud-based identity management service.
## Configure Okta v2_Custom on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Okta v2_Custom.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Okta URL (https://&lt;domain&gt;.okta.com) | True |
    | API Token (see detailed instructions) | False |
    | API Token (see detailed instructions) | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### okta-unlock-user

***
Unlocks a single user.

#### Base Command

`okta-unlock-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to unlock. | Required | 

#### Context Output

There is no context output for this command.
### okta-deactivate-user

***
Deactivates a single user.

#### Base Command

`okta-deactivate-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to deactivate. | Required | 

#### Context Output

There is no context output for this command.
### okta-activate-user

***
Activates a single user.

#### Base Command

`okta-activate-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to activate. | Required | 

#### Context Output

There is no context output for this command.
### okta-suspend-user

***
Suspends a single user. This operation can only be performed on users with an ACTIVE status. After the porcess is completed, the user's status is SUSPENDED.

#### Base Command

`okta-suspend-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to suspend. | Required | 

#### Context Output

There is no context output for this command.
### okta-unsuspend-user

***
Returns a single user to ACTIVE status. This operation can only be performed on users that have a SUSPENDED status.

#### Base Command

`okta-unsuspend-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to change the status to ACTIVE. | Required | 

#### Context Output

There is no context output for this command.
### okta-get-user-factors

***
Returns all the enrolled factors for the specified user.

#### Base Command

`okta-get-user-factors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username for which to return all enrolled factors. | Optional | 
| userId | User ID of the user for which to get all enrolled factors. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID. | 
| Account.Factor.ID | String | Okta account factor ID. | 
| Account.Factor.Provider | String | Okta account factor provider | 
| Account.Factor.Profile | String | Okta account factor profile. | 
| Account.Factor.FactorType | String | Okta account factor type. | 
| Account.Factor.Status | Unknown | Okta account factor status. | 

### okta-reset-factor

***
Un-enrolls an existing factor for the specified user. This enables the user to enroll a new factor.

#### Base Command

`okta-reset-factor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | The user ID. | Optional | 
| username | Username for which to un-enroll an existing factor. | Optional | 
| factorId | The ID of the factor to reset. | Required | 

#### Context Output

There is no context output for this command.
### okta-set-password

***
Sets passwords without validating existing user credentials.

#### Base Command

`okta-set-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username for which to set the password. | Required | 
| password | The new password to set for the user. | Required | 
| temporary_password | When true, you'll need to change the password in the next login. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### okta-add-to-group

***
Adds a user to a group with OKTA_GROUP type.

#### Base Command

`okta-add-to-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | ID of the user to add to the group. | Optional | 
| username | Name of the user to add to the group. | Optional | 
| groupId | ID of the group to add the user to. | Optional | 
| groupName | Name of the group to add the user to. | Optional | 

#### Context Output

There is no context output for this command.
### okta-remove-from-group

***
Removes a user from a group with OKTA_GROUP type

#### Base Command

`okta-remove-from-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | ID of the user to remove from the group. | Optional | 
| username | Name of the user to remove from the group. | Optional | 
| groupId | ID of the group to remove the user from. | Optional | 
| groupName | Name of the group to remove the user from. | Optional | 

#### Context Output

There is no context output for this command.
### okta-get-groups

***
Returns all user groups associated with a specified user.

#### Base Command

`okta-get-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username in Okta for which to get the associated groups. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Group | Unknown | Okta groups with which the account is associated. | 
| Account.ID | String | Okta account ID. | 
| Account.Type | String | Okta account type. | 
| Account.Group.ID | String | Unique key for the group. | 
| Account.Group.Created | Date | Timestamp when the group was created. | 
| Account.Group.ObjectClass | String | The object class, which determines the group's profile. | 
| Account.Group.LastUpdated | Date | Timestamp when the group's profile was last updated. | 
| Account.Group.LastMembershipUpdated | Date | Timestamp when the group's memberships were last updated. | 
| Account.Group.Type | String | Group type, which determines how a group's profile and memberships are managed. | 
| Account.Group.Description | String | Description of the group. | 
| Account.Group.Name | String | Name of the group. | 

### okta-verify-push-factor

***
Enrolls and verifies a push factor for the specified user.

#### Base Command

`okta-verify-push-factor`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | The ID of the user to enroll and verify. | Required | 
| factorId | The push factor ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta user ID. | 
| Account.VerifyPushResult | String | Okta user push factor result. | 

### okta-search

***
Searches for Okta users.

#### Base Command

`okta-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| term | Searches for users based on the any user profile property, including custom-defined properties. e.g profile.department eq "Engineering" Note: If you use the special character " within a quoted string, it must also be escaped \ and encoded. For example, search=profile.lastName eq "bob"smith" is encoded as search=profile.lastName%20eq%20%22bob%5C%22smith%22. refer = https://developer.okta.com/docs/reference/api/users/#list-users-with-search. | Required | 
| limit | The maximum number of results to return. The default and maximum is 200. | Optional | 
| verbose | Whether to return details of users that match the found term. Can be "true" or "false". The default is "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account IDs returned by the search. | 
| Account.Username | String | Okta account usernames returned by the search. | 
| Account.Email | String | Okta account emails returned by the search. | 
| Account.DisplayName | String | Okta account display names returned by the search. | 
| Account.Type | String | Okta account type returned by the search. | 
| Account.Status | String | Okta account current status. | 
| Account.Created | Date | Timestamp for when the user was created. | 
| Account.Activated | Date | Timestamp for when the user was activated. | 
| Account.StatusChanged | Date | Timestamp for when the user's status was last changed. | 
| Account.PasswordChanged | Date | Timestamp for when the user's password was last changed. | 

### okta-get-user

***
Fetches information for a single user. You must enter one or more parameters for the command to run.

#### Base Command

`okta-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username for which to get information. | Optional | 
| userId | User ID of the user for which to get information. | Optional | 
| verbose | Whether to return extended user information. Can be "true" or "false". The default is "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID. | 
| Account.Email | String | Okta account email. | 
| Account.Username | String | Okta account username. | 
| Account.DisplayName | String | Okta account display name. | 
| Account.Status | String | Okta account status. | 
| Account.Created | Date | Timestamp for when the user was created. | 
| Account.Activated | Date | Timestamp for when the user was activated. | 
| Account.StatusChanged | Date | Timestamp for when the user's status was last changed. | 
| Account.PasswordChanged | Date | Timestamp for when the user's password was last changed. | 
| Account.Manager | String | The manager. | 
| Account.ManagerEmail | String | The manager email. | 

### okta-list-users

***
Lists users in your organization.

#### Base Command

`okta-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| after | The cursor in which to retrive the results from and on. if the query didn't reach the end of results, the tag can be obtained from the bottom of the grid in the readable output, or in the context path Okta.User.tag. | Optional | 
| limit | The maximum number of results to return, the default is 200. Default is 200. | Optional | 
| verbose | Whether to return extended user information. Can be "true" or "false". The default is "false". Possible values are: true, false. Default is false. | Optional | 
| query | Searches the name property of groups for matching values. | Optional | 
| filter | Useful for performing structured queries where constraints on group attribute values can be explicitly targeted. <br/>The following expressions are supported(among others) for groups with the filter query parameter: <br/>type eq "OKTA_GROUP" - Groups that have a type of OKTA_GROUP; lastUpdated lt "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with profile last updated before a specific timestamp; lastMembershipUpdated eq "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with memberships last updated at a specific timestamp; id eq "00g1emaKYZTWRYYRRTSK" - Group with a specified ID. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID. | 
| Account.Email | String | Okta account email. | 
| Account.Username | String | Okta account username. | 
| Account.DisplayName | String | Okta account display name. | 
| Account.Status | String | Okta account status. | 
| Account.Created | Date | Timestamp for when the user was created. | 
| Account.Activated | Date | Timestamp for when the user was activated. | 
| Account.StatusChanged | Date | Timestamp for when the user's status was last changed. | 
| Account.PasswordChanged | Date | Timestamp for when the user's password was last changed. | 
| Okta.User.tag | String | The location of the next item, used with after param. | 

### okta-create-user

***
Creates a new user with an option of setting a password, recovery question, and answer. The new user will immediately be able to log in after activation with the assigned password. This flow is common when developing a custom user registration experience.

#### Base Command

`okta-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstName | First name of the user (givenName). | Required | 
| lastName | Family name of the user (familyName). | Required | 
| email | Primary email address of the user. | Required | 
| login | Unique identifier for the user (username). | Required | 
| secondEmail | Secondary email address of user. Usually used for account recovery. | Optional | 
| middleName | Middle name(s) of the user. | Optional | 
| honorificPrefix | A comma-separated list of honorific prefix(es) of the user, or title in most Western languages. | Optional | 
| honorificSuffix | A comma-separated list of honorific suffix(es) of the user. | Optional | 
| title | User's title. for example, Vice President. | Optional | 
| displayName | Display name of the user. | Optional | 
| nickName | Casual way to address the user (nick name). | Optional | 
| profileUrl | URL of the user online profile. For example, a web page. | Optional | 
| primaryPhone | Primary phone number of the user. | Optional | 
| mobilePhone | Mobile phone number of the user. | Optional | 
| streetAddress | Full street address component of the user's address. | Optional | 
| city | City or locality component of the user's address (locality). | Optional | 
| state | State or region component of the user's address (region). | Optional | 
| zipCode | Zip code or postal code component of the user's address (postalCode). | Optional | 
| countryCode | Country name component of the user's address (country). | Optional | 
| postalAddress | Mailing address component of the user's address. | Optional | 
| preferredLanguage | User's preferred written or spoken languages. | Optional | 
| locale | User's default location, for purposes of localizing items such as currency, date-time format, numerical representations, etc. | Optional | 
| timezone | User's time zone. | Optional | 
| userType | The user type, which is used to identify the organization-to-user relationship such as "Employee" or "Contractor". | Optional | 
| employeeNumber | Organization or company assigned unique identifier for the user. | Optional | 
| costCenter | Name of a cost center the user is assigned to. | Optional | 
| organization | Name of the user's organization. | Optional | 
| division | Name of the user's division. | Optional | 
| department | Name of the user's department. | Optional | 
| managerId | ID of the user's manager. | Optional | 
| manager | Display name of the user's manager. | Optional | 
| password | Password for the new user. | Optional | 
| passwordQuestion | Password question for the new user. | Optional | 
| passwordAnswer | Password answer for question. | Optional | 
| providerType | The provider type. Can be "OKTA", "ACTIVE_DIRECTORY", "LDAP", "FEDERATION", or "SOCIAL". Possible values are: OKTA, ACTIVE_DIRECTORY, LDAP, FEDERATION, SOCIAL. | Optional | 
| providerName | Name of the provider. | Optional | 
| groupIds | IDs of groups that the user will be immediately added to at time of creation (does Not include default group). | Optional | 
| activate | Whether to activate the lifecycle operation when creating the user. Can be "true" or "false". Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Created Okta account ID. | 
| Account.Email | String | Created Okta account email address. | 
| Account.Username | String | Created okta account username. | 
| Account.DisplayName | String | Created Okta account display name. | 
| Account.Type | String | Type of created account - Okta. | 
| Account.Status | String | Okta account current status. | 
| Account.Created | Date | Timestamp for when the user was created. | 
| Account.Activated | Date | Timestamp for when the user was activated. | 
| Account.StatusChanged | Date | Timestamp for when the user's status was last changed. | 
| Account.PasswordChanged | Date | Timestamp for when the user's password was last changed. | 

### okta-update-user

***
Updates a user with a given login. All fields are optional. Fields which are not set, will not be overwritten.

#### Base Command

`okta-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstName | First name of the user (given name). | Optional | 
| lastName | Family name of the user. | Optional | 
| email | Primary email address of the user. | Optional | 
| username | Unique identifier for the user (login). | Required | 
| secondEmail | Secondary email address of the user (typically used for account recovery. | Optional | 
| middleName | Middle name(s) of the user. | Optional | 
| honorificPrefix | Honorific prefix(es) of the user, or title in most Western languages. | Optional | 
| honorificSuffix | Honorific suffix(es) of the user. | Optional | 
| title | User's title. For example, Vice President. | Optional | 
| displayName | Display name of the user. | Optional | 
| nickName | Casual way to address the user in real life (nick name). | Optional | 
| profileUrl | URL of the user's online profile. For example, a web page. | Optional | 
| primaryPhone | Primary phone number of the user. | Optional | 
| mobilePhone | Mobile phone number of the user. | Optional | 
| streetAddress | Full street address component of the user's address. | Optional | 
| city | City or locality component of the user's address (locality). | Optional | 
| state | State or region component of the user's address (region). | Optional | 
| zipCode | Zip code or postal code component of the user's address (postalCode). | Optional | 
| countryCode | Country name component of the user's address (country). | Optional | 
| postalAddress | Mailing address component of the user's address. | Optional | 
| preferredLanguage | User's preferred written or spoken languages. | Optional | 
| locale | User's default location for purposes of localizing items such as currency, date-time format, numerical representations, etc. | Optional | 
| timezone | User time zone. | Optional | 
| userType | The user type, which is used to identify the organization-to-user relationship such as "Employee" or "Contractor". | Optional | 
| employeeNumber | Organization or company assigned unique identifier for the user. | Optional | 
| costCenter | Name of a cost center the user is assigned to. | Optional | 
| organization | Name of the user's organization. | Optional | 
| division | Name of the user's division. | Optional | 
| department | Name of the user's department. | Optional | 
| managerId | ID of the user's manager. | Optional | 
| manager | Display name of the user's manager. | Optional | 
| password | New password for the specified user. | Optional | 
| passwordQuestion | Password question for the specified user. | Optional | 
| passwordAnswer | Password answer for the question. | Optional | 
| providerType | The provider type. Can be "OKTA", "ACTIVE_DIRECTORY", "LDAP", "FEDERATION", or "SOCIAL". Possible values are: OKTA, ACTIVE_DIRECTORY, FEDERATION, SOCIAL. | Optional | 
| providerName | Name of the provider. | Optional | 

#### Context Output

There is no context output for this command.
### okta-get-group-members

***
Enumerates all users that are members of a group.

#### Base Command

`okta-get-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | ID of the group. | Optional | 
| limit | The maximum number of results to return. | Optional | 
| verbose | Whether to print extended user details. Can be "true" or "false". The default is "false". Possible values are: true, false. Default is false. | Optional | 
| groupName | Name of the group. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID. | 
| Account.Email | String | Okta account email address. | 
| Account.Username | String | Okta account username. | 
| Account.DisplayName | String | Okta account display name. | 
| Account.Type | String | Account type - Okta. | 
| Account.Status | String | Okta account current status. | 
| Account.Created | Date | Timestamp for when the user was created. | 
| Account.Activated | Date | Timestamp for when the user was activated. | 
| Account.StatusChanged | Date | Timestamp for when the user's status was last changed. | 
| Account.PasswordChanged | Date | Timestamp for when the user's password was last changed. | 

### okta-list-groups

***
Lists groups in your organization. A subset of groups can be returned that match a supported filter expression or query.

#### Base Command

`okta-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Searches the name property of groups for matching values. | Optional | 
| filter | Useful for performing structured queries where constraints on group attribute values can be explicitly targeted. <br/>The following expressions are supported(among others) for groups with the filter query parameter: <br/>type eq "OKTA_GROUP" - Groups that have a type of OKTA_GROUP; lastUpdated lt "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with profile last updated before a specific timestamp; lastMembershipUpdated eq "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with memberships last updated at a specific timestamp; id eq "00g1emaKYZTWRYYRRTSK" - Group with a specified ID. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 
| limit | The maximum number of results to return. The default is 200. Default is 200. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Group.ID | String | Unique key for the group. | 
| Okta.Group.Created | Date | Timestamp for when the group was created. | 
| Okta.Group.ObjectClass | Unknown | The group's profile. | 
| Okta.Group.LastUpdated | Date | Timestamp for when the group's profile was last updated. | 
| Okta.Group.LastMembershipUpdated | Date | Timestamp for when the group's membership was last updated. | 
| Okta.Group.Type | String | The group type, which determines how a group's profile and membership are managed. Can be "OKTA_GROUP", "APP_GROUP", or "BUILT_IN". | 
| Okta.Group.Name | String | Name of the group. | 
| Okta.Group.Description | String | Description of the group. | 

### okta-get-failed-logins

***
Returns failed login events.

#### Base Command

`okta-get-failed-logins`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log events in the Internet Date/Time Format profile of ISO 8601. An example: 2017-05-03T16:22:18Z. | Optional | 
| until | Filters the upper time bound of the log events in the Internet Date/Time Format profile of ISO 8601. An example: 2017-05-03T16:22:18Z. | Optional | 
| sortOrder | The order of the returned events. Can be "ASCENDING" or "DESCENDING". The default is "ASCENDING". Possible values are: ASCENDING, DESCENDING. Default is ASCENDING. | Optional | 
| limit | The maximum number of results to return. The default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternative ID of the actor. | 
| Okta.Logs.Events.actor.displayName | String | Display name of the actor. | 
| Okta.Logs.Events.actor.id | String | ID of the actor. | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of the user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operating system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the browser type, if relevant. For example, Chrome. | 
| Okta.Logs.Events.client.device | String | Type of device that client operated from. For example, Computer. | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address from which the client made its request. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example Montana, Incheon. | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.displayMessage | String | The display message for an event. | 
| Okta.Logs.Events.eventType | String | Type of event that was published. | 
| Okta.Logs.Events.outcome.result | String | Result of the action. Can be "SUCCESS", "FAILURE", "SKIPPED", "UNKNOWN". | 
| Okta.Logs.Events.outcome.reason | String | Reason for the result. For example, INVALID_CREDENTIALS. | 
| Okta.Logs.Events.published | String | Timestamp when the event was published. | 
| Okta.Logs.Events.severity | String | The event severity. Can be "DEBUG", "INFO", "WARN", or "ERROR". | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to send the event's request. | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request. | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request is from a known proxy. | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source. | 
| Okta.Logs.Events.target.id | String | ID of a target. | 
| Okta.Logs.Events.target.type | String | Type of a target. | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target. | 
| Okta.Logs.Events.target.displayName | String | Display name of a target. | 

### okta-get-logs

***
Gets logs by providing optional filters.

#### Base Command

`okta-get-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Useful for performing structured queries where constraints on LogEvent attribute values can be explicitly targeted.  <br/>The following expressions are supported for events with the filter query parameter: eventType eq " :eventType" <br/>-Events that have a specific action; eventType target.id eq ":id" <br/>- Events published with a specific target id; actor.id eq ":id"<br/>- Events published with a specific actor ID. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 
| query | The query parameter can be used to perform keyword matching against a LogEvents object’s attribute values. To satisfy the constraint, all supplied keywords must be matched exactly. Note that matching is case-insensitive.  The following are some examples of common keyword filtering: <br/>Events that mention a specific city: query=San Francisco; <br/>Events that mention a specific url: query=interestingURI.com; <br/>Events that mention a specific person: query=firstName lastName. | Optional | 
| since | Filters the lower time bound of the log events in the Internet Date/Time Format profile of ISO 8601. For example: 2017-05-03T16:22:18Z. | Optional | 
| until | Filters the upper  time bound of the log events in the Internet Date/Time Format profile of ISO 8601. For example: 2017-05-03T16:22:18Z. | Optional | 
| sortOrder | The order of the returned events. Can be "ASCENDING" or "DESCENDING". The default is "ASCENDING". Possible values are: ASCENDING, DESCENDING. Default is ASCENDING. | Optional | 
| limit | The maximum number of results to return. The default is 100. Default is 100. | Optional | 

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
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request. | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request is from a known proxy. | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source. | 
| Okta.Logs.Events.target.id | String | ID of a target. | 
| Okta.Logs.Events.target.type | String | Type of a target. | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target. | 
| Okta.Logs.Events.target.displayName | String | Display name of a target. | 

### okta-get-group-assignments

***
Gets events for when a user was added to a group.

#### Base Command

`okta-get-group-assignments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log event in the Internet Date\Time format profile of ISO 8601. For example, 2020-02-14T16:00:18Z. | Optional | 
| until | Filters the upper time bound of the log event in the Internet Date\Time format profile of ISO 8601. For example, 2020-02-14T16:00:18Z. | Optional | 
| sortOrder | The order of the returned events. Can be "ASCENDING" or "DESCENDING". The default is "ASCENDING". Possible values are: ASCENDING, DESCENDING. Default is ASCENDING. | Optional | 
| limit | The maximum number of results to return. The default is 100. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternative ID of the actor. | 
| Okta.Logs.Events.actor.displayName | String | Display name of the actor. | 
| Okta.Logs.Event.actor.id | String | ID of the actor. | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operating system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome. | 
| Okta.Logs.Events.client.device | String | Type of device from which the client operated. For example, Computer. | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address from which the client made its request. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state or province encompassing in the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.displayMessage | String | The display message for an event. | 
| Okta.Logs.Events.eventType | String | Type of event that was published. | 
| Okta.Logs.Events.outcome.result | String | Result of the action. Can be "SUCCESS", "FAILURE", "SKIPPED", or "UNKNOWN". | 
| Okta.Logs.Events.outcome.reason | Unknown | Reason for the result. For example INVALID_CREDENTIALS. | 
| Okta.Logs.Events.published | String | Timestamp when the event was published. | 
| Okta.Logs.Events.severity | String | The event severity. Can be "DEBUG", "INFO", "WARN", or "ERROR". | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to send the event's request. | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request. | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request is from a known proxy. | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source. | 
| Okta.Logs.Events.target.id | String | ID of a target. | 
| Okta.Logs.Events.target.type | String | Target type. | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target. | 
| Okta.Logs.Events.target.displayName | String | Display name of a target. | 

### okta-get-application-assignments

***
Returns events for when a user was assigned to an application.

#### Base Command

`okta-get-application-assignments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log event in the Internet Date\Time format profile of ISO 8601. For example, 2020-02-14T16:00:18Z. | Optional | 
| until | Filters the upper time bound of the log event in the Internet Date\Time format profile of ISO 8601. For example, 2020-02-14T16:00:18Z. | Optional | 
| sortOrder | The order of the returned events. Can be "ASCENDING" or "DESCENDING". The default is "ASCENDING". Possible values are: ASCENDING, DESCENDING. Default is ASCENDING. | Optional | 
| limit | The maximum number of results to return. The default is 100. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternative ID of the actor. | 
| Okta.Logs.Events.actor.displayName | String | Display name of the actor. | 
| Okta.Logs.Event.actor.id | String | ID of the actor. | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of the user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The OS on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome. | 
| Okta.Logs.Events.client.device | String | Type of device from which the client operated. For example, Computer. | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address from which the client made its request. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.displayMessage | String | The display message for an event. | 
| Okta.Logs.Events.eventType | String | Type of event that was published. | 
| Okta.Logs.Events.outcome.result | String | Result of the action. For example, "SUCCESS", "FAILURE", "SKIPPED", or "UNKNOWN". | 
| Okta.Logs.Events.outcome.reason | String | Reason for the result. For example INVALID_CREDENTIALS. | 
| Okta.Logs.Events.published | String | Timestamp when the event was published. | 
| Okta.Logs.Events.severity | String | The event severity. Can be "DEBUG", "INFO", "WARN", or "ERROR". | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to send the event's request. | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request. | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request is from a known proxy. | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source. | 
| Okta.Logs.Events.target.id | String | ID of a target. | 
| Okta.Logs.Events.target.type | String | Type of a target. | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target. | 
| Okta.Logs.Events.target.displayName | String | Display name of a target. | 

### okta-get-application-authentication

***
Returns logs using specified filters.

#### Base Command

`okta-get-application-authentication`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log event in the Internet Date\Time format profile of ISO 8601. For example, 2020-02-14T16:00:18Z. | Optional | 
| until | Filters the upper time bound of the log event in the Internet Date\Time format profile of ISO 8601. For example, 2020-02-14T16:00:18Z. | Optional | 
| sortOrder | The order of the returned events. Can be "ASCENDING" or "DESCENDING". The default is "ASCENDING". Possible values are: ASCENDING, DESCENDING. Default is ASCENDING. | Optional | 
| limit | The maximum number of results to return. The default is 100. Default is 100. | Optional | 

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
| Okta.Logs.Events.outcome.reason | String | Reason for the result. For example INVALID_CREDENTIALS. | 
| Okta.Logs.Events.published | String | Timestamp when the event was published. | 
| Okta.Logs.Events.severity | String | The event severity. Can be "DEBUG", "INFO", "WARN", or "ERROR". | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to send the event's request. | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request. | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request is from a known proxy. | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geo-location coordinates, if available. For example, Seattle, San Francisco. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state or province encompassing the area containing the geo-location coordinates. For example, Montana, Incheon. | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geo-location coordinates. For example, France, Uganda. | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source. | 
| Okta.Logs.Events.target.id | String | ID of a target. | 
| Okta.Logs.Events.target.type | String | Type of a target. | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target. | 
| Okta.Logs.Events.target.displayName | String | Display name of a target. | 

### okta-delete-user

***
Deletes the specified user.

#### Base Command

`okta-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | Okta User ID. | Optional | 
| username | Username of the user. | Optional | 

#### Context Output

There is no context output for this command.
### okta-clear-user-sessions

***
Removes all active identity provider sessions. This forces the user to authenticate upon the next operation. Optionally revokes OpenID Connect and OAuth refresh and access tokens issued to the user.
For more information and examples:
https://developer.okta.com/docs/reference/api/users/#user-sessions

#### Base Command

`okta-clear-user-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | Okta User ID. | Required | 

#### Context Output

There is no context output for this command.
### okta-list-zones

***
Get an Okta Zone object

#### Base Command

`okta-list-zones`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Zone.created | Date | Zone creation timestamp, in the format 2020-04-06T22:23:12.000Z. | 
| Okta.Zone.gateways.type | String | Gateways IP entry type, e.g., CIDR. | 
| Okta.Zone.gateways.value | String | Gateways IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.id | String | Zone ID, e.g., nzoqsmcx1qWYJ6wYF0h7. | 
| Okta.Zone.lastUpdated | Date | Zone last update timestamp, e.g., 2020-04-06T22:23:12.000Z. | 
| Okta.Zone.name | String | Zone name. | 
| Okta.Zone.proxies.type | String | Proxies IP entry type e.g. CIDR | 
| Okta.Zone.proxies.value | Unknown | Proxies IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.status | String | Zone status, e.g., ACTIVE. | 
| Okta.Zone.system | Number | True if this is a system zone, false if user-created. | 
| Okta.Zone.type | String | Zone type, e.g., IP. | 

### okta-update-zone

***
Update an Okta Zone

#### Base Command

`okta-update-zone`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zoneID | Zone ID to update, e.g., nzoqsmcx1qWYJ6wYF0h7. | Required | 
| zoneName | Updates the zone name. | Optional | 
| gatewayIPs | Updates Gateway IP addresses: CIDR range (1.1.0.0/16) or single IP address (2.2.2.2). | Optional | 
| proxyIPs | Update Proxy IP addresses: CIDR range (1.1.0.0/16) or single IP address (2.2.2.2). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Zone.created | Date | Zone creation timestamp, e.g., 2020-04-06T22:23:12.000Z. | 
| Okta.Zone.gateways.type | String | Gateways IP entry type, e.g., CIDR. | 
| Okta.Zone.gateways.value | String | Gateways IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.id | String | Okta Zone ID, e.g., nzoqsmcx1qWYJ6wYF0h7. | 
| Okta.Zone.lastUpdated | Date | Zone last update timestamp, in the format 2020-04-06T22:23:12.000Z. | 
| Okta.Zone.name | String | Zone name. | 
| Okta.Zone.proxies.type | String | Proxies IP entry type, e.g., CIDR. | 
| Okta.Zone.proxies.value | Unknown | Proxies IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.status | String | Zone status, e.g., ACTIVE. | 
| Okta.Zone.system | Number | True if this is a system zone, false if user-created. | 
| Okta.Zone.type | String | Zone type, e.g., IP. | 

### okta-get-zone

***
Get a Zone by its ID

#### Base Command

`okta-get-zone`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zoneID | Zone ID to get, e.g., nzoqsmcx1qWYJ6wYF0h.7. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Zone.created | Date | Zone creation timestamp, in the format 2020-04-06T22:23:12.000Z. | 
| Okta.Zone.gateways.type | String | Gateways IP entry type, e.g., CIDR. | 
| Okta.Zone.gateways.value | String | Gateways IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.id | String | Okta Zone ID, e.g., nzoqsmcx1qWYJ6wYF0h7. | 
| Okta.Zone.lastUpdated | Date | Zone last update timestamp, in the format 2020-04-06T22:23:12.000Z. | 
| Okta.Zone.name | String | Zone name. | 
| Okta.Zone.proxies.type | String | Proxies IP entry type, e.g., CIDR. | 
| Okta.Zone.proxies.value | Unknown | Proxies IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.status | String | Zone status, e.g,. ACTIVE. | 
| Okta.Zone.system | Number | True if this is a system zone, false if user-created. | 
| Okta.Zone.type | String | Zone type, e.g., IP. | 

### okta-create-zone

***
Creates a Zone with the specified name

#### Base Command

`okta-create-zone`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Zone name. | Required | 
| gateway_ips | Update Gateway IP addresses: CIDR range (1.1.0.0/16) or single IP address (2.2.2.2). | Optional | 
| proxies | Update Proxy IP addresses: CIDR range (1.1.0.0/16) or single IP address (2.2.2.2). | Optional | 

#### Context Output

There is no context output for this command.
### okta-create-group

***
Create a new group in Okta tenant.

#### Base Command

`okta-create-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group to add. | Required | 
| description | Description of the group to add. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OktaGroup.ID | Unknown | Group ID in Okta, | 
| OktaGroup.Name | Unknown | Group name in Okta, | 
| OktaGroup.Description | Unknown | Group description in Okta, | 
| OktaGroup.Type | Unknown | Group type in Okta, | 

### okta-assign-group-to-app

***
Assign a group to an application

#### Base Command

`okta-assign-group-to-app`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the group to assign to the app. | Optional | 
| groupId | ID of the group to assign to the app. | Optional | 
| appName | Friendly name of the app that the group will be assigned to. | Optional | 

#### Context Output

There is no context output for this command.
