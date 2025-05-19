Integration with Okta's cloud-based identity management service.

## Configure Okta v2 in Cortex
### API Token Authentication Prerequisites
1. Sign in to your Okta organization as a user with administrator privileges.
2. On the **Admin Console**, select **Security** > **API** from the menu, and then select the **Tokens** tab.
3. Click **Create Token**.
4. Name your token and click **Create Token**.

#### Notes
- API tokens have the same permissions as the user who creates them, and if the permissions of a user change, so do the permissions of the API token.
- If more than one certificate is assigned to the application, the Key ID parameter is required to specify which
  certificate to use for signing the JWT token.

For more information, see the '[Create an API token](https://developer.okta.com/docs/guides/create-an-api-token/main/)' official documentation article.

### OAuth 2.0 Authentication Prerequisites
#### Required Scopes
The following scopes are required for the Okta v2 integration to work properly:
- okta.apps.manage 
- okta.apps.read 
- okta.groups.manage 
- okta.groups.read 
- okta.logs.read 
- okta.networkZones.manage 
- okta.networkZones.read 
- okta.sessions.manage 
- okta.sessions.read 
- okta.users.manage 
- okta.users.read 

1. Sign in to Okta Admin Console.
2. In the Admin Console, go to **Applications** > **Applications**.
3. Click **Create App Integration**.
4. Select **API Services** as the sign-in method, and click **Next**.
5. Enter the desired name for the created app (e.g., "Cortex XSOAR"), and click **Save**.
6. In the app configuration page, under the **General** tab and the **Client Credentials** section, select **Public key / Private key** for the **Client authentication** option.
7. Under the newly added **PUBLIC KEYS** section, click **Add Key**.
8. In the **Add Public Key** dialog box, click **Generate new key**. Make sure to copy the generated private key (in PEM format) to somewhere safe, and click **Save**.
9. Under the **General Settings** section:
   1. Next to the **Proof of possession** label, uncheck the **Require Demonstrating Proof of Possession (DPoP) header in token requests** option if it's selected.
   2. Next to the **Grant type** label, make sure the **Client Credentials** option is selected, and that the **Token Exchange** option is not selected.
   3. Click **Save**.
10. Under the **Okta API Scopes** tab, grant the required scopes mentioned above for the app.
11. Under the **Admin roles** tab:
    1. Click **Edit assignments**.
    2. In the dropdown list under "Role", select **Super Administrator**.
    3. Click **Save changes** at the top.

For more information, see the '[Implement OAuth for Okta](https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/)' official documentation article.


### Instance Configuration


| **Parameter**                              | **Description**                                                                                                                                                                                  | **Required** |
|--------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Okta URL (https://&lt;domain&gt;.okta.com) |                                                                                                                                                                                                  | True         |
| API Token                                  |                                                                                                                                                                                                  | False        |
| Use OAuth 2.0 Authentication               | See detailed instructions on the 'Help' tab.                                                                                                                                                     | False        |
| Client ID                                  | Required and used if OAuth 2.0 is used for authentication. See detailed instructions on the 'Help' tab.                                                                                          | False        |
| Private Key                                | In PEM format. Required and used if OAuth 2.0 is used for authentication. See detailed instructions on the 'Help' tab.                                                                           | False        |
| JWT Signing Algorithm                      | Algorithm to sign generated JWT tokens with. Doesn't affect integration's functionality. Required and used if OAuth 2.0 is used for authentication. See detailed instructions on the 'Help' tab. | False        |
| Key ID                                     | Required and used if more than one key is used for signing JWT tokens.                                                                                                                           | False        |
| Trust any certificate (not secure)         |                                                                                                                                                                                                  | False        |
| Use system proxy settings                  |                                                                                                                                                                                                  | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

##### Command Example
```!okta-unlock-user username=testForDocs@test.com```

##### Human Readable Output
>User testForDocs@test.com unlocked

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

##### Command Example
```!okta-deactivate-user username=testForDocs@test.com```

##### Human Readable Output
>User testForDocs@test.com deactivated

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

##### Command Example
```!okta-activate-user username=testForDocs@test.com```

##### Human Readable Output
>### testForDocs@test.com is active now

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

##### Command Example
```!okta-suspend-user username=testForDocs@test.com```

##### Human Readable Output
>### testForDocs@test.com status is Suspended

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

##### Command Example
```!okta-unsuspend-user username=testForDocs@test.com```

##### Human Readable Output
>### testForDocs@test.com is no longer SUSPENDED

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
| Account.Factor.Provider | String | Okta account factor provider. | 
| Account.Factor.Profile | String | Okta account factor profile. | 
| Account.Factor.FactorType | String | Okta account factor type. | 
| Account.Factor.Status | Unknown | Okta account factor status. | 


##### Command Example
```!okta-get-user-factors username=factor@test.com```

##### Context Example
```
{
    "Account": {
        "Factor": [
            {
                "FactorType": "sms",
                "ID": "mblpt21nffaaN5F060h7",
                "Profile": {
                    "phoneNumber": "+12025550191"
                },
                "Provider": "OKTA",
                "Status": "PENDING_ACTIVATION"
            },
            {
                "FactorType": "token:software:totp",
                "ID": "uftpt24kdrDJ7fDOq0h7",
                "Profile": {
                    "credentialId": "factor@test.com"
                },
                "Provider": "GOOGLE",
                "Status": "PENDING_ACTIVATION"
            },
            {
                "FactorType": "push",
                "ID": "opfpt1joeaArlg27g0h7",
                "Provider": "OKTA",
                "Status": "PENDING_ACTIVATION"
            }
        ],
        "ID": "00upt1w8tgFQM2v6t4"
    }
}
```

##### Human Readable Output
>Factors for user: 00upt1w8tgFQM2v0h7
>### Factors
>|FactorType|ID|Profile|Provider|Status|
>|---|---|---|---|---|
>| sms | mbgt21nffaaN5F060h7 | phoneNumber: +12025550191 | OKTA | PENDING_ACTIVATION |
>| token:software:totp | uftptgdrDJ7fDOq0h7 | credentialId: factor@test.com | GOOGLE | PENDING_ACTIVATION |
>| push | opfg1joeaArlg27g0h7 |  | OKTA | PENDING_ACTIVATION |


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

##### Command Example
```!okta-reset-factor factorId=ufsq7cvptfbjQa72c0h7 userId=00upt1w8t40wFQM2v6t4```

##### Human Readable Output
>Factor: ufsq7cvptfbjQa72c0h7 deleted

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

##### Command Example
```!okta-set-password username=testForDocs@test.com password=N3wPa55word!```

##### Human Readable Output
>testForDocs@test.com password was last changed on 2020-03-26T13:57:13.000Z

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

##### Command Example
```!okta-add-to-group groupName=Demisto username=testForDocs@test.com```

##### Human Readable Output
>User: 00uqk1qesl3k0SRbH0h7 added to group: Demisto successfully

### okta-remove-from-group

***
Removes a user from a group with OKTA_GROUP type.

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

##### Command Example
```!okta-remove-from-group groupName=demisto username=testForDocs@test.com```

##### Human Readable Output
>User: 00uqk1qesl3k0SRbH0h7 was removed from group: demisto successfully

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


##### Command Example
```!okta-get-groups username=testForDocs@test.com```

##### Context Example
```
{
    "Account": {
        "Group": [
            {
                "Created": "2016-04-12T15:01:50.000Z",
                "Description": "All users in your organization",
                "ID": "00g66lckcsAJpLcNc0h7",
                "LastMembershipUpdated": "2020-03-26T13:56:49.000Z",
                "LastUpdated": "2016-04-12T15:01:50.000Z",
                "Name": "Everyone",
                "ObjectClass": [
                    "okta:user_group"
                ],
                "Type": "BUILT_IN"
            },
            {
                "Created": "2018-01-19T02:02:06.000Z",
                "ID": "00gdougcq3zEaf7c50h7",
                "LastMembershipUpdated": "2020-03-26T13:49:47.000Z",
                "LastUpdated": "2018-01-19T02:02:06.000Z",
                "Name": "Demisto",
                "ObjectClass": [
                    "okta:user_group"
                ],
                "Type": "OKTA_GROUP"
            }
        ],
        "ID": "00uqk1qesl3k0SRbH0h7",
        "Type": "Okta"
    }
}
```

##### Human Readable Output
>Okta groups for user: testForDocs@test.com
>### Groups
>|Created|Description|ID|LastMembershipUpdated|LastUpdated|Name|ObjectClass|Type|
>|---|---|---|---|---|---|---|---|
>| 2016-04-12T15:01:50.000Z | All users in your organization | 00g66lckgAJpLcNc0h7 | 2020-03-26T13:56:49.000Z | 2016-04-12T15:01:50.000Z | Everyone | okta:user_group | BUILT_IN |
>| 2018-01-19T02:02:06.000Z |  | 00gdougcgzEaf7c50h7 | 2020-03-26T13:49:47.000Z | 2018-01-19T02:02:06.000Z | Demisto | okta:user_group | OKTA_GROUP |


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


##### Command Example
```!okta-verify-push-factor factorId=opfpt1joeaArlg27g0h7 userId=00upt1w8t40wFQM2v0h7```

##### Human Readable Output
>Verify push factor result for user 00upt1w8t40wgQM2v0h7: WAITING

##### Context Example
```
{
    "factorResult": "WAITING",
    "profile": {
        "credentialId": "test@this.com",
        "deviceType": "SmartPhone_IPhone",
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "kid": "default",
                "x": "3Y53lDoQYwzzVbjsbsPnqOnVaotIrVByQh5Sa-RwOHQ",
                "y": "0zHY_y9rVh-bq_-lR-MrmzNtUZrrIMbTrsjtxUyUT2Q",
                "crv": "P-256"
            }
        ],
        "name": "iPhone (5)",
        "platform": "IOS",
        "version": "13.1.3"
    },
    "expiresAt": "2020-02-24T11:37:08.000Z",
    "_links": {
        "cancel": {
            "href": "https://test.com/api/v1/users/00upt1w8t40wgQM2v0h7/factors/FactorID/transactions/TransactionID",
            "hints": {
                "allow": [
                    "DELETE"
                ]
            }
        },
        "poll": {
            "href": "https://test.com/api/v1/users/00upt1w8t40wgQM2v0h7/factors/FactorID/transactions/TransactionID",
            "hints": {
                "allow": [
                    "GET"
                ]
            }
        }
    }
}
```

### okta-search

***
Searches for Okta users.

#### Base Command

`okta-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| term | Term by which to search. Can be a first name, last name, or email address. The argument `term` or `advanced_search` is required. | Optional | 
| advanced_search | Searches for users with a supported filtering expression for most properties, including custom-defined properties. The argument `term` or `advanced_search` is required. | Optional | 
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


##### Command Example
```!okta-search term=test verbose=true```

##### Context Example
```
{
    "Account": [
               {
            "Activated": "2020-02-12T14:03:51.000Z",
            "Created": "2020-02-12T14:03:50.000Z",
            "DisplayName": "bar test",
            "Email": "bartest@test.com",
            "ID": "00uppjeleqJQ2kkN80h7",
            "Status": "PROVISIONED",
            "StatusChanged": "2020-02-12T14:03:51.000Z",
            "Type": "Okta",
            "Username": "bartest@test.com"
        },
        {
            "Activated": "2020-02-19T12:33:20.000Z",
            "Created": "2018-07-31T12:48:33.000Z",
            "DisplayName": "test that",
            "Email": "test@that.com",
            "ID": "00ufufhqits3y78Ju0h7",
            "PasswordChanged": "2020-02-06T13:32:56.000Z",
            "Status": "PROVISIONED",
            "StatusChanged": "2020-02-19T12:33:20.000Z",
            "Type": "Okta",
            "Username": "test@that.com"
        },
        {
            "Activated": "2020-03-26T13:56:52.000Z",
            "Created": "2020-03-26T13:56:49.000Z",
            "DisplayName": "test that",
            "Email": "testForDocs@test.com",
            "ID": "00uqk1qesl3k0SRbH0h7",
            "PasswordChanged": "2020-03-26T13:56:50.000Z",
            "Status": "ACTIVE",
            "StatusChanged": "2020-03-26T13:56:52.000Z",
            "Type": "Okta",
            "Username": "testForDocs@test.com"
        }
    ]
}
```

##### Human Readable Output
>Okta users found:
>User:bartest@test.com
>### Profile
>|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
>|---|---|---|---|---|---|
>| bartest@test.com | bar | test | bartest@test.com |  |  |

 ##### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-02-12T14:03:51.000Z | 2020-02-12T14:03:50.000Z | provider: {"type": "OKTA", "name": "OKTA"} | 00uppjeleqJQ2kkN80h7 |  | 2020-02-12T14:03:51.000Z |  | PROVISIONED |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://yourdomain.okta.com/api/v1/users/00uppjeleqJQ2kkN80h7"} |
##### User:test@that.com
##### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| test@that.com | test | that | test@that.com |  | test@that.com |

 ##### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-02-19T12:33:20.000Z | 2018-07-31T12:48:33.000Z | provider: {"type": "OKTA", "name": "OKTA"} | 00ufufhqits3y78Ju0h7 |  | 2020-02-19T12:33:20.000Z | 2020-02-06T13:32:56.000Z | PROVISIONED |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://yourdomain.okta.com/api/v1/users/00ufufhqits3y78Ju0h7"} |
##### User:testForDocs@test.com
##### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| testForDocs@test.com | test | that | testForDocs@test.com |  |  |

 ##### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-03-26T13:56:52.000Z | 2020-03-26T13:56:49.000Z | password: {}recovery_question: {"question": "whats is your favourite integration"}provider: {"type": "OKTA", "name": "OKTA"} | 00uqk1qesl3k0SRbH0h7 |  | 2020-03-26T13:56:52.000Z | 2020-03-26T13:56:50.000Z | ACTIVE |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://yourdomain.okta.com/api/v1/users/00uqk1qesl3k0SRbH0h7"} |

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

##### Command Example
```!okta-get-user username=testForDocs@test.com verbose=true```

##### Context Example
```
{
    "Account": {
        "Activated": "2020-03-26T13:56:52.000Z",
        "Created": "2020-03-26T13:56:49.000Z",
        "DisplayName": "test that",
        "Email": "testForDocs@test.com",
        "ID": "00uqk1qesl3k0SRbH0h7",
        "Manager": "manager@test.com",
        "ManagerEmail": null,
        "PasswordChanged": "2020-03-26T13:56:50.000Z",
        "Status": "ACTIVE",
        "StatusChanged": "2020-03-26T13:56:52.000Z",
        "Type": "Okta",
        "Username": "testForDocs@test.com"
    }
}
```

##### Human Readable Output
>### User:testForDocs@test.com
>### Profile
>|Email|First Name|Last Name|Login|Manager|Manager Email|Mobile Phone|Second Email|
>|---|---|---|---|---|---|---|---|
>| testForDocs@test.com | test | that | testForDocs@test.com | manager@test.com |  |  |  |

 ##### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-03-26T13:56:52.000Z | 2020-03-26T13:56:49.000Z | password: {}recovery_question: {"question": "whats is your favourite integration"} provider: {"type": "OKTA", "name": "OKTA"} | 00uqk1qesl3k0SRbH0h7 |  | 2020-03-26T13:56:52.000Z | 2020-03-26T13:56:50.000Z | ACTIVE |  | id: oty66lckcvDyVcGzS0h7 | links|


### okta-list-users

***
Lists users in your organization.

#### Base Command

`okta-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| after | The cursor in which to retrive the results from and on. if the query didn't reach the end of results, the tag can be obtained from the bottom of the grid in the readable output, or in the context path Okta.User.tag. | Optional | 
| limit | The maximum number of results to return. Default is 200. | Optional | 
| verbose | Whether to return extended user information. Possible values are: true, false. Default is false. | Optional | 
| query | Searches the name property of groups for matching values. | Optional | 
| filter | Useful for performing structured queries where constraints on group attribute values can be explicitly targeted. <br/>The following expressions are supported(among others) for groups with the filter query parameter: <br/> type eq "OKTA_GROUP" - Groups that have a type of OKTA_GROUP; lastUpdated lt "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with profile last updated before a specific timestamp; lastMembershipUpdated eq "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with memberships last updated at a specific timestamp; id eq "00g1emaKYZTWRYYRRTSK" - Group with a specified ID. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 

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


##### Command Example
```!okta-create-user email=testForDocs@test.com firstName=test lastName=that login=testForDocs@test.com password=Pa55word! passwordQuestion="whats is your favourite integration" passwordAnswer="Okta of course"```

##### Context Example
```
{
    "Account": {
        "Activated": null,
        "Created": "2020-03-26T13:56:49.000Z",
        "DisplayName": "test that",
        "Email": "testForDocs@test.com",
        "ID": "00uqk1qesl3k0SRbH0h7",
        "PasswordChanged": "2020-03-26T13:56:50.000Z",
        "Status": "STAGED",
        "StatusChanged": null,
        "Type": "Okta",
        "Username": "testForDocs@test.com"
    }
}
```

##### Human Readable Output
>### Okta User Created: testForDocs@test.com:
>|First Name|ID|Last Login|Last Name|Login|Mobile Phone|Status|
>|---|---|---|---|---|---|---|
>| test | 00uqk1qesl3k0SRbH0h7 |  | that | testForDocs@test.com |  | STAGED |


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

##### Command Example
```!okta-update-user username=testForDocs@test.com firstName="First Name Updated"```

##### Human Readable Output
>### Okta user: testForDocs@test.com Updated:
>|email|firstName|lastName|login|mobilePhone|secondEmail|
>|---|---|---|---|---|---|
>| testForDocs@test.com | First Name Updated | that | testForDocs@test.com |  |  |


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


##### Command Example
```!okta-get-group-members groupName=Demisto limit=1 verbose=true```

##### Context Example
```
{
    "Account": {
        "Created": "2016-04-12T15:01:52.000Z",
        "DisplayName": "Test Demisto",
        "Email": "XSOAR@demisto.com",
        "ID": "00u66ljhpjidYi0h7",
        "PasswordChanged": "2020-02-24T11:40:08.000Z",
        "Status": "ACTIVE",
        "StatusChanged": "2016-04-12T15:05:06.000Z",
        "Type": "Okta",
        "Username": "XSOAR@demisto.com"
    }
}
```

##### Human Readable Output
>### Users for group: Demisto:
>### User:Test@demisto.com
>### Profile
>|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
>|---|---|---|---|---|---|
>| XSOAR@demisto.com | Test | Demisto | XSOAR@demisto.com |  |  |

 ##### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
|  | 2016-04-12T15:01:52.000Z | password: {} recovery_question: {"question": "born city"} provider: {"type": "OKTA", "name": "OKTA"} | 00u66lckd7lpjidYi0h7 | 2020-03-12T09:54:36.000Z | 2020-02-24T11:42:22.000Z | 2020-02-24T11:40:08.000Z | ACTIVE |  | id: oty66lckcyVcGzS0h7 | self: {"href": "https://yourdomain.okta.com/api/v1/users/00uclpjidYi0h7"} |


### okta-list-groups

***
Lists groups in your organization. A subset of groups can be returned that match a supported filter expression or query.

#### Base Command

`okta-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Searches the name property of groups for matching values. | Optional | 
| filter | Useful for performing structured queries where constraints on group attribute values can be explicitly targeted. <br/>The following expressions are supported(among others) for groups with the filter query parameter: <br/> type eq "OKTA_GROUP" - Groups that have a type of OKTA_GROUP; lastUpdated lt "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with profile last updated before a specific timestamp; lastMembershipUpdated eq "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with memberships last updated at a specific timestamp; id eq "00g1emaKYZTWRYYRRTSK" - Group with a specified ID. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 
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


##### Command Example
```!okta-list-groups filter=`type eq "OKTA_GROUP" and lastUpdated lt "2019-04-30T00:00:00.000Z" and lastMembershipUpdated gt "2019-04-30T00:00:00.000Z"` query=demisto```

##### Context Example
```
{
    "Okta": {
        "Group": {
            "Created": "2018-01-19T02:02:06.000Z",
            "ID": "00gdout3zEaf7c50h7",
            "LastMembershipUpdated": "2020-03-26T13:56:56.000Z",
            "LastUpdated": "2018-01-19T02:02:06.000Z",
            "Name": "Demisto",
            "ObjectClass": [
                "okta:user_group"
            ],
            "Type": "OKTA_GROUP"
        }
    }
}
```

##### Human Readable Output
>### Groups
>|Created|Description|ID|LastMembershipUpdated|LastUpdated|Name|ObjectClass|Type|
>|---|---|---|---|---|---|---|---|
>| 2018-01-19T02:02:06.000Z |  | 00gdougctEaf7c50h7 | 2020-03-26T13:56:56.000Z | 2018-01-19T02:02:06.000Z | Demisto | okta:user_group | OKTA_GROUP |


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


##### Command Example
```!okta-get-failed-logins since="2019-04-30T00:00:00.000Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "goo@test.com",
                    "detailEntry": null,
                    "displayName": "unknown",
                    "id": "unknown",
                    "type": "User"
                },
                "authenticationContext": {
                    "authenticationProvider": null,
                    "authenticationStep": 0,
                    "credentialProvider": null,
                    "credentialType": null,
                    "externalSessionId": "unknown",
                    "interface": null,
                    "issuer": null
                },
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Tel Aviv",
                        "country": "Israel",
                        "geolocation": {
                            "lat": 32.0678,
                            "lon": 34.7647
                        },
                        "postalCode": null,
                        "state": "Tel Aviv"
                    },
                    "id": null,
                    "ipAddress": "127.0.0.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Windows 10",
                        "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36"
                    },
                    "zone": "null"
                },
                "debugContext": {
                    "debugData": {
                        "loginResult": "VERIFICATION_ERROR",
                        "requestId": "XYM92q-0Fs0ewvRQZVAlzwAABL8",
                        "requestUri": "/api/v1/authn",
                        "url": "/api/v1/authn?"
                    }
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_failed",
                "outcome": {
                    "reason": "VERIFICATION_ERROR",
                    "result": "FAILURE"
                },
                "published": "2019-09-19T08:35:38.353Z",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Tel Aviv",
                                "country": "Israel",
                                "geolocation": {
                                    "lat": 32.0678,
                                    "lon": 34.7647
                                },
                                "postalCode": null,
                                "state": "Tel Aviv"
                            },
                            "ip": "127.0.0.1",
                            "source": null,
                            "version": "V4"
                        }
                    ]
                },
                "securityContext": {
                    "asNumber": null,
                    "asOrg": null,
                    "domain": null,
                    "isProxy": null,
                    "isp": null
                },
                "severity": "INFO",
                "target": null,
                "transaction": {
                    "detail": {},
                    "id": "XYM92q-0Fs0ewvRQZVAlzwAABL8",
                    "type": "WEB"
                },
                "uuid": "7503c6b4-dab8-11e9-b336-d163e95fbe00",
                "version": "0"
            }
        }
    }
}
```

##### Human Readable Output
>### Failed Login Events
>|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
>|---|---|---|---|---|---|---|---|---|---|
>| unknown (User) | admin | 127.0.0.1 | CHROME on Windows 10 Computer | User login to Okta | FAILURE: VERIFICATION_ERROR | INFO | 127.0.0.1 | - | 09/30/2019, 18:42:38 |


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


##### Command Example
```!okta-get-logs filter=`actor.id eq "00u66lckvpjidYi0h7"` query=Boardman since="2020-03-03T20:23:17.573Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "Test@demisto.com",
                    "detailEntry": null,
                    "displayName": "Test Demisto",
                    "id": "00u66lvd7lpjidYi0h7",
                    "type": "User"
                },
                "authenticationContext": {
                    "authenticationProvider": null,
                    "authenticationStep": 0,
                    "credentialProvider": null,
                    "credentialType": null,
                    "externalSessionId": "trs3hs_F_UQT9K5FOPG7m4i1g",
                    "interface": null,
                    "issuer": null
                },
                "client": {
                    "device": "Unknown",
                    "geographicalContext": {
                        "city": "Boardman",
                        "country": "United States",
                        "geolocation": {
                            "lat": 45.8491,
                            "lon": -119.7143
                        },
                        "postalCode": "97818",
                        "state": "Oregon"
                    },
                    "id": null,
                    "ipAddress": "127.0.0.1",
                    "userAgent": {
                        "browser": "UNKNOWN",
                        "os": "Unknown",
                        "rawUserAgent": "Demisto/1.0"
                    },
                    "zone": "null"
                },
                "debugContext": {
                    "debugData": {
                        "requestId": "Xl68tch@7iZvNo0k8vPc5gAAAmE",
                        "requestUri": "/api/v1/groups/00g8mo0l5wuTxmoIC0h7/users/00uptu0jj9V91p5QM0h7",
                        "threatSuspected": "false",
                        "url": "/api/v1/groups/00g8mo0l5wuTxmoIC0h7/users/00uptu0jj9V91p5QM0h7?"
                    }
                },
                "displayMessage": "Remove user from group membership",
                "eventType": "group.user_membership.remove",
                "legacyEventType": "core.user_group_member.user_remove",
                "outcome": {
                    "reason": null,
                    "result": "SUCCESS"
                },
                "published": "2020-03-03T20:23:17.573Z",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Boardman",
                                "country": "United States",
                                "geolocation": {
                                    "lat": 45.8491,
                                    "lon": -119.7143
                                },
                                "postalCode": "97818",
                                "state": "Oregon"
                            },
                            "ip": "127.0.0.1",
                            "source": null,
                            "version": "V4"
                        }
                    ]
                },
                "securityContext": {
                    "asNumber": null,
                    "asOrg": null,
                    "domain": null,
                    "isProxy": null,
                    "isp": null
                },
                "severity": "INFO",
                "target": [
                    {
                        "alternateId": "test@this.com",
                        "detailEntry": null,
                        "displayName": "test this",
                        "id": "00uptu0jj9V91p5QM0h7",
                        "type": "User"
                    },
                    {
                        "alternateId": "unknown",
                        "detailEntry": null,
                        "displayName": "test1",
                        "id": "00g8mo0l5wuTxmoIC0h7",
                        "type": "UserGroup"
                    }
                ],
                "transaction": {
                    "detail": {},
                    "id": "Xl68tch@7iZvNo0k8vPc5gAAAmE",
                    "type": "WEB"
                },
                "uuid": "d14117f9-5d8c-11ea-a9cb-1f2fbd3b03f7",
                "version": "0"
            }
        }
    }
}
```

##### Human Readable Output
>### Okta Events
>|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
>|---|---|---|---|---|---|---|---|---|---|
>| Test Demisto (User) | Test@demisto.com | 127.0.0.1 | Unknown browser on Unknown OS Unknown device | Remove user from group membership | SUCCESS | INFO | 127.0.0.1 | test this (User) test1 (UserGroup)  | 03/03/2020, 20:23:17 |


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


##### Command Example
```!okta-get-group-assignments since="2019-04-30T00:00:00.000Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "Test@demisto.com",
                    "detailEntry": null,
                    "displayName": "Test Demisto",
                    "id": "00u66lckd7lpjidYi0h7",
                    "type": "User"
                },
                "authenticationContext": {
                    "authenticationProvider": null,
                    "authenticationStep": 0,
                    "credentialProvider": null,
                    "credentialType": null,
                    "externalSessionId": "trs4IvlVrvVR9G8RPsPtFjwBA",
                    "interface": null,
                    "issuer": null
                },
                "client": {
                    "device": "Unknown",
                    "geographicalContext": {
                        "city": "Boardman",
                        "country": "United States",
                        "geolocation": {
                            "lat": 45.8491,
                            "lon": -119.7143
                        },
                        "postalCode": "97818",
                        "state": "Oregon"
                    },
                    "id": null,
                    "ipAddress": "127.0.0.1",
                    "userAgent": {
                        "browser": "UNKNOWN",
                        "os": "Unknown",
                        "rawUserAgent": "Demisto/1.0"
                    },
                    "zone": "null"
                },
                "debugContext": {
                    "debugData": {
                        "requestId": "XXxTqUauHPkBXo4-TEcw9QAAAq0",
                        "requestUri": "/api/v1/groups/00g8mo0l5wuTxmoIC0h7/users/00ued6gq9jItNhAsN0h7",
                        "url": "/api/v1/groups/00g8mo0l5wuTxmoIC0h7/users/00ued6gq9jItNhAsN0h7?"
                    }
                },
                "displayMessage": "Add user to group membership",
                "eventType": "group.user_membership.add",
                "legacyEventType": "core.user_group_member.user_add",
                "outcome": {
                    "reason": null,
                    "result": "SUCCESS"
                },
                "published": "2019-09-14T02:42:49.379Z",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Boardman",
                                "country": "United States",
                                "geolocation": {
                                    "lat": 45.8491,
                                    "lon": -119.7143
                                },
                                "postalCode": "97818",
                                "state": "Oregon"
                            },
                            "ip": "127.0.0.1",
                            "source": null,
                            "version": "V4"
                        }
                    ]
                },
                "securityContext": {
                    "asNumber": null,
                    "asOrg": null,
                    "domain": null,
                    "isProxy": null,
                    "isp": null
                },
                "severity": "INFO",
                "target": [
                    {
                        "alternateId": "test@this.com",
                        "detailEntry": null,
                        "displayName": "test this",
                        "id": "00ued6gq9jItNhAsN0h7",
                        "type": "User"
                    },
                    {
                        "alternateId": "unknown",
                        "detailEntry": null,
                        "displayName": "test1",
                        "id": "00g8mo0l5wuTxmoIC0h7",
                        "type": "UserGroup"
                    }
                ],
                "transaction": {
                    "detail": {},
                    "id": "XXxTqUauHPkBXo4-TEcw9QAAAq0",
                    "type": "WEB"
                },
                "uuid": "5741ef53-d699-11e9-a08c-d549acc8afb2",
                "version": "0"
            }
        }
    }
}
```

##### Human Readable Output
>### Group Assignment Events
>|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
>|---|---|---|---|---|---|---|---|---|---|
>| Test Demisto (User) | Test@demisto.com | 127.0.0.1 | Unknown browser on Unknown OS Unknown device | Add user to group membership | SUCCESS | INFO | 127.0.0.1 | test this (User) test1 (UserGroup)  | 09/29/2019, 03:47:46 |


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


##### Command Example
```!okta-get-application-assignments since="2019-04-30T00:00:00.000Z" until="2020-02-30T00:00:00.000Z" sortOrder=DESCENDING limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "Test@demisto.com",
                    "detailEntry": null,
                    "displayName": "Test Demisto",
                    "id": "00u66lckd7lpjidYi0h7",
                    "type": "User"
                },
                "authenticationContext": {
                    "authenticationProvider": null,
                    "authenticationStep": 0,
                    "credentialProvider": null,
                    "credentialType": null,
                    "externalSessionId": "trsFSV6XXY4TMCSB_xzJrZ85A",
                    "interface": null,
                    "issuer": null
                },
                "client": {
                    "device": "Unknown",
                    "geographicalContext": {
                        "city": "Boardman",
                        "country": "United States",
                        "geolocation": {
                            "lat": 45.8491,
                            "lon": -119.7143
                        },
                        "postalCode": "97818",
                        "state": "Oregon"
                    },
                    "id": null,
                    "ipAddress": "127.0.0.1",
                    "userAgent": {
                        "browser": "UNKNOWN",
                        "os": "Unknown",
                        "rawUserAgent": "python-requests/2.22.0"
                    },
                    "zone": "null"
                },
                "debugContext": {
                    "debugData": {
                        "requestId": "XlgCgAEBMJsNo5Yh9rHtZAAACPw",
                        "requestUri": "/api/v1/users/00upywm7l0rL1V0zt0h7/lifecycle/activate",
                        "threatSuspected": "false",
                        "url": "/api/v1/users/00upywm7l0rL1V0zt0h7/lifecycle/activate?"
                    }
                },
                "displayMessage": "Add user to application membership",
                "eventType": "application.user_membership.add",
                "legacyEventType": "app.generic.provision.assign_user_to_app",
                "outcome": {
                    "reason": null,
                    "result": "SUCCESS"
                },
                "published": "2020-02-27T17:55:12.949Z",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Boardman",
                                "country": "United States",
                                "geolocation": {
                                    "lat": 45.8491,
                                    "lon": -119.7143
                                },
                                "postalCode": "97818",
                                "state": "Oregon"
                            },
                            "ip": "127.0.0.1",
                            "source": null,
                            "version": "V4"
                        }
                    ]
                },
                "securityContext": {
                    "asNumber": null,
                    "asOrg": null,
                    "domain": null,
                    "isProxy": null,
                    "isp": null
                },
                "severity": "INFO",
                "target": [
                    {
                        "alternateId": "Test1@test.com",
                        "detailEntry": null,
                        "displayName": "Test 1 that",
                        "id": "0uapywj3yxcjhpjSQ0h7",
                        "type": "AppUser"
                    },
                    {
                        "alternateId": "ShrikSAML",
                        "detailEntry": null,
                        "displayName": "ShrikSAML",
                        "id": "0oabe0e2jruaQccDf0h7",
                        "type": "AppInstance"
                    },
                    {
                        "alternateId": "Test1@test.com",
                        "detailEntry": null,
                        "displayName": "Test 1 that",
                        "id": "00upywm7l0rL1V0zt0h7",
                        "type": "User"
                    }
                ],
                "transaction": {
                    "detail": {},
                    "id": "XlgCgAEBMJsNo5Yh9rHtZAAACPw",
                    "type": "WEB"
                },
                "uuid": "4d8a4e9a-598a-11ea-a594-b9fb637659a5",
                "version": "0"
            }
        }
    }
}
```

##### Human Readable Output
>### Application Assignment Events
>|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
>|---|---|---|---|---|---|---|---|---|---|
>| Test Demisto (User) | Test@demisto.com | 127.0.0.1 | Unknown browser on Unknown OS Unknown device | Add user to application membership | SUCCESS | INFO | 127.0.0.1 | Test 1 that (AppUser) ShrikSAML (AppInstance) Test 1 that (User)  | 02/27/2020, 17:55:12 |


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


##### Command Example
```!okta-get-application-authentication since="2019-04-30T00:00:00.000Z" until="2020-02-30T00:00:00.000Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "Test@demisto.com",
                    "detailEntry": null,
                    "displayName": "Test Demisto",
                    "id": "00u66lckd7lpjidYi0h7",
                    "type": "User"
                },
                "authenticationContext": {
                    "authenticationProvider": null,
                    "authenticationStep": 0,
                    "credentialProvider": null,
                    "credentialType": null,
                    "externalSessionId": "102ejbJMP0RSE2zwIOhr_PpHA",
                    "interface": null,
                    "issuer": null
                },
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Tel Aviv",
                        "country": "Israel",
                        "geolocation": {
                            "lat": 32.0678,
                            "lon": 34.7647
                        },
                        "postalCode": null,
                        "state": "Tel Aviv"
                    },
                    "id": null,
                    "ipAddress": "127.0.0.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36"
                    },
                    "zone": "null"
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "XYI-PiWDTYEsVNLm7sc0vwAACi0",
                        "initiationType": "SP_INITIATED",
                        "requestId": "XYI-PzNoI1UMTtFvio-9LAAACAc",
                        "requestUri": "/app/demistodev725178_benzi_1/exkm30ffmuhcL0rFv0h7/sso/saml",
                        "signOnMode": "SAML 2.0",
                        "url": "/app/demistodev725178_benzi_1/exkm30ffmuhcL0rFv0h7/sso/saml?RelayState=&SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzRiODZjMGUzLWI0NzktNGU2NS00ZjIwLWJiNTE0YTc3NTUyMiIgVmVyc2lvbj0iMi4wIiBQcm90b2NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVBPU1QiIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cHM6Ly9lYzItNTItNDgtMTItMTIzLmV1LXdlc3QtMS5jb21wdXRlLmFtYXpvbmF3cy5jb20vc2FtbCIgSXNzdWVJbnN0YW50PSIyMDE5LTA5LTE4VDE0OjIyOjM3WiI%2BPHNhbWw6SXNzdWVyPmh0dHBzOi8vZGV2LTcyNTE3OC5va3RhcHJldmlldy5jb20vYXBwL2V4a20zMGZmbXVoY0wwckZ2MGg3L3Nzby9zYW1sL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEFsbG93Q3JlYXRlPSJ0cnVlIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiPjwvc2FtbHA6TmFtZUlEUG9saWN5Pjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg%3D%3D&fromLoginToken=OODncZp5PTgZ-8QwGMHgbJ6psmQES6dUWiMohfLGGm7GWKko8LFXHz3faG7ZkoocPX2ixv-dyUSOF7qJ9DZDVoVkeETM7n6MskWQ01woQFqUcUVdM1xDBmplZlK1DMhX6ozpZQV2XNK073FfDt4bASBEFFgGkFi5ygH-LmBFSfcoiLWHM5MGJ-JEUB97peJxOL41inNX2r333FMJoDzem0dLAOf4cfApoVz7VDdY06r8i6Lt0vuxmxKyZRWJkCHroKyc3ysag9gbUMR5tSoe3hRPJvCBozjYtzkpVlLBP_6V01eGL2YVP8JR2rkpI8MvBYNDLIoJry1e_eBOF3kzJA"
                    }
                },
                "displayMessage": "User single sign on to app",
                "eventType": "user.authentication.sso",
                "legacyEventType": "app.auth.sso",
                "outcome": {
                    "reason": null,
                    "result": "SUCCESS"
                },
                "published": "2019-09-18T14:29:19.329Z",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Tel Aviv",
                                "country": "Israel",
                                "geolocation": {
                                    "lat": 32.0678,
                                    "lon": 34.7647
                                },
                                "postalCode": null,
                                "state": "Tel Aviv"
                            },
                            "ip": "127.0.0.1",
                            "source": null,
                            "version": "V4"
                        }
                    ]
                },
                "securityContext": {
                    "asNumber": null,
                    "asOrg": null,
                    "domain": null,
                    "isProxy": null,
                    "isp": null
                },
                "severity": "INFO",
                "target": [
                    {
                        "alternateId": "benzi_master",
                        "detailEntry": {
                            "signOnModeType": "SAML_2_0"
                        },
                        "displayName": "benzi_master",
                        "id": "0oam30ffmvM5cLzxo0h7",
                        "type": "AppInstance"
                    },
                    {
                        "alternateId": "Test@demisto.com",
                        "detailEntry": null,
                        "displayName": "Test Demisto",
                        "id": "0uam30nfffJqV3I4M0h7",
                        "type": "AppUser"
                    }
                ],
                "transaction": {
                    "detail": {},
                    "id": "XYI-PzNoI1UMTtFvio-9LAAACAc",
                    "type": "WEB"
                },
                "uuid": "b349fd35-da20-11e9-81c0-95908eb13131",
                "version": "0"
            }
        }
    }
}
```

##### Human Readable Output
>### Application Authentication Events
>|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
>|---|---|---|---|---|---|---|---|---|---|
>| Test Demisto (User) | Test@demisto.com | 127.0.0.1 | CHROME on Mac OS X Computer | User single sign on to app | SUCCESS | INFO | 127.0.0.1 | BenziPermanent (AppInstance) Test Demisto (AppUser)  | 10/14/2019, 12:16:53 |


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

##### Command Example
```!okta-delete-user username=testForDocs@test.com```


##### Human Readable Output
>User: testForDocs@test.com was Deleted successfully

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

##### Command Example
```!okta-clear-user-sessions userId=00ui5brmwtJpMdoZZ0h7```


##### Human Readable Output
>### User session was cleared for: 00ui5brmwtJpMdoZZ0h7


### okta-list-zones

***
Get an Okta Zone object.

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
| Okta.Zone.proxies.type | String | Proxies IP entry type e.g. CIDR. | 
| Okta.Zone.proxies.value | Unknown | Proxies IP entry value, e.g., 34.103.1.108/32. | 
| Okta.Zone.status | String | Zone status, e.g., ACTIVE. | 
| Okta.Zone.system | Number | True if this is a system zone, false if user-created. | 
| Okta.Zone.type | String | Zone type, e.g., IP. | 


#### Command Example
```!okta-list-zones```

#### Context Example
```
{
    "Okta": {
        "Zone": [
            {
                "_links": {
                    "deactivate": {
                        "hints": {
                            "allow": [
                                "POST"
                            ]
                        },
                        "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzo9rbw8evGOFV1VE0h7/lifecycle/deactivate"
                    },
                    "self": {
                        "hints": {
                            "allow": [
                                "GET",
                                "PUT",
                                "DELETE"
                            ]
                        },
                        "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzo9rbw8evGOFV1VE0h7"
                    }
                },
                "created": "2017-03-03T22:05:24.000Z",
                "gateways": [
                    {
                        "type": "CIDR",
                        "value": "2.2.2.2/32"
                    }
                ],
                "id": "nzo9rbw8evGOFV1VE0h7",
                "lastUpdated": "2020-04-23T08:58:55.000Z",
                "name": "LegacyIpZone",
                "proxies": null,
                "status": "ACTIVE",
                "system": true,
                "type": "IP"
            },
            {
                "_links": {
                    "deactivate": {
                        "hints": {
                            "allow": [
                                "POST"
                            ]
                        },
                        "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wY33h7/lifecycle/deactivate"
                    },
                    "self": {
                        "hints": {
                            "allow": [
                                "GET",
                                "PUT",
                                "DELETE"
                            ]
                        },
                        "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wY33h7"
                    }
                },
                "created": "2020-04-06T22:23:12.000Z",
                "gateways": [
                    {
                        "type": "CIDR",
                        "value": "1.1.1.2/32"
                    },
                    {
                        "type": "CIDR",
                        "value": "1.1.1.3/32"
                    },
                    {
                        "type": "CIDR",
                        "value": "2.2.2.2/32"
                    },
                    {
                        "type": "CIDR",
                        "value": "2.2.2.3/32"
                    }
                ],
                "id": "nzoqsmcx1qWYJ6wY33h7",
                "lastUpdated": "2020-06-05T08:57:57.000Z",
                "name": "MyZone",
                "proxies": null,
                "status": "ACTIVE",
                "system": false,
                "type": "IP"
            }
        ]
    }
}
```

#### Human Readable Output
>### Okta Zones
>|name|id|gateways|status|system|lastUpdated|created|
>|---|---|---|---|---|---|---|
>| LegacyIpZone | nzo9rbw8evGOFV1VE0h7 | {'type': 'CIDR', 'value': '2.2.2.2/32'} | ACTIVE | true | 2020-04-23T08:58:55.000Z | 2017-03-03T22:05:24.000Z |
>| MyZone | nzoqsmcx1qWYJ6wY33h7 | {'type': 'CIDR', 'value': '3.3.3.4/32'},<br/>{'type': 'CIDR', 'value': '5.5.5.3/32'},<br/>{'type': 'CIDR', 'value': '3.3.3.1/32'},<br/>{'type': 'CIDR', 'value': '2.2.2.3/32'} | ACTIVE | false | 2020-06-05T08:57:57.000Z | 2020-04-06T22:23:12.000Z |


### okta-update-zone

***
Update an Okta Zone.

#### Base Command

`okta-update-zone`

#### Input

| **Argument Name** | **Description**                                                                                                                                         | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| zoneID | Zone ID to update, e.g., nzoqsmcx1qWYJ6wYF0h7.                                                                                                          | Required | 
| zoneName | Updates the zone name.                                                                                                                                  | Optional | 
| gatewayIPs | Updates Gateway IP addresses: CIDR range (1.1.0.0/16) or single IP address (2.2.2.2).                                                                   | Optional | 
| proxyIPs | Update Proxy IP addresses: CIDR range (1.1.0.0/16) or single IP address (2.2.2.2).                                                                      | Optional | 
| updateType | Indicate the action of adding an IP to an existing zone or overriding the existing IPs. Possible values are: "APPEND", "OVERRIDE". Default is "OVERRIDE". | Optional | 

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


#### Command Example
```!okta-update-zone zoneID=nzoqsmcx1qWYJ6wY33h7 zoneName=MyZone```

#### Context Example
```
{
    "Okta": {
        "Zone": {
            "_links": {
                "deactivate": {
                    "hints": {
                        "allow": [
                            "POST"
                        ]
                    },
                    "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wY33h7/lifecycle/deactivate"
                },
                "self": {
                    "hints": {
                        "allow": [
                            "GET",
                            "PUT",
                            "DELETE"
                        ]
                    },
                    "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wY33h7"
                }
            },
            "created": "2020-04-06T22:23:12.000Z",
            "gateways": [
                {
                    "type": "CIDR",
                    "value": "1.1.3.5/32"
                },
                {
                    "type": "CIDR",
                    "value": "5.3.143.103/32"
                },
                {
                    "type": "CIDR",
                    "value": "5.3.246.228/32"
                },
                {
                    "type": "CIDR",
                    "value": "5.3.246.229/32"
                }
            ],
            "id": "nzoqsmcx1qWYJ6wY33h7",
            "lastUpdated": "2020-06-05T08:57:57.000Z",
            "name": "MyZone",
            "proxies": null,
            "status": "ACTIVE",
            "system": false,
            "type": "IP"
        }
    }
}
```

#### Human Readable Output

>### Okta Zones
>|name|id|gateways|status|system|lastUpdated|created|
>|---|---|---|---|---|---|---|
>| MyZone | nzoqsmcx1qWYJ6wY33h7 | {'type': 'CIDR', 'value': '1.3.1.5/32'},<br/>{'type': 'CIDR', 'value': '1.3.1.5/32'},<br/>{'type': 'CIDR', 'value': '1.3.1.5/32'},<br/>{'type': 'CIDR', 'value': '1.3.1.5/32'} | ACTIVE | false | 2020-06-05T08:57:57.000Z | 2020-04-06T22:23:12.000Z |


### okta-get-zone

***
Get a Zone by its ID.

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


#### Command Example
```!okta-get-zone zoneID=nzoqsmcx1qWYJ6wY33h7```

#### Context Example
```
{
    "Okta": {
        "Zone": {
            "_links": {
                "deactivate": {
                    "hints": {
                        "allow": [
                            "POST"
                        ]
                    },
                    "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wY33h7/lifecycle/deactivate"
                },
                "self": {
                    "hints": {
                        "allow": [
                            "GET",
                            "PUT",
                            "DELETE"
                        ]
                    },
                    "href": "https://dev-950355.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wY33h7"
                }
            },
            "created": "2020-04-06T22:23:12.000Z",
            "gateways": [
                {
                    "type": "CIDR",
                    "value": "1.3.1.3/32"
                },
                {
                    "type": "CIDR",
                    "value": "3.5.146.103/32"
                },
                {
                    "type": "CIDR",
                    "value": "3.5.1.228/32"
                },
                {
                    "type": "CIDR",
                    "value": "3.5.1.229/32"
                }
            ],
            "id": "nzoqsmcx1qWYJ6wY33h7",
            "lastUpdated": "2020-06-05T08:57:57.000Z",
            "name": "MyZone",
            "proxies": null,
            "status": "ACTIVE",
            "system": false,
            "type": "IP"
        }
    }
}
```

#### Human Readable Output

>### Okta Zones
>|name|id|gateways|status|system|lastUpdated|created|
>|---|---|---|---|---|---|---|
>| MyZone | nzoqsmcx1qWYJ6wY33h7 | {'type': 'CIDR', 'value': '1.3.1.3/32'},<br/>{'type': 'CIDR', 'value': '3.5.146.103/32'},<br/>{'type': 'CIDR', 'value': '3.5.1.228/32'},<br/>{'type': 'CIDR', 'value': '3.5.1.229/32'} | ACTIVE | false | 2020-06-05T08:57:57.000Z | 2020-04-06T22:23:12.000Z |

### okta-list-users
***
Lists users in your organization.


#### Base Command

`okta-list-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verbose | Whether to return extended user information. Can be "true" or "false". The default is "false". Possible values are: true, false. Default is false. | Optional | 
| limit | The maximum number of results to return. | Optional | 
| query | Searches the name property of groups for matching values. | Optional | 
| filter | Useful for performing structured queries where constraints on group attribute values can be explicitly targeted. <br/>The following expressions are supported(among others) for groups with the filter query parameter: <br/>type eq "OKTA_GROUP" - Groups that have a type of OKTA_GROUP; lastUpdated lt "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with profile last updated before a specific timestamp; lastMembershipUpdated eq "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with memberships last updated at a specific timestamp; id eq "00g1emaKYZTWRYYRRTSK" - Group with a specified ID.
For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering. | Optional | 
| after | The cursor in which to retrive the results from and on. If the query didn't reach the end of results, the tag will be found in the readable output under the tag key. | Optional |

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
| Okta.User.tag| String | The location of the next item, used with after param. |


#### Command Example
```!okta-list-users```

#### Context Example
```json
{
    "Okta":
    {
        "User":
        {
            "tag": "test12tag"
        }
    },
    "Account": [
        {
            "Created": "2018-07-24T20:20:04.000Z",
            "DisplayName": "Dbot XSOAR",
            "Email": "dbot@xsoar.com",
            "ID": "XXXXXXXXX",
            "Status": "STAGED",
            "Type": "Okta",
            "Username": "dbot@xsoar.com"
        }
    ]
}
```

#### Human Readable Output

>### Okta users found:
> ### Users
>|First Name|ID|Last Login|Last Name|Login|Mobile Phone|Status|
>|---|---|---|---|---|---|---|
>| Dbot | XXXXX |  | XSOAR | dbot@xsoar.com |  | STAGED |
> 
> ### tag: test12tag
### okta-create-zone

***
Creates a Zone with the specified name.

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
| OktaGroup.ID | Unknown | Group ID in Okta. | 
| OktaGroup.Name | Unknown | Group name in Okta. | 
| OktaGroup.Description | Unknown | Group description in Okta. | 
| OktaGroup.Type | Unknown | Group type in Okta. | 
#### Command example
```!okta-create-group name="TestGroup" description="TestGroup description."```
#### Context Example
```json
{
    "OktaGroup": {
        "Description": "TestGroup description.",
        "ID": "00g3qb398kItYXzKd1d7",
        "Name": "TestGroup",
        "Type": "OKTA_GROUP"
    }
}
```

#### Human Readable Output

>Group Created: [GroupID:00g3qb398kItYXzKd1d7, GroupName: TestGroup]

### okta-assign-group-to-app

***
Assign a group to an application.

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
#### Command example
```!okta-assign-group-to-app appName="Default-App" groupName="TestGroup"```
#### Human Readable Output

>Group: TestGroup added to PA App successfully
### okta-expire-password

***
Expires a password for an existing Okta user.

#### Base Command

`okta-expire-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username for which to expire the password. | Required | 
| temporary_password | When true, you'll need to change the password in the next login. Possible values are: true, false. Default is false. | Optional | 
| revoke_session | When true, revokes the user's existing sessions. | Optional |
| hide_password | When true, prevents the password from being saved in the war room. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Activated | Date | Timestamp for when the user was activated. | 
| Account.Created | Date | Timestamp for when the user was created. | 
| Account.DisplayName | String | Okta account display name. | 
| Account.Email | String | Okta account email. | 
| Account.ID | String | Created Okta account ID. | 
| Account.PasswordChanged | Date | Timestamp for when the user's password was last changed. | 
| Account.Status | String | Okta account current status. | 
| Account.StatusChanged | Date | Timestamp for when the user's status was last changed. | 
| Account.Type | String | Okta account type. | 
| Account.Username | String | Okta account usernames returned by the search. | 

#### Command example
```!okta-expire-password username="4x1xh5rl@test.com" temporary_password="false"```
#### Context Example
```json
{
    "Account": {
        "Activated": "2022-06-20T04:48:04.000Z",
        "Created": "2022-06-20T04:47:59.000Z",
        "DisplayName": "Test 1  Test1",
        "Email": "4x1xh5rl@test.com",
        "ID": "00u19cr5qv91HjELI0h8",
        "PasswordChanged": "2022-06-20T04:48:07.000Z",
        "Status": "PASSWORD_EXPIRED",
        "StatusChanged": "2023-09-10T12:56:04.000Z",
        "Type": "Okta",
        "Username": "4x1xh5rl@test.com"
    }
}
```

#### Human Readable Output

>### Okta Expired Password
>|_links|activated|created|credentials|id|lastUpdated|passwordChanged|profile|status|statusChanged|type|
>|---|---|---|---|---|---|---|---|---|---|---|
>| suspend: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/lifecycle/suspend", "method": "POST"}<br/>schema: {"href": "https://test.oktapreview.com/api/v1/meta/schemas/user/osc66lckcvDyVcGzS0h7"}<br/>resetPassword: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/lifecycle/reset_password", "method": "POST"}<br/>forgotPassword: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/credentials/forgot_password", "method": "POST"}<br/>expirePassword: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/lifecycle/expire_password", "method": "POST"}<br/>changeRecoveryQuestion: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/credentials/change_recovery_question", "method": "POST"}<br/>self: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8"}<br/>type: {"href": "https://test.oktapreview.com/api/v1/meta/types/user/oty66lckcvDyVcGzS0h7"}<br/>changePassword: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/credentials/change_password", "method": "POST"}<br/>deactivate: {"href": "https://test.oktapreview.com/api/v1/users/00u19cr5qv91HjELI0h8/lifecycle/deactivate", "method": "POST"} | 2022-06-20T04:48:04.000Z | 2022-06-20T04:47:59.000Z | password: {}<br/>recovery_question: {"question": "whats the first school?"}<br/>provider: {"type": "OKTA", "name": "OKTA"} | 00u19cr5qv91HjELI0h8 | 2023-09-10T12:56:04.000Z | 2022-06-20T04:48:07.000Z | firstName: Test 1 <br/>lastName: Test1<br/>preferredLanguage: en<br/>mobilePhone: null<br/>city: Tel-Aviv<br/>displayName: Test 1 that<br/>nickName: Testush<br/>secondEmail: null<br/>login: 4x1xh5rl@test.com<br/>email: 4x1xh5rl@test.com<br/>employeeNumber: 12345 | PASSWORD_EXPIRED | 2023-09-10T12:56:04.000Z | id: oty66lckcvDyVcGzS0h7 |

### okta-auth-reset

***
Reset OAuth authentication data (authentication process will start from the beginning, and a new token will be generated).

#### Base Command

`okta-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.