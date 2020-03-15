Integration with Okta's cloud-based identity management service
This integration was integrated and tested
## Configure Okta v2 on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Okta v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Okta URL (https://<domain>.okta.com) | True |
| apitoken | API Token (see Detailed Instructions) | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### okta-unlock-user
***
Unlocks a specific user.
##### Base Command

`okta-unlock-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Unlock User | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
`````!okta-unlock-user username=testForDocs@test.com`````

##### Human Readable Output

### User testForDocs@test.com unlocked

### okta-deactivate-user
***
Deactivate User.
##### Base Command

`okta-deactivate-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Deactivates specified user. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-deactivate-user username=testForDocs@test.com```

##### Human Readable Output
### User testForDocs@test.com deactivated

### okta-activate-user
***
Activates a specific user.
##### Base Command

`okta-activate-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username in Okta to activate | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-activate-user username=testForDocs@test.com```

##### Human Readable Output
### testForDocs@test.com is active now

### okta-suspend-user
***
Suspends a user. This operation can only be performed on users with an ACTIVE status. The user has a status of SUSPENDED when the process is completed
##### Base Command

`okta-suspend-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username in Okta to suspend | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-suspend-user username=testForDocs@test.com```

##### Human Readable Output
### testForDocs@test.com status is Suspended

### okta-unsuspend-user
***
Returns a user to ACTIVE status. This operation can only be performed on users that have a SUSPENDED status.
##### Base Command

`okta-unsuspend-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username you want to change to ACTIVE status. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-unsuspend-user username=testForDocs@test.com```

##### Human Readable Output
### testForDocs@test.com is no longer SUSPENDED

### okta-get-user-factors
***
Returns all the enrolled facors for the specified user.
##### Base Command

`okta-get-user-factors`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username. | Optional | 
| userId | User ID of the user in which to get enrolled factors. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID. | 
| Account.Factor.ID | String | Okta account facor ID. | 
| Account.Factor.Provider | String | Okta account factor provider | 
| Account.Factor.Profile | String | Okta account factor profle | 
| Account.Factor.FactorType | String | Okta account factor type | 
| Account.Factor.Status | Unknown | Okta account factor status | 


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
        "ID": "00upt1w8t40wFQM2v6t4"
    }
}
```

##### Human Readable Output
Factors for user: 00upt1w8t40wFQM2v6t4
 ### Factors
|FactorType|ID|Profile|Provider|Status|
|---|---|---|---|---|
| sms | mblpt21nffaaN5F060h7 | phoneNumber: +12025550191 | OKTA | PENDING_ACTIVATION |
| token:software:totp | uftpt24kdrDJ7fDOq0h7 | credentialId: factor@test.com | GOOGLE | PENDING_ACTIVATION |
| push | opfpt1joeaArlg27g0h7 |  | OKTA | PENDING_ACTIVATION |


### okta-reset-factor
***
Unnenrolls an existing factor for thr specified user. which enables the user to enroll a new factor
##### Base Command

`okta-reset-factor`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | The user ID | Optional | 
| username | Okta username | Optional | 
| factorId | The ID of the factor to reset | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-reset-factor factorId=ufsq7cvptfbjQa72c0h7 userId=00upt1w8t40wFQM2v6t4```

##### Human Readable Output
Factor: ufsq7cvptfbjQa72c0h7 deleted

### okta-set-password
***
Sets passwords without validating existing user credentials
##### Base Command

`okta-set-password`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username in which to set the password | Required | 
| password | The new password to set for thr user | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-set-password username=testForDocs@test.com password=N3wPa55word!```

##### Human Readable Output
testForDocs@test.com password was last changed on 2020-03-11T13:29:34.000Z

### okta-add-to-group
***
Adds a user to a group with OKTA_GROUP type
##### Base Command

`okta-add-to-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | ID of the user to add | Optional | 
| username | Name of the user to add | Optional | 
| groupId | ID of the group to add the user to | Optional | 
| groupName | Name of the group to add the user to | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-add-to-group groupName=Demisto username=testForDocs@test.com```

##### Human Readable Output
User: 00uq8zbdd4h6sZOsa0h7 added to group: Demisto successfully

### okta-remove-from-group
***
Removes a user from a group with OKTA_GROUP type
##### Base Command

`okta-remove-from-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | ID of the user to remove | Optional | 
| username | Name of the user to remove | Optional | 
| groupId | ID of the group to remove the user from | Optional | 
| groupName | Name of the group to remove the user from | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-remove-from-group groupName=demisto username=testForDocs@test.com```

##### Human Readable Output
User: 00uq8zbdd4h6sZOsa0h7 was removed from group: demisto successfully

### okta-get-groups
***
Returns all user groups associated with a specified user.
##### Base Command

`okta-get-groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username in Okta in which to get groups | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Group | Unknown | Okta groups in which the account is associated | 
| Account.ID | String | Okta account ID | 
| Account.Type | String | Account type - Okta | 
| Account.Group.ID | String | Unique key for the group | 
| Account.Group.Created | Date | Timestamp when the group was ceated | 
| Account.Group.ObjectClass | String | Determines the group's profile | 
| Account.Group.LastUpdated | Date | Timestamp when the group's profile was last updated | 
| Account.Group.LastMembershipUpdated | Date | Timestamp when the group's memberships were last updated | 
| Account.Group.Type | String | Determines how a group's profile and emberships ae managed | 
| Account.Group.Description | String | Description of the group | 
| Account.Group.Name | String | Name of the group | 


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
                "LastMembershipUpdated": "2020-03-11T13:29:13.000Z",
                "LastUpdated": "2016-04-12T15:01:50.000Z",
                "Name": "Everyone",
                "ObjectClass": [
                    "okta:user_group"
                ],
                "Type": "BUILT_IN"
            },
            {
                "Created": "2018-01-19T02:02:06.000Z",
                "ID": "00gg5ugcq3zEaf7c50h7",
                "LastMembershipUpdated": "2020-03-11T13:29:19.000Z",
                "LastUpdated": "2018-01-19T02:02:06.000Z",
                "Name": "Demisto",
                "ObjectClass": [
                    "okta:user_group"
                ],
                "Type": "OKTA_GROUP"
            }
        ],
        "ID": "00uq7cxu1prpOHm6P0h7",
        "Type": "Okta"
    }
}
```

##### Human Readable Output
Okta groups for user: testForDocs@test.com
 ### Groups
|Created|Description|ID|LastMembershipUpdated|LastUpdated|Name|ObjectClass|Type|
|---|---|---|---|---|---|---|---|
| 2016-04-12T15:01:50.000Z | All users in your organization | 00g66lckcsAJpLcNc0h7 | 2020-03-11T13:29:13.000Z | 2016-04-12T15:01:50.000Z | Everyone | okta:user_group | BUILT_IN |
| 2018-01-19T02:02:06.000Z |  | 00gdougcq3zEaf7c50h7 | 2020-03-11T13:29:19.000Z | 2018-01-19T02:02:06.000Z | Demisto | okta:user_group | OKTA_GROUP |


### okta-verify-push-factor
***
Enrolls and verifies a push factor for a specified user.
##### Base Command

`okta-verify-push-factor`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | The id of the user to verify | Required | 
| factorId | The push factor ID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta user ID | 
| Account.VerifyPushResult | String | Okta user push factor result. | 


##### Command Example
```!okta-verify-push-factor factorId=opfpt1joeaArlg27g0h7 userId=00upt1w8t40wFQM2v0h7```

##### Human Readable Output
Verify push factor result for user 00upt1w8t40wgQM2v0h7: WAITING

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
Search for Okta users
##### Base Command

`okta-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| term | Term in which to search this term can be a first name, last name or email | Required | 
| limit | Max number of results to return (The maximum (200) is used as a default) | Optional | 
| verbose | Returns details of users that match the found term | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account IDs returned by search | 
| Account.Username | String | Okta account usernames returned by search | 
| Account.Email | String | Okta account emails returned by search | 
| Account.DisplayName | String | Okta account display names returned by search | 
| Account.Type | String | Account type returned by search - Okta | 
| Account.Status | String | Okta account current status | 
| Account.Created | Date | Timestamp for when the user was created | 
| Account.Activated | Date | Timestamp for when the user was activated | 
| Account.StatusChanged | Date | Timestamp for when the user's status was changed | 
| Account.PasswordChanged | Date | Timestamp for when the users's password was last changed | 


##### Command Example
```!okta-search term=test verbose=true```

##### Context Example
```
{
    "Account": [
        {
            "Activated": "2018-02-20T20:29:55.000Z",
            "Created": "2016-10-25T15:10:25.000Z",
            "DisplayName": "user2 test2",
            "Email": "user2@demisto.com",
            "ID": "00u8mo28qn8pmbLBJ0h7",
            "PasswordChanged": "2016-10-26T13:33:07.000Z",
            "Status": "PROVISIONED",
            "StatusChanged": "2018-02-20T20:29:55.000Z",
            "Type": "Okta",
            "Username": "user2@demisto.com"
        },
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
            "Activated": "2020-03-10T16:59:24.000Z",
            "Created": "2020-03-10T16:59:21.000Z",
            "DisplayName": "test that",
            "Email": "testForDocs@test.com",
            "ID": "00uq7cxu1prpOHm6P0h7",
            "PasswordChanged": "2020-03-10T16:59:22.000Z",
            "Status": "ACTIVE",
            "StatusChanged": "2020-03-10T16:59:24.000Z",
            "Type": "Okta",
            "Username": "testForDocs@test.com"
        }
    ]
}
```

##### Human Readable Output
### Okta users found:
 ### User:user2@demisto.com
### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| user2@demisto.com | user2 | test2 | user2@demisto.com |  |  |

 ### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2018-02-20T20:29:55.000Z | 2016-10-25T15:10:25.000Z | provider: {"type": "OKTA", "name": "OKTA"} | 00u8mo28qn8pmbLBJ0h7 |  | 2018-02-20T20:29:55.000Z | 2016-10-26T13:33:07.000Z | PROVISIONED |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00u8mo28qn8pmbLBJ0h7"} |
### User:bartest@test.com
### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| bartest@test.com | bar | test | bartest@test.com |  |  |

 ### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-02-12T14:03:51.000Z | 2020-02-12T14:03:50.000Z | provider: {"type": "OKTA", "name": "OKTA"} | 00uppjeleqJQ2kkN80h7 |  | 2020-02-12T14:03:51.000Z |  | PROVISIONED |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uppjeleqJQ2kkN80h7"} |
### User:test@that.com
### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| test@that.com | test | that | test@that.com |  | test@that.com |

 ### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-02-19T12:33:20.000Z | 2018-07-31T12:48:33.000Z | provider: {"type": "OKTA", "name": "OKTA"} | 00ufufhqits3y78Ju0h7 |  | 2020-02-19T12:33:20.000Z | 2020-02-06T13:32:56.000Z | PROVISIONED |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00ufufhqits3y78Ju0h7"} |
### User:testForDocs@test.com
### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| testForDocs@test.com | test | that | testForDocs@test.com |  |  |

 ### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-03-10T16:59:24.000Z | 2020-03-10T16:59:21.000Z | password: {}<br>recovery_question: {"question": "whats is your favourite integration"}<br>provider: {"type": "OKTA", "name": "OKTA"} | 00uq7cxu1prpOHm6P0h7 |  | 2020-03-10T16:59:24.000Z | 2020-03-10T16:59:22.000Z | ACTIVE |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq7cxu1prpOHm6P0h7"} |


### okta-get-user
***
Fetches information for a specific user. You must enter one or more parameters for the command to run
##### Base Command

`okta-get-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Okta username in which to get information | Optional | 
| userId | User ID of the user in which to get information | Optional | 
| verbose | Additional data. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID. | 
| Account.Email | String | Okta account email. | 
| Account.Username | String | Okta account username. | 
| Account.DisplayName | String | Okta account display name. | 
| Account.Status | String | Okta account status. | 
| Account.Created | Date | Timestamp for when the user was created | 
| Account.Activated | Date | Timestamp for when the user was activated | 
| Account.StatusChanged | Date | Timestamp for when the user's status was changed | 
| Account.PasswordChanged | Date | Timestamp for when the users's password was last changed | 


##### Command Example
```!okta-get-user username=testForDocs@test.com verbose=true```

##### Context Example
```
{
    "Account": {
        "Activated": "2020-03-11T13:29:16.000Z",
        "Created": "2020-03-11T13:29:13.000Z",
        "DisplayName": "test that",
        "Email": "testForDocs@test.com",
        "ID": "00uq8zbdd4h6sZOsa0h7",
        "PasswordChanged": "2020-03-11T13:29:13.000Z",
        "Status": "ACTIVE",
        "StatusChanged": "2020-03-11T13:29:16.000Z",
        "Type": "Okta",
        "Username": "testForDocs@test.com"
    }
}
```

##### Human Readable Output
### User:testForDocs@test.com
### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| testForDocs@test.com | test | that | testForDocs@test.com |  |  |

 ### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
| 2020-03-11T13:29:16.000Z | 2020-03-11T13:29:13.000Z | password: {}<br>recovery_question: {"question": "whats is your favourite integration"}<br>provider: {"type": "OKTA", "name": "OKTA"} | 00uq8zbdd4h6sZOsa0h7 |  | 2020-03-11T13:29:16.000Z | 2020-03-11T13:29:13.000Z | ACTIVE |  | id: oty66lckcvDyVcGzS0h7 | suspend: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/lifecycle/suspend", "method": "POST"}<br>schema: {"href": "https://dev-725178.oktapreview.com/api/v1/meta/schemas/user/osc66lckcvDyVcGzS0h7"}<br>resetPassword: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/lifecycle/reset_password", "method": "POST"}<br>forgotPassword: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/credentials/forgot_password", "method": "POST"}<br>expirePassword: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/lifecycle/expire_password", "method": "POST"}<br>changeRecoveryQuestion: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/credentials/change_recovery_question", "method": "POST"}<br>self: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7"}<br>type: {"href": "https://dev-725178.oktapreview.com/api/v1/meta/types/user/oty66lckcvDyVcGzS0h7"}<br>changePassword: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/credentials/change_password", "method": "POST"}<br>deactivate: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00uq8zbdd4h6sZOsa0h7/lifecycle/deactivate", "method": "POST"} |


### okta-create-user
***
Creates a new user with an option of setting password, recovery question and answer.The new user will immediately be able to login after activation with the assigned password. This flow is common when developing a custom user registration experience.
##### Base Command

`okta-create-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstName | First name of the user(givenName) | Required | 
| lastName | Family name of the user (familyName) | Required | 
| email | Primary Email address of the user | Required | 
| login | Unique identifier for the user (username) | Required | 
| secondEmail | Secondary email address of user. Usually for account recovery. | Optional | 
| middleName | Middle name(s) of the user | Optional | 
| honorificPrefix | Honorific prefix(es) of the user, or title in most western languages. Supports multiple input. | Optional | 
| honificSuffix | Honorific suffix(es) of the user. Supports multiple inputs. | Optional | 
| title | User's title. for example, Vice President. | Optional | 
| displayName | Name of the user, suitable for display to end users. | Optional | 
| nickName | Casual way to address the user | Optional | 
| profileUrl | Url of the user online profile. For example, a web page. | Optional | 
| primaryPhone | Primary phone number of user. | Optional | 
| mobilePhone | Mobile phone number of user. | Optional | 
| streetAddress | Full street address component of user's address. | Optional | 
| city | City or locality component of user's address (locality). | Optional | 
| state | State or region component of user's address (region). | Optional | 
| zipCode | Zipcode or postal code component of user's address (postalCode) | Optional | 
| countryCode | Country name component of user's address (country). | Optional | 
| postalAddress | Mailing address component of user's address | Optional | 
| preferredLanguage | User's preferred written or spoken languages | Optional | 
| locale | User's default location for purposes of localizing items such as currency, date time frmat, numerical represetations, etc. | Optional | 
| timezone | User time zone | Optional | 
| userType | Used to identify the organization to user relationship such as "Employee" or "Contractor". | Optional | 
| employeeNumber | Organization or ompany assigned unique identifier for the user. | Optional | 
| costCenter | Name of a cost center assigned to. | Optional | 
| organization | Name of user's organiztion. | Optional | 
| division | Name of user's division. | Optional | 
| department | Name of user's department. | Optional | 
| managerId | ID of a user's manager. | Optional | 
| manager | Display name of the user's manager. | Optional | 
| password | Password for new user. | Optional | 
| passwordQuestion | Password question for new user | Optional | 
| passwordAnswer | Password answer for question supplied. | Optional | 
| providerType | OKTA, ACTIVE_DIRECTORY, LDAP, FEDERATION, SOCIAL | Optional | 
| providerName | Name of provider. | Optional | 
| groupIds | Ids of groups that user will be immediately added to at time of creation (Do Not include default group). | Optional | 
| activate | Activates lifecycle operation when creating the user. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Created okta account ID. | 
| Account.Email | String | Created okt account Email. | 
| Account.Username | String | Created okta account username. | 
| Account.DisplayName | String | Created okta account display name | 
| Account.Type | String | Type of created account - Okta. | 
| Account.Status | String | Okta account current status | 
| Account.Created | Date | Timestamp for when the user was created | 
| Account.Activated | Date | Timestamp for when the user was activated | 
| Account.StatusChanged | Date | Timestamp for when the user's status was changed | 
| Account.PasswordChanged | Date | Timestamp for when the users's password was last changed | 


##### Command Example
```!okta-create-user email=testForDocs@test.com firstName=test lastName=that login=testForDocs@test.com password=Pa55word! passwordQuestion="whats is your favourite integration" passwordAnswer="Okta of course"```

##### Context Example
```
{
    "Account": {
        "Activated": null,
        "Created": "2020-03-11T13:29:13.000Z",
        "DisplayName": "test that",
        "Email": "testForDocs@test.com",
        "ID": "00uq8zbdd4h6sZOsa0h7",
        "PasswordChanged": "2020-03-11T13:29:13.000Z",
        "Status": "STAGED",
        "StatusChanged": null,
        "Type": "Okta",
        "Username": "testForDocs@test.com"
    }
}
```

##### Human Readable Output
### Okta User Created: testForDocs@test.com:
|First Name|ID|Last Login|Last Name|Login|Mobile Phone|Status|
|---|---|---|---|---|---|---|
| test | 00uq8zbdd4h6sZOsa0h7 |  | that | testForDocs@test.com |  | STAGED |


### okta-update-user
***
Update user with a given login, all fields are optional, fields which are not set will not be overridden.
##### Base Command

`okta-update-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstName | First name of the user (given name). | Optional | 
| lastName | Family name of the user. | Optional | 
| email | Primary Email address of user. | Optional | 
| username | Unique identifier for the user (login). | Required | 
| secondEmail | Secondary email address of user - typically used for account recovery. | Optional | 
| middleName | Midddle name(s) of the user | Optional | 
| honorificPrefix | Honorific Prefix(es) of the user, or title in most western languages | Optional | 
| honorificSuffix | Honorific suffix(es) of the user | Optional | 
| title | User's title. For example, Vice President | Optional | 
| displayName | Name if the user suitable for display to end-users | Optional | 
| nickName | Casual way to address the user in real life | Optional | 
| profileUrl | Url of user's online profile. (e.g.- a web page) | Optional | 
| primaryPhone | Primary phone number of user. | Optional | 
| mobilePhone | Mobile phone number of user. | Optional | 
| streetAddress | Full street address component of user's address. | Optional | 
| city | City or locality component of user's address (loclity) | Optional | 
| state | State or region component of user's address (region) | Optional | 
| zipCode | Zipcode or postal code component of user's address (postalCode) | Optional | 
| countryCode | Country name component of user's address (country) | Optional | 
| postalSddress | Mailing address component of user's address | Optional | 
| preferredLanguage | User's preferred written or spoken languages. | Optional | 
| locale | User's default location for purposes of localizing items such as currncy, date time format, numerical representations. etc. | Optional | 
| timezone | User time zone. | Optional | 
| userType | Used to identify the organization to user relationship such as "Employee" or "Contractor" | Optional | 
| employeeNumber | Organization or company assigned unique identifier for the user. | Optional | 
| costCenter | Name of a cost center assigned to. | Optional | 
| organization | Name of user's organization | Optional | 
| division | Name of user's division | Optional | 
| department | Name of user's department | Optional | 
| managerId | ID of user's manager | Optional | 
| manager | Display name of user's manager | Optional | 
| password | New Password for the specified user | Optional | 
| passwordQuestion | Password question for the specified user | Optional | 
| passwordAnswer | Password answer for the question supplied. | Optional | 
| providerType | OKTA, ACTIVE_DIRECTORY, LDAP, FEDERATION, SOCIAL | Optional | 
| providerName | Name of provider | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-update-user username=testForDocs@test.com firstName="First Name Updated"```

##### Context Example
```
{}
```

##### Human Readable Output
### Okta user: testForDocs@test.com Updated:
|email|firstName|lastName|login|mobilePhone|secondEmail|
|---|---|---|---|---|---|
| testForDocs@test.com | First Name Updated | that | testForDocs@test.com |  |  |


### okta-get-group-members
***
Enumerates all users that are members of  a group.
##### Base Command

`okta-get-group-members`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | Id of the group | Optional | 
| limit | Specifies the number of user results | Optional | 
| verbose | Print all details of user | Optional | 
| groupName | Name of the group | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | String | Okta account ID | 
| Account.Email | String | Okta account email | 
| Account.Username | String | Okta account username | 
| Account.DisplayName | String | Okta account display name | 
| Account.Type | String | Account type - Okta | 
| Account.Status | String | Okta account current status | 
| Account.Created | Date | Timestamp for when the user was created | 
| Account.Activated | Date | Timestamp for when the user was activated | 
| Account.StatusChanged | Date | Timestamp for when the user's status was changed | 
| Account.PasswordChanged | Date | Timestamp for when the users's password was last changed | 


##### Command Example
```!okta-get-group-members groupName=Demisto limit=1 verbose=true```

##### Context Example
```
{
    "Account": {
        "Created": "2016-04-12T15:01:52.000Z",
        "DisplayName": "Doron Sharon",
        "Email": "dorsha@demisto.com",
        "ID": "00u66lcg7lpjidYi0h7",
        "PasswordChanged": "2020-02-24T11:40:08.000Z",
        "Status": "ACTIVE",
        "StatusChanged": "2016-04-12T15:05:06.000Z",
        "Type": "Okta",
        "Username": "dorsha@demisto.com"
    }
}
```

##### Human Readable Output
### Users for group: Demisto:
 ### User:dorsha@demisto.com
### Profile
|Email|First Name|Last Name|Login|Mobile Phone|Second Email|
|---|---|---|---|---|---|
| dorsha@demisto.com | Doron | Sharon | dorsha@demisto.com |  |  |

 ### Additional Data
|Activated|Created|Credentials|ID|Last Login|Last Updated|Password Changed|Status|Status Changed|Type|_links|
|---|---|---|---|---|---|---|---|---|---|---|
|  | 2016-04-12T15:01:52.000Z | password: {}<br>recovery_question: {"question": "born city"}<br>provider: {"type": "OKTA", "name": "OKTA"} | 00u66lckd7lpjidYi0h7 | 2020-03-11T11:35:52.000Z | 2020-02-24T11:42:22.000Z | 2020-02-24T11:40:08.000Z | ACTIVE |  | id: oty66lckcvDyVcGzS0h7 | self: {"href": "https://dev-725178.oktapreview.com/api/v1/users/00u66lckd7lpjidYi0h7"} |


### okta-list-groups
***
Lists groups in your organization. A subset of groups can be returned that match a supported filter expression or query.
##### Base Command

`okta-list-groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Searches the name property of groups for matching value | Optional | 
| filter | Useful for performing structured queries where constraints on group attribute values can be explicitly targeted. <br>The following expressions are supported(among others) for groups with the filter query parameter: <br>type eq "OKTA_GROUP" - Groups that have a type of OKTA_GROUP; lastUpdated lt "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with profile last updated before a specific timestamp; lastMembershipUpdated eq "yyyy-MM-dd''T''HH:mm:ss.SSSZ" - Groups with memberships last updated at a specific timestamp; id eq "00g1emaKYZTWRYYRRTSK" - Group with a specified id. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering | Optional | 
| limit | Sets the number of results returned in the response (default: 200) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Group.ID | String | Unique key for the group | 
| Okta.Group.Created | Date | Timestamp for when the group was created | 
| Okta.Group.ObjectClass | Unknown | The group's profile | 
| Okta.Group.LastUpdated | Date | Timestamp for when the group's profile was last updated | 
| Okta.Group.LastMembershipUpdated | Date | Timestamp for when the group's membership were last updated | 
| Okta.Group.Type | String | Determines how a group's profile and membership are managed - OKTA_GROUP, APP_GROUP, BUILT_IN | 
| Okta.Group.Name | String | Name of the group | 
| Okta.Group.Description | String | Description of the group | 


##### Command Example
```!okta-list-groups filter=`type eq "OKTA_GROUP" and lastUpdated lt "2019-04-30T00:00:00.000Z" and lastMembershipUpdated gt "2019-04-30T00:00:00.000Z"` query=demisto```

##### Context Example
```
{
    "Okta": {
        "Group": {
            "Created": "2018-01-19T02:02:06.000Z",
            "ID": "00gdouhq3zEaf7c50h7",
            "LastMembershipUpdated": "2020-03-11T13:29:19.000Z",
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
### Groups
|Created|Description|ID|LastMembershipUpdated|LastUpdated|Name|ObjectClass|Type|
|---|---|---|---|---|---|---|---|
| 2018-01-19T02:02:06.000Z |  | 00gdougcq3zEaf7c50h7 | 2020-03-11T13:29:19.000Z | 2018-01-19T02:02:06.000Z | Demisto | okta:user_group | OKTA_GROUP |


### okta-get-failed-logins
***
Returnes Failed login events.
##### Base Command

`okta-get-failed-logins`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filers the lower time bound of the log events in the Internet Date/Time Format profile of ISO 8601. An example: 2017-05-03T16:22:18Z | Optional | 
| until | Filers the upper time bound of the log events in the Internet Date/Time Format profile of ISO 8601. An example: 2017-05-03T16:22:18Z | Optional | 
| sortOrder | The order of the returned events, default is ASCENDING | Optional | 
| limit | Sets the number of results returned in the respons. Default is 100. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternative ID of actor | 
| Okta.Logs.Events.actor.displayName | String | Display name of actor | 
| Okta.Logs.Events.actor.id | String | ID of actor | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The Operation system on which the client runs. For ex. Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the browser typr, if relevant. For ex: Chrome. | 
| Okta.Logs.Events.client.device | String | Type of device that client operated from. e.g: Computer | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address in which the client made its request. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available (e.g. Seattle, San Francisco) | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state/province encompassing in the area containing the geolocation coordinates (e.g Montana, Incheon) | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates (e.g France, Uganda) | 
| Okta.Logs.Events.displayMessage | String | The display message for an event | 
| Okta.Logs.Events.eventType | String | Type of event that was published | 
| Okta.Logs.Events.outcome.result | String | Result of the action: SUCCESS, FAILURE, SKIPPED, UNKNOWN | 
| Okta.Logs.Events.outcome.reason | String | Reason for the rsult, for example- INVALID_CREDENTIALS | 
| Okta.Logs.Events.published | String | Timestamp when event was published | 
| Okta.Logs.Events.severity | String | Indicates how severe the event is: DEBUG, INFO, WARN, ERROR | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sources to | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to sent the event's request | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request isfrom a known proxy | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available - e.g Seeatle, San Francisco | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state/province encompassing the area containing the geolocation coordinates - e.g Montana, Incheon | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates - e.g France, Uganda | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source | 
| Okta.Logs.Events.target.id | String | ID of a target | 
| Okta.Logs.Events.target.type | String | Type of a target | 
| Okta.Logs.Events.target.alternateId | String | Alternative ID of a target | 
| Okta.Logs.Events.target.displayName | String | Display Name of a target | 


##### Command Example
```!okta-get-failed-logins since="2019-04-30T00:00:00.000Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "gfilippov@paloaltonetworks.com",
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
### Failed Login Events
|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
|---|---|---|---|---|---|---|---|---|---|
| unknown (User) | gfilippov@paloaltonetworks.com | 127.0.0.1 | CHROME on Windows 10 Computer | User login to Okta | FAILURE: VERIFICATION_ERROR | INFO | 127.0.0.1 | - | 09/19/2019, 08:35:38 |


### okta-get-logs
***
Get logs by providing optional filter.
##### Base Command

`okta-get-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Useful for performing structured queries where constraints on LogEvent attribute values can be explicitly targeted.  <br>The following expressions are supported for events with the filter query parameter: eventType eq " :eventType" <br>-Events that have a specific action; eventType target.id eq ":id" <br>- Events published with a specific target id; actor.id eq ":id"<br>- Events published with a specific actor id. For more information about filtering, visit https://developer.okta.com/docs/api/getting_started/design_principles#filtering | Optional | 
| query | The query parameter can be used to perform keyword matching against a LogEvents object’s attribute values. In order to satisfy the constraint, all supplied keywords must be matched exactly. Note that matching is case-insensitive.  The following are some examples of common keyword filtering: <br>Events that mention a specific city: query=San Francisco; <br>Events that mention a specific url: query=interestingURI.com; <br>Events that mention a specific person: query=firstName lastName. | Optional | 
| since | Filters the lower time bound of the log events in the Internet Date/Time Format profile of ISO 8601. An example: 2017-05-03T16:22:18Z | Optional | 
| until | Filters the upper  time bound of the log events in the Internet Date/Time Format profile of ISO 8601. An example: 2017-05-03T16:22:18Z | Optional | 
| sortOrder | The order of the returned events, default is ASCENDING | Optional | 
| limit | Sets the number of results returned in the response. Default is 100. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternattive ID of actor | 
| Okta.Logs.Events.actor.displayName | String | Display name of actor | 
| Okta.Logs.Events.actor.id | String | ID of actor | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operation system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome | 
| Okta.Logs.Events.client.device | String | Type of device that client operated from. e.g: Computer | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address in which the client made its request from. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available (e.g. Seattle, San Francisco) | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state/province encompassing in the area containing the geolocation coordinates (e.g Montana, Incheon) | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates (e.g France, Uganda) | 
| Okta.Logs.Events.displayMessage | String | The display message for an event | 
| Okta.Logs.Events.eventType | String | Type of event that was published | 
| Okta.Logs.Events.outcome.result | String | Result of the action: SUCCESS, FAILURE, SKIPPED, UNKNOWN | 
| Okta.Logs.Events.outcome.reason | String | Reason for the result, for example INVALID_CREDENTIALS | 
| Okta.Logs.Events.published | String | Timestamp when event was published | 
| Okta.Logs.Events.severity | String | Indicates how severe the event is: DEBUG, INFO, WARN, ERROR | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sources to | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to sent the event's request | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request isfrom a known proxy | 
| Okta.Logs.Events.request.ipChain.IP | String | IP Address | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available - e.g Seeatle, San Francisco | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state/province encompassing the area containing the geolocation coordinates - e.g Montana, Incheon | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates - e.g France, Uganda | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source | 
| Okta.Logs.Events.target.id | String | ID of a target | 
| Okta.Logs.Events.target.type | String | Type of a target | 
| Okta.Logs.Events.target.alternateId | String | Alternative Id of a target | 
| Okta.Logs.Events.target.displayName | String | Display name of a target | 


##### Command Example
```!okta-get-logs filter=`actor.id eq "00u66lckd7lpjidYi0h7"` query=Boardman since="2020-03-03T20:23:17.573Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "dorsha@demisto.com",
                    "detailEntry": null,
                    "displayName": "Doron Sharon",
                    "id": "00u66lckd7lpjidYi0h7",
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
### Okta Events
|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
|---|---|---|---|---|---|---|---|---|---|
| Doron Sharon (User) | dorsha@demisto.com | 127.0.0.1 | Unknown browser on Unknown OS Unknown device | Remove user from group membership | SUCCESS | INFO | 127.0.0.1 | test this (User)<br>test1 (UserGroup)<br> | 03/03/2020, 20:23:17 |


### okta-get-group-assignments
***
Get events for when a user added to a group
##### Base Command

`okta-get-group-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log event in the Internet Date\Time format profile of ISO 8601. e.g. 2020-02-14T16:00:18Z | Optional | 
| until | Filters the upper time bound of the log event in the Internet Date\Time format profile of ISO 8601. e.g. 2020-02-14T16:00:18Z | Optional | 
| sortOrder | The order of the returned events, default is ASCENDING | Optional | 
| limit | Sets the number of results returned in the response. Default is 100 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternattive ID of actor | 
| Okta.Logs.Events.actor.displayName | String | Display name of actor | 
| Okta.Logs.Event.actor.id | String | ID of actor | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operation system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome | 
| Okta.Logs.Events.client.device | String | Type of device that client operated from. e.g: Computer | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address in which the client made its request from. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available (e.g. Seattle, San Francisco) | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state/province encompassing in the area containing the geolocation coordinates (e.g Montana, Incheon) | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates (e.g France, Uganda) | 
| Okta.Logs.Events.displayMessage | String | The display message for an event | 
| Okta.Logs.Events.eventType | String | Type of event that was published | 
| Okta.Logs.Events.outcome.result | String | Result of the action: SUCCESS, FAILURE, SKIPPED, UNKNOWN | 
| Okta.Logs.Events.outcome.reason | Unknown | Reason for the result, for example INVALID_CREDENTIALS | 
| Okta.Logs.Events.published | String | Timestamp when event was published | 
| Okta.Logs.Events.severity | String | Indicates how severe the event is: DEBUG, INFO, WARN, ERROR | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sources to | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to sent the event's request | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request isfrom a known proxy | 
| Okta.Logs.Events.request.ipChain.IP | String | IP Address | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available - e.g Seeatle, San Francisco | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state/province encompassing the area containing the geolocation coordinates - e.g Montana, Incheon | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates - e.g France, Uganda | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source | 
| Okta.Logs.Events.target.id | String | ID of a target | 
| Okta.Logs.Events.target.type | String | Type of a target | 
| Okta.Logs.Events.target.alternateId | String | Alternative Id of a target | 
| Okta.Logs.Events.target.displayName | String | Display name of a target | 


##### Command Example
```!okta-get-group-assignments since="2019-04-30T00:00:00.000Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "dorsha@demisto.com",
                    "detailEntry": null,
                    "displayName": "Doron Sharon",
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
### Group Assignment Events
|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
|---|---|---|---|---|---|---|---|---|---|
| Doron Sharon (User) | dorsha@demisto.com | 127.0.0.1 | Unknown browser on Unknown OS Unknown device | Add user to group membership | SUCCESS | INFO | 127.0.0.1 | test this (User)<br>test1 (UserGroup)<br> | 09/12/2019, 17:57:37 |


### okta-get-application-assignments
***
Returnes events for when a user was assigned to an application.
##### Base Command

`okta-get-application-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log event in the Internet Date\Time format profile of ISO 8601. e.g. 2020-02-14T16:00:18Z | Optional | 
| until | Filters the upper time bound of the log event in the Internet Date\Time format profile of ISO 8601. e.g. 2020-02-14T16:00:18Z | Optional | 
| sortOrder | The order of the returned events, default is ASCENDING | Optional | 
| limit | Sets the number of results returned in the response. Default is 100 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternattive ID of actor | 
| Okta.Logs.Events.actor.displayName | String | Display name of actor | 
| Okta.Logs.Event.actor.id | String | ID of actor | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operation system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome | 
| Okta.Logs.Events.client.device | String | Type of device that client operated from. e.g: Computer | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address in which the client made its request from. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available (e.g. Seattle, San Francisco) | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state/province encompassing in the area containing the geolocation coordinates (e.g Montana, Incheon) | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates (e.g France, Uganda) | 
| Okta.Logs.Events.displayMessage | String | The display message for an event | 
| Okta.Logs.Events.eventType | String | Type of event that was published | 
| Okta.Logs.Events.outcome.result | String | Result of the action: SUCCESS, FAILURE, SKIPPED, UNKNOWN | 
| Okta.Logs.Events.outcome.reason | String | Reason for the result, for example INVALID_CREDENTIALS | 
| Okta.Logs.Events.published | String | Timestamp when event was published | 
| Okta.Logs.Events.severity | String | Indicates how severe the event is: DEBUG, INFO, WARN, ERROR | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sources to | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to sent the event's request | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request isfrom a known proxy | 
| Okta.Logs.Events.request.ipChain.IP | String | IP address | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available - e.g Seeatle, San Francisco | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state/province encompassing the area containing the geolocation coordinates - e.g Montana, Incheon | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates - e.g France, Uganda | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source | 
| Okta.Logs.Events.target.id | String | ID of a target | 
| Okta.Logs.Events.target.type | String | Type of a target | 
| Okta.Logs.Events.target.alternateId | String | Alternative Id of a target | 
| Okta.Logs.Events.target.displayName | String | Display name of a target | 


##### Command Example
```!okta-get-application-assignments since="2019-04-30T00:00:00.000Z" until="2020-02-30T00:00:00.000Z" sortOrder=DESCENDING limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "dorsha@demisto.com",
                    "detailEntry": null,
                    "displayName": "Doron Sharon",
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
### Application Assignment Events
|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
|---|---|---|---|---|---|---|---|---|---|
| Doron Sharon (User) | dorsha@demisto.com | 127.0.0.1 | Unknown browser on Unknown OS Unknown device | Add user to application membership | SUCCESS | INFO | 127.0.0.1 | Test 1 that (AppUser)<br>ShrikSAML (AppInstance)<br>Test 1 that (User)<br> | 02/27/2020, 17:55:12 |


### okta-get-application-authentication
***
Returns logs using specified filters.
##### Base Command

`okta-get-application-authentication`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters the lower time bound of the log event in the Internet Date\Time format profile of ISO 8601. e.g. 2020-02-14T16:00:18Z | Optional | 
| until | Filters the upper time bound of the log event in the Internet Date\Time format profile of ISO 8601. e.g. 2020-02-14T16:00:18Z | Optional | 
| sortOrder | The order of the returned events, default is ASCENDING | Optional | 
| limit | Sets the number of results returned in the response. Default is 100 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Okta.Logs.Events.actor.alternateId | String | Alternattive ID of actor | 
| Okta.Logs.Events.actor.displayName | String | Display name of actor | 
| Okta.Logs.Events.actor.id | String | ID of actor | 
| Okta.Logs.Events.client.userAgent.rawUserAgent | String | A raw string representation of user agent, formatted according to section 5.5.3 of HTTP/1.1 Semantics and Content. Both the browser and the OS fields can be derived from this field. | 
| Okta.Logs.Events.client.userAgent.os | String | The operation system on which the client runs. For example, Microsoft Windows 10. | 
| Okta.Logs.Events.client.userAgent.browser | String | Identifies the type of web browser, if relevant. For example, Chrome | 
| Okta.Logs.Events.client.device | String | Type of device that client operated from. e.g: Computer | 
| Okta.Logs.Events.client.id | String | For OAuth requests, the ID of the OAuth client making the request. For SSWS token requests, the ID of the agent making the request. | 
| Okta.Logs.Events.client.ipAddress | String | IP address in which the client made its request from. | 
| Okta.Logs.Events.client.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available (e.g. Seattle, San Francisco) | 
| Okta.Logs.Events.client.geographicalContext.state | String | Full name of the state/province encompassing in the area containing the geolocation coordinates (e.g Montana, Incheon) | 
| Okta.Logs.Events.client.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates (e.g France, Uganda) | 
| Okta.Logs.Events.displayMessage | String | The display message for an event | 
| Okta.Logs.Events.eventType | String | Type of event that was published | 
| Okta.Logs.Events.outcome.result | String | Result of the action: SUCCESS, FAILURE, SKIPPED, UNKNOWN | 
| Okta.Logs.Events.outcome.reason | String | Reason for the result, for example INVALID_CREDENTIALS | 
| Okta.Logs.Events.published | String | Timestamp when event was published | 
| Okta.Logs.Events.severity | String | Indicates how severe the event is: DEBUG, INFO, WARN, ERROR | 
| Okta.Logs.Events.securityContext.asNumber | Number | Autonomous system number associated with the autonomous system that the event request was sources to | 
| Okta.Logs.Events.securityContext.asOrg | String | Organization associated with the autonomous system that the event request was sourced to. | 
| Okta.Logs.Events.securityContext.isp | String | Internet service provider used to sent the event's request | 
| Okta.Logs.Events.securityContext.domain | String | The domain name associated with the IP address of the inbound event request | 
| Okta.Logs.Events.securityContext.isProxy | String | Specifies whether an event's request isfrom a known proxy | 
| Okta.Logs.Events.request.ipChain.IP | String | IP Address | 
| Okta.Logs.Events.request.ipChain.geographicalContext.city | String | The city encompassing the area containing the geolocation coordinates, if available - e.g Seeatle, San Francisco | 
| Okta.Logs.Events.request.ipChain.geographicalContext.state | String | Full name of the state/province encompassing the area containing the geolocation coordinates - e.g Montana, Incheon | 
| Okta.Logs.Events.request.ipChain.geographicalContext.country | String | Full name of the country encompassing the area containing the geolocation coordinates - e.g France, Uganda | 
| Okta.Logs.Events.request.ipChain.source | String | Details regarding the source | 
| Okta.Logs.Events.target.id | String | ID of a target | 
| Okta.Logs.Events.target.type | String | Type of a target | 
| Okta.Logs.Events.target.alternateId | String | Alternative Id of a target | 
| Okta.Logs.Events.target.displayName | String | Display name of a target | 


##### Command Example
```!okta-get-application-authentication since="2019-04-30T00:00:00.000Z" until="2020-02-30T00:00:00.000Z" limit=1```

##### Context Example
```
{
    "Okta": {
        "Logs": {
            "Events": {
                "actor": {
                    "alternateId": "dorsha@demisto.com",
                    "detailEntry": null,
                    "displayName": "Doron Sharon",
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
                        "alternateId": "dorsha@demisto.com",
                        "detailEntry": null,
                        "displayName": "Doron Sharon",
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
### Application Authentication Events
|Actor|ActorAlternaneId|ChainIP|Client|EventInfo|EventOutcome|EventSeverity|RequestIP|Targets|Time|
|---|---|---|---|---|---|---|---|---|---|
| Doron Sharon (User) | dorsha@demisto.com | 127.0.0.1 | CHROME on Mac OS X Computer | User single sign on to app | SUCCESS | INFO | 31.154.166.148 | benzi_master (AppInstance)<br>Doron Sharon (AppUser)<br> | 09/18/2019, 14:29:19 |


### okta-delete-user
***
Delete specified user.
##### Base Command

`okta-delete-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | Okta User ID | Optional | 
| username | Username of the user | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-delete-user username=testForDocs@test.com```

##### Human Readable Output
User: testForDocs@test.com was Deleted successfully

### okta-clear-user-sessions
***
Removes all active identity provider sessions. This forces the user to authenticate on the next operation. Optionally revokes OpenID Connect and OAuth refresh and access tokens issued to the user.
For more information and examples:
https://developer.okta.com/docs/reference/api/users/#user-sessions.
##### Base Command

`okta-clear-user-sessions`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userId | Okta User ID | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!okta-clear-user-sessions userId=00ui5brmwtJpMdoZZ0h7```

##### Human Readable Output
User session was cleared for: 00ui5brmwtJpMdoZZ0h7

## Additional Information

## Known Limitations
