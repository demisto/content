The Entra ID Users integration (formerly Azure Active Directory Users) is a Unified gateway to security insights - all from a unified Microsoft Graph User API.

## Authentication

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).  

Required Permissions:

- Directory.Read.All - Delegated
- User.ReadWrite.All - Application
- User.Read - Delegated

## Authorize Cortex XSOAR for Entra ID Users (Self deployed Azure App)

There are two different authentication methods for a self-deployed configuration:

- [Client Credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#client-credentials-flow)
- [Authorization Code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authorization-code-flow)

We recommend using the Client Credentials flow.
In order to use the msgraph-user-change-password command, you must configure with the Authorization Code flow.

Note: When using the Authorization Code flow, make sure the user you authenticate with has the correct roles in Azure AD in order to use the command.

## Configure Entra ID Users in Cortex

| **Parameter**                                                          | **Description**                                                                                                                                                                                                                                                                                                                                        | **Required** |
|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Azure Cloud                        | See option table below.
| Host URL (e.g., https://graph.microsoft.com)                           |                                                                                                                                                                                                                                                                                                                                                        | True         |
| ID / client ID                                                         |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Token / Tenant ID                                                      |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Key / Client Secret                                                    |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Certificate Thumbprint                                                 | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app.                                                                                                                                                                                                                                               | False        |
| Private Key                                                            | Used for certificate authentication. The private key of the registered certificate.                                                                                                                                                                                                                                                                    | False        |
| Use a self-deployed Azure application                                  |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Application redirect URI (for Self Deployed - Authorization Code Flow) |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Authorization code (for Self Deployed - Authorization Code Flow)       |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Use Azure Managed Identities                                           | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False        |
| Azure Managed Identities Client ID                                     | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM.                                                                                                                                                                                                                                         | False        |
| Trust any certificate (not secure)                                     |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Use system proxy settings                                              |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Suppress Errors for Non Found Users                                    |                                                                                                                                                                                                                                                                                                                                                        | False        |
| Allow secret generators commands execution                                     |      Checking this box will allow running commands that generate and print secrets. Make sure to add restrictions to the related commands. For more information please refer to the following guide - MFA guide                                                                                                                                                                                                                                                                                                                                                  | False        |

Azure cloud options

| Azure Cloud | Description                                                         |
|-------------|---------------------------------------------------------------------|
| Worldwide   | The publicly accessible Azure Cloud                                 |
| US GCC      | Azure cloud for the USA Government Cloud Community (GCC)            |
| US GCC-High | Azure cloud for the USA Government Cloud Community High (GCC-High)  |
| DoD         | Azure cloud for the USA Department of Defense (DoD)                 |
| Germany     | Azure cloud for the German Government                               |
| China       | Azure cloud for the Chinese Government                              |
| Custom      | Custom endpoint configuration to the Azure cloud. See note below.   |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-user-account-disable

***
Disables a user from all Office 365 applications, and prevents sign in. Note: This command disables the user
but does not terminate an existing session. Supported only in a self deployed app flow with the
Permission: Directory.AccessAsUser.All(Delegated).

#### Base Command

`msgraph-user-account-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-unblock

***
Unblock a user.

#### Base Command

`msgraph-user-unblock`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Command example

```!msgraph-user-unblock user=123456-abcd-7890-erty-987qwe987```

#### Human Readable Output

>"123456-abcd-7890-erty-987qwe987" unblocked. It might take several minutes for the changes to take affect across all applications.

### msgraph-user-update

***
Updates the properties of a user object.
**Permissions**: - User.ReadWrite (Delegated & Application)
**Permission For unblocking an admin/privileged user**: User.EnableDisableAccount.All (Application).

#### Base Command

`msgraph-user-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName to update properties for. | Required |
| updated_fields | User fields to update (in a key=value format. Example: displayName=John. | Required |
| updated_fields_delimiter | Delimiter to use for passing multiple fields to the 'updated_fields' argument. Example using ',' as a delimiter: displayName=John,givenName=John,surname=Doe. Default is ,. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.ID | String | User's ID. |
| MSGraphUser.DisplayName | String | User's display name. |
| MSGraphUser.GivenName | String | User's given name. |
| MSGraphUser.BusinessPhones | String | User's business phone numbers. |
| MSGraphUser.JobTitle | String | User's job title. |
| MSGraphUser.Mail | String | User's mail address. |
| MSGraphUser.MobilePhone | String | User's mobile phone number. |
| MSGraphUser.OfficeLocation | String | User's office location. |
| MSGraphUser.PreferredLanguage | String | User's preferred language. |
| MSGraphUser.Surname | String | User's surname. |
| MSGraphUser.UserPrincipalName | String | User's principal name. |

#### Command example

```!msgraph-user-update user=123456-abcd-7890-erty-987qwe987 updated_fields="MobilePhone=050123456"```

#### Context Example

```json
{
    "Account": {
        "DisplayName": "Test 1",
        "Email": {
            "Address": null
        },
        "ID": "123456-abcd-7890-erty-987qwe987",
        "JobTitle": null,
        "Office": null,
        "TelephoneNumber": "050123456",
        "Type": "Azure AD",
        "Username": "test1@demistodev.onmicrosoft.com"
    },
    "MSGraphUser": {
        "BusinessPhones": [],
        "DisplayName": "Test 1",
        "GivenName": "Test",
        "ID": "123456-abcd-7890-erty-987qwe987",
        "JobTitle": null,
        "Mail": null,
        "MobilePhone": "050123456",
        "OfficeLocation": null,
        "PreferredLanguage": null,
        "Surname": "Test",
        "UserPrincipalName": "test1@demistodev.onmicrosoft.com"
    }
}
```

#### Human Readable Output

>### 123456-abcd-7890-erty-987qwe987 data
>
>| Display Name |Given Name|ID|Mobile Phone|Surname|User Principal Name|
--------------|---|---|---|---|---|---|
>| Test 1 | Test | 123456-abcd-7890-erty-987qwe987 | 050123456 | Test | test1@demistodev.onmicrosoft.com |

### msgraph-user-delete

***
Deletes an existing user.
**Permissions**: Directory.AccessAsUser.All (Delegated), User.ReadWrite.All (Application)

#### Base Command

`msgraph-user-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName to delete. | Required |

### msgraph-user-create

***
Creates a new user.
**Permissions**: User.ReadWrite.All (Delegated & Application)

#### Base Command

`msgraph-user-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_enabled | true if the account is enabled; otherwise, false. Possible values are: true, false. Default is true. | Optional |
| display_name | The name to display in the address book. | Required |
| on_premises_immutable_id | Only needs to be specified when creating a new user account if you are using a federated domain for the user's userPrincipalName (UPN) property. | Optional |
| mail_nickname | The mail alias for the user. | Required |
| password | The password profile for the user. | Required |
| user_principal_name |  The user principal name, for example: foo@test.com. . | Required |
| other_properties |  Optional properties for the user, for example: "displayName=name,mobilePhone=phone-num" . | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.ID | String | User's ID. |
| MSGraphUser.DisplayName | String | User's display name. |
| MSGraphUser.GivenName | String | User's given name. |
| MSGraphUser.BusinessPhones | String | User's business phone numbers. |
| MSGraphUser.JobTitle | String | User's job title. |
| MSGraphUser.Mail | String | User's mail address. |
| MSGraphUser.MobilePhone | String | User's mobile phone number. |
| MSGraphUser.OfficeLocation | String | User's office location. |
| MSGraphUser.PreferredLanguage | String | User's preferred language. |
| MSGraphUser.Surname | String | User's surname. |
| MSGraphUser.UserPrincipalName | String | User's principal name. |
| Account.ID | String | User’s ID. |
| Account.DisplayName | String | User’s display name. |
| Account.Username | String | User’s principal name. |
| Account.JobTitle | String | User’s job title. |
| Account.Email.Address | String | User’s mail address. |
| Account.TelephoneNumber | String | User’s mobile phone number. |
| Account.Office | String | User’s office location. |
| Account.Type | String | The account entity type. |

### msgraph-user-get

***
Retrieves the properties and relationships of a user object. For more information, visit: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http.
**Permissions**: User.Read (Delegated), User.Read.All (Application).

#### Base Command

`msgraph-user-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| properties | A CSV list of properties by which to filter the results, for example: "displayName,jobTitle,mobilePhone". For the list of possible properties and the relevant permissions, if needed, visit: https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.ID | String | User's ID. |
| MSGraphUser.DisplayName | String | User's display name. |
| MSGraphUser.GivenName | String | User's given name. |
| MSGraphUser.BusinessPhones | String | User's business phone numbers. |
| MSGraphUser.JobTitle | String | User's job title. |
| MSGraphUser.Mail | String | User's mail address. |
| MSGraphUser.MobilePhone | String | User's mobile phone number. |
| MSGraphUser.OfficeLocation | String | User's office location. |
| MSGraphUser.PreferredLanguage | String | User's preferred language. |
| MSGraphUser.Surname | String | User's surname. |
| MSGraphUser.UserPrincipalName | String | User's principal name. |
| Account.ID | String | User’s ID. |
| Account.DisplayName | String | User’s display name. |
| Account.Username | String | User’s principal name. |
| Account.JobTitle | String | User’s job title. |
| Account.Email.Address | String | User’s mail address. |
| Account.TelephoneNumber | String | User’s mobile phone number. |
| Account.Office | String | User’s office location. |
| Account.Type | String | The account entity type. |

#### Command example

```!msgraph-user-get user=123456-abcd-7890-erty-987qwe987```

#### Context Example

```json
{
    "Account": {
        "DisplayName": "Test 1",
        "Email": {
            "Address": null
        },
        "ID": "123456-abcd-7890-erty-987qwe987",
        "JobTitle": null,
        "Office": null,
        "TelephoneNumber": "050123456",
        "Type": "Azure AD",
        "Username": "test1@demistodev.onmicrosoft.com"
    },
    "MSGraphUser": {
        "BusinessPhones": [],
        "DisplayName": "Test 1",
        "GivenName": "Test",
        "ID": "123456-abcd-7890-erty-987qwe987",
        "JobTitle": null,
        "Mail": null,
        "MobilePhone": "050123456",
        "OfficeLocation": null,
        "PreferredLanguage": null,
        "Surname": "Test",
        "UserPrincipalName": "test1@demistodev.onmicrosoft.com"
    }
}
```

#### Human Readable Output

>### 123456-abcd-7890-erty-987qwe987 data
>
>| Display Name |Given Name|ID|Mobile Phone|Surname|User Principal Name|
--------------|---|---|---|---|---|---|
>| Test 1 | Test | 123456-abcd-7890-erty-987qwe987 | 050123456 | Test | test1@demistodev.onmicrosoft.com |

### msgraph-user-list

***
Retrieves a list of user objects.
**Permissions**: User.ReadBasic.All (Delegated), User.Read.All (Application)

#### Base Command

`msgraph-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| properties | A CSV list of properties by which to filter the results, for example: "displayName,jobTitle,mobilePhone". | Optional |
| next_page | The URL for the next page in the list. | Optional |
| filter | Filter to be plugged directly into the API. For more information about the Filter syntax, see the Microsoft documentation: https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.ID | String | User's ID. |
| MSGraphUser.DisplayName | String | User's display name. |
| MSGraphUser.GivenName | String | User's given name. |
| MSGraphUser.BusinessPhones | String | User's business phone numbers. |
| MSGraphUser.JobTitle | String | User's job title. |
| MSGraphUser.Mail | String | User's mail address. |
| MSGraphUser.MobilePhone | String | User's mobile phone number. |
| MSGraphUser.OfficeLocation | String | User's office location. |
| MSGraphUser.PreferredLanguage | String | User's preferred language. |
| MSGraphUser.Surname | String | User's surname. |
| MSGraphUser.UserPrincipalName | String | User's principal name. |
| MSGraphUser.NextPage | String | A token to pass to the next list command to retrieve additional results. |
| Account.ID | String | User’s ID. |
| Account.DisplayName | String | User’s display name. |
| Account.Username | String | User’s principal name. |
| Account.JobTitle | String | User’s job title. |
| Account.Email.Address | String | User’s mail address. |
| Account.TelephoneNumber | String | User’s mobile phone number. |
| Account.Office | String | User’s office location. |
| Account.Type | String | The account entity type. |

#### Command example

```!msgraph-user-list```

#### Context Example

```json
{
    "Account": [
        {
            "DisplayName": "Test1",
            "Email": {
                "Address": "test1@demistodev.onmicrosoft.com"
            },
            "ID": "123456-abcd-7890-erty-987qwe988",
            "JobTitle": null,
            "Office": null,
            "TelephoneNumber": "050505050",
            "Type": "Azure AD",
            "Username": null
        },
        {
            "DisplayName": "Test2",
            "Email": {
                "Address": "test2@demistodev.onmicrosoft.com"
            },
            "ID": "123456-abcd-7890-erty-987qwe989",
            "JobTitle": null,
            "Office": null,
            "TelephoneNumber": null,
            "Type": "Azure AD",
            "Username": null
        },
        {
            "DisplayName": "Test3",
            "Email": {
                "Address": null
            },
            "ID": "123456-abcd-7890-erty-987qwe990",
            "JobTitle": null,
            "Office": null,
            "TelephoneNumber": null,
            "Type": "Azure AD",
            "Username": null
        }
    ],
    "MSGraphUser": [
        {
            "NextPage": "https://graph.microsoft.com/v1.0/users?$select=id%2cdisplayName%2cjobTitle%2cmobilePhone%2cmail&$count=true&$skiptoken=m~AQAnO2Q2MjljMzcwNjFjOTQ4NTE4ZjNkODBlYTZjMDc2NTVmOzswOzA7"
        },
        {
            "DisplayName": "Test 1",
            "ID": "123456-abcd-7890-erty-987qwe991",
            "JobTitle": null,
            "Mail": "test1@demistodev.onmicrosoft.com",
            "MobilePhone": "050505050"
        },
        {
            "DisplayName": "Test 2",
            "ID": "123456-abcd-7890-erty-987qwe992",
            "JobTitle": null,
            "Mail": "test2@demistodev.onmicrosoft.com",
            "MobilePhone": null
        },
        {
            "DisplayName": "Test 3",
            "ID": "123456-abcd-7890-erty-987qwe993",
            "JobTitle": null,
            "Mail": null,
            "MobilePhone": null
        }
    ]
}
```

#### Human Readable Output

>### All Graph Users
>
>To get further results, enter this to the next_page parameter:
>https:<span>//</span>graph.microsoft.com/v1.0/users?$select=id%2cdisplayName%2cjobTitle%2cmobilePhone%2cmail&$count=true&$skiptoken=m~AQAnO2Q2MjljMzcwNjFjOTQ4NTE4ZjNkODBlYTZjMDc2NTVmOzswOzA7
>
>|Display Name|ID|Job Title|Mail|Mobile Phone|
>|---|---|---|---|---|
>| Test 1 | 023096d0-595e-47b5-80dd-ea5886ab9294 |  | test1@demistodev.onmicrosoft.com | 050505050 |
>| Test 2 | 0628c545-94f6-4d07-8bc6-e6718ba1bc95 |  | test2@demistodev.onmicrosoft.com |  |
>| Test 3 | 082b3bc9-bb2d-4d12-8b1a-d84a53229696 |  |  |  |

### msgraph-direct-reports

***
Retrieves the direct reports for a user. Direct reports are the people who have that user configured as their manager.

#### Base Command

`msgraph-direct-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The User ID or userPrincipalName of the user for which to retrieve direct reports. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUserDirectReports.Manager | String | The manager's user principal name \(UPN\). |
| MSGraphUserDirectReports.Reports.@Odata.Type | String | A string value that can be used to classify user types in your directory, such as "Member" and "Guest". |
| MSGraphUserDirectReports.Reports.DisplayName | String | The name displayed in the address book for the user. This is usually the combination of the user's first name, middle initial and last name. |
| MSGraphUserDirectReports.Reports.GivenName | String | The given name \(first name\) of the user. |
| MSGraphUserDirectReports.Reports.ID | String | The user ID in Microsoft Graph User. |
| MSGraphUserDirectReports.Reports.JobTitle | String | The user's job title. |
| MSGraphUserDirectReports.Reports.Mail | String | The email address of the user. |
| MSGraphUserDirectReports.Reports.MobilePhone | String | The primary cellular telephone number for the user. |
| MSGraphUserDirectReports.Reports.OfficeLocation | String | The office location in the user's place of business. |
| MSGraphUserDirectReports.Reports.PreferredLanguage | String | The preferred language for the user. Should follow ISO 639-1 Code; for example: en-US. |
| MSGraphUserDirectReports.Reports.Surname | String | The user's surname \(family name or last name\). |
| MSGraphUserDirectReports.Reports.UserPrincipalName | String | The user principal name \(UPN\) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant’s collection of verified domains. This property is required when a user is created. The verified domains for the tenant can be accessed from the verifiedDomains property of organization. |

#### Command example

```!msgraph-direct-reports user=123456-abcd-7890-erty-987qwe987```

#### Context Example

```json
{
    "MSGraphUserDirectReports": {
        "Manager": "123456-abcd-7890-erty-987qwe987",
        "Reports": [
            {
                "@Odata.Type": "#microsoft.graph.user",
                "BusinessPhones": [],
                "DisplayName": "Test 1",
                "GivenName": "Test",
                "ID": "123456-abcd-7890-erty-987qwe987",
                "JobTitle": null,
                "Mail": null,
                "MobilePhone": "050123456",
                "OfficeLocation": null,
                "PreferredLanguage": null,
                "Surname": "Test",
                "UserPrincipalName": "test1@demistodev.onmicrosoft.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### 259d2a3c-167b-411c-b2ee-88646ce6e054 - direct reports
>
>|@Odata.Type| Display Name | Given Name |ID|Mobile Phone| Surname | User Principal Name|
>|--------|------------|---|---|---------|--------------------------------|---|
>| #microsoft.graph.user | Test 1 | Test | 123456-abcd-7890-erty-987qwe987 | 050123456 | Test | test1@demistodev.onmicrosoft.com |

### msgraph-user-get-manager

***
Retrieves the properties from the manager of a user.

#### Base Command

`msgraph-user-get-manager`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The User ID or userPrincipalName of the user for which to get the manager properties. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUserManager.ID | String | User's user ID. |
| MSGraphUserManager.Manager.ID | String | Manager's user ID. |
| MSGraphUserManager.Manager.DisplayName | String | User's display name. |
| MSGraphUserManager.Manager.GivenName | String | User's given name. |
| MSGraphUserManager.Manager.BusinessPhones | String | User's business phone numbers. |
| MSGraphUserManager.Manager.JobTitle | String | User's job title. |
| MSGraphUserManager.Manager.Mail | String | User's mail address. |
| MSGraphUserManager.Manager.MobilePhone | String | User's mobile phone number. |
| MSGraphUserManager.Manager.OfficeLocation | String | User's office location. |
| MSGraphUserManager.Manager.PreferredLanguage | String | User's preferred language. |
| MSGraphUserManager.Manager.Surname | String | User's surname. |
| MSGraphUserManager.Manager.UserPrincipalName | String | User's principal name. |

#### Command example

```!msgraph-user-get-manager user=123456-abcd-7890-erty-987qwe987```

#### Context Example

```json
{
    "MSGraphUserManager": {
        "Manager": {
            "BusinessPhones": [],
            "DisplayName": "Test 2",
            "GivenName": "Test",
            "ID": "259d2a3c-167b-411c-b2ee-88646ce6e054",
            "JobTitle": null,
            "Mail": null,
            "MobilePhone": "050505050",
            "OfficeLocation": null,
            "PreferredLanguage": null,
            "Surname": "Test",
            "UserPrincipalName": "test2@demistodev.onmicrosoft.com"
        },
        "User": "123456-abcd-7890-erty-987qwe987"
    }
}
```

#### Human Readable Output

>### 123456-abcd-7890-erty-987qwe987 - manager
>
>| Display Name |Given Name|ID|Mobile Phone|Surname|User Principal Name|
--------------|---|---|---|---|---|---|
>| Test 2 | Test | 259d2a3c-167b-411c-b2ee-88646ce6e054 | 050505050 | Test | test2@demistodev.onmicrosoft.com |

### msgraph-user-assign-manager

***
Assigns a manager to the specified user.
Permission: - User.ReadWrite (Delegated) or - User.ReadWrite (Application)

#### Base Command

`msgraph-user-assign-manager`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName of the user to which to assign a manager. | Required |
| manager | User ID or userPrincipalName of the manager. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-user-assign-manager user=123456-abcd-7890-erty-987qwe987 manager=9627hp-sq12-b65m-4256h6h```

#### Human Readable Output

>A manager was assigned to user "123456-abcd-7890-erty-987qwe987". It might take several minutes for the changes to take effect across all applications.

### msgraph-user-change-password

***
Changes the user password.
Supported only in a self deployed app flow with the Permission: Directory.AccessAsUser.All(Delegated)
Note: In order to change the password, you need additional permissions: Auth Admin, Privileged Auth Admin or Global Admin, depending on the target user's role.

#### Base Command

`msgraph-user-change-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName to update password for. | Required |
| password | The new password. | Required |
| force_change_password_next_sign_in | Whether the password will be changed on the next sign in. Possible values are: true, false. Default is true. | Optional |
| force_change_password_with_mfa | Whether to change the password with MFA. Possible values are: true, false. Default is false. | Optional |

### msgraph-user-test

***
Tests connectivity to Microsoft Graph User.

#### Base Command

`msgraph-user-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-user-test```

#### Human Readable Output

### msgraph-user-session-revoke

***
Revoke a user session by invalidating all refresh tokens issued to applications for a user.
This command requires an administrator role.
Permission required: Directory.AccessAsUser.All (Delegated).

#### Base Command

`msgraph-user-session-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Context Output

There is no context output for this command.
There is no context output for this command.

### msgraph-user-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`msgraph-user-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```msgraph-user-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>
>1. Click on the login URL to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.

### msgraph-user-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-user-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msgraph-user-tap-policy-delete

***
Deletes a specific TAP policy.
**Permissions**: UserAuthenticationMethod.ReadWrite.All (Delegated), UserAuthenticationMethod.ReadWrite.All (Application).

#### Base Command

`msgraph-user-tap-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The Azure AD user ID. | Required |
| policy_id | Policy ID. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-user-tap-policy-delete policy_id=r4y67u4-69nh-h671-a4bj8922 user_id=123456-abcd-7890-erty-987qwe987"```

### msgraph-user-tap-policy-create

***
Create a new TAP policy for a user.
During the command execution, a password-protected zip file will be generated, including the new TAP password. You can download the file, use your password to unlock it, and get the TAP password.
A user can only have one Temporary Access Pass that's usable within its specified lifetime.
**Permissions**: UserAuthenticationMethod.ReadWrite.All (Delegated), UserAuthenticationMethod.ReadWrite.All (Application).

#### Base Command

`msgraph-user-tap-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The Azure AD user ID. | Required |
| zip_password | A password for the password-protected zip file that will include the password of the new TAP. | Required |
| lifetime_in_minutes | The duration of the TAP. Must be between 10 and 43200 (equivalent to 30 days). Default is 60. | Optional |
| is_usable_once | Determines if the pass is limited to a one-time use. If true, the pass can be used once; if false, the TAP can be used multiple times within its 'lifetime_in_minutes' setting. <br/>A multi-use Temporary Access Pass (isUsableOnce = false) can only be created and used for sign-in if it is allowed by the Temporary Access Pass authentication method policy.   . Possible values are: true, false. | Optional |
| start_time | The start time for the TAP (has to be a time in the future). Can be specified in ISO 8601 format - "YYYY-MM-DDThh:mm:ssZ",<br/>for example: "2025-03-26T00:00:00.000Z" or in a future relative time format, for example: "now", "in 2 days". Default is now. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.TAPPolicy.ID | String | TAP policy's ID. |
| MSGraphUser.TAPPolicy.IsUsable | Bool | TAP policy's usability. |
| MSGraphUser.TAPPolicy.IsUsableOnce | Bool | TAP policy's once - usability. |
| MSGraphUser.TAPPolicy.CreatedDateTime | String | TAP policy's creation date and time. |
| MSGraphUser.TAPPolicy.MethodUsabilityReason | String | TAP policy's method usability reason. |
| MSGraphUser.TAPPolicy.LifetimeInMinutes | Int | TAP policy's lifetime in minutes. |
| MSGraphUser.TAPPolicy.StartDateTime | String | TAP policy's start date and time. |

#### Command example

```!msgraph-user-tap-policy-create user_id=123456-abcd-7890-erty-987qwe987 zip_password=123```

### msgraph-user-tap-policy-list

***
Lists all TAP policies for a user.
This command will only return a single object in the collection as a user can have only one Temporary Access Pass (TAP) method.
**Permissions**: UserAuthenticationMethod.Read.All (Delegated), UserAuthenticationMethod.Read.All (Application).

#### Base Command

`msgraph-user-tap-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The Azure AD user ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.TAPPolicy.ID | String | TAP policy's ID. |
| MSGraphUser.TAPPolicy.IsUsable | Bool | TAP policy's usability. |
| MSGraphUser.TAPPolicy.IsUsableOnce | Bool | TAP policy's once - usability. |
| MSGraphUser.TAPPolicy.CreatedDateTime | String | TAP policy's creation date and time. |
| MSGraphUser.TAPPolicy.MethodUsabilityReason | String | TAP policy's method usability reason. |
| MSGraphUser.TAPPolicy.LifetimeInMinutes | Int | TAP policy's lifetime in minutes. |
| MSGraphUser.TAPPolicy.StartDateTime | String | TAP policy's start date and time. |

#### Command example

```!msgraph-user-tap-policy-list user_id=123456-abcd-7890-erty-987qwe987```

### msgraph-user-change-password-on-premise

***
Changes the password of an on-premise user. Requires the following permissions: -UserAuthenticationMethod.Read.All - delegated, Users.Read.All - delegated.
Providing a password is required (password auto-generation is not supported).

**Prerequisites and Configuration Requirements:**

1. **Authentication Flow**: Must use **Authorization Code flow** with a **self-deployed Azure app**. Client Credentials flow is not supported for this command.

2. **Required App Permissions**: The Azure app must have the following delegated permissions:
   - `UserAuthenticationMethod.ReadWrite.All` - Delegated
   - `Users.Read.All` - Delegated

3. **Azure App Role Configuration**:
   - The app must have the **Authorization Administrator** role granted to it through the Microsoft Entra Admin Center:
     - Navigate to **Roles and administrators** → Search for **Authorization Administrator**
     - Click **Authorization Administrator** → **Add assignments**.
     - Select the app you want to configure the instance with and click **Save**.
   - Additionally, create a new app role in the Azure Portal for the app you want to configure the instance with:
     - Navigate to **App roles** → **Create Role App**
     - Set **Value** to `UserAuthenticationMethod.ReadWrite.All`
     - Set **Allowed member types** to `Both`.
     - Click on **Create**.

4. **User Role Requirements**: The logged-in user (authenticating via Authorization Code flow) must have the Authorization Administrator role in Azure AD.

#### Base Command

`msgraph-user-change-password-on-premise`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName to update password for. | Required |
| password | The new password. | Optional |
| nonsensitive_password | The new password. This argument can be used in playbooks, but note its value will NOT be hidden in logs. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-user-change-password-on-premise user=123456-abcd-7890-erty-987qwe987 password=123456```

### msgraph-user-force-reset-password

***
Forces a user to reset their password the next time they log in.
Note that this action does not terminate the user’s current session.
If you also want to force the user to sign in again, use the msgraph-user-session-revoke command.
This operation is supported only when using a self-deployed app flow with the Directory.AccessAsUser.All and User-PasswordProfile.ReadWrite.All delegated permissions. For further info, see https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http#example-3-update-the-passwordprofile-of-a-user-and-reset-their-password
Furthermore, the signed in user must have a higher privileged administrator role than the user who's password is being reset. The admin hierarchy table can be viewed here: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-reset-passwords

#### Base Command

`msgraph-user-force-reset-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-get-groups

***
Retrieves the groups a user is part of.

#### Base Command

`msgraph-user-get-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUserGroups.ID | String | The user ID. |
| MSGraphUserGroups.Groups.Classification | String | Value used to classify data types in your groups. |
| MSGraphUserGroups.Groups.@Odata.Type | String | A string value that can be used to classify the user's groups. |
| MSGraphUserGroups.Groups.CreatedDateTime | String | Group creation date and time. |
| MSGraphUserGroups.Groups.CreationOptions | String | Group creation options. |
| MSGraphUserGroups.Groups.DeletedDateTime | String | Group deletion date and time. |
| MSGraphUserGroups.Groups.Description | String | Group description string. |
| MSGraphUserGroups.Groups.DisplayName | String | Group display name. |
| MSGraphUserGroups.Groups.ExpirationDateTime | String | Group expiration date and time. |
| MSGraphUserGroups.Groups.GroupTypes | String | The types assigned to the group. |
| MSGraphUserGroups.Groups.ID | String | Group id. |
| MSGraphUserGroups.Groups.IsAssignableToRole | Bool | Indicates whether the group can be assigned to roles. |
| MSGraphUserGroups.Groups.Mail | String | Group associated mail. |
| MSGraphUserGroups.Groups.MailEnabled | Bool | Indicates whether the group has mail enabled. |
| MSGraphUserGroups.Groups.MailNickname | String | Mail nickname of the group. |
| MSGraphUserGroups.Groups.MembershipRule | String | Membership rule applied to the group. |
| MSGraphUserGroups.Groups.MembershipRuleProcessingState | String | Processing state of the group’s membership rule. |
| MSGraphUserGroups.Groups.OnPremisesDomainName | String | On-premises domain name associated with the group. |
| MSGraphUserGroups.Groups.OnPremisesLastSyncDateTime | String | Date and time when the group was last synchronized from on-premises. |
| MSGraphUserGroups.Groups.OnPremisesNetBiosName | String | On-premises NetBIOS name of the group. |
| MSGraphUserGroups.Groups.OnPremisesProvisioningErrors | String | Errors encountered during on-premises provisioning of the group. |
| MSGraphUserGroups.Groups.OnPremisesSamAccountName | String | SAM account name of the group in on-premises Active Directory. |
| MSGraphUserGroups.Groups.OnPremisesSecurityIdentifier | String | Security identifier \(SID\) of the group in on-premises Active Directory. |
| MSGraphUserGroups.Groups.OnPremisesSyncEnabled | String | Indicates whether the group is synchronized from on-premises. |
| MSGraphUserGroups.Groups.PreferredDataLocation | String | Preferred geographic location for the group’s data. |
| MSGraphUserGroups.Groups.PreferredLanguage | String | Preferred language for the group. |
| MSGraphUserGroups.Groups.ProxyAddresses | String | Email addresses associated with the group. |
| MSGraphUserGroups.Groups.RenewedDateTime | String | Date and time the group was last renewed. |
| MSGraphUserGroups.Groups.ResourceBehaviorOptions | String | Options defining the group’s behavior as a resource. |
| MSGraphUserGroups.Groups.ResourceProvisioningOptions | String | Options used for provisioning the group as a resource. |
| MSGraphUserGroups.Groups.SecurityEnabled | Bool | Indicates whether the group is security-enabled. |
| MSGraphUserGroups.Groups.SecurityIdentifier | String | Security identifier of the group. |
| MSGraphUserGroups.Groups.ServiceProvisioningErrors | String | Errors encountered during service provisioning of the group. |
| MSGraphUserGroups.Groups.Theme | String | Theme associated with the group. |
| MSGraphUserGroups.Groups.UniqueName | String | Unique name of the group. |
| MSGraphUserGroups.Groups.Visibility | String | Groups visibility. |
| MSGraphUserGroups.Groups.WellKnownObject | String | Indicates if the group is a well-known system object. |

### msgraph-user-get-auth-methods

***
Retrieve a list of authentication methods registered to a user.

#### Base Command

`msgraph-user-get-auth-methods`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUserAuthMethods.ID | String | The user ID. |
| MSGraphUserAuthMethods.Methods.CreatedDateTime | String | Authentication method's creation date and time. |
| MSGraphUserAuthMethods.Methods.ID | String | The unique identifier for the authentication method. |
| MSGraphUserAuthMethods.Methods.@Odata.Type | String | The type of the authentication method. |
| MSGraphUserAuthMethods.Methods.Password | String | The password associated with the authentication method, if applicable. |
| MSGraphUserAuthMethods.Methods.DisplayName | String | Authentication methods displayName. |
| MSGraphUserAuthMethods.Methods.DeviceTag | String | The device tag associated with the authentication method. |
| MSGraphUserAuthMethods.Methods.IsUsable | String | Indicates whether the authentication method is currently usable. |
| MSGraphUserAuthMethods.Methods.IsUsableOnce | String | Indicates whether the authentication method can be used only once. |
| MSGraphUserAuthMethods.Methods.MethodUsabilityReason | String | The reason why the authentication method is or is not usable. |

### msgraph-user-owned-devices-list

***
Lists the devices that are owned by the user.
Permission:User.Read.All, Directory.Read.All - Delegated
Note: When using the XSOAR app, this command returns partial data. To retrieve full data, use a self-deployed Azure app with the appropriate permissions.

#### Base Command

`msgraph-user-owned-devices-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The Azure AD user ID. | Required |
| limit | Number of devices in the list. Maximum is 50. Default is 50. | Optional |
| next_page | The URL for the next page in the list. | Optional |
| filter | Filter to be plugged directly into the API. For more information about the Filter syntax, see the Microsoft documentation: https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.ID | String | User's ID. |
| MSGraphUser.OwnedDevice.ID | String | Owned device's ID. |
| MSGraphUser.OwnedDevice.PhysicalIds | String | Physical IDs of the device. |
| MSGraphUser.OwnedDevice.DeviceVersion | String | The version of the device. |
| MSGraphUser.OwnedDevice.ProfileType | String | The profile type of the device. |
| MSGraphUser.OwnedDevice.CreatedDateTime | String | The date and time when the device was created. |
| MSGraphUser.OwnedDevice.ApproximateLastSignInDateTime | String | The approximate date and time of the last sign-in. |
| MSGraphUser.OwnedDevice.OperatingSystemVersion | String | The version of the operating system. |
| MSGraphUser.OwnedDevice.AlternativeSecurityIds | String | Alternative security IDs of the device. |
| MSGraphUser.OwnedDevice.DisplayName | String | The display name of the device. |
| MSGraphUser.OwnedDevice.OperatingSystem | String | The operating system of the device. |
| MSGraphUser.OwnedDevice.DeviceId | String | The unique identifier for the device. |
| MSGraphUser.OwnedDevice.TrustType | String | The trust type of the device. |
| MSGraphUser.OwnedDevice.RegistrationDateTime | String | The date and time when the device was registered. |

### msgraph-user-fido2-method-list

***
Lists the FIDO2 authentication methods registered to a user, or retrieves a specific FIDO2 method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All

#### Base Command

`msgraph-user-fido2-method-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of a specific FIDO2 authentication method to retrieve. | Optional |
| limit | Maximum number of FIDO2 methods to return when listing all methods. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.FIDO2Method.ID | String | The unique identifier of the FIDO2 authentication method. |
| MSGraphUser.FIDO2Method.DisplayName | String | The display name of the key as given by the user. |
| MSGraphUser.FIDO2Method.CreatedDateTime | String | The timestamp when this key was registered. |
| MSGraphUser.FIDO2Method.AaGuid | String | Authenticator Attestation GUID, an identifier that indicates the type of authenticator. |
| MSGraphUser.FIDO2Method.Model | String | The manufacturer-assigned model of the FIDO2 security key. |
| MSGraphUser.FIDO2Method.AttestationCertificates | String | The attestation certificate\(s\) attached to this security key. |
| MSGraphUser.FIDO2Method.AttestationLevel | String | The attestation level of this FIDO2 security key. |

### msgraph-user-fido2-method-delete

***
Deletes a FIDO2 authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-fido2-method-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of the FIDO2 authentication method to delete. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-email-method-list

***
Lists the email authentication methods registered to a user, or retrieves a specific email method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-email-method-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of a specific email authentication method to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.EmailAuthMethod.ID | String | The unique identifier of the email authentication method. |
| MSGraphUser.EmailAuthMethod.EmailAddress | String | The email address registered to this user. |

### msgraph-user-email-method-delete

***
Deletes an email authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-email-method-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of the email authentication method to delete. Default is 3ddfcfc8-9383-446f-83cc-3ab9be4be18f. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-authenticator-method-list

***
Lists the Microsoft Authenticator authentication methods registered to a user, or retrieves a specific method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-authenticator-method-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of a specific Microsoft Authenticator authentication method to retrieve. | Optional |
| limit | Maximum number of results to return when listing all methods. Default is 50. | Optional |
| next_page | The URL for the next page in the list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.UserAuthMethod.ID | String | The unique identifier of the Microsoft Authenticator authentication method. |
| MSGraphUser.UserAuthMethod.DisplayName | String | The name of the device on which Microsoft Authenticator is registered. |
| MSGraphUser.UserAuthMethod.PhoneAppVersion | String | The version of Microsoft Authenticator installed on the device. |
| MSGraphUser.UserAuthMethod.DeviceTag | String | Tags containing app metadata. |
| MSGraphUser.UserAuthMethod.CreatedDateTime | String | The timestamp when this method was registered to the user. |
| MSGraphUser.UserAuthMethod.NextPage | String | A token to pass to the next list command to retrieve additional results. |

### msgraph-user-authenticator-method-delete

***
Deletes a Microsoft Authenticator authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-authenticator-method-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of the Microsoft Authenticator authentication method to delete. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-phone-method-list

***
Lists the phone authentication methods registered to a user, or retrieves a specific phone method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-phone-method-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of a specific phone authentication method to retrieve. | Optional |
| next_page | The URL for the next page in the list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.PhoneAuthMethod.ID | String | The unique identifier of the phone authentication method. |
| MSGraphUser.PhoneAuthMethod.PhoneNumber | String | The phone number registered to this user. |
| MSGraphUser.PhoneAuthMethod.PhoneType | String | The type of phone \(mobile, alternateMobile, or office\). |
| MSGraphUser.PhoneAuthMethod.SmsSignInState | String | Whether the phone is ready to be used for SMS sign-in. |
| MSGraphUser.PhoneAuthMethod.NextPage | String | A token to pass to the next list command to retrieve additional results. |

### msgraph-user-phone-method-delete

***
Deletes a phone authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-phone-method-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of the phone authentication method to delete. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-software-oath-method-list

***
Lists the software OATH authentication methods registered to a user, or retrieves a specific method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-software-oath-method-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of a specific software OATH authentication method to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.SoftOathAuthMethod.ID | String | The unique identifier of the software OATH authentication method. |

### msgraph-user-software-oath-method-delete

***
Deletes a software OATH authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-software-oath-method-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of the software OATH authentication method to delete. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-windows-hello-method-list

***
Lists the Windows Hello for Business authentication methods registered to a user, or retrieves a specific method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-windows-hello-method-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of a specific Windows Hello for Business authentication method to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.WindowsHelloAuthMethod.ID | String | The unique identifier of the Windows Hello for Business authentication method. |
| MSGraphUser.WindowsHelloAuthMethod.DisplayName | String | The name of the device on which Windows Hello is registered. |
| MSGraphUser.WindowsHelloAuthMethod.KeyStrength | String | The key strength of the Windows Hello for Business key \(normal or weak\). |
| MSGraphUser.WindowsHelloAuthMethod.CreatedDateTime | String | The timestamp when this method was registered to the user. |

### msgraph-user-windows-hello-method-delete

***
Deletes a Windows Hello for Business authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-windows-hello-method-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |
| method_id | The ID of the Windows Hello for Business authentication method to delete. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-temp-access-pass-method-list

***
Lists the Temporary Access Pass authentication methods registered to a user, or retrieves a specific method by ID.
Permission: UserAuthenticationMethod.Read.All or UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-temp-access-pass-method-list`

#### Input

**Argument Name** | **Description** | **Required** |
--- | --- | --- |
user | User ID or userPrincipalName. | Required |
method_id | The ID of a specific Temporary Access Pass authentication method to retrieve. | Optional |

#### Context Output

**Path** | **Type** | **Description** |
--- | --- | --- |
MSGraphUser.TempAccessPassAuthMethod.ID | String | The unique identifier of the Temporary Access Pass authentication method. |
MSGraphUser.TempAccessPassAuthMethod.IsUsable | Bool | Indicates whether the authentication method is currently usable. |

### msgraph-user-temp-access-pass-method-delete

***
Deletes a Temporary Access Pass authentication method from a user.
Permission: UserAuthenticationMethod.ReadWrite.All - Delegated or Application

#### Base Command

`msgraph-user-temp-access-pass-method-delete`

#### Input

**Argument Name** | **Description** | **Required** |
--- | --- | --- |
user | User ID or userPrincipalName. | Required |
method_id | The ID of the Temporary Access Pass authentication method to delete. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-request-mfa

***
Pops a synchronous MFA request for the given user. This is a blocking call that waits for user response or timeout.

#### Base Command

`msgraph-user-request-mfa`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_mail | The user mail to send the MFA request to. | Required |
| timeout | The timeout for the MFA request. Default is 60. | Optional |
| access_token | The MFA access token obtained from msgraph-user-create-mfa-client-access-token command. | Required |

#### Context Output

There is no context output for this command.

### msgraph-user-get-user-default-auth-method

***
Retrieves the authentication preferences for a user, including the default method.

#### Base Command

`msgraph-user-get-user-default-auth-method`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphUser.AuthMethod.User | String | The user principal name. |
| MSGraphUser.AuthMethod.DefaultMethod | String | The default authentication method for the user. |
| MSGraphUser.AuthMethod.IsSystemPreferredAuthenticationMethodEnabled | Boolean | Whether system-preferred authentication is enabled. |
| MSGraphUser.AuthMethod.UserPreferredMethodForSecondaryAuthentication | String | The user's preferred method for secondary authentication. |
| MSGraphUser.AuthMethod.SystemPreferredAuthenticationMethod | String | The system-preferred authentication method. |
