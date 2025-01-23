Unified gateway to security insights - all from a unified Microsoft Graph User API.


## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).  

Required Permissions:
- Directory.Read.All - Delegated
- User.ReadWrite.All - Application
- User.Read - Delegated

## Authorize Cortex XSOAR for Azure Active Directory Users (Self deployed Azure App)

There are two different authentication methods for a self-deployed configuration:

- [Client Credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#client-credentials-flow)
- [Authorization Code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authorization-code-flow)

We recommend using the Client Credentials flow.
In order to use the msgraph-user-change-password command, you must configure with the Authorization Code flow.

Note: When using the Authorization Code flow, make sure the user you authenticate with has the correct roles in Azure AD in order to use the command.

## Configure Azure Active Directory Users in Cortex


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
Disables a user from all Office 365 applications, and prevents sign in. Note: This command disables user,
but does not terminate an existing session. Supported only in a self deployed app flow with the
Permission: Directory.AccessAsUser.All(Delegated)


#### Base Command

`msgraph-user-account-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required | 


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
```!msgraph-user-unblock user=1875cf87-ebf9-4a29-b5e2-74e36591296e```
#### Human Readable Output

>"1875cf87-ebf9-4a29-b5e2-74e36591296e" unblocked. It might take several minutes for the changes to take affect across all applications. 

### msgraph-user-update
***
Updates the properties of a user object.
Permissions: - User.ReadWrite (Delegated & Application)


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
```!msgraph-user-update user=1875cf87-ebf9-4a29-b5e2-74e36591296e updated_fields="MobilePhone=050123456"```
#### Context Example
```json
{
    "Account": {
        "DisplayName": "Test 1",
        "Email": {
            "Address": null
        },
        "ID": "1875cf87-ebf9-4a29-b5e2-74e36591296e",
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
        "ID": "1875cf87-ebf9-4a29-b5e2-74e36591296e",
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

>### 1875cf87-ebf9-4a29-b5e2-74e36591296e data
>| Display Name |Given Name|ID|Mobile Phone|Surname|User Principal Name|
--------------|---|---|---|---|---|---|
>| Test 1 | Test | 1875cf87-ebf9-4a29-b5e2-74e36591296e | 050123456 | Test | test1@demistodev.onmicrosoft.com |


### msgraph-user-delete
***
Deletes an existing user.
Permissions: - Directory.AccessAsUser.All (Delegated) - User.ReadWrite.All (Application)


#### Base Command

`msgraph-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName to delete. | Required | 


### msgraph-user-create
***
Creates a new user.
Permissions: - User.ReadWrite.All (Delegated & Application)


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
Retrieves the properties and relationships of a user object. For more information, visit: https://docs.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0).
Permissions: - User.Read (Delegated) - User.Read.All (Application)


#### Base Command

`msgraph-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required | 
| properties |  A CSV list of properties by which to filter the results, for example: "displayName,jobTitle,mobilePhone" . | Optional | 


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
```!msgraph-user-get user=1875cf87-ebf9-4a29-b5e2-74e36591296e```
#### Context Example
```json
{
    "Account": {
        "DisplayName": "Test 1",
        "Email": {
            "Address": null
        },
        "ID": "1875cf87-ebf9-4a29-b5e2-74e36591296e",
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
        "ID": "1875cf87-ebf9-4a29-b5e2-74e36591296e",
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

>### 1875cf87-ebf9-4a29-b5e2-74e36591296e data
>| Display Name |Given Name|ID|Mobile Phone|Surname|User Principal Name|
--------------|---|---|---|---|---|---|
>| Test 1 | Test | 1875cf87-ebf9-4a29-b5e2-74e36591296e | 050123456 | Test | test1@demistodev.onmicrosoft.com |


### msgraph-user-list
***
Retrieves a list of user objects.
Permissions: - User.ReadBasic.All (Delegated) - User.Read.All (Application)


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
            "ID": "023096d0-595e-47b5-80dd-ea5886ab9294",
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
            "ID": "0628c545-94f6-4d07-8bc6-e6718ba1bc95",
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
            "ID": "082b3bc9-bb2d-4d12-8b1a-d84a53229696",
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
            "ID": "023096d0-595e-47b5-80dd-ea5886ab9294",
            "JobTitle": null,
            "Mail": "test1@demistodev.onmicrosoft.com",
            "MobilePhone": "050505050"
        },
        {
            "DisplayName": "Test 2",
            "ID": "0628c545-94f6-4d07-8bc6-e6718ba1bc95",
            "JobTitle": null,
            "Mail": "test2@demistodev.onmicrosoft.com",
            "MobilePhone": null
        },
        {
            "DisplayName": "Test 3",
            "ID": "082b3bc9-bb2d-4d12-8b1a-d84a53229696",
            "JobTitle": null,
            "Mail": null,
            "MobilePhone": null
        }
    ]
}
```

#### Human Readable Output

>### All Graph Users
>To get further results, enter this to the next_page parameter:
>https:<span>//</span>graph.microsoft.com/v1.0/users?$select=id%2cdisplayName%2cjobTitle%2cmobilePhone%2cmail&$count=true&$skiptoken=m~AQAnO2Q2MjljMzcwNjFjOTQ4NTE4ZjNkODBlYTZjMDc2NTVmOzswOzA7
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
```!msgraph-direct-reports user=259d2a3c-167b-411c-b2ee-88646ce6e054```
#### Context Example
```json
{
    "MSGraphUserDirectReports": {
        "Manager": "259d2a3c-167b-411c-b2ee-88646ce6e054",
        "Reports": [
            {
                "@Odata.Type": "#microsoft.graph.user",
                "BusinessPhones": [],
                "DisplayName": "Test 1",
                "GivenName": "Test",
                "ID": "1875cf87-ebf9-4a29-b5e2-74e36591296e",
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
>|@Odata.Type| Display Name | Given Name |ID|Mobile Phone| Surname | User Principal Name|
>|--------|------------|---|---|---------|--------------------------------|---|
>| #microsoft.graph.user | Test 1 | Test | 1875cf87-ebf9-4a29-b5e2-74e36591296e | 050123456 | Test | test1@demistodev.onmicrosoft.com |


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
```!msgraph-user-get-manager user=1875cf87-ebf9-4a29-b5e2-74e36591296e```
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
        "User": "1875cf87-ebf9-4a29-b5e2-74e36591296e"
    }
}
```

#### Human Readable Output

>### 1875cf87-ebf9-4a29-b5e2-74e36591296e - manager
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
```!msgraph-user-assign-manager user=1875cf87-ebf9-4a29-b5e2-74e36591296e manager=259d2a3c-167b-411c-b2ee-88646ce6e054```
#### Human Readable Output

>A manager was assigned to user "1875cf87-ebf9-4a29-b5e2-74e36591296e". It might take several minutes for the changes to take effect across all applications.

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

>ok

### msgraph-user-session-revoke
***
Revoke a user session- Invalidates all the refresh tokens issued to applications for a user.
Permission: Directory.AccessAsUser.All(Delegated)


#### Base Command

`msgraph-user-session-revoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User ID or userPrincipalName. | Required | 


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
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
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