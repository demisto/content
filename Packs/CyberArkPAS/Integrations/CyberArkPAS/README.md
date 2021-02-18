Use the CyberArk Privileged Access Security (PAS) solution to manage users, safes, vaults, and accounts from Cortex XSOAR.

## Configure CyberArkPAS on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberArkPAS.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://example.net\) | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| max_fetch | Max fetch | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| score | CyberArk PAS score \(0.0\-100.0\) | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberark-pas-user-add
***
Add a new user to the vault.


#### Base Command

`cyberark-pas-user-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The name of the user. | Required | 
| user_type | The user type according to the license. | Optional | 
| non_authorized_interfaces | The CyberArkPAS interfaces that this user is not authorized to use, e.g., - "PSM", "PSMP" | Optional | 
| location | The location in the vault where the user will be created. Must begin with "\\".  If just "\\", the vault is in the root. | Optional | 
| expiry_date | The date when the user credentials expire. Must be in the following timestamp format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year). | Optional | 
| password | The password that the user will use to log in for the first time. | Required | 
| change_password_on_the_next_logon | Whether or not the user must change the user password from the second log in onward. Can be 'true' or 'false'. Default is 'true'. | Optional | 
| password_never_expires | Whether the user’s password will not expire unless they decide to change it. Can be 'true' or 'false'. Default is 'false'. | Optional | 
| vault_authorization | A comma-separated list of user permissions. Valid values are: AuditUsers, AddUpdateUsers, ResetUsersPasswords, ActivateUsers, AddNetworkAreas, ManageDirectoryMapping, ManageServerFileCategories, BackupAllSafes, RestoreAllSafes e.g., AddSafes,AuditUsers | Optional | 
| description | Notes and comments. | Optional | 
| email | The email address of the user. | Optional | 
| first_name | The first name of the user. | Optional | 
| last_name | The last name of the user. | Optional | 
| enable_user | Whether the user will be enabled upon creation. Can be 'true' or 'false'. Default is 'true'. | Optional | 
| distinguished_name | The distinguished name of the user. The usage is for PKI authentication. This will match the certificate subject name or domain name. | Optional | 
| profession | The profession of the user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Users.id | Number | The unique ID of the user. | 
| CyberArkPAS.Users.authenticationMethod | String | The authentication method of the user. | 
| CyberArkPAS.Users.changePassOnNextLogon | Boolean | Whether or not the user must change the user password. | 
| CyberArkPAS.Users.description | String | Description of the user. | 
| CyberArkPAS.Users.enableUser | Boolean | Whether or not the user is enabled. | 
| CyberArkPAS.Users.expiryDate | Number | The expiry date of the user credentials. | 
| CyberArkPAS.Users.internet.businessEmail | String | The email address of the user. | 
| CyberArkPAS.Users.lastSuccessfulLoginDate | Number | The last successful login date of the user. | 
| CyberArkPAS.Users.location | String | The location in the vault where the user will be created. | 
| CyberArkPAS.Users.personalDetails.profession | String | The profession of the user. | 
| CyberArkPAS.Users.suspended | Boolean | Whether or not the user is suspended. | 
| CyberArkPAS.Users.userType | String | The type of the user. | 
| CyberArkPAS.Users.username | String | The name of the user. | 
| CyberArkPAS.Users.vaultAuthorization | String | The permissions of the user. | 


#### Command Example
```!cyberark-pas-user-add username="TestUser" password="12345Aa" change_password_on_the_next_logon=true description="new user for test" email="usertest@test.com" enable_user=true first_name="user" last_name="test" profession="testing integrations"```

#### Context Example
```
{
    "CyberArkPAS": {
        "Users": {
            "authenticationMethod": [
                "AuthTypePass"
            ],
            "businessAddress": {
                "workCity": "",
                "workCountry": "",
                "workState": "",
                "workStreet": "",
                "workZip": ""
            },
            "changePassOnNextLogon": true,
            "componentUser": false,
            "description": "new user for test",
            "distinguishedName": "",
            "enableUser": true,
            "expiryDate": -62135578800,
            "groupsMembership": [],
            "id": 150,
            "internet": {
                "businessEmail": "usertest@test.com",
                "homeEmail": "",
                "homePage": "",
                "otherEmail": ""
            },
            "lastSuccessfulLoginDate": 1597830302,
            "location": "\\",
            "passwordNeverExpires": false,
            "personalDetails": {
                "city": "",
                "country": "",
                "department": "",
                "firstName": "user",
                "lastName": "test",
                "middleName": "",
                "organization": "",
                "profession": "testing integrations",
                "state": "",
                "street": "",
                "title": "",
                "zip": ""
            },
            "phones": {
                "businessNumber": "",
                "cellularNumber": "",
                "faxNumber": "",
                "homeNumber": "",
                "pagerNumber": ""
            },
            "source": "CyberArk",
            "suspended": false,
            "unAuthorizedInterfaces": [],
            "userType": "EPVUser",
            "username": "TestUser",
            "vaultAuthorization": []
        }
    }
}
```

#### Human Readable Output

>### Results
>|authenticationMethod|businessAddress|changePassOnNextLogon|componentUser|description|distinguishedName|enableUser|expiryDate|groupsMembership|id|internet|lastSuccessfulLoginDate|location|passwordNeverExpires|personalDetails|phones|source|suspended|unAuthorizedInterfaces|userType|username|vaultAuthorization|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| AuthTypePass | workStreet: <br/>workCity: <br/>workState: <br/>workZip: <br/>workCountry:  | true | false | new user for test |  | true | -62135578800 |  | 150 | homePage: <br/>homeEmail: <br/>businessEmail: usertest@test.com<br/>otherEmail:  | 1597830302 | \ | false | street: <br/>city: <br/>state: <br/>zip: <br/>country: <br/>title: <br/>organization: <br/>department: <br/>profession: testing integrations<br/>firstName: user<br/>middleName: <br/>lastName: test | homeNumber: <br/>businessNumber: <br/>cellularNumber: <br/>faxNumber: <br/>pagerNumber:  | CyberArk | false |  | EPVUser | TestUser |  |


### cyberark-pas-user-update
***
Update an existing vault user.


#### Base Command

`cyberark-pas-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The name of the user. | Optional | 
| user_type | User type according to the license. | Optional | 
| non_authorized_interfaces | The CyberArkPAS interfaces that this user is not authorized to use, e.g., "PSM", "PSMP" | Optional | 
| location | The location in the vault where the user will be created. Must begin with "\\". If just "\\", the vault is in the root. | Optional | 
| expiry_date | The date when the user expires. Must be in the following timestamp format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year). | Optional | 
| change_password_on_the_next_logon | Whether or not the user must change their password from the second log on onward. Can be 'true' or 'false'. Default is 'true'. | Optional | 
| password_never_expires | Whether the user’s password will not expire unless they decide to change it. Can be 'true' or 'false'. Default is 'false'. | Optional | 
| vault_authorization | A comma-separated list of user permissions. Valid values are: AddSafes, AuditUsers, AddUpdateUsers, ResetUsersPasswords, ActivateUsers, AddNetworkAreas, ManageDirectoryMapping, ManageServerFileCategories, BackupAllSafes, RestoreAllSafes e.g., AddSafes,AuditUsers | Optional | 
| description | Notes and comments. | Optional | 
| email | The email addresses of the user. | Optional | 
| first_name | The first name of the user. | Optional | 
| last_name | The last name of the user. | Optional | 
| enable_user | Whether the user will be enabled upon creation. Can be 'true' or 'false'. Default is 'true'. | Optional | 
| distinguished_name | The distinguished name of the user. The usage is for PKI authentication. This will match the certificate subject name or domain name. | Optional | 
| profession | The profession of the user. | Optional | 
| user_id | The ID of the user to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Users.id | Number | The unique ID of the user. | 
| CyberArkPAS.Users.authenticationMethod | String | The authentication method for the user. | 
| CyberArkPAS.Users.changePassOnNextLogon | Boolean | Whether or not the user must change the user password. | 
| CyberArkPAS.Users.description | String | Description of the user. | 
| CyberArkPAS.Users.enableUser | Boolean | Whether or not the user is enabled. | 
| CyberArkPAS.Users.expiryDate | Number | The expiry date of the user. | 
| CyberArkPAS.Users.internet.businessEmail | String | The email address of the user. | 
| CyberArkPAS.Users.lastSuccessfulLoginDate | Number | The last successful login date of the user. | 
| CyberArkPAS.Users.location | String | The location in the vault where the user will be created. | 
| CyberArkPAS.Users.personalDetails.profession | String | The profession of the user. | 
| CyberArkPAS.Users.suspended | Boolean | Whether or not the user is suspended. | 
| CyberArkPAS.Users.userType | String | The type of the user. | 
| CyberArkPAS.Users.username | String | The name of the user. | 
| CyberArkPAS.Users.vaultAuthorization | String | The permissions of the user. | 


#### Command Example
```!cyberark-pas-user-update user_id=150 change_password_on_the_next_logon=true description="updated description" email="update@test.com" first_name="test1" last_name="updated-name" username="TestUser1" profession="test1"```

#### Context Example
```
{
    "CyberArkPAS": {
        "Users": {
            "authenticationMethod": [
                "AuthTypePass"
            ],
            "businessAddress": {
                "workCity": "",
                "workCountry": "",
                "workState": "",
                "workStreet": "",
                "workZip": ""
            },
            "changePassOnNextLogon": true,
            "componentUser": false,
            "description": "updated description",
            "distinguishedName": "",
            "enableUser": true,
            "expiryDate": -62135578800,
            "groupsMembership": [],
            "id": 150,
            "internet": {
                "businessEmail": "update@test.com",
                "homeEmail": "",
                "homePage": "",
                "otherEmail": ""
            },
            "lastSuccessfulLoginDate": 1597830302,
            "location": "\\",
            "passwordNeverExpires": false,
            "personalDetails": {
                "city": "",
                "country": "",
                "department": "",
                "firstName": "test1",
                "lastName": "updated-name",
                "middleName": "",
                "organization": "",
                "profession": "test1",
                "state": "",
                "street": "",
                "title": "",
                "zip": ""
            },
            "phones": {
                "businessNumber": "",
                "cellularNumber": "",
                "faxNumber": "",
                "homeNumber": "",
                "pagerNumber": ""
            },
            "source": "CyberArk",
            "suspended": false,
            "unAuthorizedInterfaces": [],
            "userType": "EPVUser",
            "username": "TestUser1",
            "vaultAuthorization": []
        }
    }
}
```

#### Human Readable Output

>### Results
>|authenticationMethod|businessAddress|changePassOnNextLogon|componentUser|description|distinguishedName|enableUser|expiryDate|groupsMembership|id|internet|lastSuccessfulLoginDate|location|passwordNeverExpires|personalDetails|phones|source|suspended|unAuthorizedInterfaces|userType|username|vaultAuthorization|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| AuthTypePass | workStreet: <br/>workCity: <br/>workState: <br/>workZip: <br/>workCountry:  | true | false | updated description |  | true | -62135578800 |  | 150 | homePage: <br/>homeEmail: <br/>businessEmail: update@test.com<br/>otherEmail:  | 1597830302 | \ | false | street: <br/>city: <br/>state: <br/>zip: <br/>country: <br/>title: <br/>organization: <br/>department: <br/>profession: test1<br/>firstName: test1<br/>middleName: <br/>lastName: updated-name | homeNumber: <br/>businessNumber: <br/>cellularNumber: <br/>faxNumber: <br/>pagerNumber:  | CyberArk | false |  | EPVUser | TestUser1 |  |



### cyberark-pas-user-delete
***
Delete a specific user in the vault.


#### Base Command
`cyberark-pas-user-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Users.Deleted | Boolean | Whether the user was deleted. | 


#### Command Example
```!cyberark-pas-user-delete user_id=150```

#### Context Example
```
{
    "CyberArkPAS": {
        "Users": {
            "Deleted": true,
            "id": "150"
        }
    }
}
```

#### Human Readable Output

>User 150 was deleted




### cyberark-pas-users-list
***
Return a list of all existing users in the vault that meet the filter and search criteria.


#### Base Command

`cyberark-pas-users-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Retrieve users using filters. Valid values: userType, componentUser. | Optional | 
| search | Search by the following values: username, first name, last name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Users.id | Number | The unique IDs of the users. | 
| CyberArkPAS.Users.authenticationMethod | String | The authentication method of the user. | 
| CyberArkPAS.Users.changePassOnNextLogon | Boolean | Whether or not the users must change their password. | 
| CyberArkPAS.Users.description | String | Descriptions of the users. | 
| CyberArkPAS.Users.enableUser | Boolean | Whether or not the users are enabled. | 
| CyberArkPAS.Users.expiryDate | Number | The expiry dates of the users. | 
| CyberArkPAS.Users.internet.businessEmail | String | The email addresses of the users. | 
| CyberArkPAS.Users.lastSuccessfulLoginDate | Number | The last successful login dates of the users. | 
| CyberArkPAS.Users.location | String | The locations in the vault where the users were created. | 
| CyberArkPAS.Users.personalDetails.profession | String | The professions of the users. | 
| CyberArkPAS.Users.suspended | Boolean | Whether or not the users are suspended. | 
| CyberArkPAS.Users.userType | String | The types of the users. | 
| CyberArkPAS.Users.username | String | The names of the users. | 
| CyberArkPAS.Users.vaultAuthorization | String | The permissions of the users. | 


#### Command Example
```!cyberark-pas-users-list```

#### Context Example
```
{
    "CyberArkPAS": {
        "Users": [
            {
                "componentUser": false,
                "id": 2,
                "location": "\\",
                "personalDetails": {
                    "firstName": "",
                    "lastName": "",
                    "middleName": ""
                },
                "source": "CyberArk",
                "userType": "Built-InAdmins",
                "username": "Administrator",
                "vaultAuthorization": [
                    "AddUpdateUsers",
                    "AddSafes",
                    "AddNetworkAreas",
                    "ManageDirectoryMapping",
                    "ManageServerFileCategories",
                    "AuditUsers",
                    "BackupAllSafes",
                    "RestoreAllSafes",
                    "ResetUsersPasswords",
                    "ActivateUsers"
                ]
            },
            {
                "componentUser": false,
                "id": 3,
                "location": "\\",
                "personalDetails": {
                    "firstName": "",
                    "lastName": "",
                    "middleName": ""
                },
                "source": "CyberArk",
                "userType": "Built-InAdmins",
                "username": "Auditor",
                "vaultAuthorization": [
                    "AuditUsers"
                ]
            }
}
```

#### Human Readable Output

>### There are 2 users
>|componentUser|id|location|personalDetails|source|userType|username|vaultAuthorization|
>|---|---|---|---|---|---|---|---|
>| false | 2 | \ | firstName: <br/>middleName: <br/>lastName:  | CyberArk | Built-InAdmins | Administrator | AddUpdateUsers,<br/>AddSafes,<br/>AddNetworkAreas,<br/>ManageDirectoryMapping,<br/>ManageServerFileCategories,<br/>AuditUsers,<br/>BackupAllSafes,<br/>RestoreAllSafes,<br/>ResetUsersPasswords,<br/>ActivateUsers |
>| false | 3 | \ | firstName: <br/>middleName: <br/>lastName:  | CyberArk | Built-InAdmins | Auditor | AuditUsers |


### cyberark-pas-user-activate
***
Activate an existing vault user who was suspended after entering incorrect credentials multiple times.
Uses the V1 of the API and may change in the future.

#### Base Command

`cyberark-pas-user-activate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to activate. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-pas-user-activate user_id=150```


#### Human Readable Output

>User 150 was activated



### cyberark-pas-safes-list
***
Return information about all of the user’s safes in the vault.


#### Base Command

`cyberark-pas-safes-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.SafeName | String | The names of the safes. | 
| CyberArkPAS.Safes.Description | String | The descriptions of the safes. | 
| CyberArkPAS.Safes.Location | String | The locations of the safes. | 
| CyberArkPAS.Safes.ManagingCPM | String | The name of the Central Policy Manager \(CPM\) user who will manage the safes. | 
| CyberArkPAS.Safes.NumberOfDaysRetention | Number | The number of retained versions of every password that is stored in the safes. | 
| CyberArkPAS.Safes.NumberOfVersionsRetention | Number | The number of days for which password versions are saved in the safes. | 
| CyberArkPAS.Safes.OLACEnabled | Boolean | Whether or not to enable Object Level Access Control \(OLAC\) for the safes. | 


#### Command Example
```!cyberark-pas-safes-list```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": [
            {
                "Description": "",
                "Location": "\\",
                "SafeName": "Internal",
                "SafeUrlId": "Internal"
            },
            {
                "Description": "",
                "Location": "\\",
                "SafeName": "Notification",
                "SafeUrlId": "Notification"
            },
            {
                "Description": "",
                "Location": "\\",
                "SafeName": "Reports",
                "SafeUrlId": "Reports"
            }
        ]
    }
}
```

#### Human Readable Output

>### There are 3 safes
>|Description|Location|SafeName|SafeUrlId|
>|---|---|---|---|
>|  | \ | Internal | Internal |
>|  | \ | Notification | Notification |
>|  | \ | Reports | Reports |


### cyberark-pas-safe-get-by-name
***
Return information about a specific safe in the vault.


#### Base Command

`cyberark-pas-safe-get-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| safe_name | The name of the safe about which information is returned. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.SafeName | String | The name of the safe. | 
| CyberArkPAS.Safes.Description | String | The description of the safe. | 
| CyberArkPAS.Safes.Location | String | The location of the safe. | 
| CyberArkPAS.Safes.ManagingCPM | String | The name of the Central Policy Manager \(CPM\) user who will manage the safe. | 
| CyberArkPAS.Safes.NumberOfDaysRetention | Number | The number of retained versions of every password that is stored in the safe. | 
| CyberArkPAS.Safes.NumberOfVersionsRetention | Number | The number of days for which password versions are saved in the safe. | 
| CyberArkPAS.Safes.OLACEnabled | Boolean | Whether or not to enable Object Level Access Control \(OLAC\) for the safe. | 


#### Command Example
```!cyberark-pas-safe-get-by-name safe_name=UpdatedName1```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "AutoPurgeEnabled": false,
            "Description": "UpdatedSafe",
            "Location": "\\",
            "ManagingCPM": "",
            "NumberOfDaysRetention": 150,
            "NumberOfVersionsRetention": null,
            "OLACEnabled": true,
            "SafeName": "UpdatedName1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AutoPurgeEnabled|Description|Location|ManagingCPM|NumberOfDaysRetention|NumberOfVersionsRetention|OLACEnabled|SafeName|
>|---|---|---|---|---|---|---|---|
>| false | UpdatedSafe | \ |  | 150 |  | true | UpdatedName1 |



### cyberark-pas-safe-add
***
Add a new safe to the vault.


#### Base Command

`cyberark-pas-safe-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| safe_name | Name of a safe to create. | Required | 
| description | Description of the new safe. | Optional | 
| OLAC_enabled | Whether or not to enable Object Level Access Control (OLAC) for the new<br/>safe. Valid values are: 'true' or 'false'. Default is 'true'. | Optional | 
| managing_cpm | The name of the Central Policy Manager (CPM) user who will manage the new safe. | Optional | 
| number_of_versions_retention | The number of retained versions of every password that is stored in the safe. | Optional | 
| number_of_days_retention | The number of days for which password versions are saved in the safe. | Optional | 
| location | The location of the new safe. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.SafeName | String | The name of the safe. | 
| CyberArkPAS.Safes.Description | String | The description of the safe. | 
| CyberArkPAS.Safes.Location | String | The location of the safe. | 
| CyberArkPAS.Safes.ManagingCPM | String | The name of the Central Policy Manager \(CPM\) user who will manage the safe. | 
| CyberArkPAS.Safes.NumberOfDaysRetention | Number | The number of retained versions of every password that is stored in the safe. | 
| CyberArkPAS.Safes.NumberOfVersionsRetention | Number | The number of days for which password versions are saved in the safe. | 
| CyberArkPAS.Safes.OLACEnabled | Boolean | Whether or not to enable Object Level Access Control \(OLAC\) for the safe. | 


#### Command Example
```!cyberark-pas-safe-add safe_name="TestSafe1" description="safe for tests" number_of_days_retention=100```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "AutoPurgeEnabled": false,
            "Description": "safe for tests",
            "Location": "\\",
            "ManagingCPM": "",
            "NumberOfDaysRetention": 100,
            "NumberOfVersionsRetention": null,
            "OLACEnabled": true,
            "SafeName": "TestSafe1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AutoPurgeEnabled|Description|Location|ManagingCPM|NumberOfDaysRetention|NumberOfVersionsRetention|OLACEnabled|SafeName|
>|---|---|---|---|---|---|---|---|
>| false | safe for tests | \ |  | 100 |  | true | TestSafe1 |



### cyberark-pas-safe-update
***
Update a single safe in the vault.


#### Base Command

`cyberark-pas-safe-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| safe_name | The name of the safe that will be updated. | Required | 
| description | The description of the updated safe. | Optional | 
| OLAC_enabled | Whether or not to enable Object Level Access Control (OLAC) for the updated<br/>safe. Valid values are: 'true' or 'false'. Default is 'true'. | Optional | 
| managing_cpm | The name of the Central Policy Manager (CPM) user who will manage the updated safe. | Optional | 
| number_of_versions_retention | The number of retained versions of every password that is stored in the updated safe. | Optional | 
| number_of_days_retention | The number of days for which password versions are saved in the updated safe. | Optional | 
| safe_new_name | The new name of the safe. | Optional | 
| location | The location of the updated safe. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.SafeName | String | The name of the updated safe. | 
| CyberArkPAS.Safes.Description | String | The description of the updated safe. | 
| CyberArkPAS.Safes.Location | String | The location of the updated safe. | 
| CyberArkPAS.Safes.ManagingCPM | String | The name of the Central Policy Manager \(CPM\) user who will manage the safe. | 
| CyberArkPAS.Safes.NumberOfDaysRetention | Number | The number of retained versions of every password that is stored in the updated safe. | 
| CyberArkPAS.Safes.NumberOfVersionsRetention | Number | The number of days for which password versions are saved in the updated safe. | 
| CyberArkPAS.Safes.OLACEnabled | Boolean | Whether or not to enable Object Level Access Control \(OLAC\) for the updated safe. | 


#### Command Example
```!cyberark-pas-safe-update safe_name=TestSafe1 safe_new_name=UpdatedName1 description=UpdatedSafe number_of_days_retention=150```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "AutoPurgeEnabled": false,
            "Description": "UpdatedSafe",
            "Location": "\\",
            "ManagingCPM": "",
            "NumberOfDaysRetention": 150,
            "NumberOfVersionsRetention": null,
            "OLACEnabled": true,
            "SafeName": "UpdatedName1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AutoPurgeEnabled|Description|Location|ManagingCPM|NumberOfDaysRetention|NumberOfVersionsRetention|OLACEnabled|SafeName|
>|---|---|---|---|---|---|---|---|
>| false | UpdatedSafe | \ |  | 150 |  | true | UpdatedName1 |



### cyberark-pas-safe-delete
***
Delete a safe from the vault.


#### Base Command

`cyberark-pas-safe-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| safe_name | The name of the safe that will be deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.Deleted | Boolean | Whether the safe was deleted. | 

#### Command Example
```!cyberark-pas-safe-delete safe_name=UpdatedName1```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "Deleted": true,
            "SafeName": "UpdatedName1"
        }
    }
}
```

#### Human Readable Output

>Safe UpdatedName1 was deleted


### cyberark-pas-safe-members-list
***
Return a list of the members of the safe.


#### Base Command

`cyberark-pas-safe-members-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| safe_name | The name of the safe whose safe members will be listed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.Members.MemberName | String | The names of the safe members. | 
| CyberArkPAS.Safes.Members.MembershipExpirationDate | Number | The expiration dates of the safe members. | 
| CyberArkPAS.Safes.Members.Permissions | Unknown | The permissions of the safe members. | 
| CyberArkPAS.Safes.Members.SearchIn | String | The vault or domain where the users or groups was found. | 


#### Command Example
```!cyberark-pas-safe-members-list safe_name=UpdatedName1```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "Members": [
                {
                    "IsExpiredMembershipEnable": false,
                    "IsPredefinedUser": true,
                    "MemberName": "Administrator",
                    "MemberType": "User",
                    "MembershipExpirationDate": null,
                    "Permissions": {
                        "AccessWithoutConfirmation": true,
                        "AddAccounts": true,
                        "BackupSafe": true,
                        "CreateFolders": true,
                        "DeleteAccounts": true,
                        "DeleteFolders": true,
                        "InitiateCPMAccountManagementOperations": true,
                        "ListAccounts": true,
                        "ManageSafe": true,
                        "ManageSafeMembers": true,
                        "MoveAccountsAndFolders": true,
                        "RenameAccounts": true,
                        "RequestsAuthorizationLevel1": true,
                        "RequestsAuthorizationLevel2": false,
                        "RetrieveAccounts": true,
                        "SpecifyNextAccountContent": true,
                        "UnlockAccounts": true,
                        "UpdateAccountContent": true,
                        "UpdateAccountProperties": true,
                        "UseAccounts": true,
                        "ViewAuditLog": true,
                        "ViewSafeMembers": true
                    }
                },
                {
                    "IsExpiredMembershipEnable": false,
                    "IsPredefinedUser": false,
                    "MemberName": "TestUser1",
                    "MemberType": "User",
                    "MembershipExpirationDate": null,
                    "Permissions": {
                        "AccessWithoutConfirmation": false,
                        "AddAccounts": false,
                        "BackupSafe": false,
                        "CreateFolders": false,
                        "DeleteAccounts": false,
                        "DeleteFolders": false,
                        "InitiateCPMAccountManagementOperations": false,
                        "ListAccounts": false,
                        "ManageSafe": false,
                        "ManageSafeMembers": false,
                        "MoveAccountsAndFolders": false,
                        "RenameAccounts": false,
                        "RequestsAuthorizationLevel1": false,
                        "RequestsAuthorizationLevel2": false,
                        "RetrieveAccounts": false,
                        "SpecifyNextAccountContent": false,
                        "UnlockAccounts": false,
                        "UpdateAccountContent": false,
                        "UpdateAccountProperties": false,
                        "UseAccounts": true,
                        "ViewAuditLog": false,
                        "ViewSafeMembers": false
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### There are 2 safe members for UpdatedName1
>|IsExpiredMembershipEnable|IsPredefinedUser|MemberName|MemberType|MembershipExpirationDate|Permissions|
>|---|---|---|---|---|---|
>| false | true | Administrator | User |  | UseAccounts: true<br/>RetrieveAccounts: true<br/>ListAccounts: true<br/>AddAccounts: true<br/>UpdateAccountContent: true<br/>UpdateAccountProperties: true<br/>InitiateCPMAccountManagementOperations: true<br/>SpecifyNextAccountContent: true<br/>RenameAccounts: true<br/>DeleteAccounts: true<br/>UnlockAccounts: true<br/>ManageSafe: true<br/>ManageSafeMembers: true<br/>BackupSafe: true<br/>ViewAuditLog: true<br/>ViewSafeMembers: true<br/>AccessWithoutConfirmation: true<br/>CreateFolders: true<br/>DeleteFolders: true<br/>MoveAccountsAndFolders: true<br/>RequestsAuthorizationLevel1: true<br/>RequestsAuthorizationLevel2: false |
>| false | false | TestUser1 | User |  | UseAccounts: true<br/>RetrieveAccounts: false<br/>ListAccounts: false<br/>AddAccounts: false<br/>UpdateAccountContent: false<br/>UpdateAccountProperties: false<br/>InitiateCPMAccountManagementOperations: false<br/>SpecifyNextAccountContent: false<br/>RenameAccounts: false<br/>DeleteAccounts: false<br/>UnlockAccounts: false<br/>ManageSafe: false<br/>ManageSafeMembers: false<br/>BackupSafe: false<br/>ViewAuditLog: false<br/>ViewSafeMembers: false<br/>AccessWithoutConfirmation: false<br/>CreateFolders: false<br/>DeleteFolders: false<br/>MoveAccountsAndFolders: false<br/>RequestsAuthorizationLevel1: false<br/>RequestsAuthorizationLevel2: false |


### cyberark-pas-safe-member-add
***
Add an existing user as a safe member.
Uses the V1 of the API and may change in the future.

#### Base Command

`cyberark-pas-safe-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| member_name | The name of the user to add as a safe member. | Required | 
| search_in | Search for the member in the vault or domain. | Optional | 
| membership_expiration_date | The membership expiration date in the format MM\DD\YY. Leave empty if there is no expiration date. | Optional | 
| permissions | The user’s permissions in the safe.<br/>Valid values: UseAccounts, RetrieveAccounts, ListAccounts, AddAccounts, UpdateAccountContent, UpdateAccountProperties, InitiateCPMAccountManagementOperations, InitiateCPMAccountManagementOperations, SpecifyNextAccountContent, RenameAccounts, DeleteAccounts, UnlockAccounts, ManageSafe, ManageSafeMembers, BackupSafe, ViewAuditLog, ViewAuditLog, ViewSafeMembers, AccessWithoutConfirmation, CreateFolders, DeleteFolders, MoveAccountsAndFolders<br/>e.g., UseAccounts,RetrieveAccounts | Optional | 
| safe_name | The name of the safe to add a member to. | Required | 
| requests_authorization_level | The request authorization levels.<br/>0 – cannot authorize<br/>1 – authorization level 1<br/>2 – authorization level 2<br/>Default is '0'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.Members.MemberName | String | The name of the safe member. | 
| CyberArkPAS.Safes.Members.MembershipExpirationDate | Number | The expiration date of the safe member. | 
| CyberArkPAS.Safes.Members.Permissions | Unknown | The permissions of the safe member. | 
| CyberArkPAS.Safes.Members.SearchIn | String | The vault or domain where the user or group was found. | 


#### Command Example
```!cyberark-pas-safe-member-add member_name="TestUser1" safe_name="UpdatedName1"```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "Members": {
                "MemberName": "TestUser1",
                "MembershipExpirationDate": "",
                "Permissions": [
                    {
                        "Key": "UseAccounts",
                        "Value": false
                    },
                    {
                        "Key": "RetrieveAccounts",
                        "Value": false
                    },
                    {
                        "Key": "ListAccounts",
                        "Value": false
                    },
                    {
                        "Key": "AddAccounts",
                        "Value": false
                    },
                    {
                        "Key": "UpdateAccountContent",
                        "Value": false
                    },
                    {
                        "Key": "UpdateAccountProperties",
                        "Value": false
                    },
                    {
                        "Key": "InitiateCPMAccountManagementOperations",
                        "Value": false
                    },
                    {
                        "Key": "SpecifyNextAccountContent",
                        "Value": false
                    },
                    {
                        "Key": "RenameAccounts",
                        "Value": false
                    },
                    {
                        "Key": "DeleteAccounts",
                        "Value": false
                    },
                    {
                        "Key": "UnlockAccounts",
                        "Value": false
                    },
                    {
                        "Key": "ManageSafe",
                        "Value": false
                    },
                    {
                        "Key": "ManageSafeMembers",
                        "Value": false
                    },
                    {
                        "Key": "BackupSafe",
                        "Value": false
                    },
                    {
                        "Key": "ViewAuditLog",
                        "Value": false
                    },
                    {
                        "Key": "ViewSafeMembers",
                        "Value": false
                    },
                    {
                        "Key": "AccessWithoutConfirmation",
                        "Value": false
                    },
                    {
                        "Key": "CreateFolders",
                        "Value": false
                    },
                    {
                        "Key": "DeleteFolders",
                        "Value": false
                    },
                    {
                        "Key": "MoveAccountsAndFolders",
                        "Value": false
                    },
                    {
                        "Key": "RequestsAuthorizationLevel",
                        "Value": 0
                    }
                ],
                "SearchIn": "vault"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|MemberName|MembershipExpirationDate|Permissions|SearchIn|
>|---|---|---|---|
>| TestUser1 |  | {'Key': 'UseAccounts', 'Value': False},<br/>{'Key': 'RetrieveAccounts', 'Value': False},<br/>{'Key': 'ListAccounts', 'Value': False},<br/>{'Key': 'AddAccounts', 'Value': False},<br/>{'Key': 'UpdateAccountContent', 'Value': False},<br/>{'Key': 'UpdateAccountProperties', 'Value': False},<br/>{'Key': 'InitiateCPMAccountManagementOperations', 'Value': False},<br/>{'Key': 'SpecifyNextAccountContent', 'Value': False},<br/>{'Key': 'RenameAccounts', 'Value': False},<br/>{'Key': 'DeleteAccounts', 'Value': False},<br/>{'Key': 'UnlockAccounts', 'Value': False},<br/>{'Key': 'ManageSafe', 'Value': False},<br/>{'Key': 'ManageSafeMembers', 'Value': False},<br/>{'Key': 'BackupSafe', 'Value': False},<br/>{'Key': 'ViewAuditLog', 'Value': False},<br/>{'Key': 'ViewSafeMembers', 'Value': False},<br/>{'Key': 'AccessWithoutConfirmation', 'Value': False},<br/>{'Key': 'CreateFolders', 'Value': False},<br/>{'Key': 'DeleteFolders', 'Value': False},<br/>{'Key': 'MoveAccountsAndFolders', 'Value': False},<br/>{'Key': 'RequestsAuthorizationLevel', 'Value': 0} | vault |


### cyberark-pas-safe-member-update
***
Update an existing safe member.
Uses the V1 of the API and may change in the future.

#### Base Command

`cyberark-pas-safe-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| member_name | The member name that will be updated. | Required | 
| membership_expiration_date | The membership expiration date in the format MM\DD\YY. Leave empty if there is no expiration date. | Optional | 
| permissions | The user’s permissions in the safe.<br/>Valid values are:<br/>UseAccounts, RetrieveAccounts, ListAccounts, AddAccounts, UpdateAccountContent, UpdateAccountProperties, InitiateCPMAccountManagementOperations, InitiateCPMAccountManagementOperations, SpecifyNextAccountContent, RenameAccounts, DeleteAccounts, UnlockAccounts, ManageSafe, ManageSafeMembers, BackupSafe, ViewAuditLog, ViewAuditLog, ViewSafeMembers, RequestsAuthorizationLevel, AccessWithoutConfirmation, CreateFolders, DeleteFolders, MoveAccountsAndFolders<br/>e.g., UseAccounts,RetrieveAccounts | Optional | 
| safe_name | The name of the safe to which the safe member belongs. | Required | 
| requests_authorization_level | Request authorization levels.<br/>0 – cannot authorize<br/>1 – authorization level 1<br/>2 – authorization level 2<br/>Default is: '0'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.Members.MemberName | String | The name of the safe member. | 
| CyberArkPAS.Safes.Members.MembershipExpirationDate | Number | The expiration date of the safe member. | 
| CyberArkPAS.Safes.Members.Permissions | Unknown | The permissions of the safe member. | 
| CyberArkPAS.Safes.Members.SearchIn | String | The vault or domain where the user or group was found. | 


#### Command Example
```!cyberark-pas-safe-member-update member_name="TestUser1" safe_name="UpdatedName1" permissions=UseAccounts```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "Members": {
                "MembershipExpirationDate": "",
                "Permissions": [
                    {
                        "Key": "UseAccounts",
                        "Value": true
                    },
                    {
                        "Key": "RetrieveAccounts",
                        "Value": false
                    },
                    {
                        "Key": "ListAccounts",
                        "Value": false
                    },
                    {
                        "Key": "AddAccounts",
                        "Value": false
                    },
                    {
                        "Key": "UpdateAccountContent",
                        "Value": false
                    },
                    {
                        "Key": "UpdateAccountProperties",
                        "Value": false
                    },
                    {
                        "Key": "InitiateCPMAccountManagementOperations",
                        "Value": false
                    },
                    {
                        "Key": "SpecifyNextAccountContent",
                        "Value": false
                    },
                    {
                        "Key": "RenameAccounts",
                        "Value": false
                    },
                    {
                        "Key": "DeleteAccounts",
                        "Value": false
                    },
                    {
                        "Key": "UnlockAccounts",
                        "Value": false
                    },
                    {
                        "Key": "ManageSafe",
                        "Value": false
                    },
                    {
                        "Key": "ManageSafeMembers",
                        "Value": false
                    },
                    {
                        "Key": "BackupSafe",
                        "Value": false
                    },
                    {
                        "Key": "ViewAuditLog",
                        "Value": false
                    },
                    {
                        "Key": "ViewSafeMembers",
                        "Value": false
                    },
                    {
                        "Key": "AccessWithoutConfirmation",
                        "Value": false
                    },
                    {
                        "Key": "CreateFolders",
                        "Value": false
                    },
                    {
                        "Key": "DeleteFolders",
                        "Value": false
                    },
                    {
                        "Key": "MoveAccountsAndFolders",
                        "Value": false
                    },
                    {
                        "Key": "RequestsAuthorizationLevel",
                        "Value": 0
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|MembershipExpirationDate|Permissions|
>|---|---|
>|  | {'Key': 'UseAccounts', 'Value': True},<br/>{'Key': 'RetrieveAccounts', 'Value': False},<br/>{'Key': 'ListAccounts', 'Value': False},<br/>{'Key': 'AddAccounts', 'Value': False},<br/>{'Key': 'UpdateAccountContent', 'Value': False},<br/>{'Key': 'UpdateAccountProperties', 'Value': False},<br/>{'Key': 'InitiateCPMAccountManagementOperations', 'Value': False},<br/>{'Key': 'SpecifyNextAccountContent', 'Value': False},<br/>{'Key': 'RenameAccounts', 'Value': False},<br/>{'Key': 'DeleteAccounts', 'Value': False},<br/>{'Key': 'UnlockAccounts', 'Value': False},<br/>{'Key': 'ManageSafe', 'Value': False},<br/>{'Key': 'ManageSafeMembers', 'Value': False},<br/>{'Key': 'BackupSafe', 'Value': False},<br/>{'Key': 'ViewAuditLog', 'Value': False},<br/>{'Key': 'ViewSafeMembers', 'Value': False},<br/>{'Key': 'AccessWithoutConfirmation', 'Value': False},<br/>{'Key': 'CreateFolders', 'Value': False},<br/>{'Key': 'DeleteFolders', 'Value': False},<br/>{'Key': 'MoveAccountsAndFolders', 'Value': False},<br/>{'Key': 'RequestsAuthorizationLevel', 'Value': 0} |



### cyberark-pas-safe-member-delete
***
Remove a specific member from a safe.
Uses the V1 of the API and may change in the future.

#### Base Command

`cyberark-pas-safe-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| safe_name | The name of the safe to delete a member from. | Required | 
| member_name | The name of the safe member to delete from the safe’s list of members. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Safes.Members.Deleted | Boolean | Whether the safe member was deleted. | 


#### Command Example
```!cyberark-pas-safe-member-delete member_name=TestUser1 safe_name=UpdatedName1```

#### Context Example
```
{
    "CyberArkPAS": {
        "Safes": {
            "Members": {
                "Deleted": true,
                "MemberName": "TestUser1"
            }
        }
    }
}
```

#### Human Readable Output

>Member TestUser1 was deleted from UpdatedName1 safe



### cyberark-pas-account-add
***
Add a new privileged account or SSH key to the vault.


#### Base Command

`cyberark-pas-account-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | The name of the account. | Required | 
| address | The name or address of the machine where the account will be used. | Required | 
| platform_id | The platform assigned to this account. | Required | 
| safe_name | The name of the safe where the account will be created. | Required | 
| secret_type | The type of password. Valid values are: 'password', 'key'. Default is 'password'. | Optional | 
| username | The The user name of the account. | Required | 
| password | The password that the user will use to log on for the first time. | Required | 
| properties | Object containing key-value pairs to associate with the account, as defined by the account platform.<br/>e.g., {"Location": "IT", "OwnerName": "MSSPAdmin"} | Optional | 
| automatic_management_enabled | Whether the account secret is automatically managed by the Central Policy Manager (CPM). Can be 'true' or 'false'. Default is 'true'. | Optional | 
| manual_management_reason | The reason for disabling automatic secret management. | Optional | 
| remote_machines | List of remote machines, separated by semicolons.<br/>e.g., server1.cyberark.com;server2.cyberark.com | Optional | 
| access_restricted_to_remote_machines | Whether or not to restrict access to specified remote machines only. Can be 'true' or 'false'. Default is: 'true'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Accounts.id | String | The unique ID of the account. | 
| CyberArkPAS.Accounts.categoryModificationTime | Number | The last modified date of the account. | 
| CyberArkPAS.Accounts.createdTime | Number | The date the account was created. | 
| CyberArkPAS.Accounts.name | String | The name of the account. | 
| CyberArkPAS.Accounts.platformId | String | The platform assigned to this account. | 
| CyberArkPAS.Accounts.safeName | String | The safe where the account is created. | 
| CyberArkPAS.Accounts.secretManagement | String | Whether the account secret is automatically managed by the CPM. | 
| CyberArkPAS.Accounts.secretType | String | The type of password. | 
| CyberArkPAS.Accounts.userName | String | The name of the account user. | 
| CyberArkPAS.Accounts.address | String | The name or address of the machine where the account will be used. | 


#### Command Example
```!cyberark-pas-account-add safe_name=TestSafe1 account_name=TestAccount1 address=/ password=12345Aa platform_id=WinServerLocal username=TestUser```

#### Context Example
```
{
    "CyberArkPAS": {
        "Accounts": {
            "address": "/",
            "categoryModificationTime": 1597863168,
            "createdTime": 1597863168,
            "id": "89_3",
            "name": "TestAccount1",
            "platformId": "WinServerLocal",
            "safeName": "TestSafe1",
            "secretManagement": {
                "automaticManagementEnabled": true,
                "lastModifiedTime": 1597848768
            },
            "secretType": "password",
            "userName": "TestUser"
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|categoryModificationTime|createdTime|id|name|platformId|safeName|secretManagement|secretType|userName|
>|---|---|---|---|---|---|---|---|---|---|
>| / | 1597863168 | 1597863168 | 89_3 | TestAccount1 | WinServerLocal | TestSafe1 | automaticManagementEnabled: true<br/>lastModifiedTime: 1597848768 | password | TestUser |


### cyberark-pas-account-delete
***
Delete a specific account in the vault.


#### Base Command

`cyberark-pas-account-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Accounts.Deleted | Boolean | Whether the safe was deleted. | 


#### Command Example
```!cyberark-pas-account-delete account_id= 89_3```

#### Context Example
```
{
    "CyberArkPAS": {
        "Accounts": {
            "Deleted": true,
            "id": "89_3"
        }
    }
}
```

#### Human Readable Output

> Account 89_3 was deleted




### cyberark-pas-account-update
***
Update the details of an existing account.


#### Base Command

`cyberark-pas-account-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account to update. | Required | 
| account_name | The name of the account to update. | Optional | 
| address | The name or address of the machine where the account will be used. | Optional | 
| platform_id | The platform assigned to this account. | Optional | 
| username | The user name of the account. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Accounts.id | String | The unique ID of the account. | 
| CyberArkPAS.Accounts.categoryModificationTime | Number | The last modified date of the account. | 
| CyberArkPAS.Accounts.createdTime | Number | The date the account was created. | 
| CyberArkPAS.Accounts.name | String | The name of the account. | 
| CyberArkPAS.Accounts.platformId | String | The platform assigned to this account. | 
| CyberArkPAS.Accounts.safeName | String | The safe where the account was created. | 
| CyberArkPAS.Accounts.secretManagement | String | Whether the account secret is automatically managed by the CPM. | 
| CyberArkPAS.Accounts.secretType | String | The type of password. | 
| CyberArkPAS.Accounts.userName | String | The user name of the account. | 
| CyberArkPAS.Accounts.address | String | The name or address of the machine where the account will be used. | 



#### Command Example
```!cyberark-pas-account-update account_id= 89_3 account_name=NewName```

#### Context Example
```
{
    "CyberArkPAS": {
        "Accounts": {
            "address": "/",
            "categoryModificationTime": 1597863168,
            "createdTime": 1597863168,
            "id": "89_3",
            "name": "NewName",
            "platformId": "WinServerLocal",
            "safeName": "TestSafe1",
            "secretManagement": {
                "automaticManagementEnabled": true,
                "lastModifiedTime": 1597848768
            },
            "secretType": "password",
            "userName": "TestUser"
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|categoryModificationTime|createdTime|id|name|platformId|safeName|secretManagement|secretType|userName|
>|---|---|---|---|---|---|---|---|---|---|
>| / | 1597863168 | 1597863168 | 89_3 | NewName | WinServerLocal | TestSafe1 | automaticManagementEnabled: true<br/>lastModifiedTime: 1597848768 | password | TestUser |





### cyberark-pas-accounts-list
***
Return a list of all the accounts in the vault.


#### Base Command

`cyberark-pas-accounts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | List of keywords to search for in the accounts.<br/>Separated with a space, e.g,. Windows admin | Optional | 
| sort | Property or properties by which to sort the returned accounts. <br/>The properties are followed by a comma and then 'asc' (default) or 'desc' to control the sort direction,<br/>e.g., Windows,asc | Optional | 
| offset | The offset of the first account that is returned in the collection of results. Default is '0'. | Optional | 
| limit | Maximum number of accounts in the returned list. Default is '50'. | Optional | 
| filter | Search for accounts filtered by a specific safe,<br/>e.g., safeName eq 'mySafe'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Accounts.id | String | The unique IDs of the accounts. | 
| CyberArkPAS.Accounts.categoryModificationTime | Number | Last modified dates of the accounts. | 
| CyberArkPAS.Accounts.createdTime | Number | Date the account was created. | 
| CyberArkPAS.Accounts.name | String | The names of the accounts. | 
| CyberArkPAS.Accounts.platformId | String | The platforms assigned to these accounts. | 
| CyberArkPAS.Accounts.safeName | String | The safes where the accounts were created. | 
| CyberArkPAS.Accounts.secretManagement | String | Whether the accounts secrets were automatically managed by the CPM. | 
| CyberArkPAS.Accounts.secretType | String | The type of passwords. | 
| CyberArkPAS.Accounts.userName | String | The user names of the accounts. | 
| CyberArkPAS.Accounts.address | String | The names or addresses of the machine where the accounts are used. | 


#### Command Example
```!cyberark-pas-accounts-list limit=2```

#### Context Example
```
{
    "CyberArkPAS": {
        "Accounts": [
            {
                "address": "string",
                "categoryModificationTime": 1594569595,
                "createdTime": 1594573679,
                "id": "2_6",
                "name": "account1",
                "platformAccountProperties": {},
                "platformId": "Oracle",
                "safeName": "VaultInternal",
                "secretManagement": {
                    "automaticManagementEnabled": true,
                    "lastModifiedTime": 159459279
                },
                "secretType": "password",
                "userName": "string"
            },
            {
                "address": "string",
                "categoryModificationTime": 1583345933,
                "createdTime": 157312750,
                "id": "2_3",
                "name": "cybr",
                "platformAccountProperties": {},
                "platformId": "WinDomain",
                "safeName": "VaultInternal",
                "secretManagement": {
                    "automaticManagementEnabled": false,
                    "lastModifiedTime": 157319750,
                    "manualManagementReason": "NoReason"
                },
                "secretType": "password",
                "userName": "vault"
            }
        ]
    }
}
```

#### Human Readable Output

>### There are 2 accounts
>|address|categoryModificationTime|createdTime|id|name|platformAccountProperties|platformId|safeName|secretManagement|secretType|userName|
>|---|---|---|---|---|---|---|---|---|---|---|
>| string | 1594569595 | 1594573679 | 2_6 | account1 |  | Oracle | VaultInternal | automaticManagementEnabled: true<br/>lastModifiedTime: 1594559279 | password | string |
>| string | 1583345933 | 1573127750 | 2_3 | cybr|  | WinDomain | VaultInternal | automaticManagementEnabled: false<br/>manualManagementReason: NoReason<br/>lastModifiedTime: 1573109750 | password | vault |



### cyberark-pas-account-get-list-activity
***
Returns the activities of a specific account that is identified by its account ID.


#### Base Command

`cyberark-pas-account-get-list-activity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The ID of the account whose activities will be retrieved. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Activities.Action | String | The activity that was performed. | 
| CyberArkPAS.Activities.ActionID | Number | The code identification of the specific activity. | 
| CyberArkPAS.Activities.Alert | Boolean | Whether or not the activity caused an alert. | 
| CyberArkPAS.Activities.ClientID | String | The name of the account. | 
| CyberArkPAS.Activities.Date | Number | The date the account was created. | 
| CyberArkPAS.Activities.MoreInfo | String | More information about the activity. | 
| CyberArkPAS.Activities.Reason | String | The reason given by the user for the activity. | 
| CyberArkPAS.Activities.User | String | The user who performed the activity. | 


#### Command Example
```!cyberark-pas-account-get-list-activity account_id= 89_3```

#### Context Example
```
{
    "CyberArkPAS": {
        "Activities": [
            {
                "Action": "Rename File",
                "ActionID": 124,
                "Alert": false,
                "ClientID": "1",
                "Date": 1597863265,
                "MoreInfo": "NewName",
                "Reason": "",
                "User": "Administrator"
            },
            {
                "Action": "Add File Category",
                "ActionID": 105,
                "Alert": false,
                "ClientID": "1",
                "Date": 1597863168,
                "MoreInfo": "CreationMethod",
                "Reason": "Value=[ABC]",
                "User": "Administrator"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Action|ActionID|Alert|ClientID|Date|MoreInfo|Reason|User|
>|---|---|---|---|---|---|---|---|
>| Rename File | 124 | false | 1 | 1597863265 | NewName |  | Administrator |
>| Add File Category | 105 | false | 1 | 1597863168 | CreationMethod | Value=[ABC] | Administrator |


### cyberark-pas-account-get-details
***
Returns information for the specified account, identified by the account ID.


#### Base Command

`cyberark-pas-account-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The ID of the account for which to retrieve information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.Accounts.id | String | The unique ID of the account. | 
| CyberArkPAS.Accounts.categoryModificationTime | Number | The date the account was last modified. | 
| CyberArkPAS.Accounts.createdTime | Number | The date the account was created. | 
| CyberArkPAS.Accounts.name | String | The name of the account. | 
| CyberArkPAS.Accounts.platformId | String | The platform assigned to this account. | 
| CyberArkPAS.Accounts.safeName | String | The safe where the account is created. | 
| CyberArkPAS.Accounts.secretManagement | String | Whether the account secret is automatically managed by the CPM. | 
| CyberArkPAS.Accounts.secretType | String | The type of password. | 
| CyberArkPAS.Accounts.userName | String | The name of the account user. | 
| CyberArkPAS.Accounts.address | String | The name or address of the machine where the account will be used. | 


#### Command Example
```!cyberark-pas-account-get-details account_id=46_7```

#### Context Example
```
{
    "CyberArkPAS": {
        "Accounts": {
            "address": "address.com",
            "categoryModificationTime": 1597581174,
            "createdTime": 1595431869,
            "id": "46_7",
            "name": "Operating System-UnixSSH",
            "platformAccountProperties": {
                "Tags": "SSH",
                "UseSudoOnReconcile": "No"
            },
            "platformId": "UnixSSH",
            "safeName": "Linux Accounts",
            "secretManagement": {
                "automaticManagementEnabled": true,
                "lastModifiedTime": 1595417469,
                "lastReconciledTime": 1576120341,
                "status": "success"
            },
            "secretType": "password",
            "userName": "user1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|categoryModificationTime|createdTime|id|name|platformAccountProperties|platformId|safeName|secretManagement|secretType|userName|
>|---|---|---|---|---|---|---|---|---|---|---|
>| address | 1597581174 | 1595431869 | 46_7 | Operating System-UnixSSH | UseSudoOnReconcile: No<br/>Tags: SSH | UnixSSH | Linux Accounts | automaticManagementEnabled: true<br/>status: success<br/>lastModifiedTime: 1595417469<br/>lastReconciledTime: 1576120341 | password | user1 |



### cyberark-pas-credentials-change-in-vault-only
***
Enable users to set account credentials and change them in the vault.


#### Base Command

`cyberark-pas-credentials-change-in-vault-only`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account. | Required | 
| new_credentials | The new account credentials that will be allocated to the account in the vault. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-pas-credentials-change-in-vault-only account_id=89_4 new_credentials=1234Asw```


#### Human Readable Output

>The password in the account 89_4 was changed




### cyberark-pas-credentials-verify
***
Mark an account for verification by the Central Policy Manager (CPM).


#### Base Command

`cyberark-pas-credentials-verify`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-pas-credentials-verify account_id=89_4```


#### Human Readable Output

>The account 89_4 was marked for verification by the CPM




### cyberark-pas-credentials-reconcile
***
Mark an account for automatic reconciliation by the Central Policy Manager (CPM).


#### Base Command

`cyberark-pas-credentials-reconcile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-pas-credentials-reconcile account_id=89_4```


#### Human Readable Output

>The account 89_4 was marked for automatic reconciliation by the CPM.




### cyberark-pas-credentials-change-random-password
***
Mark an account for an immediate credentials change by the CPM to a new random value.


#### Base Command

`cyberark-pas-credentials-change-random-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-pas-credentials-change-random-password account_id=89_4```


#### Human Readable Output

>The password in the account 89_4 was changed





### cyberark-pas-credentials-change-set-new-password
***
Enable users to set the account's credentials to use for the next Central Policy Manager (CPM) change.


#### Base Command

`cyberark-pas-credentials-change-set-new-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique ID of the account. | Required | 
| new_credentials | The new account credentials that will be allocated to the account in the vault. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cyberark-pas-credentials-change-set-new-password account_id=89_4```


#### Human Readable Output

>The password in the account 89_4 was changed





### cyberark-pas-security-events-get
***
Return all Privileged Threat Analytics (PTA) security events.


#### Base Command

`cyberark-pas-security-events-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The starting date to get the security events from. Must be in the following timestamp format:<br/>(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year). | Required | 
| limit | The number of events that will be shown, from newest to oldest. Default is '50'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberArkPAS.SecurityEvents.id | Number | The unique ID of the security events. | 
| CyberArkPAS.SecurityEvents.additionalData | String | Additional data about the security events. | 
| CyberArkPAS.SecurityEvents.audits.createTime | Number | The time the security events were created. | 
| CyberArkPAS.SecurityEvents.lastUpdateTime | Number | The last update time of the security events. | 
| CyberArkPAS.SecurityEvents.mStatus | String | The status of the security events. | 
| CyberArkPAS.SecurityEvents.score | Number | The score of the security events. | 
| CyberArkPAS.SecurityEvents.type | String | The type of the security events. | 


#### Command Example
```!cyberark-pas-security-events-get start_time="3 days" limit=2```

#### Context Example
```
{
    "CyberArkPAS": {
        "SecurityEvents": [
            {
                "additionalData": {
                    "reason": "ip",
                    "station": "1.1.1.1",
                    "vault_user": "administrator"
                },
                "audits": [
                    {
                        "action": "Logon",
                        "cloudData": {},
                        "createTime": 1597864497000,
                        "id": "1a2b3c4d",
                        "sensorType": "VAULT",
                        "source": {
                            "mOriginalAddress": "1.1.1.1",
                            "mResolvedAddress": {
                                "mAddress": "1.1.1.1",
                                "mFqdn": "1-2-3-4",
                                "mHostName": "1-2-3-4",
                                "mOriginalAddress": "1.1.1.1",
                            }
                        },
                        "type": "VAULT_LOGON",
                        "vaultUser": "Administrator"
                    }
                ],
                "createTime": 1597864497000,
                "id": "1",
                "lastUpdateTime": 1597864497000,
                "mStatus": "OPEN",
                "score": 25.751749103263528,
                "type": "VaultViaIrregularIp"
            },
            {
                "additionalData": {
                    "reason": "ip",
                    "station": "1.1.1.1",
                    "vault_user": "administrator"
                },
                "audits": [
                    {
                        "action": "Logon",
                        "cloudData": {},
                        "createTime": 1597864209000,
                        "id": "5f3d7911e4b0b8d4ac363b1b",
                        "sensorType": "VAULT",
                        "source": {
                            "mOriginalAddress": "1.1.1.1",
                            "mResolvedAddress": {
                                "mAddress": "1.1.1.1",
                                "mFqdn": "1-2-3-4",
                                "mHostName": "1-2-3-4",
                                "mOriginalAddress": "1.1.1.1",
                            }
                        },
                        "type": "VAULT_LOGON",
                        "vaultUser": "Administrator"
                    }
                ],
                "createTime": 1597864209000,
                "id": "2",
                "lastUpdateTime": 1597864209000,
                "mStatus": "OPEN",
                "score": 25.751749103263528,
                "type": "VaultViaIrregularIp"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|additionalData|audits|createTime|id|lastUpdateTime|mStatus|score|type|
>|---|---|---|---|---|---|---|---|
>| station: 1.1.1.1<br/>reason: ip<br/>vault_user: administrator | {'id': '1', 'type': 'VAULT_LOGON', 'sensorType': 'VAULT', 'action': 'Logon', 'createTime': 1597864497000, 'vaultUser': 'Administrator', 'source': {'mOriginalAddress': '1.1.1.1', 'mResolvedAddress': {'mOriginalAddress': '1.1.1.1', 'mAddress': '1.1.1.1', 'mHostName': '1-2-3-4', 'mFqdn': '1-2-3-4'}}, 'cloudData': {}} | 1597864497000 | 1 | 1597864497000 | OPEN | 25.751749103263528 | VaultViaIrregularIp |
>| station: 1.1.1.1<br/>reason: ip<br/>vault_user: administrator | {'id': '2', 'type': 'VAULT_LOGON', 'sensorType': 'VAULT', 'action': 'Logon', 'createTime': 1597864209000, 'vaultUser': 'Administrator', 'source': {'mOriginalAddress': '1.1.1.1', 'mResolvedAddress': {'mOriginalAddress': '1.1.1.1', 'mAddress': '1.1.1.1', 'mHostName': '1-2-3-4', 'mFqdn': '1-2-3-4'}}, 'cloudData': {}} | 1597864209000 | 2 | 1597864209000 | OPEN | 25.751749103263528 | VaultViaIrregularIp |

