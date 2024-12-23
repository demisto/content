The Active Directory Query integration enables you to access and manage Active Directory objects (users, contacts, and computers).
This integration was integrated and tested with version 1.5.0 of Active Directory Query v2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---active-directory-query-v2).

Use Cases
---------

##### Query for Active Directory objects

* Use the `!ad-search` command to run a query for Active Directory objects (users, contacts, computers, and so on). This command enables you to determine which data fields should be returned for the objects.
##### Manage users and contacts

* The integration enables you to create, update, and delete users and contacts in Active Directory using the following commands:
    + `ad-create-user`
    + `ad-create-contact`
    + `ad-update-user`
    + `ad-update-contact`
    + `ad-delete-user` (to delete both users and contacts)

* Add or remove users from groups using the following commands:
    + `ad-add-to-group`
    + `ad-remove-from-group`

* Enable or disable a user account using the following commands:
    + `ad-enable-account`
    + `ad-disable-user-account`

##### Manage Computers

* Modify a computer organizational unit using the ‘ad-modify-computer-ou’ command.
* Add or remove a computer from a group using the following commands:
    + `ad-add-to-group`
    + `ad-remove-from-group`

##### IAM premium pack uses

* Create or modify Active Directory users.
* Manage user accounts and their status

## Configure Active Directory Query v2 in Cortex


| **Parameter** | **Description**                                                                                  | **Required** |
|--------------------------------------------------------------------------------------------------| --- | --- |
| Server IP address (for example, 192.168.0.1) | The Server IP that should be used to access Active Directory.                                    | True |
| Port  | Server port. If not specified, the default port is 389 for LDAP, 636 for LDAPS, or 3268 for global catalog servers.                        | False |
| Credentials | User credentials.                                                                                                 | True |
| Password |                                                                                                  | True |
| NTLM authentication | Indicates whether to use NTLM authentication.                                                                                                 | False |
| Base DN (for example "dc=company,dc=com") | The basic hierarchical path of objects in the active directory.                                                                                                 | True |
| Page size | The number of results to be returned, per page (page - response content from AD server), from a query. This may effect query run time.                                                                                                 | True |
| Secure Connection |  Use SSL or Start TLS for secure connection or ‘None’ for communication over clear-text.                                                                                                | True |
| SSL Version | The SSL\TLS version to use in SSL or Start TLS connections types. It is recommended to select the TLS_CLIENT option, which auto-negotiate the highest protocol version that both the client and server support, and configure the context client-side connections. For more information please see: [ssl.PROTOCOLS](https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS_CLIENT)). | False |
| Trust any certificate (not secure) | Select to avoid server certification validation. You may want to do this in case Cortex XSOAR cannot validate the integration server certificate (due to a missing CA certificate)                                                                                                 | False |
| Incoming Mapper | Used in the IAM commands.                                                                        | True |
| Outgoing Mapper | Used in the IAM commands.                                                                        | True |
| Group CN for terminated employees |                                                                                                  | False |
| Create user if does not exist | If true, the user is created if the user profile doesn't exist in AD. Used in IAM commands only. | False |

> <i>Note:</i> For queries and operations across multiple domains within an Active Directory forest the server port should be 3268. This port is used for queries specifically targeted for the global catalog. LDAP requests sent to port 3268 can be used to search for objects in the entire Active Directory forest. For more information on global catalog see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-global-catalog-server-placement).

##### Identity Lifecycle Management premium pack configuration

The premium ILM content pack introduces new functionality that uses both an incoming and an outgoing mapper.

1. Configure the "Incoming Mapper" with the name of the incoming mapper that you're using. ILM's default mapper is "User Profile - Active Directory (Incoming)".
2. Configure the "Outgoing Mapper" with the name of the outgoing mapper that you're using. ILM's default mapper is "User Profile - Active Directory (Outgoing)".

> <i>Note:</i> As part of the configuration of the mapper, you must map a value to the OU (organizational unit) required field. To do this, create a transformer that maps a user attribute of your choice to an OU value.

To allow the integration to access the mapper from within the code, as required by the ILM pack, both mappers have to be configured in their proper respective fields and *not* in the "Mapper (outgoing)" dropdown list selector.


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ad-expire-password
***
Expires the password of an Active Directory user.


#### Base Command

`ad-expire-password`

##### Required Permissions
Requires `Reset user passwords and force password change at next logon` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required | 
| base-dn | Root (for example, DC=domain,DC=com). | Optional | 


#### Context Output

There is no context output for this command.


### ad-modify-password-never-expire
***
Modifies the AD account attribute "Password Never Expire".


#### Base Command

`ad-modify-password-never-expire`

##### Required Permissions
Requires `Read userAccountControl` and `write userAccountControl` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The sAMAccountName of the user to modify. | Required | 
| value | Value to set "Password Never Expire". Possible values are: true, false. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-modify-password-never-expire username=jack value=true
```
##### Human Readable Output
```
AD account jack has set "password never expire" attribute. Value is set to True
```

### ad-create-user
***
Creates an Active Directory user. This command requires a secure connection (SSL,TLS).


#### Base Command

`ad-create-user`

##### Required Permissions
Requires `Create, delete, and manage user accounts` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required | 
| password | The initial password to set for the user. The user is requested to change the password after login. | Required | 
| user-dn | The user DN. | Required | 
| display-name | The user display name. | Optional | 
| description | A short description of the user. | Optional | 
| email | The user email. | Optional | 
| telephone-number | The user telephone number. | Optional | 
| title | The user job title. | Optional | 
| custom-attributes | Sets basic or custom attributes of the user object. For example, custom-attributes="{\"notes\":\"a note about the contact\",\"company\":\"company name\"}". | Optional | 


#### Context Output

There is no context output for this command.


##### Command Example
```
ad-create-user username="jack" password="1q2w3e4r!" user-dn="cn=jack,dc=demisto,dc=int" display-name="Samurai Jack"
```
##### Human Readable Output
```
Created user with DN: cn=jack,dc=demisto,dc=int
```

### ad-search
***
Runs Active Directory queries.

For more information on the query syntax see the [Microsoft documentation](https://docs.microsoft.com/en-us/windows/desktop/adsi/search-filter-syntax).

For more information on LDAP filters, see the [LDAP documentation](https://ldap.com/ldap-filters/).

#### Base Command

`ad-search`

##### Required Permissions
Requires `Read` and `Read and read all properties` permissions in `General` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| filter            | Enables you to define search criteria in the Query Active Directory using Active Directory syntax. For example, the following query searches for all user objects except Andy: "(&amp;(objectCategory=person)(objectClass=user)(!(cn=andy)))". Note: If you have special characters such as "*","(",or "\" the character must be preceded by two backslashes "\\". For example, to use "*", type "\\*". For more information about search filters, see syntax: https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax. | Required | 
| base-dn           | Root. For example, DC=domain,DC=com). By default, the Base DN configured for the instance is used. | Optional | 
| attributes        | A CSV list of the object attributes to return. For example, "dn,memberOf". To return all object attributes, specify 'ALL'. | Optional | 
| size-limit        | The maximum number of records to return. Default is 50. | Optional | 
| time-limit        | The maximum time to pull records (in seconds). | Optional | 
| context-output    | Whether to output the search results to the context. Possible values are: yes, no. Default is yes. | Optional | 
| page-size         | The page size to query. The size-limit value will be ignored. | Optional | 
| page-cookie       | An opaque string received in a paged search, used for requesting subsequent entries. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Search.dn | string | The distinguished names that match the query. | 
| ActiveDirectory.Search | unknown | The result of the search. | 
| ActiveDirectory.SearchPageCookie | string | An opaque string received in a paged search, used for requesting subsequent entries. | 

##### Command Example
```
ad-search filter="(&(objectCategory=person)(objectClass=user)(!(cn=andy)))"
```

##### Context Example
```
{
    "ActiveDirectory.Search": [
        {
            "dn": "CN=demistoadmin,CN=Users,DC=demisto,DC=int"
        },
        {
            "dn": "CN=Guest,CN=Users,DC=demisto,DC=int"
        }
    ]
}
```

##### Human Readable Output
>### Active Directory Search
>|dn|
>|---|
>| CN=demistoadmin,CN=Users,DC=demisto,DC=int |
>| CN=Guest,CN=Users,DC=demisto,DC=int  |

### ad-add-to-group

***
Adds an Active Directory user or computer to a group.

#### Base Command

`ad-add-to-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to add to the group. If this argument is not specified, the computer name argument must be specified.\n Supports single or comma delimited list of usernames. | Optional | 
| computer-name | The name of the computer to add to the group. If this argument is not specified, the username argument must be specified. | Optional | 
| group-cn | The name of the group to add the user to. | Required | 
| base-dn | Root. For example, DC=domain,DC=com. By default, the Base DN configured for the instance is used. | Optional | 
| nested_group_cn | The name of the group to add as a member of the group specified group-cn. | Optional | 

#### Context Output

There is no context output for this command.
### ad-remove-from-group
***
Removes an Active Directory user or computer from a group.
#### Base Command

`ad-remove-from-group`

##### Required Permissions
Requires `Create, delete, and manage groups` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The name of the user to remove from the group. If this argument is not specified, the computer name argument must be specified. | Optional | 
| computer-name | The name of the computer to remove from the group. If this argument is not specified, the username argument must be specified. | Optional | 
| group-cn | The name of the group to remove the user from. | Required | 
| base-dn | Root. For example, DC=domain,DC=com). By default, the Base DN configured for the instance is used. | Optional | 

#### Context Output

There is no context output for this command.

##### Command Example
```
ad-remove-from-group username="jack" group-cn="Users"
```

##### Human Readable Output
```
Object with dn CN=jack,DC=demisto,DC=int removed from group Users
```

### ad-update-user
***
Updates attributes of an existing Active Directory user.


#### Base Command

`ad-update-user`

##### Required Permissions
Requires `Write All Properties` and `Read All Properties` permission from `User objects`.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to update (sAMAccountName). | Required | 
| attribute-name | The name of the attribute to modify. For example, sn, displayName, mail, and so on. | Required | 
| attribute-value | The value to change the attribute to. | Required | 
| base-dn | Root. For example, DC=domain,DC=com. By default, the Base DN configured for the instance is used. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-update-user attribute-name=description attribute-value=Samurai username=jack
```

##### Human Readable Output
```
Updated user's description to Samurai
```

### ad-delete-user
***
Deletes an Active Directory user.

#### Base Command

`ad-delete-user`

##### Required Permissions
Requires `Create, delete, and manage user accounts` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-dn | The DN of the user to delete. | Required | 

#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-delete-user user-dn="cn=jack,dc=demisto,dc=int"
```

##### Human Readable Output
```
Deleted object with dn cn=jack,dc=demisto,dc=int
```

### ad-create-contact
***
Creates an Active Directory contact.


#### Base Command

`ad-create-contact`

##### Required Permissions
Requires `full control` permission from `Contact objects`.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact-dn | The contact DN. | Required | 
| display-name | The contact display name. | Optional | 
| description | The short description of the contact. | Optional | 
| email | The email address of the contact. | Optional | 
| telephone-number | The contact telephone number. | Optional | 
| custom-attributes | Sets basic or custom attributes of the contact object. For example, custom-attributes="{\"notes\":\"some note about the contact\",\"company\":\"some company\"}.". | Optional | 
| title | The contact job title. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-create-contact contact-dn="cn=jack,dc=demisto,dc=int" description="Samurai" email=jack@company.com
```

##### Human Readable Output
```
Created contact with DN: cn=jack,dc=demisto,dc=int
```

### ad-update-contact
***
Updates attributes of an existing Active Directory contact.


#### Base Command

`ad-update-contact`

##### Required Permissions
Requires `Write All Properties` and `Read All Properties` permission from `Contact objects`.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact-dn | The contact DN. | Required | 
| attribute-name | The attribute name to update. | Required | 
| attribute-value | The attribute value to update. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
```
ad-update-contact contact-dn="cn=Jack,dc=demisto,dc=int" attribute-name="displayName" attribute-value="Jack H."
```

##### Human Readable Output
```
Updated contact’s displayName to: Jack H.
```

### ad-disable-account
***
Disables an Active Directory user account.


#### Base Command

`ad-disable-account`

##### Required Permissions
Requires `Read userAccountControl` and `write userAccountControl` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to disable (sAMAccountName). | Required | 
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance is used. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
ad-disable-account username="jack"
```

##### Human Readable Output
```
User “CN=jack,DC=demisto,DC=int” has been disabledUser jack was disabled
```

### ad-enable-account
***
Enables a previously disabled Active Directory account.


#### Base Command

`ad-enable-account`

##### Required Permissions
Requires `Read userAccountControl` and `write userAccountControl` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to enable (sAMAccountName). | Required | 
| base-dn | Root. For example, DC=domain,DC=com). By default, the Base DN configured for the instance is used. | Optional | 
| restore_user | If true, the command will enable the user with his restored options. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
ad-enable-account username="jack"
```

##### Human Readable Output
```
User jack was enabledUser “CN=jack,DC=demisto,DC=int” has been enabled
```

### ad-unlock-account
***
Unlocks a previously locked Active Directory user account.


#### Base Command

`ad-unlock-account`

##### Required Permissions
Requires `Read lockoutTime` and `write lockoutTime` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to unlock (sAMAccountName). | Required | 
| base-dn | Root. For example, DC=domain,DC=com. By default, the Base DN configured for the instance is used. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-unlock-account username=mooncake
```

##### Human Readable Output
```
User "CN=mooncake,CN=Users,DC=demisto,DC=int" has been unlocked
```

### ad-set-new-password
***
Sets a new password for an Active Directory user. This command requires a secure connection (SSL,TLS).

#### Base Command

`ad-set-new-password`

##### Required Permissions
Requires `Reset password` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to disable (sAMAccountName). | Required | 
| password | The password to set for the user. | Required | 
| base-dn | Root. For example, DC=domain,DC=com. Base DN configured for the instance is used as default. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-set-new-password username="NoaCo" password="noni1q2w3e!"
```

##### Human Readable Output
```
User password successfully set
```

### ad-modify-computer-ou
***
Modifies the computer organizational unit within a domain.

#### Base Command

`ad-modify-computer-ou`

##### Required Permissions
Requires `Write All Properties` permission from `Computer objects`.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer-name | The name of the computer to modify. | Required | 
| full-superior-dn | Superior DN. For example, OU=computers,DC=domain,DC=com (the specified domain must be the same as the current computer domain). | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-modify-computer-ou computer-name=mike full-superior-dn=OU=Sarah,DC=demisto,DC=int
```

##### Human Readable Output
```
"mike" was successfully moved to "OU=Sarah,DC=demisto,DC=int"
```

### ad-modify-user-ou
***
Modifies the user organizational unit within a domain.

#### Base Command

`ad-modify-user-ou`

##### Required Permissions
Requires `Write All Properties` permission from `Computer objects`.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-name | The name of the user to modify. | Required | 
| full-superior-dn | Superior DN. For example, OU=users,DC=domain,DC=com (the specified domain must be the same as the current user domain). | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example
```
!ad-modify-user-ou user-name=username full-superior-dn=OU=users,DC=demisto,DC=int
```

##### Human Readable Output
```
"username" was successfully moved to "OU=users,DC=demisto,DC=int"
```

### ad-get-user
***
Retrieves detailed information about a user account. The user can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filter is specified, all users are returned.

#### Base Command

`ad-get-user`

##### Required Permissions
Requires `Read all user information` permissions.

#### Input

| **Argument Name** | **Description**                                                                                                                            | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------| --- |
| dn | The Distinguished Name of the user in which to return information.                                                                         | Optional | 
| name | The name of the user to return information.                                                                                                | Optional | 
| attributes | Adds AD attributes of the resulting objects to the default attributes.                                                                     | Optional | 
| attributes-to-exclude | Removes AD attributes of the resulting objects from the attributes.                                                                | Optional | 
| custom-field-type | Queries users by custom field type.                                                                                                        | Optional | 
| custom-field-data | Queries users by custom field data (relevant only if the `custom-field-type` argument is provided).                                        | Optional | 
| username | Queries users by the samAccountName attribute.                                                                                             | Optional | 
| sAMAccountName | Queries users by the samAccountName attribute.                                                                                             | Optional | 
| limit | The maximum number of objects to return. Default is 20.                                                                                    | Optional | 
| email | Queries by the user's email address.                                                                                                       | Optional | 
| user-account-control-out | Whether to include verbose translation for UserAccountControl flags. Default is false. Possible values are: true, false. Default is false. | Optional | 
| page-size | The page size to query. The limit value will be ignored.                                                                                             | Optional | 
| page-cookie | An opaque string received in a paged search, used for requesting subsequent entries.                                                       | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Users.dn | string | The user distinguished name. | 
| ActiveDirectory.Users.displayName | string | The user display name. | 
| ActiveDirectory.Users.name | string | The user common name. | 
| ActiveDirectory.Users.sAMAccountName | string | The user sAMAccountName. | 
| ActiveDirectory.Users.userAccountControl | number | The user account control flag. | 
| ActiveDirectory.Users.mail | string | The user email address. | 
| ActiveDirectory.Users.manager | string | The manager of the user. | 
| ActiveDirectory.Users.memberOf | string | Groups in which the user is a member. | 
| ActiveDirectory.Users.userAccountControlFields.SCRIPT | bool | Whether the login script is run. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.ACCOUNTDISABLE | bool | Whether the user account is disabled. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.HOMEDIR_REQUIRED | bool | Whether the home folder is required. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.LOCKOUT | bool | Whether the user is locked out. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.PASSWD_NOTREQD | bool | Whether the password is required. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.PASSWD_CANT_CHANGE | bool | Whether the user can change the password. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.ENCRYPTED_TEXT_PWD_ALLOWED | bool | Whether the user can send an encrypted password. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.TEMP_DUPLICATE_ACCOUNT | bool | Whether this is an account for users whose primary account is in another domain. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.NORMAL_ACCOUNT | bool | Whether this is a default account type that represents a typical user. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.INTERDOMAIN_TRUST_ACCOUNT | bool | Whether the account is permitted to trust a system domain that trusts other domains. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.WORKSTATION_TRUST_ACCOUNT | bool | Whether this is a computer account for a computer running Microsoft Windows NT 4.0 Workstation, Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional, or Windows 2000 Server and is a member of this domain. | 
| ActiveDirectory.Users.userAccountControlFields.SERVER_TRUST_ACCOUNT | bool | Whether this is a computer account for a domain controller that is a member of this domain. Works for \*Windows Server 2012 R2\*. | 
| ActiveDirectory.Users.userAccountControlFields.DONT_EXPIRE_PASSWORD | bool | Whether to never expire the password on the account. | 
| ActiveDirectory.Users.userAccountControlFields.MNS_LOGON_ACCOUNT | bool | Whether this is an MNS login account. | 
| ActiveDirectory.Users.userAccountControlFields.SMARTCARD_REQUIRED | bool | Whether to force the user to log in by using a smart card. | 
| ActiveDirectory.Users.userAccountControlFields.TRUSTED_FOR_DELEGATION | bool | Whether the service account \(the user or computer account\) under which a service runs is trusted for Kerberos delegation. | 
| ActiveDirectory.Users.userAccountControlFields.NOT_DELEGATED | bool | Whether the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation. | 
| ActiveDirectory.Users.userAccountControlFields.USE_DES_KEY_ONLY | bool | Whether to restrict this principal to use only Data Encryption Standard \(DES\) encryption types for keys. | 
| ActiveDirectory.Users.userAccountControlFields.DONT_REQ_PREAUTH | bool | Whether this account require Kerberos pre-authentication for logging on. | 
| ActiveDirectory.Users.userAccountControlFields.PASSWORD_EXPIRED | bool | Whether the user password expired. | 
| ActiveDirectory.Users.userAccountControlFields.TRUSTED_TO_AUTH_FOR_DELEGATION | bool | Whether the account is enabled for delegation. | 
| ActiveDirectory.Users.userAccountControlFields.PARTIAL_SECRETS_ACCOUNT | bool | Whether the account is a read-only domain controller \(RODC\). | 
| ActiveDirectory.UsersPageCookie | string | An opaque string received in a paged search, used for requesting subsequent entries. | 
| Account.DisplayName | string | The user display name. | 
| Account.Groups | string | Groups for which the user is a member. | 
| Account.Manager | string | The user manager. | 
| Account.ID | string | The user distinguished name. | 
| Account.Username | string | The user samAccountName. | 
| Account.Email | string | The user email address. | 

##### Command Example
```
!ad-get-user name=*
```

##### Human Readable Output

>### Active Directory - Get Users
>|dn|displayName|mail|manager|memberOf|name|sAMAccountName|userAccountControl|
>|---|---|---|---|---|---|---|---|
>| CN=demistoadmin,CN=Users,DC=demisto,DC=int | demistoadmin | demistoadmin@demisto.int |  | CN=Discovery Management,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int,CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int,CN=Group Policy Creator Owners,CN=Users,DC=demisto,DC=int,CN=Domain Admins,CN=Users,DC=demisto,DC=int,CN=Enterprise Admins,CN=Users,DC=demisto,DC=int,CN=Schema Admins,CN=Users,DC=demisto,DC=int,CN=Administrators,CN=Builtin,DC=demisto,DC=int | demistoadmin | demistoadmin | 66048 |
>| CN=Guest,CN=Users,DC=demisto,DC=int |  |  |  | CN=Guests,CN=Builtin,DC=demisto,DC=int | Guest | Guest | 66082 |

### ad-get-computer
***
Retrieves detailed information about a computer account. The computer can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filters are provided, all computers are returned.

#### Base Command

`ad-get-computer`

##### Required Permissions
Requires `Read` and `Read and read all properties` permissions from `Computer objects`.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The computer's DN. | Optional | 
| name | The name of the computer to return information about. | Optional | 
| attributes | Adds AD attributes of the resulting objects to the default attributes. | Optional | 
| custom-field-data | Search computers by custom field data (relevant only if the `customFieldType` argument is provided). | Optional | 
| custom-field-type | Search the computer by custom field type. | Optional | 
| limit | The maximum number of records to return. | Optional |
| page-size | The page size to query. The value limit will be ignored. | Optional | 
| page-cookie | An opaque string received in a paged search, used for requesting subsequent entries. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Computers.dn | unknown | The computer distinguished name. | 
| ActiveDirectory.Computers.memberOf | unknown | Groups for which the computer is listed. | 
| ActiveDirectory.Computers.name | unknown | The computer name. | 
| Endpoint.ID | unknown | The computer DN. | 
| Endpoint.Hostname | unknown | The computer host name. | 
| Endpoint.Groups | unknown | Groups for which the computer is listed as a member. | 
| ActiveDirectory.ComputersPageCookie | string | An opaque string received in a paged search, used for requesting subsequent entries. | 


##### Command Example
```
ad-get-computer name=noapc
```

##### Context Example
```
{
    "ActiveDirectory.Computers":
         [ { "dn": "CN=noapc,OU=Shani,DC=demisto,DC=int",
             "memberOf": [ "CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int" ],
             "name": [ "noapc" ] } ],
             "Endpoint": [ { "Hostname": [ "noapc" ],
             "Type": "AD", "ID": "CN=noapc,OU=Shani,DC=demisto,DC=int",
             "Groups": [ "CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int" ]
        } ]
}
```

##### Human Readable Output
>### Active Directory - Get Computers
>| dn | memberOf| name |
>|---| ---| ---|
>| CN=noapc,OU=Shani,DC=demisto,DC=int | CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int | noapc |

### ad-get-group-members
***
Retrieves the list of users or computers that are members of the specified group.

#### Base Command

`ad-get-group-members`

##### Required Permissions
Requires `Read members` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group-dn | The Distinguished Name of the Group's Active Directory. | Required | 
| member-type | The type of members to search. Can be: "Person", or "computer". Default is person. Possible values are: person, computer, group. Default is person. | Required | 
| attributes | CSV list of attributes to include in the results, in addition to the default attributes. | Optional | 
| time_limit | Time limit (in seconds) for the search to run. Default is 180. | Optional | 
| disable-nested-search | Whether to disable recursive retrieval of group memberships of a user. Possible values are: false, true. Default is false. | Optional | 
| sAMAccountName | Queries results by the samAccountName attribute. Default is *. | Optional |
| limit | The maximum number of records to return. | Optional | 
| page-size | The page size to query. The limit value will be ignored. | Optional | 
| page-cookie | An opaque string received in a paged search, used for requesting subsequent entries. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Groups.dn | string | The group DN. | 
| ActiveDirectory.Groups.members.dn | string | The group member DN. | 
| ActiveDirectory.Groups.members.category | string | The group members category. | 
| ActiveDirectory.GroupsPageCookie | string | An opaque string received in a paged search, used for requesting subsequent entries. | 


#### Command Example
```
!ad-get-group-members group-dn="CN=Group124,OU=DemistoMng,DC=demisto,DC=int"
```

##### Context Example
```
{ "Account":
         [ { "DisplayName": [ "User 671 User 671" ],
             "Email": null,
             "Groups": [ "CN=Group124,OU=DemistoMng,DC=demisto,DC=int", "CN=Group2,OU=DemistoMng,DC=demisto,DC=int" ],
             "ID": "CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int",
             "Managr": [],
             "Type": "AD",
             "Username": null } ],
  "ActiveDirectory":
                  { "Groups": { "dn": "CN=Group124,OU=DemistoMng,DC=demisto,DC=int",
                    "members": [ { "category": "person", "dn": "CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int" } ] },
                    "Users": { "displayName": [ "User 671 User 671" ],
                    "dn": "CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int",
                    "mail": [ "test@demisto.int" ],
                    "manager": [],
                    "memberOf": [ "CN=Group124,OU=DemistoMng,DC=demisto,DC=int",
                    "CN=Group2,OU=DemistoMng,DC=demisto,DC=int" ],
                    "name": [ "User 671 User 671" ],
                    "sAMAccountName": [ "User 671User 671" ],
                    "userAccountControl": [ 514 ] }
                  }
}
```

 ##### Human Readable Output

>###Active Directory - Get Group Members
>| dn | displayName | mail | manager | memberOf | name | sAMAccountName | userAccountControl
>|---| ---| ---|---| ---| ---|---| ---|
>| CN=User 671 User  | User 671  | test@demisto.int | | CN=Group124,OU=DemistoMng,DC=demisto,DC=int | User 671 | User 671User 671 | 514
>| 671,OU=DemistoMng,DC=demisto,DC=int | User 671  | | | CN=Group2,OU=DemistoMng,DC=demisto,DC=int | User 671 | User 671User 671 | 514

### ad-create-group
***
Creates a new security or distribution Active Directory group.


#### Base Command

`ad-create-group`

##### Required Permissions
Requires `Create, delete, and manage groups` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The Active Directory name of the group. | Required | 
| group-type | The type of group. Can be: "security", or "distribution". Possible values are: security, distribution. | Required | 
| dn | The Full Distinguished Name (DN) of the group. Use double quotes ("") rather than single quotes ('') when initializing this command. | Required | 
| members | The Full DN Of users or groups that will be members of the newly created group. | Optional | 


#### Context Output

There is no context output for this command.

### ad-delete-group
***
Deletes an existing Active Directory security or distribution group.


#### Base Command

`ad-delete-group`

##### Required Permissions
Requires `Create, delete, and manage groups` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The Active Directory Distinguished Name (DN) of the group. | Required | 


#### Context Output

There is no context output for this command.

### ad-update-group
***
Updates attributes of an existing Active Directory group.


#### Base Command

`ad-update-group`

##### Required Permissions
Requires `Create, delete, and manage groups` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupname | The group name of the group to update (sAMAccountName). | Optional | 
| attributename | The name of the attribute to modify. For example, Description and displayName. | Required | 
| attributevalue | The value of the attribute to change. | Required | 
| basedn | Root. For example, DC=domain,DC=com. By default, the Base DN configured for the instance is used. | Optional | 


#### Context Output

There is no context output for this command.

### ad-test-credentials
***
Test given credentials.


#### Base Command

`ad-test-credentials`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to test. By itself or formatted as SERVER_IP\\USERNAME | Required | 
| password | Password to test. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.ValidCredentials | Unknown | List of usernames that successfully logged in. | 

### iam-create-user
***
Creates an Active Directory user. This command requires a secure connection (SSL,TLS).
Used in the IAM premium pack.

#### Base Command

`iam-create-user`

##### Required Permissions
Requires `Create, delete, and manage user accounts` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name, email address, etc. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.UserProfile | Unknown | The user profile. | 
| IAM.Vendor.active | Boolean | If true, the employee status is active. | 
| IAM.Vendor.brand | String | The integration name. | 
| IAM.Vendor.details | Unknown | Tells the user if the API was successful, otherwise provides error information. | 
| IAM.Vendor.email | String | The employee email address. | 
| IAM.Vendor.errorCode | Number | The HTTP error response code. | 
| IAM.Vendor.errorMessage | String | The reason the API failed. | 
| IAM.Vendor.id | String | The employee user ID in the app. | 
| IAM.Vendor.instanceName | Unknown | The name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command executed successfully. | 
| IAM.Vendor.username | String | The employee username in the app. | 
| IAM.Vendor.action | String | The command name. | 

#### Command Example

```
!iam-create-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\", \"lastname\":\"Test\",\"firstname\":\"Demisto\"}
```
#### Human Readable Output
### Create User Results

|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Active Directory Query | IAM_instance_1 | true | true |  | testdemisto2| testdemisto2@paloaltonetworks.com | status: PROVISIONED<br />created: 2020-10-18T17:54:30.000Z<br />activated: 2020-10-18T17:54:30.000Z<br />statusChanged: 2020-10-18T17:54:30.000Z<br />lastLogin: null<br />lastUpdated: 2020-10-18T17:54:30.000Z<br />passwordChanged: null<br />type: {"id": "oty8zfz6plq7b0r830h7"}<br />profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto44@paloaltonetworks.com"}<br />credentials: {"provider": {"type": "Active Directory Query", "name": "Active Directory Query"}}}

### iam-get-user
***
Retrieves a single user resource.
Used in the IAM premium pack.

#### Base Command

`iam-get-user`

##### Required Permissions
Requires `Read all user information` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name and email address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.UserProfile | Unknown | The user profile. | 
| IAM.Vendor.active | Boolean | If true the employee status is active. | 
| IAM.Vendor.brand | String | The integration name. | 
| IAM.Vendor.details | Unknown | Tells the user if the API was successful, otherwise provides error information. | 
| IAM.Vendor.email | String | The employee email address. | 
| IAM.Vendor.errorCode | Number | The HTTP error response code. | 
| IAM.Vendor.errorMessage | String | The reason the API failed. | 
| IAM.Vendor.id | String | The employee user ID in the app. | 
| IAM.Vendor.instanceName | Unknown | The integration instance name. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully. | 
| IAM.Vendor.username | String | The employee username in the app. | 
| IAM.Vendor.action | String | The command name. | 

#### Command Example
```
!iam-get-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\"}
```

#### Human Readable Output

### Get User Results
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Active Directory Query | IAM_instance_1 | true | true |  | testdemisto2| testdemisto2@paloaltonetworks.com | status: PROVISIONED<br />created: 2020-10-18T17:54:30.000Z<br />activated: 2020-10-18T17:54:30.000Z<br />statusChanged: 2020-10-18T17:54:30.000Z<br />lastLogin: null<br />lastUpdated: 2020-10-18T17:54:30.000Z<br />passwordChanged: null<br />type: {"id": "oty8zfz6plq7b0r830h7"}<br />profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto44@paloaltonetworks.com"}<br />credentials: {"provider": {"type": "Active Directory Query", "name": "Active Directory Query"}}}

### iam-update-user
***
Updates an existing user with the data in the User Profile indicator that is passed in the user-profile argument.
Used in the IAM premium pack.

#### Base Command

`iam-update-user`

##### Required Permissions
Requires `Create, delete, and manage user accounts` permissions.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name and email address. | Required | 
| allow-enable | When set to true, after the command executes the user status in the 3rd-party integration is active. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.UserProfile | Unknown | The user profile | 
| IAM.Vendor.active | Boolean | Gives the active status of user. Can be true or false. | 
| IAM.Vendor.brand | String | The integration name. | 
| IAM.Vendor.details | Unknown | Tells the user if the API was successful, otherwise provides error information. | 
| IAM.Vendor.email | String | The employee email address. | 
| IAM.Vendor.errorCode | Number | The HTTP error response code. | 
| IAM.Vendor.errorMessage | String | The reason the API failed. | 
| IAM.Vendor.id | String | The employee user ID in the app. | 
| IAM.Vendor.instanceName | Unknown | The integration instance name. | 
| IAM.Vendor.success | Boolean | If true, the command executed successfully. | 
| IAM.Vendor.username | String | The employee username in the app. | 
| IAM.Vendor.action | String | The command name. | 


#### Command Example
```
!iam-update-user user-profile={\"email\":\"testdemisto22@paloaltonetworks.com\", \"name\":\"testdemisto2\"}
```

#### Human Readable Output

### Update User Results
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Active Directory Query | IAM_instance_1 | true | true |  | testdemisto2| testdemisto22@paloaltonetworks.com | status: PROVISIONED<br />created: 2020-10-18T17:54:30.000Z<br />activated: 2020-10-18T17:54:30.000Z<br />statusChanged: 2020-10-18T17:54:30.000Z<br />lastLogin: null<br />lastUpdated: 2020-10-18T17:54:30.000Z<br />passwordChanged: null<br />type: {"id": "oty8zfz6plq7b0r830h7"}<br />profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto44@paloaltonetworks.com"}<br />credentials: {"provider": {"type": "Active Directory Query", "name": "Active Directory Query"}}}

### iam-disable-user
***
Disables a user.
Used in the IAM premium pack.

#### Base Command

`iam-disable-user`

##### Required Permissions
Requires `Read userAccountControl` and `write userAccountControl` permissions.

#### Input

### iam-disable-user

***
Disables a user.

#### Base Command

`iam-disable-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name and email address. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.UserProfile | Unknown | The user profile. | 
| IAM.Vendor.active | Boolean | Gives the active status of user. Can be true or false. | 
| IAM.Vendor.brand | String | The integration name. | 
| IAM.Vendor.details | Unknown | Tells the user if the API was successful, otherwise provides error information. | 
| IAM.Vendor.email | String | The employee email address. | 
| IAM.Vendor.errorCode | Number | The HTTP error response code. | 
| IAM.Vendor.errorMessage | String | The reason the API failed. | 
| IAM.Vendor.id | String | The employee user ID in the app. | 
| IAM.Vendor.instanceName | Unknown | The integration instance name. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully. | 
| IAM.Vendor.username | String | The employee username in the app. | 
| IAM.Vendor.action | String | The command name. | 

There are no input arguments for this command.

#### Context Output

There is no context output for this command.


## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Active Directory Query v2 corresponding events (available from Cortex XSOAR version 6.0.0).

To set up the mirroring, enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.

**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Active Directory Query v2.

## Breaking changes from the previous version of this integration - Active Directory Query v2
The following sections list the changes in this version.

### Arguments
#### The following arguments were added in this version:

In the *ad-get-user* command:
* *attributes-to-exclude*

### get-mapping-fields

***
Retrieves a User Profile schema which holds all of the user fields in the application. Used for outgoing mapping through the Get Schema option.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.