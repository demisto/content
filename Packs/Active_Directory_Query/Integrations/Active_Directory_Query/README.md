Use the Active Directory Query integration to access and manage Active Directory objects (users, contacts, and computers) and run AD queries. 

This integration can be used along with our Identity Lifecycle Management premium pack.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

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

Configure Active Directory Query v2 on Demisto
----------------------------------------------

2. Navigate to **Settings** > **Integrations** > **Servers & Services**.
4. Search for Active Directory Query v2.
2. Click **Add instance** to create and configure a new integration instance. 
    *  **Name**: a textual name for the integration instance.
    *  **Server IP address (e.g., 192.168.0.1)**: The Server IP that should be used to access Active Directory.
    *  **Port**: Server port. If not specified, the default port is 389, or 636 for LDAPS.
    *  **Credentials**: User credentials.
    *  **NTLM authentication**: Indicates whether to use NTLM authentication.
    *  **Base DN (for example “dc=company,dc=com”)**: The basic hierarchical path of objects in the active directory.
    *  **Page size**: The number of results to be returned, per page (page - response content from AD server), from a query. This may effect query run time.
    *  **Secure Connection**: Use SSL secure connection or ‘None’ (communication over clear-text).
    *  **Trust any certificate (not secure)**:Select to avoid server certification validation. You may want to do this in case Cortex XSOAR cannot validate the integration server certificate (due to a missing CA certificate)

4. Click **Test** to validate the URLs, token, and connection.


##### Identity Lifecycle Management premium pack configuration

The premium ILM content pack introduces new functionality that uses both an incoming and an outgoing mapper.

1. Configure the "Incoming Mapper" with the name of the incoming mapper that you're using. ILM's default mapper is "User Profile - Active Directory (Incoming)".
2. Configure the "Outgoing Mapper" with the name of the outgoing mapper that you're using. ILM's default mapper is "User Profile - Active Directory (Outgoing)".

To allow the integration to access the mapper from within the code, as required by the ILM pack, both mappers have to be configured in their proper respective fields and *not* in the "Mapper (outgoing)" dropdown list selector.

Commands
--------

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### 1. Expire a password

Expires the password of an Active Directory user.

##### Base Command

`ad-expire-password`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required |
| base-dn | Root (e.g., DC=domain,DC=com). | Optional |

##### Context Output

There is no context output for this command.

### 2. Create an AD user

Creates a user in Active Directory.

##### Base Command

`ad-create-user`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required |
| password | The initial password to set for the user. The user will be asked to change the password after the initial login. | Required |
| user-dn | The user’s DN. | Required |
| display-name | The user’s display name. | Optional |
| description | A description of the user or their function. | Optional |
| email | The user’s email address. | Optional |
| telephone-number | The user’s telephone number. | Optional |
| title | The user’s job title. | Optional |
| custom-attributes | set basic or custom attributes of the user object. For example, custom-attributes="{\"notes\":\"a note about the contact\",\"company\":\"company name\"}" | Optional |     

##### Context Output

There is no context output for this command.

##### Command Example
```
ad-create-user username="jack" password="1q2w3e4r!" user-dn="cn=jack,dc=demisto,dc=int" display-name="Samurai Jack" 
```
##### Human Readable Output
```
Created user with DN: cn=jack,dc=demisto,dc=int
```

### 3. Perform a search in Active Directory

Runs queries in Active Directory. 

For more information on the query syntax see the [Microsoft documentation](https://docs.microsoft.com/en-us/windows/desktop/adsi/search-filter-syntax).

For more information on LDAP filters, see the [LDAP documentation](https://ldap.com/ldap-filters/).

##### Base Command

`ad-search`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Defines search criteria in the Query Active Directory using Active Directory syntax. For example, the following query searches for all user objects, except Andy: "(&(objectCategory=person)(objectClass=user)(!(cn=andy)))". NOTE if you have special characters such as "*","(",or "\" the character must be preceded by two backslashes "\\". For example, to use "*", type "\\*". For more information about search filters, see [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax). | Required |
| base-dn | Root (e.g. DC=domain,DC=com). By default, the Base DN configured for the instance that will be used. | Required |
| attributes | A CSV list of the object attributes to return, e.g., “dn,memberOf”. To get all object attributes, specify ‘ALL’. | Optional |
| size-limit | The maximum number of records to return. | Optional |
| time-limit | The maximum time to pull records (in seconds). | Optional |
| context-output | If “no”, will not output the search results to the context. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Search.dn | string | The distinguished names that match the query.    |
| ActiveDirectory.Search | unknown | Result of the search. |

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


### 4. Add an AD user or computer to a group

Adds an Active Directory user or computer to a group.

##### Base Command

`ad-add-to-group`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to add to the group. If this argument is not specified, the computer name argument must be specified. | Optional |
| computer-name | The name of the computer to add to the group. If this argument is not specified, the username argument must be specified. | Optional |
| group-cn | The name of the group to add to the group| Required |
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```
ad-add-to-group username="Jack" group-cn="Users"
```

##### Human Readable Output
```
Object with dn CN=jack,DC=demisto,DC=int was added to group Users
```

### 5. Remove an AD user or computer from a group

Removes an Active Directory user or computer from a group.

##### Base Command

`ad-remove-from-group`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The name of the user to remove from the group. If this argument is not specified, the computer name argument must be specified. | Optional |
| computer-name | The name of the computer to remove from the group. If this argument is not specified, the username argument must be specified. | Optional |
| group-cn | The name of the group to remove the user from| Required |
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Required |

##### Context Output

There is no context output for this command.

##### Command Example
```
ad-remove-from-group username="jack" group-cn="Users"
```

##### Human Readable Output
```
Object with dn CN=jack,DC=demisto,DC=int removed from group Users
```

### 6. Update attributes for an AD user

Updates attributes of an existing Active Directory user.

##### Base Command

`ad-update-user`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to update (sAMAccountName) | Required |
| attribute-name | The name of the attribute to modify (e.g., sn, displayName, mail, etc.). | Required |
| attribute-value | The value the attribute should be changed to. | Required |
| base-dn | Root (e.g. DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Optional |

##### Context Output

There is no context output for this command.

##### Command Example
```
!ad-update-user attribute-name=description attribute-value=Samurai username=jack
```

##### Human Readable Output
```
Updated user's description to Samurai
```

### 7. Delete an AD user

Deletes an Active Directory user.

##### Base Command

`ad-delete-user`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-dn  | The DN of the user to delete. | Required |

##### Context Output

There is no context output for this command.

##### Command Example
```
!ad-delete-user user-dn="cn=jack,dc=demisto,dc=int"
```

##### Human Readable Output
```
Deleted object with dn cn=jack,dc=demisto,dc=int
```

### 8. Create an AD contact

Creates an Active Directory contact.

##### Base Command

`ad-create-contact`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact-dn | The contact’s DN. | Required |
| display-name | The contact’s display name. | Optional |
| description | A short description of the contact. | Optional |
| email | The contact’s email address. | Optional |
| telephone-number | The contact’s telephone number. | Optional |
| custom-attributes | Sets basic or custom attributes of the user object. For example, custom-attributes="{\"notes\":\"a note about the contact\",\"company\":\"companyname\"}" | Optional |
| title | The contact’s job title. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```
!ad-create-contact contact-dn="cn=jack,dc=demisto,dc=int" description="Samurai" email=jack@company.com
```

##### Human Readable Output
```
Created contact with DN: cn=jack,dc=demisto,dc=int
```

### 9. Update attributes of an AD contact

Updates attributes of an existing Active Directory contact.

##### Base Command

`ad-update-contact`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact-dn | The contact’s DN. | Required |
| attribute-name | The name of the attribute to update. | Required |
| attribute-value | The attribute value to update. | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```
ad-update-contact contact-dn="cn=Jack,dc=demisto,dc=int" attribute-name="displayName" attribute-value="Jack H."
```

##### Human Readable Output
```
Updated contact’s displayName to: Jack H.
```

### 10. Disable an AD user account

Disables an Active Directory user account.

##### Base Command

`ad-disable-account`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to disable (sAMAccountName). | Required |
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Optional |

##### Context Output

There is no context output for this command.

##### Command Example
```
ad-disable-account username="jack"
```

##### Human Readable Output
```
User “CN=jack,DC=demisto,DC=int” has been disabledUser jack was disabled
```

### 11. Enable an AD user account

Enables a previously disabled Active Directory account.

##### Base Command

`ad-enable-account`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to enable (sAMAccountName). | Required |
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Optional |

##### Context Output

There is no context output for this command.

##### Command Example
```
ad-enable-account username="jack"   
```

##### Human Readable Output
```
User jack was enabledUser “CN=jack,DC=demisto,DC=int” has been enabled
```

### 12. Unlock an AD user account

Unlocks a previously locked Active Directory user account.

##### Base Command

`ad-unlock-account`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to unlock (sAMAccountName). | Required |
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```
!ad-unlock-account username=mooncake
```

##### Human Readable Output
```
User "CN=mooncake,CN=Users,DC=demisto,DC=int" has been unlocked
```

### 13. Set a new password for an AD user account

Sets a new password for an Active Directory user. This command requires a secure connection (SSL,TLS).

##### Base Command

`ad-set-new-password`

##### Input
    
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to set a new password for. | Required |
| password | The new password to set for the user. | Required |
| base-dn | Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```
!ad-set-new-password username="NoaCo" password="noni1q2w3e!"   
```

##### Human Readable Output
```
User password successfully set
```

### 14. Modify the computer organizational unit in a domain

Modifies the computer organizational unit within a domain.

##### Base Command

`ad-modify-computer-ou`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer-name | The name of the computer to modify. | Required |
| full-superior-dn  | Superior DN, e.g., OU=computers,DC=domain,DC=com (The specified domain must be the same as the current computer domain). | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```
!ad-modify-computer-ou computer-name=mike full-superior-dn=OU=Sarah,DC=demisto,DC=int
```

##### Context Output

There is no context output for this command.

##### Human Readable Output
```
"mike" was successfully moved to "OU=Sarah,DC=demisto,DC=int"
```

### 15. Get information for an AD user account

Retrieves detailed information about a user account. The user can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filter is specified, all users are returned.

##### Base Command

`ad-get-user`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The Distinguished Name of the user to get information for. | Optional |
| name | The name of the user to get information for. | Optional |
| attributes | Include these AD attributes of the resulting objects in addition to the default attributes. | Optional |
| custom-field-type | Query users by this custom field type. | Optional |
| custom-field-data | Query users by this custom field data (relevant only if the custom-field-type argument is provided). | Optional |
| username | Query users by the samAccountName attribute | Optional |
| limit | Maximum number of objects to return (default is 20). | Optional |
| email | Query by the user’s email address. | Optional |
| user-account-control-out | Include verbose translation for UserAccountControl flags. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Users.dn | string | The user’s distinguished name |
| ActiveDirectory.Users.displayName | string | The user’s display name |
| ActiveDirectory.Users.name | string | The user’s common name |
| ActiveDirectory.Users.sAMAccountName | string | The user’s sAMAccountName |
| ActiveDirectory.Users.userAccountControl | number | The user’s account control flag |
| ActiveDirectory.Users.mail | string | The user’s email address |
| ActiveDirectory.Users.manager | string | The user’s manager |
| ActiveDirectory.Users.memberOf | string | Groups the user is member of |
| Account.DisplayName | string | The user’s display name |
| Account.Groups | string | Groups the user is member of |
| Account.Manager | string | The user’s manager |
| Account.ID | string | The user’s distinguished name |
| Account.Username | string | The user’s samAccountName |
| Account.Email | string | The user’s email address |

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


### 16. Get information for a computer account

Retrieves detailed information about a computer account. The computer can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filters are provided, all computers are returned.

##### Base Command

`ad-get-computer`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The computer’s DN. | Optional |
| name | The name of the computer to get information for. | Optional |
| attributes | Include these AD attributes of the resulting objects in addition to the default attributes. | Optional |
| custom-field-data | Search computers by this custom field data (relevant only if the customFieldType argument is provided). | Optional |
| custom-field-type | The custom field type to search by. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Computers.dn | unknown | The computer distinguished name |
| ActiveDirectory.Computers.memberOf | unknown | Groups the computer is listed as a member |
| ActiveDirectory.Computers.name | unknown | The computer name |
| Endpoint.ID | unknown | The computer DN |
| Endpoint.Hostname | unknown | The computer name |
| Endpoint.Groups | unknown | Groups the computer is listed as a member of |


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


### 17. Get a list of users or computers for a group

Retrieves the list of users or computers that are members of the specified group.

##### Base Command

`ad-get-group-members`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group-dn  | Group’s Active Directory Distinguished Name. | Required |
| member-type | The member type to query by. | Required |
| attributes | A CSV list of attributes to include in the results (in addition to the default attributes). | Optional |
| time\_limit | Time limit (in seconds) for the search to run. | Optional |
| disable-nested-search | Disable recursive retrieval of a user's group memberships. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Groups.dn | string | The group DN.  |
| ActiveDirectory.Groups.members.dn | string | The group member DN. |
| ActiveDirectory.Groups.members.category | string | The category ("person" or "computer". |


##### Command Example
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


### 18. Create an AD user

Create an AD user.
Used in the IAM premium pack.

#### Base Command
`iam-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name, email address, etc. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | String | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The email address of the employee. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | String | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 
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



### 19. Update an AD user

Updates an existing AD user with the data passed in the user-profile argument.
Used in the IAM premium pack.

#### Base Command
`iam-update-user`

#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name, email address, etc. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | String | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The email address of the employee. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | String | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 
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



### 20. Update an AD user

Retrieves a single AD user resource.
Used in the IAM premium pack.


#### Base Command
`iam-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name, email address, etc. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | String | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The email address of the employee. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | String | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 
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


### 22. Disable an AD user

Disable an active AD user.
Used in the IAM premium pack.

#### Base Command
`iam-disable-user`

#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator that contains user information, such as name, email address, etc. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | String | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The email address of the employee. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | String | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. | 
| IAM.Vendor.username | String | The employee's username in the app. | 
| IAM.Vendor.action | String | The command name. | 

#### Command Example

```
!iam-disable-user user-profile={\"email\":\"testdemisto2@paloaltonetworks.com\"}
```

#### Human Readable Output

### Disable User Results
|brand|instanceName|success|active|id|username|email|details|
|---|---|---|---|---|---|---|---|
| Active Directory Query | IAM_instance_1 | true | false |  | testdemisto2| testdemisto2@paloaltonetworks.com | status: PROVISIONED<br />created: 2020-10-18T17:54:30.000Z<br />activated: 2020-10-18T17:54:30.000Z<br />statusChanged: 2020-10-18T17:54:30.000Z<br />lastLogin: null<br />lastUpdated: 2020-10-18T17:54:30.000Z<br />passwordChanged: null<br />type: {"id": "oty8zfz6plq7b0r830h7"}<br />profile: {"firstName": "Demisto", "lastName": "Test", "mobilePhone": null, "secondEmail": null, "login": "testdemisto2@paloaltonetworks.com", "email": "testdemisto44@paloaltonetworks.com"}<br />credentials: {"provider": {"type": "Active Directory Query", "name": "Active Directory Query"}}}




Additional Information
----------------------

* LDAP attributes: <https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx> 
* Distinguished Names explanation and examples: <https://ldap.com/ldap-dns-and-rdns/> 
