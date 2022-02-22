This integration enables you to process alerts from SafeNet Trusted Access (STA) indicating security risks to end user accounts, and apply security remediation actions on SafeNet Trusted Access through security orchestration playbooks. For information about the configuration steps, visit our [Help Documentation](https://thalesdocs.com/sta/Content/STA/SecurityInt/CortexXSOAR_PaloAltoNetworks.htm).

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

> **_NOTE :_**  Perform create, update and delete operations  using commands only for internal users or groups. Such operations aren't recommended for synchronized users or groups.

### sta-get-user-list
***
Get list of users in the tenant.


#### Base Command

`sta-get-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | number | Mobile number of the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.ALIAS3 | string | Additional alias for the user. | 
| STA.USER.ALIAS4 | string | Additional alias for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | number | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is the user synchronized. | 


#### Command Example
```!sta-get-user-list```

#### Context Example
```json
{
    "STA": {
        "USER": [
            {
                "email": "demo.user@demisto.com",
                "firstName": "Demo",
                "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
                "isSynchronized": false,
                "lastName": "User",
                "schemaVersionNumber": "1.0",
                "userName": "demouser"
            },
            {
                "email": "test.user@demisto.com",
                "firstName": "Hello",
                "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
                "isSynchronized": false,
                "lastName": "User",
                "schemaVersionNumber": "1.0",
                "userName": "hellouser"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of users in the tenant :
>|Id|Schema Version Number|User Name|First Name|Last Name|Email|Is Synchronized|
>|---|---|---|---|---|---|---|
>| CNlM6Pyq3nADXA4rWyUAAAAc | 1.0 | demouser | Demo | User | demo.user@demisto.com | false |
>| CNlM6rvB0uQDXA4rWyUAAAAc | 1.0 | hellouser | Hello | User | test.user@demisto.com | false |


### sta-get-user-info
***
Get the profile information for a specific user.


#### Base Command

`sta-get-user-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | string | Mobile number of the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.ALIAS3 | string | Additional alias for the user. | 
| STA.USER.ALIAS4 | string | Additional alias for the user. | 
| STA.USER.CUSTOM1 | string | Custom value for the user. | 
| STA.USER.CUSTOM2 | string | Additional custom value for the user. | 
| STA.USER.CUSTOM3 | string | Additional custom value for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | string | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is user synchronized. | 


#### Command Example
```!sta-get-user-info userName="demouser"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "demo.user@demisto.com",
            "firstName": "Demo",
            "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
            "isSynchronized": false,
            "lastName": "User",
            "schemaVersionNumber": "1.0",
            "userName": "demouser"
        }
    }
}
```

#### Human Readable Output

>### Information for user - demouser :
>|Id|Schema Version Number|User Name|First Name|Last Name|Email|Is Synchronized|
>|---|---|---|---|---|---|---|
>| CNlM6Pyq3nADXA4rWyUAAAAc | 1.0 | demouser | Demo | User | demo.user@demisto.com | false |


### sta-create-user
***
Create a new user in the tenant.


#### Base Command

`sta-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | User ID of the user. | Required | 
| first_name | First name of the user. | Required | 
| last_name | Last name of the user. | Required | 
| email | Email ID of the user. | Required | 
| mobile_number | Mobile number of the user. | Optional | 
| alias1 | Alias for the user. | Optional | 
| alias2 | Additional alias for the user. | Optional | 
| custom1 | Custom value for the user. | Optional | 
| custom2 | Additional custom value for the user. | Optional | 
| custom3 | Additional custom value for the user. | Optional | 
| address | Address of the user. | Optional | 
| city | City of the user. | Optional | 
| state | State of the user. | Optional | 
| country | Country of the user. | Optional | 
| postal_code | Postal Code of the user. | Optional | 
| synchronized | Is user synchronized. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | string | Mobile number of the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.CUSTOM1 | string | Custom value for the user. | 
| STA.USER.CUSTOM2 | string | Additional custom value for the user. | 
| STA.USER.CUSTOM3 | string | Additional custom value for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | string | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is user synchronized. | 


#### Command Example
```!sta-create-user email="test.user@demisto.com" first_name="User" last_name="Test" userName="usertest123"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "test.user@demisto.com",
            "firstName": "User",
            "id": "iNlsjym+x1MLesvCSusAAAAc",
            "isSynchronized": false,
            "lastName": "Test",
            "schemaVersionNumber": "1.0",
            "userName": "usertest123"
        }
    }
}
```

#### Human Readable Output

>### STA user successfully created :
>|Id|Schema Version Number|User Name|First Name|Last Name|Email|Is Synchronized|
>|---|---|---|---|---|---|---|
>| iNlsjym+x1MLesvCSusAAAAc | 1.0 | usertest123 | User | Test | test.user@demisto.com | false |


### sta-update-user-info
***
Update the profile for a specific user.


#### Base Command

`sta-update-user-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | User ID of the user. | Required | 
| first_name | First name of the user. | Optional | 
| last_name | Last name of the user. | Optional | 
| email | Email ID of the user. | Optional | 
| mobile_number | Mobile number of the user. | Optional | 
| alias1 | Alias for the user. | Optional | 
| alias2 | Additional alias for the user. | Optional | 
| address | Address of the user. | Optional | 
| city | City of the user. | Optional | 
| state | State of the user. | Optional | 
| country | Country of the user. | Optional | 
| postal_code | Postal Code of the user. | Optional | 
| userName_new | New userName to be updated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | number | Mobile number for the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.CUSTOM1 | string | Custom value for the user. | 
| STA.USER.CUSTOM2 | string | Additional custom value for the user. | 
| STA.USER.CUSTOM3 | string | Additional custom value for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | number | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is user synchronized. | 


#### Command Example
```!sta-update-user-info userName="usertest123" userName_new="testuser1" first_name="Demo" last_name="Name"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "test.user@demisto.com",
            "firstName": "Demo",
            "id": "iNlsjym+x1MLesvCSusAAAAc",
            "isSynchronized": false,
            "lastName": "Name",
            "schemaVersionNumber": "1.0",
            "userName": "testuser1"
        }
    }
}
```

#### Human Readable Output

>### STA user successfully updated:
>|Id|Schema Version Number|User Name|First Name|Last Name|Email|Is Synchronized|
>|---|---|---|---|---|---|---|
>| iNlsjym+x1MLesvCSusAAAAc | 1.0 | testuser1 | Demo | Name | test.user@demisto.com | false |


### sta-delete-user
***
Delete a user from the tenant.


#### Base Command

`sta-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user to be deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user to be deleted from the tenant. | 
| STA.USER.USERNAME | string | Username of the user to be deleted from the tenant. | 
| STA.USER.DELETED | boolean | Returns true, if the user is deleted from the tenant. | 


#### Command Example
```!sta-delete-user userName="testuser1"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "Deleted": true,
            "id": "iNlsjym+x1MLesvCSusAAAAc",
            "userName": "testuser1"
        }
    }
}
`````

#### Human Readable Output

>## STA user - testuser1 successfully deleted.

### sta-get-user-groups
***
Return all the groups associated with a specific user.


#### Base Command

`sta-get-user-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | number | Mobile number for the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.CUSTOM1 | string | Custom value for the user. | 
| STA.USER.CUSTOM2 | string | Additional custom value for the user. | 
| STA.USER.CUSTOM3 | string | Additional custom value for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | number | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is user synchronized. | 
| STA.USER.GROUP.ID | string | Group ID of the group. | 
| STA.USER.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.USER.GROUP.NAME | string | Name of the group. | 
| STA.USER.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.USER.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-get-user-groups userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "test.user@demisto.com",
            "firstName": "Hello",
            "groups": [
                {
                    "description": "User would be added to unusual activity group on denying Push Notification.",
                    "id": "50331650",
                    "isSynchronized": false,
                    "name": "TestUnusualActivityGroup",
                    "schemaVersionNumber": "1.0"
                },
                {
                    "description": "Group for testing.",
                    "id": "50331652",
                    "isSynchronized": false,
                    "name": "TestGroup0",
                    "schemaVersionNumber": "1.0"
                }
            ],
            "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
            "isSynchronized": false,
            "lastName": "User",
            "schemaVersionNumber": "1.0",
            "userName": "hellouser"
        }
    }
}
```

#### Human Readable Output

>### Groups associated with user - hellouser : 
>|Id|Schema Version Number|Name|Description|Is Synchronized|
>|---|---|---|---|---|
>| 50331650 | 1.0 | TestUnusualActivityGroup | Group for testing. | false |
>| 50331652 | 1.0 | TestGroup0 | Group for testing. | false |


### sta-get-group-list
***
Get list of groups in the tenant.


#### Base Command

`sta-get-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-get-group-list```

#### Context Example
```json
{
    "STA": {
        "GROUP": [
            {
                "description": "Description has been updated.",
                "id": "50331649",
                "isSynchronized": false,
                "name": "TestGroup1",
                "schemaVersionNumber": "1.0"
            },
            {
                "description": "Unusual Activity Group for Testing",
                "id": "50331650",
                "isSynchronized": false,
                "name": "TestUnusualActivityGroup",
                "schemaVersionNumber": "1.0"
            },
            {
                "description": "Group for testing.",
                "id": "50331652",
                "isSynchronized": false,
                "name": "TestGroup0",
                "schemaVersionNumber": "1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### STA groups in the tenant : 
>|Id|Schema Version Number|Name|Description|Is Synchronized|
>|---|---|---|---|---|
>| 50331649 | 1.0 | TestGroup1 | Description has been updated. | false |
>| 50331650 | 1.0 | TestUnusualActivityGroup | Unusual Activity Group for Testing | false |
>| 50331652 | 1.0 | TestGroup0 | Group for testing. | false |


### sta-get-group-info
***
Get information for a specific group.


#### Base Command

`sta-get-group-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-get-group-info groupName="TestGroup1"```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "description": "Description has been updated.",
            "id": "50331649",
            "isSynchronized": false,
            "name": "TestGroup1",
            "schemaVersionNumber": "1.0"
        }
    }
}
```

#### Human Readable Output

>### Group - TestGroup1 :
>|Id|Schema Version Number|Name|Description|Is Synchronized|
>|---|---|---|---|---|
>| 50331649 | 1.0 | TestGroup1 | Description has been updated. | false |


### sta-get-group-members
***
Get list of users in a specific group.


#### Base Command

`sta-get-group-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the group. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 
| STA.GROUP.USER.ID | string | User ID of the user. | 
| STA.GROUP.USER.NAME | string | Username of the user. | 
| STA.GROUP.USER.TYPE | string | Type of the user. | 
| STA.GROUP.USER.LINKS.SELF | string | Link for the user details. | 


#### Command Example
```!sta-get-group-members groupName="TestGroup0"```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "description": "Group for testing.",
            "id": "50331652",
            "isSynchronized": false,
            "name": "TestGroup0",
            "schemaVersionNumber": "1.0",
            "users": [
                {
                    "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
                    "links": {
                        "self": "https://api.stademo.com/api/v1/tenants/HNISOUTHA4/users/CNlM6Pyq7nADXA4rWyUAAATc?isUid=true"
                    },
                    "name": "demouser",
                    "type": "User"
                },
                {
                    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
                    "links": {
                        "self": "https://api.stademo.com/api/v1/tenants/HNISOUTHA4/users/CNlM6rvB9uQDXA4rWyUAAATc?isUid=true"
                    },
                    "name": "hellouser",
                    "type": "User"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Members of group - TestGroup0 : 
>|Id|Name|Type|
>|---|---|---|
>| CNlM6Pyq3nADXA4rWyUAAAAc | demouser | User |
>| CNlM6rvB0uQDXA4rWyUAAAAc | hellouser | User |


### sta-create-group
***
Create a new group in the tenant.


#### Base Command

`sta-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the group. | Required | 
| description | Description of the group. | Optional | 
| synchronized | Is group synchronized. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-create-group groupName="TestGroup2" description="Group description." synchronized=False```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "description": "Group description.",
            "id": "16777228",
            "isSynchronized": false,
            "name": "TestGroup2",
            "schemaVersionNumber": "1.0"
        }
    }
}
```

#### Human Readable Output

>### STA group - TestGroup2 successfully created:
>|Id|Schema Version Number|Name|Description|Is Synchronized|
>|---|---|---|---|---|
>| 16777228 | 1.0 | TestGroup2 | Group description. | false |


### sta-delete-group
***
Delete group from the tenant.


#### Base Command

`sta-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the group to be deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group to be deleted. | 
| STA.GROUP.GROUPNAME | string | Name of the group to be deleted. | 
| STA.GROUP.DELETED | boolean | Returns true, if the group is deleted from the tenant. | 


#### Command Example
```!sta-delete-group groupName="TestGroup2"```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "Deleted": true,
            "groupName": "TestGroup2",
            "id": "16777228"
        }
    }
}
```

#### Human Readable Output

>## STA group - TestGroup2 successfully deleted.

### sta-update-group-info
***
Update information for a specific group.


#### Base Command

`sta-update-group-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the group to be updated. | Required | 
| description | Description of the group. | Optional | 
| groupName_new | New name in case you want to update the group name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-update-group-info groupName="TestGroup1" description="Description has been updated."```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "description": "Description has been updated.",
            "id": "50331649",
            "isSynchronized": false,
            "name": "TestGroup1",
            "schemaVersionNumber": "1.0"
        }
    }
}
```

#### Human Readable Output

>### STA user successfully updated :
>|Id|Schema Version Number|Name|Description|Is Synchronized|
>|---|---|---|---|---|
>| 50331649 | 1.0 | TestGroup1 | Description has been updated. | false |


### sta-user-exist-group
***
Check if user exists in a specific group.


#### Base Command

`sta-user-exist-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user to be checked. | Required | 
| groupName | Group name in which you want to search for the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.EXIST.USER.GROUP | boolean | Check if user exists in group. Returns true, if the user is a member of the group. | 


#### Command Example
```!sta-user-exist-group groupName="TestGroup1" userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "EXIST": {
            "USER": {
                "GROUP": true
            }
        }
    }
}
```

#### Human Readable Output

>## Yes, user - hellouser is a member of group - TestGroup1.

### sta-add-user-group
***
Add user to a specific group.


#### Base Command

`sta-add-user-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | User name of the user to be added. | Required | 
| groupName | Name of the group in which the user needs to be added. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.UPDATE.USER.GROUP.USERID | string | User ID of the user. | 
| STA.UPDATE.USER.GROUP.USERNAME | string | Username of the user. | 
| STA.UPDATE.USER.GROUP.GROUPID | string | Group ID of the group. | 
| STA.UPDATE.USER.GROUP.GROUPNAME | string | Groupname of the group. | 
| STA.UPDATE.USER.GROUP.STATUS | boolean | Returns true, if the user successfully added to the group. | 


#### Command Example
```!sta-add-user-group groupName="TestGroup1" userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "UPDATE": {
            "USER": {
                "GROUP": {
                    "groupName": "TestGroup1",
                    "group_id": "50331649",
                    "status": true,
                    "userName": "hellouser",
                    "user_id": "CNlM6rvB0uQDXA4rWyUAAAAc"
                }
            }
        }
    }
}
```

#### Human Readable Output

>## User - hellouser successfully added to the group - TestGroup1.

### sta-remove-user-group
***
Remove user from a group.


#### Base Command

`sta-remove-user-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | User name of the user to be deleted from the group. | Required | 
| groupName | Group name from which the user needs to be deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.UPDATE.USER.GROUP.USERID | string | User ID of the user. | 
| STA.UPDATE.USER.GROUP.USERNAME | string | Username of the user. | 
| STA.UPDATE.USER.GROUP.GROUPID | string | Group ID of the group. | 
| STA.UPDATE.USER.GROUP.GROUPNAME | string | Groupname of the group. | 
| STA.UPDATE.USER.GROUP.STATUS | boolean | Returns false, if the user successfully removed from the group. | 


#### Command Example
```!sta-remove-user-group groupName="TestGroup1" userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "UPDATE": {
            "USER": {
                "GROUP": {
                    "groupName": "TestGroup1",
                    "group_id": "50331649",
                    "status": false,
                    "userName": "hellouser",
                    "user_id": "CNlM6rvB0uQDXA4rWyUAAAAc"
                }
            }
        }
    }
}
```

#### Human Readable Output

>## User - hellouser successfully removed from the group - TestGroup1.

### sta-get-logs
***
Get access, authentication, and audit logs.


#### Base Command

`sta-get-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Optional | 
| since | Filter logs since the specified date and time in Universal Time Coordinated time zone. Format : yyyy-mm-ddTHH:mm:ss.fffZ  .Example : 2021-06-03T06:27:00.000Z | Optional | 
| until | Filter logs until the specified date and time in Universal Time Coordinated time zone. Format : yyyy-mm-ddTHH:mm:ss.fffZ  .Example : 2021-06-03T07:40:00.000Z | Optional | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.LOGS.TIMESTAMP | string | Timestamp of event. | 
| STA.LOGS.USERNAME | string | Username of the user. | 
| STA.LOGS.TYPE | string | Type of event log. | 
| STA.LOGS.CREDENTIAL | string | Credential type of the event. | 
| STA.LOGS.ACTION | string | Authentication action. | 
| STA.LOGS.RESULT | string | Authentication Action Result. | 
| STA.LOGS.MESSAGE | string | Message or description of the event. | 
| STA.LOGS.APPLICATION | string | Application name. | 
| STA.LOGS.POLICY | string | Policy applied for the application. | 
| STA.LOGS.STATE | string | State of the access request. | 
| STA.LOGS.OPERATIONTYPE | string | Operation type. | 
| STA.LOGS.OPERATIONOBJECT | string | Operation object type. | 
| STA.LOGS.OPERATIONNAME | string | Operation object name. | 
| STA.LOGS.SERIAL | string | Serial number of authentication. | 
| STA.LOGS.IP | string | IP address of the user. | 


#### Command Example
```!sta-get-logs userName="demouser" since="2021-07-21T12:22:16.718Z"```

#### Context Example
```json
{
    "STA": {
        "LOGS": [
            {
                "actionText": "AUTH_ATTEMPT",
                "applicationName": "",
                "credentialType": "MobilePASS",
                "ip": "8.8.8.8",
                "logType": "AUTHENTICATION",
                "message": "Login from SafeNet Authentication Service Console.",
                "operationObjectName": "",
                "operationObjectType": "",
                "operationType": "",
                "policyName": "",
                "resultText": "CHALLENGE",
                "serial": "1000014514",
                "state": "",
                "timeStamp": "2021-07-22T08:19:05.5905986Z",
                "userName": "demouser"
            },
            {
                "actionText": "AUTH_ATTEMPT",
                "applicationName": "",
                "credentialType": "MobilePASS",
                "ip": "8.8.8.8",
                "logType": "AUTHENTICATION",
                "message": "Login from SafeNet Authentication Service Console.",
                "operationObjectName": "",
                "operationObjectType": "",
                "operationType": "",
                "policyName": "",
                "resultText": "AUTH_SUCCESS",
                "serial": "1000014514",
                "state": "",
                "timeStamp": "2021-07-22T08:20:45.5326006Z",
                "userName": "demouser"
            },
            {
                "actionText": "",
                "applicationName": "",
                "credentialType": "otp",
                "ip": "8.8.8.8",
                "logType": "OPERATOR_LOGIN",
                "message": "",
                "operationObjectName": "",
                "operationObjectType": "",
                "operationType": "",
                "policyName": "",
                "resultText": "",
                "serial": "",
                "state": "Accepted",
                "timeStamp": "2021-07-22T08:20:45.638Z",
                "userName": "demouser"
            }
        ]
    }
}
```

#### Human Readable Output

>### Logs : 
>|Time Stamp|User Name|Log Type|Credential Type|Action Text|Result Text|Message|State|Serial|Ip|
>|---|---|---|---|---|---|---|---|---|---|
>| 2021-07-22T08:19:05.5905986Z | demouser | AUTHENTICATION | MobilePASS | AUTH_ATTEMPT | CHALLENGE | Login from SafeNet Authentication Service Console. |  | 1000014514 | 8.8.8.8 |
>| 2021-07-22T08:20:45.5326006Z | demouser | AUTHENTICATION | MobilePASS | AUTH_ATTEMPT | AUTH_SUCCESS | Login from SafeNet Authentication Service Console. |  | 1000014514 | 8.8.8.8 |
>| 2021-07-22T08:20:45.638Z | demouser | OPERATOR_LOGIN | otp |  |  |  | Accepted |  | 8.8.8.8 |


### sta-validate-tenant
***
Checks if you have permission to access the requested tenant.


#### Base Command

`sta-validate-tenant`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.VALIDATE.TENANT | boolean | Checks if you have permission to access the requested tenant. | 


#### Command Example
```!sta-validate-tenant```

#### Context Example
```json
{
    "STA": {
        "VALIDATE": {
            "TENANT": true
        }
    }
}
```

#### Human Readable Output

>## The requested tenant is accessible.

### sta-get-application-list
***
Get the list of the applications in the tenant.


#### Base Command

`sta-get-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.APPLICATION.ID | string | ID of the application. | 
| STA.APPLICATION.NAME | string | Name of the application. | 
| STA.APPLICATION.STATUS | string | Status of the application. | 


#### Command Example
```!sta-get-application-list```

#### Context Example
```json
{
    "STA": {
        "APPLICATION": [
            {
                "id": "g444faf1-6d7a-44t2-98c1-43572422b409",
                "name": "Application1",
                "status": "Active"
            },
            {
                "id": "k0de1afc-59ef-66bc-9abd-dacca890a390",
                "name": "Application2",
                "status": "Active"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of applications in the tenant :
>|Id|Name|Status|
>|---|---|---|
>| g444faf1-6d7a-44t2-98c1-43572422b409 | Application1 | Active |
>| k0de1afc-59ef-66bc-9abd-dacca890a390 | Application2 | Active |


### sta-get-application-info
***
Get the information for a specific application in the tenant.


#### Base Command

`sta-get-application-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| applicationName | Name of the application. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.APPLICATION.ID | string | ID of the application. | 
| STA.APPLICATION.NAME | string | Name of the application. | 
| STA.APPLICATION.STATUS | string | Status of the application. | 
| STA.APPLICATION.TYPE | string | Status of the application. | 
| STA.APPLICATION.TEMPLATE | string | Name of the template. | 
| STA.APPICATION.ASSIGNMENT | string | Groups or users authorized to access an application. | 
| STA.APPICATION.SCHEMA | string | Schema version number. | 
| STA.APPICATION.LASTMODIFIED | string | Last modified date and time of application. | 


#### Command Example
```!sta-get-application-info applicationName="Application1"```

#### Context Example
```json
{
    "STA": {
        "APPLICATION": {
            "applicationType": "Saml",
            "assignment": {
                "everyone": true
            },
            "id": "9ccbad94-06c2-4af2-bb9b-af9f811ccfdb",
            "lastModified": "2021-08-27T12:25:47.998Z",
            "name": "Application1",
            "schemaVersionNumber": "1.0",
            "status": "Active",
            "templateName": "Template1"
        }
    }
}
```

#### Human Readable Output

>### Information of application - Application1 :
>|Id|Name|Status|Application Type|Template Name|Assignment|Schema Version Number|Last Modified|
>|---|---|---|---|---|---|---|---|
>| 9ccbad94-06c2-4af2-bb9b-af9f811ccfdb | Application1 | Active | Saml | Template1 | All | 1.0 | 2021-08-27T12:25:47.998Z |


### sta-get-user-applications
***
Get the list of the applications assigned to a specific user.


#### Base Command

`sta-get-user-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | number | Mobile number for the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.CUSTOM1 | string | Custom value for the user. | 
| STA.USER.CUSTOM2 | string | Additional custom value for the user. | 
| STA.USER.CUSTOM3 | string | Additional custom value for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | number | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is user synchronized. | 
| STA.USER.APPLICATION.ID | string | ID of the application. | 
| STA.USER.APPLICATION.NAME | string | Name of the application. | 
| STA.USER.APPLICATION.STATUS | string | Status of the application. | 


#### Command Example
```!sta-get-user-applications userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "applications": [
                {
                    "id": "9570b825-961e-4ed3-aa51-e53b732b16ec",
                    "name": "Application1",
                    "status": "Active"
                },
                {
                    "id": "66df07af-7c95-42e7-b0cd-2e97b6827d59",
                    "name": "Application2",
                    "status": "Active"
                }
            ],
            "email": "test.user@demisto.com",
            "firstName": "Hello",
            "id": "ONksETu5i8cDs0k67bQAAAD9",
            "isSynchronized": false,
            "lastName": "User",
            "schemaVersionNumber": "1.0",
            "userName": "hellouser"
        }
    }
}
```

#### Human Readable Output

>### Applications associated with user - hellouser : 
>|Id|Name|Status|
>|---|---|---|
>| 9570b825-961e-4ed3-aa51-e53b732b16ec | Application1 | Active |
>| 66df07af-7c95-42e7-b0cd-2e97b6827d59 | Application2 | Active |


### sta-get-user-sessions
***
Get sessions for a specific user.


#### Base Command

`sta-get-user-sessions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA | string | Schema version number. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.FIRSTNAME | string | First name of the user. | 
| STA.USER.LASTNAME | string | Last name of the user. | 
| STA.USER.EMAIL | string | Email ID of the user. | 
| STA.USER.MOBILENUMBER | number | Mobile number for the user. | 
| STA.USER.ALIAS1 | string | Alias for the user. | 
| STA.USER.ALIAS2 | string | Additional alias for the user. | 
| STA.USER.CUSTOM1 | string | Custom value for the user. | 
| STA.USER.CUSTOM2 | string | Additional custom value for the user. | 
| STA.USER.CUSTOM3 | string | Additional custom value for the user. | 
| STA.USER.ADDRESS | string | Address of the user. | 
| STA.USER.CITY | string | City of the user. | 
| STA.USER.STATE | string | State of the user. | 
| STA.USER.COUNTRY | string | Country of the user. | 
| STA.USER.POSTALCODE | number | Postal Code of the user. | 
| STA.USER.SYNCHRONIZED | boolean | Is user synchronized. | 
| STA.USER.SESSION.ID | string | Session ID for the user. | 
| STA.USER.SESSION.START | string | Session start timestamp. | 
| STA.USER.SESSION.EXPIRY | string | Session end timestamp. | 
| STA.USER.SESSION.APPLICATION.ID | string | Name of the application. | 
| STA.USER.SESSION.APPLICATION.NAME | boolean | Returns true, if the user session is deleted for an application. | 


#### Command Example
```!sta-get-user-sessions userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "test.user@demisto.com",
            "firstName": "Hello",
            "id": "ONksETu5i8cDs0k67bQAAAD9",
            "isSynchronized": false,
            "lastName": "User",
            "schemaVersionNumber": "1.0",
            "sessions": [
                {
                    "applications": [
                        {
                            "id": "entity-id1",
                            "name": "Application1"
                        },
                        {
                            "id": "entity-id2",
                            "name": "Application2"
                        }
                    ],
                    "expiry": 1633086960,
                    "id": "86f4593d-fb8a-4f62-byd9-ceb833a8090b",
                    "start": 1633079752
                }
            ],
            "userName": "hellouser"
        }
    }
}
```

#### Human Readable Output

>### Sessions associated with user - hellouser : 
>|Id|Start|Expiry|Applications|
>|---|---|---|---|
>| 86f4593d-fb8a-4f62-byd9-ceb833a8090b | 1633079752 | 1633086960 | Application1, Application2 |


### sta-delete-user-sessions
***
Delete all the active SSO sessions for a specific user from STA.


#### Base Command

`sta-delete-user-sessions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.USERNAME | string | Username of the user. | 
| STA.USER.SESSION.DELETED | boolean | Returns true, if all the user SSO sessions are deleted successfully. | 


#### Command Example
```!sta-delete-user-sessions userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "id": "",
            "sessions": {
                "Deleted": true
            },
            "userName": "hellouser"
        }
    }
}
```

#### Human Readable Output

>## IDP Sessions for the user - hellouser successfully deleted.
