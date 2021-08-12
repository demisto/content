This integration enables you to process alerts from SafeNet Trusted Access (STA) indicating security risks to end user accounts, and apply security remediation actions on SafeNet Trusted Access through security orchestration playbooks. For information about the configuration steps, visit our [Help Documentation](https://dwnxnf7o4k7c.cloudfront.net/sta/Default.htm#cshid=1017).

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| STA.USER.SCHEMA.VERSION | string | Schema version number. | 
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
```!sta-get-user-list limit=10```

#### Context Example
```json
{
    "STA": {
        "USER": [
            {
                "email": "demo.user4alert@gmail.com",
                "firstName": "Demo",
                "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
                "isSynchronized": false,
                "lastName": "User",
                "schemaVersionNumber": "1.0",
                "userName": "demouser"
            },
            {
                "email": "hello.user@gmail.com",
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
>| CNlM6Pyq3nADXA4rWyUAAAAc | 1.0 | demouser | Demo | User | demo.user4alert@gmail.com | false |
>| CNlM6rvB0uQDXA4rWyUAAAAc | 1.0 | hellouser | Hello | User | hello.user@gmail.com | false |


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
| STA.USER.SCHEMA.VERSION | string | Schema version number. | 
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
            "email": "demo.user4alert@gmail.com",
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
>| CNlM6Pyq3nADXA4rWyUAAAAc | 1.0 | demouser | Demo | User | demo.user4alert@gmail.com | false |


### sta-create-user
***
Create new user in the tenant


#### Base Command

`sta-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | User ID of the user. | Required | 
| firstName | First name of the user. | Required | 
| lastName | Last name of the user. | Required | 
| email | Email ID of the user. | Required | 
| mobileNumber | Mobile number of the user. | Optional | 
| alias1 | Alias for the user. | Optional | 
| alias2 | Additional alias for the user. | Optional | 
| custom1 | Custom value for the user. | Optional | 
| custom2 | Additional custom value for the user. | Optional | 
| custom3 | Additional custom value for the user. | Optional | 
| address | Address of the user. | Optional | 
| city | City of the user. | Optional | 
| state | State of the user. | Optional | 
| country | Country of the user. | Optional | 
| postalCode | Postal Code of the user. | Optional | 
| isSynchronized | Is user synchronized. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA.VERSION | string | Schema version number. | 
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
```!sta-create-user email="usertest123@gmail.com" firstName="User" lastName="Test" userName="usertest123"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "usertest123@gmail.com",
            "firstName": "User",
            "id": "iNlUrf8RIazgkpeUDHEAAAAc",
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
>| iNlUrf8RIazgkpeUDHEAAAAc | 1.0 | usertest123 | User | Test | usertest123@gmail.com | false |


### sta-update-user-info
***
Update the profile for a specific user.


#### Base Command

`sta-update-user-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | User ID of the user. | Required | 
| firstName | First name of the user. | Optional | 
| lastName | Last name of the user. | Optional | 
| email | Email ID of the user. | Optional | 
| mobileNumber | Mobile number of the user. | Optional | 
| alias1 | Alias for the user. | Optional | 
| alias2 | Additional alias for the user. | Optional | 
| address | Address of the user. | Optional | 
| city | City of the user. | Optional | 
| state | State of the user. | Optional | 
| country | Country of the user. | Optional | 
| postalCode | Postal Code of the user. | Optional | 
| userName_new | New userName to be updated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.SCHEMA.VERSION | string | Schema version number. | 
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
```!sta-update-user-info userName="usertest123" userName_new="demousername" firstName="Demo" lastName="Name"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "email": "usertest123@gmail.com",
            "firstName": "Demo",
            "id": "iNlUrf8RIazgkpeUDHEAAAAc",
            "isSynchronized": false,
            "lastName": "Name",
            "schemaVersionNumber": "1.0",
            "userName": "demousername"
        }
    }
}
```

#### Human Readable Output

>### STA user successfully updated:
>|Id|Schema Version Number|User Name|First Name|Last Name|Email|Is Synchronized|
>|---|---|---|---|---|---|---|
>| iNlUrf8RIazgkpeUDHEAAAAc | 1.0 | demousername | Demo | Name | usertest123@gmail.com | false |


### sta-delete-user
***
Delete user from the tenant.


#### Base Command

`sta-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user to be deleted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.USER.DELETE | string | User deleted from the tenant. | 


#### Command Example
```!sta-delete-user userName="demousername"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "DELETE": 204
        }
    }
}
```

#### Human Readable Output

>## STA user - demousername successfully deleted.

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
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-get-user-groups userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "GROUP": [
            {
                "description": "High Risk Group for Testing",
                "id": "50331650",
                "isSynchronized": false,
                "name": "TestHighRiskGroup",
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

>### Groups associated with user - hellouser : 
>|Id|Schema Version Number|Name|Description|Is Synchronized|
>|---|---|---|---|---|
>| 50331650 | 1.0 | TestHighRiskGroup | High Risk Group for Testing | false |
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
```!sta-get-group-list limit=5```

#### Context Example
```json
{
    "STA": {
        "GROUP": [
            {
                "description": "Description has been updated from XSOAR end.",
                "id": "50331649",
                "isSynchronized": false,
                "name": "TestGroup1",
                "schemaVersionNumber": "1.0"
            },
            {
                "description": "High Risk Group for Testing",
                "id": "50331650",
                "isSynchronized": false,
                "name": "TestHighRiskGroup",
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
>| 50331649 | 1.0 | TestGroup1 | Description has been updated from XSOAR end. | false |
>| 50331650 | 1.0 | TestHighRiskGroup | High Risk Group for Testing | false |
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
            "description": "Description has been updated from XSOAR end.",
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
>| 50331649 | 1.0 | TestGroup1 | Description has been updated from XSOAR end. | false |


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
| STA.USER.ID | string | User ID of the user. | 
| STA.USER.NAME | string | Username of the user. | 
| STA.USER.TYPE | string | Type of the user. | 


#### Command Example
```!sta-get-group-members groupName="TestGroup0"```

#### Context Example
```json
{
    "STA": {
        "USER": [
            {
                "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
                "links": {
                    "self": "https://api.stademo.com/api/v1/tenants/HNESAUHHA6/users/CNlM6Pyq3nADXA4rWyUAAAAc?isUid=true"
                },
                "name": "demouser",
                "type": "User"
            },
            {
                "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
                "links": {
                    "self": "https://api.stademo.com/api/v1/tenants/HNESAUHHA6/users/CNlM6rvB0uQDXA4rWyUAAAAc?isUid=true"
                },
                "name": "hellouser",
                "type": "User"
            }
        ]
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
| isSynchronized | Is group synchronized. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.GROUP.ID | string | Group ID of the group. | 
| STA.GROUP.SCHEMA | string | Schema version for the group. | 
| STA.GROUP.NAME | string | Name of the group. | 
| STA.GROUP.DESCRIPTION | string | Description of the group. | 
| STA.GROUP.SYNCHRONIZED | boolean | Is group synchronized. | 


#### Command Example
```!sta-create-group groupName="TestGroup2" description="Group description." isSynchronized=False```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "description": "Group description.",
            "id": "16777225",
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
>| 16777225 | 1.0 | TestGroup2 | Group description. | false |


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
| STA.DELETE.GROUP | string | Group successfully deleted. | 


#### Command Example
```!sta-delete-group groupName="TestGroup2"```

#### Context Example
```json
{
    "STA": {
        "DELETE": {
            "GROUP": 204
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
```!sta-update-group-info groupName="TestGroup1" description="Description has been updated from XSOAR end."```

#### Context Example
```json
{
    "STA": {
        "GROUP": {
            "description": "Description has been updated from XSOAR end.",
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
>| 50331649 | 1.0 | TestGroup1 | Description has been updated from XSOAR end. | false |


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
| STA.USER.EXIST.GROUP | string | Check if user exists in group. | 


#### Command Example
```!sta-user-exist-group groupName="TestGroup1" userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "USER": {
            "EXIST": {
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
| STA.ADD.USER.GROUP | string | User successfully added to the group. | 


#### Command Example
```!sta-add-user-group groupName="TestGroup1" userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "ADD": {
            "USER": {
                "GROUP": 200
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
| STA.REMOVE.USER.GROUP | unknown | User successfully removed from the group. | 


#### Command Example
```!sta-remove-user-group groupName="TestGroup1" userName="hellouser"```

#### Context Example
```json
{
    "STA": {
        "REMOVE": {
            "USER": {
                "GROUP": 204
            }
        }
    }
}
```

#### Human Readable Output

>## User - hellouser successfully removed from the group - TestGroup1.

### sta-get-access-logs
***
Fetch the access logs.


#### Base Command

`sta-get-access-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username of the user. | Optional | 
| since | Filter logs since the specified date and time in UTC time zone. Format : yyyy-mm-ddTHH:mm:ss.fffZ  .Example : 2021-06-03T06:27:00.000Z. | Optional | 
| till | Filter logs until the specified date and time in UTC time zone. Format : yyyy-mm-ddTHH:mm:ss.fffZ  .Example : 2021-06-03T07:40:00.000Z. | Optional | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| STA.LOGS.TIMESTAMP | date | Timestamp of event. | 
| STA.LOGS.USERNAME | string | Username of the user. | 
| STA.LOGS.RESULT | string | Result of the event. | 
| STA.LOGS.TYPE | string | Authentication type. | 
| STA.LOGS.IP | string | IP of the user. | 
| STA.LOGS.MESSAGE | string | Authentication message. | 
| STA.LOGS.ACTION | string | Action type of the event. | 
| STA.LOGS.SERIAL | number | Authentication serial number. | 


#### Command Example
```!sta-get-access-logs userName="demouser" since="2021-07-21T12:22:16.718Z"```

#### Context Example
```json
{
    "STA": {
        "LOGS": {
            "actionText": "AUTH_ATTEMPT",
            "credentialType": "MobilePASS",
            "ip": "165.225.104.81",
            "message": "Login from SafeNet Authentication Service Console.",
            "resultText": "AUTH_SUCCESS",
            "serial": "1000014514",
            "timeStamp": "2021-07-22T09:20:21.1356016Z",
            "userName": "demouser"
        }
    }
}
```

#### Human Readable Output

>### Access logs : 
>|Time Stamp|User Name|Action Text|Result Text|Credential Type|Message|Serial|Ip|
>|---|---|---|---|---|---|---|---|
>| 2021-07-22T08:19:05.5905986Z | demouser | AUTH_ATTEMPT | CHALLENGE | MobilePASS | Login from SafeNet Authentication Service Console. | 1000014514 | 165.225.104.81 |
>| 2021-07-22T08:20:45.5326006Z | demouser | AUTH_ATTEMPT | AUTH_SUCCESS | MobilePASS | Login from SafeNet Authentication Service Console. | 1000014514 | 165.225.104.81 |
>| 2021-07-22T09:20:21.1356016Z | demouser | AUTH_ATTEMPT | AUTH_SUCCESS | MobilePASS | Login from SafeNet Authentication Service Console. | 1000014514 | 165.225.104.81 |


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
| STA.VALIDATE.TENANT | string | Checks if you have permission to access the requested tenant. | 


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
