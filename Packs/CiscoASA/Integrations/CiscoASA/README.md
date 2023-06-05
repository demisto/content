Use the Cisco Adaptive Security Appliance Software integration to manage interfaces, rules, and network objects.
This integration was integrated and tested with version xx of Cisco ASA

## Configure Cisco ASA on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco ASA.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | True |
    | Credentials | True |
    | Password | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |
    | Is ASAv | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-asa-list-network-object-group

***
Retrieve information about network object groups. Network object groups can contain multiple network objects as well as inline networks or hosts. Network object groups can include a mix of both IPv4 and IPv6 addresses/network.

#### Base Command

`cisco-asa-list-network-object-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID of the network group to retrieve. This can't be used with pagination arguments. | Optional | 
| page | Page number of paginated results. Minimum of 1; default 1. | Optional | 
| page_size | The number of items per page. Maximum of 100; default 50. | Optional | 
| limit | The maximum number of records to retrieve. Maximum of 100; default 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.NetworkObjectGroup.object_id | String | The object ID of the network object group. | 
| CiscoASA.NetworkObjectGroup.name | String | The name of the network object group. | 
| CiscoASA.NetworkObjectGroup.description | String | The description of the network object group. | 
| CiscoASA.NetworkObjectGroup.members.kind | String | The type of the network item. The viable types are IPv4Address, IPv4Network, IPv6Address, IPv6Network and objectRef\#NetworkObj. | 
| CiscoASA.NetworkObjectGroup.members.object_id | String | The object ID of the network object. | 
| CiscoASA.NetworkObjectGroup.members.value | String | The value of IPv4Address, IPv4Network, IPv6Address or IPv6Network. | 

#### Command example
```!cisco-asa-list-network-object-group limit=1```
#### Context Example
```json
{
    "CiscoASA": {
        "NetworkObjectGroup": {
            "description": "This is a test",
            "members": [
                {
                    "kind": "objectRef#NetworkObj",
                    "object_id": "Test_Lior"
                },
                {
                    "kind": "objectRef#NetworkObj",
                    "object_id": "Test_Lior1"
                },
                {
                    "kind": "objectRef#NetworkObj",
                    "object_id": "Test_Lior2"
                }
            ],
            "name": "TEST_GROUP1",
            "object_id": "TEST_GROUP1"
        }
    }
}
```

#### Human Readable Output

>### Network Object Groups
>|Object Id|Name|Description|Members|
>|---|---|---|---|
>| TEST_GROUP1 | TEST_GROUP1 | This is a test | {'kind': 'objectRef#NetworkObj', 'object_id': 'Test_Lior'},<br/>{'kind': 'objectRef#NetworkObj', 'object_id': 'Test_Lior1'},<br/>{'kind': 'objectRef#NetworkObj', 'object_id': 'Test_Lior2'} |


### cisco-asa-list-local-user-group

***
Retrieve information about local user groups, which are collections of user accounts, either from the local database or imported from Active Directory, that manage access to network resources not defined globally.

#### Base Command

`cisco-asa-list-local-user-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID of the local user group to retrieve. This can't be used with pagination arguments. | Optional | 
| page | Page number of paginated results. Minimum of 1; default 1. | Optional | 
| page_size | The number of items per page. Maximum of 100; default 50. | Optional | 
| limit | The maximum number of records to retrieve. Maximum of 100; default 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.LocalUserGroup.object_id | String | The object ID of the local user group. | 
| CiscoASA.LocalUserGroup.name | String | The name of the local user group. | 
| CiscoASA.LocalUserGroup.description | String | The description of the local user group. | 
| CiscoASA.LocalUserGroup.members.kind | String | The type of the user. | 
| CiscoASA.LocalUserGroup.members.object_id | String | The ID of the user. | 

#### Command example
```!cisco-asa-list-local-user-group limit=1```
#### Context Example
```json
{
    "CiscoASA": {
        "LocalUserGroup": {
            "members": [
                {
                    "kind": "objectRef#UserObj",
                    "object_id": "api"
                },
                {
                    "kind": "objectRef#UserObj",
                    "object_id": "restapi"
                }
            ],
            "name": "LIOR_GROUP",
            "object_id": "LIOR_GROUP"
        }
    }
}
```

#### Human Readable Output

>### Local User Groups
>|Object Id|Name|Members|
>|---|---|---|
>| LIOR_GROUP | LIOR_GROUP | {'kind': 'objectRef#UserObj', 'object_id': 'api'},<br/>{'kind': 'objectRef#UserObj', 'object_id': 'restapi'} |


### cisco-asa-list-local-user

***
Retrieve information about individual local user accounts within a network system. These local users can be part of local user groups and groups imported from Active Directory.

#### Base Command

`cisco-asa-list-local-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID of the local user to retrieve. This can't be used with pagination arguments. | Optional | 
| page | Page number of paginated results. Minimum of 1; default 1. | Optional | 
| page_size | The number of items per page. Maximum of 100; default 50. | Optional | 
| limit | The maximum number of records to retrieve. Maximum of 100; default 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.LocalUser.object_id | String | The object ID of the local user. | 
| CiscoASA.LocalUser.name | String | The name of the local user. | 
| CiscoASA.LocalUser.mschap_authenticated | Boolean | Whether Extensible Authentication Protocol-Microsoft Challenge Handshake Authentication Protocol authenticated. | 
| CiscoASA.LocalUser.privilege_level | Number | The user's privilege level. | 
| CiscoASA.LocalUser.asdm_cli_access_type | String | ASDM and CLI access type; can be one of "Full", "None", "Cli". | 

#### Command example
```!cisco-asa-list-local-user limit=1```
#### Context Example
```json
{
    "CiscoASA": {
        "LocalUser": {
            "asdm_cli_access_type": "Full",
            "mschap_authenticated": false,
            "name": "admin",
            "object_id": "admin",
            "privilege_level": 15
        }
    }
}
```

#### Human Readable Output

>### Local Users
>|Object Id|Name|Privilege Level|Asdm Cli Access Type|
>|---|---|---|---|
>| admin | admin | 15 | Full |


### cisco-asa-list-time-range

***
Retrieve information about time range objects. A time range object defines a specific time consisting of a start time, an end time, and optional recurring entries. You use these objects on ACL rules to provide time-based access to certain features or assets. For example, you could create an access rule that allows access to a particular server during working hours only.

#### Base Command

`cisco-asa-list-time-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID of the time range to retrieve. This can't be used with pagination arguments. | Optional | 
| page | Page number of paginated results. Minimum of 1; default 1. | Optional | 
| page_size | The number of items per page. Maximum of 100; default 50. | Optional | 
| limit | The maximum number of records to retrieve. Maximum of 100; default 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.TimeRange.object_id | String | The object ID of the time range. | 
| CiscoASA.TimeRange.name | String | The name of the time range. | 
| CiscoASA.TimeRange.start | String | Time at which this time range starts. | 
| CiscoASA.TimeRange.end | String | Time at which this time range ends. | 
| CiscoASA.TimeRange.periodic.frequency | String | The days of the week at which this time range will run periodically. | 
| CiscoASA.TimeRange.periodic.start_hour | Number | The hour at which this time range will start periodically. | 
| CiscoASA.TimeRange.periodic.start_minute | Number | The minute at which this time range will start periodically. | 
| CiscoASA.TimeRange.periodic.end_hour | Number | The hour at which this time range will end periodically. | 
| CiscoASA.TimeRange.periodic.end_minute | Number | The minute at which this time range will end periodically. | 

#### Command example
```!cisco-asa-list-time-range page=1 page_size=1```
#### Context Example
```json
{
    "CiscoASA": {
        "TimeRange": {
            "end": "03:47 May 14 2014",
            "name": "trUserTest",
            "object_id": "trUserTest",
            "periodic": [
                {
                    "end_hour": 23,
                    "end_minute": 59,
                    "frequency": "Wednesday to Thursday",
                    "start_hour": 4,
                    "start_minute": 3
                }
            ],
            "start": "now"
        }
    }
}
```

#### Human Readable Output

>### Time Ranges
>|Object Id|Name|Start|End|Periodic|
>|---|---|---|---|---|
>| trUserTest | trUserTest | now | 03:47 May 14 2014 | {'frequency': 'Wednesday to Thursday', 'start_hour': 4, 'start_minute': 3, 'end_hour': 23, 'end_minute': 59} |


### cisco-asa-list-security-object-group

***
Retrieve information about security groups, which are collections of security groups or identifiers that manage access and permissions to network resources. These groups can be used in features like Cisco TrustSec and are often part of extended access control lists, enabling centralized and localized security policy management.

#### Base Command

`cisco-asa-list-security-object-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID of the security object group to retrieve. This can't be used with pagination arguments. | Optional | 
| page | Page number of paginated results. Minimum of 1; default 1. | Optional | 
| page_size | The number of items per page. Maximum of 100; default 50. | Optional | 
| limit | The maximum number of records to retrieve. Maximum of 100; default 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.SecurityObjectGroup.object_id | String | The object ID of the security object group. | 
| CiscoASA.SecurityObjectGroup.name | String | The name of the security object group. | 
| CiscoASA.SecurityObjectGroup.description | String | The description of the security object group. | 
| CiscoASA.SecurityObjectGroup.members.kind | String | The type of the security object group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.SecurityObjectGroup.members.value | String | The value of the SecurityName or SecurityTag. | 
| CiscoASA.SecurityObjectGroup.members.object_id | String | The object ID of objectRef\#SecurityObjGroup. | 

#### Command example
```!cisco-asa-list-security-object-group page=1 page_size=1```
#### Context Example
```json
{
    "CiscoASA": {
        "SecurityObjectGroup": {
            "description": "test12",
            "members": [
                {
                    "kind": "SecurityName",
                    "value": "zeno1"
                },
                {
                    "kind": "SecurityTag",
                    "value": "71"
                }
            ],
            "name": "oneSecurityGroup",
            "object_id": "oneSecurityGroup"
        }
    }
}
```

#### Human Readable Output

>### Security Object Groups
>|Object Id|Name|Description|Members|
>|---|---|---|---|
>| oneSecurityGroup | oneSecurityGroup | test12 | {'kind': 'SecurityName', 'value': 'zeno1'},<br/>{'kind': 'SecurityTag', 'value': '71'} |


### cisco-asa-list-user-object

***
Retrieve information about user definitions within the system. This helps in managing and configuring user access and permissions in a network security context.

#### Base Command

`cisco-asa-list-user-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The object ID of the user object to retrieve. This can't be used with pagination arguments. | Optional | 
| page | Page number of paginated results. Minimum of 1; default 1. | Optional | 
| page_size | The number of items per page. Maximum of 100; default 50. | Optional | 
| limit | The maximum number of records to retrieve. Maximum of 100; default 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.UserObject.object_id | String | The object ID of the user object. | 
| CiscoASA.UserObject.user_name | String | The user's user name. | 
| CiscoASA.UserObject.local_user_object_id | String | The object ID of the local user. | 
| CiscoASA.UserObject.value | String | The value of the local user. | 

#### Command example
```!cisco-asa-list-user-object page=1 page_size=1```
#### Context Example
```json
{
    "CiscoASA": {
        "UserObject": {
            "local_user_object_id": "api",
            "object_id": "api",
            "user_name": "api"
        }
    }
}
```

#### Human Readable Output

>### User Objects
>|Object Id|User Name|
>|---|---|
>| api | api |


### cisco-asa-write-memory

***
The write memory command saves the running configuration to the default location for the startup configuration.

#### Base Command

`cisco-asa-write-memory`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.WriteMemory.response | String | shows a successful 'write memory' command execution on a Cisco ASA device, building the configuration and generating a cryptochecksum for integrity. The process is completed with an "\[OK\]" message. | 

#### Command example
```!cisco-asa-write-memory```
#### Context Example
```json
{
    "CiscoASA": {
        "WriteMemory": {
            "response": [
                "Building configuration...\nCryptochecksum: fa399474 22b66df0 6e2a7619 b37adea3 \n\n20838 bytes copied in 0.50 secs\n[OK]\n"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|response|
>|---|
>| Building configuration...<br/>Cryptochecksum: fa399474 22b66df0 6e2a7619 b37adea3 <br/><br/>20838 bytes copied in 0.50 secs<br/>[OK]<br/> |


### cisco-asa-list-rules

***
Gets a list all rules for the supplied interface.

#### Base Command

`cisco-asa-list-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interface_name | The name of the interface from which to get rules. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". . Possible values are: In, Out, Global. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 
| CiscoASA.Rules.SourceKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.DestKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.SourceSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.SourceSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.SourceSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.DestinationSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.User.kind | String | One of AnyUser, NoneUser, objectRef\#LocalUserObjGroup, objectRef\#UserGroupObj, objectRef\#UserObj | 
| CiscoASA.Rules.User.value | String | The user value. | 
| CiscoASA.Rules.User.objectId | String | The object ID of the user. | 
| CiscoASA.Rules.TimeRange.kind | String | The object reference type or the actual TimeRange value. | 
| CiscoASA.Rules.TimeRange.value | String | The value of the time range. | 
| CiscoASA.Rules.TimeRange.objectId | String | The object ID of the time range. | 

#### Command example
```!cisco-asa-list-rules interface_type=Global```
#### Context Example
```json
{
    "CiscoASA": {
        "Rules": [
            {
                "Dest": "TEST_GROUP2",
                "DestKind": "objectRef#NetworkObjGroup",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "71"
                },
                "ID": "3583139358",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": true,
                "Permit": false,
                "Position": 1,
                "Remarks": [],
                "Source": "TEST_GROUP1",
                "SourceKind": "objectRef#NetworkObjGroup",
                "SourceSecurity": {
                    "kind": "objectRef#SecurityObjGroup",
                    "objectId": "oneSecurityGroup"
                },
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                },
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "TEST_GROUP2",
                "DestKind": "objectRef#NetworkObjGroup",
                "DestService": "ip",
                "ID": "3194110035",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": true,
                "Permit": false,
                "Position": 2,
                "Remarks": [],
                "Source": "TEST_GROUP1",
                "SourceKind": "objectRef#NetworkObjGroup",
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                },
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "8.88.8.8",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "2152246838",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 3,
                "Remarks": [
                    "123",
                    "123",
                    "123",
                    "123",
                    "123",
                    "123"
                ],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                },
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "LOCAL_API_BACK_SLASH_qadmin"
                }
            },
            {
                "Dest": "9.9.98.134",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "3678444278",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 4,
                "Remarks": [
                    "123"
                ],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                },
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "LOCAL_API_BACK_SLASH_api"
                }
            },
            {
                "Dest": "9.9.98.134",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "3197713155",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 5,
                "Remarks": [
                    "123"
                ],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                }
            },
            {
                "Dest": "9.9.98.24",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "3283508865",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 6,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                }
            },
            {
                "Dest": "121.1.10.0/24",
                "DestKind": "IPv4Network",
                "DestService": "ip",
                "ID": "66321110",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 7,
                "Remarks": [],
                "Source": "80.80.80.10",
                "SourceKind": "IPv4Address",
                "SourceService": "ip"
            },
            {
                "Dest": "2.3.4.5",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "4164799404",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": true,
                "Position": 8,
                "Remarks": [],
                "Source": "3.4.5.6",
                "SourceKind": "IPv4Address",
                "SourceService": "ip"
            },
            {
                "Dest": "1.1.1.0/24",
                "DestKind": "IPv4Network",
                "DestService": "ip",
                "ID": "1804620212",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": true,
                "Position": 9,
                "Remarks": [],
                "Source": "1.1.1.0/24",
                "SourceKind": "IPv4Network",
                "SourceService": "ip"
            },
            {
                "Dest": "1.1.1.0/24",
                "DestKind": "IPv4Network",
                "DestService": "ip",
                "ID": "3885338977",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": true,
                "Position": 10,
                "Remarks": [],
                "Source": "TEST_GROUP1",
                "SourceKind": "objectRef#NetworkObjGroup",
                "SourceService": "ip"
            },
            {
                "Dest": "1.1.1.0/24",
                "DestKind": "IPv4Network",
                "DestService": "ip",
                "ID": "256234915",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": true,
                "Position": 11,
                "Remarks": [],
                "Source": "TEST_GROUP1",
                "SourceKind": "objectRef#NetworkObjGroup",
                "SourceService": "ip",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "LOCAL_API_BACK_SLASH_api"
                }
            },
            {
                "Dest": "9.9.9.9",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "164613141",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 12,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.9.2",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "582621523",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 13,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.9.2",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "2722832655",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 14,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.9.2",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "2658041834",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 15,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.9.44",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "250433276",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 16,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.9.34",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "2493527555",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 17,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.9.24",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "1985112553",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 18,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip"
            },
            {
                "Dest": "9.9.97.24",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "DestinationSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "ID": "3747253149",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 19,
                "Remarks": [],
                "Source": "8.8.8.8",
                "SourceKind": "IPv4Address",
                "SourceSecurity": {
                    "kind": "SecurityName",
                    "value": "oneSecurityGroup"
                },
                "SourceService": "ip",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                }
            },
            {
                "Dest": "1.1.1.1",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "1637366722",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": true,
                "Permit": false,
                "Position": 20,
                "Remarks": [],
                "Source": "2.2.2.2",
                "SourceKind": "IPv4Address",
                "SourceService": "ip"
            },
            {
                "Dest": "1.1.1.0",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "947522241",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": true,
                "Permit": false,
                "Position": 21,
                "Remarks": [],
                "Source": "2.2.2.0/24",
                "SourceKind": "IPv4Network",
                "SourceService": "ip"
            },
            {
                "Dest": "1.1.0.0",
                "DestKind": "IPv4Address",
                "DestService": "ip",
                "ID": "2117166018",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 22,
                "Remarks": [],
                "Source": "2.2.2.0/24",
                "SourceKind": "IPv4Network",
                "SourceService": "ip"
            },
            {
                "Dest": "1.0.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "ID": "1073590608",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 23,
                "Remarks": [],
                "Source": "2.2.2.0/24",
                "SourceKind": "IPv4Network",
                "SourceService": "tcp/cifs"
            },
            {
                "Dest": "0.0.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "ID": "2265996835",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 24,
                "Remarks": [],
                "Source": "2.2.2.0/24",
                "SourceKind": "IPv4Network",
                "SourceService": "tcp/cifs"
            },
            {
                "Dest": "0.0.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "ID": "3356130164",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 25,
                "Remarks": [],
                "Source": "2.2.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceService": "tcp/cifs"
            },
            {
                "Dest": "0.0.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "2585882281",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 26,
                "Remarks": [],
                "Source": "2.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs"
            },
            {
                "Dest": "0.0.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "3796265964",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 27,
                "Remarks": [],
                "Source": "2.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                },
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "LOCAL_API_BACK_SLASH_api"
                }
            },
            {
                "Dest": "0.0.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "2719669867",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 28,
                "Remarks": [],
                "Source": "9.9.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "TimeRange": {
                    "kind": "objectRef#TimeRange",
                    "objectId": "trUserTest"
                },
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "LOCAL_API_BACK_SLASH_api"
                }
            },
            {
                "Dest": "2.2.2.2",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "1244564438",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 29,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "LOCAL_API_BACK_SLASH_api"
                }
            },
            {
                "Dest": "5.5.5.5",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "3371063501",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": true,
                "Permit": false,
                "Position": 30,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "5.5.5.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "1759670323",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 31,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "5.5.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "874938452",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 32,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "9.9.0.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "328819598",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 33,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "9.9.9.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "2657762586",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 34,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "9.1.9.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "4111751697",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 35,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "9.2.4.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "947043677",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 36,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            },
            {
                "Dest": "9.5.4.0",
                "DestKind": "IPv4Address",
                "DestService": "tcp/citrix-ica",
                "DestinationSecurity": {
                    "kind": "SecurityTag",
                    "value": "1"
                },
                "ID": "3152305802",
                "Interface": null,
                "InterfaceType": "Global",
                "IsActive": false,
                "Permit": false,
                "Position": 37,
                "Remarks": [],
                "Source": "0.0.0.0/24",
                "SourceKind": "IPv4Network",
                "SourceSecurity": {
                    "kind": "SecurityTag",
                    "value": "2"
                },
                "SourceService": "tcp/cifs",
                "User": {
                    "kind": "objectRef#UserObj",
                    "objectId": "api"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Rules:
>|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|DestService|
>|---|---|---|---|---|---|---|---|---|---|
>| 3583139358 | TEST_GROUP1 | TEST_GROUP2 | false |  | Global | true | 1 | ip | ip |
>| 3194110035 | TEST_GROUP1 | TEST_GROUP2 | false |  | Global | true | 2 | ip | ip |
>| 2152246838 | 8.8.8.8 | 8.88.8.8 | false |  | Global | false | 3 | ip | ip |
>| 3678444278 | 8.8.8.8 | 9.9.98.134 | false |  | Global | false | 4 | ip | ip |
>| 3197713155 | 8.8.8.8 | 9.9.98.134 | false |  | Global | false | 5 | ip | ip |
>| 3283508865 | 8.8.8.8 | 9.9.98.24 | false |  | Global | false | 6 | ip | ip |
>| 66321110 | 80.80.80.10 | 121.1.10.0/24 | false |  | Global | false | 7 | ip | ip |
>| 4164799404 | 3.4.5.6 | 2.3.4.5 | true |  | Global | false | 8 | ip | ip |
>| 1804620212 | 1.1.1.0/24 | 1.1.1.0/24 | true |  | Global | false | 9 | ip | ip |
>| 3885338977 | TEST_GROUP1 | 1.1.1.0/24 | true |  | Global | false | 10 | ip | ip |
>| 256234915 | TEST_GROUP1 | 1.1.1.0/24 | true |  | Global | false | 11 | ip | ip |
>| 164613141 | 8.8.8.8 | 9.9.9.9 | false |  | Global | false | 12 | ip | ip |
>| 582621523 | 8.8.8.8 | 9.9.9.2 | false |  | Global | false | 13 | ip | ip |
>| 2722832655 | 8.8.8.8 | 9.9.9.2 | false |  | Global | false | 14 | ip | ip |
>| 2658041834 | 8.8.8.8 | 9.9.9.2 | false |  | Global | false | 15 | ip | ip |
>| 250433276 | 8.8.8.8 | 9.9.9.44 | false |  | Global | false | 16 | ip | ip |
>| 2493527555 | 8.8.8.8 | 9.9.9.34 | false |  | Global | false | 17 | ip | ip |
>| 1985112553 | 8.8.8.8 | 9.9.9.24 | false |  | Global | false | 18 | ip | ip |
>| 3747253149 | 8.8.8.8 | 9.9.97.24 | false |  | Global | false | 19 | ip | ip |
>| 1637366722 | 2.2.2.2 | 1.1.1.1 | false |  | Global | true | 20 | ip | ip |
>| 947522241 | 2.2.2.0/24 | 1.1.1.0 | false |  | Global | true | 21 | ip | ip |
>| 2117166018 | 2.2.2.0/24 | 1.1.0.0 | false |  | Global | false | 22 | ip | ip |
>| 1073590608 | 2.2.2.0/24 | 1.0.0.0 | false |  | Global | false | 23 | tcp/cifs | tcp/citrix-ica |
>| 2265996835 | 2.2.2.0/24 | 0.0.0.0 | false |  | Global | false | 24 | tcp/cifs | tcp/citrix-ica |
>| 3356130164 | 2.2.0.0/24 | 0.0.0.0 | false |  | Global | false | 25 | tcp/cifs | tcp/citrix-ica |
>| 2585882281 | 2.0.0.0/24 | 0.0.0.0 | false |  | Global | false | 26 | tcp/cifs | tcp/citrix-ica |
>| 3796265964 | 2.0.0.0/24 | 0.0.0.0 | false |  | Global | false | 27 | tcp/cifs | tcp/citrix-ica |
>| 2719669867 | 9.9.0.0/24 | 0.0.0.0 | false |  | Global | false | 28 | tcp/cifs | tcp/citrix-ica |
>| 1244564438 | 0.0.0.0/24 | 2.2.2.2 | false |  | Global | false | 29 | tcp/cifs | tcp/citrix-ica |
>| 3371063501 | 0.0.0.0/24 | 5.5.5.5 | false |  | Global | true | 30 | tcp/cifs | tcp/citrix-ica |
>| 1759670323 | 0.0.0.0/24 | 5.5.5.0 | false |  | Global | false | 31 | tcp/cifs | tcp/citrix-ica |
>| 874938452 | 0.0.0.0/24 | 5.5.0.0 | false |  | Global | false | 32 | tcp/cifs | tcp/citrix-ica |
>| 328819598 | 0.0.0.0/24 | 9.9.0.0 | false |  | Global | false | 33 | tcp/cifs | tcp/citrix-ica |
>| 2657762586 | 0.0.0.0/24 | 9.9.9.0 | false |  | Global | false | 34 | tcp/cifs | tcp/citrix-ica |
>| 4111751697 | 0.0.0.0/24 | 9.1.9.0 | false |  | Global | false | 35 | tcp/cifs | tcp/citrix-ica |
>| 947043677 | 0.0.0.0/24 | 9.2.4.0 | false |  | Global | false | 36 | tcp/cifs | tcp/citrix-ica |
>| 3152305802 | 0.0.0.0/24 | 9.5.4.0 | false |  | Global | false | 37 | tcp/cifs | tcp/citrix-ica |


### cisco-asa-backup

***
Creates a backup of the current settings (i.e., the backup.cfg file).

#### Base Command

`cisco-asa-backup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| backup_name | The name of the backup. | Required | 
| passphrase | The passphrase for the backup. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-asa-backup backup_name=Lior```
#### Human Readable Output

>Created backup successfully in:
>Location: disk0:/Lior
>Passphrase: None

### cisco-asa-get-rule-by-id

***
Gets a specific rule by rule ID.

#### Base Command

`cisco-asa-get-rule-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. | Required | 
| interface_name | The name of the interface. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". Possible values are: In, Out, Global. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 
| CiscoASA.Rules.SourceKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.DestKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.SourceSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.SourceSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.SourceSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.DestinationSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.User.kind | String | One of AnyUser, NoneUser, objectRef\#LocalUserObjGroup, objectRef\#UserGroupObj, objectRef\#UserObj | 
| CiscoASA.Rules.User.value | String | The user value. | 
| CiscoASA.Rules.User.objectId | String | The object ID of the user. | 
| CiscoASA.Rules.TimeRange.kind | String | The object reference type or the actual TimeRange value. | 
| CiscoASA.Rules.TimeRange.value | String | The value of the time range. | 
| CiscoASA.Rules.TimeRange.objectId | String | The object ID of the time range. | 

#### Command example
```!cisco-asa-get-rule-by-id interface_type=Global rule_id=3371063501```
#### Context Example
```json
{
    "CiscoASA": {
        "Rules": {
            "Dest": "5.5.5.5",
            "DestKind": "IPv4Address",
            "DestService": "tcp/citrix-ica",
            "DestinationSecurity": {
                "kind": "SecurityTag",
                "value": "1"
            },
            "ID": "3371063501",
            "Interface": "",
            "InterfaceType": "Global",
            "IsActive": true,
            "Permit": false,
            "Position": 30,
            "Remarks": [],
            "Source": "0.0.0.0/24",
            "SourceKind": "IPv4Network",
            "SourceSecurity": {
                "kind": "SecurityTag",
                "value": "2"
            },
            "SourceService": "tcp/cifs",
            "User": {
                "kind": "objectRef#UserObj",
                "objectId": "api"
            }
        }
    }
}
```

#### Human Readable Output

>### Rule 3371063501:
>|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|DestService|
>|---|---|---|---|---|---|---|---|---|---|
>| 3371063501 | 0.0.0.0/24 | 5.5.5.5 | false |  | Global | true | 30 | tcp/cifs | tcp/citrix-ica |


### cisco-asa-create-rule

***
Creates a rule.

#### Base Command

`cisco-asa-create-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | The source. Can be the value of an IPv4, an address block, or the name of a network object. | Required | 
| destination | The destination. Can be the value of an IPv4, an address block, or the name of a network object. | Required | 
| permit | Whether the rule is a permit. If True, the rule is a permit. Possible values are: True, False. | Required | 
| remarks | A list of remarks for the rule. | Optional | 
| position | The position in which to create the rule. | Optional | 
| log_level | The log level of the rule. Can be "Default", "Emergencies", "Alerts", "Critical", "Errors", "Warnings", "Notifications", "Informational", or "Debugging". Possible values are: Default, Emergencies, Alerts, Critical, Errors, Warnings, Notifications, Informational, Debugging. | Optional | 
| active | Whether the rule will be active. If True, the rule will be active. Possible values are: True, False. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". Possible values are: In, Out, Global. | Required | 
| interface_name | The interface name. | Optional | 
| service | The service of the rule. | Optional | 
| destination_kind | The destination address kind in the ace. Can be on of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. Possible values are: AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. | Optional | 
| source_kind | The source address kind in the ace. Can be on of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. Possible values are: AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. | Optional | 
| service_kind | The source service kind, can be one of AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. Possible values are: AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. | Optional | 
| destination_service | The destination service value. | Optional | 
| destination_service_kind | The destination service kind, can be one of AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. Possible values are: AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. | Optional | 
| time_range | Object ID of for the time range object. Can be received with the command cisco-asa-list-time-range. | Optional | 
| user | The object ID to the user; can be one of LocalUserObjGroup, UserGroupObj, UserObj. Can be received with existing commands; cisco-asa-list-local-user-group, cisco-asa-list-local-user, cisco-asa-list-user-object. | Optional | 
| user_kind | The type of the user, can be one of LocalUserObjGroup, UserGroupObj, UserObj. Possible values are: LocalUserObjGroup, UserGroupObj, UserObj. | Optional | 
| source_security | Source security group in the ace. Can be one of SecurityName, SecurityTag and SecurityObjGroup values can be added. Can be received with the existing command cisco-asa-list-security-object-group. | Optional | 
| source_security_kind | The source security type, can be one of SecurityName, SecurityTag, SecurityObjGroup. Possible values are: SecurityName, SecurityTag, SecurityObjGroup. | Optional | 
| destination_security | Destination security group in the ace. Can be one of SecurityName, SecurityTag and SecurityObjGroup values can be added. Can be received with the existing command cisco-asa-list-security-object-group. | Optional | 
| destination_security_kind | The destination security type, can be one of SecurityName, SecurityTag, SecurityObjGroup. Possible values are: SecurityName, SecurityTag, SecurityObjGroup. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 
| CiscoASA.Rules.SourceKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.DestKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.SourceSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.SourceSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.SourceSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.DestinationSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.User.kind | String | One of AnyUser, NoneUser, objectRef\#LocalUserObjGroup, objectRef\#UserGroupObj, objectRef\#UserObj | 
| CiscoASA.Rules.User.value | String | The user value. | 
| CiscoASA.Rules.User.objectId | String | The object ID of the user. | 
| CiscoASA.Rules.TimeRange.kind | String | The object reference type or the actual TimeRange value. | 
| CiscoASA.Rules.TimeRange.value | String | The value of the time range. | 
| CiscoASA.Rules.TimeRange.objectId | String | The object ID of the time range. | 

#### Command example
```!cisco-asa-create-rule destination=9.5.4.0 source=0.0.0.0/24 interface_type=Global permit=False destination_kind=IPv4Address source_kind=IPv4Network active=False service_kind=TcpUdpService service=tcp/cifs destination_service=tcp/citrix-ica destination_service_kind=TcpUdpService destination_security_kind=SecurityTag destination_security=1 source_security_kind=SecurityTag source_security=2 timerange=trUserTest user_kind=UserObj user=api```
#### Context Example
```json
{
    "CiscoASA": {
        "Rules": {
            "Dest": "9.5.4.0",
            "DestKind": "IPv4Address",
            "DestService": "tcp/citrix-ica",
            "DestinationSecurity": {
                "kind": "SecurityTag",
                "value": "1"
            },
            "ID": "3152305802",
            "Interface": "",
            "InterfaceType": "Global",
            "IsActive": false,
            "Permit": false,
            "Position": 37,
            "Remarks": [],
            "Source": "0.0.0.0/24",
            "SourceKind": "IPv4Network",
            "SourceSecurity": {
                "kind": "SecurityTag",
                "value": "2"
            },
            "SourceService": "tcp/cifs",
            "User": {
                "kind": "objectRef#UserObj",
                "objectId": "api"
            }
        }
    }
}
```

#### Human Readable Output

>### Created new rule. ID: 3152305802
>|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|DestService|
>|---|---|---|---|---|---|---|---|---|---|
>| 3152305802 | 0.0.0.0/24 | 9.5.4.0 | false |  | Global | false | 37 | tcp/cifs | tcp/citrix-ica |


### cisco-asa-delete-rule

***
Deletes a rule.

#### Base Command

`cisco-asa-delete-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. | Required | 
| interface_name | The name of the interface. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". Possible values are: In, Out, Global. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-asa-delete-rule rule_id=2152246838 interface_type=Global```
#### Human Readable Output

>Rule 2152246838 deleted successfully.

### cisco-asa-edit-rule

***
Updates an existing rule.

#### Base Command

`cisco-asa-edit-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interface_type | The interface type. Can be "In", "Out", or "Global". Possible values are: In, Out, Global. | Required | 
| interface_name | The interface name. | Optional | 
| rule_id | The rule ID. | Required | 
| active | Whether the rule will be active. If True, will be active. Possible values are: True, False. | Optional | 
| log_level | The log level of the rule. | Optional | 
| position | The position the rule will be in. . | Optional | 
| remarks | A list of remarks for the rule. | Optional | 
| permit | True if the rule is a permit. Possible values are: True, False. | Optional | 
| destination | The destination. Can be the value of an IPv4, an address block, or the name of a network object. | Optional | 
| source | The source. Can be the value of an IPv4, an address block, or the name of a network object. | Optional | 
| service | The service of the rule. | Optional | 
| destination_kind | The destination address kind in the ace. Can be on of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. Possible values are: AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. | Optional | 
| source_kind | The source address kind in the ace. Can be on of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. Possible values are: AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, NetworkObj, NetworkObjGroup. | Optional | 
| service_kind | The source service kind, can be one of AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. Possible values are: AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. | Optional | 
| destination_service | The destination service value. | Optional | 
| destination_service_kind | The destination service kind, can be one of AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. Possible values are: AnyService, ICMP6Service, ICMPService, NetworkProtocol, NetworkServiceGroups, NetworkServiceObjects, TcpUdpService. | Optional | 
| time_range | Object ID of for the time range object. Can be received with the command cisco-asa-list-time-range. | Optional | 
| user | The object ID to the user; can be one of LocalUserObjGroup, UserGroupObj, UserObj. Can be received with existing commands; cisco-asa-list-local-user-group, cisco-asa-list-local-user, cisco-asa-list-user-object. | Optional | 
| user_kind | The type of the user, can be one of LocalUserObjGroup, UserGroupObj, UserObj. Possible values are: LocalUserObjGroup, UserGroupObj, UserObj. | Optional | 
| source_security | Source security group in the ace. Can be one of SecurityName, SecurityTag and SecurityObjGroup values can be added. Can be received with the existing command cisco-asa-list-security-object-group. | Optional | 
| source_security_kind | The source security type, can be one of SecurityName, SecurityTag, SecurityObjGroup. Possible values are: SecurityName, SecurityTag, SecurityObjGroup. | Optional | 
| destination_security | Destination security group in the ace. Can be one of SecurityName, SecurityTag and SecurityObjGroup values can be added. Can be received with the existing command cisco-asa-list-security-object-group. | Optional | 
| destination_security_kind | The destination security type, can be one of SecurityName, SecurityTag, SecurityObjGroup. Possible values are: SecurityName, SecurityTag, SecurityObjGroup. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 
| CiscoASA.Rules.SourceKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.DestKind | String | One of AnyIPAddress, IPv4Address, IPv4FQDN, IPv4Network, IPv4Range, IPv6Address, IPv6FQDN, IPv6Network, IPv6Range, SecurityName, SecurityTag, interfaceIP, objectRef\#NetworkObj, objectRef\#NetworkObjGroup. | 
| CiscoASA.Rules.SourceSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.SourceSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.SourceSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.kind | String | The type of the security group; SecurityName, SecurityTag, objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.DestinationSecurity.value | String | The value of the SecurityName or SecurityTag | 
| CiscoASA.Rules.DestinationSecurity.objectId | String | The object ID of objectRef\#SecurityObjGroup. | 
| CiscoASA.Rules.User.kind | String | One of AnyUser, NoneUser, objectRef\#LocalUserObjGroup, objectRef\#UserGroupObj, objectRef\#UserObj | 
| CiscoASA.Rules.User.value | String | The user value. | 
| CiscoASA.Rules.User.objectId | String | The object ID of the user. | 
| CiscoASA.Rules.TimeRange.kind | String | The object reference type or the actual TimeRange value. | 
| CiscoASA.Rules.TimeRange.value | String | The value of the time range. | 
| CiscoASA.Rules.TimeRange.objectId | String | The object ID of the time range. | 

#### Command example
```!cisco-asa-edit-rule rule_id=3371063501 interface_type=Global active=True```
#### Context Example
```json
{
    "CiscoASA": {
        "Rules": {
            "Dest": "5.5.5.5",
            "DestKind": "IPv4Address",
            "DestService": "tcp/citrix-ica",
            "DestinationSecurity": {
                "kind": "SecurityTag",
                "value": "1"
            },
            "ID": "3371063501",
            "Interface": "",
            "InterfaceType": "Global",
            "IsActive": true,
            "Permit": false,
            "Position": 30,
            "Remarks": [],
            "Source": "0.0.0.0/24",
            "SourceKind": "IPv4Network",
            "SourceSecurity": {
                "kind": "SecurityTag",
                "value": "2"
            },
            "SourceService": "tcp/cifs",
            "User": {
                "kind": "objectRef#UserObj",
                "objectId": "api"
            }
        }
    }
}
```

#### Human Readable Output

>### Edited rule 3371063501
>|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|DestService|
>|---|---|---|---|---|---|---|---|---|---|
>| 3371063501 | 0.0.0.0/24 | 5.5.5.5 | false |  | Global | true | 30 | tcp/cifs | tcp/citrix-ica |


### cisco-asa-list-network-objects

***
Gets a list all configured network objects.

#### Base Command

`cisco-asa-list-network-objects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_name | A comma-separated list of network object names for which to get the network. | Optional | 
| object_id | A comma-separated list of object IDs for which to get the network object. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.NetworkObject.ID | String | The ID of the network object. | 
| CiscoASA.NetworkObject.Host | String | The host information of the network object. | 
| CiscoASA.NetworkObject.Description | String | A description of the network object. | 
| CiscoASA.NetworkObject.Name | String | The name of the network object. | 

#### Command example
```!cisco-asa-list-network-objects object_name=Test_Lior```
#### Context Example
```json
{
    "CiscoASA": {
        "NetworkObject": {
            "Host": {
                "kind": "IPv4Address",
                "value": "0.0.0.0"
            },
            "ID": "Test_Lior",
            "Name": "Test_Lior"
        }
    }
}
```

#### Human Readable Output

>### Network Objects
>|ID|Name|Host|Description|
>|---|---|---|---|
>| Test_Lior | Test_Lior | kind: IPv4Address<br/>value: 0.0.0.0 |  |


### cisco-asa-create-network-object

***
Creates a network object.

#### Base Command

`cisco-asa-create-network-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of network object to create. Possible values are: IPv4, IP-Network. | Required | 
| object_name | The name of the object to create. | Required | 
| object_value | The value of the network object to create. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.NetworkObject.ID | String | The ID of the network object. | 
| CiscoASA.NetworkObject.Host | String | The host information of the network object. | 
| CiscoASA.NetworkObject.Description | String | A description of the network object, if exists. | 
| CiscoASA.NetworkObject.Name | String | The name of the network object. | 

#### Command example
```!cisco-asa-create-network-object object_name=HelloThereLiorSB object_type=IPv4 object_value=9.5.3.9```
#### Context Example
```json
{
    "CiscoASA": {
        "NetworkObject": {
            "Host": {
                "kind": "IPv4Address",
                "value": "9.5.3.9"
            },
            "ID": "HelloThereLiorSB",
            "Name": "HelloThereLiorSB"
        }
    }
}
```

#### Human Readable Output

>### Network Objects
>|ID|Name|Host|Description|
>|---|---|---|---|
>| HelloThereLiorSB | HelloThereLiorSB | kind: IPv4Address<br/>value: 9.5.3.9 |  |


### cisco-asa-list-interfaces

***
Gets a list of all interfaces.

#### Base Command

`cisco-asa-list-interfaces`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Interface.ID | String | The interface ID. | 
| CiscoASA.Interface.Name | String | The interface name. | 
| CiscoASA.Interface.Type | String | The type of interface. | 

#### Command example
```!cisco-asa-list-interfaces```
#### Context Example
```json
{
    "CiscoASA": {
        "Interface": [
            {
                "ID": "-1",
                "Name": null,
                "Type": "Global"
            },
            {
                "ID": "GigabitEthernet0_API_SLASH_0",
                "Name": "outside",
                "Type": "In"
            },
            {
                "ID": "Management0_API_SLASH_0",
                "Name": "inside",
                "Type": "Out"
            }
        ]
    }
}
```

#### Human Readable Output

>### Interfaces
>|Type|ID|Name|
>|---|---|---|
>| Global | -1 |  |
>| In | GigabitEthernet0_API_SLASH_0 | outside |
>| Out | Management0_API_SLASH_0 | inside |

