Read information and to send commands to the Check Point Firewall server.

Please note that for all:
- add
- update
- delete 
commands you are requires session id, that can be retrieved with checkpoint-login-and-get-session-id command.

For list and get commands, providing session id is optional.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### checkpoint-host-list
***
Show all host objects


#### Base Command

`checkpoint-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 


#### Command Example
```!checkpoint-host-list session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "host": [
            {
                "name": "host_test",
                "type": "host",
                "uid": "d3fb20c2-826c-4b5b-84f0-6209750bda01"
            },
            {
                "name": "test_for_ben",
                "type": "host",
                "uid": "f3818a47-8371-4321-a1d1-7f9d6868efbb"
            },
            {
                "name": "test_host_1",
                "type": "host",
                "uid": "275e0492-1c99-4b74-b4fb-d14860466717"
            },
            {
                "name": "test_host_2",
                "type": "host",
                "uid": "e58c7352-babd-4be7-ac5c-5ced2adf0cf2"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing hosts:
>|name|uid|type|
>|---|---|---|
>| host_test | d3fb20c2-826c-4b5b-84f0-6209750bda01 | host |
>| test_for_ben | f3818a47-8371-4321-a1d1-7f9d6868efbb | host |
>| test_host_1 | 275e0492-1c99-4b74-b4fb-d14860466717 | host |
>| test_host_2 | e58c7352-babd-4be7-ac5c-5ced2adf0cf2 | host |


### checkpoint-host-get
***
get all data of a given host


#### Base Command

`checkpoint-host-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object unique identifier (uid) or name | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | Unknown | host name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | Unknown | object type | 
| CheckPoint.host.domain-name | String | domain name | 
| CheckPoint.host.domain-uid | String | domain uid | 
| CheckPoint.host.ipv4-address | String | IP address | 
| CheckPoint.host.ipv6-address | String | IP address | 
| CheckPoint.host.read-only | Boolean | indicates if the object is read only | 
| CheckPoint.host.creator | String | indicates the creator of the object | 
| CheckPoint.host.last-modifier | Unknown | indicates the last user modified the object | 
| CheckPoint.host.groups-name | String | Group object name linked to current host object. | 
| CheckPoint.host.groups-uid | Unknown | Group object uid linked to current host object. | 


#### Command Example
```!checkpoint-host-get identifier=host_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "host": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4_address": "8.8.8.8",
            "ipv6_address": "8.8.8.8",
            "last_modifier": "adminsh",
            "name": "host_test",
            "read_only": false,
            "type": "host",
            "uid": "d3fb20c2-826c-4b5b-84f0-6209750bda01"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting host:
>|creator|domain-name|domain-uid|ipv4_address|ipv6_address|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | 8.8.8.8 | 8.8.8.8 | adminsh | host_test | false | host | d3fb20c2-826c-4b5b-84f0-6209750bda01 |


### checkpoint-host-add
***
Add new host


#### Base Command

`checkpoint-host-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | name of the new host | Required | 
| ip_address | ip address | Required | 
| groups | Collection of group identifiers. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 
| CheckPoint.host.domain-name | String | domain name | 
| CheckPoint.host.domain-uid | String | domain uid | 
| CheckPoint.host.domain-type | String | domain type | 
| CheckPoint.host.creator | String | indicates the creator of the object | 
| CheckPoint.host.last-modifier | String | indicates the last user modifies the object | 
| CheckPoint.host.ipv4-address | String | ip address | 
| CheckPoint.host.ipv6-address | String | IP address | 
| CheckPoint.host.read-only | String | indicates if the object is read only | 
| CheckPoint.host.groups | String | Collection of group identifiers | 


#### Command Example
```!checkpoint-host-add name=test_host ip_address=8.8.8.8 session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "host": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": "8.8.8.8",
            "ipv6-address": "8.8.8.8",
            "last_modifier": "adminsh",
            "name": "test_host",
            "read-only": true,
            "type": "host",
            "uid": "1d6714dd-6316-4e83-b9f7-b4c2a218ff7f"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding host:
>|creator|domain-name|domain-uid|ipv4-address|ipv6-address|last_modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | 8.8.8.8 | 8.8.8.8 | adminsh | test_host | true | host | 1d6714dd-6316-4e83-b9f7-b4c2a218ff7f |


### checkpoint-host-update
***
update host changes


#### Base Command

`checkpoint-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | Object unique identifier or name | Required | 
| ip | IPv4 or IPv6 address. | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. You won't be able to publish such a changes.<br/>If ignore-warnings flag was omitted - warnings will also be ignored. | Optional | 
| groups | Collection of group identifiers. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 
| CheckPoint.host.domain-name | String | domain name | 
| CheckPoint.host.domain-uid | String | domain uid | 
| CheckPoint.host.domain-type | String | domain type | 
| CheckPoint.host.creator | String | indicates the creator of the object | 
| CheckPoint.host.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.host.ipv4-address | String | IP address | 
| CheckPoint.host.read-only | Boolean | IP address | 
| CheckPoint.host.group-name | String | Group object name linked to the host. | 
| CheckPoint.host.group-uid | String | Group object name linked to the host | 


#### Command Example
```!checkpoint-host-update identifier=host_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "host": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": "8.8.8.8",
            "ipv6-address": "8.8.8.8",
            "name": "host_test",
            "total-number": null,
            "type": "host",
            "uid": "d3fb20c2-826c-4b5b-84f0-6209750bda01"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating host:
>|domain-name|domain-uid|ipv4-address|ipv6-address|name|type|uid|
>|---|---|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | 8.8.8.8 | 8.8.8.8 | host_test | host | d3fb20c2-826c-4b5b-84f0-6209750bda01 |


### checkpoint-host-delete
***
delete host


#### Base Command

`checkpoint-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.message | String | operation status | 


#### Command Example
```!checkpoint-host-delete identifier=host_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "host": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting host:
>|message|
>|---|
>| OK |


### checkpoint-group-list
***
Show a list of all groups


#### Base Command

`checkpoint-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object's name | 
| CheckPoint.group.uid | String | object's uid | 
| CheckPoint.group.type | String | Type of the object | 


#### Command Example
```!checkpoint-group-list session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "group": [
            {
                "name": "group_test",
                "type": "group",
                "uid": "35a46b01-47f5-496f-9329-d55c7d2ab083"
            },
            {
                "name": "test1",
                "type": "group",
                "uid": "67e93a2b-c7d4-44a2-9313-6e48f664c19a"
            },
            {
                "name": "test_group_2",
                "type": "group",
                "uid": "77d16f8b-8767-445e-b880-ad31e22d7608"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing groups:
>|name|uid|type|
>|---|---|---|
>| group_test | 35a46b01-47f5-496f-9329-d55c7d2ab083 | group |
>| test1 | 67e93a2b-c7d4-44a2-9313-6e48f664c19a | group |
>| test_group_2 | 77d16f8b-8767-445e-b880-ad31e22d7608 | group |


### checkpoint-group-get
***
Get all data of a given group


#### Base Command

`checkpoint-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object uid or name | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object name | 
| CheckPoint.group.uid | String | object uid | 
| CheckPoint.group.type | String | object type | 
| CheckPoint.group.domain-name | String | domain name | 
| CheckPoint.group.domain-uid | String | domain uid | 
| CheckPoint.group.domain-type | String | domain type | 
| CheckPoint.group.creator | String | indicates the creator of the object | 
| CheckPoint.group.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.group.read-only | Boolean | indicates if the object is read only | 


#### Command Example
```!checkpoint-group-get identifier=test_group session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "group": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4_address": null,
            "ipv6_address": null,
            "last_modifier": "adminsh",
            "members": [
                {
                    "member-domain-name": "SMC User",
                    "member-domain-type": null,
                    "member-domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                    "member-name": "test_host",
                    "member-type": "host",
                    "member-uid": "ff0d466b-9d7f-46e1-8a31-a54e00820c1b"
                },
                {
                    "member-domain-name": "SMC User",
                    "member-domain-type": null,
                    "member-domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                    "member-name": "address_range_test",
                    "member-type": "address-range",
                    "member-uid": "c62e1e64-3119-4b74-989a-6ef6e67d6070"
                }
            ],
            "name": "test_group",
            "read_only": false,
            "type": "group",
            "uid": "e50aecdd-94a6-43bd-bc79-3ea575b7f36b"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting group:
>|creator|domain-name|domain-uid|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | test_group | false | group | e50aecdd-94a6-43bd-bc79-3ea575b7f36b |
>### CheckPoint member data:
>|member-name|member-uid|member-type|member-domain-name|member-domain-uid|
>|---|---|---|---|---|
>| test_host | ff0d466b-9d7f-46e1-8a31-a54e00820c1b | host | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |
>| address_range_test | c62e1e64-3119-4b74-989a-6ef6e67d6070 | address-range | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |


### checkpoint-group-add
***
add a group


#### Base Command

`checkpoint-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Object name. Must be unique in the domain. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object's name | 
| CheckPoint.group.uid | String | object uid | 
| CheckPoint.group.type | Unknown | object type | 
| CheckPoint.group.domain-name | String | domain name | 
| CheckPoint.group.domain-uid | String | domain uid | 
| CheckPoint.group.domain-type | String | domain type | 
| CheckPoint.group.creator | String | Indicates the object creator | 
| CheckPoint.group.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.group.read-only | Boolean | Indicates whether the object is read\-only | 
| CheckPoint.group.groups-name | Unknown | groups name | 


#### Command Example
```!checkpoint-group-add name=test_group_2 session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Human Readable Output



### checkpoint-group-update
***
update group object


#### Base Command

`checkpoint-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| new_name | New name of the group object | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object name | 
| CheckPoint.group.uid | String | object uid | 
| CheckPoint.group.type | String | object type | 
| CheckPoint.group.domain-name | String | domain name | 
| CheckPoint.group.domain-uid | String | domain uid | 
| CheckPoint.group.domain-type | String | domain type | 
| CheckPoint.group.creator | String | Indicates the creator of the object | 
| CheckPoint.group.last-modifier | String | Indicates the lasr user modified the object | 
| CheckPoint.group.read-only | Boolean | Indicates if the object is read only | 


```!checkpoint-group-update identifier=test_group session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "group": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "test_group",
            "total-number": null,
            "type": "group",
            "uid": "e50aecdd-94a6-43bd-bc79-3ea575b7f36b"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating group:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | test_group | group | e50aecdd-94a6-43bd-bc79-3ea575b7f36b |



### checkpoint-group-delete
***
delete a group object


#### Base Command

`checkpoint-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.message | String | Operation massege | 


#### Command Example
```!checkpoint-group-delete identifier=test_group session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "group": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting group:
>|message|
>|---|
>| OK |


### checkpoint-address-range-list
***
List all address range objects


#### Base Command

`checkpoint-address-range-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | Object's name | 
| CheckPoint.address-range.uid | String | Object's uid | 
| CheckPoint.address-range.type | String | Type of the object. | 


#### Command Example
```!checkpoint-address-range-list session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "address-range": [
            {
                "name": "address_range_test",
                "type": "address-range",
                "uid": "0145a9c1-9127-4e53-8bcc-fc9b6e492f5f"
            },
            {
                "name": "address_range_test_2",
                "type": "address-range",
                "uid": "1f9b89c7-a4e5-4f1e-b59a-e9c3029e7572"
            },
            {
                "name": "All_Internet",
                "type": "address-range",
                "uid": "f90e0a2b-f166-427a-b47f-a107b6fe43b9"
            },
            {
                "name": "LocalMachine_Loopback",
                "type": "address-range",
                "uid": "5d3b2752-4072-41e1-9aa0-488813b02a40"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing address-ranges:
>|name|uid|type|
>|---|---|---|
>| address_range_test | 0145a9c1-9127-4e53-8bcc-fc9b6e492f5f | address-range |
>| address_range_test_2 | 1f9b89c7-a4e5-4f1e-b59a-e9c3029e7572 | address-range |
>| All_Internet | f90e0a2b-f166-427a-b47f-a107b6fe43b9 | address-range |
>| LocalMachine_Loopback | 5d3b2752-4072-41e1-9aa0-488813b02a40 | address-range |


### checkpoint-address-range-add
***
Add address range object


#### Base Command

`checkpoint-address-range-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | object name | Required | 
| ip_address_first | First IP address in the range. | Required | 
| ip_address_last | Last IP address in the range. | Required | 
| set_if_exists | If another object with the same identifier already exists, it will be updated. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object name | 
| CheckPoint.address-range.uid | String | object uid | 
| CheckPoint.address-range.type | String | object type | 
| CheckPoint.address-range.domain-name | String | domain name | 
| CheckPoint.address-range.domain-uid | String | domain uid | 
| CheckPoint.address-range.domain-type | String | domain type | 
| CheckPoint.address-range.ipv4-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv4-address-last | String | Last IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-last | String | Last IPv6 address in the range | 
| CheckPoint.address-range.read-only | Boolean | Indicates whether the object is read\-only. | 
| CheckPoint.address-range.creator | String | Indicates the creator of the object | 
| CheckPoint.address-range.last-modifier | String | Indicates the last user modified the object | 


#### Command Example
```!checkpoint-address-range-add name=address_range_test_2 ip_address_first=8.8.8.8 ip_address_last=9.9.9.9 session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Human Readable Output



### checkpoint-address-range-update
***
Update an address range object


#### Base Command

`checkpoint-address-range-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| ip_address_first | First IP address in the range. IPv4 or IPv6 address. | Optional | 
| ip_address_last | Last IP address in the range. IPv4 or IPv6 address. | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. | Optional | 
| groups | Collection of group identifiers. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object name | 
| CheckPoint.address-range.uid | String | object uid | 
| CheckPoint.address-range.type | String | object type | 
| CheckPoint.address-range.domain-name | String | domain name | 
| CheckPoint.address-range.domain-uid | String | domain uid | 
| CheckPoint.address-range.domain-type | String | domain type | 
| CheckPoint.address-range.ipv4-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv4-address-last | String | Last IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-last | String | Last IPv6 address in the range | 
| CheckPoint.address-range.read-only | Boolean | Indicates whether the object is read\-only. | 
| CheckPoint.address-range.groups | String | List of all groups the address range is linked to | 


#### Command Example
```!checkpoint-address-range-update identifier=address_range_test layer=Network session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "address-range": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "address_range_test",
            "total-number": null,
            "type": "address-range",
            "uid": "0145a9c1-9127-4e53-8bcc-fc9b6e492f5f"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating address-range:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | address_range_test | address-range | 0145a9c1-9127-4e53-8bcc-fc9b6e492f5f |


### checkpoint-address-range-delete
***
Delete a given address range


#### Base Command

`checkpoint-address-range-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.message | String | Operation status | 


#### Command Example
```!checkpoint-address-range-delete identifier=address_range_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "address-range": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting address-range:
>|message|
>|---|
>| OK |


### checkpoint-threat-indicator-list
***
List all threat indicators


#### Base Command

`checkpoint-threat-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Skip that many results before beginning to return them. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 


#### Command Example
```!checkpoint-threat-indicator-list limit=5 session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "threat-indicator": [
            {
                "name": "My_Indicator",
                "type": "threat-indicator",
                "uid": "a40ec97c-e286-474b-bff7-b922e3b3294d"
            },
            {
                "name": "test_indicator",
                "type": "threat-indicator",
                "uid": "3e6a22c0-0416-4a2d-b7c0-f81df12916e1"
            },
            {
                "name": "threat_test",
                "type": "threat-indicator",
                "uid": "3d878a07-35c5-4499-91a7-e909b479e512"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing threat-indicators:
>|name|uid|type|
>|---|---|---|
>| My_Indicator | a40ec97c-e286-474b-bff7-b922e3b3294d | threat-indicator |
>| test_indicator | 3e6a22c0-0416-4a2d-b7c0-f81df12916e1 | threat-indicator |
>| threat_test | 3d878a07-35c5-4499-91a7-e909b479e512 | threat-indicator |


### checkpoint-threat-indicator-get
***
Get data for a given list indicator


#### Base Command

`checkpoint-threat-indicator-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object uid or name | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 
| CheckPoint.threat-indicator.domain-name | String | Domain name | 
| CheckPoint.threat-indicator.domain-uid | String | object uid | 
| CheckPoint.threat-indicator.domain-type | Unknown | domain type | 
| CheckPoint.threat-indicator.creator | String | creator | 
| CheckPoint.threat-indicator.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.threat-indicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
```!checkpoint-threat-indicator-get identifier=threat_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "threat-indicator": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4_address": null,
            "ipv6_address": null,
            "last_modifier": "adminsh",
            "name": "threat_test",
            "read_only": false,
            "type": "threat-indicator",
            "uid": "3d878a07-35c5-4499-91a7-e909b479e512"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting threat-indicator:
>|creator|domain-name|domain-uid|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | threat_test | false | threat-indicator | 3d878a07-35c5-4499-91a7-e909b479e512 |


### checkpoint-threat-indicator-add
***
Add a threat indicator


#### Base Command

`checkpoint-threat-indicator-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | threat indicator name | Required | 
| observables | The indicator's observable or the contents of a file containing the indicator's observables. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.task-id | String | Asynchronous task unique identifier. | 


#### Command Example
```!checkpoint-threat-indicator-add name=threat_test2 observables=[] session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Human Readable Output



### checkpoint-threat-indicator-update
***
Update a given indicator


#### Base Command

`checkpoint-threat-indicator-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| action | the action to set. | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 
| CheckPoint.threat-indicator.action | String | The indicator's action. | 
| CheckPoint.threat-indicator.domain-name | String | domain name | 
| CheckPoint.threat-indicator.domain-uid | String | domain uid | 
| CheckPoint.threat-indicator.domain-type | String | domain type | 
| CheckPoint.threat-indicator.creator | String | Indicates the creator of the object | 
| CheckPoint.threat-indicator.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.threat-indicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
```!checkpoint-threat-indicator-update identifier=threat_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "threat-indicator": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "threat_test",
            "total-number": null,
            "type": "threat-indicator",
            "uid": "3d878a07-35c5-4499-91a7-e909b479e512"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating threat-indicator:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | threat_test | threat-indicator | 3d878a07-35c5-4499-91a7-e909b479e512 |


### checkpoint-address-range-get
***
Get all date of a given address range object


#### Base Command

`checkpoint-address-range-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object name | 
| CheckPoint.address-range.uid | String | object uid | 
| CheckPoint.address-range.type | String | object type | 
| CheckPoint.address-range.domain-name | String | domain name | 
| CheckPoint.address-range.domain-uid | String | domain uid | 
| CheckPoint.address-range.domain-type | String | domain type | 
| CheckPoint.address-range.groups-name | String | Group object name linked to current host object | 
| CheckPoint.address-range.groups-uid | String | Group object uid linked to current host object | 


#### Command Example
```!checkpoint-address-range-get identifier=address_range_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "address-range": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4_address": null,
            "ipv6_address": null,
            "last_modifier": "adminsh",
            "name": "address_range_test",
            "read_only": false,
            "type": "address-range",
            "uid": "0145a9c1-9127-4e53-8bcc-fc9b6e492f5f"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting address-range:
>|creator|domain-name|domain-uid|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | address_range_test | false | address-range | 0145a9c1-9127-4e53-8bcc-fc9b6e492f5f |


### checkpoint-threat-indicator-delete
***
delete threat indicator


#### Base Command

`checkpoint-threat-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.message | String | Operation status | 


#### Command Example
```!checkpoint-threat-indicator-delete identifier=threat_test session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "threat-indicator": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting threat-indicator:
>|message|
>|---|
>| OK |


### checkpoint-access-rule-list
***
Shows the entire Access Rules layer. This layer is divided into sections. An Access Rule may be within a section, or independent of a section.


#### Base Command

`checkpoint-access-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 


#### Command Example
```!checkpoint-access-rule-list identifier=Network session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "access-rule": [
            {
                "name": "Any",
                "uid": "97aeb369-9aea-11d5-bd16-0090272ccb30"
            },
            {
                "name": "Drop",
                "uid": "6c488338-8eec-4103-ad21-cd461ac2c473"
            },
            {
                "name": "None",
                "uid": "29e53e3d-23bf-48fe-b6b1-d59bd88036f9"
            },
            {
                "name": "Policy Targets",
                "uid": "6c488338-8eec-4103-ad21-cd461ac2c476"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing access-rules:
>|name|uid|
>|---|---|
>| Any | 97aeb369-9aea-11d5-bd16-0090272ccb30 |
>| Drop | 6c488338-8eec-4103-ad21-cd461ac2c473 |
>| None | 29e53e3d-23bf-48fe-b6b1-d59bd88036f9 |
>| Policy Targets | 6c488338-8eec-4103-ad21-cd461ac2c476 |


### checkpoint-access-rule-add
***
Create new access rule


#### Base Command

`checkpoint-access-rule-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| layer | Layer that the rule belongs to identified by the name or UID. | Required | 
| position | Position in the rulebase. | Required | 
| name | Rule name. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 
| CheckPoint.access-rule.type | String | object type | 
| CheckPoint.access-rule.domain-name | String | domain name | 
| CheckPoint.access-rule.domain-uid | String | domain uid | 
| CheckPoint.access-rule.domain-type | String | domain type | 
| CheckPoint.access-rule.enabled | Boolean | Enable/Disable the rule. | 
| CheckPoint.access-rule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| CheckPoint.access-rule.creator | String | Indicated the object creator | 
| CheckPoint.access-rule.last-modifier | String | Indicates the last user modofied the object | 


#### Command Example
```!checkpoint-access-rule-add name=test_access_rule_5 layer=Network position=top session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "access-rule": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "enabled": true,
            "last_modifier": "adminsh",
            "layer": "c0264a80-1832-4fce-8a90-d0849dc4ba33",
            "name": "test_access_rule_5",
            "type": "access-rule",
            "uid": "1c30774c-1c2a-4539-93ff-66fbc5c52887"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding access-rule:
>|creator|domain-name|domain-uid|enabled|last_modifier|layer|name|type|uid|
>|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | true | adminsh | c0264a80-1832-4fce-8a90-d0849dc4ba33 | test_access_rule_5 | access-rule | 1c30774c-1c2a-4539-93ff-66fbc5c52887 |


### checkpoint-access-rule-update
***
Edit existing access rule using object name or uid.


#### Base Command

`checkpoint-access-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid, OR rule number | Required | 
| layer | Layer that the rule belongs to identified by the name or UID. | Required | 
| action | action to be taken on the rule | Optional | 
| enabled | Enable/Disable the rule. | Optional | 
| new_name | New name of the object. | Optional | 
| new_position | New position in the rulebase. Value can be int to set specific position, ot str- 'top' or 'bottom' | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 
| CheckPoint.access-rule.type | String | object type | 
| CheckPoint.access-rule.action-name | String | action name | 
| CheckPoint.access-rule.action-uid | String | action uid | 
| CheckPoint.access-rule.action-type | Unknown | action type | 
| CheckPoint.access-rule.action-domain-name | String | action domain name | 
| CheckPoint.access-rule.content-direction | String | On which direction the file types processing is applied. | 
| CheckPoint.access-rule.domain-name | String | domain name | 
| CheckPoint.access-rule.domain-uid | String | domain uid | 
| CheckPoint.access-rule.domain-type | String | domain type | 
| CheckPoint.access-rule.enabled | Boolean | Enable/Disable the rule. | 
| CheckPoint.access-rule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| CheckPoint.access-rule.creator | String | Indicates the creator of the object | 
| CheckPoint.access-rule.last-modifier | String | Indicates the last user modified the object | 


#### Command Example
```!checkpoint-access-rule-update identifier=test_access_rule layer=Network session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Human Readable Output



### checkpoint-access-rule-delete
***
Delete access rule


#### Base Command

`checkpoint-access-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid, name or rule-number. | Required | 
| layer | Layer that the rule belongs to identified by the name or UID. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.message | String | Operation status | 


#### Command Example
```!checkpoint-access-rule-delete identifier=test_access_rule session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Human Readable Output



### checkpoint-application-site-list
***
Retrieve all objects.


#### Base Command

`checkpoint-application-site-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | objects name | 
| CheckPoint.application-site.uid | String | objects uid | 
| CheckPoint.application-site.type | String | objects type | 


#### Command Example
```!checkpoint-application-site-list limit=5 session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "application-site": [
            {
                "name": "#hashtags",
                "type": "application-site",
                "uid": "00fa9e3c-36ef-0f65-e053-08241dc22da2"
            },
            {
                "name": "050 Plus",
                "type": "application-site",
                "uid": "00fa9e44-4035-0f65-e053-08241dc22da2"
            },
            {
                "name": "1000keyboards",
                "type": "application-site",
                "uid": "00fa9e3d-a077-0f65-e053-08241dc22da2"
            },
            {
                "name": "1000memories",
                "type": "application-site",
                "uid": "00fa9e43-56d7-0f65-e053-08241dc22da2"
            },
            {
                "name": "1001",
                "type": "application-site",
                "uid": "00fa9e3d-1ab6-0f65-e053-08241dc22da2"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing application-sites:
>|name|uid|type|
>|---|---|---|
>| #hashtags | 00fa9e3c-36ef-0f65-e053-08241dc22da2 | application-site |
>| 050 Plus | 00fa9e44-4035-0f65-e053-08241dc22da2 | application-site |
>| 1000keyboards | 00fa9e3d-a077-0f65-e053-08241dc22da2 | application-site |
>| 1000memories | 00fa9e43-56d7-0f65-e053-08241dc22da2 | application-site |
>| 1001 | 00fa9e3d-1ab6-0f65-e053-08241dc22da2 | application-site |


### checkpoint-application-site-add
***
Add application site


#### Base Command

`checkpoint-application-site-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Object name. Must be unique in the domain | Required | 
| primary_category | Each application is assigned to one primary category based on its most defining aspect | Required | 
| identifier | can be:<br/>  url-list(str): URLs that determine this particular application.<br/>  application-signature(str): Application signature generated by Signature Tool. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | object name | 
| CheckPoint.application-site.uid | String | object uid | 
| CheckPoint.application-site.type | String | object type | 
| CheckPoint.application-site.application-id | Number | application ID | 
| CheckPoint.application-site.description | String | A description for the application. | 
| CheckPoint.application-site.domain-name | String | domain name | 
| CheckPoint.application-site.domain-uid | String | domain uid | 
| CheckPoint.application-site.domain-type | String | domain name | 
| CheckPoint.application-site.url-list | String | URLs that determine this particular application. | 
| CheckPoint.application-site.creator | String | Indicates the creator of the object | 
| CheckPoint.application-site.last-modifier | String | Indicates the last user modified this object | 


#### Command Example
```!checkpoint-application-site-add name='test_application_site_2' primary_category='Test Category' url-list='www.stackoverflow.com'```


#### Human Readable Output



### checkpoint-application-site-update
***
Edit existing application using object name or uid. 
It's impossible to set  'application-signature' when the application was initialized with 'url-list' and vice-verse.


#### Base Command

`checkpoint-application-site-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| description | A description for the application. | Optional | 
| primary_category | Each application is assigned to one primary category based on its most defining aspect. | Optional | 
| application_signature | Application signature generated by Signature Tool. | Optional | 
| new_name | New name of the object. | Optional | 
| urls_defined_as_regular_expression | States whether the URL is defined as a Regular Expression or not. | Optional | 
| url_list | URLs that determine this particular application. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | object name | 
| CheckPoint.application-site.uid | String | object uid | 
| CheckPoint.application-site.type | String | object ty\[e | 
| CheckPoint.application-site.application-id | Number | application ID | 
| CheckPoint.application-site.description | String | A description for the application. | 
| CheckPoint.application-site.domain-name | String | domain name | 
| CheckPoint.application-site.domain-uid | String | domain uid | 
| CheckPoint.application-site.domain-type | String | domain type | 
| CheckPoint.application-site.url-list | String | URLs that determine this particular application. | 


#### Command Example
```!checkpoint-application-site-update identifier=test_application_site session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "application-site": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "test_application_site",
            "total-number": null,
            "type": "application-site",
            "uid": "845944a8-bc2d-4a61-9326-9da76e0de36e"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating application-site:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | test_application_site | application-site | 845944a8-bc2d-4a61-9326-9da76e0de36e |


### checkpoint-application-site-delete
***
Delete existing application site object using object name or uid.


#### Base Command

`checkpoint-application-site-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.message | String | Operation status. | 


#### Command Example
```!checkpoint-application-site-delete identifier=test_application_site session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "application-site": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting application-site:
>|message|
>|---|
>| OK |


### checkpoint-publish
***
publish changes


#### Base Command

`checkpoint-publish`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!checkpoint-publish session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "publish": {
            "task-id": "01234567-89ab-cdef-95aa-d18176d0302d"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for publish:
>|task-id|
>|---|
>| 01234567-89ab-cdef-95aa-d18176d0302d |


### checkpoint-install-policy
***
Intsalling policy


#### Base Command

`checkpoint-install-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_package | The name of the Policy Package to be installed. | Required | 
| targets | On what targets to execute this command. Targets may be identified by their name, or object unique identifier. | Required | 
| access | Set to be true in order to install the Access Control policy. | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.instal-policy.task-id | String | Operation task ID. | 


#### Command Example
```!checkpoint-install-policy policy_package=standard targets=test-gw session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "install-policy": {
            "task-id": "a826e748-74b4-41e0-aa54-cd182ed89818"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for install-policy:
>|task-id|
>|---|
>| a826e748-74b4-41e0-aa54-cd182ed89818 |


### checkpoint-verify-policy
***
Verifies the policy of the selected package.


#### Base Command

`checkpoint-verify-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_package | The name of the Policy Package to be installed. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.instal-policy.task-id | String | Operation task ID. | 


#### Command Example
```!checkpoint-policy-verify policy_package=standard```

#### Human Readable Output



### checkpoint-show-task
***
Show task progress and details.


#### Base Command

`checkpoint-show-task`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Unique identifier of one or more tasks. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.show-task.task-id | String | Task ID | 
| CheckPoint.show-task.task-name | String | Task name | 
| CheckPoint.show-task.status | String | Task status | 
| CheckPoint.show-task.progress-percentage | Unknown | Task prograss in percentage | 
| CheckPoint.show-task.suppressed | Boolean | Indicates if the task is suppressed | 


#### Command Example
```!checkpoint-show-task task_id=01234567-89ab-cdef-802d-cc117e483dba session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{}
```

#### Human Readable Output

>No data to show.

### checkpoint-login-and-get-session-id
***
Login to CheckPoint and get the session id


#### Base Command

`checkpoint-login-and-get-session-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_timeout | Session expiration timeout in seconds. Default 600 seconds. Session timeout range is between 600 to 3600 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.session-id | String | Session ID | 


#### Command Example
```!checkpoint-login-and-get-session-id ```

#### Human Readable Output



### checkpoint-logout
***
Logout from a given session


#### Base Command

`checkpoint-logout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | Session ID to logout from | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!checkpoint-logout session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Human Readable Output



### checkpoint-packages-list
***
List all packages.


#### Base Command

`checkpoint-packages-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results | Optional | 
| offset | Number of the results to initially skip | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.packages.name | String | Name of the package | 
| CheckPoint.packages.uid | String | UID of the package | 
| CheckPoint.packages.type | String | Type of the package | 
| CheckPoint.packages.domain-name | String | Domain name | 
| CheckPoint.packages.domain-uid | String | Domain uid | 
| CheckPoint.packages.domain-type | String | Domain type | 


#### Command Example
```!checkpoint-packages-list session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "list-packages": {
            "domain": {
                "domain-type": "domain",
                "name": "SMC User",
                "uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"
            },
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "name": "Standard",
            "type": "package",
            "uid": "ca4e32a8-bee0-423c-84f0-19bab6751d5e"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for: list-packages:
>|name|uid|type|domain-name|domain-uid|
>|---|---|---|---|---|
>| Standard | ca4e32a8-bee0-423c-84f0-19bab6751d5e | package | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |


### checkpoint-gateways-list
***
Retrieve all gateways and servers


#### Base Command

`checkpoint-gateways-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results | Optional | 
| offset | Number of the results to initially skip | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.gateways.name | String | Gateway name | 
| CheckPoint.gateways.uid | String | Gateway uid | 
| CheckPoint.gateways.type | String | Gateway type | 
| CheckPoint.gateways.version | String | Gateway vesion | 
| CheckPoint.gateways.network-security-blades | String | Gateway network security blades | 
| CheckPoint.gateways.management-blades | String | Gateway management blades | 
| CheckPoint.gateways.domain-name | String | Domain name | 
| CheckPoint.gateways.domain-uid | String | Domain UID | 
| CheckPoint.gateways.domain-type | String | Doamin type | 


#### Command Example
```!checkpoint-gateways-list session_id=RwBtCVHua8LcL__ROV1z6opDbdVLf6aqozL5Sk5CZOM```

#### Context Example
```
{
    "CheckPoint": {
        "list-gateways": [
            {
                "domain": {
                    "domain-type": "domain",
                    "name": "SMC User",
                    "uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"
                },
                "domain-name": "SMC User",
                "domain-type": null,
                "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                "management-blades": {
                    "logging-and-status": true,
                    "network-policy-management": true
                },
                "name": "gw-88a290",
                "network-security-blades": {},
                "type": "CpmiHostCkp",
                "uid": "98bee60f-23ab-bf41-ba29-4c574b9d6f7c",
                "version": "R80.30"
            },
            {
                "domain": {
                    "domain-type": "domain",
                    "name": "SMC User",
                    "uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"
                },
                "domain-name": "SMC User",
                "domain-type": null,
                "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                "management-blades": {},
                "name": "test-gw",
                "network-security-blades": {
                    "firewall": true
                },
                "type": "simple-gateway",
                "uid": "3b83b6cb-d3cb-4596-8d90-ba9735d7d53c",
                "version": "R80.30"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for: list-gateways:
>|name|uid|type|domain-name|domain-uid|version|network-security-blades|management-blades|
>|---|---|---|---|---|---|---|---|
>| gw-88a290 | 98bee60f-23ab-bf41-ba29-4c574b9d6f7c | CpmiHostCkp | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | R80.30 |  | network-policy-management: true<br/>logging-and-status: true |
>| test-gw | 3b83b6cb-d3cb-4596-8d90-ba9735d7d53c | simple-gateway | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | R80.30 | firewall: true |  |

