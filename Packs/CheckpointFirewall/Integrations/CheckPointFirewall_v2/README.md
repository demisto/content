
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
| CheckPoint.Host.name | String | object name | 
| CheckPoint.Host.uid | String | object uid | 
| CheckPoint.Host.type | String | object type | 
| CheckPoint.Host.ipv4 | String | IP\-v4 address of a spesific host | 


#### Command Example
```!checkpoint-host-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "Host": [
            {
                "ipv4": "200.200.200.111",
                "name": "200.200.200.111",
                "type": "host",
                "uid": "3b80b631-2241-42c9-af12-c00e3ef16801"
            },
            {
                "ipv4": "200.200.200.112",
                "name": "200.200.200.112",
                "type": "host",
                "uid": "23c4b2cf-0adc-4282-8f15-262cfec7f5f5"
            },
            {
                "ipv4": "200.200.200.113",
                "name": "200.200.200.113",
                "type": "host",
                "uid": "1404bc91-2a3b-4b42-a8ec-cc5637a8782f"
            },
            {
                "ipv4": "200.200.200.114",
                "name": "200.200.200.114",
                "type": "host",
                "uid": "635bb5af-05d9-4754-a2ce-0e5c9e2df6b2"
            },
            {
                "ipv4": "200.200.200.115",
                "name": "200.200.200.115",
                "type": "host",
                "uid": "d5558fe3-f6de-48e9-9029-5f8711e9654d"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing Hosts:
>|name|uid|type|ipv4|
>|---|---|---|---|
>| 200.200.200.111 | 3b80b631-2241-42c9-af12-c00e3ef16801 | host | 200.200.200.111 |
>| 200.200.200.112 | 23c4b2cf-0adc-4282-8f15-262cfec7f5f5 | host | 200.200.200.112 |
>| 200.200.200.113 | 1404bc91-2a3b-4b42-a8ec-cc5637a8782f | host | 200.200.200.113 |
>| 200.200.200.114 | 635bb5af-05d9-4754-a2ce-0e5c9e2df6b2 | host | 200.200.200.114 |
>| 200.200.200.115 | d5558fe3-f6de-48e9-9029-5f8711e9654d | host | 200.200.200.115 |


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
| CheckPoint.Host.name | Unknown | host name | 
| CheckPoint.Host.uid | String | object uid | 
| CheckPoint.Host.type | Unknown | object type | 
| CheckPoint.Host.domain-name | String | domain name | 
| CheckPoint.Host.domain-uid | String | domain uid | 
| CheckPoint.Host.ipv4-address | String | IP address | 
| CheckPoint.Host.ipv6-address | String | IP address | 
| CheckPoint.Host.read-only | Boolean | indicates if the object is read only | 
| CheckPoint.Host.creator | String | indicates the creator of the object | 
| CheckPoint.Host.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.Host.groups-name | String | Group object name linked to current host object. | 
| CheckPoint.Host.groups-uid | Unknown | Group object uid linked to current host object. | 


#### Command Example
```!checkpoint-host-get identifier=host_test```

#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": [
                {
                    "name": "test_group",
                    "uid": "d3347224-ee5e-435a-b274-bdc29b5e707c"
                }
            ],
            "ipv4-address": "11.22.33.45",
            "ipv6-address": "11.22.33.45",
            "last-modifier": "adminsh",
            "name": "host_test",
            "read-only": false,
            "type": "host",
            "uid": "badfe307-d517-46e8-bc66-abdec61d7a53"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting Host:
>|creator|domain-name|domain-uid|ipv4-address|ipv6-address|last-modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | 11.22.33.45 | 11.22.33.45 | adminsh | host_test | false | host | badfe307-d517-46e8-bc66-abdec61d7a53 |
>### CheckPoint data for Host groups:
>|name|uid|
>|---|---|
>| test_group | d3347224-ee5e-435a-b274-bdc29b5e707c |


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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Host.name | String | object name | 
| CheckPoint.Host.uid | String | object uid | 
| CheckPoint.Host.type | String | object type | 
| CheckPoint.Host.domain-name | String | domain name | 
| CheckPoint.Host.domain-uid | String | domain uid | 
| CheckPoint.Host.domain-type | String | domain type | 
| CheckPoint.Host.creator | String | indicates the creator of the object | 
| CheckPoint.Host.last-modifier | String | indicates the last user modifies the object | 
| CheckPoint.Host.ipv4-address | String | ip address | 
| CheckPoint.Host.ipv6-address | String | IP address | 
| CheckPoint.Host.read-only | String | indicates if the object is read only | 
| CheckPoint.Host.groups | String | Collection of group identifiers | 


#### Command Example
```!checkpoint-host-add name=test_host ip_address=8.8.8.8 session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": "8.8.8.8",
            "ipv6-address": "8.8.8.8",
            "last-modifier": "adminsh",
            "name": "test_host",
            "read-only": true,
            "type": "host",
            "uid": "dfeb5a46-40f3-4937-bda9-3321ffa02251"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding Host:
>|creator|domain-name|domain-uid|ipv4-address|ipv6-address|last-modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | 8.8.8.8 | 8.8.8.8 | adminsh | test_host | true | host | dfeb5a46-40f3-4937-bda9-3321ffa02251 |


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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Host.name | String | object name | 
| CheckPoint.Host.uid | String | object uid | 
| CheckPoint.Host.type | String | object type | 
| CheckPoint.Host.domain-name | String | domain name | 
| CheckPoint.Host.domain-uid | String | domain uid | 
| CheckPoint.Host.domain-type | String | domain type | 
| CheckPoint.Host.creator | String | indicates the creator of the object | 
| CheckPoint.Host.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.Host.ipv4-address | String | IP address | 
| CheckPoint.Host.read-only | Boolean | IP address | 
| CheckPoint.Host.group-name | String | Group object name linked to the host. | 
| CheckPoint.Host.group-uid | String | Group object name linked to the host | 


#### Command Example
```!checkpoint-host-update identifier=host_test session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": "test_group",
            "ipv4-address": "11.22.33.45",
            "ipv6-address": "11.22.33.45",
            "name": "host_test",
            "total-number": null,
            "type": "host",
            "uid": "badfe307-d517-46e8-bc66-abdec61d7a53"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating Host:
>|domain-name|domain-uid|groups|ipv4-address|ipv6-address|name|type|uid|
>|---|---|---|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | test_group | 11.22.33.45 | 11.22.33.45 | host_test | host | badfe307-d517-46e8-bc66-abdec61d7a53 |


### checkpoint-host-delete
***
delete host


#### Base Command

`checkpoint-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Host.message | String | operation status | 


#### Command Example
``` !checkpoint-host-delete identifier="host_test" session_id="TEAK9kWnZ9Dhql9hYP5IR4aZEw1mrKdPjw3lRnxvp88"```

#### Context Example
#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "message": "ok"
        }
    }
}
```
#### Human Readable Output
### CheckPoint Data for deleting Host:
|message|
|---|
| OK |


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
| CheckPoint.Group.name | String | object's name | 
| CheckPoint.Group.uid | String | object's uid | 
| CheckPoint.Group.type | String | Type of the object | 


#### Command Example
```!checkpoint-group-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "Group": [
            {
                "ipv4": null,
                "name": "bensar",
                "type": "group",
                "uid": "fe26adc1-c0e1-4424-9a9e-f74f511a7f28"
            },
            {
                "ipv4": null,
                "name": "group_test",
                "type": "group",
                "uid": "35a46b01-47f5-496f-9329-d55c7d2ab083"
            },
            {
                "ipv4": null,
                "name": "Group_test_for_demisto",
                "type": "group",
                "uid": "1deaead0-136c-4791-8d58-9229c143b8c5"
            },
            {
                "ipv4": null,
                "name": "new_empty_group",
                "type": "group",
                "uid": "46bc7185-ad43-4792-b9be-40364a1d0883"
            },
            {
                "ipv4": null,
                "name": "new_host_group",
                "type": "group",
                "uid": "a4f0f6c4-7b60-44c1-8dce-6307069fcccf"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing Groups:
>|name|uid|type|
>|---|---|---|
>| bensar | fe26adc1-c0e1-4424-9a9e-f74f511a7f28 | group |
>| group_test | 35a46b01-47f5-496f-9329-d55c7d2ab083 | group |
>| Group_test_for_demisto | 1deaead0-136c-4791-8d58-9229c143b8c5 | group |
>| new_empty_group | 46bc7185-ad43-4792-b9be-40364a1d0883 | group |
>| new_host_group | a4f0f6c4-7b60-44c1-8dce-6307069fcccf | group |


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
| CheckPoint.Group.name | String | object name | 
| CheckPoint.Group.uid | String | object uid | 
| CheckPoint.Group.type | String | object type | 
| CheckPoint.Group.domain-name | String | domain name | 
| CheckPoint.Group.domain-uid | String | domain uid | 
| CheckPoint.Group.domain-type | String | domain type | 
| CheckPoint.Group.creator | String | indicates the creator of the object | 
| CheckPoint.Group.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.Group.read-only | Boolean | indicates if the object is read only | 


#### Command Example
```!checkpoint-group-get identifier=test_group```

#### Context Example
```
{
    "CheckPoint": {
        "Group": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "last-modifier": "adminsh",
            "members": [
                {
                    "member-domain-name": "SMC User",
                    "member-domain-type": null,
                    "member-domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                    "member-name": "host_test",
                    "member-type": "host",
                    "member-uid": "badfe307-d517-46e8-bc66-abdec61d7a53"
                },
                {
                    "member-domain-name": "SMC User",
                    "member-domain-type": null,
                    "member-domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                    "member-name": "200.200.200.114",
                    "member-type": "host",
                    "member-uid": "635bb5af-05d9-4754-a2ce-0e5c9e2df6b2"
                }
            ],
            "name": "test_group",
            "read-only": false,
            "type": "group",
            "uid": "d3347224-ee5e-435a-b274-bdc29b5e707c"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting Group:
>|creator|domain-name|domain-uid|last-modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | test_group | false | group | d3347224-ee5e-435a-b274-bdc29b5e707c |
>### CheckPoint member data:
>|member-name|member-uid|member-type|member-domain-name|member-domain-uid|
>|---|---|---|---|---|
>| host_test | badfe307-d517-46e8-bc66-abdec61d7a53 | host | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |
>| 200.200.200.114 | 635bb5af-05d9-4754-a2ce-0e5c9e2df6b2 | host | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |


### checkpoint-group-add
***
add a group


#### Base Command

`checkpoint-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Object name. Must be unique in the domain. | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Group.name | String | object's name | 
| CheckPoint.Group.uid | String | object uid | 
| CheckPoint.Group.type | Unknown | object type | 
| CheckPoint.Group.domain-name | String | domain name | 
| CheckPoint.Group.domain-uid | String | domain uid | 
| CheckPoint.Group.domain-type | String | domain type | 
| CheckPoint.Group.creator | String | Indicates the object creator | 
| CheckPoint.Group.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.Group.read-only | Boolean | Indicates whether the object is read\-only | 
| CheckPoint.Group.groups-name | Unknown | groups name | 


#### Command Example
```!checkpoint-group-add name=test_group_1 session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Group": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "last-modifier": "adminsh",
            "name": "test_group_1",
            "type": "group",
            "uid": "11e751da-a0e7-499a-bcde-5bc638c73fb5"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding Group:
>|creator|domain-name|domain-uid|last-modifier|name|type|uid|
>|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | test_group_1 | group | 11e751da-a0e7-499a-bcde-5bc638c73fb5 |


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
| session_id | Execute command with a specific session ID | Required | 
| members | Collection of Network objects identified by the name or UID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Group.name | String | object name | 
| CheckPoint.Group.uid | String | object uid | 
| CheckPoint.Group.type | String | object type | 
| CheckPoint.Group.domain-name | String | domain name | 
| CheckPoint.Group.domain-uid | String | domain uid | 
| CheckPoint.Group.domain-type | String | domain type | 
| CheckPoint.Group.creator | String | Indicates the creator of the object | 
| CheckPoint.Group.last-modifier | String | Indicates the lasr user modified the object | 
| CheckPoint.Group.read-only | Boolean | Indicates if the object is read only | 


#### Command Example
```!checkpoint-group-update identifier=test_group session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Group": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "test_group",
            "total-number": null,
            "type": "group",
            "uid": "d3347224-ee5e-435a-b274-bdc29b5e707c"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating Group:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | test_group | group | d3347224-ee5e-435a-b274-bdc29b5e707c |


### checkpoint-group-delete
***
delete a group object


#### Base Command

`checkpoint-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Group.message | String | Operation massege | 


#### Command Example
```!checkpoint-group-delete identifier=test_group session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Group": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting Group:
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
| CheckPoint.AddressRange.name | String | Object's name | 
| CheckPoint.AddressRange.uid | String | Object's uid | 
| CheckPoint.AddressRange.type | String | Type of the object. | 


#### Command Example
```!checkpoint-address-range-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange": [
            {
                "ipv4": null,
                "name": "address_range_test",
                "type": "address-range",
                "uid": "459d883d-8c1f-40b2-b269-450dc4f857ac"
            },
            {
                "ipv4": null,
                "name": "address_range_test_2",
                "type": "address-range",
                "uid": "1f9b89c7-a4e5-4f1e-b59a-e9c3029e7572"
            },
            {
                "ipv4": null,
                "name": "All_Internet",
                "type": "address-range",
                "uid": "f90e0a2b-f166-427a-b47f-a107b6fe43b9"
            },
            {
                "ipv4": null,
                "name": "LocalMachine_Loopback",
                "type": "address-range",
                "uid": "5d3b2752-4072-41e1-9aa0-488813b02a40"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing AddressRanges:
>|name|uid|type|
>|---|---|---|
>| address_range_test | 459d883d-8c1f-40b2-b269-450dc4f857ac | address-range |
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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.AddressRange.name | String | object name | 
| CheckPoint.AddressRange.uid | String | object uid | 
| CheckPoint.AddressRange.type | String | object type | 
| CheckPoint.AddressRange.domain-name | String | domain name | 
| CheckPoint.AddressRange.domain-uid | String | domain uid | 
| CheckPoint.AddressRange.domain-type | String | domain type | 
| CheckPoint.AddressRange.ipv4-address-first | String | First IPv4 address in the range | 
| CheckPoint.AddressRange.ipv4-address-last | String | Last IPv4 address in the range | 
| CheckPoint.AddressRange.ipv6-address-first | String | First IPv4 address in the range | 
| CheckPoint.AddressRange.ipv6-address-last | String | Last IPv6 address in the range | 
| CheckPoint.AddressRange.read-only | Boolean | Indicates whether the object is read\-only. | 
| CheckPoint.AddressRange.creator | String | Indicates the creator of the object | 
| CheckPoint.AddressRange.last-modifier | String | Indicates the last user modified the object | 


#### Command Example
``` !checkpoint-address-range-add name="address_range_test_1" ip_address_first="100.100.100.3" ip_address_last="100.100.100.5" session_id="TEAK9kWnZ9Dhql9hYP5IR4aZEw1mrKdPjw3lRnxvp88"```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange":
                    {
                      'name': 'address_range_test_1',
                      'uid': '13b34d0b-64a6-4a35-837d-8d25e3faf995',
                      'type': 'address-range',
                      'domain-name': 'SMC User',
                      'domain-uid': '41e821a0-3720-11e3-aa6e-0800200c9fde',
                      'domain-type': None,
                      'creator': 'adminsh',
                      'last-modifier': 'adminsh'
                    }
    }
}
```

#### Human Readable Output
### CheckPoint data for adding AddressRange:
|creator|domain-name|domain-uid|last-modifier|name|type|uid|
|---|---|---|---|---|---|---|
| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | address_range_test_1 | address-range | 13b34d0b-64a6-4a35-837d-8d25e3faf995 |


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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.AddressRange.name | String | object name | 
| CheckPoint.AddressRange.uid | String | object uid | 
| CheckPoint.AddressRange.type | String | object type | 
| CheckPoint.AddressRange.domain-name | String | domain name | 
| CheckPoint.AddressRange.domain-uid | String | domain uid | 
| CheckPoint.AddressRange.domain-type | String | domain type | 
| CheckPoint.AddressRange.ipv4-address-first | String | First IPv4 address in the range | 
| CheckPoint.AddressRange.ipv4-address-last | String | Last IPv4 address in the range | 
| CheckPoint.AddressRange.ipv6-address-first | String | First IPv4 address in the range | 
| CheckPoint.AddressRange.ipv6-address-last | String | Last IPv6 address in the range | 
| CheckPoint.AddressRange.read-only | Boolean | Indicates whether the object is read\-only. | 
| CheckPoint.AddressRange.groups | String | List of all groups the address range is linked to | 


#### Command Example
```!checkpoint-address-range-update identifier=address_range_test layer=Network session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "address_range_test",
            "total-number": null,
            "type": "address-range",
            "uid": "459d883d-8c1f-40b2-b269-450dc4f857ac"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating AddressRange:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | address_range_test | address-range | 459d883d-8c1f-40b2-b269-450dc4f857ac |


### checkpoint-address-range-delete
***
Delete a given address range


#### Base Command

`checkpoint-address-range-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.AddressRange.message | String | Operation status | 


#### Command Example
```!checkpoint-address-range-delete identifier=address_range_test session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting AddressRange:
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
| CheckPoint.ThreatIndicator.name | String | object name | 
| CheckPoint.ThreatIndicator.uid | String | object uid | 
| CheckPoint.ThreatIndicator.type | String | object type | 


#### Command Example
```!checkpoint-threat-indicator-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": [
            {
                "ipv4": null,
                "name": "My_Indicator",
                "type": "threat-indicator",
                "uid": "a40ec97c-e286-474b-bff7-b922e3b3294d"
            },
            {
                "ipv4": null,
                "name": "test_indicator",
                "type": "threat-indicator",
                "uid": "3e6a22c0-0416-4a2d-b7c0-f81df12916e1"
            },
            {
                "ipv4": null,
                "name": "threat_test",
                "type": "threat-indicator",
                "uid": "2830048d-0836-4ad0-a7bf-545e0fa00779"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing ThreatIndicators:
>|name|uid|type|
>|---|---|---|
>| My_Indicator | a40ec97c-e286-474b-bff7-b922e3b3294d | threat-indicator |
>| test_indicator | 3e6a22c0-0416-4a2d-b7c0-f81df12916e1 | threat-indicator |
>| threat_test | 2830048d-0836-4ad0-a7bf-545e0fa00779 | threat-indicator |


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
| CheckPoint.ThreatIndicator.name | String | object name | 
| CheckPoint.ThreatIndicator.uid | String | object uid | 
| CheckPoint.ThreatIndicator.type | String | object type | 
| CheckPoint.ThreatIndicator.domain-name | String | Domain name | 
| CheckPoint.ThreatIndicator.domain-uid | String | object uid | 
| CheckPoint.ThreatIndicator.domain-type | Unknown | domain type | 
| CheckPoint.ThreatIndicator.creator | String | creator | 
| CheckPoint.ThreatIndicator.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.ThreatIndicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
```!checkpoint-threat-indicator-get identifier=threat_test```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "last-modifier": "adminsh",
            "name": "threat_test",
            "read-only": false,
            "type": "threat-indicator",
            "uid": "2830048d-0836-4ad0-a7bf-545e0fa00779"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting ThreatIndicator:
>|creator|domain-name|domain-uid|last-modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | threat_test | false | threat-indicator | 2830048d-0836-4ad0-a7bf-545e0fa00779 |


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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ThreatIndicator.task-id | String | Asynchronous task unique identifier. | 


#### Command Example
```!checkpoint-threat-indicator-add name=threat_test2 observables=[] session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4 ```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": {
                    'task-id': 'c3b11fff-c58d-4242-af44-f549c40b0af5'
        }
    }
}
```

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
| CheckPoint.ThreatIndicator.name | String | object name | 
| CheckPoint.ThreatIndicator.uid | String | object uid | 
| CheckPoint.ThreatIndicator.type | String | object type | 
| CheckPoint.ThreatIndicator.action | String | The indicator's action. | 
| CheckPoint.ThreatIndicator.domain-name | String | domain name | 
| CheckPoint.ThreatIndicator.domain-uid | String | domain uid | 
| CheckPoint.ThreatIndicator.domain-type | String | domain type | 
| CheckPoint.ThreatIndicator.creator | String | Indicates the creator of the object | 
| CheckPoint.ThreatIndicator.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.ThreatIndicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
```!checkpoint-threat-indicator-update identifier=threat_test session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "threat_test",
            "total-number": null,
            "type": "threat-indicator",
            "uid": "2830048d-0836-4ad0-a7bf-545e0fa00779"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating ThreatIndicator:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | threat_test | threat-indicator | 2830048d-0836-4ad0-a7bf-545e0fa00779 |


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
| CheckPoint.AddressRange.name | String | object name | 
| CheckPoint.AddressRange.uid | String | object uid | 
| CheckPoint.AddressRange.type | String | object type | 
| CheckPoint.AddressRange.domain-name | String | domain name | 
| CheckPoint.AddressRange.domain-uid | String | domain uid | 
| CheckPoint.AddressRange.domain-type | String | domain type | 
| CheckPoint.AddressRange.groups-name | String | Group object name linked to current host object | 
| CheckPoint.AddressRange.groups-uid | String | Group object uid linked to current host object | 


#### Command Example
```!checkpoint-address-range-get identifier=address_range_test```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "last-modifier": "adminsh",
            "name": "address_range_test",
            "read-only": false,
            "type": "address-range",
            "uid": "459d883d-8c1f-40b2-b269-450dc4f857ac"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting AddressRange:
>|creator|domain-name|domain-uid|last-modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | address_range_test | false | address-range | 459d883d-8c1f-40b2-b269-450dc4f857ac |


### checkpoint-threat-indicator-delete
***
delete threat indicator


#### Base Command

`checkpoint-threat-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ThreatIndicator.message | String | Operation status | 


#### Command Example
```!checkpoint-threat-indicator-delete identifier=threat_test session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting ThreatIndicator:
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
| CheckPoint.AccessRule.name | String | object name | 
| CheckPoint.AccessRule.uid | String | object uid | 


#### Command Example
```!checkpoint-access-rule-list identifier=Network limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "AccessRule": [
            {
                "ipv4": null,
                "name": "Any",
                "uid": "97aeb369-9aea-11d5-bd16-0090272ccb30"
            },
            {
                "ipv4": "192.192.10.45",
                "name": "Demisto - 2110",
                "uid": "35f582cc-cbfd-4e7e-b39e-7b6ffe636c6c"
            },
            {
                "ipv4": "192.192.10.97",
                "name": "Demisto - 2111",
                "uid": "644179b3-98c9-4b49-851d-6bdc7e3f2e3f"
            },
            {
                "ipv4": "192.152.10.45",
                "name": "Demisto - 2114",
                "uid": "877955ea-6587-4db7-83cd-41d213043dea"
            },
            {
                "ipv4": "192.152.22.45",
                "name": "Demisto - 2122",
                "uid": "b48b07fe-1acd-493c-af10-4a9e75c7fe9a"
            },
            {
                "ipv4": null,
                "name": "Drop",
                "uid": "6c488338-8eec-4103-ad21-cd461ac2c473"
            },
            {
                "ipv4": null,
                "name": "None",
                "uid": "29e53e3d-23bf-48fe-b6b1-d59bd88036f9"
            },
            {
                "ipv4": null,
                "name": "Policy Targets",
                "uid": "6c488338-8eec-4103-ad21-cd461ac2c476"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing AccessRules:
>|name|uid|ipv4|
>|---|---|---|
>| Any | 97aeb369-9aea-11d5-bd16-0090272ccb30 |  |
>| Demisto - 2110 | 35f582cc-cbfd-4e7e-b39e-7b6ffe636c6c | 192.192.10.45 |
>| Demisto - 2111 | 644179b3-98c9-4b49-851d-6bdc7e3f2e3f | 192.192.10.97 |
>| Demisto - 2114 | 877955ea-6587-4db7-83cd-41d213043dea | 192.152.10.45 |
>| Demisto - 2122 | b48b07fe-1acd-493c-af10-4a9e75c7fe9a | 192.152.22.45 |
>| Drop | 6c488338-8eec-4103-ad21-cd461ac2c473 |  |
>| None | 29e53e3d-23bf-48fe-b6b1-d59bd88036f9 |  |
>| Policy Targets | 6c488338-8eec-4103-ad21-cd461ac2c476 |  |


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
| action | Action settings. valid values are: Accept, Drop, Apply Layer, Ask and Info. default value is Drop. | Optional | 
| vpn | Communities or Directional. Valid values: Any, All_GwToGw. | Optional | 
| destination | Collection of Network objects identified by the name or UID. | Optional | 
| service | Collection of Network objects identified by the name or UID. | Optional | 
| source | Collection of Network objects identified by the name or UID. | Optional | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.AccessRule.name | String | object name | 
| CheckPoint.AccessRule.uid | String | object uid | 
| CheckPoint.AccessRule.type | String | object type | 
| CheckPoint.AccessRule.domain-name | String | domain name | 
| CheckPoint.AccessRule.domain-uid | String | domain uid | 
| CheckPoint.AccessRule.domain-type | String | domain type | 
| CheckPoint.AccessRule.enabled | Boolean | Enable/Disable the rule. | 
| CheckPoint.AccessRule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| CheckPoint.AccessRule.creator | String | Indicated the object creator | 
| CheckPoint.AccessRule.last-modifier | String | Indicates the last user modofied the object | 


#### Command Example
```!checkpoint-access-rule-add name=test_access_rule_1 layer=Network position=top session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "AccessRule": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "enabled": true,
            "last-modifier": "adminsh",
            "layer": "c0264a80-1832-4fce-8a90-d0849dc4ba33",
            "name": "test_access_rule_1",
            "type": "access-rule",
            "uid": "7ab4a92f-384d-4dc3-bfd9-f0da00e45a4d"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding AccessRule:
>|creator|domain-name|domain-uid|enabled|last-modifier|layer|name|type|uid|
>|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | true | adminsh | c0264a80-1832-4fce-8a90-d0849dc4ba33 | test_access_rule_1 | access-rule | 7ab4a92f-384d-4dc3-bfd9-f0da00e45a4d |


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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.AccessRule.name | String | object name | 
| CheckPoint.AccessRule.uid | String | object uid | 
| CheckPoint.AccessRule.type | String | object type | 
| CheckPoint.AccessRule.action-name | String | action name | 
| CheckPoint.AccessRule.action-uid | String | action uid | 
| CheckPoint.AccessRule.action-type | Unknown | action type | 
| CheckPoint.AccessRule.action-domain-name | String | action domain name | 
| CheckPoint.AccessRule.content-direction | String | On which direction the file types processing is applied. | 
| CheckPoint.AccessRule.domain-name | String | domain name | 
| CheckPoint.AccessRule.domain-uid | String | domain uid | 
| CheckPoint.AccessRule.domain-type | String | domain type | 
| CheckPoint.AccessRule.enabled | Boolean | Enable/Disable the rule. | 
| CheckPoint.AccessRule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| CheckPoint.AccessRule.creator | String | Indicates the creator of the object | 
| CheckPoint.AccessRule.last-modifier | String | Indicates the last user modified the object | 


#### Command Example
```!checkpoint-access-rule-update identifier=test_access_rule layer=Network session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "AccessRule": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "None",
            "total-number": null,
            "type": "access-rule",
            "uid": "064775c9-2603-4af2-bb04-9c90e0cd29f8"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating AccessRule:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | None | access-rule | 064775c9-2603-4af2-bb04-9c90e0cd29f8 |


### checkpoint-access-rule-delete
***
Delete access rule


#### Base Command

`checkpoint-access-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid, name or rule-number. | Required | 
| layer | Layer that the rule belongs to identified by the name or UID. | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.AccessRule.message | String | Operation status | 


#### Command Example
``` !checkpoint-access-rule-delete identifier=test_access_rule layer=Network session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

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
| CheckPoint.ApplicationSite.name | String | objects name | 
| CheckPoint.ApplicationSite.uid | String | objects uid | 
| CheckPoint.ApplicationSite.type | String | objects type | 


#### Command Example
```!checkpoint-application-site-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSite": [
            {
                "ipv4": null,
                "name": "#hashtags",
                "type": "application-site",
                "uid": "00fa9e3c-36ef-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "050 Plus",
                "type": "application-site",
                "uid": "00fa9e44-4035-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "1000keyboards",
                "type": "application-site",
                "uid": "00fa9e3d-a077-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "1000memories",
                "type": "application-site",
                "uid": "00fa9e43-56d7-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "1001",
                "type": "application-site",
                "uid": "00fa9e3d-1ab6-0f65-e053-08241dc22da2"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing ApplicationSites:
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
| session_id | Execute command with a specific session ID | Required | 
| groups | Collection of group identifiers. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ApplicationSite.name | String | object name | 
| CheckPoint.ApplicationSite.uid | String | object uid | 
| CheckPoint.ApplicationSite.type | String | object type | 
| CheckPoint.ApplicationSite.application-id | Number | application ID | 
| CheckPoint.ApplicationSite.description | String | A description for the application. | 
| CheckPoint.ApplicationSite.domain-name | String | domain name | 
| CheckPoint.ApplicationSite.domain-uid | String | domain uid | 
| CheckPoint.ApplicationSite.domain-type | String | domain name | 
| CheckPoint.ApplicationSite.url-list | String | URLs that determine this particular application. | 
| CheckPoint.ApplicationSite.creator | String | Indicates the creator of the object | 
| CheckPoint.ApplicationSite.last-modifier | String | Indicates the last user modified this object | 
| CheckPoint.ApplicationSite.groups | Unknown | Collection of group identifiers | 


#### Command Example
``` !checkpoint-application-site-add name="test_application_site_1" primary_category="Test Category" identifier="qmasters.co" session_id="TEAK9kWnZ9Dhql9hYP5IR4aZEw1mrKdPjw3lRnxvp88"```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSite": {
                'name': 'test_application_site_1',
                'uid': '452f6cff-e7fb-47b8-abfe-53c668dc0038',
                'type': 'application-site',
                'domain-name': 'SMC User',
                'domain-uid': '41e821a0-3720-11e3-aa6e-0800200c9fde',
                'domain-type': None,
                'creator': 'adminsh',
                'last-modifier': 'adminsh',
                'application-id': 0,
                'description': '',
                'url-list': [
                  'qmasters.co'
                ]
    }
}
``` 

#### Human Readable Output
### CheckPoint data for adding ApplicationSite:
|application-id|creator|domain-name|domain-uid|last-modifier|name|type|uid|url-list|
|---|---|---|---|---|---|---|---|---|
| 0 | adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | test_application_site_1 | application-site | 452f6cff-e7fb-47b8-abfe-53c668dc0038 | qmasters.co |


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
| session_id | Execute command with a specific session ID | Required | 
| groups | Collection of group identifiers. Can be a single group or a list of groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ApplicationSite.name | String | object name | 
| CheckPoint.ApplicationSite.uid | String | object uid | 
| CheckPoint.ApplicationSite.type | String | object ty\[e | 
| CheckPoint.ApplicationSite.application-id | Number | application ID | 
| CheckPoint.ApplicationSite.description | String | A description for the application. | 
| CheckPoint.ApplicationSite.domain-name | String | domain name | 
| CheckPoint.ApplicationSite.domain-uid | String | domain uid | 
| CheckPoint.ApplicationSite.domain-type | String | domain type | 
| CheckPoint.ApplicationSite.url-list | String | URLs that determine this particular application. | 
| CheckPoint.ApplicationSite.groups | String | Collection of group identifiers | 


#### Command Example
```!checkpoint-application-site-update identifier=test_application_site session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSite": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "ipv6-address": null,
            "name": "test_application_site",
            "total-number": null,
            "type": "application-site",
            "uid": "463b6c43-0de9-4ec7-80c5-7e2163099510"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating ApplicationSite:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | test_application_site | application-site | 463b6c43-0de9-4ec7-80c5-7e2163099510 |


### checkpoint-application-site-delete
***
Delete existing application site object using object name or uid.


#### Base Command

`checkpoint-application-site-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ApplicationSite.message | String | Operation status. | 


#### Command Example
```!checkpoint-application-site-delete identifier=test_application_site session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSite": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for deleting ApplicationSite:
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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Publish.task-id | String | Task id of the publish command. | 


#### Command Example
```!checkpoint-publish session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Publish": {
            "task-id": "01234567-89ab-cdef-bf09-149f8cd4d2b3"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for Publish:
>|task-id|
>|---|
>| 01234567-89ab-cdef-bf09-149f8cd4d2b3 |


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
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.InstallPolicy.task-id | String | Operation task ID. | 


#### Command Example
```!checkpoint-install-policy policy_package=standard targets=test-gw session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "InstallPolicy": {
            "task-id": "0317d452-efce-4c89-a6e2-29ff83ed1e9b"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for InstallPolicy:
>|task-id|
>|---|
>| 0317d452-efce-4c89-a6e2-29ff83ed1e9b |


### checkpoint-verify-policy
***
Verifies the policy of the selected package.


#### Base Command

`checkpoint-verify-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_package | The name of the Policy Package to be installed. | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.VerifyPolicy.task-id | String | Operation task ID. | 


#### Command Example
```!checkpoint-policy-verify policy_package=standard session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4 ```

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
| CheckPoint.ShowTask.task-id | String | Task ID | 
| CheckPoint.ShowTask.task-name | String | Task name | 
| CheckPoint.ShowTask.status | String | Task status | 
| CheckPoint.ShowTask.progress-percentage | Unknown | Task prograss in percentage | 
| CheckPoint.ShowTask.suppressed | Boolean | Indicates if the task is suppressed | 


#### Command Example
```!checkpoint-show-task task_id=01234567-89ab-cdef-8dba-36edc2efb5b0```

#### Context Example
```
{
    "CheckPoint": {
        "ShowTask": {
            "progress-percentage": 100,
            "status": "succeeded",
            "suppressed": false,
            "task-id": "01234567-89ab-cdef-8dba-36edc2efb5b0",
            "task-name": "Publish operation"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing tasks:
>|task-name|task-id|status|suppressed|progress-percentage|
>|---|---|---|---|---|
>| Publish operation | 01234567-89ab-cdef-8dba-36edc2efb5b0 | succeeded | false | 100 |


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
| CheckPoint.Login.session-id | String | Session ID | 


#### Command Example
```!checkpoint-login-and-get-session-id timeout=60```

#### Context Example
```
{
    "CheckPoint": {
        "Login": {
            "session-id": "PJZcuoWM5IKd4CeAa9Dc_pmDOUBfY2eELgqQSEP6mug"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint session data:
>|session-id|
>|---|
>| PJZcuoWM5IKd4CeAa9Dc_pmDOUBfY2eELgqQSEP6mug |


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
```!checkpoint-logout session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{}
```

#### Human Readable Output

>OK

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
| CheckPoint.Packages.name | String | Name of the package | 
| CheckPoint.Packages.uid | String | UID of the package | 
| CheckPoint.Packages.type | String | Type of the package | 
| CheckPoint.Packages.domain-name | String | Domain name | 
| CheckPoint.Packages.domain-uid | String | Domain uid | 
| CheckPoint.Packages.domain-type | String | Domain type | 


#### Command Example
```!checkpoint-packages-list session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Packages": [
            {
                "domain": {
                    "domain-type": "domain",
                    "name": "SMC User",
                    "uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"
                },
                "domain-name": "SMC User",
                "domain-type": null,
                "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
                "name": "BenLayer",
                "type": "package",
                "uid": "9daac370-ad2d-4a21-a503-a312755aceaf"
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
                "name": "Standard",
                "type": "package",
                "uid": "ca4e32a8-bee0-423c-84f0-19bab6751d5e"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for: Packages:
>|name|uid|type|domain-name|domain-uid|
>|---|---|---|---|---|
>| BenLayer | 9daac370-ad2d-4a21-a503-a312755aceaf | package | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |
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
| CheckPoint.Gateways.name | String | Gateway name | 
| CheckPoint.Gateways.uid | String | Gateway uid | 
| CheckPoint.Gateways.type | String | Gateway type | 
| CheckPoint.Gateways.version | String | Gateway vesion | 
| CheckPoint.Gateways.network-security-blades | String | Gateway network security blades | 
| CheckPoint.Gateways.management-blades | String | Gateway management blades | 
| CheckPoint.Gateways.domain-name | String | Domain name | 
| CheckPoint.Gateways.domain-uid | String | Domain UID | 
| CheckPoint.Gateways.domain-type | String | Doamin type | 


#### Command Example
```!checkpoint-gateways-list session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "Gateways": [
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

>### CheckPoint data for: Gateways:
>|name|uid|type|domain-name|domain-uid|version|network-security-blades|management-blades|
>|---|---|---|---|---|---|---|---|
>| gw-88a290 | 98bee60f-23ab-bf41-ba29-4c574b9d6f7c | CpmiHostCkp | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | R80.30 |  | network-policy-management: true<br/>logging-and-status: true |
>| test-gw | 3b83b6cb-d3cb-4596-8d90-ba9735d7d53c | simple-gateway | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | R80.30 | firewall: true |  |


### checkpoint-application-site-category-list
***
Retrieve all application site category.


#### Base Command

`checkpoint-application-site-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results | Optional | 
| offset | Number of the results to initially skip | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ApplicationSiteCategory.name | String | Name of the package | 
| CheckPoint.ApplicationSiteCategory.uid | String | UID of the package | 
| CheckPoint.ApplicationSiteCategory.type | String | Type of the package | 
| CheckPoint.ApplicationSiteCategory.domain-name | String | Domain name | 
| CheckPoint.ApplicationSiteCategory.domain-uid | String | Domain uid | 
| CheckPoint.ApplicationSiteCategory.domain-type | String | Domain type | 


#### Command Example
```!checkpoint-application-site-category-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSiteCategory": [
            {
                "ipv4": null,
                "name": "Adds other software",
                "type": "application-site-category",
                "uid": "00fa9e44-40c9-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "Alcohol",
                "type": "application-site-category",
                "uid": "00fa9e44-409e-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "Allows remote connect",
                "type": "application-site-category",
                "uid": "00fa9e44-40c3-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "Allows remote control",
                "type": "application-site-category",
                "uid": "00fa9e44-40ca-0f65-e053-08241dc22da2"
            },
            {
                "ipv4": null,
                "name": "Anonymizer",
                "type": "application-site-category",
                "uid": "00fa9e44-415a-0f65-e053-08241dc22da2"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing ApplicationSiteCategorys:
>|name|uid|type|
>|---|---|---|
>| Adds other software | 00fa9e44-40c9-0f65-e053-08241dc22da2 | application-site-category |
>| Alcohol | 00fa9e44-409e-0f65-e053-08241dc22da2 | application-site-category |
>| Allows remote connect | 00fa9e44-40c3-0f65-e053-08241dc22da2 | application-site-category |
>| Allows remote control | 00fa9e44-40ca-0f65-e053-08241dc22da2 | application-site-category |
>| Anonymizer | 00fa9e44-415a-0f65-e053-08241dc22da2 | application-site-category |


### checkpoint-application-site-category-add
***
Add new application site category


#### Base Command

`checkpoint-application-site-category-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | Object name or uid. Must be unique in the domain. | Required | 
| session_id | Execute command with a specific session ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ApplicationSiteCategory.name | String | object name | 
| CheckPoint.ApplicationSiteCategory.uid | String | object uid | 
| CheckPoint.ApplicationSiteCategory.type | String | object type | 
| CheckPoint.ApplicationSiteCategory.description | String | A description for the application. | 
| CheckPoint.ApplicationSiteCategory.domain-name | String | domain name | 
| CheckPoint.ApplicationSiteCategory.domain-uid | String | domain uid | 
| CheckPoint.ApplicationSiteCategory.domain-type | String | domain name | 
| CheckPoint.ApplicationSiteCategory.creator | String | Indicates the creator of the object | 
| CheckPoint.ApplicationSiteCategory.last-modifier | String | Indicates the last user modified this object | 
| CheckPoint.ApplicationSiteCategory.groups | Unknown | Collection of group identifiers | 


#### Command Example
```!checkpoint-application-site-category-add identifier=new_app_site_category session_id=fQqLms8Gzf3uXrWo3rOWvKhlxL_tWKx0i4BxeM8vJT4```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSiteCategory": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "last-modifier": "adminsh",
            "name": "new_app_site_category",
            "type": "application-site-category",
            "uid": "59105cbd-0267-4ab0-8e78-4771fb837cc0"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding ApplicationSiteCategory:
>|creator|domain-name|domain-uid|last-modifier|name|type|uid|
>|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | new_app_site_category | application-site-category | 59105cbd-0267-4ab0-8e78-4771fb837cc0 |


### checkpoint-application-site-category-get
***
Retrieve application site category object using object name or uid.


#### Base Command

`checkpoint-application-site-category-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | application site category object name or UID. | Required | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.ApplicationSiteCategory.name | Unknown | host name | 
| CheckPoint.ApplicationSiteCategory.uid | String | object uid | 
| CheckPoint.ApplicationSiteCategory.type | Unknown | object type | 
| CheckPoint.ApplicationSiteCategory.domain-name | String | domain name | 
| CheckPoint.ApplicationSiteCategory.domain-uid | String | domain uid | 
| CheckPoint.ApplicationSiteCategory.read-only | Boolean | indicates if the object is read only | 
| CheckPoint.ApplicationSiteCategory.creator | String | indicates the creator of the object | 
| CheckPoint.ApplicationSiteCategory.last-modifier | String | indicates the last user modified the object | 


#### Command Example
```!checkpoint-application-site-category-get identifier=Alcohol```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSiteCategory": {
            "creator": "System",
            "domain-name": "APPI Data",
            "domain-type": null,
            "domain-uid": "8bf4ac51-2df7-40e1-9bce-bedbedbedbed",
            "ipv4-address": null,
            "ipv6-address": null,
            "last-modifier": "System",
            "name": "Alcohol",
            "read-only": false,
            "type": "application-site-category",
            "uid": "00fa9e44-409e-0f65-e053-08241dc22da2"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting ApplicationSiteCategory:
>|creator|domain-name|domain-uid|last-modifier|name|read-only|type|uid|
>|---|---|---|---|---|---|---|---|
>| System | APPI Data | 8bf4ac51-2df7-40e1-9bce-bedbedbedbed | System | Alcohol | false | application-site-category | 00fa9e44-409e-0f65-e053-08241dc22da2 |


### checkpoint-show-objects
***
Retrieve data about objects.


#### Base Command

`checkpoint-show-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 
| filter_search | Search expression to filter objects by. The provided text should be exactly the same as it would be given in Smart Console. The logical operators in the expression ('AND', 'OR') should be provided in capital letters. By default, the search involves both a textual search and a IP search. To use IP search only, set the "ip-only" parameter to true. | Optional | 
| ip_only | If using "filter", use this field to search objects by their IP address only, without involving the textual search. | Optional | 
| object_type | he objects' type, e.g.: host, service-tcp, network, address-range. Default value is object | Optional | 
| session_id | Execute command with a specific session ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Object.name | String | object name | 
| CheckPoint.Object.uid | String | object uid | 
| CheckPoint.Object.type | String | object type | 
| CheckPoint.Object.ipv4 | String | IP\-v4 address of a spesific object | 


#### Command Example
``` !checkpoint-show-object limit=3 filter_search=1.2.3.4 ip_only=true```

#### Human Readable Output


