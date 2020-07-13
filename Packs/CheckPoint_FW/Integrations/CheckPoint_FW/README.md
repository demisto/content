Read information and to send commands to the Check Point Firewall server.
This integration was integrated and tested with version R80.30 of CheckPoint Smart Console.
## Configure CheckPoint_FW on Cortex XSOAR

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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 


#### Command Example
```!checkpoint-host-list```

#### Context Example
```
{
    "CheckPoint": {
        "host": [
            {
                "name": "test_host",
                "type": "host",
                "uid": "ff0d466b-9d7f-46e1-8a31-a54e00820c1b"
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
>| test_host | ff0d466b-9d7f-46e1-8a31-a54e00820c1b | host |
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
```!checkpoint-host-get identifier=test_host```

#### Context Example
```
{
    "CheckPoint": {
        "host": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": [
                {
                    "name": "test_group",
                    "uid": "e50aecdd-94a6-43bd-bc79-3ea575b7f36b"
                }
            ],
            "ipv4_address": "1.2.3.4",
            "ipv6_address": "1.2.3.4",
            "last_modifier": "adminsh",
            "name": "test_host",
            "read_only": false,
            "type": "host",
            "uid": "ff0d466b-9d7f-46e1-8a31-a54e00820c1b"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting host:
>|creator|domain-name|domain-uid|ipv4_address|ipv6_address|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | 1.2.3.4 | 1.2.3.4 | adminsh | test_host | false | host | ff0d466b-9d7f-46e1-8a31-a54e00820c1b |
>### CheckPoint data for host groups:
>|name|uid|
>|---|---|
>| test_group | e50aecdd-94a6-43bd-bc79-3ea575b7f36b |


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
```!checkpoint-host-add name=host_test ip_address=8.8.8.8```

#### Human Readable Output



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
```!checkpoint-host-update identifier=test_host```

#### Context Example
```
{
    "CheckPoint": {
        "host": {
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": "test_group",
            "ipv4-address": "1.2.3.4",
            "ipv6-address": "1.2.3.4",
            "name": "test_host",
            "total-number": null,
            "type": "host",
            "uid": "ff0d466b-9d7f-46e1-8a31-a54e00820c1b"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating host:
>|domain-name|domain-uid|groups|ipv4-address|ipv6-address|name|type|uid|
>|---|---|---|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | test_group | 1.2.3.4 | 1.2.3.4 | test_host | host | ff0d466b-9d7f-46e1-8a31-a54e00820c1b |


### checkpoint-host-delete
***
delete host


#### Base Command

`checkpoint-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.message | String | operation status | 


#### Command Example
```!checkpoint-host-delete identifier=test_host```

#### Human Readable Output



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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object's name | 
| CheckPoint.group.uid | String | object's uid | 
| CheckPoint.group.type | String | Type of the object | 


#### Command Example
```!checkpoint-group-list```

#### Context Example
```
{
    "CheckPoint": {
        "group": [
            {
                "name": "test1",
                "type": "group",
                "uid": "67e93a2b-c7d4-44a2-9313-6e48f664c19a"
            },
            {
                "name": "test_group",
                "type": "group",
                "uid": "e50aecdd-94a6-43bd-bc79-3ea575b7f36b"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing groups:
>|name|uid|type|
>|---|---|---|
>| test1 | 67e93a2b-c7d4-44a2-9313-6e48f664c19a | group |
>| test_group | e50aecdd-94a6-43bd-bc79-3ea575b7f36b | group |


### checkpoint-group-get
***
Get all data of a given group


#### Base Command

`checkpoint-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object uid or name | Required | 


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
```!checkpoint-group-get identifier=test_group```

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
```!checkpoint-group-add name=test_group_2```

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


#### Command Example
```!checkpoint-group-update identifier=test_group```

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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.message | String | Operation massege | 


#### Command Example
```!checkpoint-group-delete identifier=test_group```

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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | Object's name | 
| CheckPoint.address-range.uid | String | Object's uid | 
| CheckPoint.address-range.type | String | Type of the object. | 


#### Command Example
```!checkpoint-address-range-list ```

#### Context Example
```
{
    "CheckPoint": {
        "address-range": [
            {
                "name": "address_range_test",
                "type": "address-range",
                "uid": "c62e1e64-3119-4b74-989a-6ef6e67d6070"
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
>| address_range_test | c62e1e64-3119-4b74-989a-6ef6e67d6070 | address-range |
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
```!checkpoint-address-range-add name=address_range_test_2 ip_address_first=8.8.8.8 ip_address_last=9.9.9.9```

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
```!checkpoint-address-range-update identifier=address_range_test layer=Network```

#### Human Readable Output



### checkpoint-address-range-delete
***
Delete a given address range


#### Base Command

`checkpoint-address-range-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.message | String | Operation status | 


#### Command Example
```!checkpoint-address-range-delete identifier=address_range_test```

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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 


#### Command Example
```!checkpoint-threat-indicator-list```

#### Context Example
```
{
    "CheckPoint": {
        "threat-indicator": {
            "name": "Threat_test1",
            "type": "threat-indicator",
            "uid": "3746e4e0-2432-4646-894d-2fece93d5e94"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for listing threat-indicators:
>|name|uid|type|
>|---|---|---|
>| Threat_test1 | 3746e4e0-2432-4646-894d-2fece93d5e94 | threat-indicator |


### checkpoint-threat-indicator-get
***
Get data for a given list indicator


#### Base Command

`checkpoint-threat-indicator-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object uid or name | Required | 


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
```!checkpoint-threat-indicator-get identifier=Threat_test1```

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
            "name": "Threat_test1",
            "read_only": false,
            "type": "threat-indicator",
            "uid": "3746e4e0-2432-4646-894d-2fece93d5e94"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting threat-indicator:
>|creator|domain-name|domain-uid|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | Threat_test1 | false | threat-indicator | 3746e4e0-2432-4646-894d-2fece93d5e94 |


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.task-id | String | Asynchronous task unique identifier. | 


#### Command Example
```!checkpoint-threat-indicator-add name=threat_test2 observables=observables```

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
```!checkpoint-threat-indicator-update identifier=Threat_test1```

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
            "name": "Threat_test1",
            "total-number": null,
            "type": "threat-indicator",
            "uid": "3746e4e0-2432-4646-894d-2fece93d5e94"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint Data for updating threat-indicator:
>|domain-name|domain-uid|name|type|uid|
>|---|---|---|---|---|
>| SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | Threat_test1 | threat-indicator | 3746e4e0-2432-4646-894d-2fece93d5e94 |


### checkpoint-address-range-get
***
Get all date of a given address range object


#### Base Command

`checkpoint-address-range-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 


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
```!checkpoint-address-range-get identifier=address_range_test```

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
            "uid": "c62e1e64-3119-4b74-989a-6ef6e67d6070"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for getting address-range:
>|creator|domain-name|domain-uid|last_modifier|name|read_only|type|uid|
>|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | address_range_test | false | address-range | c62e1e64-3119-4b74-989a-6ef6e67d6070 |


### checkpoint-threat-indicator-delete
***
delete threat indicator


#### Base Command

`checkpoint-threat-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.message | String | Operation status | 


#### Command Example
```!checkpoint-threat-indicator-delete identifier=Threat_test1```

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
Shows the entire Access Rules layer


#### Base Command

`checkpoint-access-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 


#### Command Example
```!checkpoint-access-rule-list identifier=test_access_rule```

#### Human Readable Output



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
```!checkpoint-access-rule-add name=test_access_rule_2 layer=Network position=top```

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
            "name": "test_access_rule_2",
            "type": "access-rule",
            "uid": "66055287-7d13-46de-9287-3ef19fabec38"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding access-rule:
>|creator|domain-name|domain-uid|enabled|last_modifier|layer|name|type|uid|
>|---|---|---|---|---|---|---|---|---|
>| adminsh | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | true | adminsh | c0264a80-1832-4fce-8a90-d0849dc4ba33 | test_access_rule_2 | access-rule | 66055287-7d13-46de-9287-3ef19fabec38 |


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
```!checkpoint-access-rule-update identifier=test_access_rule layer=Network```

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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.message | String | Operation status | 


#### Command Example
```!checkpoint-access-rule-delete identifier=test_access_rule```

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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | objects name | 
| CheckPoint.application-site.uid | String | objects uid | 
| CheckPoint.application-site.type | String | objects type | 


#### Command Example
```!checkpoint-application-site-list limit=5```

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
It's impossible to set 'application-signature' when the application was initialized with 'url-list' and vice-verse.


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
```!checkpoint-application-site-update identifier=test_application_site```

#### Human Readable Output



### checkpoint-application-site-delete
***
Delete existing application site object using object name or uid.


#### Base Command

`checkpoint-application-site-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.message | String | Operation status. | 


#### Command Example
```!checkpoint-application-site-delete name=test_application_site```

#### Human Readable Output



### checkpoint-publish
***
publish changes


#### Base Command

`checkpoint-publish`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!checkpoint-publish```

#### Context Example
```
{
    "CheckPoint": {
        "publish": {
            "task-id": "01234567-89ab-cdef-9651-76f9fecda483"
        }
    }
}
```

#### Human Readable Output

>Integration log: {'tasks': [{'task-id': '01234567-89ab-cdef-9651-76f9fecda483', 'task-name': 'Publish operation', 'status': 'in progress', 'progress-percentage': 10, 'suppressed': False}]}Integration log: {'tasks': [{'task-id': '01234567-89ab-cdef-9651-76f9fecda483', 'task-name': 'Publish operation', 'status': 'succeeded', 'progress-percentage': 100, 'suppressed': False, 'task-details': [{'publishResponse': {'numberOfPublishedChanges': 4, 'mode': 'async'}, 'revision': '7997756b-6ad0-4fef-a08a-520941b47f85'}]}]}### CheckPoint data for publish:
>|task-id|
>|---|
>| 01234567-89ab-cdef-9651-76f9fecda483 |


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.instal-policy.task-id | String | Operation task ID. | 


#### Command Example
```!checkpoint-install-policy policy_package=standard targets=LAN-TEST```

#### Human Readable Output



### checkpoint-verify-policy
***
Verifies the policy of the selected package.


#### Base Command

`checkpoint-verify-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_package | The name of the Policy Package to be installed. | Required | 


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.show-task.task-id | String | Task ID | 
| CheckPoint.show-task.task-name | String | Task name | 
| CheckPoint.show-task.status | String | Task status | 
| CheckPoint.show-task.progress-percentage | Unknown | Task prograss in percentage | 
| CheckPoint.show-task.suppressed | Boolean | Indicates if the task is suppressed | 


#### Command Example
```!checkpoint-show-task task_id=01234567-89ab-cdef-8462-535e125c3879```

#### Context Example
```
{
    "CheckPoint": {
        "show-task": {
            "progress-percentage": 100,
            "status": "succeeded",
            "suppressed": false,
            "task-id": "01234567-89ab-cdef-8462-535e125c3879",
            "task-name": "Publish operation"
        }
    }
}
```

#### Human Readable Output

>Integration log: {'tasks': [{'task-id': '01234567-89ab-cdef-8462-535e125c3879', 'task-name': 'Publish operation', 'status': 'succeeded', 'progress-percentage': 100, 'suppressed': False, 'task-details': [{'publishResponse': {'numberOfPublishedChanges': 6, 'mode': 'async'}, 'revision': '7b5e1869-b35e-4d7e-93fa-895c351b9974'}]}]}### CheckPoint data for listing tasks:
>|task-name|task-id|status|suppressed|progress-percentage|
>|---|---|---|---|---|
>| Publish operation | 01234567-89ab-cdef-8462-535e125c3879 | succeeded | false | 100 |

