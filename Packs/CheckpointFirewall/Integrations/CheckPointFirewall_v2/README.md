## Overview
---

Integration Overview Manage Check Point Firewall. Read information and to send commands to the Check Point Firewall server. 
This integration was integrated and tested with version R80.30 of CheckPoint SmartConsole.

Product Name: Check Point Firewall  
Product Type: Network Security  
Product Version: R80.30  

### How to configure the integration:

In the Smart Console, enable the web api: **Management & Setting** → **Blades** → **Management API, Advanced Setting** → **All IP address**

Enable sftp on your server Check Point guide to walk you through: https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk82281 

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CheckPoint_FW.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. example.net or 8.8.8.8\) | True |
| port | Server Port \(e.g. 4434\) | True |
| username | username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.


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
| CheckPoint.Host.ipv4 | String | IP-v4 address of a spesific host | 


#### Command Example
```!checkpoint-host-list limit=5```

#### Context Example
```
{
    "CheckPoint": {
        "Host": [
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": "18.88.8.7",
                "last-modifier": null,
                "name": "18.88.8.7",
                "read-only": null,
                "type": "host",
                "uid": "f083d3ce-8e95-460f-a386-0bc4eca1214a"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": "18.88.8.8",
                "last-modifier": null,
                "name": "18.88.8.8",
                "read-only": null,
                "type": "host",
                "uid": "b032c0a7-096c-4b27-9a09-8d9437312135"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": "192.168.30.2",
                "last-modifier": null,
                "name": "192.168.30.2",
                "read-only": null,
                "type": "host",
                "uid": "5bd98c85-f848-45ab-aa4c-c729fb8b1723"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": "200.200.200.112",
                "last-modifier": null,
                "name": "200.200.200.112",
                "read-only": null,
                "type": "host",
                "uid": "23c4b2cf-0adc-4282-8f15-262cfec7f5f5"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": "192.192.10.10",
                "last-modifier": null,
                "name": "Demisto - 2096",
                "read-only": null,
                "type": "host",
                "uid": "cded0c90-3402-4766-ad1b-adaf972b254f"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all hosts:
>|name|uid|type|ipv4-address|
>|---|---|---|---|
>| 18.88.8.7 | f083d3ce-8e95-460f-a386-0bc4eca1214a | host | 18.88.8.7 |
>| 18.88.8.8 | b032c0a7-096c-4b27-9a09-8d9437312135 | host | 18.88.8.8 |
>| 192.168.30.2 | 5bd98c85-f848-45ab-aa4c-c729fb8b1723 | host | 192.168.30.2 |
>| 200.200.200.112 | 23c4b2cf-0adc-4282-8f15-262cfec7f5f5 | host | 200.200.200.112 |
>| Demisto - 2096 | cded0c90-3402-4766-ad1b-adaf972b254f | host | 192.192.10.10 |


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
            "groups": [],
            "ipv4-address": "1.1.1.1",
            "last-modifier": "adminsh",
            "name": "host_test",
            "read-only": false,
            "type": "host",
            "uid": "11c194c4-db5f-46de-a9e2-95b8e858b98f"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data of host object host_test:
>|name|uid|type|ipv4-address|domain-name|domain-uid|read-only|creator|last-modifier|
>|---|---|---|---|---|---|---|---|---|
>| host_test | 11c194c4-db5f-46de-a9e2-95b8e858b98f | host | 1.1.1.1 | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | false | adminsh | adminsh |


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
| groups | group identifier. | Optional | 
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
```!checkpoint-host-add name=test_host_1 ip_address=18.18.18.18 session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": [],
            "ipv4-address": "18.18.18.18",
            "ipv6-address": null,
            "last-modifier": "adminsh",
            "name": "test_host_1",
            "read-only": true,
            "type": "host",
            "uid": "7290f66a-fdd4-40fb-a639-774e3f387113"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding host:
>|name|uid|type|domain-name|domain-uid|creator|last-modifier|ipv4-address|read-only|
>|---|---|---|---|---|---|---|---|---|
>| test_host_1 | 7290f66a-fdd4-40fb-a639-774e3f387113 | host | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | adminsh | 18.18.18.18 | true |


### checkpoint-host-update
***
update host changes


#### Base Command

`checkpoint-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | Object unique identifier or name | Required | 
| ip_address | IPv4 or IPv6 address. | Optional | 
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
```!checkpoint-host-update identifier=host_test session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "comments": "",
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": "1.1.1.1",
            "last-modifier": "adminsh",
            "name": "host_test",
            "read-only": false,
            "type": "host",
            "uid": "11c194c4-db5f-46de-a9e2-95b8e858b98f"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for updating a host:
>|name|uid|type|domain-name|domain-uid|creator|ipv4-address|last-modifier|read-only|
>|---|---|---|---|---|---|---|---|---|
>| host_test | 11c194c4-db5f-46de-a9e2-95b8e858b98f | host | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | 1.1.1.1 | adminsh | false |


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
```!checkpoint-host-delete identifier=host_test session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "Host": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for deleting host_test:
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
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "bensar",
                "read-only": null,
                "type": "group",
                "uid": "fe26adc1-c0e1-4424-9a9e-f74f511a7f28"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "group10",
                "read-only": null,
                "type": "group",
                "uid": "cf069504-5ea5-4eb2-9b97-ccdc500db118"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "group9",
                "read-only": null,
                "type": "group",
                "uid": "c4635886-15c9-4416-8160-5c70d68462cd"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "group_test",
                "read-only": null,
                "type": "group",
                "uid": "35a46b01-47f5-496f-9329-d55c7d2ab083"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "Group_test_for_demisto",
                "read-only": null,
                "type": "group",
                "uid": "1deaead0-136c-4791-8d58-9229c143b8c5"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all groups:
>|name|uid|type|
>|---|---|---|
>| bensar | fe26adc1-c0e1-4424-9a9e-f74f511a7f28 | group |
>| group10 | cf069504-5ea5-4eb2-9b97-ccdc500db118 | group |
>| group9 | c4635886-15c9-4416-8160-5c70d68462cd | group |
>| group_test | 35a46b01-47f5-496f-9329-d55c7d2ab083 | group |
>| Group_test_for_demisto | 1deaead0-136c-4791-8d58-9229c143b8c5 | group |


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
```!checkpoint-group-get identifier=group_test```

#### Context Example
```
{
    "CheckPoint": {
        "Group": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": [],
            "ipv4-address": null,
            "last-modifier": "adminsh",
            "name": "group_test",
            "read-only": false,
            "type": "group",
            "uid": "35a46b01-47f5-496f-9329-d55c7d2ab083"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint for group_test group:
>|name|uid|type|domain-name|domain-uid|read-only|creator|last-modifier|
>|---|---|---|---|---|---|---|---|
>| group_test | 35a46b01-47f5-496f-9329-d55c7d2ab083 | group | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | false | adminsh | adminsh |


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
| CheckPoint.Group.read-only | Boolean | Indicates whether the object is read-only | 
| CheckPoint.Group.groups-name | Unknown | groups name | 


#### Command Example
```!checkpoint-group-add name=test_group_1 session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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
```!checkpoint-group-update identifier=group_test session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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
            "name": "group_test",
            "read-only": false,
            "type": "group",
            "uid": "35a46b01-47f5-496f-9329-d55c7d2ab083"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for updating a group:
>|name|uid|type|domain-name|domain-uid|creator|last-modifier|read-only|
>|---|---|---|---|---|---|---|---|
>| group_test | 35a46b01-47f5-496f-9329-d55c7d2ab083 | group | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | adminsh | false |


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
```!checkpoint-group-delete identifier=group_test session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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

>### CheckPoint data for deleting group_test:
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
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "address_range_1",
                "read-only": null,
                "type": "address-range",
                "uid": "d4543195-8744-4592-906e-1cdcd534a564"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "address_range_test",
                "read-only": null,
                "type": "address-range",
                "uid": "26887214-d639-4acd-ab48-508d900cdfc2"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "address_range_test_1",
                "read-only": null,
                "type": "address-range",
                "uid": "46800cfe-e3ff-4101-867c-27772ade9d72"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "All_Internet",
                "read-only": null,
                "type": "address-range",
                "uid": "f90e0a2b-f166-427a-b47f-a107b6fe43b9"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "LocalMachine_Loopback",
                "read-only": null,
                "type": "address-range",
                "uid": "5d3b2752-4072-41e1-9aa0-488813b02a40"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all address ranges:
>|name|uid|type|
>|---|---|---|
>| address_range_1 | d4543195-8744-4592-906e-1cdcd534a564 | address-range |
>| address_range_test | 26887214-d639-4acd-ab48-508d900cdfc2 | address-range |
>| address_range_test_1 | 46800cfe-e3ff-4101-867c-27772ade9d72 | address-range |
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
| groups | Collection of group identifiers.  | Optional | 


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
| CheckPoint.AddressRange.read-only | Boolean | Indicates whether the object is read-only. | 
| CheckPoint.AddressRange.creator | String | Indicates the creator of the object | 
| CheckPoint.AddressRange.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.AddressRange.groups | String | Name of the group object | 


#### Command Example
```!checkpoint-address-range-add name=address_range_test_2 ip_address_first=8.8.8.8 ip_address_last=9.9.9.9 session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address-first": "8.8.8.8",
            "ipv4-address-last": "9.9.9.9",
            "ipv6-address-first": "",
            "ipv6-address-last": "",
            "last-modifier": "adminsh",
            "name": "address_range_test_2",
            "read-only": true,
            "type": "address-range",
            "uid": "4fb8174d-89db-42f8-88b8-525c8fe818be"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding an address range:
>|name|uid|type|domain-name|domain-uid|creator|ipv4-address-first|ipv4-address-last|last-modifier|read-only|
>|---|---|---|---|---|---|---|---|---|---|
>| address_range_test_2 | 4fb8174d-89db-42f8-88b8-525c8fe818be | address-range | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | 8.8.8.8 | 9.9.9.9 | adminsh | true |


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
| CheckPoint.AddressRange.read-only | Boolean | Indicates whether the object is read-only. | 
| CheckPoint.AddressRange.groups | String | List of all groups the address range is linked to | 


#### Command Example
```!checkpoint-address-range-update identifier=address_range_test layer=Network session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "AddressRange": {
            "comments": "",
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "last-modifier": "adminsh",
            "name": "address_range_test",
            "read-only": false,
            "type": "address-range",
            "uid": "26887214-d639-4acd-ab48-508d900cdfc2"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for updating an address range:
>|name|uid|type|domain-name|domain-uid|creator|last-modifier|read-only|
>|---|---|---|---|---|---|---|---|
>| address_range_test | 26887214-d639-4acd-ab48-508d900cdfc2 | address-range | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | adminsh | false |


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
```!checkpoint-address-range-delete identifier=address_range_test session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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

>### CheckPoint data for deleting address range:
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
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "My_Indicator!",
                "read-only": null,
                "type": "threat-indicator",
                "uid": "a40ec97c-e286-474b-bff7-b922e3b3294d"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "test_indicator",
                "read-only": null,
                "type": "threat-indicator",
                "uid": "3e6a22c0-0416-4a2d-b7c0-f81df12916e1"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "threat_test_1",
                "read-only": null,
                "type": "threat-indicator",
                "uid": "88e502f1-2bd5-4ad4-ba6b-dbbb2fef8260"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "threat_test_2",
                "read-only": null,
                "type": "threat-indicator",
                "uid": "f34c89f1-b18f-4cf2-b2bb-672462178b9d"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "threat_test_3",
                "read-only": null,
                "type": "threat-indicator",
                "uid": "ee17772c-94aa-4e42-93e4-f0ba49de339b"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all threat indicators:
>|name|uid|type|
>|---|---|---|
>| My_Indicator! | a40ec97c-e286-474b-bff7-b922e3b3294d | threat-indicator |
>| test_indicator | 3e6a22c0-0416-4a2d-b7c0-f81df12916e1 | threat-indicator |
>| threat_test_1 | 88e502f1-2bd5-4ad4-ba6b-dbbb2fef8260 | threat-indicator |
>| threat_test_2 | f34c89f1-b18f-4cf2-b2bb-672462178b9d | threat-indicator |
>| threat_test_3 | ee17772c-94aa-4e42-93e4-f0ba49de339b | threat-indicator |


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
| CheckPoint.ThreatIndicator.read-only | Boolean | Indicates whether the object is read-only. | 


#### Command Example
```!checkpoint-threat-indicator-get identifier=threat_test_1```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": {
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": null,
            "ipv4-address": null,
            "last-modifier": "adminsh",
            "name": "threat_test_1",
            "number-of-observables": 1,
            "read-only": false,
            "type": "threat-indicator",
            "uid": "88e502f1-2bd5-4ad4-ba6b-dbbb2fef8260"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for threat_test_1 threat indicator:
>|name|uid|type|domain-name|domain-uid|read-only|creator|last-modifier|number-of-observables|
>|---|---|---|---|---|---|---|---|---|
>| threat_test_1 | 88e502f1-2bd5-4ad4-ba6b-dbbb2fef8260 | threat-indicator | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | false | adminsh | adminsh | 1 |


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
```!checkpoint-threat-indicator-add name=threat_test2 observables=[] session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew ```

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
| session_id | Execute command with a specific session ID | Required | 


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
| CheckPoint.ThreatIndicator.read-only | Boolean | Indicates whether the object is read-only. | 


#### Command Example
```!checkpoint-threat-indicator-update identifier=threat_test_1 session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "ThreatIndicator": {
            "comments": "",
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "ipv4-address": null,
            "last-modifier": "adminsh",
            "name": "threat_test_1",
            "read-only": false,
            "type": "threat-indicator",
            "uid": "88e502f1-2bd5-4ad4-ba6b-dbbb2fef8260"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for update threat_test_1 threat indicator
>|name|uid|type|domain-name|domain-uid|creator|last-modifier|read-only|
>|---|---|---|---|---|---|---|---|
>| threat_test_1 | 88e502f1-2bd5-4ad4-ba6b-dbbb2fef8260 | threat-indicator | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | adminsh | false |


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
            "groups": [],
            "ipv4-address": null,
            "last-modifier": "adminsh",
            "name": "address_range_test",
            "read-only": false,
            "type": "address-range",
            "uid": "26887214-d639-4acd-ab48-508d900cdfc2"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for address_range_test address range:
>|name|uid|type|domain-name|domain-uid|read-only|creator|last-modifier|
>|---|---|---|---|---|---|---|---|
>| address_range_test | 26887214-d639-4acd-ab48-508d900cdfc2 | address-range | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | false | adminsh | adminsh |


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
```!checkpoint-threat-indicator-delete identifier=threat_test_1 session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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

>### CheckPoint status for deleting threat_test_1threat indicator:
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
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": null,
                "read-only": null,
                "type": "access-rule",
                "uid": "6521b7b9-d340-44ec-a104-17d5ea669bc0"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": null,
                "read-only": null,
                "type": "access-rule",
                "uid": "bb6016e3-36e8-4214-b17f-89623160dd10"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "test_access_rule_8",
                "read-only": null,
                "type": "access-rule",
                "uid": "0c71cc44-a5ad-43cd-9af0-79e5f153f62f"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "None",
                "read-only": null,
                "type": "access-rule",
                "uid": "c44add02-0f02-4b29-8ab3-d5ac687d31f7"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "est_access_rule",
                "read-only": null,
                "type": "access-rule",
                "uid": "e5bc5918-7155-493e-89ce-5562586d3acc"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all access rule bases:
>|name|uid|type|
>|---|---|---|
>|  | 6521b7b9-d340-44ec-a104-17d5ea669bc0 | access-rule |
>|  | bb6016e3-36e8-4214-b17f-89623160dd10 | access-rule |
>| test_access_rule_8 | 0c71cc44-a5ad-43cd-9af0-79e5f153f62f | access-rule |
>| None | c44add02-0f02-4b29-8ab3-d5ac687d31f7 | access-rule |
>| est_access_rule | e5bc5918-7155-493e-89ce-5562586d3acc | access-rule |


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
```!checkpoint-access-rule-add name=test_access_rule layer=Network position=top session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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
            "name": "test_access_rule",
            "type": "access-rule",
            "uid": "a9f00b65-bb3b-4548-b06a-6c5672df6c8b"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding access rule:
>|name|uid|type|domain-name|domain-uid|enabled|layer|creator|last-modifier|
>|---|---|---|---|---|---|---|---|---|
>| test_access_rule | a9f00b65-bb3b-4548-b06a-6c5672df6c8b | access-rule | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | true | c0264a80-1832-4fce-8a90-d0849dc4ba33 | adminsh | adminsh |


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
```!checkpoint-access-rule-update identifier=7867e584-0e68-42b4-ba18-2dd16cdbd436 layer=Network session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "AccessRule": {
            "action-name": "Drop",
            "action-type": "RulebaseAction",
            "action-uid": "6c488338-8eec-4103-ad21-cd461ac2c473",
            "content-direction": "any",
            "creator": "adminsh",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "enabled": true,
            "last-modifier": "adminsh",
            "name": "None",
            "type": "access-rule",
            "uid": "7867e584-0e68-42b4-ba18-2dd16cdbd436"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for updating an access rule:
>|name|uid|type|domain-name|domain-uid|action-name|action-uid|action-type|content-direction|creator|enabled|last-modifier|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| None | 7867e584-0e68-42b4-ba18-2dd16cdbd436 | access-rule | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | Drop | 6c488338-8eec-4103-ad21-cd461ac2c473 | RulebaseAction | any | adminsh | true | adminsh |


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
```!checkpoint-access-rule-delete identifier=7867e584-0e68-42b4-ba18-2dd16cdbd436 layer=Network session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "AccessRule": {
            "message": "OK"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for deleting access rule range: 7867e584-0e68-42b4-ba18-2dd16cdbd436
>|message|
>|---|
>| OK |


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
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "#hashtags",
                "read-only": null,
                "type": "application-site",
                "uid": "00fa9e3c-36ef-0f65-e053-08241dc22da2"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "050 Plus",
                "read-only": null,
                "type": "application-site",
                "uid": "00fa9e44-4035-0f65-e053-08241dc22da2"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "0test_application_site_10",
                "read-only": null,
                "type": "application-site",
                "uid": "446cff2c-7e1f-4dbc-a943-66740e890d67"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "1000keyboards",
                "read-only": null,
                "type": "application-site",
                "uid": "00fa9e3d-a077-0f65-e053-08241dc22da2"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "1000memories",
                "read-only": null,
                "type": "application-site",
                "uid": "00fa9e43-56d7-0f65-e053-08241dc22da2"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all access rule bases:
>|name|uid|type|
>|---|---|---|
>| #hashtags | 00fa9e3c-36ef-0f65-e053-08241dc22da2 | application-site |
>| 050 Plus | 00fa9e44-4035-0f65-e053-08241dc22da2 | application-site |
>| 0test_application_site_10 | 446cff2c-7e1f-4dbc-a943-66740e890d67 | application-site |
>| 1000keyboards | 00fa9e3d-a077-0f65-e053-08241dc22da2 | application-site |
>| 1000memories | 00fa9e43-56d7-0f65-e053-08241dc22da2 | application-site |


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
### CheckPoint data for adding application site:
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
| url_list | URLs that determine this particular application. This will replace the current url collection. | Optional | 
| url_list_to_add | Adds to collection of values. | Optional | 
| url_list_to_remove | Removes from collection of values. | Optional | 
| groups | Collection of group identifiers. Can be a single group or a list of groups. | Optional | 
| session_id | Execute command with a specific session ID | Required | 


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
| CheckPoint.ApplicationSite.primary-category | String | Objects primary category. | 


#### Command Example
```!checkpoint-application-site-update identifier=test_application_site session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSite": {
            "application-id": 1073741861,
            "description": "",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": [],
            "name": "test_application_site",
            "primary-category": "Test Category",
            "type": "application-site",
            "uid": "ccc788d1-b798-4e5c-8530-a6c375853730",
            "url-list": [
                "qmasters.co"
            ]
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for updating an application site:
>|name|uid|type|application-id|primary-category|url-list|domain-name|domain-uid|
>|---|---|---|---|---|---|---|---|
>| test_application_site | ccc788d1-b798-4e5c-8530-a6c375853730 | application-site | 1073741861 | Test Category | qmasters.co | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde |


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
```!checkpoint-application-site-delete identifier=test_application_site session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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

>### CheckPoint data for deleting application site : test_application_site
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
```!checkpoint-publish session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "Publish": {
            "task-id": "01234567-89ab-cdef-9338-e44df5384ac3"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for publishing current session:
>|task-id|
>|---|
>| 01234567-89ab-cdef-9338-e44df5384ac3 |


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
```!checkpoint-install-policy policy_package=standard targets=test-gw session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "InstallPolicy": {
            "task-id": "d461078b-cc1e-41b6-869b-096438673323"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for installing policy:
>|task-id|
>|---|
>| d461078b-cc1e-41b6-869b-096438673323 |


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
```!checkpoint-policy-verify policy_package=standard session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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
```!checkpoint-show-task task_id=01234567-89ab-cdef-997f-2e3e3b4b2541```

#### Context Example
```
{
    "CheckPoint": {
        "ShowTask": {
            "progress-percentage": 100,
            "status": "succeeded",
            "suppressed": false,
            "task-id": "01234567-89ab-cdef-997f-2e3e3b4b2541",
            "task-name": "Publish operation"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for tasks:
>|task-name|task-id|status|suppressed|progress-percentage|
>|---|---|---|---|---|
>| Publish operation | 01234567-89ab-cdef-997f-2e3e3b4b2541 | succeeded | false | 100 |


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
```!checkpoint-login-and-get-session-id```

#### Context Example
```
{
    "CheckPoint": {
        "Login": {
            "session-id": "LoUhF29pRkJsBiIWlMdBFy1LhHWXzE0VJT_lWpz4v0k"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint session data:
>|session-id|
>|---|
>| LoUhF29pRkJsBiIWlMdBFy1LhHWXzE0VJT_lWpz4v0k |


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
```!checkpoint-logout session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

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
```!checkpoint-packages-list session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "Packages": [
            {
                "name": "BenLayer",
                "type": "package",
                "uid": "9daac370-ad2d-4a21-a503-a312755aceaf"
            },
            {
                "name": "Standard",
                "type": "package",
                "uid": "ca4e32a8-bee0-423c-84f0-19bab6751d5e"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all packages:
>|name|uid|type|
>|---|---|---|
>| BenLayer | 9daac370-ad2d-4a21-a503-a312755aceaf | package |
>| Standard | ca4e32a8-bee0-423c-84f0-19bab6751d5e | package |


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
```!checkpoint-gateways-list session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "Gateways": [
            {
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

>### CheckPoint data for all gateways:
>|name|uid|type|version|network-security-blades|management-blades|
>|---|---|---|---|---|---|
>| gw-88a290 | 98bee60f-23ab-bf41-ba29-4c574b9d6f7c | CpmiHostCkp | R80.30 |  | network-policy-management: true<br/>logging-and-status: true |
>| test-gw | 3b83b6cb-d3cb-4596-8d90-ba9735d7d53c | simple-gateway | R80.30 | firewall: true |  |


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
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "0new_app_site_category",
                "read-only": null,
                "type": "application-site-category",
                "uid": "d42e14e7-1c50-48d5-9412-2306dc8e5219"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "0new_category_1",
                "read-only": null,
                "type": "application-site-category",
                "uid": "13e91cb3-1025-41a5-8203-89e28102f82f"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "0new_category_2",
                "read-only": null,
                "type": "application-site-category",
                "uid": "f49849de-9132-479d-b73a-56696976c235"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "0new_category_3",
                "read-only": null,
                "type": "application-site-category",
                "uid": "51ebf347-290f-4d8c-b99d-7aba73a5698c"
            },
            {
                "creator": null,
                "domain-name": null,
                "domain-uid": null,
                "groups": null,
                "ipv4-address": null,
                "last-modifier": null,
                "name": "0new_category_4",
                "read-only": null,
                "type": "application-site-category",
                "uid": "6b996605-099c-41fa-a4c6-1733ff895bac"
            }
        ]
    }
}
```

#### Human Readable Output

>### CheckPoint data for all application site category:
>|name|uid|type|
>|---|---|---|
>| 0new_app_site_category | d42e14e7-1c50-48d5-9412-2306dc8e5219 | application-site-category |
>| 0new_category_1 | 13e91cb3-1025-41a5-8203-89e28102f82f | application-site-category |
>| 0new_category_2 | f49849de-9132-479d-b73a-56696976c235 | application-site-category |
>| 0new_category_3 | 51ebf347-290f-4d8c-b99d-7aba73a5698c | application-site-category |
>| 0new_category_4 | 6b996605-099c-41fa-a4c6-1733ff895bac | application-site-category |


### checkpoint-application-site-category-add
***
Add new application site category


#### Base Command

`checkpoint-application-site-category-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | Object name or uid. Must be unique in the domain. | Required | 
| groups | Collection of group identifiers. | Optional | 
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
```!checkpoint-application-site-category-add identifier=application_site_category_0101 session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```

#### Context Example
```
{
    "CheckPoint": {
        "ApplicationSite": {
            "application-id": null,
            "creator": "adminsh",
            "description": "",
            "domain-name": "SMC User",
            "domain-type": null,
            "domain-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde",
            "groups": [],
            "last-modifier": "adminsh",
            "name": "application_site_category_0101",
            "type": "application-site-category",
            "uid": "5fb2e946-7e9c-42db-8b0a-cf5056f427d8",
            "url-list": null
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for adding application site category application_site_category_0101:
>|name|uid|type|domain-name|domain-uid|creator|last-modifier|
>|---|---|---|---|---|---|---|
>| application_site_category_0101 | 5fb2e946-7e9c-42db-8b0a-cf5056f427d8 | application-site-category | SMC User | 41e821a0-3720-11e3-aa6e-0800200c9fde | adminsh | adminsh |


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
            "groups": [],
            "ipv4-address": null,
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

>### CheckPoint data for adding application site category:
>|name|uid|type|domain-name|domain-uid|read-only|creator|last-modifier|
>|---|---|---|---|---|---|---|---|
>| Alcohol | 00fa9e44-409e-0f65-e053-08241dc22da2 | application-site-category | APPI Data | 8bf4ac51-2df7-40e1-9bce-bedbedbedbed | false | System | System |


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
| CheckPoint.Object.ipv4 | String | IP-v4 address of a spesific object | 


#### Command Example
```!checkpoint-show-objects limit=3 filter_search=1.2.3.4 ip_only=true```

#### Context Example
```
{
    "CheckPoint": {
        "Objects": {
            "creator": null,
            "domain-name": null,
            "domain-uid": null,
            "groups": null,
            "ipv4-address": null,
            "last-modifier": null,
            "name": "All_Internet",
            "read-only": null,
            "type": "address-range",
            "uid": "f90e0a2b-f166-427a-b47f-a107b6fe43b9"
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for objects:
>|name|uid|type|
>|---|---|---|
>| All_Internet | f90e0a2b-f166-427a-b47f-a107b6fe43b9 | address-range |


### checkpoint-package-list
***
Get checkpoint-packages details.


#### Base Command

`checkpoint-package-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | Object unique identifier or name. | Required | 
| session_id | Execute command with a specific session ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.Package.name | String | The name of the package. |
| CheckPoint.Package.target-name | String | The name of the targe. |
| CheckPoint.Package.target-uid | String | The UID of the target. |
| CheckPoint.Package.revision.domain.domain-type | String | The type of the domain. |
| CheckPoint.Package.revision.domain.name | String | The name of the domain. |
| CheckPoint.Package.revision.domain.uid | String | The UID of the domain. |
| CheckPoint.Package.revision.type | String | The type of the revision. |
| CheckPoint.Package.revision.uid | String | The UID of the revision. |


#### Command Example
```!checkpoint-package-list identifier=Standard session_id=GFcJQ9N-Zv8eG33qc4WQ7d4zmdsNvK_l3GcnOUqo8ew```


#### Context Example
```
{
    "CheckPoint": {
        "Package": {
            "name": "Standard",
            "target-name": "Host1",
            "target-uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"
            "revision": {
                "domain": {
                    "name": "test",
                    "domain-type": "domain",
                    "uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"
                },
                "type": "session",
                "uid", "41e821a0-3720-11e3-aa6e-0800200c9fde"
            }
        }
    }
}
```

#### Human Readable Output

>### CheckPoint data for objects:
>|target-name|name|target-uid|revision
>|---|---|---|---|
>| Host1 | Standard | 41e821a0-3720-11e3-aa6e-0800200c9fde | "domain": {<br/>"name": "test",<br/>"domain-type": "domain",<br/>"uid": "41e821a0-3720-11e3-aa6e-0800200c9fde"<br/>},<br/>"type": "session",<br/>"uid", "41e821a0-3720-11e3-aa6e-0800200c9fde"<br/> |

