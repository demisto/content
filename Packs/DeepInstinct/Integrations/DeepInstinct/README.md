## Overview
---

Deep Instinct
This integration was integrated and tested with version xx of Deep Instinct
## Deep Instinct Playbook
---

## Use Cases
---

## Configure Deep Instinct on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Deep Instinct.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __base server url__
    * __api key__
    * __Fetch incidents__
    * __Incident type__
    * __first event id to fetch from__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. di-get-device
2. di-hash-to-bl
3. di-hash-to-wl
4. di-add-devices-to-group
5. di-remove-devices-from-group
6. di-delete-files-remotely
7. di-terminate-processes
8. di-close-events
### 1. di-get-device
---
get specific device by id
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-get-device`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.id | number | Device id | 
| DeepInstinct.os | string | Device OS | 
| DeepInstinct.osv | string | Device OS version | 
| DeepInstinct.ip_address | string | Device IP address | 
| DeepInstinct.mac_address | string | Device mac address | 
| DeepInstinct.hostname | string | Device hostname | 
| DeepInstinct.domain | string | Device domain | 
| DeepInstinct.scanned_files | number | Num of device scanned files | 
| DeepInstinct.tag | string | Device tag | 
| DeepInstinct.connectivity_status | string | Device connectivity status | 
| DeepInstinct.deployment_status | string | Device deployment status | 
| DeepInstinct.last_registration | string | Device last registration datetime | 
| DeepInstinct.last_contact | string | Device last contact datetime | 
| DeepInstinct.distinguished_name | string | Device distinguished name | 
| DeepInstinct.group_name | string | Device group name | 
| DeepInstinct.group_id | number | Device group id | 
| DeepInstinct.policy_name | string | Device policy name | 
| DeepInstinct.policy_id | number | Device policy id | 
| DeepInstinct.log_status | string | Device log status | 
| DeepInstinct.agent_version | string | Device agent version | 
| DeepInstinct.brain_version | string | Device brain version | 
| DeepInstinct.msp_name | string | Device msp name | 
| DeepInstinct.msp_id | number | Device msp id | 
| DeepInstinct.tenant_name | string | Device tenant name | 
| DeepInstinct.tenant_id | number | Device tenant id | 


##### Command Example
```!di-get-device device_id=1```

##### Context Example
```
{
    "DeepInstinct.Devices": {
        "last_registration": "2020-04-09T14:49:39.722292Z", 
        "domain": "", 
        "msp_name": "MSP 1", 
        "distinguished_name": "OU=Organizations & Sites,DC=bancshares,DC=mib", 
        "tenant_name": "Tenant 1", 
        "osv": "Windows", 
        "tag": "", 
        "id": 1, 
        "last_contact": "2020-04-09T14:49:39.711487Z", 
        "hostname": "Mock_2020-04-09 17:49:39.408405_1", 
        "mac_address": "00:00:00:00:00:00", 
        "brain_version": "115wt", 
        "connectivity_status": "OFFLINE", 
        "deployment_status": "REGISTERED", 
        "msp_id": 1, 
        "group_name": "Windows Default Group", 
        "ip_address": "192.168.88.80", 
        "log_status": "NA", 
        "tenant_id": 1, 
        "agent_version": "2.3.1.12", 
        "scanned_files": 0, 
        "policy_name": "Windows Default Policy", 
        "group_id": 3, 
        "os": "WINDOWS", 
        "policy_id": 3
    }
}
```

##### Human Readable Output
### Device
|agent_version|brain_version|connectivity_status|deployment_status|distinguished_name|domain|group_id|group_name|hostname|id|ip_address|last_contact|last_registration|log_status|mac_address|msp_id|msp_name|os|osv|policy_id|policy_name|scanned_files|tag|tenant_id|tenant_name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.3.1.12 | 115wt | OFFLINE | REGISTERED | OU=Organizations & Sites,DC=bancshares,DC=mib |  | 3 | Windows Default Group | Mock_2020-04-09 17:49:39.408405_1 | 1 | 192.168.88.80 | 2020-04-09T14:49:39.711487Z | 2020-04-09T14:49:39.722292Z | NA | 00:00:00:00:00:00 | 1 | MSP 1 | WINDOWS | Windows | 3 | Windows Default Policy | 0 |  | 1 | Tenant 1 |


### 2. di-hash-to-bl
---
add file hash to blacklist
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-hash-to-bl`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy id | Required | 
| file_hash | file hash | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-hash-to-bl file_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb policy_id=6```

##### Human Readable Output
ok

### 3. di-hash-to-wl
---
add file hash to whitelist
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-hash-to-wl`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy id | Required | 
| file_hash | file hash | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-hash-to-wl file_hash=wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww policy_id=6```

##### Human Readable Output
ok

### 4. di-add-devices-to-group
---
add multiple devices to group
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-add-devices-to-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group id | Required | 
| device_ids | comma separeted devices ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-add-devices-to-group device_ids=1 group_id=6```

##### Human Readable Output
ok

### 5. di-remove-devices-from-group
---
remove list of devices from group
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-remove-devices-from-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group id to remove from | Required | 
| device_ids | comma separeted list of device ids to remove | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-remove-devices-from-group device_ids=1 group_id=6```

##### Human Readable Output
ok

### 6. di-delete-files-remotely
---
delete multiple files remotely
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-delete-files-remotely`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separeted list of event ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-delete-files-remotely event_ids=1```

##### Human Readable Output
ok

### 7. di-terminate-processes
---
terminate list of processes
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-terminate-processes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separeted list of event ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-terminate-processes event_ids=1,2```

##### Human Readable Output
ok

### 8. di-close-events
---
close list of events
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`di-close-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separeted list of event ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!di-close-events event_ids=1```

##### Human Readable Output
ok

## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* message=s
