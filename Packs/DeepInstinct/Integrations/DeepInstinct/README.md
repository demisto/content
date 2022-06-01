## Overview
---

Deep Instinct
This integration was integrated and tested with version 2.3.1.17 of Deep Instinct


## Configure Deep Instinct on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Deep Instinct.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Base server URL__
    * __API Key__
    * __Fetch incidents__
    * __Incident type__
    * __First event ID to fetch from__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. deepinstinct-get-device
2. deepinstinct-get-events
3. deepinstinct-get-all-groups
4. deepinstinct-get-all-policies
5. deepinstinct-add-hash-to-blacklist
6. deepinstinct-add-hash-to-whitelist
7. deepinstinct-remove-hash-from-blacklist
8. deepinstinct-remove-hash-from-whitelist
9. deepinstinct-add-devices-to-group
10. deepinstinct-remove-devices-from-group
11. deepinstinct-delete-files-remotely
12. deepinstinct-terminate-processes
13. deepinstinct-close-events
### 1. deepinstinct-get-device
---
get specific device by ID
##### Base Command

`deepinstinct-get-device`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.devices.ID | number | Device ID | 
| DeepInstinct.devices.os | string | Device OS | 
| DeepInstinct.devices.osv | string | Device OS version | 
| DeepInstinct.devices.ip_address | string | Device IP address | 
| DeepInstinct.devices.mac_address | string | Device mac address | 
| DeepInstinct.devices.hostname | string | Device hostname | 
| DeepInstinct.devices.domain | string | Device domain | 
| DeepInstinct.devices.scanned_files | number | Num of device scanned files | 
| DeepInstinct.devices.tag | string | Device tag | 
| DeepInstinct.devices.connectivity_status | string | Device connectivity status | 
| DeepInstinct.devices.deployment_status | string | Device deployment status | 
| DeepInstinct.devices.last_registration | string | Device last registration datetime | 
| DeepInstinct.devices.last_contact | string | Device last contact datetime | 
| DeepInstinct.devices.distinguished_name | string | Device distinguished name | 
| DeepInstinct.devices.group_name | string | Device group name | 
| DeepInstinct.devices.group_id | number | Device group ID | 
| DeepInstinct.devices.policy_name | string | Device policy name | 
| DeepInstinct.devices.policy_id | number | Device policy ID | 
| DeepInstinct.devices.log_status | string | Device log status | 
| DeepInstinct.devices.agent_version | string | Device agent version | 
| DeepInstinct.devices.brain_version | string | Device brain version | 
| DeepInstinct.devices.msp_name | string | Device msp name | 
| DeepInstinct.devices.msp_id | number | Device msp ID | 
| DeepInstinct.devices.tenant_name | string | Device tenant name | 
| DeepInstinct.devices.tenant_id | number | Device tenant ID | 


##### Command Example
```!deepinstinct-get-device device_id=1```

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
        "connectivity_status": "EXPIRED", 
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
| 2.3.1.12 | 115wt | EXPIRED | REGISTERED | OU=Organizations & Sites,DC=bancshares,DC=mib |  | 3 | Windows Default Group | Mock_2020-04-09 17:49:39.408405_1 | 1 | 192.168.88.80 | 2020-04-09T14:49:39.711487Z | 2020-04-09T14:49:39.722292Z | NA | 00:00:00:00:00:00 | 1 | MSP 1 | WINDOWS | Windows | 3 | Windows Default Policy | 0 |  | 1 | Tenant 1 |


### 2. deepinstinct-get-events
---
Get all events. Max events in response can be 50, use first_event_id parameter to define first event id to get
##### Base Command

`deepinstinct-get-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | First event id to get as max events in response can be 50 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Events.events.ID | number | event ID | 
| DeepInstinct.Events.events.device_id | number | event device ID | 
| DeepInstinct.Events.events.file_hash | string | event file hash | 
| DeepInstinct.Events.events.file_type | string | event file type | 
| DeepInstinct.Events.events.file_archive_hash | string | event file archive hash | 
| DeepInstinct.Events.events.path | unknown | event file path | 
| DeepInstinct.Events.events.file_size | number | event file size | 
| DeepInstinct.Events.events.threat_severity | string | event threat severity | 
| DeepInstinct.Events.events.deep_classification | string | Deep Instinct classification | 
| DeepInstinct.Events.events.file_status | string | event file status | 
| sandbox_statusDeepInstinct.Events.events. | string | event sandbox status | 
| DeepInstinct.Events.events.model | string | event model | 
| DeepInstinct.Events.events.type | string | event type | 
| DeepInstinct.Events.events.trigger | string | event trigger | 
| DeepInstinct.Events.events.action | string | event action | 
| DeepInstinct.Events.events.tenant_id | number | event tenant id | 
| DeepInstinct.Events.events.msp_id | number | event msp id | 
| DeepInstinct.Events.events.status | unknown | event status | 
| DeepInstinct.Events.events.close_trigger | unknown | event close trigger | 
| DeepInstinct.Events.events.recorded_device_info | unknown | event device info | 
| DeepInstinct.Events.events.reoccurrence_count | number | event reoccurrence_count | 


##### Command Example
```!deepinstinct-get-events```

##### Context Example
```
{
    "DeepInstinct.Events": [
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 18127052, 
            "close_timestamp": "2020-04-22T10:27:45.391625Z", 
            "id": 1, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:39.408405_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:41.170331Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "CLOSED", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:41.154850Z", 
            "msp_id": 1, 
            "close_trigger": "CLOSED_BY_ADMIN", 
            "path": "c:\\temp\\file1.exe", 
            "reoccurrence_count": 0, 
            "device_id": 1, 
            "tenant_id": 1, 
            "file_archive_hash": "d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 15090736, 
            "close_timestamp": null, 
            "id": 2, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:41.170765_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:41.810047Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "OPEN", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:41.805228Z", 
            "msp_id": 1, 
            "close_trigger": null, 
            "path": "c:\\temp\\file2.exe", 
            "reoccurrence_count": 0, 
            "device_id": 2, 
            "tenant_id": 1, 
            "file_archive_hash": "edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "5b40c30d3a3b5c532bb9d338defc0eee6161ace8baf9fabe3c0cb1e73eeb8571", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 6100823, 
            "close_timestamp": null, 
            "id": 3, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:41.826874_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:42.406046Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "OPEN", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:42.400310Z", 
            "msp_id": 1, 
            "close_trigger": null, 
            "path": "c:\\temp\\file2.exe", 
            "reoccurrence_count": 0, 
            "device_id": 3, 
            "tenant_id": 1, 
            "file_archive_hash": "5b40c30d3a3b5c532bb9d338defc0eee6161ace8baf9fabe3c0cb1e73eeb8571", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "727c2de729aa5fc471628a7bcfdf80353286a8a3981b9f0ffb58826e11518e3a", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 1274571, 
            "close_timestamp": null, 
            "id": 4, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:42.419868_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:43.096316Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "OPEN", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:43.091237Z", 
            "msp_id": 1, 
            "close_trigger": null, 
            "path": "c:\\temp\\file3.exe", 
            "reoccurrence_count": 0, 
            "device_id": 4, 
            "tenant_id": 1, 
            "file_archive_hash": "727c2de729aa5fc471628a7bcfdf80353286a8a3981b9f0ffb58826e11518e3a", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "59c6185cc5fb87f8be1cbfc0903d1486c892bd2f84c1fab685eecd1517d041cf", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 5797166, 
            "close_timestamp": null, 
            "id": 5, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:43.110126_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:43.829681Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "OPEN", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:43.821976Z", 
            "msp_id": 1, 
            "close_trigger": null, 
            "path": "c:\\temp\\file4.exe", 
            "reoccurrence_count": 0, 
            "device_id": 5, 
            "tenant_id": 1, 
            "file_archive_hash": "59c6185cc5fb87f8be1cbfc0903d1486c892bd2f84c1fab685eecd1517d041cf", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "8e83ec9a47265ed552f5369d25ae8f82074be91162c77d55dea5895637770e42", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 20730162, 
            "close_timestamp": null, 
            "id": 6, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:43.843723_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:44.453057Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "OPEN", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:44.446870Z", 
            "msp_id": 1, 
            "close_trigger": null, 
            "path": "c:\\temp\\file5.exe", 
            "reoccurrence_count": 0, 
            "device_id": 6, 
            "tenant_id": 1, 
            "file_archive_hash": "8e83ec9a47265ed552f5369d25ae8f82074be91162c77d55dea5895637770e42", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "5fd4efe63a89a08e860a4a53c1efd7773d7ffc07a279be04bab5860492ce4dd4", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 9009328, 
            "close_timestamp": "2020-04-20T11:45:00.987088Z", 
            "id": 7, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:44.464658_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:45.101055Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "CLOSED", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:45.096553Z", 
            "msp_id": 1, 
            "close_trigger": "CLOSED_BY_ADMIN", 
            "path": "c:\\temp\\file6.exe", 
            "reoccurrence_count": 0, 
            "device_id": 7, 
            "tenant_id": 1, 
            "file_archive_hash": "5fd4efe63a89a08e860a4a53c1efd7773d7ffc07a279be04bab5860492ce4dd4", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "56bb8166c11e63dbbc42b18ad61c27d0df2346e72deb6235ba166f97169aad2d", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 6975122, 
            "close_timestamp": "2020-04-12T10:12:45.428138Z", 
            "id": 8, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:45.116724_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:45.889202Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "CLOSED", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:45.884910Z", 
            "msp_id": 1, 
            "close_trigger": "CLOSED_BY_ADMIN", 
            "path": "c:\\temp\\file7.exe", 
            "reoccurrence_count": 0, 
            "device_id": 8, 
            "tenant_id": 1, 
            "file_archive_hash": "56bb8166c11e63dbbc42b18ad61c27d0df2346e72deb6235ba166f97169aad2d", 
            "action": "PREVENTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "fbf76ae6c929d5b094e376e93ef7486f0527a4060c09f0dd1ebaf073b21dd81d", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 11929486, 
            "close_timestamp": "2020-04-12T10:12:45.428138Z", 
            "id": 9, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:45.906650_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:46.515957Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "CLOSED", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:46.510849Z", 
            "msp_id": 1, 
            "close_trigger": "CLOSED_BY_ADMIN", 
            "path": "c:\\temp\\file8.exe", 
            "reoccurrence_count": 0, 
            "device_id": 9, 
            "tenant_id": 1, 
            "file_archive_hash": "fbf76ae6c929d5b094e376e93ef7486f0527a4060c09f0dd1ebaf073b21dd81d", 
            "action": "DETECTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }, 
        {
            "comment": null, 
            "last_action": null, 
            "file_type": "ZIP", 
            "tenant_name": "Tenant 1", 
            "deep_classification": null, 
            "file_hash": "0a733f0b309cc330641a1205b928ae80cfd1f129d8c5df2e03f5cde13215b4b2", 
            "threat_severity": "NONE", 
            "file_status": "NOT_UPLOADED", 
            "file_size": 18723521, 
            "close_timestamp": "2020-04-12T09:41:19.991511Z", 
            "id": 10, 
            "msp_name": "MSP 1", 
            "last_reoccurrence": null, 
            "sandbox_status": "NOT_READY_TO_GENERATE", 
            "trigger": "BRAIN", 
            "recorded_device_info": {
                "tenant_name": "Tenant 1", 
                "hostname": "Mock_2020-04-09 17:49:46.533149_1", 
                "policy_name": "Windows Default Policy", 
                "tag": "", 
                "mac_address": "00:00:00:00:00:00", 
                "group_name": "Windows Default Group", 
                "os": "WINDOWS"
            }, 
            "insertion_timestamp": "2020-04-09T14:49:47.192314Z", 
            "type": "STATIC_ANALYSIS", 
            "status": "CLOSED", 
            "certificate_thumbprint": null, 
            "timestamp": "2020-04-09T14:49:47.187327Z", 
            "msp_id": 1, 
            "close_trigger": "CLOSED_BY_ADMIN", 
            "path": "c:\\temp\\file9.exe", 
            "reoccurrence_count": 0, 
            "device_id": 10, 
            "tenant_id": 1, 
            "file_archive_hash": "0a733f0b309cc330641a1205b928ae80cfd1f129d8c5df2e03f5cde13215b4b2", 
            "action": "DETECTED", 
            "model": "FileEvent", 
            "certificate_vendor_name": null
        }
    ]
}
```

##### Human Readable Output
### Events
|action|certificate_thumbprint|certificate_vendor_name|close_timestamp|close_trigger|comment|deep_classification|device_id|file_archive_hash|file_hash|file_size|file_status|file_type|id|insertion_timestamp|last_action|last_reoccurrence|model|msp_id|msp_name|path|recorded_device_info|reoccurrence_count|sandbox_status|status|tenant_id|tenant_name|threat_severity|timestamp|trigger|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PREVENTED |  |  | 2020-04-22T10:27:45.391625Z | CLOSED_BY_ADMIN |  |  | 1 | d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f | d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f | 18127052 | NOT_UPLOADED | ZIP | 1 | 2020-04-09T14:49:41.170331Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file1.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:39.408405_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:41.154850Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  |  |  |  |  | 2 | edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960 | edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960 | 15090736 | NOT_UPLOADED | ZIP | 2 | 2020-04-09T14:49:41.810047Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file1.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:41.170765_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:41.805228Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  |  |  |  |  | 3 | 5b40c30d3a3b5c532bb9d338defc0eee6161ace8baf9fabe3c0cb1e73eeb8571 | 5b40c30d3a3b5c532bb9d338defc0eee6161ace8baf9fabe3c0cb1e73eeb8571 | 6100823 | NOT_UPLOADED | ZIP | 3 | 2020-04-09T14:49:42.406046Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file2.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:41.826874_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:42.400310Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  |  |  |  |  | 4 | 727c2de729aa5fc471628a7bcfdf80353286a8a3981b9f0ffb58826e11518e3a | 727c2de729aa5fc471628a7bcfdf80353286a8a3981b9f0ffb58826e11518e3a | 1274571 | NOT_UPLOADED | ZIP | 4 | 2020-04-09T14:49:43.096316Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file3.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:42.419868_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:43.091237Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  |  |  |  |  | 5 | 59c6185cc5fb87f8be1cbfc0903d1486c892bd2f84c1fab685eecd1517d041cf | 59c6185cc5fb87f8be1cbfc0903d1486c892bd2f84c1fab685eecd1517d041cf | 5797166 | NOT_UPLOADED | ZIP | 5 | 2020-04-09T14:49:43.829681Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file4.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:43.110126_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:43.821976Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  |  |  |  |  | 6 | 8e83ec9a47265ed552f5369d25ae8f82074be91162c77d55dea5895637770e42 | 8e83ec9a47265ed552f5369d25ae8f82074be91162c77d55dea5895637770e42 | 20730162 | NOT_UPLOADED | ZIP | 6 | 2020-04-09T14:49:44.453057Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file5.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:43.843723_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:44.446870Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  | 2020-04-20T11:45:00.987088Z | CLOSED_BY_ADMIN |  |  | 7 | 5fd4efe63a89a08e860a4a53c1efd7773d7ffc07a279be04bab5860492ce4dd4 | 5fd4efe63a89a08e860a4a53c1efd7773d7ffc07a279be04bab5860492ce4dd4 | 9009328 | NOT_UPLOADED | ZIP | 7 | 2020-04-09T14:49:45.101055Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file6.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:44.464658_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:45.096553Z | BRAIN | STATIC_ANALYSIS |
| PREVENTED |  |  | 2020-04-12T10:12:45.428138Z | CLOSED_BY_ADMIN |  |  | 8 | 56bb8166c11e63dbbc42b18ad61c27d0df2346e72deb6235ba166f97169aad2d | 56bb8166c11e63dbbc42b18ad61c27d0df2346e72deb6235ba166f97169aad2d | 6975122 | NOT_UPLOADED | ZIP | 8 | 2020-04-09T14:49:45.889202Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file7.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:45.116724_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:45.884910Z | BRAIN | STATIC_ANALYSIS |
| DETECTED |  |  | 2020-04-12T10:12:45.428138Z | CLOSED_BY_ADMIN |  |  | 9 | fbf76ae6c929d5b094e376e93ef7486f0527a4060c09f0dd1ebaf073b21dd81d | fbf76ae6c929d5b094e376e93ef7486f0527a4060c09f0dd1ebaf073b21dd81d | 11929486 | NOT_UPLOADED | ZIP | 9 | 2020-04-09T14:49:46.515957Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file8.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:45.906650_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:46.510849Z | BRAIN | STATIC_ANALYSIS |
| DETECTED |  |  | 2020-04-12T09:41:19.991511Z | CLOSED_BY_ADMIN |  |  | 10 | 0a733f0b309cc330641a1205b928ae80cfd1f129d8c5df2e03f5cde13215b4b2 | 0a733f0b309cc330641a1205b928ae80cfd1f129d8c5df2e03f5cde13215b4b2 | 18723521 | NOT_UPLOADED | ZIP | 10 | 2020-04-09T14:49:47.192314Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file9.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:46.533149_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:47.187327Z | BRAIN | STATIC_ANALYSIS |


### 3. deepinstinct-get-all-groups
---
get all groups
##### Base Command

`deepinstinct-get-all-groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Groups.ID | number | group id | 
| DeepInstinct.Groups.os | string | group operation system | 
| DeepInstinct.Groups.name | string | group name | 
| DeepInstinct.Groups.policy_id | number | group policy ID | 
| DeepInstinct.Groups.is_default_group | boolean | True if group is a default group, false otherwise | 
| DeepInstinct.Groups.msp_name | string | msp name | 
| DeepInstinct.Groups.msp_id | number | msp ID | 


##### Command Example
```!deepinstinct-get-all-groups first_event_id=0```

##### Context Example
```
{
    "DeepInstinct.Groups": [
        {
            "name": "Android Default Group", 
            "msp_name": "MSP 1", 
            "msp_id": 1, 
            "is_default_group": true, 
            "os": "ANDROID", 
            "id": 1, 
            "policy_id": 1
        }, 
        {
            "name": "iOS Default Group", 
            "msp_name": "MSP 1", 
            "msp_id": 1, 
            "is_default_group": true, 
            "os": "IOS", 
            "id": 2, 
            "policy_id": 2
        }, 
        {
            "name": "Windows Default Group", 
            "msp_name": "MSP 1", 
            "msp_id": 1, 
            "is_default_group": true, 
            "os": "WINDOWS", 
            "id": 3, 
            "policy_id": 3
        }, 
        {
            "name": "macOS Default Group", 
            "msp_name": "MSP 1", 
            "msp_id": 1, 
            "is_default_group": true, 
            "os": "MAC", 
            "id": 4, 
            "policy_id": 4
        }, 
        {
            "name": "Chrome OS Default Group", 
            "msp_name": "MSP 1", 
            "msp_id": 1, 
            "is_default_group": true, 
            "os": "CHROME", 
            "id": 5, 
            "policy_id": 5
        }, 
        {
            "name": "Test", 
            "msp_name": "MSP 1", 
            "msp_id": 1, 
            "is_default_group": false, 
            "priority": 1, 
            "os": "WINDOWS", 
            "id": 6, 
            "policy_id": 3
        }
    ]
}
```

##### Human Readable Output
### Groups
|id|is_default_group|msp_id|msp_name|name|os|policy_id|
|---|---|---|---|---|---|---|
| 1 | true | 1 | MSP 1 | Android Default Group | ANDROID | 1 |
| 2 | true | 1 | MSP 1 | iOS Default Group | IOS | 2 |
| 3 | true | 1 | MSP 1 | Windows Default Group | WINDOWS | 3 |
| 4 | true | 1 | MSP 1 | macOS Default Group | MAC | 4 |
| 5 | true | 1 | MSP 1 | Chrome OS Default Group | CHROME | 5 |
| 6 | false | 1 | MSP 1 | Test | WINDOWS | 3 |


### 4. deepinstinct-get-all-policies
---
get all policies
##### Base Command

`deepinstinct-get-all-policies`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Policies.ID | number | policy ID | 
| DeepInstinct.Policies.name | string | policy name | 
| DeepInstinct.Policies.os | string | policy operating system | 
| DeepInstinct.Policies.is_default_policy | boolean | True if policy is a default policy, False otherwise | 
| DeepInstinct.Policies.msp_id | number | msp ID | 
| DeepInstinct.Policies.msp_name | string | msp name | 


##### Command Example
```!deepinstinct-get-all-policies```

##### Context Example
```
{
    "DeepInstinct.Policies": [
        {
            "name": "iOS Default Policy", 
            "is_default_policy": true, 
            "msp_id": 1, 
            "msp_name": "MSP 1", 
            "os": "IOS", 
            "id": 2
        }, 
        {
            "name": "Windows Default Policy", 
            "is_default_policy": true, 
            "msp_id": 1, 
            "msp_name": "MSP 1", 
            "os": "WINDOWS", 
            "id": 3
        }, 
        {
            "name": "macOS Default Policy", 
            "is_default_policy": true, 
            "msp_id": 1, 
            "msp_name": "MSP 1", 
            "os": "MAC", 
            "id": 4
        }, 
        {
            "name": "Chrome OS Default Policy", 
            "is_default_policy": true, 
            "msp_id": 1, 
            "msp_name": "MSP 1", 
            "os": "CHROME", 
            "id": 5
        }, 
        {
            "name": "testPolicy", 
            "is_default_policy": false, 
            "msp_id": 1, 
            "msp_name": "MSP 1", 
            "os": "WINDOWS", 
            "id": 6
        }, 
        {
            "name": "Android Default Policy", 
            "is_default_policy": true, 
            "msp_id": 1, 
            "msp_name": "MSP 1", 
            "os": "ANDROID", 
            "id": 1
        }
    ]
}
```

##### Human Readable Output
### Policies
|id|is_default_policy|msp_id|msp_name|name|os|
|---|---|---|---|---|---|
| 2 | true | 1 | MSP 1 | iOS Default Policy | IOS |
| 3 | true | 1 | MSP 1 | Windows Default Policy | WINDOWS |
| 4 | true | 1 | MSP 1 | macOS Default Policy | MAC |
| 5 | true | 1 | MSP 1 | Chrome OS Default Policy | CHROME |
| 6 | false | 1 | MSP 1 | testPolicy | WINDOWS |
| 1 | true | 1 | MSP 1 | Android Default Policy | ANDROID |


### 5. deepinstinct-add-hash-to-blacklist
---
add file hash to block list
##### Base Command

`deepinstinct-add-hash-to-blacklist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required | 
| file_hash | file hash | Required | 
| comment | Optional, add comment to hash field | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-add-hash-to-blacklist file_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00 policy_id=6 comment=mycomment```

##### Human Readable Output
ok

### 6. deepinstinct-add-hash-to-whitelist
---
add file hash to allow list
##### Base Command

`deepinstinct-add-hash-to-whitelist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required | 
| file_hash | file hash | Required | 
| comment | Optional, add comment to hash field | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-add-hash-to-whitelist file_hash=wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww00 policy_id=6 comment=mycomment```

##### Human Readable Output
ok

### 7. deepinstinct-remove-hash-from-blacklist
---
remove file hash from block list
##### Base Command

`deepinstinct-remove-hash-from-blacklist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required | 
| file_hash | file hash | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-hash-from-blacklist file_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00 policy_id=6```

##### Human Readable Output
ok

### 8. deepinstinct-remove-hash-from-whitelist
---
remove file hash from allow list
##### Base Command

`deepinstinct-remove-hash-from-whitelist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required | 
| file_hash | file hash | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-hash-from-whitelist file_hash=wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww00 policy_id=6```

##### Human Readable Output
ok

### 9. deepinstinct-add-devices-to-group
---
add multiple devices to group
##### Base Command

`deepinstinct-add-devices-to-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID | Required | 
| device_ids | comma separated devices ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-add-devices-to-group device_ids=1 group_id=6```

##### Human Readable Output
ok

### 10. deepinstinct-remove-devices-from-group
---
remove list of devices from group
##### Base Command

`deepinstinct-remove-devices-from-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID to remove from | Required | 
| device_ids | comma separeted list of device ids to remove | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-devices-from-group device_ids=1 group_id=6```

##### Human Readable Output
ok

### 11. deepinstinct-delete-files-remotely
---
delete multiple files remotely
##### Base Command

`deepinstinct-delete-files-remotely`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separeted list of event ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-delete-files-remotely event_ids=1```

##### Human Readable Output
ok

### 12. deepinstinct-terminate-processes
---
terminate list of processes
##### Base Command

`deepinstinct-terminate-processes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separeted list of event ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-terminate-processes event_ids=1,2```

##### Human Readable Output
ok

### 13. deepinstinct-close-events
---
close list of events
##### Base Command

`deepinstinct-close-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separeted list of event ids | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-close-events event_ids=1```

##### Human Readable Output
ok
