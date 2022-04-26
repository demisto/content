## Overview
---

Deep Instinct
This integration was integrated and tested with version 3.3.x of Deep Instinct


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
3. deepinstinct-get-suspicious-events
4. deepinstinct-get-all-groups
5. deepinstinct-get-all-policies
6. deepinstinct-add-hash-to-deny-list
7. deepinstinct-add-hash-to-allow-list
8. deepinstinct-remove-hash-from-deny-list
9. deepinstinct-remove-hash-from-allow-list
10. deepinstinct-add-devices-to-group
11. deepinstinct-remove-devices-from-group
12. deepinstinct-delete-files-remotely
13. deepinstinct-terminate-processes
14. deepinstinct-close-events
15. deepinstinct-disable-device
16. deepinstinct-enable-device
17. deepinstinct-isolate-from-network
18. deepinstinct-release-from-isolation
19. deepinstinct-remote-file-upload
20. deepinstinct-upload-logs
21. deepinstinct-remove-device

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
| DeepInstinct.devices.email | string | Device email address |
| DeepInstinct.devices.mac_address | string | Device mac address |
| DeepInstinct.devices.hostname | string | Device hostname |
| DeepInstinct.devices.domain | string | Device domain |
| DeepInstinct.devices.scanned_files | number | Num of device scanned files |
| DeepInstinct.devices.comment | string | Device comment |
| DeepInstinct.devices.tag | string | Device tag |
| DeepInstinct.devices.connectivity_status | string | Device connectivity status |
| DeepInstinct.devices.deployment_status | string | Device deployment status |
| DeepInstinct.devices.deployment_status_last_update | string | Device last client version update |
| DeepInstinct.devices.license_status | string | Device license status |
| DeepInstinct.devices.last_registration | string | Device last registered datetime |
| DeepInstinct.devices.last_contact | string | Device last contact datetime |
| DeepInstinct.devices.distinguished_name | string | Device distinguished name |
| DeepInstinct.devices.group_name | string | Device group name |
| DeepInstinct.devices.group_id | number | Device group ID |
| DeepInstinct.devices.policy_name | string | Device policy name |
| DeepInstinct.devices.policy_id | number | Device policy ID |
| DeepInstinct.devices.log_status | string | Device log status |
| DeepInstinct.devices.agent_version | string | Device agent version |
| DeepInstinct.devices.brain_version | string | Device brain version |
| DeepInstinct.devices.logged_in_users | string | Device logged in users |
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
		"id": 12,
		"os": "WINDOWS_SERVER",
		"osv": "Windows Server 2016 Datacenter",
		"ip_address": "10.10.10.10,
		"mac_address": "00:50:56:bd:47:ef",
		"hostname": "TEST-DC",
		"domain": "acme.local",
		"scanned_files": 2072083,
		"tag": "",
		"connectivity_status": "ONLINE",
		"deployment_status": "REGISTERED",
		"deployment_status_last_update": "2022-01-09T07:05:18.406894Z",
		"license_status": "ACTIVATED",
		"last_registration": "2020-03-20T21:48:14.771125Z",
		"last_contact": "2022-01-14T19:46:53.077558Z",
		"distinguished_name": "CN=TEST-DC,OU=Computers,OU=acme,DC=acme,DC=local",
		"group_name": "Windows Servers",
		"group_id": 13,
		"policy_name": "Windows Servers",
		"policy_id": 13,
		"log_status": "NA",
		"agent_version": "3.3.1.15",
		"brain_version": "126w",
		"logged_in_users": "",
		"msp_name": "Server Lab",
		"msp_id": 2,
		"tenant_name": "Server Lab",
		"tenant_id": 4
    }
}
```

##### Human Readable Output
>### Device Information
>Provides detailed information for the selected device
>|agent_version|brain_version|connectivity_status|deployment_status|distinguished_name|domain|group_id|group_name|hostname|id|ip_address|last_contact|last_registration|license_status|log_status|logged_in_uders|mac_address|msp_id|msp_name|os|osv|policy_id|policy_name|scanned_files|tag|tenant_id|tenant_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>3.3.1.15 | 126w | ONLINE | REGISTERED | 2022-01-09T07:05:18.406894Z | CN=TEST-DC,OU=Computers,OU=acme,DC=acme,DC=local | acme.local | 13 | Windows Servers | TEST-DC | 12 | 10.10.10.10 | 2022-01-14T01:33:01.512439Z | 2020-03-20T21:48:14.771125Z | ACTIVATED | NA |  | 00:50:56:bd:47:ef | 2 | Server Lab | WINDOWS_SERVER | Windows Server 2016 Datacenter | 13 | Windows Servers | 2065772 |  | 4 | Server Lab |


### 2. deepinstinct-get-events
---
Get all events. Max events in response can be 50, use first_event_id parameter to define first event id to get
##### Base Command

`deepinstinct-get-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | First event id to retrieve (max events in response is 50) | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Events.events.ID | number | event ID |
| DeepInstinct.Events.events.device_id | number | event device ID |
| DeepInstinct.Events.events.timestamp | string | event timestamp from device |
| DeepInstinct.Events.events.insertion_timestamp | string | event timestamp from console  |
| DeepInstinct.Events.events.close_timestamp | string | event closed timestamp  |
| DeepInstinct.Events.events.last_action | string | event last action  |
| DeepInstinct.Events.events.status | string | event status |
| DeepInstinct.Events.events.comment | string | event comment |
| DeepInstinct.Events.events.recorded_device_info | unknown | event device info |
| DeepInstinct.Events.events.msp_name | string | event msp name |
| DeepInstinct.Events.events.msp_id | number | event msp id |
| DeepInstinct.Events.events.tenant_name | string | event tenant name |
| DeepInstinct.Events.events.tenant_id | number | event tenant id |
| DeepInstinct.Events.events.mitre_classifications | unknown | event mitre calssifications |
| DeepInstinct.Events.events.type | string | event type |
| DeepInstinct.Events.events.trigger | string | event trigger |
| DeepInstinct.Events.events.action | string | event action |
| DeepInstinct.Events.events.close_trigger | unknown | event close trigger |
| DeepInstinct.Events.events.reoccurrence_count | number | event reoccurrence_count |
| DeepInstinct.Events.events.file_type | string | event file type |
| DeepInstinct.Events.events.file_hash | string | event file hash |
| DeepInstinct.Events.events.file_archive_hash | string | event file archive hash |
| DeepInstinct.Events.events.path | unknown | event file path |
| DeepInstinct.Events.events.file_size | number | event file size |
| DeepInstinct.Events.events.threat_severity | string | event threat severity |
| DeepInstinct.Events.events.certificate_thumbprint | string | event certificate thumbprint |
| DeepInstinct.Events.events.certificate_vendor_name | string | event certificate vendor name |
| DeepInstinct.Events.events.deep_classification | string | Deep Instinct classification |
| DeepInstinct.Events.events.file_status | string | event file status |
| DeepInstinct.Events.events.sandbox_status | string | event sandbox status |


##### Command Example
```!deepinstinct-get-events```

##### Context Example
```
{
    "DeepInstinct.Events": [
        {
			"id": 7001,
			"device_id": 15799,
			"timestamp": "2022-01-14T23:03:34.749Z",
			"insertion_timestamp": "2022-01-14T23:03:34.749Z",
			"close_timestamp": "2022-01-14T23:03:34.749Z",
			"last_action": "FILE_UPLOADED_SUCCESSFULLY",
			"status": "OPEN",
			"comment": "string",
			"recorded_device_info": {
				"id": 1,
				"os": "WINDOWS",
				"osv": "8.0.0",
				"ip_address": "192.168.1.20",
				"email": "user@example.com",
				"mac_address": "0f:5e:56:1e:11:fb",
				"hostname": "WINDOWS-SERVER-01",
				"domain": "acme.local",
				"scanned_files": 155660,
				"comment": "string",
				"tag": "string",
				"connectivity_status": "ONLINE",
				"deployment_status": "REGISTERED",
				"deployment_status_last_update": "2022-01-14T23:03:34.749Z",
				"license_status": "ACTIVATED",
				"last_registration": "2022-01-14T23:03:34.749Z",
				"last_contact": "2022-01-14T23:03:34.749Z",
				"distinguished_name": "CN=SAMPLE_LAP,OU=IT,OU=Domain Computers,DC=acme,DC=local",
				"group_name": "Windows Default Group",
				"group_id": 3,
				"policy_name": "Windows Default Group",
				"policy_id": 3,
				"log_status": 4,
				"agent_version": "2.2.0.9",
				"brain_version": "108",
				"logged_in_users": "BUILTIN\\Administrator",
				"msp_name": "string",
				"msp_id": 1,
				"tenant_name": "string",
				"tenant_id": 1
			},
			"msp_name": "string",
			"msp_id": 1,
			"tenant_name": "string",
			"tenant_id": 1,
			"mitre_classifications": [
				{
				"mitre_id": "T1566.001",
				"tactic_id": "TA001",
				"tactic_name": "Initial Access",
				"technique_id": "T1566",
				"technique_name": "Phishing",
				"sub_technique_id": "T1566.001",
				"sub_technique_name": "Spearphishing Attachment"
				}
			],
			"type": "STATIC_ANALYSIS",
			"trigger": "MALICIOUS_FILE",
			"action": "PREVENTED",
			"close_trigger": "CLOSED_BY_ADMIN",
			"reoccurrence_count": 21,
			"last_reoccurrence": "2022-01-14T23:03:34.749Z",
			"file_type": "PE",
			"file_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"file_archive_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"path": "C:\\Temp\\malware.dll",
			"file_size": 156400,
			"threat_severity": "VERY_HIGH",
			"certificate_thumbprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"certificate_vendor_name": "Deep Instinct",
			"deep_classification": "RANSOMWARE",
			"file_status": "UPLOADED",
			"sandbox_status": "REPORT_CREATED"
        }
    ]
}
```

##### Human Readable Output
>### Events
>|action|certificate_thumbprint|certificate_vendor_name|close_timestamp|close_trigger|comment|deep_classification|device_id|file_archive_hash|file_hash|file_size|file_status|file_type|id|insertion_timestamp|last_action|mitre_classifications|msp_id|msp_name|path|recorded_device_info|reoccurrence_count|sandbox_status|status|tenant_id|tenant_name|threat_severity|timestamp|trigger|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| PREVENTED |  |  | 2020-04-22T10:27:45.391625Z | CLOSED_BY_ADMIN |  |  | 1 | d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f | d1838b541ff7ffe6489d120d89dfa855665fd2c708491f336c7267069387053f | 18127052 | NOT_UPLOADED | ZIP | 1 | 2020-04-09T14:49:41.170331Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file1.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:39.408405_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:41.154850Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  |  |  |  |  | 2 | edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960 | edf34902ff17838b4bc709ff15b5265dd49f652ee75a1adf69df9ae5bc52f960 | 15090736 | NOT_UPLOADED | ZIP | 2 | 2020-04-09T14:49:41.810047Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file1.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:41.170765_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:41.805228Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  |  |  |  |  | 3 | 5b40c30d3a3b5c532bb9d338defc0eee6161ace8baf9fabe3c0cb1e73eeb8571 | 5b40c30d3a3b5c532bb9d338defc0eee6161ace8baf9fabe3c0cb1e73eeb8571 | 6100823 | NOT_UPLOADED | ZIP | 3 | 2020-04-09T14:49:42.406046Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file2.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:41.826874_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:42.400310Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  |  |  |  |  | 4 | 727c2de729aa5fc471628a7bcfdf80353286a8a3981b9f0ffb58826e11518e3a | 727c2de729aa5fc471628a7bcfdf80353286a8a3981b9f0ffb58826e11518e3a | 1274571 | NOT_UPLOADED | ZIP | 4 | 2020-04-09T14:49:43.096316Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file3.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:42.419868_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:43.091237Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  |  |  |  |  | 5 | 59c6185cc5fb87f8be1cbfc0903d1486c892bd2f84c1fab685eecd1517d041cf | 59c6185cc5fb87f8be1cbfc0903d1486c892bd2f84c1fab685eecd1517d041cf | 5797166 | NOT_UPLOADED | ZIP | 5 | 2020-04-09T14:49:43.829681Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file4.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:43.110126_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:43.821976Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  |  |  |  |  | 6 | 8e83ec9a47265ed552f5369d25ae8f82074be91162c77d55dea5895637770e42 | 8e83ec9a47265ed552f5369d25ae8f82074be91162c77d55dea5895637770e42 | 20730162 | NOT_UPLOADED | ZIP | 6 | 2020-04-09T14:49:44.453057Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file5.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:43.843723_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | OPEN | 1 | Tenant 1 | NONE | 2020-04-09T14:49:44.446870Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  | 2020-04-20T11:45:00.987088Z | CLOSED_BY_ADMIN |  |  | 7 | 5fd4efe63a89a08e860a4a53c1efd7773d7ffc07a279be04bab5860492ce4dd4 | 5fd4efe63a89a08e860a4a53c1efd7773d7ffc07a279be04bab5860492ce4dd4 | 9009328 | NOT_UPLOADED | ZIP | 7 | 2020-04-09T14:49:45.101055Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file6.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:44.464658_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:45.096553Z | BRAIN | STATIC_ANALYSIS |
>| PREVENTED |  |  | 2020-04-12T10:12:45.428138Z | CLOSED_BY_ADMIN |  |  | 8 | 56bb8166c11e63dbbc42b18ad61c27d0df2346e72deb6235ba166f97169aad2d | 56bb8166c11e63dbbc42b18ad61c27d0df2346e72deb6235ba166f97169aad2d | 6975122 | NOT_UPLOADED | ZIP | 8 | 2020-04-09T14:49:45.889202Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file7.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:45.116724_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:45.884910Z | BRAIN | STATIC_ANALYSIS |
>| DETECTED |  |  | 2020-04-12T10:12:45.428138Z | CLOSED_BY_ADMIN |  |  | 9 | fbf76ae6c929d5b094e376e93ef7486f0527a4060c09f0dd1ebaf073b21dd81d | fbf76ae6c929d5b094e376e93ef7486f0527a4060c09f0dd1ebaf073b21dd81d | 11929486 | NOT_UPLOADED | ZIP | 9 | 2020-04-09T14:49:46.515957Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file8.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:45.906650_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:46.510849Z | BRAIN | STATIC_ANALYSIS |
>| DETECTED |  |  | 2020-04-12T09:41:19.991511Z | CLOSED_BY_ADMIN |  |  | 10 | 0a733f0b309cc330641a1205b928ae80cfd1f129d8c5df2e03f5cde13215b4b2 | 0a733f0b309cc330641a1205b928ae80cfd1f129d8c5df2e03f5cde13215b4b2 | 18723521 | NOT_UPLOADED | ZIP | 10 | 2020-04-09T14:49:47.192314Z |  |  | FileEvent | 1 | MSP 1 | c:\temp\file9.exe | os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: Mock_2020-04-09 17:49:46.533149_1 tag:  group_name: Windows Default Group policy_name: Windows Default Policy tenant_name: Tenant 1 | 0 | NOT_READY_TO_GENERATE | CLOSED | 1 | Tenant 1 | NONE | 2020-04-09T14:49:47.187327Z | BRAIN | STATIC_ANALYSIS |


### 3. deepinstinct-get-suspicious-events
---
Get suspicious events. Max events in response can be 50, use first_event_id parameter to define first event id to get
##### Base Command

`deepinstinct-get-suspicious-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | First event id to retrieve (max events in response is 50) | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Suspicious-Events.events.ID | number | event ID |
| DeepInstinct.Suspicious-Events.events.device_id | number | event device ID |
| DeepInstinct.Suspicious-Events.events.timestamp | string | event timestamp from device |
| DeepInstinct.Suspicious-Events.events.insertion_timestamp | string | event timestamp from console  |
| DeepInstinct.Suspicious-Events.events.status | string | event status |
| DeepInstinct.Suspicious-Events.events.recorded_device_info | array | event device info |
| DeepInstinct.Suspicious-Events.events.msp_name | string | event msp name |
| DeepInstinct.Suspicious-Events.events.msp_id | number | event msp id |
| DeepInstinct.Suspicious-Events.events.tenant_name | string | event tenant name |
| DeepInstinct.Suspicious-Events.events.tenant_id | number | event tenant id |
| DeepInstinct.Suspicious-Events.events.mitre_classifications | array | event mitre calssifications |
| DeepInstinct.Suspicious-Events.events.type | string | event type |
| DeepInstinct.Suspicious-Events.events.trigger | string | event trigger |
| DeepInstinct.Suspicious-Events.events.action | string | event action |
| DeepInstinct.Suspicious-Events.events.close_trigger | unknown | event close trigger |
| DeepInstinct.Suspicious-Events.events.file_type | string | event file type |
| DeepInstinct.Suspicious-Events.events.rule_trigger | string | event rule trigger |
| DeepInstinct.Suspicious-Events.events.file_archive_hash | string | event file archive hash |
| DeepInstinct.Suspicious-Events.events.remediation | unknown | event remediation |
| DeepInstinct.Suspicious-Events.events.source | array | event source |
| DeepInstinct.Suspicious-Events.events.path | unknown | event file path |


##### Command Example
```!deepinstinct-get-suspicious-events```

##### Context Example
```
{
    "DeepInstinct.Suspicious-Events": [
        {
			"id": 1234,
			"device_id": 123,
			"timestamp": "2022-03-19T19:57:09.204815Z",
			"insertion_timestamp": "2022-03-19T19:57:09.229320Z",
			"status": "OPEN",
			"recorded_device_info": {
				"os": "WINDOWS",
				"mac_address": "00:00:00:00:00:00",
				"hostname": "DESKTOP-123XYZ",
				"tag": "",
				"group_name": "Windows Desktop",
				"policy_name": "Windows Desktop",
				tenant_name": "Tenant"
		},
			"msp_name": "ACME",
			"msp_id": 2,
			"tenant_name": "Tenant",
			"tenant_id": 35,
			"mitre_classifications": [
			  {
				"mitre_id": "TA0003.T1574.011",
				"tactic_id": "TA0003",
				"tactic_name": "Persistence",
				"technique_id": "T1574",
				"technique_name": "Hijack Execution Flow",
				"sub_technique_id": "T1574.011",
				"sub_technique_name": "Services Registry Permissions Weakness"
			  }
			],
			"type": "SUSPICIOUS_ACTIVITY",
			"trigger": "SUSPICIOUS_ACTIVITY",
			"action": "DETECTED",
			"rule_trigger": "REGISTRY",
			"remediation": [],
			"source": [
			  {
				"type": "REGISTRY_DATA",
				"value": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\badflt.inf_amd64\\badflt.sys"
			  },
			  {
				"type": "REGISTRY_PATH",
				"value": "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\badflt\\ImagePath"
			  },
			  {
				"type": "PROCESS_PATH",
				"value": "C:\\Windows\\System32\\services.exe"
			  },
			  {
				"type": "PARENT_PROCESS_PATH",
				"value": "C:\\Windows\\System32\\wininit.exe"
			  }
			],
			"path": "Existing service was modified to run another binary file."
  }
}
    ]
}
```

##### Human Readable Output
>### Suspicious Events
>|action|device_id|id|insertion_timestamp|mitre_classifications|msp_id|msp_name|path|recorded_device_info|remediation|rule_trigger|source|status|tenant_id|tenant_name|timestamp|trigger|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|DETECTED|"123"|"12345"|"2022-03-20T13:09:45.026686Z"|"{'mitre_id': 'TA0003.T1574.011','tactic_id': 'TA0003', 'tactic_name': 'Persistence', 'technique_id': ', T1574', 'technique_name': 'Hijack Execution Flow', 'sub_technique_id': 'T1574.011','sub_technique_name': 'Services Registry Permissions Weakness'}"|"2"|"ACME"|"Existing service was modified to run another binary file."|"os: WINDOWS mac_address: 00:00:00:00:00:00 hostname: LAPTOP-X13 tag: "" group_name: ACME Labs policy_name: Admin Devices tenant_name: Tenant"|""|"REGISTRY"|"{'type': 'REGISTRY_DATA'| 'value': '""C:\Program Files (x86)\Widgets\Application\Client.1150.46\ElevateService.exe""'}|{'type': 'REGISTRY_PATH'| 'value': '\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\GoodApplication\ImagePath'}|{'type': 'PROCESS_PATH'| 'value': 'C:\Windows\System32\services.exe'}| {'type': 'PARENT_PROCESS_PATH'| 'value': 'C:\Windows\System32\wininit.exe'}"|"OPEN"|"3"|"Tenant"|"2022-03-20T13:09:44.988791Z"|"SUSPICIOUS_ACTIVITY"|"SUSPICIOUS_ACTIVITY"|
>|PREVENTED|"227"|"1985"|"2022-03-22T00:25:28.725997Z"|"{'mitre_id': 'TA0002.T1059.001', 'tactic_id': 'TA0002', 'tactic_name': 'Execution', 'technique_id': ', T1059', 'technique_name': 'Command and Scripting Interpreter', 'sub_technique_id': ', T1059.001', 'sub_technique_name': 'PowerShell'}"|"2"|"ACME"|"C:\WINDOWS\TEMP\SDIAG_257bd48a-e8a3-47d6-839c-31c3b92adec1\Wckd_Utility.ps1"|"os: WINDOWS mac_address: 00:00:00:00:00:00:00 hostname: DESKTOP-123XYZ tag: "" group_name: Windows Desktop policy_name: Windows Desktops tenant_name: Tenant"|""|""|""|"OPEN"|"35"|"Tenant"|"2022-03-22T00:25:28.694909Z"|"POWERSHELL_EXECUTION"|"SUSPICIOUS_POWERSHELL_COMMAND_EXECUTION"|


### 4. deepinstinct-get-all-groups
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
| DeepInstinct.Groups.is_default_group | boolean | True if group is a default group, false otherwise |
| DeepInstinct.Groups.msp_id | number | msp ID |
| DeepInstinct.Groups.name | string | group name |
| DeepInstinct.Groups.policy_id | number | group policy ID |
| DeepInstinct.Groups.os | string | group operation system |  



##### Command Example
```!deepinstinct-get-all-groups```

##### Context Example
```
{
    "DeepInstinct.Groups": [
        {
      "os": "ANDROID",
			"id": 6,
			"is_default_group": true,
			"name": "Android Default Group",
			"policy_id": 6,
			"msp_id": 2
		},
		{
			"os": "IOS",
			"id": 7,
			"is_default_group": true,
			"name": "iOS Default Group",
			"policy_id": 7,
			"msp_id": 2
		},
		{
			"os": "WINDOWS",
			"id": 8,
			"is_default_group": true,
			"name": "Windows Default Group",
			"policy_id": 8,
			"msp_id": 2
		},
		{
			"os": "MAC",
			"id": 9,
			"is_default_group": true,
			"name": "macOS Default Group",
			"policy_id": 9,
			"msp_id": 2
		},
		{
			"os": "CHROME",
			"id": 10,
			"is_default_group": true,
			"name": "Chrome OS Default Group",
			"policy_id": 10,
			"msp_id": 2
		},
		{
			"os": "WINDOWS",
			"id": 11,
			"is_default_group": false,
			"priority": 3,
			"name": "Laptops only",
			"policy_id": 11,
			"msp_id": 2
		},
		{
			"os": "LINUX",
			"id": 12,
			"is_default_group": true,
			"name": "Linux Default Group",
			"policy_id": 399,
			"msp_id": 2
  },
    ]
}
```

##### Human Readable Output
>### Groups
>Provides summary information about all groups
>|id|is_default_group|msp_id|name|os|policy_id|
>|---|---|---|---|---|---|
>| 6 | true | 1 | MSP 1 | Android Default Group | ANDROID | 6 |
>| 7 | true | 1 | MSP 1 | iOS Default Group | IOS | 7 |
>| 8 | true | 1 | MSP 1 | Windows Default Group | WINDOWS | 8 |
>| 9 | true | 1 | MSP 1 | macOS Default Group | MAC | 9 |
>| 10 | true | 1 | MSP 1 | Chrome OS Default Group | CHROME | 10 |
>| 11 | false | 1 | MSP 1 | Laptops only | WINDOWS | 11 |
>| 12 | true | 1 | MASP 1| Linux Default Group | LINUX | 399 |


### 5. deepinstinct-get-all-policies
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
>### Policies
> Provides summary information for all policies
>|id|is_default_policy|msp_id|msp_name|name|os|
>|---|---|---|---|---|---|
>| 2 | true | 1 | MSP 1 | iOS Default Policy | IOS |
>| 3 | true | 1 | MSP 1 | Windows Default Policy | WINDOWS |
> 4 | true | 1 | MSP 1 | macOS Default Policy | MAC |
>| 5 | true | 1 | MSP 1 | Chrome OS Default Policy | CHROME |
>| 6 | false | 1 | MSP 1 | testPolicy | WINDOWS |
>| 1 | true | 1 | MSP 1 | Android Default Policy | ANDROID |


### 6. deepinstinct-add-hash-to-deny-list
---
add file hash to deny list
##### Base Command

`deepinstinct-add-hash-to-deny-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required |
| file_hash | file hash | Required |
| comment | Optional, add comment to hash field | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-add-hash-to-deny-list file_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00 policy_id=6 comment=mycomment```

##### Human Readable Output
ok

### 7. deepinstinct-add-hash-to-allow-list
---
add file hash to allow list
##### Base Command

`deepinstinct-add-hash-to-allow-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required |
| file_hash | file hash | Required |
| comment | Optional, add comment to hash field | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-add-hash-to-allow-list file_hash=wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww00 policy_id=6 comment=mycomment```

##### Human Readable Output
ok

### 8. deepinstinct-remove-hash-from-deny-list
---
remove file hash from deny list
##### Base Command

`deepinstinct-remove-hash-from-deny-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required |
| file_hash | file hash | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-hash-from-deny-list file_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00 policy_id=6```

##### Human Readable Output
ok

### 9. deepinstinct-remove-hash-from-allow-list
---
remove file hash from allow list
##### Base Command

`deepinstinct-remove-hash-from-allow-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID | Required |
| file_hash | file hash | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-hash-from-allow-list file_hash=wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww00 policy_id=6```

##### Human Readable Output
ok

### 10. deepinstinct-add-devices-to-group
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

### 11. deepinstinct-remove-devices-from-group
---
remove list of devices from group
##### Base Command

`deepinstinct-remove-devices-from-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID to remove from | Required |
| device_ids | comma separated list of device ids to remove | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-devices-from-group device_ids=1 group_id=6```

##### Human Readable Output
ok

### 12. deepinstinct-delete-files-remotely
---
delete multiple files remotely
##### Base Command

`deepinstinct-delete-files-remotely`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-delete-files-remotely event_ids=1```

##### Human Readable Output
ok

### 13. deepinstinct-terminate-processes
---
terminate list of processes
##### Base Command

`deepinstinct-terminate-processes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-terminate-processes event_ids=1,2```

##### Human Readable Output
ok

### 14. deepinstinct-close-events
---
close list of events
##### Base Command

`deepinstinct-close-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-close-events event_ids=1```

##### Human Readable Output
ok

### 15. deepinstinct-disable-device
---
disable device at next check-in
##### Base Command

`deepinstinct-disable-device`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-disable-device device_id=7```

##### Human Readable Output
ok

### 16. deepinstinct-enable-device
---
enable device at next check-in
##### Base Command

`deepinstinct-enable-device`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-enable-device device_id=7```

##### Human Readable Output
ok

### 17. deepinstinct-isolate-from-network
---
isolate device(s) from network
##### Base Command

`deepinstinct-isolate-from-network`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | comma separated list of device ids | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-isolate-from-network device_id=2,4,6,8```

##### Human Readable Output
ok

### 18. deepinstinct-release-from-isolation
---
release device(s) from isolation
##### Base Command

`deepinstinct-release-from-isolation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | comma separated list of device ids | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-release-from-isolation device_id=2,4,6,8```

##### Human Readable Output
ok

### 19. deepinstinct-remote-file-upload
---
upload the file associated with the given event ID the next time it checks in
##### Base Command

`deepinstinct-remote-file-upload`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | single event id | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remote-file-upload event_id=1```

##### Human Readable Output
ok

### 20. deepinstinct-upload-logs
---
upload device logs from given device next time it checks in
##### Base Command

`deepinstinct-upload-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-upload-logs device_id=1```

##### Human Readable Output
ok

### 21. deepinstinct-remove-device
---
remove agent from device next time it checks in
##### Base Command

`deepinstinct-remove-device`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id | Required |


##### Context Output

There is no context output for this command.

##### Command Example
```!deepinstinct-remove-device device_id=1```

##### Human Readable Output
ok
