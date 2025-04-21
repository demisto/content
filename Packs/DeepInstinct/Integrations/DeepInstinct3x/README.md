Deep Instinct is a prevention-first approach to stopping ransomware and other malware using the world's first purpose-built, deep learning cybersecurity framework.
This integration was integrated and tested with version 3.3.x of DeepInstinct v3

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure DeepInstinct v3 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Base server URL | True |
| API Key | True |
| First event ID to fetch from | False |
| Fetch incidents | False |
| Incidents Fetch Interval | False |
| Incident type | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### deepinstinctv3-get-device
***
Get device information from its ID


#### Base Command

`deepinstinctv3-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Get device information from its ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| deepinstinctv3.devices.ID | number | Device ID | 
| deepinstinctv3.devices.os | string | Device OS | 
| deepinstinctv3.devices.osv | string | Device OS version | 
| deepinstinctv3.devices.ip_address | string | Device IP address | 
| deepinstinctv3.devices.email | sting | Device email ip_address | 
| deepinstinctv3.devices.mac_address | string | Device mac address | 
| deepinstinctv3.devices.hostname | string | Device hostname | 
| deepinstinctv3.devices.domain | string | Device domain | 
| deepinstinctv3.devices.scanned_files | number | Num of device scanned files | 
| deepinstinctv3.devices.comment | string | Device comment | 
| deepinstinctv3.devices.tag | string | Device tag | 
| deepinstinctv3.devices.connectivity_status | string | Device connectivity status | 
| deepinstinctv3.devices.deployment_status | string | Device deployment status | 
| deepinstinctv3.devices.deployment_status_last_update | string | Device last client version update | 
| deepinstinctv3.devices.license_status | string | Device license status | 
| deepinstinctv3.devices.last_registration | string | Device last registration datetime | 
| deepinstinctv3.devices.last_contact | string | Device last contact datetime | 
| deepinstinctv3.devices.distinguished_name | string | Device distinguished name | 
| deepinstinctv3.devices.group_name | string | Device group name | 
| deepinstinctv3.devices.group_id | number | Device group ID | 
| deepinstinctv3.devices.policy_name | string | Device policy name | 
| deepinstinctv3.devices.policy_id | number | Device policy ID | 
| deepinstinctv3.devices.log_status | string | Device log status | 
| deepinstinctv3.devices.agent_version | string | Device agent version | 
| deepinstinctv3.devices.brain_version | string | Device brain version | 
| deepinstinctv3.devices.logged_in_users | string | Device logged in user\(s\) | 
| deepinstinctv3.devices.msp_name | string | Device msp name | 
| deepinstinctv3.devices.msp_id | number | Device msp ID | 
| deepinstinctv3.devices.tenant_name | string | Device tenant name | 
| deepinstinctv3.devices.tenant_id | number | Device tenant ID | 

### deepinstinctv3-get-events
***
Get all events after given event ID


#### Base Command

`deepinstinctv3-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | Get all events. Max events in response is 50, use first_event_id parameter to define first event id to get. Default is 0. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| deepinstinctv3.Events.events.id | number | event ID | 
| deepinstinctv3.Events.events.device_id | number | event device ID | 
| deepinstinctv3.Events.events.timestamp | string | event timestamp from device | 
| deepinstinctv3.Events.events.insertion_timestamp | string | event timestamp from console | 
| deepinstinctv3.Events.events.close_timestamp | string | event closed timestamp | 
| deepinstinctv3.Events.events.last_action | string | event last last_action | 
| deepinstinctv3.Events.events.status | string | event status | 
| deepinstinctv3.Events.events.comment | string | event comment | 
| deepinstinctv3.Events.events.recorded_device_info | unknown | event device information | 
| deepinstinctv3.Events.events.msp_name | string | event msp name | 
| deepinstinctv3.Events.events.msp_id | number | event msp id | 
| deepinstinctv3.Events.events.tenant_name | string | event tenant name | 
| deepinstinctv3.Events.events.tenant_id | number | event tenant id | 
| deepinstinctv3.Events.events.mitre_classifications | unknown | event MITRE classification | 
| deepinstinctv3.Events.events.type | string | event type | 
| deepinstinctv3.Events.events.trigger | string | event trigger | 
| deepinstinctv3.Events.events.action | string | event action | 
| deepinstinctv3.Events.events.close_trigger | string | event close trigger | 
| deepinstinctv3.Events.events.reoccurrence_count | number | event reoccurrence_count | 
| deepinstinctv3.Events.events.file_type | string | event file type | 
| deepinstinctv3.Events.events.file_hash | string | event file hash | 
| deepinstinctv3.Events.events.file_archive_hash | string | event file archive hash | 
| deepinstinctv3.Events.events.path | unknown | event file path | 
| deepinstinctv3.Events.events.file_size | number | event file size | 
| deepinstinctv3.Events.events.threat_severity | string | event threat severity | 
| deepinstinctv3.Events.events.certificate_thumbprint | string | event certificate certificate thumbprint | 
| deepinstinctv3.Events.events.certificate_vendor_name | string | event certificate certificate vendor name | 
| deepinstinctv3.Events.events.deep_classification | string | Deep Instinct classification | 
| deepinstinctv3.Events.events.file_status | string | event file status | 
| deepinstinctv3.Events.events.sandbox_status | string | event sandbox status | 

### deepinstinctv3-get-suspicious-events
***
Get all suspicious events after given event ID


#### Base Command

`deepinstinctv3-get-suspicious-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | Get all suspicious events. Max events in response is 50, use first_event_id parameter to define first event id to get. Default is 0. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| deepinstinctv3.Suspicious-Events.events.ID | number | event ID | 
| deepinstinctv3.Suspicious-Events.events.device_id | number | event device ID | 
| deepinstinctv3.Suspicious-Events.events.timestamp | string | event timestamp from device | 
| deepinstinctv3.Suspicious-Events.events.insertion_timestamp | string | event timestamp from console | 
| deepinstinctv3.Suspicious-Events.events.status | string | event status | 
| deepinstinctv3.Suspicious-Events.events.recorded_device_info | unkown | event device info | 
| deepinstinctv3.Suspicious-Events.events.msp_name | string | event msp name | 
| deepinstinctv3.Suspicious-Events.events.msp_id | number | event msp id | 
| deepinstinctv3.Suspicious-Events.events.tenant_name | string | event tenant name | 
| deepinstinctv3.Suspicious-Events.events.tenant_id | number | event tenant id | 
| deepinstinctv3.Suspicious-Events.events.mitre_classifications | unknown | event MITRE classification | 
| deepinstinctv3.Suspicious-Events.events.type | string | event type | 
| deepinstinctv3.Suspicious-Events.events.trigger | string | event trigger | 
| deepinstinctv3.Suspicious-Events.events.action | string | event action | 
| deepinstinctv3.Suspicious-Events.events.close_trigger | string | event close trigger | 
| deepinstinctv3.Suspicious-Events.events.file_type | string | event file type | 
| deepinstinctv3.Suspicious-Events.events.rule_trigger | string | event rule trigger | 
| deepinstinctv3.Suspicious-Events.events.file_archive_hash | string | event file archive hash | 
| deepinstinctv3.Suspicious-Events.events.remediation | unknown | event remediation | 
| deepinstinctv3.Suspicious-Events.events.path | unknown | event file path | 

### deepinstinctv3-get-all-groups
***
Get all groups


#### Base Command

`deepinstinctv3-get-all-groups`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| deepinstinctv3.Groups.ID | number | group id | 
| deepinstinctv3.Groups.is_default_group | boolean | True if group is a default group, false otherwise | 
| deepinstinctv3.Groups.msp_id | number | msp ID | 
| deepinstinctv3.Groups.name | string | group name | 
| deepinstinctv3.Groups.os | string | group operation system | 
| deepinstinctv3.Groups.policy_id | number | group policy ID | 

### deepinstinctv3-get-all-policies
***
Get list of all policies


#### Base Command

`deepinstinctv3-get-all-policies`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| deepinstinctv3.Policies.ID | number | policy ID | 
| deepinstinctv3.Policies.name | string | policy name | 
| deepinstinctv3.Policies.os | string | policy operating system | 
| deepinstinctv3.Policies.is_default_policy | boolean | True if policy is a default policy, False otherwise | 
| deepinstinctv3.Policies.msp_id | number | msp ID | 
| deepinstinctv3.Policies.msp_name | string | msp name | 

### deepinstinctv3-add-hash-to-deny-list
***
Add file hash to Deny List


#### Base Command

`deepinstinctv3-add-hash-to-deny-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 
| comment | comment to hash field. | Optional | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-add-hash-to-allow-list
***
Add file hash to Allow List


#### Base Command

`deepinstinctv3-add-hash-to-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 
| comment | comment to hash field. | Optional | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-remove-hash-from-deny-list
***
Remove hash from Deny List


#### Base Command

`deepinstinctv3-remove-hash-from-deny-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-remove-hash-from-allow-list
***
Remove hash from Allow List


#### Base Command

`deepinstinctv3-remove-hash-from-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-add-devices-to-group
***
Add multiple devices to a group


#### Base Command

`deepinstinctv3-add-devices-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID. | Required | 
| device_ids | comma seperated list of device ids to address. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-remove-devices-from-group
***
Remove list of devices from groups


#### Base Command

`deepinstinctv3-remove-devices-from-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID to remove from. | Required | 
| device_ids | Comma seperated list of device ids to remove. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-delete-files-remotely
***
Delete multiple files remotely


#### Base Command

`deepinstinctv3-delete-files-remotely`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-terminate-processes
***
Terminate list of processes


#### Base Command

`deepinstinctv3-terminate-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-close-events
***
Close list of events


#### Base Command

`deepinstinctv3-close-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-disable-device
***
Disable device at next check-in


#### Base Command

`deepinstinctv3-disable-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-enable-device
***
Enable device at next check-in


#### Base Command

`deepinstinctv3-enable-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-isolate-from-network
***
Isolate device(s) from Network


#### Base Command

`deepinstinctv3-isolate-from-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | comma separated list of device ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-release-from-isolation
***
Release device(s) from isolation


#### Base Command

`deepinstinctv3-release-from-isolation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | comma separated list of device ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-remote-file-upload
***
Upload file associated with given event id at next check-in


#### Base Command

`deepinstinctv3-remote-file-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | the event id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-upload-logs
***
Upload device logs from given device at next check-in


#### Base Command

`deepinstinctv3-upload-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinctv3-remove-device
***
Remove agent from device at next check-in


#### Base Command

`deepinstinctv3-remove-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.