Deep Instinct takes a prevention-first approach to stopping ransomware and other malware using the world’s first and only purpose-built, deep learning cybersecurity framework. We predict and prevent known, unknown, and zero-day threats in <20 milliseconds, 750X faster than the fastest ransomware can encrypt.
This integration was integrated and tested with version xx of DeepInstinct

## Configure DeepInstinct on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DeepInstinct.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Base server URL | True |
    | API Key | True |
    | First event ID to fetch from | False |
    | Fetch incidents | False |
    | Incidents Fetch Interval | False |
    | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### deepinstinct-get-device
***
get specific device by ID


#### Base Command

`deepinstinct-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. | Required | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-get-events
***
Get all events. Max events in response can be 50, use first_event_id parameter to define first event id to get


#### Base Command

`deepinstinct-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | First event id to get as max events in response can be 50. Default is 0. | Optional | 


#### Context Output

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
| DeepInstinct.Events.events.status | string | event status | 
| DeepInstinct.Events.events.close_trigger | string | event close trigger | 
| DeepInstinct.Events.events.reoccurrence_count | number | event reoccurrence_count | 


#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-get-suspicious-events
***
Get all suspicious events. Max events in response can be 50, use first_event_id parameter to define first event id to get


#### Base Command

`deepinstinct-get-suspicious-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | First event id to get as max events in response can be 50. Default is 0. | Optional | 


#### Context Output

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
| DeepInstinct.Events.events.status | string | event status | 
| DeepInstinct.Events.events.close_trigger | string | event close trigger | 
| DeepInstinct.Events.events.reoccurrence_count | number | event reoccurrence_count | 


#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-get-all-groups
***
get all groups


#### Base Command

`deepinstinct-get-all-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Groups.ID | number | group id | 
| DeepInstinct.Groups.os | string | group operation system | 
| DeepInstinct.Groups.name | string | group name | 
| DeepInstinct.Groups.policy_id | number | group policy ID | 
| DeepInstinct.Groups.is_default_group | boolean | True if group is a default group, false otherwise | 
| DeepInstinct.Groups.msp_name | string | msp name | 
| DeepInstinct.Groups.msp_id | number | msp ID | 


#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-get-all-policies
***
get all policies


#### Base Command

`deepinstinct-get-all-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Policies.ID | number | policy ID | 
| DeepInstinct.Policies.name | string | policy name | 
| DeepInstinct.Policies.os | string | policy operating system | 
| DeepInstinct.Policies.is_default_policy | boolean | True if policy is a default policy, False otherwise | 
| DeepInstinct.Policies.msp_id | number | msp ID | 
| DeepInstinct.Policies.msp_name | string | msp name | 


#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-add-hash-to-deny-list
***
add file hash to deny-list


#### Base Command

`deepinstinct-add-hash-to-deny-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID. | Required | 
| file_hash | file hash. | Required | 
| comment | Optional, add comment to hash field. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-add-hash-to-allow-list
***
add file hash to allow-list


#### Base Command

`deepinstinct-add-hash-to-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID. | Required | 
| file_hash | file hash. | Required | 
| comment | Optional, add comment to hash field. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-remove-hash-from-deny-list
***
remove file hash from deny-list


#### Base Command

`deepinstinct-remove-hash-from-deny-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID. | Required | 
| file_hash | file hash. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-remove-hash-from-allow-list
***
remove file hash from allow-list


#### Base Command

`deepinstinct-remove-hash-from-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | policy ID. | Required | 
| file_hash | file hash. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-add-devices-to-group
***
add multiple devices to group


#### Base Command

`deepinstinct-add-devices-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID. | Required | 
| device_ids | comma separated devices ids. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-remove-devices-from-group
***
remove list of devices from group


#### Base Command

`deepinstinct-remove-devices-from-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID to remove from. | Required | 
| device_ids | comma separated list of device ids to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-delete-files-remotely
***
delete multiple files remotely


#### Base Command

`deepinstinct-delete-files-remotely`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-terminate-processes
***
terminate list of processes


#### Base Command

`deepinstinct-terminate-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### deepinstinct-close-events
***
close list of events


#### Base Command

`deepinstinct-close-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


