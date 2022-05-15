Deep Instinct is a prevention-first approach to stopping ransomware and other malware using the world's first purpose-built, deep learning cybersecurity framework.
This integration was integrated and tested with version 3.3.x of DeepInstinct v3

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-deepinstinct-v3).

## Configure DeepInstinct v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DeepInstinct v3.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### deepinstinct-get-device
***
Get device information from its ID


#### Base Command

`deepinstinct-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Get device information from its ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.devices.ID | number | Device ID | 
| DeepInstinct.devices.os | string | Device OS | 
| DeepInstinct.devices.osv | string | Device OS version | 
| DeepInstinct.devices.ip_address | string | Device IP address | 
| DeepInstinct.devices.email | sting | Device email ip_address | 
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
| DeepInstinct.devices.logged_in_users | string | Device logged in user\(s\) | 
| DeepInstinct.devices.msp_name | string | Device msp name | 
| DeepInstinct.devices.msp_id | number | Device msp ID | 
| DeepInstinct.devices.tenant_name | string | Device tenant name | 
| DeepInstinct.devices.tenant_id | number | Device tenant ID | 

### deepinstinct-get-events
***
Get all events after given event ID


#### Base Command

`deepinstinct-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | Get all events. Max events in response is 50, use first_event_id parameter to define first event id to get. Default is 0. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Events.events.id | number | event ID | 
| DeepInstinct.Events.events.device_id | number | event device ID | 
| DeepInstinct.Events.events.timestamp | string | event timestamp from device | 
| DeepInstinct.Events.events.insertion_timestamp | string | event timestamp from console | 
| DeepInstinct.Events.events.close_timestamp | string | event closed timestamp | 
| DeepInstinct.Events.events.last_action | string | event last last_action | 
| DeepInstinct.Events.events.status | string | event status | 
| DeepInstinct.Events.events.comment | string | event comment | 
| DeepInstinct.Events.events.recorded_device_info | unknown | event device information | 
| DeepInstinct.Events.events.msp_name | string | event msp name | 
| DeepInstinct.Events.events.msp_id | number | event msp id | 
| DeepInstinct.Events.events.tenant_name | string | event tenant name | 
| DeepInstinct.Events.events.tenant_id | number | event tenant id | 
| DeepInstinct.Events.events.mitre_classifications | unknown | event MITRE classification | 
| DeepInstinct.Events.events.type | string | event type | 
| DeepInstinct.Events.events.trigger | string | event trigger | 
| DeepInstinct.Events.events.action | string | event action | 
| DeepInstinct.Events.events.close_trigger | string | event close trigger | 
| DeepInstinct.Events.events.reoccurrence_count | number | event reoccurrence_count | 
| DeepInstinct.Events.events.file_type | string | event file type | 
| DeepInstinct.Events.events.file_hash | string | event file hash | 
| DeepInstinct.Events.events.file_archive_hash | string | event file archive hash | 
| DeepInstinct.Events.events.path | unknown | event file path | 
| DeepInstinct.Events.events.file_size | number | event file size | 
| DeepInstinct.Events.events.threat_severity | string | event threat severity | 
| DeepInstinct.Events.events.certificate_thumbprint | string | event certificate certificate thumbprint | 
| DeepInstinct.Events.events.certificate_vendor_name | string | event certificate certificate vendor name | 
| DeepInstinct.Events.events.deep_classification | string | Deep Instinct classification | 
| DeepInstinct.Events.events.file_status | string | event file status | 
| DeepInstinct.Events.events.sandbox_status | string | event sandbox status | 

### deepinstinct-get-suspicious-events
***
Get all suspicious events after given event ID


#### Base Command

`deepinstinct-get-suspicious-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_event_id | Get all suspicious events. Max events in response is 50, use first_event_id parameter to define first event id to get. Default is 0. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Suspicious-Events.events.ID | number | event ID | 
| DeepInstinct.Suspicious-Events.events.device_id | number | event device ID | 
| DeepInstinct.Suspicious-Events.events.timestamp | string | event timestamp from device | 
| DeepInstinct.Suspicious-Events.events.insertion_timestamp | string | event timestamp from console | 
| DeepInstinct.Suspicious-Events.events.status | string | event status | 
| DeepInstinct.Suspicious-Events.events.recorded_device_info | unkown | event device info | 
| DeepInstinct.Suspicious-Events.events.msp_name | string | event msp name | 
| DeepInstinct.Suspicious-Events.events.msp_id | number | event msp id | 
| DeepInstinct.Suspicious-Events.events.tenant_name | string | event tenant name | 
| DeepInstinct.Suspicious-Events.events.tenant_id | number | event tenant id | 
| DeepInstinct.Suspicious-Events.events.mitre_classifications | unknown | event MITRE classification | 
| DeepInstinct.Suspicious-Events.events.type | string | event type | 
| DeepInstinct.Suspicious-Events.events.trigger | string | event trigger | 
| DeepInstinct.Suspicious-Events.events.action | string | event action | 
| DeepInstinct.Suspicious-Events.events.close_trigger | string | event close trigger | 
| DeepInstinct.Suspicious-Events.events.file_type | string | event file type | 
| DeepInstinct.Suspicious-Events.events.rule_trigger | string | event rule trigger | 
| DeepInstinct.Suspicious-Events.events.file_archive_hash | string | event file archive hash | 
| DeepInstinct.Suspicious-Events.events.remediation | unknown | event remediation | 
| DeepInstinct.Suspicious-Events.events.path | unknown | event file path | 

### deepinstinct-get-all-groups
***
Get all groups


#### Base Command

`deepinstinct-get-all-groups`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Groups.ID | number | group id | 
| DeepInstinct.Groups.is_default_group | boolean | True if group is a default group, false otherwise | 
| DeepInstinct.Groups.msp_id | number | msp ID | 
| DeepInstinct.Groups.name | string | group name | 
| DeepInstinct.Groups.os | string | group operation system | 
| DeepInstinct.Groups.policy_id | number | group policy ID | 

### deepinstinct-get-all-policies
***
Get list of all policies


#### Base Command

`deepinstinct-get-all-policies`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepInstinct.Policies.ID | number | policy ID | 
| DeepInstinct.Policies.name | string | policy name | 
| DeepInstinct.Policies.os | string | policy operating system | 
| DeepInstinct.Policies.is_default_policy | boolean | True if policy is a default policy, False otherwise | 
| DeepInstinct.Policies.msp_id | number | msp ID | 
| DeepInstinct.Policies.msp_name | string | msp name | 

### deepinstinct-add-hash-to-deny-list
***
Add file hash to Deny List


#### Base Command

`deepinstinct-add-hash-to-deny-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 
| comment | comment to hash field. | Optional | 


#### Context Output

There is no context output for this command.
### deepinstinct-add-hash-to-allow-list
***
Add file hash to Allow List


#### Base Command

`deepinstinct-add-hash-to-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 
| comment | comment to hash field. | Optional | 


#### Context Output

There is no context output for this command.
### deepinstinct-remove-hash-from-deny-list
***
Remove hash from Deny List


#### Base Command

`deepinstinct-remove-hash-from-deny-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-remove-hash-from-allow-list
***
Remove hash from Allow List


#### Base Command

`deepinstinct-remove-hash-from-allow-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| file_hash | file hash. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-add-devices-to-group
***
Add multiple devices to a group


#### Base Command

`deepinstinct-add-devices-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | group ID. | Required | 
| device_ids | comma seperated list of device ids to address. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-remove-devices-from-group
***
Remove list of devices from groups


#### Base Command

`deepinstinct-remove-devices-from-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID to remove from. | Required | 
| device_ids | Comma seperated list of device ids to remove. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-delete-files-remotely
***
Delete multiple files remotely


#### Base Command

`deepinstinct-delete-files-remotely`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-terminate-processes
***
Terminate list of processes


#### Base Command

`deepinstinct-terminate-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-close-events
***
Close list of events


#### Base Command

`deepinstinct-close-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | comma separated list of event ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-disable-device
***
Disable device at next check-in


#### Base Command

`deepinstinct-disable-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-enable-device
***
Enable device at next check-in


#### Base Command

`deepinstinct-enable-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-isolate-from-network
***
Isolate device(s) from Network


#### Base Command

`deepinstinct-isolate-from-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | comma separated list of device ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-release-from-isolation
***
Release device(s) from isolation


#### Base Command

`deepinstinct-release-from-isolation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | comma separated list of device ids. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-remote-file-upload
***
Upload file associated with given event id at next check-in


#### Base Command

`deepinstinct-remote-file-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | the event id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-upload-logs
***
Upload device logs from given device at next check-in


#### Base Command

`deepinstinct-upload-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
### deepinstinct-remove-device
***
Remove agent from device at next check-in


#### Base Command

`deepinstinct-remove-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | single device id. | Required | 


#### Context Output

There is no context output for this command.
## Breaking changes from the previous version of this integration - DeepInstinct v3
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
