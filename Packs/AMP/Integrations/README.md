Uses CISCO AMP Endpoint
This integration was integrated and tested with API version v1 of AMP

## Configure AMP on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for AMP.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://api.amp.cisco.com)__
    * __Client ID__
    * __Trust any certificate (not secure)__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. amp_get_computers
2. amp_get_computer_by_connector
3. amp_get_computer_trajctory
4. amp_move_computer
5. amp_get_computer_activity
6. amp_get_events
7. amp_get_event_types
8. amp_get_application_blocking
9. amp_get_file_list_by_guid
10. amp_get_simple_custom_detections
11. amp_get_file_list_files
12. amp_get_file_list_files_by_sha
13. amp_set_file_list_files_by_sha
14. amp_delete_file_list_files_by_sha
15. amp_get_groups
16. amp_get_group
17. amp_set_group_policy
18. amp_get_policies
19. amp_get_policy
20. amp_get_version
21. amp_delete_computers_isolation
22. amp_put_computers_isolation
23. amp_get_computers_isolation
### 1. amp_get_computers
---
Returns a list of computers on which agents are deployed. You can use filters (arguments) to narrow the search.
##### Base Command

`amp_get_computers`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. | Optional | 
| hostname | Filter results by hostname. | Optional | 
| internal_ip | Filter results by internal IP address. | Optional | 
| external_ip | Filter results by external IP address. | Optional | 
| group_guid | Filter results by group GUID. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
 !amp_get_computers limit=10 hostname='demisto.com'
```

### 2. amp_get_computer_by_connector
---
Returns information for the specified computer.
##### Base Command

`amp_get_computer_by_connector`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for which to return information. | Required | 


##### Command Example
```
!amp_get_computer_by_connector connector_guid=12345abcde
```

### 3. amp_get_computer_trajctory
---
Returns a list of all activities associated with a particular computer. This is analogous to the Device Trajectory on the FireAMP Console. Use the Q argument to search for an IP address, SHA256 hash, or URL.

##### Base Command

`amp_get_computer_trajctory`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | The IP address, SHA256 hash, or URL. | Optional | 
| limit | Maximum number of results to return. | Optional | 
| connector_guid | The connector GUID. | Required | 


##### Command Example
```
!amp_get_computer_trajctory q='8.8.8.8' limit=10 connector_guid=12345abdce
```

### 4. amp_move_computer
---
Moves a computer to a group with the corresponding connector_guid and group_guid, respectively.
##### Base Command

`amp_move_computer`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID. | Required | 
| group_guid | The group GUID. | Required | 


##### Command Example
```
!amp_move_computer connector_guid='abcde12345' group_guid='demisto123'
```

### 5. amp_get_computer_activity
---
This endpoint enables you to search all computers across your organization for any events or activities associated with a file or network operation, and returns computers that match the specified criteria. You can then query the /computers/{connector-guid}/trajectory endpoint for specific details.

##### Base Command

`amp_get_computer_activity`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | An IPv4 address, SHA256 hash, filename, or URL fragment. | Required | 
| limit | Maximum number of results to return. | Optional | 
| offset | offset | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_computer_activity q='8.8.8.8'
```

### 6. amp_get_events
---
A general query interface for events. This is analogous to the Events view on the FireAMP Console.

##### Base Command

`amp_get_events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. | Optional | 
| connector_guid | The connector GUID. | Optional | 
| group_guid | The group GUID. | Optional | 
| detection_sha256 | The detected SHA256 hash. | Optional | 
| application_sha256 | The application SHA256. | Optional | 
| event_type | The event type. | Optional | 
| offset | The offset. | Optional | 
| start_date | The start date for the query, in ISO8601 format. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_events connector_guid='abcde12345'
```

### 7. amp_get_event_types
---
Events are identified and filtered by a unique ID. This endpoint provides a human readable name and short description of each event (by ID).

##### Base Command

`amp_get_event_types`
##### Input

There is no input for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_event_types
```

### 8. amp_get_application_blocking
---
Returns a list of application blocking file lists. You can filter this list by name

##### Base Command

`amp_get_application_blocking`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. | Optional | 
| offset | The offset. | Optional | 
| name | Name of the file. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_application_blocking name='abcde12345'
```

### 9. amp_get_file_list_by_guid
---
Returns a particular file list for application blocking or simple custom detection. You need to specify the file_list_guid argument to retrieve information about a particular file_list.

##### Base Command

`amp_get_file_list_by_guid`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | Retrieves information about a particular file_list. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_file_list_by_guid file_list_guid='abcde12345'
```

### 10. amp_get_simple_custom_detections
---
Returns a list of simple custom detection file lists. You can filter this list by detection name.

##### Base Command

`amp_get_simple_custom_detections`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. | Optional | 
| offset | The offset. | Optional | 
| name | Name of the detection. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_simple_custom_detections name='sample detections'
```

### 11. amp_get_file_list_files
---
Returns a list of items for a particular file_list. You need to specify the file_list_guid argument to retrieve these items.

##### Base Command

`amp_get_file_list_files`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. | Optional | 
| offset | The offset. | Optional | 
| file_list_guid | Retrieves information about a particular file_list. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_file_list_files file_list_guid='abcde12345'
```

### 12. amp_get_file_list_files_by_sha
---
Returns a particular item for a given file_list. You need to specify the sha256 argument and the file_list_guid argument to retrieve an item.

##### Base Command

`amp_get_file_list_files_by_sha`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | Retrieves information about a particular file_list. | Required | 
| sha256 | SHA256 hash. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_file_list_files_by_sha file_list_guid='abcde12345' sha256='samplesha256'
```


### 13. amp_set_file_list_files_by_sha
---
Adds a SHA256 hash to a file list, using file_list_guid.

##### Base Command

`amp_set_file_list_files_by_sha`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | Retrieves information about a particular file_list. | Required | 
| sha256 | SHA256 hash. | Required | 
| description | Description of the SHA256 hash. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_set_file_list_files_by_sha file_list_guid='abcde12345' sha256='samplesha256' description='This is a sample SHA'
```


### 14. amp_delete_file_list_files_by_sha
---
Deletes an item from a file_list using the SHA256 hash and file_list_guid.

##### Base Command

`amp_delete_file_list_files_by_sha`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | The file_list_guid to retrieve information about a particular file_list | Required | 
| sha256 | SHA256 hash. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_delete_file_list_files_by_sha file_list_guid='abcde12345' sha256='samplesha256'
```

### 15. amp_get_groups
---
Returns basic information about groups in your organization. You can map group names to GUIDs for filtering on the events endpoint.

##### Base Command

`amp_get_groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | amount of results | Optional | 
| name | name of the group | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_groups limit=25
```

### 16. amp_get_group
---
Returns a particular group

##### Base Command

`amp_get_group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_guid | The particular group guid | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_group group_guid='abcde12345'
```

### 17. amp_set_group_policy
---
Sets a security policy to a group of endpoints.

##### Base Command

`amp_set_group_policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_guid | The group GUID. | Required | 
| linux_policy_guid | The Linux policy guide. | Optional | 
| android_policy_guid | The Android policy guide. | Optional | 
| mac_policy_guid | The Mac policy guide. | Optional | 
| windows_policy_guid | The Windows policy guide. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_set_group_policy group_guid='abcde12345'
```

### 18. amp_get_policies
---
Returns a list of policies. You can filter this list by name and product.
##### Base Command

`amp_get_policies`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to return. | Optional | 
| offset | The offset. | Optional | 
| name | The policy name. | Optional | 
| product | The policy product. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_policies name='TestPolicy'
```

### 19. amp_get_policy
---
Retrieves information about a particular policy, based on policy_guid.

##### Base Command

`amp_get_policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_guid | The policy GUID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_policy policy_guid='abcde12345'
```

### 20. amp_get_version
---
Fetches a list of versions.

##### Base Command

`amp_get_version`
##### Input
There is no input for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_version
```

### 21. amp_delete_computers_isolation
---
Request to unlock an isolated computer. Can also be used as a course-grained isolation status request.

##### Base Command

`amp_delete_computers_isolation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector GUID. | Required | 
| unlock_code | Comment about unlocking the computer. Use the amp_get_computers_isolation command to retrieve the unlock_code. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_delete_computers_isolation connector_guid=12345abcde
```

### 22. amp_put_computers_isolation
---
Requests isolation for a Computer.  If a computer is already isolated a 409 conflict error status is returned.

##### Base Command

`amp_put_computers_isolation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector GUID. | Required | 
| unlock_code | Comment used when locking the computer. Use the amp_get_computers_isolation command to retrieve the unlock_code. | Optional | 

##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_put_computers_isolation connector_guid=12345abcde
```

### 23. amp_get_computers_isolation
---
Returns a fine grained isolation status for a computer.

##### Base Command

`amp_get_computers_isolation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector GUID. | Required | 
| status | The status of the computer. Can be: "not_isolated", "pending_start", "isolated", or "pending_stop". | Optional | 

##### Context Output

There is no context output for this command.

##### Command Example
```
!amp_get_computers_isolation connector_guid=12345abcde
```
