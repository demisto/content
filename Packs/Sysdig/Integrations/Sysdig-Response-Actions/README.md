This is an integration that will use Sysdig agent to respond to malicious activity by triggering different actions at the host or container level like killing a container, quarantine a file or perform a system capture
This integration was integrated and tested with version xx of SysdigResponseActions.

## Configure Sysdig Response Actions in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for the connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### execute-response-action

***
Execute response actions through the Sysdig API

#### Base Command

`execute-response-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actionType | Action type to perform. Possible values are: KILL_PROCESS, KILL_CONTAINER, STOP_CONTAINER, PAUSE_CONTAINER, FILE_QUARANTINE. | Required | 
| callerId | The caller ID, it must be unique every time. | Required | 
| container_id | The container ID to apply the action. Example "container.id": "123456789123". | Optional | 
| path_absolute | The path of the file to quarantine. Example "/etc/sensitive". Required for the `FILE_QUARANTINE` action. | Optional | 
| host_id | The host ID. Example "laksjdf1923u90snca893". | Optional | 
| process_id | The process ID. Example "1234". Required for the `KILL_PROCESS` action. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| execute_response_action.Output | String | Output of the response-actions API | 

### create-system-capture

***
Command to trigger a system capture, it will record all system calls at the host level.

#### Base Command

`create-system-capture`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_id | The container ID to apply the action. Example "container.id": "123456789123". | Required | 
| host_name | The host name. Example "ip-1-1-1-1.us-west-1.compute.internal". | Required | 
| capture_name | The capture name. | Required | 
| agent_id | The agent ID. | Required | 
| customer_id | The customer ID. | Required | 
| machine_id | The machine ID/MAC. Example "01:aa:02:bb:03:cc". | Required | 
| scap_duration | Capture duration in seconds. | Required | 
| scap_filter | Filter the scope of the capture to take. Example: (proc.name=ncat or proc.name=vi). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| create_system_capture.Output | String | Output of the system capture created | 

### get-capture-file

***
Command to get a system capture based on the capture ID.

#### Base Command

`get-capture-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| capture_id | System Capture ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| get_capture_file.Output | String | Output of the system capture downloaded | 

### get-action-execution

***
Get the status and information of a triggered action execution

#### Base Command

`get-action-execution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_execution_id | The action exection ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| get_action_execution.Output | String | Output of the action execution info | 
