This is an integration that will use Sysdig agent to respond to malicious activity by triggering different actions at the host or container level like killing a container, quarantine a file or perform a system capture
This integration was integrated and tested with version xx of Sysdig-Response-Actions.

## Configure Sysdig-Response-Actions in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for the connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### call-response-api

***
Calling the Sysdig response-actions API

#### Base Command

`call-response-api`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | API metthod to perform i.e POST, GET. Default is GET. | Required | 
| url_suffix | The API suffix. Default is /secure/response-actions/v1alpha1/action-executions. | Required | 
| actionType | Action type to perform. Possible values are: KILL_PROCESS, KILL_CONTAINER, STOP_CONTAINER, PAUSE_CONTAINER, FILE_QUARANTINE. | Optional | 
| callerId | The caller ID, it must be unique every time. | Optional | 
| container_id | The container ID to apply the action. Example "container.id": "123456789123". | Optional | 
| path_absolute | The path of the file to quarantine. Example "/etc/sensitive". | Optional | 
| host_id | The host ID. Example "laksjdf1923u90snca893". | Optional | 
| process_id | The process ID. Example "1234". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| call_response_api.Output | String | Output of the response-actions API | 

### create-system-capture

***
Command to trigger a system capture, it will record all system calls at the host level.

#### Base Command

`create-system-capture`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | API metthod to perform i.e POST, GET. Default is GET. | Required | 
| url_suffix | The API suffix. Default is /api/v1/captures. | Required | 
| container_id | The container ID to apply the action. Example "container.id": "123456789123". | Required | 
| host_name | The host name. Example "ip-1-1-1-1.us-west-1.compute.internal". | Required | 
| capture_name | The capture name. | Required | 
| agent_id | The agent ID. | Required | 
| customer_id | The customer ID. | Required | 
| machine_id | The machine ID/MAC. Example "01:aa:02:bb:03:cc". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| create_system_capture.Output | String | Output of the system capture created | 

### download-capture-file

***
Command to download a system capture based on the capture ID.

#### Base Command

`download-capture-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| capture_id | System Capture ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| download_capture_file.Output | String | Output of the system capture downloaded | 
