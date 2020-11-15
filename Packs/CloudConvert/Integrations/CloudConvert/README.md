Use the CloudConvert integration to convert your files to desired format
This integration was integrated and tested with version xx of CloudConvert
## Configure CloudConvert on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CloudConvert.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cloudconvert-import
***
Import a file for later conversion


#### Base Command

`cloudconvert-import`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The file's url. If an entry id is supplied, do not use this argument | Optional | 
| entry_id | The file's war room entry ID. If a url is supplied, do not use this argument | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task id of scanned file | 
| CloudConvert.Task.status | String | Status of current task | 
| CloudConvert.Task.message | String | Response message from the API | 
| CloudConvert.Task.operation | String | The operation conducted | 
| CloudConvert.Task.result.files.filename | String | Resulted file name | 
| CloudConvert.Task.result.files.size | Number | Resulted size of file | 
| CloudConvert.Task.result.files.url | String | Resulted file url | 
| CloudConvert.Task.created_at | Date | Creation Time | 
| CloudConvert.Task.started_at | Date | Operation start time | 
| CloudConvert.Task.ended_at | Date | Operation end time | 
| CloudConvert.Task.host_name | String | Name of host used for operation | 
| CloudConvert.Task.storage | String | Storage server for operation | 
| CloudConvert.Task.links | String | APIs link for operation | 


#### Command Example
`cloudconvert-import entry_id=@123`

#### Human Readable Output



### cloudconvert-convert
***
Convert a priorly uploaded file to desired format


#### Base Command

`cloudconvert-convert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task id of the import task of the file of interest | Required | 
| output_format | The desired output format for the given file | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task id of scanned file | 
| CloudConvert.Task.status | String | Status of current task | 
| CloudConvert.Task.message | String | Response message from API | 
| CloudConvert.Task.operation | String | The operation conducted | 
| CloudConvert.Task.result.files.filename | String | Resulted file name | 
| CloudConvert.Task.result.files.size | Number | Resulted size of file | 
| CloudConvert.Task.result.files.url | String | Resulted file url | 
| CloudConvert.Task.created_at | Date | Creation Time | 
| CloudConvert.Task.started_at | Date | Operation start time | 
| CloudConvert.Task.ended_at | Date | Operation end time | 
| CloudConvert.Task.host_name | String | Name of host used for operation | 
| CloudConvert.Task.storage | String | Storage server for operation | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous operation conducted on this file | 
| CloudConvert.Task.links | String | APIs link for operation | 


#### Command Example
`cloudconvert-convert task_id=1 output_format=pdf`

#### Human Readable Output



### cloudconvert-check-status
***
Check the status of an operation. Use the 'is_entry' argument to also create a war room entry of the file when checking on an export to war room entry operation


#### Base Command

`cloudconvert-check-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task id of the convert task of the file of interest | Required | 
| is_entry | use this argument if you are checking on an export to war room entry operation, so an entry will be created if the operation is finished | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task id of scanned file | 
| CloudConvert.Task.status | String | Status of current task | 
| CloudConvert.Task.message | String | Response message from API | 
| CloudConvert.Task.operation | String | The operation conducted | 
| CloudConvert.Task.result.files.filename | String | Resulted file name | 
| CloudConvert.Task.result.files.size | Number | Resulted size of file | 
| CloudConvert.Task.result.files.url | String | Resulted file url | 
| CloudConvert.Task.created_at | Date | Creation Time | 
| CloudConvert.Task.started_at | Date | Operation start time | 
| CloudConvert.Task.ended_at | Date | Operation end time | 
| CloudConvert.Task.host_name | String | Name of host used for operation | 
| CloudConvert.Task.storage | String | Storage server for operation | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous operation conducted on this file | 
| CloudConvert.Task.links | String | APIs link for operation | 


#### Command Example
`cloudconvert-check-status task_id=1`

#### Human Readable Output



### cloudconvert-export
***
Export a converted file to a url or a war room entry


#### Base Command

`cloudconvert-export`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| export_as | where should the file be exported to | Required | 
| task_id | Task id of the convert task of the file of interest | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task id of scanned file | 
| CloudConvert.Task.status | String | Status of current task | 
| CloudConvert.Task.message | String | Response message from API | 
| CloudConvert.Task.operation | String | The operation conducted | 
| CloudConvert.Task.result.files.filename | String | Resulted file name | 
| CloudConvert.Task.result.files.size | Number | Resulted size of file | 
| CloudConvert.Task.result.files.url | String | Resulted file url | 
| CloudConvert.Task.created_at | Date | Creation Time | 
| CloudConvert.Task.started_at | Date | Operation start time | 
| CloudConvert.Task.ended_at | Date | Operation end time | 
| CloudConvert.Task.host_name | String | Name of host used for operation | 
| CloudConvert.Task.storage | String | Storage server for operation | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous operation conducted on this file | 
| CloudConvert.Task.links | String | APIs link for operation | 


#### Command Example
`cloudconvert-export task_id=1 export_as=url`

#### Human Readable Output


