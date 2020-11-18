Use the CloudConvert integration to convert your files to the required format.
This integration was integrated and tested with version v2 of CloudConvert.
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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cloudconvert-import
***
Imports a file for conversion.


#### Base Command

`cloudconvert-import`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The file's URL. If an entry ID is supplied, do not use this argument. | Optional | 
| entry_id | The file's War Room entry ID. If a URL is supplied, do not use this argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task ID of the scanned file. | 
| CloudConvert.Task.status | String | Status of the current task. | 
| CloudConvert.Task.message | String | Response message from the API. | 
| CloudConvert.Task.operation | String | The operation that was performed. | 
| CloudConvert.Task.result.files.filename | String | The name of the imported file. | 
| CloudConvert.Task.result.files.size | Number | The size of the imported file. | 
| CloudConvert.Task.result.files.url | String | The URL of the imported file. | 
| CloudConvert.Task.created_at | Date | Time the task was created. | 
| CloudConvert.Task.started_at | Date | Start time of the task. | 
| CloudConvert.Task.ended_at | Date | End time of the task. | 
| CloudConvert.Task.host_name | String | Name of the host used for the task. | 
| CloudConvert.Task.storage | String | Storage server used for the task. | 
| CloudConvert.Task.links | String | API link for the task. | 


#### Command Example
`cloudconvert-import entry_id=@123`

#### Human Readable Output



### cloudconvert-convert
***
Converts an uploaded file to the required format.


#### Base Command

`cloudconvert-convert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | ID of the task that imported the file. | Required | 
| output_format | The required output format for the given file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task ID of the scanned file. | 
| CloudConvert.Task.status | String | Status of the current task. | 
| CloudConvert.Task.message | String | Response message from the API. | 
| CloudConvert.Task.operation | String | The task that was performed. | 
| CloudConvert.Task.result.files.filename | String | The name of the converted file. | 
| CloudConvert.Task.result.files.size | Number | The size of the converted file. | 
| CloudConvert.Task.result.files.url | String | The URL of the converted file. | 
| CloudConvert.Task.created_at | Date | Time the task was created. | 
| CloudConvert.Task.started_at | Date | Start time of the task. | 
| CloudConvert.Task.ended_at | Date | End time of the task. | 
| CloudConvert.Task.host_name | String | Name of the host used for the task. | 
| CloudConvert.Task.storage | String | Storage server used for the task. | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous task that was conducted on this file. | 
| CloudConvert.Task.links | String | API link for the task. | 


#### Command Example
`cloudconvert-convert task_id=1 output_format=pdf`

#### Human Readable Output



### cloudconvert-check-status
***
Checks the status of an operation. Use the 'create_war_room_entry' argument to also create a war room entry of the file when checking on an export operation


#### Base Command

`cloudconvert-check-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | ID of the task used to convert the file. | Required | 
| create_war_room_entry | Whether to create an entry in the War Room if the task is finished. Possible values are: "True" and "False". Use this argument to be able to check on an export operation in the War Room. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task ID of the scanned file. | 
| CloudConvert.Task.status | String | Status of the current task. | 
| CloudConvert.Task.message | String | Response message from the API. | 
| CloudConvert.Task.operation | String | The task that was performed. | 
| CloudConvert.Task.result.files.filename | String | The name of the converted file. | 
| CloudConvert.Task.result.files.size | Number | The size of the converted file. | 
| CloudConvert.Task.result.files.url | String | The URL of the converted file. | 
| CloudConvert.Task.created_at | Date | The time the task was created. | 
| CloudConvert.Task.started_at | Date | Start time of the task. | 
| CloudConvert.Task.ended_at | Date | End time of the task. | 
| CloudConvert.Task.host_name | String | Name of the host used for the task. | 
| CloudConvert.Task.storage | String | Storage server used for the task. | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous task conducted on this file. | 
| CloudConvert.Task.links | String | API link for the task. | 


#### Command Example
`cloudconvert-check-status task_id=1`

#### Human Readable Output



### cloudconvert-export
***
Exports a converted file to a URL or a War Room entry.


#### Base Command

`cloudconvert-export`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| export_as | 'Whether to export the converted file to a URL or as a War Room entry. Possible values are: "url" and "war_room_entry". Note that if you export the file as a War Room entry, a URL of the file will also be generated.' | Required | 
| task_id | ID of the task that converted the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task ID of the scanned file. | 
| CloudConvert.Task.status | String | Status of the current task. | 
| CloudConvert.Task.message | String | Response message from the API. | 
| CloudConvert.Task.operation | String | The operation that was performed. | 
| CloudConvert.Task.result.files.filename | String | The file name of the exported file. | 
| CloudConvert.Task.result.files.size | Number | The size of the exported file. | 
| CloudConvert.Task.result.files.url | String | The URL of the exported file. | 
| CloudConvert.Task.created_at | Date | Time the task was created. | 
| CloudConvert.Task.started_at | Date | Start time of the task. | 
| CloudConvert.Task.ended_at | Date | End time of the task. | 
| CloudConvert.Task.host_name | String | Name of the host used for the task. | 
| CloudConvert.Task.storage | String | Storage server used for the task. | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous task conducted on this file. | 
| CloudConvert.Task.links | String | API link for the task. | 


#### Command Example
`cloudconvert-export task_id=1 export_as=url`

#### Human Readable Output


