Use the CloudConvert integration to convert your files to the required format.
This integration was integrated and tested with version v2 of CloudConvert.

## Configure CloudConvert in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cloudconvert-upload

***
Uploads a file for conversion.


#### Base Command

`cloudconvert-upload`

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
| CloudConvert.Task.result.files.filename | String | The name of the uploaded file. | 
| CloudConvert.Task.result.files.size | Number | The size of the uploaded file. | 
| CloudConvert.Task.result.files.url | String | The URL of the uploaded file. | 
| CloudConvert.Task.created_at | Date | Time the task was created. | 
| CloudConvert.Task.started_at | Date | Start time of the task. | 
| CloudConvert.Task.ended_at | Date | End time of the task. | 
| CloudConvert.Task.host_name | String | Name of the host used for the task. | 
| CloudConvert.Task.storage | String | Storage server used for the task. | 
| CloudConvert.Task.links | String | API link for the task. | 


#### Command Example

`cloudconvert-upload entry_id=@123`

#### Human Readable Output



### cloudconvert-convert

***
Converts an uploaded file to the required format.


#### Base Command

`cloudconvert-convert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | ID of the task that uploaded the file. | Required | 
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
Checks the status of an operation. Use the 'create_war_room_entry' argument to also create a war room entry of the file when checking on a download operation.


#### Base Command

`cloudconvert-check-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | ID of the task used to convert the file. | Required | 
| create_war_room_entry | Whether to create an entry in the War Room if the task is finished. Possible values are: "True" and "False". Use this argument to be able to check on a download operation in the War Room. | Optional | 


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



### cloudconvert-download

***
Downloads a converted file as a URL or a War Room entry.


#### Base Command

`cloudconvert-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| download_as | 'Whether to download the converted file as a URL or as a War Room entry. Possible values are: "url" and "war_room_entry". Note that if you download the file as a War Room entry, a URL of the file will also be generated.' | Required | 
| task_id | ID of the task that converted the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudConvert.Task.id | String | Unique task ID of the scanned file. | 
| CloudConvert.Task.status | String | Status of the current task. | 
| CloudConvert.Task.message | String | Response message from the API. | 
| CloudConvert.Task.operation | String | The operation that was performed. | 
| CloudConvert.Task.result.files.filename | String | The file name of the downloaded file. | 
| CloudConvert.Task.result.files.size | Number | The size of the downloaded file. | 
| CloudConvert.Task.result.files.url | String | The URL of the downloaded file. | 
| CloudConvert.Task.created_at | Date | Time the task was created. | 
| CloudConvert.Task.started_at | Date | Start time of the task. | 
| CloudConvert.Task.ended_at | Date | End time of the task. | 
| CloudConvert.Task.host_name | String | Name of the host used for the task. | 
| CloudConvert.Task.storage | String | Storage server used for the task. | 
| CloudConvert.Task.depends_on_task_ids | String | The ID of the previous task conducted on this file. | 
| CloudConvert.Task.links | String | API link for the task. | 


#### Command Example

`cloudconvert-download task_id=1 download_as=url`

#### Human Readable Output

