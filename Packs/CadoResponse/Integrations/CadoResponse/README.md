Automate data collection. Process data at cloud speed. Analyze with purpose.
This integration was integrated and tested with version 1.1.0 of CadoResponse

## Configure Cado Response on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cado Response.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Cado Response Instance | The URL for your Cado Response Instance | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Default Cado Response Project | Provides a fallback Project ID from Cado Response if you forget to add an ID to a command. If you're not sure, don't change\! | True |
    | Default AWS Region | Provides a default AWS region to fallback to if you forget to add it to a command. | True |
    | Default S3 Bucket | Provides a default S3 bucket to fallback to if you forget to add it to a command. | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cado-create-project
***
Create a project in Cado Response


#### Base Command

`cado-create-project`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Name of the project. | Required | 
| project_description | Description for the project. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.Project.id | Number | The Project ID of the newly created project | 


#### Command Example
``` ```

#### Human Readable Output



### cado-list-project
***
Get a list of projects from Cado Response


#### Base Command

`cado-list-project`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | ID of the project to retrive. | Optional | 
| limit | Limit results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.Projects.id | Number | ID of the retrieved project | 
| CadoResponse.Projects.caseName | String | Name of the retrieved project | 
| CadoResponse.Projects.description | String | Description of the retrieved project | 
| CadoResponse.Projects.users | Array | Array of users assigned to the retrieved project | 
| CadoResponse.Projects.created | Date | Creation date of the project | 


#### Command Example
```!cado-list-project limit=100```

#### Context Example
```json
{
    "CadoResponse": {
        "Projects": [
            {
                "caseName": "test",
                "created": "2021-12-15T11:37:14.525699",
                "deleted": false,
                "description": "",
                "id": 1,
                "status": "Pending",
                "users": [
                    {
                        "display_name": "admin",
                        "id": 1,
                        "is_admin": true,
                        "login_type": 0,
                        "username": "admin"
                    }
                ]
            },
            {
                "caseName": "Project Name_XSOAR",
                "created": "2021-12-21T14:59:07.420844",
                "deleted": false,
                "description": "This is a project in Cado Response created through Cortex XSOAR!",
                "id": 2,
                "status": "Pending",
                "users": [
                    {
                        "display_name": "admin",
                        "id": 1,
                        "is_admin": true,
                        "login_type": 0,
                        "username": "admin"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|caseName|created|deleted|description|id|status|users|
>|---|---|---|---|---|---|---|
>| test | 2021-12-15T11:37:14.525699 | false |  | 1 | Pending | {'display_name': 'admin', 'id': 1, 'is_admin': True, 'login_type': 0, 'username': 'admin'} |
>| Project Name_XSOAR | 2021-12-21T14:59:07.420844 | false | This is a project in Cado Response created through Cortex XSOAR! | 2 | Pending | {'display_name': 'admin', 'id': 1, 'is_admin': True, 'login_type': 0, 'username': 'admin'} |


### cado-get-pipeline
***
Get pipeline details from Cado Response


#### Base Command

`cado-get-pipeline`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The id of the pipeline to retrieve. | Required | 
| project_id | The id of the project the pipeline belongs to. | Optional | 
| limit | Limit results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.Pipeline.pipeline_id | Number | The ID of the retrieved pipeline | 
| CadoResponse.Pipeline.pipeline_type | String | The type of pipeline that was retrieved | 
| CadoResponse.Pipeline.created | Date | The date at which the retrieved pipeline was started | 
| CadoResponse.Pipeline.evidence_id | Number | The evidence ID linked to the retrieved pipeline | 
| CadoResponse.Pipeline.project_id | Number | The ID of the project the pipeline belongs to | 
| CadoResponse.Pipeline.is_terminated | Boolean | A boolean which says if the retrieved pipeline has been finished/terminated | 
| CadoResponse.Pipeline.summary | Array | An array of values containing the cancelled, failed, pending, running and successful pipeline subtasks | 
| CadoResponse.Pipeline.subtask | Array | An array of tasks in the retrieved pipeline | 


#### Command Example
```!cado-get-pipeline project_id=1 pipeline_id=1```

#### Context Example
```json
{
    "CadoResponse": {
        "Pipelines": {
            "can_be_terminated": false,
            "created": "2021-12-15T11:38:09.061520",
            "evidence_id": 1,
            "evidence_name": "cado-test-george_",
            "name": "",
            "pipeline_id": 1,
            "pipeline_type": "processing",
            "project_id": 1,
            "project_name": "test",
            "subtasks": [
                {
                    "execution_duration": 5,
                    "finish_time": 1639568640.9770923,
                    "name": "Analysis > Timeline: Building MACB timeline events.",
                    "name_key": "timeline_builder.macb_events",
                    "notification_level": "Info",
                    "progress_text": [
                        "Error: Unrecoverable error: Internal error, see messages tab or application logs for more details. Raw error was: Command '['./binaries/linux/plaso_compiled_linux_custom/fast_timeline', '/mnt/nvme/ft_uploads_1/cado-test-george_/test_folder/test.vmdk', '--output_file', './ft_uploads_1//mnt/nvme/ft_uploads_1/cado-test-george_/test_folder/test.vmdk_file.csv']' returned non-zero exit status 1."
                    ],
                    "start_time": 1639568635.256025,
                    "state": "FAILURE",
                    "task_id": "5e8e8a32-8136-4d09-861b-d1c80a329c52",
                    "total_stages": null
                },
                {
                    "execution_duration": 5,
                    "finish_time": 1639568635.2399778,
                    "name": "Triage: Extracting evidence and any additional archives.",
                    "name_key": "extraction.disk_extraction",
                    "notification_level": "Info",
                    "progress_text": [
                        "1 additional artifacts contained inside the original evidence could not be extracted because the archive was encrypted.",
                        "1 additional artifacts contained inside the original evidence could not be extracted because of a problem with a third-party tool."
                    ],
                    "start_time": 1639568629.5225127,
                    "state": "SUCCESS",
                    "task_id": "8a74f577-0739-45f0-8ac3-ec48278a9cf2",
                    "total_stages": null
                },
                {
                    "execution_duration": 6,
                    "finish_time": 1639568629.5098612,
                    "name": "Acquisition > Data Transfer: Downloading data from the cloud storage.",
                    "name_key": "acquisition.from_cloud_storage",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 1639568622.744932,
                    "state": "SUCCESS",
                    "task_id": "fee7218f-6525-4d42-b022-f53e979bf960",
                    "total_stages": null
                },
                {
                    "execution_duration": 1,
                    "finish_time": 1639568622.6965997,
                    "name": "Triage: Attaching disk for local data storage.",
                    "name_key": "infrastructure.check_ssd",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 1639568621.4006076,
                    "state": "SUCCESS",
                    "task_id": "e9fc4a42-e556-4fc6-bb74-74121bfb9441",
                    "total_stages": null
                },
                {
                    "execution_duration": 129,
                    "finish_time": 1639568418.3605351,
                    "name": "Acquisition > Setup: Spinning up processing worker machine.",
                    "name_key": "infrastructure.spinup_worker_machine",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 1639568289.1548634,
                    "state": "SUCCESS",
                    "task_id": "8d6c4604-86e8-4ee7-b695-8717fc2508a8",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Acquisition > Data Transfer: Copying extracted data to EFS.",
                    "name_key": "acquisition.copy_to_efs",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "07122468-5347-4ce9-bdba-b3fbf79374c9",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis > Timeline: Adding details to timeline events.",
                    "name_key": "timeline_builder.log2_timeline",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "0cdeba09-86c3-40f7-93d0-86c28d737528",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Triage: Obtaining disk information.",
                    "name_key": "extraction.disk_info",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "ee4f6aab-2b7a-4f40-bde9-5d6a7fe938ad",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Running Yara rules.",
                    "name_key": "plugins.yara",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "0f5e7361-3a45-41aa-a82b-cd1f844b6439",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Hashing files.",
                    "name_key": "plugins.hash_files",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "d61ac54f-7655-490c-a883-1bd564353733",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Looking for PII.",
                    "name_key": "plugins.detect_pii",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "42a4dd46-16af-49e1-ba6c-278e5f75e986",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis > Timeline: Adding parsed log details to timeline events.",
                    "name_key": "timeline_builder.custom_logs",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "79a01c6b-5361-4fbe-9fcb-5008af39d44f",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Hashing evidence item.",
                    "name_key": "plugins.hash_evidence",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "a4d4314f-1219-471b-9e18-c571b9c634f8",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Enhancing analysis using VirusTotal.",
                    "name_key": "plugins.intel",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "3d1d2520-f146-4ce9-aa9b-c46ee626e0e8",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Extracting file text strings.",
                    "name_key": "plugins.strings",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "d44de48a-e8ff-424f-b4af-647f639b7be6",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Analysis: Searching for IoCs.",
                    "name_key": "plugins.ioc_extract",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "7271b5d2-6306-44ae-b70b-1178f4124150",
                    "total_stages": null
                },
                {
                    "execution_duration": 0,
                    "finish_time": 0,
                    "name": "Shutdown: Stopping worker machine.",
                    "name_key": "infrastructure.self_shutdown",
                    "notification_level": "Info",
                    "progress_text": [],
                    "start_time": 0,
                    "state": "CANCELLED",
                    "task_id": "c9a5536b-967e-40ea-9628-8aff637a75dc",
                    "total_stages": null
                }
            ],
            "summary": {
                "cancelled": 12,
                "failure": 1,
                "pending": 0,
                "running": 0,
                "success": 4,
                "total": 17
            },
            "terminated": true,
            "user_id": 1,
            "user_name": "admin"
        }
    }
}
```

#### Human Readable Output

>### Results
>|can_be_terminated|created|evidence_id|evidence_name|name|pipeline_id|pipeline_type|project_id|project_name|subtasks|summary|terminated|user_id|user_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-12-15T11:38:09.061520 | 1 | cado-test-george_ |  | 1 | processing | 1 | test | {'execution_duration': 5, 'finish_time': 1639568640.9770923, 'name': 'Analysis > Timeline: Building MACB timeline events.', 'name_key': 'timeline_builder.macb_events', 'notification_level': 'Info', 'progress_text': ["Error: Unrecoverable error: Internal error, see messages tab or application logs for more details. Raw error was: Command '['./binaries/linux/plaso_compiled_linux_custom/fast_timeline', '/mnt/nvme/ft_uploads_1/cado-test-george_/test_folder/test.vmdk', '--output_file', './ft_uploads_1//mnt/nvme/ft_uploads_1/cado-test-george_/test_folder/test.vmdk_file.csv']' returned non-zero exit status 1."], 'start_time': 1639568635.256025, 'state': 'FAILURE', 'task_id': '5e8e8a32-8136-4d09-861b-d1c80a329c52', 'total_stages': None},<br/>{'execution_duration': 5, 'finish_time': 1639568635.2399778, 'name': 'Triage: Extracting evidence and any additional archives.', 'name_key': 'extraction.disk_extraction', 'notification_level': 'Info', 'progress_text': ['1 additional artifacts contained inside the original evidence could not be extracted because the archive was encrypted.', '1 additional artifacts contained inside the original evidence could not be extracted because of a problem with a third-party tool.'], 'start_time': 1639568629.5225127, 'state': 'SUCCESS', 'task_id': '8a74f577-0739-45f0-8ac3-ec48278a9cf2', 'total_stages': None},<br/>{'execution_duration': 6, 'finish_time': 1639568629.5098612, 'name': 'Acquisition > Data Transfer: Downloading data from the cloud storage.', 'name_key': 'acquisition.from_cloud_storage', 'notification_level': 'Info', 'progress_text': [], 'start_time': 1639568622.744932, 'state': 'SUCCESS', 'task_id': 'fee7218f-6525-4d42-b022-f53e979bf960', 'total_stages': None},<br/>{'execution_duration': 1, 'finish_time': 1639568622.6965997, 'name': 'Triage: Attaching disk for local data storage.', 'name_key': 'infrastructure.check_ssd', 'notification_level': 'Info', 'progress_text': [], 'start_time': 1639568621.4006076, 'state': 'SUCCESS', 'task_id': 'e9fc4a42-e556-4fc6-bb74-74121bfb9441', 'total_stages': None},<br/>{'execution_duration': 129, 'finish_time': 1639568418.3605351, 'name': 'Acquisition > Setup: Spinning up processing worker machine.', 'name_key': 'infrastructure.spinup_worker_machine', 'notification_level': 'Info', 'progress_text': [], 'start_time': 1639568289.1548634, 'state': 'SUCCESS', 'task_id': '8d6c4604-86e8-4ee7-b695-8717fc2508a8', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Acquisition > Data Transfer: Copying extracted data to EFS.', 'name_key': 'acquisition.copy_to_efs', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '07122468-5347-4ce9-bdba-b3fbf79374c9', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis > Timeline: Adding details to timeline events.', 'name_key': 'timeline_builder.log2_timeline', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '0cdeba09-86c3-40f7-93d0-86c28d737528', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Triage: Obtaining disk information.', 'name_key': 'extraction.disk_info', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': 'ee4f6aab-2b7a-4f40-bde9-5d6a7fe938ad', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Running Yara rules.', 'name_key': 'plugins.yara', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '0f5e7361-3a45-41aa-a82b-cd1f844b6439', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Hashing files.', 'name_key': 'plugins.hash_files', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': 'd61ac54f-7655-490c-a883-1bd564353733', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Looking for PII.', 'name_key': 'plugins.detect_pii', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '42a4dd46-16af-49e1-ba6c-278e5f75e986', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis > Timeline: Adding parsed log details to timeline events.', 'name_key': 'timeline_builder.custom_logs', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '79a01c6b-5361-4fbe-9fcb-5008af39d44f', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Hashing evidence item.', 'name_key': 'plugins.hash_evidence', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': 'a4d4314f-1219-471b-9e18-c571b9c634f8', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Enhancing analysis using VirusTotal.', 'name_key': 'plugins.intel', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '3d1d2520-f146-4ce9-aa9b-c46ee626e0e8', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Extracting file text strings.', 'name_key': 'plugins.strings', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': 'd44de48a-e8ff-424f-b4af-647f639b7be6', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Analysis: Searching for IoCs.', 'name_key': 'plugins.ioc_extract', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': '7271b5d2-6306-44ae-b70b-1178f4124150', 'total_stages': None},<br/>{'execution_duration': 0, 'finish_time': 0, 'name': 'Shutdown: Stopping worker machine.', 'name_key': 'infrastructure.self_shutdown', 'notification_level': 'Info', 'progress_text': [], 'start_time': 0, 'state': 'CANCELLED', 'task_id': 'c9a5536b-967e-40ea-9628-8aff637a75dc', 'total_stages': None} | cancelled: 12<br/>failure: 1<br/>pending: 0<br/>running: 0<br/>success: 4<br/>total: 17 | true | 1 | admin |


### cado-list-ec2
***
Get a list of EC2 instances in a region


#### Base Command

`cado-list-ec2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS region to list instances in. | Required | 
| project_id | The ID of the project you wish to attach the acquisition to. | Optional | 
| limit | Limit results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.EC2Instances.id | Number | AWS ID of the EC2 Instance | 
| CadoResponse.EC2Instances.instance_name | String | Name of the EC2 Instance | 
| CadoResponse.EC2Instances.instance_type | String | AWS Type of the EC2 instance | 
| CadoResponse.EC2Instances.region | String | AWS region of the EC2 instance | 


#### Command Example
``` ```

#### Human Readable Output



### cado-list-s3
***
Get a list of S3 buckets


#### Base Command

`cado-list-s3`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project you wish to attach the acquisition to. | Optional | 
| limit | Limit results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.S3Buckets.buckets | Array | An array of S3 buckets available to the project | 


#### Command Example
``` ```

#### Human Readable Output



### cado-trigger-ec2
***
Trigger a disk acquisition and processing pipeline in Cado Response for a given EC2 instance


#### Base Command

`cado-trigger-ec2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project you wish to attach the acquisition to. | Optional | 
| instance_id | ID of the EC2 instance to acquire. | Required | 
| region | AWS region in which the EC2 instance is located. | Optional | 
| bucket | S3 bucket where the uploaded disk image resides. | Optional | 
| compress | Flag indicating if disk compression is enabled. | Optional | 
| include_disks | Flag indicating if we include disk images in the acquisition. | Optional | 
| include_hash | Flag indicating if we calculate the hash of the disk. | Optional | 
| include_logs | Flag indicating if we include system logs in the acquisition. | Optional | 
| include_screenshot | Flag indicating if we include a screenshot of the system in the acquisition. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.EC2Acquisition.pipeline_id | Number | ID of the created pipeline | 


#### Command Example
``` ```

#### Human Readable Output



### cado-trigger-s3
***
Trigger a disk acquisition and processing pipeline in Cado Response for a given file in an S3 bucket


#### Base Command

`cado-trigger-s3`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project you wish to attach the acquisition to. | Optional | 
| bucket | The S3 bucket name containing the file. | Required | 
| file_name | The name of the file to process. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CadoResponse.S3Acquisition.pipeline_id | Number | ID of the created pipeline | 


#### Command Example
```!cado-trigger-s3 project_id=1 bucket="my-bucket" file_name="my-file.dd.gz"```

#### Context Example
```json
{
    "CadoResponse": {
        "S3Acquisition": {
            "created": "2021-12-22T10:25:58.759346",
            "evidence_id": 3,
            "name": "",
            "pipeline_id": 5,
            "pipeline_type": "processing",
            "project_id": 1,
            "subtasks": [
                {
                    "id": "c9c75aac-65ba-4d12-8f61-b122976de9ca"
                },
                {
                    "id": "c2cec24c-f418-4997-8cef-250def73daf1"
                },
                {
                    "id": "33bb6867-8740-417b-a245-b3388614ca2e"
                },
                {
                    "id": "79babdfd-403c-427d-a244-5c31865da0ad"
                },
                {
                    "id": "6b33293d-cdcf-4f8e-ac92-abb6f7c56c94"
                },
                {
                    "id": "2800231b-e671-4bc7-b7e3-e37a6da60926"
                },
                {
                    "id": "6d497470-631b-46ea-b69c-bdcf068585c0"
                },
                {
                    "id": "b8adcd9d-1186-4d36-a4fe-8432933cddec"
                },
                {
                    "id": "e90b2d5b-d219-491f-ab7b-db5d12a4d06f"
                },
                {
                    "id": "8eb8fbd5-7502-4d8e-85b2-296b94532e94"
                },
                {
                    "id": "cf927417-15e1-41a2-b935-16caacdcb516"
                },
                {
                    "id": "6cc12035-e852-4700-803d-fed5a8f8fcc6"
                },
                {
                    "id": "15490a7a-9d25-47f0-9b75-4dcffb4847d8"
                },
                {
                    "id": "2705c77d-1f80-498d-9db8-c9f0df720113"
                },
                {
                    "id": "7ada785e-63c7-4d27-a197-3c3e53d75b7e"
                },
                {
                    "id": "86dedbc9-2717-4af2-813b-ed81c8c3793e"
                },
                {
                    "id": "537aaf7a-4cdd-4301-a733-36e3a7d95d0f"
                }
            ],
            "user_id": 1
        }
    }
}
```

#### Human Readable Output

>### Results
>|created|evidence_id|name|pipeline_id|pipeline_type|project_id|subtasks|user_id|
>|---|---|---|---|---|---|---|---|
>| 2021-12-22T10:25:58.759346 | 3 |  | 5 | processing | 1 | {'id': 'c9c75aac-65ba-4d12-8f61-b122976de9ca'},<br/>{'id': 'c2cec24c-f418-4997-8cef-250def73daf1'},<br/>{'id': '33bb6867-8740-417b-a245-b3388614ca2e'},<br/>{'id': '79babdfd-403c-427d-a244-5c31865da0ad'},<br/>{'id': '6b33293d-cdcf-4f8e-ac92-abb6f7c56c94'},<br/>{'id': '2800231b-e671-4bc7-b7e3-e37a6da60926'},<br/>{'id': '6d497470-631b-46ea-b69c-bdcf068585c0'},<br/>{'id': 'b8adcd9d-1186-4d36-a4fe-8432933cddec'},<br/>{'id': 'e90b2d5b-d219-491f-ab7b-db5d12a4d06f'},<br/>{'id': '8eb8fbd5-7502-4d8e-85b2-296b94532e94'},<br/>{'id': 'cf927417-15e1-41a2-b935-16caacdcb516'},<br/>{'id': '6cc12035-e852-4700-803d-fed5a8f8fcc6'},<br/>{'id': '15490a7a-9d25-47f0-9b75-4dcffb4847d8'},<br/>{'id': '2705c77d-1f80-498d-9db8-c9f0df720113'},<br/>{'id': '7ada785e-63c7-4d27-a197-3c3e53d75b7e'},<br/>{'id': '86dedbc9-2717-4af2-813b-ed81c8c3793e'},<br/>{'id': '537aaf7a-4cdd-4301-a733-36e3a7d95d0f'} | 1 |

