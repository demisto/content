# Cado Response Integration for Cortex XSOAR

Automate data collection. Process data at cloud speed. Analyze with purpose.
This integration was integrated and tested with version 1.2.0 of CadoResponse

## Configure Cado Response in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cado Response Instance | The URL for your Cado Response Instance | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Default Cado Response Project | Provides a fallback Project ID from Cado Response if you forget to add an ID to a command. If you're not sure, don't change\! | True |
| Default AWS Region | Provides a default AWS region to fallback to if you forget to add it to a command. | True |
| Default S3 Bucket | Provides a default S3 bucket to fallback to if you forget to add it to a command. | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

#### Command example
```!cado-create-project project_name="Project Name" description="Project Description"```
#### Context Example
```json
{
    "CadoResponse": {
        "Project": {
            "id": 1,
            "msg": "Created"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|msg|
>|---|---|
>| 1 | Created |


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

#### Command example
```!cado-list-project limit=100```
#### Context Example
```json
{
    "CadoResponse": {
        "Projects": {
            "caseName": "Project Name_XSOAR",
            "created": "2022-01-17T12:21:46.613814",
            "deleted": false,
            "description": "This is a project in Cado Response created through Cortex XSOAR!",
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
        }
    }
}
```

#### Human Readable Output

>### Results
>|caseName|created|deleted|description|id|status|users|
>|---|---|---|---|---|---|---|
>| Project Name_XSOAR | 2022-01-17T12:21:46.613814 | false | This is a project in Cado Response created through Cortex XSOAR! | 1 | Pending | {'display_name': 'admin', 'id': 1, 'is_admin': True, 'login_type': 0, 'username': 'admin'} |


#### Command example
```!cado-list-project project_id=1```
#### Context Example
```json
{
    "CadoResponse": {
        "Projects": {
            "caseName": "Project Name_XSOAR",
            "created": "2022-01-17T12:21:46.613814",
            "deleted": false,
            "description": "This is a project in Cado Response created through Cortex XSOAR!",
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
        }
    }
}
```

#### Human Readable Output

>### Results
>|caseName|created|deleted|description|id|status|users|
>|---|---|---|---|---|---|---|
>| Project Name_XSOAR | 2022-01-17T12:21:46.613814 | false | This is a project in Cado Response created through Cortex XSOAR! | 1 | Pending | {'display_name': 'admin', 'id': 1, 'is_admin': True, 'login_type': 0, 'username': 'admin'} |


### cado-get-pipeline
***
Get pipeline details from Cado Response


#### Base Command

`cado-get-pipeline`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The id of the pipeline to retrieve. | Optional | 
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

#### Command example
```!cado-get-pipeline project_id=1 pipeline_id=1```
#### Context Example

```json
{
    "CadoResponse": {
        "Pipeline": {
           	"pipeline_id": 1,
			"pipeline_type": "processing",
    		"created": "2022-01-17T12:22:00.843869",
    		"evidence_id": 1,
    		"project_id": 1,
    		"is_terminated": false,
			"subtasks": [
      			{
					"execution_duration": 0,
					"finish_time": 0,
					"name": "Triage: Attaching disk for local data storage.",
					"name_key": "infrastructure.check_ssd",
					"notification_level": "Info",
					"progress_text": [],
					"start_time": 0,
					"state": "PENDING",
					"task_id": "3699827f-63c4-4408-88a4-0ae899187ed3",
					"total_stages": null
				  }
			],
			"summary": {
			  "cancelled": 0,
			  "failure": 0,
			  "pending": 14,
			  "running": 0,
			  "success": 0,
			  "total": 14
			}
        }
    }

}
```

#### Human Readable Output
>### Results
>|pipeline_id|pipeline_type|created|evidence_id|project_id|is_terminated|summary|subtask|
>|---|---|---|---|---|---|---|---|
>| 1 | processing | 2022-01-17T12:22:00.843869 | 1 | 1 | false |"execution_duration": 0,<br />"finish_time": 0,<br />"name": "Triage: attaching disk for local data storage.",<br />"name_key": infrastructure.check_ssd",<br />"notification_level": "Info",<br />"progress_text": [],<br />"start_time": 0,<br />"state": "PENDING",<br />"task_id": "3699827f-63c4-4408-88a4-0ae899187ed3",<br />"total_stages": null<br />|"cancelled": 0,<br />"failure": 0,<br />"pending": 14,<br />"running": 0,<br />"success": 0,<br />"total": 14<br />|

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

#### Command example
```!cado-list-ec2 project_id=1 region="us-east-1" limit=100```
#### Context Example
```json
{
    "CadoResponse": {
        "EC2Instances": [
            {
                "_placement": "us-east-1c",
                "_state": "stopped",
                "celery_worker_name": null,
                "deployment_id": null,
                "evidence_id": null,
                "id": "i-00000000000",
                "instance_name": "Instance",
                "instance_type": "t3a.2xlarge",
                "ip_address": null,
                "launch_time": "Thu, 25 Mar 2021 18:38:13 GMT",
                "processing_type": null,
                "project_id": null,
                "queue_name": null,
                "region": {
                    "name": "us-east-1"
                },
                "worker_used": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|_placement|_state|celery_worker_name|deployment_id|evidence_id|id|instance_name|instance_type|ip_address|launch_time|processing_type|project_id|queue_name|region|worker_used|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| us-east-1c | stopped |  |  |  | i-00000000000 | Instance | t3a.2xlarge |  | Thu, 25 Mar 2021 18:38:13 GMT |  |  |  | name: us-east-1 |  |


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

#### Command example
```!cado-list-s3 project_id=1 limit=100```
#### Context Example
```json
{
    "CadoResponse": {
        "S3Buckets": {
            "buckets": [
                "bucket",
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|buckets|
>|---|
>| bucket |


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

#### Command example
```!cado-trigger-ec2 project_id=1 instance_id="i-00000000000" region="us-east-1" bucket="bucket" compress=true include_disks=true include_hash=true include_logs=true include_screenshot=true```
#### Context Example
```json
{
    "CadoResponse": {
        "EC2Acquistion": {
            "created": "2022-01-17T12:21:59.084282",
            "evidence_id": 0,
            "name": "Acquiring i-00000000000",
            "pipeline_id": 1,
            "pipeline_type": "acquisition",
            "project_id": 1,
            "subtasks": [
                {
                    "id": "1587a9c9-c02c-464b-a6f7-d4b7e720bd93"
                },
                {
                    "id": "4f798bf8-c7d3-427c-9498-10a85cfe3978"
                },
                {
                    "id": "c5fa26f1-e282-47a6-8335-1160766e089b"
                },
                {
                    "id": "82ec9a7e-47ac-4539-9623-166a44a59d0f"
                },
                {
                    "id": "88151005-a999-422e-b4cb-9e76699d6e42"
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
>| 2022-01-17T12:21:59.084282 | 0 | Acquiring i-00000000000 | 1 | acquisition | 1 | {'id': '1587a9c9-c02c-464b-a6f7-d4b7e720bd93'},<br/>{'id': '4f798bf8-c7d3-427c-9498-10a85cfe3978'},<br/>{'id': 'c5fa26f1-e282-47a6-8335-1160766e089b'},<br/>{'id': '82ec9a7e-47ac-4539-9623-166a44a59d0f'},<br/>{'id': '88151005-a999-422e-b4cb-9e76699d6e42'} | 1 |


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

#### Command example
```!cado-trigger-s3 project_id=1 bucket="bucket" file_name="file"```
#### Context Example
```json
{
    "CadoResponse": {
        "S3Acquisition": {
            "created": "2022-01-17T12:22:00.843869",
            "evidence_id": 1,
            "name": "",
            "pipeline_id": 2,
            "pipeline_type": "processing",
            "project_id": 1,
            "subtasks": [
                {
                    "id": "3699827f-63c4-4408-88a4-0ae899187ed3"
                },
                {
                    "id": "727e2072-8bf7-4847-89ea-9447f5fd8fd0"
                },
                {
                    "id": "857d48b8-abaf-4ea6-b159-d25c9784b837"
                },
                {
                    "id": "533f7deb-74bc-4ffb-b81f-788ed714bead"
                },
                {
                    "id": "3f1defde-3986-4292-a423-1bef62d4c52b"
                },
                {
                    "id": "e41a0934-266b-4868-9a7d-5f083b1efcc1"
                },
                {
                    "id": "75411e10-46e9-41dd-8bf7-9b5fbdc8df71"
                },
                {
                    "id": "0afbf2f4-fbf3-4305-ad9f-b19d30f4b17c"
                },
                {
                    "id": "ca063c7b-1135-4922-8542-49f40ce71449"
                },
                {
                    "id": "67fdb0ea-dcee-4f65-a003-4f40fcd567fb"
                },
                {
                    "id": "1437ec33-6af2-4eb8-9c43-e071dcb7e0ac"
                },
                {
                    "id": "06db4dcc-57fd-48bc-bb34-5bd8f2da0a0d"
                },
                {
                    "id": "e3cc930e-9a60-46c3-97a1-611824c24437"
                },
                {
                    "id": "ad2c8877-39e7-4bff-9756-81278802ee76"
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
>| 2022-01-17T12:22:00.843869 | 1 |  | 2 | processing | 1 | {'id': '3699827f-63c4-4408-88a4-0ae899187ed3'},<br/>{'id': '727e2072-8bf7-4847-89ea-9447f5fd8fd0'},<br/>{'id': '857d48b8-abaf-4ea6-b159-d25c9784b837'},<br/>{'id': '533f7deb-74bc-4ffb-b81f-788ed714bead'},<br/>{'id': '3f1defde-3986-4292-a423-1bef62d4c52b'},<br/>{'id': 'e41a0934-266b-4868-9a7d-5f083b1efcc1'},<br/>{'id': '75411e10-46e9-41dd-8bf7-9b5fbdc8df71'},<br/>{'id': '0afbf2f4-fbf3-4305-ad9f-b19d30f4b17c'},<br/>{'id': 'ca063c7b-1135-4922-8542-49f40ce71449'},<br/>{'id': '67fdb0ea-dcee-4f65-a003-4f40fcd567fb'},<br/>{'id': '1437ec33-6af2-4eb8-9c43-e071dcb7e0ac'},<br/>{'id': '06db4dcc-57fd-48bc-bb34-5bd8f2da0a0d'},<br/>{'id': 'e3cc930e-9a60-46c3-97a1-611824c24437'},<br/>{'id': 'ad2c8877-39e7-4bff-9756-81278802ee76'} | 1 |
