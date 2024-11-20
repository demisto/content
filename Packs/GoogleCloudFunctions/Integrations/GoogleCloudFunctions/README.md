Google Cloud Functions is an event-driven serverless compute platform that enables you to run your code locally or in the cloud without having to provision servers.
This integration was integrated and tested with API version 1 of Google Cloud Functions
## Configure Google Cloud Functions in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials_json | Service account private key file contents \(JSON\) | True |
| project_id | Default project ID | False |
| region | Default region | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-cloud-functions-list
***
Lists all Google Cloud functions.


##### Base Command

`google-cloud-functions-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The project ID the Google Cloud function is in. Default is the instance&#x27;s project. | Optional | 
| region | The region of the Google Cloud function. Default is all regions. You can get a full list of regions using the `google-cloud-function-regions-list` command. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudFunctions.Function.name | String | A user\-defined name of the Google Cloud function. | 
| GoogleCloudFunctions.Function.status | String | Status of the Google Cloud function deployment. The status can be: ACTIVE, OFFLINE, DEPLOY\_IN\_PROGRESS, DELETE\_IN\_PROGRESS, UNKNOWN. | 
| GoogleCloudFunctions.Function.labels | String | Labels associated with this Google Cloud function. | 
| GoogleCloudFunctions.Function.runtime | String | The time in which to run the Google Cloud function. | 


##### Command Example
```!google-cloud-functions-list```

##### Context Example
```
{
    "GoogleCloudFunctions": {
        "Function": [
            {
                "availableMemoryMb": 128,
                "entryPoint": "hello_world",
                "httpsTrigger": {
                    "url": "www.example.com"
                },
                "ingressSettings": "ALLOW_ALL",
                "labels": {
                    "deployment-tool": "console-cloud"
                },
                "name": "projects/project/locations/us-central1/functions/demisto-func",
                "runtime": "python37",
                "serviceAccountEmail": "email",
                "sourceUploadUrl": "",
                "status": "ACTIVE",
                "timeout": "60s",
                "updateTime": "2020-04-05T12:43:29.610Z",
                "versionId": "1"
            }
        ]
    }
}
```

##### Human Readable Output
### Functions in project "gcp-integrations" and region "us-central1"
|name|httpsTrigger|status|entryPoint|timeout|availableMemoryMb|serviceAccountEmail|updateTime|versionId|labels|sourceUploadUrl|runtime|ingressSettings|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| projects/project/locations/us-central1/functions/demisto-func | url: www.example.com | ACTIVE | hello_world | 60s | 128 | email | 2020-04-05T12:43:29.610Z | 1 | deployment-tool: console-cloud |  | python37 | ALLOW_ALL |


### google-cloud-function-regions-list
***
Lists all regions in the project.


##### Base Command

`google-cloud-function-regions-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The project ID the Google Cloud function is in. Default is the instance&#x27;s project. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudFunctions.Region.locationId | String | The location ID of the region. | 
| GoogleCloudFunctions.Region.name | String | The full name of the region. | 
| GoogleCloudFunctions.Region.labels | String | The labels for the region. | 


##### Command Example
```!google-cloud-function-regions-list```

##### Context Example
```
{
    "GoogleCloudFunctions": {
        "Region": [
            {
                "labels": {
                    "cloud.googleapis.com/region": "europe-west1"
                },
                "locationId": "europe-west1",
                "name": "projects/gcp-integrations/locations/europe-west1"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "europe-west3"
                },
                "locationId": "europe-west3",
                "name": "projects/gcp-integrations/locations/europe-west3"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "europe-west2"
                },
                "locationId": "europe-west2",
                "name": "projects/gcp-integrations/locations/europe-west2"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "us-central1"
                },
                "locationId": "us-central1",
                "name": "projects/gcp-integrations/locations/us-central1"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "us-east1"
                },
                "locationId": "us-east1",
                "name": "projects/gcp-integrations/locations/us-east1"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "us-east4"
                },
                "locationId": "us-east4",
                "name": "projects/gcp-integrations/locations/us-east4"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "asia-northeast1"
                },
                "locationId": "asia-northeast1",
                "name": "projects/gcp-integrations/locations/asia-northeast1"
            },
            {
                "labels": {
                    "cloud.googleapis.com/region": "asia-east2"
                },
                "locationId": "asia-east2",
                "name": "projects/gcp-integrations/locations/asia-east2"
            }
        ]
    }
}
```

##### Human Readable Output
### Regions in project "gcp-integrations"
|locationId|name|labels|
|---|---|---|
| europe-west1 | projects/gcp-integrations/locations/europe-west1 | cloud.googleapis.com/region: europe-west1 |
| europe-west3 | projects/gcp-integrations/locations/europe-west3 | cloud.googleapis.com/region: europe-west3 |
| europe-west2 | projects/gcp-integrations/locations/europe-west2 | cloud.googleapis.com/region: europe-west2 |
| us-central1 | projects/gcp-integrations/locations/us-central1 | cloud.googleapis.com/region: us-central1 |
| us-east1 | projects/gcp-integrations/locations/us-east1 | cloud.googleapis.com/region: us-east1 |
| us-east4 | projects/gcp-integrations/locations/us-east4 | cloud.googleapis.com/region: us-east4 |
| asia-northeast1 | projects/gcp-integrations/locations/asia-northeast1 | cloud.googleapis.com/region: asia-northeast1 |
| asia-east2 | projects/gcp-integrations/locations/asia-east2 | cloud.googleapis.com/region: asia-east2 |


### google-cloud-function-get-by-name
***
Gets the details of a specific Google Cloud function.


##### Base Command

`google-cloud-function-get-by-name`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The project ID the Google Cloud function is in. Default is the instance&#x27;s project. | Optional | 
| region | The region of the Google Cloud function. You can get a full list of regions using the `google-cloud-function-regions-list` command. Default is all regions. | Optional | 
| function_name | The name of the function. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudFunctions.Function.name | String | A user\-defined name of the Google Cloud function. | 
| GoogleCloudFunctions.Function.status | String | Status of the Google Cloud function deployment. The status can be ACTIVE, OFFLINE, DEPLOY\_IN\_PROGRESS, DELETE\_IN\_PROGRESS, UNKNOWN. | 
| GoogleCloudFunctions.Function.labels | String | The labels associated with this Google Cloud Function. | 
| GoogleCloudFunctions.Function.runtime | String | The time in which to run the Google Cloud function. | 


##### Command Example
```!google-cloud-function-get-by-name function_name="demisto-func"```

##### Context Example
```
{
    "GoogleCloudFunctions": {
        "Function": {
            "availableMemoryMb": 128,
            "entryPoint": "hello_world",
            "httpsTrigger": {
                "url": ""
            },
            "ingressSettings": "ALLOW_ALL",
            "labels": {
                "deployment-tool": "console-cloud"
            },
            "name": "projects/project/locations/us-central1/functions/demisto-func",
            "runtime": "python37",
            "serviceAccountEmail": "email",
            "sourceUploadUrl": "",
            "status": "ACTIVE",
            "timeout": "60s",
            "updateTime": "2020-04-05T12:43:29.610Z",
            "versionId": "1"
        }
    }
}
```

##### Human Readable Output
### Here are the details for demisto-func:
|name|httpsTrigger|status|entryPoint|timeout|availableMemoryMb|serviceAccountEmail|updateTime|versionId|labels|sourceUploadUrl|runtime|ingressSettings|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| projects/project/locations/us-central1/functions/demisto-func | url: www.example.com | ACTIVE | hello_world | 60s | 128 | email | 2020-04-05T12:43:29.610Z | 1 | deployment-tool: console-cloud |  | python37 | ALLOW_ALL |


### google-cloud-function-execute
***
Executes a Google Cloud function.


##### Base Command

`google-cloud-function-execute`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| function_name | The name of the Google Cloud function to execute. | Required | 
| region | The region of the Google Cloud function. Default is all regions. You can get a full list of regions using the `google-cloud-function-regions-list` command. | Optional | 
| parameters | The Google Cloud function parameters in a key:value format. Multiple parameters should be comma-separated (i.e., key1:value1,key2:value2). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudFunctions.Execution.executionId | String | Execution ID of the Google Cloud function invocated. | 
| GoogleCloudFunctions.Execution.result | String | Result populated for successful execution of a synchronous Google Cloud function. It will not be populated if the Google Cloud function does not return a result through context. | 
| GoogleCloudFunctions.Execution.error | String | Either a system or user\-function generated error. Set if the execution was not successful. | 


##### Command Example
```!google-cloud-function-execute function_name=demisto-func parameters=message:hell\"oThere```

##### Context Example
```
{
    "GoogleCloudFunctions": {
        "Execution": {
            "executionId": "xp9hifb4y996",
            "result": "hell\"oThere"
        }
    }
}
```

##### Human Readable Output
### Execution details for demisto-func:
|executionId|result|
|---|---|
| xp9hifb4y996 | hell"oThere |
