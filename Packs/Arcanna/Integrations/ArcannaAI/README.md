Arcanna integration for using the power of AI in SOC
This integration was integrated and tested with version 1.0 and above of Arcanna.AI

## Configure Arcanna.AI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Arcanna.AI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | URL of Arcanna API | True |
    | API Key | Api Key for Arcanna API | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Default Arcanna Job Id | Default Arcanna Job Id | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### arcanna-get-jobs
***
Get jobs list


#### Base Command

`arcanna-get-jobs`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Jobs.job_id | Int | Arcanna Job id | 
| Arcanna.Jobs.data_type | String | Arcanna Job type | 
| Arcanna.Jobs.title | String | Arcanna Job title | 
| Arcanna.Jobs.status | String | Arcanna job status | 


#### Command Example
```!arcanna-get-jobs```

#### Context Example
```json
{
    "Arcanna": {
        "Jobs": [
            {
                "data_type": "es",
                "job_id": 1101,
                "status": "IDLE",
                "title": "cortex"
            }
        ]
    }
}
```

#### Human Readable Output

>### Arcanna Jobs
>|job_id|title|data_type|status|
>|---|---|---|---|
>| 1101 | cortex | es | IDLE |


### arcanna-send-event
***
Sends a raw event to Arcanna


#### Base Command

`arcanna-send-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | arcanna running job_id. | Optional | 
| event_json | json event for arcanna to inference. | Required | 
| title | event title. | Required | 
| severity | event severity. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Event.event_id | Number | Arcanna event id | 
| Arcanna.Event.status | String | Arcanna ingestion status | 
| Arcanna.Event.ingest_timestamp | date | Arcanna ingestion timestamp | 
| Arcanna.Event.error_message | String | Arcanna error message if any | 



### arcanna-get-event-status
***
Retrieves Arcanna Inference result


#### Base Command

`arcanna-get-event-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Arcanna Job Id. | Optional | 
| event_id | Arcanna generated unique event id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Event.event_id | String | Arcanna event id | 
| Arcanna.Event.ingest_timestamp | String | Arcanna ingestion timestamp | 
| Arcanna.Event.confidence_level | Number | Arcanna ML confidence_level | 
| Arcanna.Event.result | String | Arcanna event  result | 
| Arcanna.Event.is_duplicated | boolean | Arcanna signalling if event is duplicated by another alert | 
| Arcanna.Event.error_message | String | Arcanna error message if any | 
| Arcanna.Event.status | String | arcanna event status | 


#### Command Example
```!arcanna-get-event-status job_id="1102" event_id="11021484171024"```

#### Context Example
```json
{
    "Arcanna": {
        "Event": {
            "confidence_level": 0.9999940395355225,
            "error_message": null,
            "event_id": "11021484171024",
            "ingest_timestamp": "2021-07-02T10:16:12.148417",
            "is_duplicated": false,
            "result": "drop_alert",
            "status": "OK"
        }
    }
}
```

#### Human Readable Output

>## {'event_id': '11021484171024', 'ingest_timestamp': '2021-07-02T10:16:12.148417', 'status': 'OK', 'confidence_level': 0.9999940395355225, 'result': 'drop_alert', 'is_duplicated': False, 'error_message': None}

### arcanna-get-default-job-id
***
Retrieves Arcanna Default Job id


#### Base Command

`arcanna-get-default-job-id`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Default_Job_Id | String | Arcanna Default Job id | 


#### Command Example
```!arcanna-get-default-job-id```

#### Context Example
```json
{
    "Arcanna": {
        "Default_Job_Id": "1102"
    }
}
```

#### Human Readable Output

>## 1102

### arcanna-set-default-job-id
***
Sets Arcanna Default Job id


#### Base Command

`arcanna-set-default-job-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job_id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Default_Job_Id | Unknown | Arcanna default job id | 


#### Command Example
```!arcanna-set-default-job-id job_id=1102```

#### Context Example
```json
{
    "Arcanna": {
        "Default_Job_Id": "1102"
    }
}
```

#### Human Readable Output

>## 1102
