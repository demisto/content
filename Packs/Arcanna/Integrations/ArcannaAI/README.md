Arcanna integration for using the power of AI in SOC
This integration was integrated and tested with version xx of Arcanna.AI

## Configure Arcanna.AI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Arcanna.AI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://&lt;your arcanna ai api&gt;) | URL of Arcanna API | True |
    | API Key | Api Key for Arcanna API | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Default Arcanna Job Id |  | False |
    | Feature Mapping as an array to map between CLOSING REASON and Arcanna labels |  | False |
    | Field use to signal to arcanna the status for closing an alert(or marking as feedback for Arcanna) |  | False |

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
| Arcanna.Jobs.job_id | Number | Arcanna Job id | 
| Arcanna.Jobs.data_type | String | Arcanna Job type | 
| Arcanna.Jobs.title | String | Arcanna Job title | 
| Arcanna.Jobs.status | String | Arcanna job status | 


#### Command Example
```!arcanna-get-jobs```

#### Context Example
```json
{
    "Arcanna": {
        "Jobs": {
            "data_type": "dev",
            "job_id": 1201,
            "status": "STARTED",
            "title": "dev1"
        }
    }
}
```

#### Human Readable Output

>### Arcanna Jobs
>|job_id|title|data_type|status|
>|---|---|---|---|
>| 1201 | dev1 | dev | STARTED |


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
| Arcanna.Event.job_id | Unknown | Arcanna Job id used for sending. | 


#### Command Example
``` ```

#### Human Readable Output



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
| Arcanna.Event.status | String | Arcanna event status | 


#### Command Example
```!arcanna-get-event-status job_id="1201" event_id="12011938471583"```

#### Context Example
```json
{
    "Arcanna": {
        "Event": {
            "confidence_level": 0.9999464750289917,
            "error_message": null,
            "event_id": "12011938471583",
            "ingest_timestamp": "2021-08-26T12:53:47.193847Z",
            "is_duplicated": true,
            "result": "escalate_alert",
            "status": "OK"
        }
    }
}
```

#### Human Readable Output

>## {'event_id': '12011938471583', 'ingest_timestamp': '2021-08-26T12:53:47.193847Z', 'status': 'OK', 'confidence_level': 0.9999464750289917, 'result': 'escalate_alert', 'is_duplicated': True, 'error_message': None}

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
        "Default_Job_Id": "1201"
    }
}
```

#### Human Readable Output

>## 1201

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
```!arcanna-set-default-job-id job_id=1201```

#### Context Example
```json
{
    "Arcanna": {
        "Default_Job_Id": "1201"
    }
}
```

#### Human Readable Output

>## 1201

### arcanna-send-event-feedback
***
Send Arcanna feedback for a previous inferred event


#### Base Command

`arcanna-send-event-feedback`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Arcanna job id. | Required | 
| event_id | Arcanna event id. | Required | 
| label | Arcanna Feedback Label. | Optional | 
| username | User providing feedback. | Optional | 
| closing_notes | Cortex closing notes if any. | Optional | 
| indicators | Cortex Indicator if any. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Event.feedback_status | String | Arcanna feedback status response  | 


#### Command Example
```!arcanna-send-event-feedback job_id="1201" event_id="12011938471583" label="Resolved" username="dbot" closing_notes="some note"```

#### Context Example
```json
{
    "Arcanna": {
        "Feedback": {
            "status": "updated"
        }
    }
}
```

#### Human Readable Output

>## {'status': 'updated'}

### arcanna-send-bulk-events
***
Send to Arcanna a bulk of events.


#### Base Command

`arcanna-send-bulk-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Arcanna job_id. | Required | 
| events | Arcanna evens to be sent . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### arcanna-get-feedback-field
***
Returns the Feedback field set on integration


#### Base Command

`arcanna-get-feedback-field`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!arcanna-get-feedback-field```

#### Context Example
```json
{
    "Arcanna": {
        "FeedbackField": "closeReason"
    }
}
```

#### Human Readable Output

>## closeReason
