Arcanna integration for using the power of AI in SOC
This integration was integrated and tested with version 1.45.1 of Arcanna.AI

## Configure Arcanna.AI in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://&lt;your arcanna ai api&gt;) | URL of Arcanna API | True |
| API Key | Api Key for Arcanna API | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Default Arcanna Job Id |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| Arcanna.Jobs.last_processed_timestamp | date | Last processed time |

#### Command Example
```!arcanna-get-jobs```

#### Context Example
```json
{
    "Arcanna": {
        "Jobs": [
            {
                "data_type": "",
                "job_id": 1201,
                "status": "STARTED",
                "title": "dev1"
            },
            {
                "data_type": "",
                "job_id": 1202,
                "status": "STARTED",
                "title": "marian-demo"
            }
        ]
    }
}
```

#### Human Readable Output

>### Arcanna Jobs
>|job_id|title|data_type|status|
>|---|---|---|---|
>| 1201 | dev1 |  | STARTED |
>| 1202 | marian-demo |  | STARTED |


### arcanna-send-event
***
Sends a raw event to Arcanna


#### Base Command

`arcanna-send-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | An Arcanna running job_id. | Optional | 
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
| Arcanna.Event.job_id | Number | An Arcanna Job id used for sending. | 


#### Command Example
```!arcanna-send-event job_id=1202 event_json="{\"destination\":{   \"address\":\"10.128.0.6\",   \"port\":53720,   \"bytes\":836035,   \"ip\":\"10.128.0.6\",   \"packets\":6459},\"rule\":{   \"name\":\"SURICATA HTTP unable to match response to request\",   \"id\":\"2221010\",   \"category\":\"Generic Protocol Command Decode\"},\"source\":{   \"address\":\"8.8.8.8\",   \"port\":9200,   \"bytes\":4833843,   \"ip\":\"8.8.8.8\",   \"packets\":9677},\"event\":{   \"severity\":3,   \"ingested\":\"2021-06-15T07:56:50.654225827Z\",   \"created\":\"2021-06-15T07:56:49.649Z\",   \"kind\":\"alert\",   \"module\":\"suricata\",   \"start\":\"2021-06-14T14:02:06.280Z\",   \"category\":[      \"network\",      \"intrusion_detection\"   ],   \"type\":[      \"allowed\"   ],   \"dataset\":\"suricata.eve\"},\"fileset\":{   \"name\":\"eve\"},\"message\":\"Generic Protocol Command Decode\",\"url\":{   \"path\":\"/libhtp::request_uri_not_seen\",   \"original\":\"/libhtp::request_uri_not_seen\"},\"@timestamp\":\"2021-06-15T07:56:49.647Z\",\"suricata\":{   \"eve\":{      \"in_iface\":\"ens4\",      \"metadata\":{         \"flowints\":{            \"http.anomaly.count\":2419         }      },      \"event_type\":\"alert\",      \"alert\":{         \"signature_id\":2221010,         \"rev\":1,         \"gid\":1,         \"signature\":\"SURICATA HTTP unable to match response to request\",         \"category\":\"Generic Protocol Command Decode\"      },      \"flow_id\":576330410117303,      \"tx_id\":3224,      \"flow\":{               }   }}}" title=Test_alert severity=3```

#### Context Example
```json
{
    "Arcanna": {
        "Event": {
            "error_message": "",
            "event_id": "12023636421762",
            "ingest_timestamp": "2021-09-02T09:46:22.363642Z",
            "job_id": 1202,
            "status": "Pending inference"
        }
    }
}
```

#### Human Readable Output

>## {'event_id': '12023636421762', 'job_id': 1202, 'ingest_timestamp': '2021-09-02T09:46:22.363642Z', 'status': 'Pending inference', 'error_message': ''}


### arcanna-trigger-train
***
Trigger AI Train for specified Arcanna.ai Job.

#### Base Command

`arcanna-trigger-train`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to trigger train for. | Required |
| username | Username for audit. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Train.status | String | Action status. |
| Arcanna.Train.error_message | String | Message in case of error. |

#### Command Example
```!arcanna-trigger-train job_id="1201" username="admin"```

#### Context Example
```json
{
  "status": "OK",
  "error_message": ""
}
```
#### Human Readable Output

> ## Arcanna trigger train results: {'status': 'OK', 'error_message': ''}


### arcanna-get-decision-set
***
Retrieve avaiable decision points for specified AI Job.

#### Base Command

`arcanna-get-decision-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to use for exporting event. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Event.decision_set | List | Available decisions for specified AI Job. |

#### Command Example
```!arcanna-get-decision-set job_id="1201"```

#### Context Example
```json
{
  "decision_set": ["Drop", "Escalate"]
}
```
#### Human Readable Output

> ## Arcanna get decision set results: {'decision_set': ['Drop','Escalate']}



### arcanna-export-event
***
Export full event with metadata from Arcanna.ai based on specified Job ID and Event ID.


#### Base Command

`arcanna-export-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to use for exporting event. | Required |
| event_id | Event ID to use for exporting event. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Event.arcanna_event | unknown | Full export for specified event. |

#### Command Example
```!arcanna-export-event job_id="1201" event_id="12011938471583"```

#### Context Example
```json
{
  "result": "Escalate with Priority",
  "metadata": {
    "id": "12011938471583",
    ...
  }
  ... 
}
```

#### Human Readable Output

> ## Arcanna export event results: {'result': 'Escalate with Priority', 'metadata': {'id': '12011938471583', .. }, ..}


### arcanna-get-event-status
***
Retrieves Arcanna Inference result.


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
| Arcanna.Event.ingest_timestamp | String | Arcanna ingestion timestamp. | 
| Arcanna.Event.result | String | Arcanna event  result | 
| Arcanna.Event.error_message | String | Arcanna error message if any. | 
| Arcanna.Event.status | String | Arcanna event status. | 
| Arcanna.Event.result_label | String | Arcanna event result label |
| Arcanna.Event.is_duplicated | boolean | Deprecated. Arcanna signalling if event is duplicated by another alert. |
| Arcanna.Event.confidence_level | Number | Deprecated. Arcanna ML confidence_level |
| Arcanna.Event.confidence_score | Number | Arcanna ML confidence_score |
| Arcanna.Event.bucket_state | String | Flag to indicate the current event's state in the AI Model |
| Arcanna.Event.outlier | boolean | Arcanna signalling if event is an outlier based on historical data | 

#### Command Example
```!arcanna-get-event-status job_id="1201" event_id="12011938471583"```

#### Context Example
```json
{
    "Arcanna": {
        "Event": {
            "confidence_score": 0.9999464750289917,
            "error_message": null,
            "event_id": "12011938471583",
            "ingest_timestamp": "2021-08-26T12:53:47.193847Z",
            "result": "escalate_alert",
            "result_label": "Escalate",
            "outlier": False
            "status": "OK"
        }
    }
}
```

#### Human Readable Output

>## {'event_id': '12011938471583', 'ingest_timestamp': '2021-08-26T12:53:47.193847Z', 'status': 'OK', 'confidence_score': 0.9999464750289917, 'result': 'escalate_alert', 'result_label': 'Escalate', 'outlier': False, 'error_message': None}

### arcanna-send-event-feedback
***
Send Arcanna feedback for a previous inferred event.


#### Base Command

`arcanna-send-event-feedback`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | An Arcanna job id. | Optional | 
| event_id | An Arcanna event id. | Required | 
| feedback | An Arcanna feedback label. | Required | 
| username | A username providing the feedback. | Required | 
| decision_set | List of possible decisions to be used as feedback values. | Required | 
| closing_notes | Deprecated. Prior used for audit. | Optional |
| label | Deprecated. Replaced by `feedback`. | Required |
| indicators | Deprecated. Prior used for metadata. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.Event.feedback_status | String | An Arcanna feedback status response. | 


#### Command Example
```!arcanna-send-event-feedback job_id="1201" event_id="12011938471583" feedback="Escalate with Priority" username="dbot"```

#### Context Example
```json
{
    "Arcanna": {
        "Event": {
            "status": "updated"
        }
    }
}
```

#### Human Readable Output

> ## Arcanna send event feedback results: {'status': 'updated'}
