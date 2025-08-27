# Arcanna integration for using the power of AI in SOC

This integration was integrated and tested with version 1.63.2 of Arcanna.AI

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
                "job_id": 1201,
                "status": "ENABLED",
                "title": "dev1",
                "last_processed_timestamp": "2025-07-24T15:51:01.731058+00:00"
            },
            {
                "job_id": 1202,
                "status": "ENABLED",
                "title": "marian-demo",
                "last_processed_timestamp": "2025-07-23T13:50:01.351058+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Arcanna Jobs
>
>|job_id|title|status|last_processed_timestamp|
>|---|---|---|---|
>| 1201 | dev1 | ENABLED | 2025-07-24T15:51:01.731058+00:00 |
>| 1202 | marian-demo | ENABLED | 2025-07-23T13:50:01.351058+00:00 |

### arcanna-send-event

***
Sends a raw event to Arcanna

#### Base Command

`arcanna-send-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | An Arcanna running job_id. | Required |
| event_json | json event for arcanna to inference. | Required |
| title | event title. | Required |
| severity | event severity. | Optional |
| id_value | event id. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.SendEventDetails.event_id | Number | Arcanna event id |
| Arcanna.SendEventDetails.status | String | Arcanna ingestion status |
| Arcanna.SendEventDetails.ingest_timestamp | date | Arcanna ingestion timestamp |
| Arcanna.SendEventDetails.error_message | String | Arcanna error message if any |
| Arcanna.SendEventDetails.job_id | Number | An Arcanna Job id used for sending. |

#### Command Example

```!arcanna-send-event job_id=1202 event_json="{\"destination\":{   \"address\":\"10.128.0.6\",   \"port\":53720,   \"bytes\":836035,   \"ip\":\"10.128.0.6\",   \"packets\":6459},\"rule\":{   \"name\":\"SURICATA HTTP unable to match response to request\",   \"id\":\"2221010\",   \"category\":\"Generic Protocol Command Decode\"},\"source\":{   \"address\":\"8.8.8.8\",   \"port\":9200,   \"bytes\":4833843,   \"ip\":\"8.8.8.8\",   \"packets\":9677},\"event\":{   \"severity\":3,   \"ingested\":\"2021-06-15T07:56:50.654225827Z\",   \"created\":\"2021-06-15T07:56:49.649Z\",   \"kind\":\"alert\",   \"module\":\"suricata\",   \"start\":\"2021-06-14T14:02:06.280Z\",   \"category\":[      \"network\",      \"intrusion_detection\"   ],   \"type\":[      \"allowed\"   ],   \"dataset\":\"suricata.eve\"},\"fileset\":{   \"name\":\"eve\"},\"message\":\"Generic Protocol Command Decode\",\"url\":{   \"path\":\"/libhtp::request_uri_not_seen\",   \"original\":\"/libhtp::request_uri_not_seen\"},\"@timestamp\":\"2021-06-15T07:56:49.647Z\",\"suricata\":{   \"eve\":{      \"in_iface\":\"ens4\",      \"metadata\":{         \"flowints\":{            \"http.anomaly.count\":2419         }      },      \"event_type\":\"alert\",      \"alert\":{         \"signature_id\":2221010,         \"rev\":1,         \"gid\":1,         \"signature\":\"SURICATA HTTP unable to match response to request\",         \"category\":\"Generic Protocol Command Decode\"      },      \"flow_id\":576330410117303,      \"tx_id\":3224,      \"flow\":{               }   }}}" title=Test_alert severity=3```

#### Context Example

```json
{
    "Arcanna": {
        "SendEventDetails": {
            "error_message": "",
            "event_id": "12023636421762",
            "ingest_timestamp": "2021-09-02T09:46:22.363642Z",
            "job_id": 1202,
            "status": "pending_inference"
        }
    }
}
```

#### Human Readable Output

>### Arcanna Send Event
>
>| | |
>|-|-|
>| event_id | 12023636421762 |
>| ingest_timestamp | 2021-09-02T09:46:22.363642Z |
>| status | pending_inference |
>| job_id | 1202 |

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
    "Arcanna": {
        "Train": {
           "status": "OK",
            "error_message": ""
        }
    }
}
```

#### Human Readable Output

>### Arcanna.ai training outcome
>
>| | |
>|-|-|
>| status | OK |


### arcanna-get-decision-set

***
Retrieve avaiable decision points for specified AI Job.

#### Base Command

`arcanna-get-decision-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to use for exporting decision set. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.GetDecisionSet.decision_set | List | Available decisions for specified AI Job. |

#### Command Example

```!arcanna-get-decision-set job_id="1201"```

#### Context Example

```json
{
    "Arcanna": {
        "GetDecisionSet": {
			"decision_set": {
				"decision_set": ["Drop", "Escalate"]
			}
        }
    }
}
```

#### Human Readable Output

>### Arcanna Get Decision Set
>
>| **decision_set** |
>| --- |
>| Drop |
>| Escalate |

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
| Arcanna.RawEvent.arcanna_event | unknown | Full export for specified event. |

#### Command Example

```!arcanna-export-event job_id="1201" event_id="12011938471583"```

#### Context Example

```json
{
    "Arcanna": {
        "RawEvent": {
			"arcanna_event": {
				...
			}
			"event_id": "615471",
			"ingest_timestamp": "2025-07-14T20:34:06.946556Z",
			"status": "OK"
        }
    }
}
```

#### Human Readable Output

>### Arcanna Raw Event
>
>| **arcanna_event** | **status** | **ingest_timestamp** | **event_id** |
>| --- | --- | --- | --- |
>| ... | OK | 2025-07-14T20:34:06.946556Z | 615471 |

### arcanna-get-event-status

***
Retrieves Arcanna Inference result.

#### Base Command

`arcanna-get-event-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Arcanna Job Id. | Required |
| event_id | Arcanna generated unique event id. | Required |
| polling | Run until specified or until result is valid. | Optional |
| interval | Polling interval. | Optional |
| timeout | Total time allowed for polling. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.GetEventDetails.event_id | String | Arcanna event id |
| Arcanna.GetEventDetails.ingest_timestamp | String | Arcanna ingestion timestamp. |
| Arcanna.GetEventDetails.result | String | Arcanna event result |
| Arcanna.GetEventDetails.error_message | String | Arcanna error message if any. |
| Arcanna.GetEventDetails.status | String | Arcanna event status. |
| Arcanna.GetEventDetails.result_label | String | Arcanna event result label |
| Arcanna.GetEventDetails.is_duplicated | boolean | Deprecated. Arcanna signalling if event is duplicated by another alert. |
| Arcanna.GetEventDetails.confidence_level | Number | Deprecated. Arcanna ML confidence_level |
| Arcanna.GetEventDetails.confidence_score | Number | Arcanna ML confidence_score |
| Arcanna.GetEventDetails.bucket_state | String | Flag to indicate the current event's state in the AI Model |
| Arcanna.GetEventDetails.outlier | boolean | Arcanna signalling if event is an outlier based on historical data |

#### Command Example

```!arcanna-get-event-status job_id="1208" event_id="615471" polling="true" interval="10" timeout="60"```

#### Context Example

```json
{
    "Arcanna": {
        "GetEventDetails": {
            "confidence_score": 98.3,
            "error_message": null,
            "event_id": "615471",
            "ingest_timestamp": "2025-07-14T20:34:06.946556Z",
            "result": "class_0",
            "result_label": "Escalate",
            "outlier": false,
            "status": "OK",
			"bucket_state" : "in_knowledge_base"
        }
    }
}
```

#### Human Readable Output

>### Arcanna Get Event Status
>
>| | |
>|-|-|
>| event_id | 615471 |
>| ingest_timestamp | 2025-07-14T20:34:06.946556Z |
>| status | OK |
>| error_message | n/a |
>| bucket_state | in_knowledge_base |
>| confidence_score | 98.3 |
>| outlier | false |
>| result_label | Escalate |

### arcanna-send-event-feedback

***
Send Arcanna feedback for a previous inferred event.

#### Base Command

`arcanna-send-event-feedback`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | An Arcanna job id. | Required |
| event_id | An Arcanna event id. | Required |
| feedback | An Arcanna feedback label. | Required |
| username | A username providing the feedback. | Required |
| closing_notes | Deprecated. Prior used for audit. | Optional |
| label | Deprecated. Replaced by `feedback`. | Optional |
| indicators | Deprecated. Prior used for metadata. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Arcanna.SendEventFeedback.status | String | An Arcanna feedback status response. |

#### Command Example

```!arcanna-send-event-feedback job_id="1208" event_id="615471" feedback="Escalate" username="admin"```

#### Context Example

```json
{
    "Arcanna": {
        "SendEventFeedback": {
            "status": "updated"
        }
    }
}
```

#### Human Readable Output

>### Arcanna Send Event Feedback
>
>| | |
>|-|-|
>| status | updated |
