Tessian is an email security platform that allows organizations to protect their users from inbound phishing threats, outbound data loss (both malicious and accidental) and account takeovers.

## Configure Tessian in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Portal URL | The URL that you use to access the Tessian Portal. Please include the extension, e.g. "example.tessian-platform.com" or "example.tessian-app.com" | True |
| API Key | The API Key to use to connect to the Tessian API. This can be found under "Security Integrations" in your Tessian Portal \(/0/admin/integrations/api/tokens\) | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tessian-list-events

***
This command allows you to pull Tessian event data into your XSOAR instance.

#### Base Command

`tessian-list-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events you would like Tessian to return per call. The maximum value is 100. The minimum value is 2. | Optional | 
| after_checkpoint | If provided, this parameter must be set to the checkpoint returned by a previous request to this endpoint. When provided, events from the previous request will not be included in the response from this request. If the new checkpoint returned by this request is used in yet another call to this endpoint events from both previous requests will not be included in the response (and so on). By making a number of consecutive requests to this endpoint where the checkpoint from the previous request is provided, clients can get all events from the Tessian platform, even when there are many more than can be returned in a single request. This process is often referred to as pagination. If an event is updated, it will no longer be excluded from subsequent requests. | Optional | 
| created_after | Only include events that were created after this time. For example, 2020-02-02T19:00:00Z. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.EventsOutput.checkpoint | String | This value can be provided to a subsequent request via the after_checkpoint query parameter to ensure that events from this request are not returned in future responses. This allows clients to paginate through results. | 
| Tessian.EventsOutput.additional_results | Boolean | True if there may be more events that can be immediately retrieved. | 
| Tessian.EventsOutput.results | Unknown | The events returned by this request. | 

#### Command example
```!tessian-list-events limit=2```

#### Context Example
```json
{
    "Tessian": {
        "EventsOutput": {
            {
                "checkpoint": "string",
                "additional_results": true,
                "results": [
                    {
                        "id": "string",
                        "type": "string",
                        "created_at": "2019-08-24T14:15:22Z",
                        "updated_at": "2019-08-24T14:15:22Z",
                        "portal_link": "string",
                        "outbound_email_details": {
                            "send_time": "2019-08-24T14:15:22Z",
                            "tessian_action": "WARN",
                            "message_id": "string",
                            "tessian_id": "string",
                            "from": null,
                            "transmitter": null,
                            "reply_to": [
                                null
                            ],
                            "recipients": {
                                "to": [
                                    null
                                ],
                                "cc": [
                                    null
                                ],
                                "bcc": [
                                    null
                                ],
                                "all": [
                                    null
                                ],
                                "count": 0
                            },
                            "subject": "string",
                            "attachments": {
                                "names": [
                                    "string"
                                ],
                                "count": 0,
                                "bytes": 0
                            }
                        },
                        "guardian_details": {
                            "triggered_filter_ids": [
                                "string"
                            ],
                            "type": "MISDIRECTED_EMAIL",
                            "triggered_filter_names": [
                            "string"
                            ],
                            "breach_prevented": true,
                            "anomalous_recipients": [
                                null
                            ],
                            "suggested_recipients": [
                                null
                            ],
                            "anomalous_attachments": [
                                "string"
                            ],
                            "final_outcome": null,
                            "user_responses": [
                                "SEND"
                            ],
                            "admin_action": "SAFE",
                            "justifications": [
                                "string"
                            ],
                            "user_shown_message": true
                        }
                    },
                    {
                        "id": "string",
                        "type": "string",
                        "created_at": "2019-08-24T14:15:22Z",
                        "updated_at": "2019-08-24T14:15:22Z",
                        "portal_link": "string",
                        "inbound_email_details": {
                            "received_time": "2019-08-24T14:15:22Z",
                            "urls": ["strings"],
                            "attachment_urls": ["strings"],
                            "message_id": "string",
                            "tessian_id": "string",
                            "from": null,
                            "transmitter": null,
                            "reply_to": [null],
                            "recipients": {
                                "to": [
                                    null
                                ],
                                "cc": [
                                    null
                                ],
                                "bcc": [
                                    null
                                ],
                                "all": [
                                    null
                                ],
                                "count": 0
                            },
                            "subject": "string",
                            "attachments": {
                                "names": [
                                    "string"
                                ],
                                "count": 0,
                                "bytes": 0
                            }
                        },
                        "defender_details": {
                            "burst_attack_id": "string",
                            "intent_types": ["INVOICE"],
                            "threat_signal_types": ["string"],
                            "threat_types": ["MATCHED_DENYLIST"],
                            "spf_result": null,
                            "dkim_result": null,
                            "dmarc_result": null,
                            "sender_location": null,
                            "users_responded": {
                                "malicious": 1,
                                "safe" 0,
                                "unsure": 0,
                                "deleted": 0,
                            },
                            "admin_label": null,
                            "quarantine_status_count": {
                                "admin_quarantine_status_count": {
                                    "not_quarantined": 0,
                                    "quarantined": 1,
                                    "released": 0,
                                    "deleted": 0,
                                    "pending_release": 0,
                                },
                                "user_quarantine_status_count": {
                                    "not_quarantined": 0,
                                    "quarantined": 1,
                                    "released": 0,
                                    "deleted": 0,
                                    "pending_release": 0,
                                },
                            },
                            "deletion_status_count": {
                                "deleted": 1,
                                "deletion_pending": 0,
                                "not_deleted": 0,
                            },
                            "number_protected_users": 1,
                            "confidence": HIGH,
                            "impersonation_type": null,
                            "impersonated_domain": null,
                            "impersonated_address": null,
                        }
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

># Tessian Events
>## Checkpoint: eyJzb3J0X3ZhbHVlcyI6IFsxNjkxNTkyNTc4Mjg4LCAiaW5ib3VuZC1lNWI1MmQyYWQ3ZGQ4MTdhMGRhYmVhZjgzMDhhYWMwMDhkZDY3ZDg1ZTQ3MTk1NDE4NTZmMzRkN2JlY2Y4ZTNlIl0sICJyZXZlcnNlIjogZmFsc2V9
>## Additional Results: True
>### Number of events returned: 2
> ### Results
>
> | Event ID                           | Event Type                           | Event Created At                           | Event Updated At                           | Portal Link                           |
> | ------------------------------------ | ------------------------------------ | ------------------------------------ | ------------------------------------ | ------------------------------------ |
> | string | string | 2019-08-24T14:15:22Z | 2019-08-24T14:15:22Z | string |
> | string | string | 2019-08-24T14:15:22Z | 2019-08-24T14:15:22Z | string |

### tessian-release-from-quarantine

***
This command allows you to release a quarantined emails associated with an event from Tessian.

#### Base Command

`tessian-release-from-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event you would like to release from quarantine. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.ReleaseFromQuarantineOutput.number_of_actions_attempted | String | The number of users that release from quarantine actions were attempted for. | 
| Tessian.ReleaseFromQuarantineOutput.number_of_actions_succeeded | String | The number of users that the release from quarantine action was successful for. | 
| Tessian.ReleaseFromQuarantineOutput.results | Unknown | The results of the release action. This is an array of objects mapping the email address of users to the result of the release action. | 
| Tessian.ReleaseFromQuarantineOutput.event_id | String | The event ID that was submitted for release. | 

#### Command example
```!tessian-release-from-quarantine event_id="string"```

#### Context Example
```json
{
    "Tessian": {
        "EventsOutput": {
            "number_of_actions_attempted": 1,
            "number_of_actions_succeeded": 1,
            "results": [
                {
                    "user_address": "test_user@example.com",
                    "error": null,
                },
                {
                    "user_address": "test_user2@example.com",
                    "error": "EMAIL_ALREADY_REMEDIATED",
                },
            ]
        }
    }
}
```

#### Human Readable Output

># Release from Quarantine Action
>## Event ID: string
>## Number of Release Actions Successfully Initiated: 1
>## Number of Release Actions Failed: 1
> ### Errors
>
> | Recipient                           | Error                           |
> | ------------------------------------ | ------------------------------------ |
> | test_user2@example.com | EMAIL_ALREADY_REMEDIATED |

### tessian-delete-from-quarantine

***
This command allows you to delete quarantined emails associated with an event from Tessian.

#### Base Command

`tessian-delete-from-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event you would like to delete from quarantine. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.DeleteFromQuarantineOutput.number_of_actions_attempted | String | The number of users that delete from quarantine actions were attempted for. | 
| Tessian.DeleteFromQuarantineOutput.number_of_actions_succeeded | String | The number of users that the delete from quarantine action was successful for. | 
| Tessian.DeleteFromQuarantineOutput.results | Unknown | The results of the delete action. This is an array of objects mapping the email address of users to the result of the delete action. | 
| Tessian.DeleteFromQuarantineOutput.event_id | String | The event ID that was submitted for deletion. | 

#### Command example
```!tessian-delete-from-quarantine event_id="string"```

#### Context Example
```json
{
    "Tessian": {
        "EventsOutput": {
            "number_of_actions_attempted": 1,
            "number_of_actions_succeeded": 1,
            "results": [
                {
                    "user_address": "test_user@example.com",
                    "error": null,
                },
                {
                    "user_address": "test_user2@example.com",
                    "error": "EMAIL_ALREADY_REMEDIATED",
                },
            ]
        }
    }
}
```

#### Human Readable Output

># Delete from Quarantine Action
>## Event ID: string
>## Number of Delete Actions Successfully Initiated: 1
>## Number of Delete Actions Failed: 1
> ### Errors
>
> | Recipient                           | Error                           |
> | ------------------------------------ | ------------------------------------ |
> | test_user2@example.com | EMAIL_ALREADY_REMEDIATED |

### tessian-delete-from-inbox

***
This command allows you to delete emails associated with a Tessian event from your inbox.

#### Base Command

`tessian-delete-from-inbox`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event you would like to delete from inbox. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tessian.DeleteFromQuarantineOutput.number_of_actions_attempted | String | The number of users that delete from inbox actions were attempted for. | 
| Tessian.DeleteFromQuarantineOutput.number_of_actions_succeeded | String | The number of users that the delete from inbox action was successful for. | 
| Tessian.DeleteFromQuarantineOutput.results | Unknown | The results of the delete action. This is an array of objects mapping the email address of users to the result of the delete action. | 
| Tessian.DeleteFromQuarantineOutput.event_id | String | The event ID that was submitted for deletion. | 

#### Command example
```!tessian-delete-from-inbox event_id="string"```

#### Context Example
```json
{
    "Tessian": {
        "EventsOutput": {
            "number_of_actions_attempted": 1,
            "number_of_actions_succeeded": 1,
            "results": [
                {
                    "user_address": "test_user@example.com",
                    "error": null,
                },
                {
                    "user_address": "test_user2@example.com",
                    "error": "ALREADY_DELETED",
                },
            ]
        }
    }
}
```

#### Human Readable Output

># Delete from Inbox Action
>## Event ID: string
>## Number of Delete Actions Successfully Initiated: 1
>## Number of Delete Actions Failed: 1
> ### Errors
>
> | Recipient                           | Error                           |
> | ------------------------------------ | ------------------------------------ |
> | test_user2@example.com | ALREADY_DELETED |